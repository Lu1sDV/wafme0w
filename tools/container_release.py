#!/usr/bin/env python3
"""Build native release images without pushing; publish only verified image bundles.

The build command is safe for PR CI and has no registry credentials. The publish
command belongs only to the release workflow's separately permissioned final job.
Version tags are never overwritten; consumers should pin the attested digest.
"""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile

import release

ARCHES = ("amd64", "arm64")
MAX_IMAGE_BYTES = 256 * 1024 * 1024


def require(condition, message):
    release.require(condition, message)


def image_name(repository):
    return "ghcr.io/" + release.repository_name(repository).lower()


def local_image(tag, arch):
    release.version_key(tag)
    require(arch in ARCHES and len(tag + "-linux-" + arch) <= 128,
            "Unsupported container tag or architecture")
    return f"wafmeow-release:{tag}-{arch}"


def inspect_image(image, tag, revision, arch, repository):
    values = json.loads(release.command("docker", "image", "inspect", image))
    require(len(values) == 1, "Expected one release image")
    value = values[0]
    config = value["Config"]
    labels = config.get("Labels") or {}
    require(value["Os"] == "linux" and value["Architecture"] == arch,
            "Container architecture differs from native tested target")
    require(config.get("User") == "65532:65532" and config.get("WorkingDir") == "/work" and
            config.get("Entrypoint") == ["/usr/local/bin/wafmeow"] and not config.get("Cmd"),
            "Container changed the hardened runtime identity or entry point")
    require(labels.get("org.opencontainers.image.source") == "https://github.com/" + repository and
            labels.get("org.opencontainers.image.revision") == revision and
            labels.get("org.opencontainers.image.version") == tag, "Container source labels disagree")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", value["Id"]), "Invalid image identity")
    return value["Id"]


def build(args):
    repository = release.repository_name(args.repository)
    host_arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    require(platform.system() == "Linux" and host_arch == args.arch, "Release image smoke must run on its native Linux architecture")
    require(release.command("git", "rev-parse", "HEAD") == args.revision, "Container checkout differs from frozen source")
    release.validate_candidate(args.tag, args.revision)
    image = local_image(args.tag, args.arch)
    archive = args.dist / f"wafmeow_{args.tag}_linux_{args.arch}.tar.gz"
    metadata = json.loads((args.dist / (archive.name + ".metadata.json")).read_text(encoding="utf-8"))
    require(metadata["tag"] == args.tag and metadata.get("program_version") == args.tag and
            metadata["archive_sha256"] == release.digest(archive),
            "Native archive or embedded version changed before container build")
    require(not args.output.exists(), "Container output must be a new directory")
    with tempfile.TemporaryDirectory(prefix="wafmeow-image-") as temporary:
        root = Path(temporary)
        binary = release.extract_archive(archive, root / "extracted")
        identity = release.binary_identity(binary, args.revision, "linux", args.arch)
        release.verify_binary_release_version(binary, args.tag)
        require(all(metadata.get(key) == value for key, value in identity.items()) and
                release.digest(binary) == metadata["binary_sha256"], "Native binary identity changed")
        require((binary.parent / "LICENSE.md").read_bytes() == Path("LICENSE.md").read_bytes(),
                "Native archive license differs from frozen source")
        context = root / "context"
        context.mkdir()
        shutil.copyfile(binary, context / "wafmeow")
        shutil.copyfile(binary.parent / "LICENSE.md", context / "LICENSE.md")
        subprocess.run(["docker", "build", "--file", str(Path("Dockerfile").resolve()),
                        "--target", "release", "--platform", "linux/" + args.arch,
                        "--label", "org.opencontainers.image.source=https://github.com/" + repository,
                        "--label", "org.opencontainers.image.revision=" + args.revision,
                        "--label", "org.opencontainers.image.version=" + args.tag,
                        "--tag", image, str(context)], check=True, timeout=300)
        subprocess.run([sys.executable, "tools/smoke.py", "docker", image, "--version", args.tag],
                       check=True, timeout=300)
        identity = inspect_image(image, args.tag, args.revision, args.arch, repository)
        args.output.mkdir(parents=True)
        image_archive = args.output / f"linux-{args.arch}.tar"
        release.command("docker", "image", "save", "--output", str(image_archive), image)
        require(0 < image_archive.stat().st_size <= MAX_IMAGE_BYTES, "Container artifact exceeds size bound")
        record = {"schema_version": 1, "tag": args.tag, "revision": args.revision, "arch": args.arch,
                  "repository": repository, "image_id": identity, "archive_sha256": metadata["archive_sha256"],
                  "binary_sha256": metadata["binary_sha256"], "image_archive_sha256": release.digest(image_archive)}
        (args.output / f"linux-{args.arch}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Native image smoke passed for linux/{args.arch}: {identity}")


def require_absent(reference):
    result = subprocess.run(["docker", "manifest", "inspect", reference], capture_output=True, text=True, timeout=60)
    require(result.returncode != 0, f"Container tag already exists; refusing overwrite: {reference}")
    # Authentication, connectivity and registry failures are not absence.
    error = result.stderr.lower()
    require("manifest unknown" in error or "no such manifest" in error,
            f"Cannot establish container tag absence: {reference}: {result.stderr.strip()[:1000]}")


def verify_images(args, manifest):
    expected = {f"linux-{arch}.{extension}" for arch in ARCHES for extension in ("tar", "json")}
    require({item.name for item in args.images.iterdir()} == expected, "Missing or unexpected native image artifacts")
    images = {}
    for arch in ARCHES:
        record = json.loads((args.images / f"linux-{arch}.json").read_text(encoding="utf-8"))
        archive = args.images / f"linux-{arch}.tar"
        native = manifest["archives"][f"wafmeow_{args.tag}_linux_{arch}.tar.gz"]
        require(record.get("schema_version") == 1 and record.get("tag") == args.tag and
                record.get("revision") == args.revision and record.get("arch") == arch and
                record.get("repository") == args.repository and
                record.get("archive_sha256") == native["archive_sha256"] and
                record.get("binary_sha256") == native["binary_sha256"], "Container differs from verified release manifest")
        require(0 < archive.stat().st_size <= MAX_IMAGE_BYTES and
                release.digest(archive) == record["image_archive_sha256"], "Native image artifact changed")
        release.command("docker", "image", "load", "--input", str(archive))
        image_id = inspect_image(local_image(args.tag, arch), args.tag, args.revision, arch, args.repository)
        require(image_id == record["image_id"], "Loaded image differs from native smoke image")
        # Creating and copying needs no execution or emulation of the ARM image.
        container = release.command("docker", "create", "--platform", "linux/" + arch, "--network", "none", image_id)
        try:
            with tempfile.TemporaryDirectory(prefix="wafmeow-image-identity-") as temporary:
                binary = Path(temporary) / "wafmeow"
                release.command("docker", "cp", container + ":/usr/local/bin/wafmeow", str(binary))
                require(release.digest(binary) == native["binary_sha256"], "Container binary differs from scanned native archive")
        finally:
            release.command("docker", "rm", container)
        images[arch] = image_id
    return images


def publish(args):
    image = image_name(args.repository)
    reference = image + ":" + args.tag
    require(not args.output.exists(), "Container publication metadata already exists")
    manifest = release.check_bundle(args.dist, args.tag, args.revision)
    require(manifest["repository"] == args.repository, "Container repository differs from verified release")
    images = verify_images(args, manifest)
    require(release.remote_revision("origin", args.tag) == args.revision, "Remote tag moved before image publication")
    references = {arch: reference + "-linux-" + arch for arch in ARCHES}
    for target in [reference, *references.values()]:
        require_absent(target)
    digests = {}
    for arch, image_id in images.items():
        release.command("docker", "image", "tag", image_id, references[arch])
        output = release.command("docker", "image", "push", references[arch])
        found = re.findall(r"digest:\s*(sha256:[0-9a-f]{64})", output)
        require(len(set(found)) == 1, "Registry did not report one pushed image digest")
        digests[arch] = found[0]
    require(release.remote_revision("origin", args.tag) == args.revision, "Remote tag moved during image upload")
    require_absent(reference)
    release.command("docker", "manifest", "create", reference, *[image + "@" + digests[arch] for arch in ARCHES])
    for arch in ARCHES:
        release.command("docker", "manifest", "annotate", reference, image + "@" + digests[arch], "--os", "linux", "--arch", arch)
    output = release.command("docker", "manifest", "push", "--purge", reference)
    digest = output.splitlines()[-1]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", digest), "Registry did not report the published manifest digest")
    record = {"schema_version": 1, "image": image, "tag": args.tag, "revision": args.revision,
              "digest": digest, "platforms": {"linux/" + arch: value for arch, value in digests.items()}}
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
            stream.write(f"image={image}\ndigest={digest}\n")
    print(f"Published {reference}; pin immutable digest {image}@{digest}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    build_parser = commands.add_parser("build")
    build_parser.add_argument("--arch", choices=ARCHES, required=True)
    publish_parser = commands.add_parser("publish")
    publish_parser.add_argument("--images", type=Path, required=True)
    for item in (build_parser, publish_parser):
        item.add_argument("--tag", required=True)
        item.add_argument("--revision", required=True)
        item.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "Lu1sDV/wafmeow"))
        item.add_argument("--dist", type=Path, default=Path("dist"))
        item.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    release.version_key(args.tag)
    require(re.fullmatch(r"[0-9a-f]{40}", args.revision), "Expected a frozen commit SHA")
    {"build": build, "publish": publish}[args.mode](args)


if __name__ == "__main__":
    main()
