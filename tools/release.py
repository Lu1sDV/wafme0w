#!/usr/bin/env python3
"""Release controls (Python 3.12+, stdlib only); workflows own builds and native smoke.

Tags are canonical vMAJOR.MINOR.PATCH with optional SemVer prerelease identifiers.
Build metadata is deliberately disallowed. Prereleases never become latest; stable
backports do not displace a newer stable release. Security maintenance covers the
highest stable version and a higher prerelease, independently of maintained source.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import zipfile

from smoke import CAPTURE, MAX_ARCHIVE_BYTES, extract_archive

GO_VERSION = "go1.27.3"
SCANNER = "golang.org/x/vuln/cmd/govulncheck@v1.9.0"
TARGETS = (("linux", "amd64", "tar.gz"), ("darwin", "arm64", "tar.gz"),
           ("windows", "amd64", "zip"), ("linux", "arm64", "tar.gz"),
           ("darwin", "amd64", "tar.gz"))
LEGACY_TARGETS = TARGETS[:3]
FORMULA = "wafme0w.rb"
TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=180).stdout.strip()


def version_key(tag):
    match = TAG.fullmatch(tag)
    require(match is not None, f"Invalid release tag {tag!r}: use vMAJOR.MINOR.PATCH[-PRERELEASE], no build metadata")
    major, minor, patch, prerelease = match.groups()
    identifiers = []
    for part in prerelease.split(".") if prerelease else ():
        require(not (part.isdigit() and len(part) > 1 and part.startswith("0")),
                f"Numeric prerelease identifiers cannot have leading zeroes: {tag}")
        identifiers.append((0, int(part)) if part.isdigit() else (1, part))
    return (int(major), int(minor), int(patch), prerelease is None, tuple(identifiers))


def module_path(go_mod):
    # Go module directives accept an unquoted path or a quoted string. Other
    # directives and trailing line comments do not affect the module identity.
    matches = re.findall(r'^\s*module\s+("[^"\r\n]+"|[^\s"]+)\s*(?://[^\r\n]*)?$', go_mod, re.MULTILINE)
    require(len(matches) == 1, "Candidate go.mod must contain exactly one module directive")
    path = json.loads(matches[0]) if matches[0].startswith('"') else matches[0]
    require(re.fullmatch(r"[A-Za-z0-9._~/-]+", path) and not path.endswith("/"), "Unsupported module path")
    return path


def module_major(module):
    match = re.search(r"/v([0-9]+)$", module)
    if not match:
        return None  # An unsuffixed module permits v0 and v1, never v2+.
    value = match.group(1)
    require(not value.startswith("0") and int(value) >= 2, "Invalid Go module major suffix")
    return int(value)


def require_module_version(tag, module):
    major = version_key(tag)[0]
    expected = module_major(module)
    require(major == expected if expected is not None else major in (0, 1),
            f"Release tag major {major} disagrees with candidate module {module}")


def validate_candidate(tag, revision, *, fetch=False):
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Candidate revision must be a full commit SHA")
    if fetch:
        command("git", "fetch", "--no-tags", "--depth=1", "origin", revision)
    require(command("git", "rev-parse", revision + "^{commit}") == revision, "Candidate is not a commit")
    # workflow_dispatch can run a workflow from a different branch. Never read
    # that checkout's go.mod when validating the peeled release candidate.
    module = module_path(command("git", "show", revision + ":go.mod"))
    require_module_version(tag, module)
    return module


def ci_tag():
    module = module_path(Path("go.mod").read_text(encoding="utf-8"))
    run = os.environ.get("GITHUB_RUN_ID", "0")
    require(re.fullmatch(r"[0-9]+", run), "Invalid CI run identifier")
    return f"v{module_major(module) or 0}.0.0-ci.{run}"


def release_versions(releases):
    result = []
    for item in releases:
        if item["draft"]:
            continue
        try:
            key = version_key(item["tag_name"])
        except ValueError:
            continue  # Historical non-version releases are outside the supported release policy.
        require(item["prerelease"] == (not key[3]), f"Release prerelease flag disagrees with tag: {item['tag_name']}")
        result.append((key, item))
    return result


def make_latest(tag, releases):
    key = version_key(tag)
    stable = [other for other, _ in release_versions(releases) if other[3]]
    return key[3] and (not stable or key > max(stable))


def supported_releases(releases):
    versions = release_versions(releases)
    stable = [(key, item) for key, item in versions if key[3]]
    candidates = [(key, item) for key, item in versions if not key[3]]
    selected = [max(stable, key=lambda pair: pair[0])] if stable else []
    if candidates:
        candidate = max(candidates, key=lambda pair: pair[0])
        if not selected or candidate[0] > selected[0][0]:
            selected.append(candidate)
    return [item for _, item in selected]


def repository_releases():
    pages = json.loads(command("gh", "api", "--paginate", "--slurp",
                               f"repos/{os.environ['GH_REPO']}/releases?per_page=100"))
    return [item for page in pages for item in page]


def remote_revision(remote, tag):
    version_key(tag)
    ref = "refs/tags/" + tag
    output = command("git", "ls-remote", "--exit-code", remote, ref, ref + "^{}")
    refs = dict((name, sha) for sha, name in (line.split() for line in output.splitlines()))
    require(ref in refs and set(refs) <= {ref, ref + "^{}"}, f"Missing or unexpected remote tag: {tag}")
    revision = refs.get(ref + "^{}", refs[ref])
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Tag did not resolve to a full SHA")
    return revision


def prepare(tag, *, expected_revision=None):
    key = version_key(tag)
    revision = remote_revision("origin", tag)
    require(expected_revision is None or revision == expected_revision,
            "Remote tag differs from the frozen manual release source")
    require(not any(item["tag_name"] == tag for item in repository_releases()),
            f"Release {tag} already exists; refusing overwrite (including drafts)")
    validate_candidate(tag, revision, fetch=True)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        output.write(f"tag={tag}\nrevision={revision}\nprerelease={str(not key[3]).lower()}\n")
    print(f"Prepared {tag} at peeled immutable source SHA {revision}")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def binary_identity(binary, revision, target_os, arch, go_version=GO_VERSION):
    output = command("go", "version", "-m", str(binary))
    lines = output.splitlines()
    actual_go_version = lines[0].split()[-1] if lines else ""
    require(actual_go_version == go_version, f"Unexpected compiler in {binary}: {output}")
    settings = {}
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
            name, value = fields[1].split("=", 1)
            settings[name] = value
    require(settings.get("vcs.revision") == revision, f"Binary revision does not match {revision}: {settings}")
    require(settings.get("vcs.modified") == "false", f"Binary must carry unmodified VCS identity: {settings}")
    require(settings.get("GOOS") == target_os and settings.get("GOARCH") == arch,
            f"Binary target does not match {target_os}/{arch}: {settings}")
    return {"revision": revision, "go_version": actual_go_version, "os": target_os, "arch": arch, "modified": False}


def archive_names(tag, targets=TARGETS):
    version_key(tag)
    return {f"wafme0w_{tag}_{target_os}_{arch}.{extension}": (target_os, arch)
            for target_os, arch, extension in targets}


def repository_name(value):
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value), "Invalid GitHub repository name")
    return value


def homebrew_formula(tag, revision, archives, repository):
    version_key(tag)
    repository_name(repository)
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "Invalid formula source revision")
    lines = [f"# Generated from verified release {tag}, source {revision}.",
             "class Wafme0w < Formula", '  desc "Identify WAF fingerprints in HTTP responses or saved captures"',
             f'  homepage "https://github.com/{repository}"',
             '  license "MIT"', ""]
    for target_os, platform in (("darwin", "macos"), ("linux", "linux")):
        lines.append(f"  on_{platform} do")
        for arch, cpu in (("arm64", "arm"), ("amd64", "intel")):
            name = f"wafme0w_{tag}_{target_os}_{arch}.tar.gz"
            checksum = archives[name]["archive_sha256"]
            require(re.fullmatch(r"[0-9a-f]{64}", checksum), f"Invalid formula archive hash: {name}")
            lines.extend([f"    on_{cpu} do", f'      url "https://github.com/{repository}/releases/download/{tag}/{name}"',
                          f'      sha256 "{checksum}"', "    end"])
        lines.extend(["  end", ""])
    lines.extend(["  def install", '    bin.install "wafme0w"', '    prefix.install "LICENSE.md"',
                  '    pkgshare.install "assets/demo/captures.jsonl"', "  end", "", "  test do",
                  '    assert_match "wafme0w ", shell_output("#{bin}/wafme0w --version")',
                  '    output = shell_output("#{bin}/wafme0w --evidence #{pkgshare}/captures.jsonl --jsonl --silent")',
                  '    assert_equal 3, output.lines.length', '    assert_match "synthetic-cloudflare", output',
                  "  end", "end", ""])
    return "\n".join(lines)


def package(args):
    version_key(args.tag)
    require(command("git", "rev-parse", "HEAD") == args.revision, "Checkout differs from prepared SHA")
    validate_candidate(args.tag, args.revision)
    require(command("go", "env", "GOVERSION") == GO_VERSION, "Release compiler differs from pinned compiler")
    identity = binary_identity(args.binary, args.revision, args.os, args.arch)
    names = [name for name, target in archive_names(args.tag).items() if target == (args.os, args.arch)]
    require(len(names) == 1, "Unsupported release target")
    args.dist.mkdir(parents=True, exist_ok=True)
    archive = args.dist / names[0]
    binary_name = "wafme0w.exe" if args.os == "windows" else "wafme0w"
    files = ((args.binary, binary_name), (Path("LICENSE.md"), "LICENSE.md"), (CAPTURE, CAPTURE.as_posix()))
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as output:
            for source, destination in files:
                output.write(source, arcname=destination)
    else:
        with tarfile.open(archive, "x:gz") as output:
            for source, destination in files:
                output.add(source, arcname=destination)
    metadata = {**identity, "tag": args.tag, "archive_sha256": digest(archive),
                "binary_sha256": digest(args.binary)}
    with (args.dist / (archive.name + ".metadata.json")).open("x", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
    print(archive)


def scan_binary(binary, report, *, timeout=300):
    # Text mode retains the finding exit status; stream diagnostics to disk so a
    # timeout cannot discard them or retain unbounded scanner output in memory.
    report.parent.mkdir(parents=True, exist_ok=True)
    with report.open("w", encoding="utf-8") as output:
        try:
            result = subprocess.run(["govulncheck", "-mode", "binary", str(binary)],
                                    stdout=output, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired:
            output.write(f"\nScanner timed out after {timeout}s; scan failed.\n")
            print(f"{binary}: scanner timed out; diagnostics: {report}")
            return False
    print(f"{binary}: scanner exit {result.returncode}; diagnostics: {report}")
    return result.returncode == 0


def verify(args):
    module = validate_candidate(args.tag, args.revision)
    repository = repository_name(os.environ["GH_REPO"])
    expected = archive_names(args.tag)
    require({path.name for path in args.dist.iterdir()} ==
            set(expected) | {name + ".metadata.json" for name in expected},
            "Missing, duplicate or unexpected release artifacts")
    archives = {}
    safe = True
    for name, (target_os, arch) in sorted(expected.items()):
        archive = args.dist / name
        metadata = json.loads((args.dist / (name + ".metadata.json")).read_text())
        require(metadata["tag"] == args.tag and metadata["archive_sha256"] == digest(archive),
                f"Archive hash/tag differs from native build metadata: {name}")
        with tempfile.TemporaryDirectory(prefix="wafme0w-verify-") as temporary:
            binary = extract_archive(archive, Path(temporary))
            identity = binary_identity(binary, args.revision, target_os, arch)
            require(all(metadata[key] == value for key, value in identity.items()), f"Identity mismatch: {name}")
            require(metadata["binary_sha256"] == digest(binary), f"Packaged binary hash mismatch: {name}")
            safe = scan_binary(binary, args.reports / (name + ".govulncheck.txt")) and safe
        archives[name] = metadata
    require(safe, "Release binary vulnerability scans failed; see retained reports")
    with (args.dist / FORMULA).open("x", encoding="utf-8", newline="\n") as output:
        output.write(homebrew_formula(args.tag, args.revision, archives, repository))
    manifest = {"schema_version": 1, "tag": args.tag, "revision": args.revision,
                "module": module, "repository": repository, "scanner": SCANNER, "archives": archives,
                "homebrew_formula_sha256": digest(args.dist / FORMULA)}
    with (args.dist / "manifest.json").open("x", encoding="utf-8") as output:
        json.dump(manifest, output, indent=2, sort_keys=True)
        output.write("\n")
    with (args.dist / "SHA256SUMS").open("x", encoding="utf-8", newline="\n") as output:
        for name in sorted([*archives, "manifest.json", FORMULA]):
            output.write(f"{digest(args.dist / name)}  {name}\n")
    # Per-build metadata is consolidated into the manifest, not published twice.
    for name in archives:
        (args.dist / (name + ".metadata.json")).unlink()


def check_bundle(dist, tag, revision):
    expected = archive_names(tag)
    actual = {path.name for path in dist.iterdir()}
    require(set(expected) | {"manifest.json", FORMULA} <= actual <= set(expected) | {"manifest.json", FORMULA, "SHA256SUMS"},
            "Missing or unexpected verified release assets")
    manifest = json.loads((dist / "manifest.json").read_text())
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1 and
            manifest.get("scanner") == SCANNER, "Unsupported manifest schema or scanner")
    require(manifest["tag"] == tag and manifest["revision"] == revision, "Manifest release identity mismatch")
    require_module_version(tag, manifest["module"])
    repository_name(manifest["repository"])
    require(set(manifest["archives"]) == set(expected), "Manifest target set mismatch")
    for name, metadata in manifest["archives"].items():
        target_os, arch = expected[name]
        require(metadata.get("revision") == revision and metadata.get("modified") is False and
                metadata.get("go_version") == GO_VERSION and metadata.get("tag") == tag and
                metadata.get("os") == target_os and metadata.get("arch") == arch and
                isinstance(metadata.get("binary_sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", metadata["binary_sha256"]),
                f"Manifest binary identity mismatch: {name}")
        require(metadata["archive_sha256"] == digest(dist / name), f"Verified archive changed: {name}")
    require(manifest["homebrew_formula_sha256"] == digest(dist / FORMULA) and
            (dist / FORMULA).read_text(encoding="utf-8") ==
            homebrew_formula(tag, revision, manifest["archives"], manifest["repository"]),
            "Verified Homebrew formula changed")
    if "SHA256SUMS" in actual:
        checksums = "".join(f"{digest(dist / name)}  {name}\n" for name in sorted([*expected, "manifest.json", FORMULA]))
        require((dist / "SHA256SUMS").read_text() == checksums, "Verified checksums changed")
    return manifest


def publish(args):
    manifest = check_bundle(args.dist, args.tag, args.revision)
    require(manifest["repository"] == os.environ["GH_REPO"], "Verified repository differs from publication target")
    require((args.dist / "SHA256SUMS").is_file(), "Missing verified checksums")
    releases = repository_releases()  # API/auth failures fail closed, not mistaken for absent releases.
    require(not any(item["tag_name"] == args.tag for item in releases), "Release exists; refusing overwrite")
    prerelease = not version_key(args.tag)[3]
    notes = Path(os.environ["RUNNER_TEMP"]) / "release-notes.txt"
    source_url = f"https://github.com/{os.environ['GH_REPO']}/blob/{args.revision}"
    notes.write_text(f"## wafme0w {args.tag}\n\n"
                     "**wafw00f's fingerprints. Go speed. Pipeline-native.**\n\n"
                     "A Go CLI and library with 172 catalogue identities, saved-evidence matching, "
                     "and structured output for pipelines.\n\n"
                     f"Source: `{args.revision}`. Compiler: `{GO_VERSION}`.\n\n"
                     f"[Migration from wafw00f]({source_url}/docs/migrating-from-wafw00f.md) · "
                     f"[v2 evidence API]({source_url}/docs/library.md#v2-evidence-api) · "
                     f"[Security policy]({source_url}/SECURITY.md).\n\n"
                     f"All {len(TARGETS)} native archives passed required CI, native package tests, extracted-archive "
                     "offline smoke and binary vulnerability scans. See manifest.json for exact source, "
                     "compiler, binary and archive hashes; SHA256SUMS also covers the manifest and generated "
                     "Homebrew formula. Stable delivery updates "
                     "[Lu1sDV/homebrew-tap](https://github.com/Lu1sDV/homebrew-tap) after its audit and test pass; "
                     "check the release workflow's Homebrew job before installing this version through the tap. "
                     "Synthetic demo captures are examples, not detection-accuracy evidence. "
                     "Use network scanning only where authorized.\n\n"
                     f"Version-specific changes: https://github.com/{os.environ['GH_REPO']}/releases/tag/{args.tag} "
                     "(generated changes below).\n", encoding="utf-8")
    require(remote_revision("origin", args.tag) == args.revision, "Remote tag moved after validation")
    create = ["gh", "release", "create", args.tag, *map(str, sorted(args.dist.iterdir())),
              "--verify-tag", "--target", args.revision, "--draft", "--latest=false",
              "--title", f"wafme0w {args.tag}", "--notes-file", str(notes), "--generate-notes"]
    if prerelease:
        create.append("--prerelease")
    command(*create)
    # Uploads may take time. Recheck immediately before the draft becomes public.
    latest = make_latest(args.tag, repository_releases())
    require(remote_revision("origin", args.tag) == args.revision, "Remote tag moved during asset upload; draft retained")
    command("gh", "release", "edit", args.tag, "--draft=false", f"--latest={str(latest).lower()}")


def published_assets(item):
    expected = archive_names(item["tag_name"])
    assets = [asset for asset in item["assets"] if asset["name"].startswith("wafme0w_")]
    names = {asset["name"] for asset in assets}
    legacy = set(archive_names(item["tag_name"], LEGACY_TARGETS))
    valid_names = names == set(expected) or (version_key(item["tag_name"])[0] < 2 and names == legacy)
    require(len(assets) == len(names) and valid_names,
            f"Missing or unexpected published archives: {item['tag_name']}")
    require(all(type(asset["size"]) is int and 0 < asset["size"] <= MAX_ARCHIVE_BYTES for asset in assets),
            f"Published archive size exceeds limit: {item['tag_name']}")
    return {asset["name"]: asset["size"] for asset in assets}


def scan_published(args):
    selected = supported_releases(repository_releases())
    require(selected, "No supported published SemVer archives found; release maintenance requires explicit review")
    assets = {item["tag_name"]: published_assets(item) for item in selected}
    require(sum(size for sizes in assets.values() for size in sizes.values()) <=
            2 * len(TARGETS) * MAX_ARCHIVE_BYTES, "Supported archives exceed aggregate download limit")
    safe = True
    for item in selected:
        tag = item["tag_name"]
        print(f"Scanning supported published release {tag} independently of current source", flush=True)
        with tempfile.TemporaryDirectory(prefix="wafme0w-published-") as temporary:
            dist = Path(temporary)
            command("gh", "release", "download", tag, "--pattern", "wafme0w_*", "--dir", str(dist))
            expected = assets[tag]
            require({path.name for path in dist.iterdir()} == set(expected), f"Missing or unexpected published archives: {tag}")
            require(all((dist / name).stat().st_size == size <= MAX_ARCHIVE_BYTES
                        for name, size in expected.items()), f"Published archive size changed after preflight: {tag}")
            for name in sorted(expected):
                with tempfile.TemporaryDirectory(prefix="wafme0w-published-binary-") as extracted:
                    binary = extract_archive(dist / name, Path(extracted))
                    safe = scan_binary(binary, args.reports / (name + ".govulncheck.txt")) and safe
    require(safe, "Supported published binaries have vulnerabilities; source fixes do not remediate existing releases")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--tag", required=True)
    subparsers.add_parser("ci-tag", help="Print a CI smoke tag matching this checkout's module major")
    package_parser = subparsers.add_parser("package")
    package_parser.add_argument("--binary", type=Path, required=True)
    package_parser.add_argument("--os", required=True)
    package_parser.add_argument("--arch", required=True)
    for mode in (package_parser, subparsers.add_parser("verify"), subparsers.add_parser("publish")):
        mode.add_argument("--tag", required=True)
        mode.add_argument("--revision", required=True)
        mode.add_argument("--dist", type=Path, default=Path("dist"))
    subparsers.choices["verify"].add_argument("--reports", type=Path, default=Path("security-reports"))
    published_parser = subparsers.add_parser("scan-published")
    published_parser.add_argument("--reports", type=Path, default=Path("security-reports"))
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.tag)
    elif args.mode == "ci-tag":
        print(ci_tag())
    else:
        {"package": package, "verify": verify, "publish": publish,
         "scan-published": scan_published}[args.mode](args)


if __name__ == "__main__":
    main()
