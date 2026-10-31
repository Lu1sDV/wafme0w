#!/usr/bin/env python3
"""Offline release checks (Python 3.12+, standard library only).

    python3 tools/smoke.py archive dist/wafmeow_VERSION_linux_amd64.tar.gz
    python3 tools/smoke.py docker wafmeow:ci --runtime podman

Archives are extracted and executed in a temporary directory outside the checkout.
Container checks use only synthetic captures, no network, and the image's default
non-root identity, including writable-image permission checks. Hardened runs add
a read-only root filesystem and private tmpfs; a host-UID override separately
checks mounted report ownership.
"""

import argparse
import gzip
import json
import os
from pathlib import Path
import queue
import shlex
import shutil
import subprocess
import struct
import tarfile
import tempfile
import threading
import uuid
import zipfile


CAPTURE = Path("assets/demo/captures.jsonl")
PRODUCT = "Cloudflare (Cloudflare Inc.)"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_MEMBER_TOTAL_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 160 * 1024 * 1024


class _BoundedArchiveReader:
    def __init__(self, source):
        self.source = source
        self.remaining = MAX_EXPANDED_BYTES

    def read(self, size):
        data = self.source.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        require(self.remaining >= 0, "Archive exceeds expanded byte limit")
        return data


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run(command, cwd, expected=0, **kwargs):
    result = subprocess.run(
        command, cwd=cwd, capture_output=True, text=True, timeout=45, **kwargs
    )
    require(
        result.returncode == expected,
        f"{command!r}: exit {result.returncode}, expected {expected}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}",
    )
    return result


def records_from(stdout):
    # Every stdout line must be a result, not a banner, progress line or summary.
    records = [json.loads(line) for line in stdout.splitlines()]
    require(all(isinstance(record, dict) for record in records), stdout)
    return records


def check_records(records, version):
    expected = {
        "synthetic-cloudflare": ("complete", {PRODUCT}),
        "synthetic-clean": ("complete", set()),
        "synthetic-truncated": ("incomplete", {PRODUCT}),
    }
    require(len(records) == len(expected), f"Unexpected records: {records!r}")
    require({record["target"] for record in records} == set(expected), records)
    for record in records:
        state, products = expected[record["target"]]
        outcome = record["outcome"]
        require(record["schema_version"] == 1, record)
        require(outcome["state"] == state, record)
        require({match["product"] for match in outcome.get("matches", [])} == products, record)
        require(record["provenance"]["scan_mode"] == "passive", record)
        require("wafmeow " + record["provenance"]["program_version"] == version, record)


def smoke(command, work, expected_version=None, require_vcs=False):
    initial_files = set(work.iterdir())
    help_result = run([*command, "--help"], work)
    require("--evidence" in help_result.stdout, "Help omitted capture support")
    version = run([*command, "--version"], work).stdout.strip()
    require(version.startswith("wafmeow ") and "\n" not in version, version)
    if require_vcs:
        require(version != "wafmeow devel", "Archive lacks embedded build/VCS identity")
    if expected_version is not None:
        require(version == "wafmeow " + expected_version, version)

    args = ["--evidence", CAPTURE.as_posix(), "--jsonl"]
    normal_run = run([*command, *args], work)
    normal = records_from(normal_run.stdout)
    check_records(normal, version)
    require("RUN PLAN  offline native" in normal_run.stderr,
            "Offline JSONL scan omitted the human run plan on stderr")
    silent = run([*command, *args, "--silent"], work)
    require(records_from(silent.stdout) == normal,
            "Silent mode changed the result records")
    require(silent.stderr == "", "Silent mode emitted a run plan or summary")
    human = run([*command, "--evidence", CAPTURE.as_posix(), "--no-colors"], work)
    for record in normal:
        require(record["target"] in human.stdout and record["target"] in human.stderr,
                "Human stream or final table omitted a target")
    require("\x1b" not in human.stdout + human.stderr, "No-color human output contains ANSI")
    strict = records_from(run([
        *command, *args, "--strict", "--output", "report.json"
    ], work, expected=2).stdout)
    check_records(strict, version)
    require(json.loads((work / "report.json").read_text()) == strict,
            "Strict exit did not publish the full report")

    # A mid-input failure must not replace a previously published report.
    sentinel = b"previous report\n"
    (work / "report.json").write_bytes(sentinel)
    (work / "malformed.jsonl").write_bytes((work / CAPTURE).read_bytes() + b"{invalid}\n")
    failed = run([
        *command, "--evidence", "malformed.jsonl", "--jsonl", "--output", "report.json"
    ], work, expected=1)
    check_records(records_from(failed.stdout), version)
    require(failed.stderr.strip(), "Input failure omitted diagnostics")
    require((work / "report.json").read_bytes() == sentinel,
            "Input failure replaced the old report")

    # Force publication, not acquisition, to fail after all results were emitted.
    blocked = work / "blocked.json"
    blocked.mkdir()
    (blocked / "keep").write_bytes(sentinel)
    failed = run([*command, *args, "--output", "blocked.json"], work, expected=1)
    check_records(records_from(failed.stdout), version)
    require(failed.stderr.strip(), "Publication failure omitted diagnostics")
    require((blocked / "keep").read_bytes() == sentinel,
            "Publication failure modified the destination")
    require(set(work.iterdir()) == initial_files | {
        work / "report.json", work / "malformed.jsonl", blocked,
    }, "Report failure left unexpected temporary files")
    print(f"{version}: help, captures, run plan, silent mode, human tables, JSONL, strict exit and atomic reports passed")


def extract_archive(archive, work, binary_stem="wafmeow"):
    archive_size = archive.stat().st_size
    require(0 < archive_size <= MAX_ARCHIVE_BYTES, "Archive exceeds compressed byte limit")
    binary = f"{binary_stem}.exe" if archive.suffix == ".zip" else binary_stem
    expected = {binary, "LICENSE.md", CAPTURE.as_posix()}
    if archive.suffix == ".zip":
        # Bound the directory before ZipFile allocates an object per entry.
        # Release archives have three short names and do not need ZIP64.
        with archive.open("rb") as source:
            footer_start = max(0, archive_size - 65557)
            source.seek(footer_start)
            footer = source.read(65557)
            position = footer.rfind(b"PK\x05\x06")
            require(position >= 0 and position + 22 <= len(footer), "Missing ZIP directory")
            end = struct.unpack_from("<4s4H2LH", footer, position)
            # A maximum-length comment puts the locator outside this window.
            locator_position = footer_start + position - 20
            if locator_position >= 0:
                source.seek(locator_position)
                require(source.read(4) != b"PK\x06\x07", "ZIP64 release archives are unsupported")
        require(end[1:3] == (0, 0) and end[3:5] == (3, 3) and end[5] <= 16384 and
                end[6] + end[5] <= archive_size and
                position + 22 + end[7] == len(footer), "Archive has extra entries or oversized ZIP directory")
        with zipfile.ZipFile(archive) as package:
            members = package.infolist()
            require(len(members) == len(expected) and
                    {member.filename for member in members} == expected,
                    "Archive has missing, duplicate or extra files")
            require(all(not member.is_dir() and 0 <= member.file_size <= MAX_MEMBER_BYTES
                        for member in members), "Invalid archive member size/type")
            require(sum(member.file_size for member in members) <= MAX_MEMBER_TOTAL_BYTES,
                    "Archive exceeds total member byte limit")
            package.extractall(work)
    else:
        total = 0
        seen = set()
        # Bound decompression including extension headers, not just file payloads.
        with gzip.open(archive, "rb") as source, tarfile.open(
                fileobj=_BoundedArchiveReader(source), mode="r|") as package:
            for member in package:
                require(len(seen) < 3 and member.name in expected and member.name not in seen,
                        "Archive has extra or duplicate files")
                require(member.isfile() and 0 <= member.size <= MAX_MEMBER_BYTES,
                        "Invalid archive member size/type")
                total += member.size
                require(total <= MAX_MEMBER_TOTAL_BYTES, "Archive exceeds total member byte limit")
                seen.add(member.name)
                destination = work / member.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                with package.extractfile(member) as contents, destination.open("wb") as output:
                    shutil.copyfileobj(contents, output, length=64 * 1024)
                destination.chmod(member.mode & 0o777)
        require(seen == expected, "Archive has missing files")
    require((work / "LICENSE.md").stat().st_size > 0, "Packaged license is empty")
    return work / binary


def smoke_archive(archive, expected_version):
    with tempfile.TemporaryDirectory(prefix="wafmeow-archive-") as temporary:
        work = Path(temporary)
        binary = extract_archive(archive, work)
        smoke([str(binary)], work, expected_version, require_vcs=True)


def smoke_cancellation(runtime, command, image, work):
    name = "wafmeow-smoke-" + uuid.uuid4().hex
    sentinel = b"previous report\n"
    (work / "cancel.json").write_bytes(sentinel)
    process = subprocess.Popen([
        *command, "--name", name, "-i", image,
        "--evidence", "-", "--jsonl", "--output", "cancel.json",
    ], cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
       stderr=subprocess.PIPE, text=True)
    assert process.stdin is not None and process.stdout is not None
    stdin, stdout = process.stdin, process.stdout
    try:
        # Leave stdin open after one result to exercise PID 1 cancellation while
        # blocked on inherited input, rather than EOF or a completed batch.
        stdin.write((work / CAPTURE).read_text().splitlines()[0] + "\n")
        stdin.flush()
        ready = queue.Queue()
        reader = threading.Thread(target=lambda: ready.put(stdout.readline()), daemon=True)
        reader.start()
        first = ready.get(timeout=30)
        reader.join()
        require(json.loads(first)["target"] == "synthetic-cloudflare", first)
        run([*runtime, "kill", "--signal", "SIGTERM", name], work)
        rest, stderr = process.communicate(timeout=10)
        require(process.returncode == 130,
                f"Cancellation exit={process.returncode}, stdout={first + rest!r}, stderr={stderr!r}")
        require(len(records_from(first + rest)) == 1, "Cancellation polluted stdout")
        require((work / "cancel.json").read_bytes() == sentinel,
                "Cancellation replaced the old report")
        require(not list(work.glob(".cancel.json-*")), "Cancellation leaked a temporary report")
    finally:
        # Also clean up a container if readiness, signaling or an assertion failed.
        try:
            subprocess.run([*runtime, "rm", "--force", name], capture_output=True, timeout=15)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=10)
    print("Container SIGTERM interrupted open stdin without publishing a partial report")


def smoke_default_identity(runtime, command, image, work, expected_version):
    metadata = json.loads(run([*runtime, "image", "inspect", image], work).stdout)
    require(len(metadata) == 1, "Expected exactly one inspected image")
    require(metadata[0]["Config"]["User"] == "65532:65532",
            "Image must default to numeric UID:GID 65532:65532")
    require(metadata[0]["Config"]["WorkingDir"] == "/work", "Image must default to /work")
    version = run([*command, "--rm", image, "--version"], work).stdout.strip()
    require(version.startswith("wafmeow ") and "\n" not in version, version)
    if expected_version is not None:
        require(version == "wafmeow " + expected_version, version)
    capture = (work / CAPTURE).read_text()
    name = "wafmeow-default-" + uuid.uuid4().hex
    try:
        # No --user, mount, tmpfs or read-only flag: exercise image defaults,
        # including its private temporary directory and owned report workdir.
        human = run([
            *command, "--name", name, "-i", image, "--evidence", "-",
            "--no-colors", "--output", "report.json",
        ], work, input=capture)
        rootfs_path = work / "default-rootfs.tar"
        run([*runtime, "export", "--output", str(rootfs_path), name], work)
        with tarfile.open(rootfs_path) as rootfs:
            members = {member.name.removeprefix("./").rstrip("/"): member
                       for member in rootfs.getmembers()}
            report = members["work/report.json"]
            require((report.uid, report.gid) == (65532, 65532),
                    "Report was not written by the inherited default UID:GID")
            require(report.isfile() and report.size <= MAX_MEMBER_BYTES, "Invalid report")
            with rootfs.extractfile(report) as contents:
                records = json.load(contents)
            check_records(records, version)
            for path in ("usr/local/bin/wafmeow", "etc/ssl/certs/ca-certificates.crt", "LICENSE.md"):
                member = members[path]
                require(member.isfile() and member.size > 0 and
                        (member.uid, member.gid) == (0, 0) and member.mode & 0o222 == 0,
                        f"Protected image file is writable or not root-owned: {path}")
            with rootfs.extractfile(members["LICENSE.md"]) as contents:
                require(contents.read() == (work / "LICENSE.md").read_bytes(),
                        "Image license/notices differ from the packaged source license")
            for path in ("usr", "usr/local", "usr/local/bin", "etc", "etc/ssl", "etc/ssl/certs"):
                member = members[path]
                require(member.isdir() and (member.uid, member.gid) == (0, 0) and
                        member.mode & 0o022 == 0, f"Unprotected image directory: {path}")
            for path, mode in (("tmp", 0o700), ("work", 0o750)):
                member = members[path]
                require(member.isdir() and (member.uid, member.gid) == (65532, 65532) and
                        member.mode & 0o777 == mode, f"Incorrect private directory: {path}")
            require(not any(path.startswith("tmp/") for path in members),
                    "Human report spool left temporary files")
        for record in records:
            require(record["target"] in human.stdout and record["target"] in human.stderr,
                    "Default identity omitted human results or final table")
        require("\x1b" not in human.stdout + human.stderr, "No-color output contains ANSI")
        run([*runtime, "rm", name], work)
        # The filesystem is writable here: failures must be Unix permission
        # denials, not merely enforcement of the separate read-only runtime flag.
        for path in ("/blocked.json", "/usr/local/bin/blocked.json", "/etc/ssl/certs/blocked.json"):
            denied = run([
                *command, "--rm", "--name", name, "-i", image,
                "--evidence", "-", "--jsonl", "--output", path,
            ], work, expected=1, input=capture)
            require("permission denied" in denied.stderr.lower(),
                    f"Protected output did not fail with a permission denial: {denied.stderr}")
        for path in ("/usr/local/bin/wafmeow", "/etc/ssl/certs/ca-certificates.crt", "/LICENSE.md"):
            denied = run([
                *command, "--rm", "--name", name, "-i", image,
                "--evidence", "-", "--jsonl", "--diagnostics-journal", path,
            ], work, expected=1, input=capture)
            require("permission denied" in denied.stderr.lower(),
                    f"Protected file did not fail with a permission denial: {denied.stderr}")
        # Podman rejects Docker's tmpfs uid/gid options. Its isolated mounts
        # use sticky permissions; report and spool files remain mode 0600.
        tmp_mode = "mode=0700,uid=65532,gid=65532"
        work_mode = "mode=0750,uid=65532,gid=65532"
        if Path(runtime[0]).name == "podman":
            tmp_mode = work_mode = "mode=1777"
        hardened = run([
            *command, "--rm", "--name", name, "-i", "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size=64m,{tmp_mode}",
            "--tmpfs", f"/work:rw,noexec,nosuid,nodev,size=64m,{work_mode}",
            image, "--evidence", "-", "--jsonl", "--output", "report.json",
        ], work, input=capture)
        check_records(records_from(hardened.stdout), version)
    finally:
        subprocess.run([*runtime, "rm", "--force", name], capture_output=True, timeout=15)
    print(f"{version}: inherited UID:GID, owned reports, private spool and protected image files passed")


def smoke_docker(image, runtime, expected_version):
    with tempfile.TemporaryDirectory(prefix="wafmeow-container-") as temporary:
        work = Path(temporary)
        # Only the explicit host-UID mount tests below use this shared directory;
        # default-identity tests write inside the image's owned /work instead.
        (work / CAPTURE).parent.mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parents[1] / CAPTURE, work / CAPTURE)
        shutil.copyfile(Path(__file__).resolve().parents[1] / "LICENSE.md", work / "LICENSE.md")
        command = [
            *runtime, "run", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--security-opt", "label=disable",
            "--pids-limit", "128", "--memory", "512m", "--cpus", "1",
        ]
        smoke_default_identity(runtime, command, image, work, expected_version)
        work.chmod(0o777)
        uid = getattr(os, "getuid", lambda: 65532)() or 65532
        gid = getattr(os, "getgid", lambda: 65532)() or 65532
        command.extend([
            "--rm", "--read-only", "--user", f"{uid}:{gid}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            "--mount", f"type=bind,source={work},target=/smoke", "--workdir", "/smoke",
        ])
        if Path(runtime[0]).name == "podman":
            # Rootless Podman's default subordinate IDs cannot read host-created
            # files owned by this user or let this user read mode-0600 reports.
            command.extend(["--userns", "keep-id"])
        name = "wafmeow-smoke-" + uuid.uuid4().hex
        try:
            smoke([*command, "--name", name, image], work, expected_version)
        finally:
            # Killing a timed-out runtime client does not stop its container.
            subprocess.run([*runtime, "rm", "--force", name], capture_output=True, timeout=15)
        smoke_cancellation(runtime, command, image, work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    archive = subparsers.add_parser("archive", help="Extract and exercise a native release archive")
    archive.add_argument("path", type=Path)
    container = subparsers.add_parser("docker", help="Exercise a Docker/Podman image without networking")
    container.add_argument("image")
    container.add_argument("--runtime", "--container-runtime", default=os.environ.get("DOCKER", "docker"),
                           help="Container command (default: DOCKER environment variable or docker)")
    for subparser in (archive, container):
        subparser.add_argument("--version", help="Expected embedded program version (the exact tag for release archives)")
    args = parser.parse_args()
    if args.mode == "archive":
        smoke_archive(args.path.resolve(), args.version)
    else:
        smoke_docker(args.image, shlex.split(args.runtime), args.version)


if __name__ == "__main__":
    main()
