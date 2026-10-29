#!/usr/bin/env python3
"""Offline release checks (Python 3.12+, standard library only).

    python3 tools/smoke.py archive dist/wafme0w_VERSION_linux_amd64.tar.gz
    python3 tools/smoke.py docker wafme0w:ci --runtime podman

Archives are extracted and executed in a temporary directory outside the checkout.
Container checks use only synthetic captures, no network, a read-only root filesystem
and a non-root user. The image's default user is not changed: mounted report
ownership remains the caller's choice through docker/podman --user.
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
        require("wafme0w " + record["provenance"]["program_version"] == version, record)


def smoke(command, work, expected_version=None, require_vcs=False):
    initial_files = set(work.iterdir())
    help_result = run([*command, "--help"], work)
    require("--evidence" in help_result.stdout, "Help omitted capture support")
    version = run([*command, "--version"], work).stdout.strip()
    require(version.startswith("wafme0w ") and "\n" not in version, version)
    if require_vcs:
        require(version != "wafme0w devel", "Archive lacks embedded build/VCS identity")
    if expected_version is not None:
        require(version == "wafme0w " + expected_version, version)

    args = ["--evidence", CAPTURE.as_posix(), "--jsonl"]
    normal = records_from(run([*command, *args], work).stdout)
    check_records(normal, version)
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
    print(f"{version}: help, captures, human tables, JSONL, strict exit and atomic reports passed")


def extract_archive(archive, work):
    archive_size = archive.stat().st_size
    require(0 < archive_size <= MAX_ARCHIVE_BYTES, "Archive exceeds compressed byte limit")
    binary = "wafme0w.exe" if archive.suffix == ".zip" else "wafme0w"
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
    with tempfile.TemporaryDirectory(prefix="wafme0w-archive-") as temporary:
        work = Path(temporary)
        binary = extract_archive(archive, work)
        smoke([str(binary)], work, expected_version, require_vcs=True)


def smoke_cancellation(runtime, command, image, work):
    name = "wafme0w-smoke-" + uuid.uuid4().hex
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


def smoke_docker(image, runtime, expected_version):
    with tempfile.TemporaryDirectory(prefix="wafme0w-container-") as temporary:
        work = Path(temporary)
        # Prove ordinary captures/reports need neither root nor a writable image.
        work.chmod(0o777)
        (work / CAPTURE).parent.mkdir(parents=True)
        shutil.copyfile(Path(__file__).resolve().parents[1] / CAPTURE, work / CAPTURE)
        shutil.copyfile(Path(__file__).resolve().parents[1] / "LICENSE.md", work / "LICENSE.md")
        uid = getattr(os, "getuid", lambda: 65532)() or 65532
        gid = getattr(os, "getgid", lambda: 65532)() or 65532
        command = [
            *runtime, "run", "--rm", "--network", "none", "--read-only",
            "--user", f"{uid}:{gid}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--security-opt", "label=disable",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,mode=1777",
            "--mount", f"type=bind,source={work},target=/smoke", "--workdir", "/smoke",
        ]
        if Path(runtime[0]).name == "podman":
            # Rootless Podman's default subordinate IDs cannot read host-created
            # files owned by this user or let this user read mode-0600 reports.
            command.extend(["--userns", "keep-id"])
        name = "wafme0w-smoke-" + uuid.uuid4().hex
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
        subparser.add_argument("--version", help="Expected embedded program version, not the release tag")
    args = parser.parse_args()
    if args.mode == "archive":
        smoke_archive(args.path.resolve(), args.version)
    else:
        smoke_docker(args.image, shlex.split(args.runtime), args.version)


if __name__ == "__main__":
    main()
