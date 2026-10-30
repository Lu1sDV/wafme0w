#!/usr/bin/env python3
"""Reproduce the pinned, network-isolated saved-capture comparison.

Run from a clean committed checkout on Linux with Go, bubblewrap and the pinned
tools/offlinebench/requirements.txt environment installed. Workers replay the
checked-in synthetic corpus; no live target input is accepted.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path("tools/offlinebench/testdata/corpus.json")
REQUIREMENTS = Path("tools/offlinebench/requirements.txt")


def command(arguments, *, environment=None, timeout=60):
    return subprocess.run(arguments, cwd=ROOT, env=environment, check=True,
                          capture_output=True, text=True, timeout=timeout).stdout.strip()


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def source_identity():
    if command(["git", "status", "--porcelain=v1", "--untracked-files=all"]):
        raise RuntimeError("Benchmark requires a clean committed checkout, including untracked source files")
    return command(["git", "rev-parse", "HEAD"])


def validate_binary_identity(identity, revision):
    settings = {}
    for line in identity.splitlines():
        fields = line.strip().split("\t", 1)
        if len(fields) == 2 and fields[0] == "build":
            key, separator, value = fields[1].partition("=")
            if separator:
                settings[key] = value
    if settings.get("vcs.revision") != revision or settings.get("vcs.modified") != "false":
        raise RuntimeError("Built binary must record the starting revision and vcs.modified=false")


def exception_detail(error):
    detail = {"message": str(error), "type": type(error).__name__}
    for name in ("cmd", "returncode", "stdout", "stderr"):
        value = getattr(error, name, None)
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if value is not None:
            detail[name] = value
    return detail


def host_identity():
    cpu_model = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in ("model name", "Hardware"):
                cpu_model = value.strip()
                break
    except OSError:
        pass
    return {"os": platform.system(), "kernel": platform.release(),
            "architecture": platform.machine(), "cpu_model": cpu_model,
            "logical_cpus": os.cpu_count(),
            "allowed_cpus": sorted(os.sched_getaffinity(0)),
            "launcher_gomaxprocs_env": os.environ.get("GOMAXPROCS"),
            "worker_environment": "offlinebench clears inherited environment; Go chooses worker GOMAXPROCS"}


def python_identity(executable):
    # Keep the venv executable's symlink path: resolving it would select the
    # base interpreter and lose the environment being compared.
    script = """import importlib.metadata, json, platform, sys
print(json.dumps({'executable':sys.executable, 'version':platform.python_version(),
 'packages':{d.metadata['Name'].lower().replace('_','-'):d.version
             for d in importlib.metadata.distributions()}}))"""
    observed = json.loads(command([str(executable), "-I", "-B", "-c", script]))
    for line in (ROOT / REQUIREMENTS).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        name, version = line.split("==", 1)
        actual = observed["packages"].get(name.lower().replace("_", "-"))
        if actual != version:
            raise RuntimeError(f"Pinned Python package differs: {name} expected {version}, observed {actual}")
    return observed


def write_metadata(path, value):
    temporary = path.with_suffix(".json.tmp")
    with temporary.open("x", encoding="utf-8") as target:
        json.dump(value, target, indent=2, sort_keys=True)
        target.write("\n")
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wafw00f-python", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path,
                        help="new directory outside the checkout or under ignored benchmarks/")
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--blocks", type=int, default=4)
    arguments = parser.parse_args()
    if platform.system() != "Linux" or not hasattr(os, "sched_getaffinity"):
        parser.error("requires Linux with bubblewrap network namespaces")
    if arguments.iterations < 1 or arguments.blocks < 4 or arguments.blocks % 4:
        parser.error("iterations must be positive and blocks a positive multiple of four")
    if not shutil.which("go") or not shutil.which("bwrap"):
        parser.error("go and bwrap must be installed; isolation is never bypassed")
    python = arguments.wafw00f_python.absolute()
    if not python.is_file():
        parser.error("--wafw00f-python must identify the installed pinned environment")
    output = arguments.output.resolve()
    try:
        relative = output.relative_to(ROOT)
    except ValueError:
        relative = None
    if relative is not None:
        ignored = subprocess.run(["git", "check-ignore", "--quiet", str(relative)], cwd=ROOT).returncode == 0
        if not ignored or ".git" in relative.parts:
            parser.error("output inside the checkout must be ignored; choose benchmarks/<new-run>")
    if output.exists():
        parser.error("output must not exist; choose a new run directory")

    revision = source_identity()
    observed_python = python_identity(python)
    environment = {**os.environ, "GOTOOLCHAIN": "local", "GOWORK": "off",
                   "GOFLAGS": "-mod=readonly", "CGO_ENABLED": "0"}
    go_environment = json.loads(command(["go", "env", "-json", "GOVERSION", "GOOS", "GOARCH",
                                        "GOEXPERIMENT", "CGO_ENABLED", "GOTOOLCHAIN", "GOWORK", "GOFLAGS"],
                                       environment=environment))
    corpus = json.loads((ROOT / CORPUS).read_text())
    metadata = {"schema_version": 1, "complete": False,
                "started_at": datetime.now(timezone.utc).isoformat(),
                "repository": "https://github.com/Lu1sDV/wafmeow", "revision": revision,
                "source_clean_at_start": True, "host": host_identity(), "go": go_environment,
                "python": observed_python,
                "input": {"path": CORPUS.as_posix(), "sha256": digest(ROOT / CORPUS),
                          "profile": corpus["profile"], "cases": len(corpus["cases"]),
                          "kinds": dict(Counter(case["kind"] for case in corpus["cases"])),
                          "selection": "All checked-in reviewed synthetic cases; no sampled live targets"},
                "requirements_sha256": digest(ROOT / REQUIREMENTS),
                "iterations": arguments.iterations, "blocks": arguments.blocks,
                "scope": "Saved-response classifier replay; not live CLI throughput or real-world accuracy"}
    output.mkdir(parents=True, exist_ok=False)
    metadata_path = output / "reproduction.json"
    write_metadata(metadata_path, metadata)
    try:
        binary = output / "offlinebench"
        build = ["go", "build", "-trimpath", "-buildvcs=true", "-o", str(binary), "./cmd/offlinebench"]
        metadata["build_command"] = build
        command(build, environment=environment, timeout=300)
        metadata["binary_sha256"] = digest(binary)
        metadata["binary_identity"] = command(["go", "version", "-m", str(binary)], environment=environment)
        validate_binary_identity(metadata["binary_identity"], revision)
        run = [str(binary), "-wafw00f-python", str(python), "-output", str(output / "run"),
               "-iterations", str(arguments.iterations), "-blocks", str(arguments.blocks),
               "-min-coverage", "1", "-min-accuracy", "1"]
        metadata["benchmark_command"] = run
        write_metadata(metadata_path, metadata)
        with (output / "stdout.txt").open("x") as stdout, (output / "stderr.txt").open("x") as stderr:
            result = subprocess.run(run, cwd=ROOT, env=environment, stdout=stdout, stderr=stderr, timeout=330)
        metadata["benchmark_exit_code"] = result.returncode
        if result.returncode:
            raise RuntimeError(f"Benchmark failed (exit {result.returncode}); inspect {output / 'stderr.txt'}")
        report = command([str(binary), "-verify-run", str(output / "run")], environment=environment)
        metadata["run_manifest_sha256"] = digest(output / "run/run-manifest.json")
        metadata["complete"] = True
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        metadata["error"] = exception_detail(error)
        raise
    finally:
        try:
            final_revision = command(["git", "rev-parse", "HEAD"])
            clean = not command(["git", "status", "--porcelain=v1", "--untracked-files=all"])
            metadata["revision_at_finish"] = final_revision
            metadata["source_clean_at_finish"] = clean
            if final_revision != revision or not clean:
                metadata["source_state_error"] = "Source changed during benchmark; results are not approved for comparison"
                metadata["complete"] = False
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            metadata["source_state_error"] = exception_detail(error)
            metadata["complete"] = False
        metadata["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_metadata(metadata_path, metadata)
    if not metadata["complete"]:
        raise RuntimeError(f"Source verification failed; inspect {metadata_path}")
    print(report)
    print(f"Verified reproduction metadata: {metadata_path}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
