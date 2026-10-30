"""Offline benchmark provenance checks; no Go build, browser, or network access."""

from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import reproduce_benchmark as benchmark


class ReproductionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "source"
        (self.root / benchmark.CORPUS).parent.mkdir(parents=True)
        (self.root / benchmark.CORPUS).write_text(json.dumps({
            "profile": "shared-products", "cases": [{"kind": "synthetic-conformance"}],
        }), encoding="utf-8")
        (self.root / benchmark.REQUIREMENTS).write_text("wafw00f==2.4.2\n", encoding="utf-8")
        self.output = self.base / "reproduction"
        self.revision = "a" * 40
        self.final_revision = self.revision
        self.initial_status = self.final_status = ""
        self.final_status_error = None
        self.binary_identity = self.identity(self.revision, "false")
        self.build_error = None
        self.benchmark_exit = 0
        self.benchmark_calls = self.verify_calls = 0
        self.status_calls = self.revision_calls = 0
        self.ignored = False
        self.python_commands = []
        self.python_packages = {"wafw00f": "2.4.2"}

    @staticmethod
    def identity(revision, modified):
        return ("offlinebench: go1.27.3\n"
                f"\tbuild\tvcs.revision={revision}\n"
                f"\tbuild\tvcs.modified={modified}\n")

    def fake_command(self, arguments, **_kwargs):
        if arguments == ["git", "status", "--porcelain=v1", "--untracked-files=all"]:
            self.status_calls += 1
            if self.status_calls == 1:
                return self.initial_status
            if self.final_status_error is not None:
                raise self.final_status_error
            return self.final_status
        if arguments == ["git", "rev-parse", "HEAD"]:
            self.revision_calls += 1
            return self.revision if self.revision_calls == 1 else self.final_revision
        if arguments[1:4] == ["-I", "-B", "-c"]:
            self.python_commands.append(arguments)
            return json.dumps({"executable": arguments[0], "version": "3.12.0",
                               "packages": self.python_packages})
        if arguments[:3] == ["go", "env", "-json"]:
            return json.dumps({"GOVERSION": "go1.27.3", "GOOS": "linux", "GOARCH": "amd64"})
        if arguments[:2] == ["go", "build"]:
            if self.build_error is not None:
                raise self.build_error
            Path(arguments[arguments.index("-o") + 1]).write_bytes(b"synthetic test executable")
            return ""
        if arguments[:3] == ["go", "version", "-m"]:
            return self.binary_identity
        if "-verify-run" in arguments:
            self.verify_calls += 1
            self.assertTrue((self.output / "run/run-manifest.json").is_file())
            return "verified synthetic test generation"
        self.fail(f"Unexpected external command: {arguments}")

    def fake_process(self, arguments, **kwargs):
        if arguments[:3] == ["git", "check-ignore", "--quiet"]:
            return subprocess.CompletedProcess(arguments, 0 if self.ignored else 1)
        self.assertEqual(arguments[0], str(self.output / "offlinebench"))
        self.benchmark_calls += 1
        if self.benchmark_exit:
            kwargs["stderr"].write("network isolation canary failed: namespace denied\n")
        else:
            run = self.output / "run"
            run.mkdir()
            (run / "run-manifest.json").write_text("{\"fixture\":true}\n", encoding="utf-8")
        return subprocess.CompletedProcess(arguments, self.benchmark_exit)

    def run_wrapper(self, python=None):
        with ExitStack() as patches:
            patches.enter_context(patch.object(benchmark, "ROOT", self.root))
            patches.enter_context(patch.object(benchmark, "command", side_effect=self.fake_command))
            patches.enter_context(patch.object(benchmark.subprocess, "run", side_effect=self.fake_process))
            patches.enter_context(patch.object(benchmark.platform, "system", return_value="Linux"))
            patches.enter_context(patch.object(benchmark.os, "sched_getaffinity", return_value={0}, create=True))
            patches.enter_context(patch.object(benchmark.shutil, "which", return_value="/test/tool"))
            patches.enter_context(patch.object(sys, "argv", [
                "reproduce_benchmark.py", "--wafw00f-python", str(python or sys.executable),
                "--output", str(self.output),
            ]))
            patches.enter_context(redirect_stdout(io.StringIO()))
            patches.enter_context(redirect_stderr(io.StringIO()))
            benchmark.main()

    def metadata(self):
        return json.loads((self.output / "reproduction.json").read_text(encoding="utf-8"))

    def test_success_records_verified_generation_and_both_source_checks(self):
        self.run_wrapper()
        metadata = self.metadata()
        self.assertTrue(metadata["complete"])
        self.assertTrue(metadata["source_clean_at_start"])
        self.assertTrue(metadata["source_clean_at_finish"])
        self.assertEqual(metadata["revision_at_finish"], self.revision)
        self.assertEqual((self.benchmark_calls, self.verify_calls), (1, 1))
        manifest = (self.output / "run/run-manifest.json").read_bytes()
        self.assertEqual(metadata["run_manifest_sha256"], hashlib.sha256(manifest).hexdigest())
        self.assertIn("finished_at", metadata)

    def test_dirty_binary_is_rejected_before_benchmark(self):
        self.binary_identity = self.identity(self.revision, "true")
        with self.assertRaisesRegex(RuntimeError, "vcs.modified=false"):
            self.run_wrapper()
        self.assertFalse(self.metadata()["complete"])
        self.assertEqual(self.benchmark_calls, 0)

    def test_wrong_revision_is_rejected_before_benchmark(self):
        self.binary_identity = self.identity("b" * 40, "false")
        with self.assertRaisesRegex(RuntimeError, "starting revision"):
            self.run_wrapper()
        self.assertFalse(self.metadata()["complete"])
        self.assertEqual(self.benchmark_calls, 0)

    def test_missing_vcs_identity_is_rejected_before_benchmark(self):
        self.binary_identity = "offlinebench: go1.27.3\n"
        with self.assertRaises(RuntimeError):
            self.run_wrapper()
        self.assertFalse(self.metadata()["complete"])
        self.assertEqual(self.benchmark_calls, 0)

    def test_failed_build_keeps_diagnostics_and_final_source_state(self):
        self.build_error = subprocess.CalledProcessError(
            2, ["go", "build"], output="build stdout", stderr="compiler failure details")
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_wrapper()
        metadata = self.metadata()
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["error"]["returncode"], 2)
        self.assertEqual(metadata["error"]["stdout"], "build stdout")
        self.assertEqual(metadata["error"]["stderr"], "compiler failure details")
        self.assertTrue(metadata["source_clean_at_finish"])
        self.assertIn("finished_at", metadata)
        self.assertEqual(self.benchmark_calls, 0)

    def test_new_revision_at_finish_invalidates_successful_run(self):
        self.final_revision = "b" * 40
        with self.assertRaisesRegex(RuntimeError, "Source verification failed"):
            self.run_wrapper()
        metadata = self.metadata()
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["revision_at_finish"], self.final_revision)
        self.assertEqual(metadata["benchmark_exit_code"], 0)
        self.assertIn("source_state_error", metadata)

    def test_dirty_finish_invalidates_successful_run(self):
        self.final_status = " M pkg/wafmeow/matcher.go\n"
        with self.assertRaisesRegex(RuntimeError, "Source verification failed"):
            self.run_wrapper()
        self.assertFalse(self.metadata()["complete"])
        self.assertFalse(self.metadata()["source_clean_at_finish"])

    def test_failed_final_inspection_cannot_approve_results(self):
        self.final_status_error = subprocess.CalledProcessError(
            128, ["git", "status"], stderr=b"repository became unavailable")
        with self.assertRaisesRegex(RuntimeError, "Source verification failed"):
            self.run_wrapper()
        metadata = self.metadata()
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["source_state_error"]["stderr"], "repository became unavailable")

    def test_isolation_failure_is_retained_and_never_verified_as_success(self):
        self.benchmark_exit = 1
        with self.assertRaisesRegex(RuntimeError, "Benchmark failed"):
            self.run_wrapper()
        metadata = self.metadata()
        self.assertFalse(metadata["complete"])
        self.assertEqual(metadata["benchmark_exit_code"], 1)
        self.assertEqual(self.verify_calls, 0)
        self.assertIn("namespace denied", (self.output / "stderr.txt").read_text())

    def test_untracked_source_is_rejected_before_output_creation(self):
        self.initial_status = "?? unexpected.go\n"
        with self.assertRaisesRegex(RuntimeError, "clean committed checkout"):
            self.run_wrapper()
        self.assertFalse(self.output.exists())
        self.assertEqual(self.benchmark_calls, 0)

    def test_unpinned_python_environment_is_rejected(self):
        self.python_packages["wafw00f"] = "0.0.0"
        with self.assertRaisesRegex(RuntimeError, "Pinned Python package differs"):
            self.run_wrapper()
        self.assertFalse(self.output.exists())

    def test_venv_executable_symlink_path_is_preserved(self):
        python = self.base / "venv/bin/python"
        python.parent.mkdir(parents=True)
        try:
            python.symlink_to(Path(sys.executable).resolve())
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        self.run_wrapper(python)
        self.assertEqual(self.python_commands[0][0], str(python))
        command = self.metadata()["benchmark_command"]
        self.assertEqual(command[command.index("-wafw00f-python") + 1], str(python))

    def test_ignored_output_inside_checkout_is_supported(self):
        self.output = self.root / "benchmarks/fixture-run"
        self.ignored = True
        self.run_wrapper()
        self.assertTrue(self.metadata()["complete"])

    def test_nonignored_checkout_output_is_rejected(self):
        self.output = self.root / "accidental-source-output"
        with self.assertRaises(SystemExit) as stopped:
            self.run_wrapper()
        self.assertEqual(stopped.exception.code, 2)
        self.assertFalse(self.output.exists())

    def test_git_metadata_output_is_rejected_even_when_ignored(self):
        self.output = self.root / ".git/benchmark-output"
        self.ignored = True
        with self.assertRaises(SystemExit) as stopped:
            self.run_wrapper()
        self.assertEqual(stopped.exception.code, 2)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
