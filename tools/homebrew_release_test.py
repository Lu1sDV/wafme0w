"""Offline checks for verified, monotonic and conflict-safe Homebrew publication."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import homebrew_release
import release


SOURCE = "example/wafmeow"
TAP = "example/homebrew-tap"
TAG = "v2.0.1"
REVISION = "b" * 40


def blob_sha(content):
    return hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()


def formula(tag, revision=REVISION, checksum="d" * 64):
    archives = {name: {"archive_sha256": checksum} for name in release.archive_names(tag)}
    return release.homebrew_formula(tag, revision, archives, SOURCE)


def tap_file(content):
    data = content.encode("utf-8")
    return {"type": "file", "path": homebrew_release.FORMULA_PATH,
            "size": len(data), "encoding": "base64", "sha": blob_sha(data),
            "content": base64.b64encode(data).decode("ascii")}


class HomebrewReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.dist = Path(self.temporary.name)
        archives = {}
        for name, (target_os, arch) in release.archive_names(TAG).items():
            path = self.dist / name
            path.write_bytes(name.encode())
            archives[name] = {"tag": TAG, "revision": REVISION, "os": target_os, "arch": arch,
                              "program_version": TAG,
                              "archive_sha256": release.digest(path), "binary_sha256": "d" * 64,
                              "go_version": release.GO_VERSION, "modified": False}
        self.formula = release.homebrew_formula(TAG, REVISION, archives, SOURCE)
        (self.dist / release.FORMULA).write_text(self.formula)
        manifest = {"schema_version": 1, "scanner": release.SCANNER, "tag": TAG,
                    "revision": REVISION, "module": SOURCE + "/v2", "repository": SOURCE,
                    "archives": archives, "homebrew_formula_sha256": release.digest(self.dist / release.FORMULA)}
        (self.dist / "manifest.json").write_text(json.dumps(manifest))
        (self.dist / "SHA256SUMS").write_text("".join(
            f"{release.digest(path)}  {path.name}\n" for path in sorted(self.dist.iterdir())))
        self.published = {"tag_name": TAG, "draft": False, "prerelease": False,
                          "assets": [{"name": path.name, "state": "uploaded", "size": path.stat().st_size,
                                      "digest": "sha256:" + release.digest(path)}
                                     for path in self.dist.iterdir()]}
        self.pages = [[self.published]]
        self.metadata = {"full_name": TAP, "permissions": {"push": True}, "default_branch": "main"}
        self.current = tap_file(formula("v2.0.0", "a" * 40))
        self.args = SimpleNamespace(tag=TAG, revision=REVISION, dist=self.dist, tap=TAP)
        self.calls = []
        self.api_error = None
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"GH_REPO": SOURCE, "GH_TOKEN": "source-only-token",
                                "HOMEBREW_TAP_TOKEN": "tap-only-token"}).start()
        self.api = patch.object(homebrew_release, "github_api", side_effect=self.fake_api).start()
        self.remote = patch.object(release, "remote_revision", return_value=REVISION).start()

    def fake_api(self, path, *, tap=False, payload=None, paginate=False, allow_missing=False):
        self.calls.append((path, tap, payload, paginate))
        if payload is not None:
            if self.api_error:
                raise self.api_error
            self.assertEqual(path, f"repos/{TAP}/contents/Formula/wafmeow.rb")
            self.assertTrue(tap)
            content = base64.b64decode(payload["content"], validate=True)
            return {"content": {"sha": blob_sha(content)}}
        if path == f"repos/{TAP}":
            self.assertTrue(tap)
            return copy.deepcopy(self.metadata)
        if path == f"repos/{TAP}/contents/Formula/wafmeow.rb?ref=main":
            self.assertTrue(tap)
            self.assertTrue(allow_missing)
            return None if self.current is None else copy.deepcopy(self.current)
        self.assertEqual(path, f"repos/{SOURCE}/releases?per_page=100")
        self.assertFalse(tap)
        self.assertTrue(paginate)
        return copy.deepcopy(self.pages)

    def writes(self):
        return [payload for _, _, payload, _ in self.calls if payload is not None]

    def test_publishes_exact_verified_formula_with_observed_sha(self):
        homebrew_release.publish(self.args)
        self.assertEqual(len(self.writes()), 1)
        payload = self.writes()[0]
        self.assertEqual(payload["sha"], self.current["sha"])
        self.assertEqual(payload["branch"], "main")
        self.assertEqual(payload["message"], "wafmeow v2.0.1")
        self.assertEqual(base64.b64decode(payload["content"]).decode(), self.formula)
        self.remote.assert_called_once_with("origin", TAG)

    def test_first_publication_creates_the_formula_without_a_previous_blob(self):
        self.current = None
        homebrew_release.publish(self.args)
        writes = self.writes()
        self.assertEqual(len(writes), 1)
        self.assertNotIn("sha", writes[0])
        self.assertEqual(base64.b64decode(writes[0]["content"]).decode("utf-8"), self.formula)

    def test_exact_current_formula_is_an_idempotent_retry(self):
        self.current = tap_file(self.formula)
        homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])
        self.assertTrue(any(paginate for _, _, _, paginate in self.calls))

    def test_refuses_downgrade_and_same_version_replacement(self):
        for current in (formula("v2.1.0"), formula(TAG, checksum="e" * 64)):
            with self.subTest(current=current[:80]):
                self.current = tap_file(current)
                with self.assertRaisesRegex(ValueError, "downgrade or replace"):
                    homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_refuses_manual_tap_changes_without_evaluating_ruby(self):
        self.current = tap_file(formula("v2.0.0") + 'system("false")\n')
        with self.assertRaisesRegex(ValueError, "manual or unrecognized"):
            homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_conflict_fails_without_refetching_sha_or_retrying(self):
        self.api_error = subprocess.CalledProcessError(1, ["gh", "api"], stderr="HTTP 409 conflict")
        with self.assertRaises(subprocess.CalledProcessError):
            homebrew_release.publish(self.args)
        self.assertEqual(len(self.writes()), 1)
        self.assertEqual(self.writes()[0]["sha"], self.current["sha"])
        self.assertEqual(sum("contents/" in path and payload is None
                             for path, _, payload, _ in self.calls), 1)

    def test_fails_when_published_release_is_not_current_stable(self):
        self.pages.append([{"tag_name": "v2.1.0", "draft": False, "prerelease": False}])
        with self.assertRaisesRegex(ValueError, "highest published stable"):
            homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_newer_draft_and_prerelease_do_not_block_stable_delivery(self):
        self.pages.append([{"tag_name": "v2.1.0", "draft": True, "prerelease": False},
                           {"tag_name": "v3.0.0-rc.1", "draft": False, "prerelease": True}])
        homebrew_release.publish(self.args)
        self.assertEqual(len(self.writes()), 1)

    def test_unpublished_draft_cannot_update_tap(self):
        self.published["draft"] = True
        with self.assertRaisesRegex(ValueError, "No published stable"):
            homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_prerelease_rejected_before_api_or_bundle_access(self):
        self.args.tag = "v2.0.1-rc.1"
        with self.assertRaisesRegex(ValueError, "Prereleases"):
            homebrew_release.publish(self.args)
        self.api.assert_not_called()

    def test_corrupt_formula_fails_before_tap_access(self):
        (self.dist / release.FORMULA).write_text(self.formula + 'system("false")\n')
        with self.assertRaisesRegex(ValueError, "formula changed"):
            homebrew_release.publish(self.args)
        self.api.assert_not_called()

    def test_missing_checksums_fail_before_tap_access(self):
        (self.dist / "SHA256SUMS").unlink()
        with self.assertRaisesRegex(ValueError, "Missing verified checksums"):
            homebrew_release.publish(self.args)
        self.api.assert_not_called()

    def test_remote_tag_move_blocks_publication(self):
        self.remote.return_value = "c" * 40
        with self.assertRaisesRegex(ValueError, "tag moved"):
            homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_published_digest_size_and_state_must_match_verified_bytes(self):
        original = copy.deepcopy(self.published["assets"][0])
        for key, value in (("digest", "sha256:" + "0" * 64), ("size", 0), ("state", "starter")):
            with self.subTest(key=key):
                self.published["assets"][0] = {**original, key: value}
                with self.assertRaisesRegex(ValueError, "differs from verified bytes"):
                    homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_missing_published_asset_blocks_tap(self):
        self.published["assets"].pop()
        with self.assertRaisesRegex(ValueError, "asset set"):
            homebrew_release.publish(self.args)
        self.assertEqual(self.writes(), [])

    def test_preflight_requires_push_permission_and_canonical_file(self):
        homebrew_release.check_access(TAP)
        self.assertEqual(self.writes(), [])
        self.remote.assert_not_called()
        self.metadata["permissions"]["push"] = False
        with self.assertRaisesRegex(ValueError, "permission to push"):
            homebrew_release.check_access(TAP)

    def test_tap_blob_sha_is_bound_to_received_formula(self):
        self.current["sha"] = "c" * 40
        with self.assertRaisesRegex(ValueError, "blob identity"):
            homebrew_release.check_access(TAP)
        self.assertEqual(self.writes(), [])

    def test_verify_only_never_uses_tap_api_or_token(self):
        with patch.dict(os.environ, {"HOMEBREW_TAP_TOKEN": ""}):
            homebrew_release.verify_only(self.args)
        self.assertTrue(self.calls)
        self.assertTrue(all(not tap and payload is None for _, tap, payload, _ in self.calls))


class HomebrewWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tap = self.root / "tap checkout"
        (self.tap / "Formula").mkdir(parents=True)
        self.installed_formula = self.tap / homebrew_release.FORMULA_PATH
        self.installed_formula.write_text(formula("v2.0.0", "a" * 40))
        (self.root / "dist").mkdir()
        self.candidate = self.root / "dist" / release.FORMULA
        self.candidate.write_text(formula(TAG))
        self.log = self.root / "brew.jsonl"
        binary_directory = self.root / "bin"
        binary_directory.mkdir()
        stub = binary_directory / "brew"
        stub.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''\
            import json
            import os
            from pathlib import Path
            import sys

            arguments = sys.argv[1:]
            with Path(os.environ["WAFMEOW_TEST_BREW_LOG"]).open("a") as log:
                log.write(json.dumps(arguments) + "\\n")
            tap = Path(os.environ["WAFMEOW_TEST_TAP"])
            canonical = "Lu1sDV/tap/wafmeow"
            commands = {
                "tap": ["tap", "Lu1sDV/tap", "https://github.com/Lu1sDV/homebrew-tap.git"],
                "--repository": ["--repository", "Lu1sDV/tap"],
                "trust": ["trust", "--formula", canonical],
                "audit": ["audit", "--strict", "--online", canonical],
                "install": ["install", "--formula", canonical],
                "test": ["test", canonical],
            }
            command = arguments[0] if arguments else ""
            if arguments != commands.get(command):
                raise SystemExit("unexpected or unscoped brew invocation: " + repr(arguments))
            if "HOMEBREW_NO_REQUIRE_TAP_TRUST" in os.environ:
                raise SystemExit("global tap trust bypass is forbidden")
            if command in ("trust", "audit", "install", "test"):
                if (tap / "Formula/wafmeow.rb").read_bytes() != Path(os.environ["WAFMEOW_TEST_FORMULA"]).read_bytes():
                    raise SystemExit("verified formula bytes must be copied before trust or evaluation")
            trusted = tap / "formula-trusted"
            if command in ("audit", "install", "test") and not trusted.exists():
                raise SystemExit("formula must be trusted before " + command)
            if command == os.environ.get("WAFMEOW_TEST_BREW_FAIL"):
                raise SystemExit("owned " + command + " failure")
            if command == "--repository":
                print(tap)
            elif command == "trust":
                trusted.write_text(canonical)
            '''), encoding="utf-8")
        stub.chmod(0o755)
        self.environment = {
            "PATH": str(binary_directory) + os.pathsep + os.defpath,
            "WAFMEOW_TEST_TAP": str(self.tap),
            "WAFMEOW_TEST_FORMULA": str(self.candidate),
            "WAFMEOW_TEST_BREW_LOG": str(self.log),
        }
        workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("HOMEBREW_NO_REQUIRE_TAP_TRUST", workflow)
        step = workflow.split("      - name: Audit and test the candidate formula against published archives\n", 1)[1].split("\n      - ", 1)[0]
        self.script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        self.commands = [
            ["tap", "Lu1sDV/tap", "https://github.com/Lu1sDV/homebrew-tap.git"],
            ["--repository", "Lu1sDV/tap"],
            ["trust", "--formula", "Lu1sDV/tap/wafmeow"],
            ["audit", "--strict", "--online", "Lu1sDV/tap/wafmeow"],
            ["install", "--formula", "Lu1sDV/tap/wafmeow"],
            ["test", "Lu1sDV/tap/wafmeow"],
        ]

    def workflow(self, failure=""):
        # Execute the checked-in shell step with an owned, stateful brew stub.
        # No Ruby, Homebrew, network access, installs or publication are involved.
        self.log.unlink(missing_ok=True)
        (self.tap / "formula-trusted").unlink(missing_ok=True)
        self.installed_formula.write_text(formula("v2.0.0", "a" * 40))
        result = subprocess.run([shutil.which("bash"), "--noprofile", "--norc", "-euo", "pipefail", "-c", self.script],
                                cwd=self.root, env={**self.environment, "WAFMEOW_TEST_BREW_FAIL": failure},
                                capture_output=True, text=True, timeout=15)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        return result, calls

    def test_workflow_trusts_only_copied_formula_before_audit(self):
        result, calls = self.workflow()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, self.commands)
        self.assertEqual(self.installed_formula.read_bytes(), self.candidate.read_bytes())

    def test_workflow_propagates_trust_and_evaluation_failures(self):
        for command in ("trust", "audit", "install", "test"):
            with self.subTest(command=command):
                result, calls = self.workflow(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("owned " + command + " failure", result.stderr)
                position = next(index for index, arguments in enumerate(self.commands) if arguments[0] == command)
                self.assertEqual(calls, self.commands[:position + 1])


class GitHubCredentialTests(unittest.TestCase):
    def test_api_tokens_are_separate_and_payload_uses_stdin(self):
        with patch.dict(os.environ, {"GH_TOKEN": "source-secret", "HOMEBREW_TAP_TOKEN": "tap-secret"}), \
                patch.object(subprocess, "run", return_value=SimpleNamespace(stdout='{"ok":true}')) as run:
            homebrew_release.github_api("repos/example/source")
            source_call = run.call_args
            self.assertEqual(source_call.kwargs["env"]["GH_TOKEN"], "source-secret")
            self.assertNotIn("HOMEBREW_TAP_TOKEN", source_call.kwargs["env"])
            homebrew_release.github_api("repos/example/tap/contents/Formula/wafmeow.rb", tap=True,
                                        payload={"content": "encoded", "sha": "b" * 40})
            tap_call = run.call_args
            self.assertEqual(tap_call.kwargs["env"]["GH_TOKEN"], "tap-secret")
            self.assertNotIn("HOMEBREW_TAP_TOKEN", tap_call.kwargs["env"])
            self.assertEqual(json.loads(tap_call.kwargs["input"])["content"], "encoded")
            self.assertNotIn("source-secret", repr(tap_call.args))
            self.assertNotIn("tap-secret", repr(tap_call.args))

    def test_missing_tap_token_fails_before_starting_gh(self):
        with patch.dict(os.environ, {"HOMEBREW_TAP_TOKEN": ""}), patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "HOMEBREW_TAP_TOKEN"):
                homebrew_release.github_api("repos/example/tap", tap=True)
            run.assert_not_called()

    def test_api_failure_reports_status_without_credential_or_debug_output(self):
        error = subprocess.CalledProcessError(1, ["gh", "api"], stderr="tap-secret debug output (HTTP 403)")
        with patch.dict(os.environ, {"HOMEBREW_TAP_TOKEN": "tap-secret"}), \
                patch.object(subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(ValueError, "GitHub tap API request failed \\(HTTP 403\\)") as caught:
                homebrew_release.github_api("repos/example/tap", tap=True)
            self.assertNotIn("tap-secret", str(caught.exception))
            self.assertNotIn("debug", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
