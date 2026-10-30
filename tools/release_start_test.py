"""Offline tests of manual version allocation, ownership, and failure recovery."""

from contextlib import ExitStack
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release
import release_start


REPOSITORY = "owner/wafme0w"
REVISION = "b" * 40
PREVIOUS = "a" * 40
RUN_ID = "1234"


def published(tag, *, draft=False, prerelease=False):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease}


class GitHub:
    """In-memory Git data API with immutable ref creation and fault injection."""

    def __init__(self):
        self.refs = {}
        self.objects = {}
        self.writes = []
        self.main = REVISION
        self.fail_reference = None

    def annotated(self, tag, *, revision=REVISION, run_id=RUN_ID, bump="patch"):
        sha = f"{len(self.objects) + 1:040x}"
        self.objects[sha] = {"sha": sha, "tag": tag,
                             "message": release_start.annotation_message(REPOSITORY, run_id, tag, bump, revision),
                             "object": {"type": "commit", "sha": revision}}
        self.refs["refs/tags/" + tag] = {"ref": "refs/tags/" + tag,
                                        "object": {"type": "tag", "sha": sha}}
        return sha

    def __call__(self, repository, path, **fields):
        if repository != REPOSITORY:
            raise AssertionError(repository)
        if not fields:
            if path == "git/matching-refs/tags/":
                return copy.deepcopy(list(self.refs.values()))
            if path == "git/ref/heads/main":
                return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": self.main}}
            if path.startswith("git/tags/"):
                return copy.deepcopy(self.objects[path[len("git/tags/"):]])
        self.writes.append((path, fields.copy()))
        if path == "git/tags":
            sha = f"{len(self.objects) + 1:040x}"
            result = {"sha": sha, "tag": fields["tag"], "message": fields["message"],
                      "object": {"type": fields["type"], "sha": fields["object"]}}
            self.objects[sha] = result
            return copy.deepcopy(result)
        if path == "git/refs":
            if self.fail_reference == "before":
                raise RuntimeError("reference API unavailable")
            if fields["ref"] in self.refs:
                raise RuntimeError("reference already exists")
            result = {"ref": fields["ref"], "object": {"type": "tag", "sha": fields["sha"]}}
            self.refs[fields["ref"]] = result
            if self.fail_reference == "after":
                raise RuntimeError("response lost after reference creation")
            return copy.deepcopy(result)
        raise AssertionError((path, fields))


class ManualReleaseTests(unittest.TestCase):
    def setUp(self):
        self.github = GitHub()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": REVISION, "GH_REPO": REPOSITORY, "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": "1", "GH_TOKEN": "offline-test-only",
        }))
        self.api = self.stack.enter_context(patch.object(release_start, "api", side_effect=self.github))
        self.releases = self.stack.enter_context(patch.object(
            release, "repository_releases", return_value=[published("v2.0.0")]))
        self.validate = self.stack.enter_context(patch.object(release, "validate_candidate"))
        self.remote = self.stack.enter_context(patch.object(release, "remote_revision", return_value=PREVIOUS))
        self.command = self.stack.enter_context(patch.object(release, "command", return_value=""))
        self.prepare = self.stack.enter_context(patch.object(release, "prepare"))

    def test_default_patch_creates_annotated_tag_for_frozen_dispatch(self):
        self.assertEqual(release_start.start("patch", REVISION), "v2.0.1")
        ref = self.github.refs["refs/tags/v2.0.1"]
        annotation = self.github.objects[ref["object"]["sha"]]
        self.assertEqual(annotation["object"], {"type": "commit", "sha": REVISION})
        self.assertEqual(annotation["message"],
                         release_start.annotation_message(REPOSITORY, RUN_ID, "v2.0.1", "patch", REVISION))
        self.validate.assert_called_once_with("v2.0.1", REVISION)
        self.prepare.assert_called_once_with("v2.0.1", expected_revision=REVISION)

    def test_exact_version_overrides_each_increment_without_calculating_a_bump(self):
        for bump in ("patch", "minor", "major"):
            with self.subTest(bump=bump):
                self.github.refs.clear()
                self.github.objects.clear()
                self.github.writes.clear()
                with patch.object(release_start, "next_version", side_effect=AssertionError("ignored bump")):
                    self.assertEqual(release_start.start(bump, REVISION, version="v2.0.5"), "v2.0.5")
                ref = self.github.refs["refs/tags/v2.0.5"]
                annotation = self.github.objects[ref["object"]["sha"]]
                self.assertEqual(annotation["object"], {"type": "commit", "sha": REVISION})
                self.assertEqual(annotation["message"], release_start.annotation_message(
                    REPOSITORY, RUN_ID, "v2.0.5", "exact", REVISION))
                self.prepare.assert_called_with("v2.0.5", expected_revision=REVISION)

    def test_exact_prerelease_is_supported_without_promoting_stable(self):
        tag = "v2.1.0-rc.1"
        self.assertEqual(release_start.start("patch", REVISION, version=tag), tag)
        self.prepare.assert_called_once_with(tag, expected_revision=REVISION)
        self.assertFalse(release.make_latest(tag, self.releases.return_value))
        self.assertFalse(release_start.validate_request("", tag, "workflow_dispatch", "refs/heads/main"))

    def test_malformed_exact_version_is_rejected_before_any_api_call(self):
        for version in ("2.0.5", "v02.0.5", "v2.0", "v2.0.5+build", "v2.1.0-rc.01",
                        "v2.0.5\n", " v2.0.5", "v2.0.5 ", "v2.0.5;exit", "$(touch sentinel)", " "):
            with self.subTest(version=version), self.assertRaises(ValueError):
                release_start.start("patch", REVISION, version=version)
        self.api.assert_not_called()
        self.releases.assert_not_called()
        self.prepare.assert_not_called()

    def test_exact_version_must_exceed_highest_published_stable_by_semver(self):
        self.releases.return_value = [published("v2.9.0"), published("v2.10.0")]
        for version in ("v1.99.99", "v2.9.9", "v2.10.0", "v2.10.0-rc.1"):
            with self.subTest(version=version), self.assertRaisesRegex(ValueError, "must be newer"):
                release_start.start("patch", REVISION, version=version)
        self.assertEqual(self.github.writes, [])
        self.validate.assert_not_called()
        self.prepare.assert_not_called()

    def test_exact_version_refuses_existing_lightweight_or_annotated_tag(self):
        name = "refs/tags/v2.0.5"
        self.github.refs[name] = {"ref": name, "object": {"type": "commit", "sha": REVISION}}
        with self.assertRaisesRegex(ValueError, "Tag v2.0.5 already exists"):
            release_start.start("patch", REVISION, version="v2.0.5")
        self.github.annotated("v2.0.5", run_id="9999", bump="exact")
        with self.assertRaisesRegex(ValueError, "Tag v2.0.5 already exists"):
            release_start.start("minor", REVISION, version="v2.0.5")
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_exact_version_cannot_replace_existing_draft_or_prerelease(self):
        for tag, draft, prerelease in (("v2.0.5", True, False), ("v2.1.0-rc.1", False, True)):
            self.releases.return_value = [published("v2.0.0"),
                                          published(tag, draft=draft, prerelease=prerelease)]
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "already exists"):
                release_start.start("patch", REVISION, version=tag)
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_exact_version_keeps_new_source_and_main_freshness_guards(self):
        self.remote.return_value = REVISION
        with self.assertRaisesRegex(ValueError, "No new commits"):
            release_start.start("patch", REVISION, version="v2.0.5")
        self.remote.return_value = PREVIOUS
        self.command.side_effect = subprocess.CalledProcessError(1, ["git", "merge-base"])
        with self.assertRaisesRegex(ValueError, "not an ancestor"):
            release_start.start("patch", REVISION, version="v2.0.5")
        self.command.side_effect = None
        self.github.main = "c" * 40
        with self.assertRaisesRegex(ValueError, "main advanced"):
            release_start.start("patch", REVISION, version="v2.0.5")
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_exact_version_recovers_same_run_even_after_baseline_advances(self):
        for tag in ("v2.0.5", "v2.1.0-rc.1"):
            self.github.refs.clear()
            self.github.annotated(tag, bump="exact")
            self.github.main = "c" * 40
            self.releases.return_value = [published("v2.9.0")]
            with self.subTest(tag=tag), patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
                self.assertEqual(release_start.start("major", REVISION, version=tag), tag)
            self.prepare.assert_called_with(tag, expected_revision=REVISION)
        self.assertEqual(self.github.writes, [])

    def test_exact_version_recovery_cannot_change_version_source_or_mode(self):
        sha = self.github.annotated("v2.0.5", bump="exact")
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.assertRaisesRegex(ValueError, "different exact version"):
                release_start.start("patch", REVISION, version="v2.0.6")
            with self.assertRaisesRegex(ValueError, "metadata"):
                release_start.start("patch", REVISION)
            self.github.objects[sha]["object"]["sha"] = "c" * 40
            with self.assertRaisesRegex(ValueError, "frozen commit"):
                release_start.start("patch", REVISION, version="v2.0.5")
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_lost_exact_tag_response_recovers_without_another_write(self):
        self.github.fail_reference = "after"
        with self.assertRaisesRegex(RuntimeError, "response lost"):
            release_start.start("patch", REVISION, version="v2.0.5")
        writes = copy.deepcopy(self.github.writes)
        self.github.fail_reference = None
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            self.assertEqual(release_start.start("patch", REVISION, version="v2.0.5"), "v2.0.5")
        self.assertEqual(self.github.writes, writes)
        self.prepare.assert_called_once_with("v2.0.5", expected_revision=REVISION)

    def test_next_automatic_patch_follows_the_custom_published_version(self):
        self.releases.return_value = [published("v2.0.0"), published("v2.0.5")]
        self.assertEqual(release_start.start("patch", REVISION), "v2.0.6")

    def test_versions_use_semver_and_skip_drafts_prereleases_and_historical_names(self):
        releases = [published("v2.9.9"), published("v2.10.2"), published("v1.99.99"),
                    published("v3.0.0-rc.1", prerelease=True), published("v9.0.0", draft=True),
                    published("old-release")]
        base = release_start.stable_base(releases)
        self.assertEqual(base, "v2.10.2")
        for bump, expected in (("patch", "v2.10.3"), ("minor", "v2.11.0"), ("major", "v3.0.0")):
            self.assertEqual(release_start.next_version(base, bump), expected)
        for versions in ([], [published("v2.0.0-rc.1", prerelease=True)], [published("v2.0.0", draft=True)]):
            with self.subTest(versions=versions), self.assertRaisesRegex(ValueError, "No published stable"):
                release_start.stable_base(versions)

    def test_dispatch_context_is_required_before_any_api_call(self):
        invalid = (("GITHUB_EVENT_NAME", "push"), ("GITHUB_REF", "refs/heads/feature"),
                   ("GITHUB_REF", "refs/tags/v2.0.1"), ("GITHUB_SHA", "c" * 40),
                   ("GH_REPO", "other/repository"), ("GH_REPO", "owner/repo/../../other"),
                   ("GITHUB_RUN_ID", "1234\n"), ("GITHUB_RUN_ATTEMPT", "0"))
        for name, value in invalid:
            with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}):
                with self.assertRaises(ValueError):
                    release_start.start("patch", REVISION)
        for revision in ("main", REVISION.upper(), REVISION + "\n"):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                release_start.start("patch", revision)
        self.api.assert_not_called()

    def test_existing_pending_tag_or_draft_is_never_adopted(self):
        self.github.annotated("v2.0.1", run_id="9999")
        with self.assertRaisesRegex(ValueError, "Tag v2.0.1 already exists"):
            release_start.start("patch", REVISION)
        self.github.refs.clear()
        self.releases.return_value.append(published("v2.0.1", draft=True))
        with self.assertRaisesRegex(ValueError, "Release v2.0.1 already exists"):
            release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_same_source_diverged_history_and_stale_main_refuse_before_writes(self):
        self.remote.return_value = REVISION
        with self.assertRaisesRegex(ValueError, "No new commits"):
            release_start.start("patch", REVISION)
        self.remote.return_value = PREVIOUS
        self.command.side_effect = subprocess.CalledProcessError(1, ["git", "merge-base"])
        with self.assertRaisesRegex(ValueError, "not an ancestor"):
            release_start.start("patch", REVISION)
        self.command.side_effect = None
        self.github.main = "c" * 40
        with self.assertRaisesRegex(ValueError, "main advanced"):
            release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])

    def test_module_validation_failure_stops_version_allocation(self):
        self.validate.side_effect = ValueError("Release tag major disagrees with candidate module")
        with self.assertRaisesRegex(ValueError, "major disagrees"):
            release_start.start("major", REVISION)
        self.assertEqual(self.github.writes, [])

    def test_owned_tag_recovery_precedes_latest_version_selection_and_main_freshness(self):
        self.github.annotated("v2.0.1")
        self.github.main = "c" * 40
        self.releases.return_value.append(published("v2.9.0"))
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            self.assertEqual(release_start.start("patch", REVISION), "v2.0.1")
        self.assertEqual(self.github.writes, [])
        self.validate.assert_not_called()
        self.prepare.assert_called_once_with("v2.0.1", expected_revision=REVISION)

    def test_recovery_refuses_existing_publication_including_drafts(self):
        self.github.annotated("v2.0.1")
        for draft in (True, False):
            self.releases.return_value = [published("v2.0.0"), published("v2.0.1", draft=draft), published("v2.0.2")]
            with self.subTest(draft=draft), patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
                with self.assertRaisesRegex(ValueError, "already exists"):
                    release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_missing_owner_on_rerun_cannot_allocate_even_after_stable_advances(self):
        self.github.annotated("v2.0.1", run_id="9999")
        self.releases.return_value.append(published("v2.0.1"))
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.assertRaisesRegex(ValueError, "No release tag owned by this rerun"):
                release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])

    def test_owned_tag_rejects_ambiguous_or_modified_metadata_and_target(self):
        first = self.github.annotated("v2.0.1")
        self.github.annotated("v2.0.2")
        with self.assertRaisesRegex(ValueError, "Multiple release tags"):
            release_start.start("patch", REVISION)
        del self.github.refs["refs/tags/v2.0.2"]
        original = copy.deepcopy(self.github.objects[first])
        mutations = (
            ("message", original["message"].replace('"patch"', '"minor"')),
            ("message", original["message"].replace('"refs/heads/main"', '"refs/heads/feature"')),
            ("message", original["message"] + "\nunrecognized metadata"),
            ("object", {"type": "commit", "sha": "c" * 40}),
            ("object", {"type": "tag", "sha": REVISION}),
            ("tag", "v2.0.9"),
        )
        for name, value in mutations:
            self.github.objects[first] = {**original, name: value}
            with self.subTest(field=name, value=value), self.assertRaises(ValueError):
                release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()

    def test_reference_creation_failure_never_selects_another_version(self):
        for failure in ("before", "after"):
            with self.subTest(failure=failure):
                github = GitHub()
                github.fail_reference = failure
                self.api.side_effect = github
                with self.assertRaisesRegex(RuntimeError, "reference"):
                    release_start.start("patch", REVISION)
                writes = copy.deepcopy(github.writes)
                github.fail_reference = None
                with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "2"}):
                    if failure == "before":
                        with self.assertRaisesRegex(ValueError, "No release tag owned"):
                            release_start.start("patch", REVISION)
                    else:
                        self.assertEqual(release_start.start("patch", REVISION), "v2.0.1")
                self.assertEqual(github.writes, writes)

    def test_read_api_failure_does_not_masquerade_as_absent_tag(self):
        self.api.side_effect = RuntimeError("authentication failed")
        with self.assertRaisesRegex(RuntimeError, "authentication failed"):
            release_start.start("patch", REVISION)
        self.assertEqual(self.github.writes, [])
        self.prepare.assert_not_called()


class RealGitAncestryTests(unittest.TestCase):
    def test_real_commit_history_and_module_major_gate_before_api_writes(self):
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            git = ("git", "-C", str(root), "-c", "user.name=Release Test",
                   "-c", "user.email=release-test@example.invalid")
            release.command(*git, "init")
            (root / "go.mod").write_text("module example.test/tool/v2\n\ngo 1.26.0\n")
            release.command(*git, "add", "go.mod")
            release.command(*git, "commit", "-m", "previous release")
            previous = release.command(*git, "rev-parse", "HEAD")
            release.command(*git, "commit", "--allow-empty", "-m", "new source")
            revision = release.command(*git, "rev-parse", "HEAD")
            github = GitHub()
            github.main = revision
            try:
                os.chdir(root)
                with patch.dict(os.environ, {
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                    "GITHUB_SHA": revision, "GH_REPO": REPOSITORY, "GITHUB_REPOSITORY": REPOSITORY,
                    "GITHUB_RUN_ID": RUN_ID, "GITHUB_RUN_ATTEMPT": "1",
                }), patch.object(release_start, "api", side_effect=github), \
                        patch.object(release, "repository_releases", return_value=[published("v2.0.0")]), \
                        patch.object(release, "remote_revision", return_value=previous), \
                        patch.object(release, "prepare"):
                    with self.assertRaisesRegex(ValueError, "major"):
                        release_start.start("major", revision)
                    with self.assertRaisesRegex(ValueError, "major"):
                        release_start.start("patch", revision, version="v3.0.0")
                    self.assertEqual(github.writes, [])
                    self.assertEqual(release_start.start("patch", revision), "v2.0.1")
                    github.refs.clear()
                    self.assertEqual(release_start.start("major", revision, version="v2.0.5"), "v2.0.5")
            finally:
                os.chdir(original)


class ReleaseRequestTests(unittest.TestCase):
    def test_new_version_and_existing_tag_are_mutually_exclusive(self):
        for tag in ("v2.0.1", "v2.0.5"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "not both"):
                release_start.validate_request(tag, "v2.0.5", "workflow_dispatch", "refs/heads/main")

    def test_automatic_exact_and_existing_tag_modes_report_stable_correctly(self):
        for tag, version, stable in (("", "", True), ("", "v2.0.5", True),
                                     ("", "v2.1.0-rc.1", False), ("v2.0.5", "", True),
                                     ("v2.1.0-rc.1", "", False)):
            with self.subTest(tag=tag, version=version):
                self.assertIs(release_start.validate_request(
                    tag, version, "workflow_dispatch", "refs/heads/main"), stable)

    def test_new_versions_require_manual_dispatch_from_main(self):
        for event, ref in (("push", "refs/heads/main"), ("pull_request", "refs/heads/main"),
                           ("workflow_dispatch", "refs/heads/feature"),
                           ("workflow_dispatch", "refs/tags/v2.0.0")):
            for version in ("", "v2.0.5", "v2.1.0-rc.1"):
                with self.subTest(event=event, ref=ref, version=version), self.assertRaises(ValueError):
                    release_start.validate_request("", version, event, ref)
        self.assertTrue(release_start.validate_request("v2.0.5", "", "push", "refs/tags/v2.0.5"))

    def test_malformed_tag_and_version_fail_in_preflight(self):
        for value in (" ", "v2.0.5\n", "v2.0", "v2.0.5+build", "v2.1.0-01"):
            for tag, version in ((value, ""), ("", value)):
                with self.subTest(tag=tag, version=version), self.assertRaises(ValueError):
                    release_start.validate_request(tag, version, "workflow_dispatch", "refs/heads/main")

    def test_cli_forwards_exact_version_and_blank_default(self):
        for version in ("", "v2.0.5", "v2.1.0-rc.1"):
            argv = ["release_start.py", "--revision", REVISION]
            if version:
                argv.extend(["--version", version])
            with self.subTest(version=version), patch.object(sys, "argv", argv), \
                    patch.object(release_start, "start") as start:
                release_start.main()
                start.assert_called_once_with("patch", REVISION, version=version)


if __name__ == "__main__":
    unittest.main()
