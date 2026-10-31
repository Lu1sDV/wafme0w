"""Historical review policy checks using synthetic contracts and local Git only."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

import check_fingerprint_review as review


def rule(product="Legacy", schema=1, digest="a" * 64, status="baseline-untested", scope=None):
    return {"product": product, "schema": schema, "sha256": digest, "status": status,
            "provenance": {"scope": scope or ("unreviewed" if status == "baseline-untested" else "synthetic-conformance")}}


def contract(*rules):
    return {"schema_version": 2, "rules": list(rules)}


def inventory(*rules):
    return review.rule_inventory(json.dumps(contract(*rules)), "test contract")


class ReviewTransitionTests(unittest.TestCase):
    def test_new_or_changed_legacy_identity_cannot_be_grandfathered(self):
        base = inventory(rule())
        for candidate in (rule(product="New"), rule(schema=2), rule(digest="b" * 64)):
            with self.subTest(candidate=candidate):
                # Even after the current contract hash is refreshed to agree
                # with a changed catalogue, the trusted base has not approved it.
                errors = review.review_regressions(base, inventory(candidate))
                self.assertEqual(len(errors), 1)
                self.assertIn("baseline-untested", errors[0])

    def test_reviews_and_real_evidence_cannot_be_downgraded(self):
        for before, after, message in (
            (rule(status="reviewed"), rule(), "reviewed"),
            (rule(status="reviewed", scope="reviewed-real"), rule(status="reviewed"), "reviewed-real"),
            (rule(status="reviewed", scope="reviewed-real"), rule(digest="b" * 64), "reviewed"),
        ):
            with self.subTest(before=before, after=after):
                errors = review.review_regressions(inventory(before), inventory(after))
                self.assertEqual(len(errors), 1)
                self.assertIn(message, errors[0])

    def test_unchanged_legacy_and_reviewed_changes_are_allowed(self):
        for before, after in (
            (rule(), rule()),
            (rule(), rule(status="reviewed")),
            (rule(), rule(digest="b" * 64, status="reviewed")),
            (rule(status="reviewed"), rule(digest="b" * 64, status="reviewed")),
            (rule(status="reviewed"), rule(status="reviewed", scope="reviewed-real")),
            (rule(status="reviewed", scope="reviewed-real"), rule(digest="b" * 64, status="reviewed", scope="reviewed-real")),
        ):
            with self.subTest(before=before, after=after):
                self.assertEqual(review.review_regressions(inventory(before), inventory(after)), [])
        self.assertEqual(review.review_regressions(inventory(rule()), inventory(rule(), rule(product="New", status="reviewed"))), [])

    def test_removal_does_not_force_retention_of_an_obsolete_rule(self):
        base = inventory(rule(), rule(product="Obsolete", status="reviewed"))
        self.assertEqual(review.review_regressions(base, inventory(rule())), [])

    def test_malformed_inventories_fail_instead_of_disabling_history(self):
        valid = contract(rule())
        malformed = [None, {}, {**valid, "schema_version": 2.0}, contract(), contract(rule(), rule()),
                     contract(rule(schema=True)), contract(rule(schema=0)),
                     contract(rule(product="")), contract(rule(digest="bad")),
                     contract(rule(status="unknown")), contract(rule(scope="reviewed-real")),
                     contract(rule(status="reviewed", scope="unreviewed"))]
        for field in ("product", "schema", "sha256", "status", "provenance"):
            missing = copy.deepcopy(valid)
            del missing["rules"][0][field]
            malformed.append(missing)
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.rule_inventory(json.dumps(value), "base contract")
        for value in ('{', '{"schema_version":2,"schema_version":2,"rules":[]}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                review.rule_inventory(value, "base contract")


class ReviewGitIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "--quiet")
        self.git("symbolic-ref", "HEAD", "refs/heads/main")
        (self.root / "tools").mkdir()
        shutil.copyfile(Path(review.__file__), self.root / "tools/check_fingerprint_review.py")
        self.write_contract(contract(rule()))
        self.base = self.commit("known inherited catalogue")

    def git(self, *arguments):
        return subprocess.run(["git", "-c", "user.name=Review Test", "-c", "user.email=review@example.invalid",
                               "-c", "commit.gpgsign=false", *arguments], cwd=self.root, check=True,
                              capture_output=True, text=True, timeout=15).stdout.strip()

    def commit(self, message):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def write_contract(self, value):
        path = self.root / review.CONTRACT
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def cli(self, base=None):
        return subprocess.run([sys.executable, "tools/check_fingerprint_review.py", "--base", base or self.base],
                              cwd=self.root, capture_output=True, text=True, timeout=15)

    def test_refreshed_current_hash_cannot_bless_an_unreviewed_change(self):
        self.write_contract(contract(rule(digest="b" * 64)))
        rejected = self.cli()
        self.assertEqual(rejected.returncode, 1, rejected.stderr)
        self.assertIn("baseline-untested", rejected.stderr)
        self.write_contract(contract(rule(digest="b" * 64, status="reviewed")))
        accepted = self.cli()
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_explicit_base_catches_changes_hidden_by_an_intermediate_commit(self):
        self.write_contract(contract(rule(), rule(product="Unreviewed addition")))
        intermediate = self.commit("incorrectly grandfather new rule")
        (self.root / "notes.txt").write_text("unrelated change\n", encoding="utf-8")
        self.commit("second commit on feature branch")
        self.assertEqual(self.cli(intermediate).returncode, 0)
        self.assertEqual(self.cli(self.base).returncode, 1)

    def test_missing_or_invalid_base_never_falls_back_to_current_contract(self):
        for base in ("HEAD", "a" * 7, "0" * 40, "f" * 40, "--help", self.base + ":" + review.CONTRACT):
            with self.subTest(base=base):
                result = self.cli(base)
                self.assertEqual(result.returncode, 2, result.stderr)
        tree = self.git("rev-parse", "HEAD^{tree}")
        result = self.cli(tree)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("must identify a commit", result.stderr)

    def test_missing_and_malformed_contracts_fail_closed(self):
        path = self.root / review.CONTRACT
        path.unlink()
        missing_base = self.commit("missing base contract")
        self.write_contract(contract(rule()))
        self.assertEqual(self.cli(missing_base).returncode, 2)
        path.write_text("not JSON", encoding="utf-8")
        malformed_base = self.commit("malformed base contract")
        self.write_contract(contract(rule()))
        self.assertEqual(self.cli(malformed_base).returncode, 2)
        path.write_text("not JSON", encoding="utf-8")
        self.assertEqual(self.cli().returncode, 2)
        path.unlink()
        self.assertEqual(self.cli().returncode, 2)

    def workflow(self, event, *, pr_base="", before="", source_ref=""):
        # Execute the actual checked-in shell step, so event-to-base routing is
        # covered without a YAML dependency or GitHub/network access.
        workflow = (review.ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        step = workflow.split("      - name: Check fingerprint review history\n", 1)[1].split("\n      - ", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        environment = {**os.environ, "FINGERPRINT_REVIEW_EVENT": event,
                       "FINGERPRINT_REVIEW_PR_BASE": pr_base, "FINGERPRINT_REVIEW_PUSH_BEFORE": before,
                       "FINGERPRINT_REVIEW_SOURCE_REF": source_ref}
        environment.pop("BASH_ENV", None)
        environment.pop("ENV", None)
        return subprocess.run(["bash", "--noprofile", "--norc", "-euo", "pipefail", "-c", script], cwd=self.root, env=environment,
                              capture_output=True, text=True, timeout=15)

    def test_workflow_checks_entire_pr_or_main_push_not_only_last_commit(self):
        self.write_contract(contract(rule(digest="b" * 64)))
        self.commit("unreviewed change in first commit")
        (self.root / "notes.txt").write_text("second change\n", encoding="utf-8")
        self.commit("unrelated second commit")
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                result = self.workflow(event, pr_base=self.base, before=self.base)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("baseline-untested", result.stderr)

    def test_workflow_rejects_missing_pr_and_branch_creation_bases(self):
        for event, before in (("pull_request", ""), ("push", ""), ("push", "0" * 40), ("workflow_dispatch", "")):
            with self.subTest(event=event, before=before):
                result = self.workflow(event, before=before)
                self.assertNotEqual(result.returncode, 0)
        # The root commit has no first parent, so a reusable call cannot skip.
        self.assertNotEqual(self.workflow("workflow_dispatch", source_ref=self.base).returncode, 0)

    def test_pull_request_merge_checkout_uses_the_target_branch_contract(self):
        self.git("checkout", "--quiet", "-b", "feature")
        self.write_contract(contract(rule(digest="b" * 64, status="reviewed")))
        self.commit("review a changed rule on the feature branch")
        self.git("checkout", "--quiet", "main")
        (self.root / "main.txt").write_text("target branch moved\n", encoding="utf-8")
        target_base = self.commit("unrelated target branch change")
        self.git("merge", "--quiet", "--no-ff", "feature", "-m", "simulate pull request merge")
        self.assertEqual(self.git("rev-parse", "HEAD^"), target_base)
        result = self.workflow("pull_request", pr_base=target_base)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_reusable_validation_compares_frozen_candidate_to_first_parent(self):
        self.write_contract(contract(rule(digest="b" * 64, status="reviewed")))
        candidate = self.commit("reviewed candidate")
        result = self.workflow("workflow_dispatch", source_ref=candidate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write_contract(contract(rule(digest="b" * 64)))
        candidate = self.commit("candidate drops review")
        result = self.workflow("workflow_dispatch", source_ref=candidate)
        self.assertEqual(result.returncode, 1, result.stderr)


if __name__ == "__main__":
    unittest.main()
