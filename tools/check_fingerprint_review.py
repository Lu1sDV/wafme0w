#!/usr/bin/env python3
"""Require fingerprint review history to move forward from a trusted commit.

This checks contract transitions only. The Go offlinebench assessor remains
responsible for current catalogue/fixture identities and positive/negative links.
Exit 1 reports a review regression; exit 2 means the comparison could not run.
"""

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "tools/offlinebench/testdata/coverage-contract.json"


@dataclass(frozen=True)
class Rule:
    digest: str
    status: str
    scope: str


def unique_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def rule_inventory(text, label):
    """Validate only the fields needed to compare historical review levels."""
    try:
        contract = json.loads(text, object_pairs_hook=unique_members)
        if (not isinstance(contract, dict) or type(contract.get("schema_version")) is not int
                or contract["schema_version"] != 2):
            raise ValueError("expected coverage contract schema_version 2")
        rules = contract.get("rules")
        if not isinstance(rules, list) or not rules:
            raise ValueError("rules must be a nonempty array")
        inventory = {}
        for index, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(f"rule {index + 1} must be an object")
            product, schema = rule.get("product"), rule.get("schema")
            if not isinstance(product, str) or not product.strip() or type(schema) is not int or schema < 1:
                raise ValueError(f"rule {index + 1} needs a product and positive integer schema")
            key = (product, schema)
            if key in inventory:
                raise ValueError(f"duplicate rule identity {key!r}")
            digest, status = rule.get("sha256"), rule.get("status")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"rule {key!r} needs a SHA-256 identity")
            provenance = rule.get("provenance")
            scope = provenance.get("scope") if isinstance(provenance, dict) else None
            if status == "baseline-untested":
                valid_scope = scope == "unreviewed"
            elif status == "reviewed":
                valid_scope = scope in ("synthetic-conformance", "reviewed-real")
            else:
                raise ValueError(f"rule {key!r} has an invalid review status")
            if not valid_scope:
                raise ValueError(f"rule {key!r} has an invalid review scope")
            inventory[key] = Rule(digest, status, scope)
        return inventory
    except (ValueError, TypeError) as error:
        raise ValueError(f"{label}: {error}") from error


def review_regressions(base, current):
    violations = []
    for key, rule in sorted(current.items()):
        previous = base.get(key)
        name = f"{key[0]!r}/schema/{key[1]}"
        if previous and previous.status == "reviewed" and rule.status != "reviewed":
            violations.append(f"{name} cannot move from reviewed to baseline-untested")
        elif previous and previous.scope == "reviewed-real" and rule.scope != "reviewed-real":
            violations.append(f"{name} cannot downgrade reviewed-real evidence to {rule.scope}")
        elif rule.status == "baseline-untested" and (previous is None or previous.digest != rule.digest):
            violations.append(f"new or changed rule {name} cannot be baseline-untested; add reviewed positive and negative fixtures")
    # Removing a rule is allowed here. The current Go assessor still requires
    # the catalogue and contract inventories to agree after an intentional removal.
    return violations


def git(*arguments):
    result = subprocess.run(["git", *arguments], cwd=ROOT, check=False,
                            capture_output=True, text=True, encoding="utf-8", timeout=15)
    if result.returncode:
        raise ValueError(f"cannot read review baseline: {result.stderr.strip()}")
    return result.stdout


def compare(base_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", base_sha) or base_sha == "0" * 40:
        raise ValueError("--base must be an explicit nonzero full commit SHA (40 lowercase hex digits)")
    if git("cat-file", "-t", base_sha).strip() != "commit":
        raise ValueError("--base must identify a commit, not a tag, tree, or blob")
    # Read a blob from the selected commit; never check out or run baseline code.
    base = rule_inventory(git("cat-file", "blob", f"{base_sha}:{CONTRACT}"), "base contract")
    current = rule_inventory((ROOT / CONTRACT).read_text(encoding="utf-8"), "current contract")
    return review_regressions(base, current)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="trusted full commit SHA containing the previous coverage contract")
    arguments = parser.parse_args(argv)
    try:
        violations = compare(arguments.base)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"Fingerprint review history could not be checked: {error}", file=sys.stderr)
        return 2
    if violations:
        for violation in violations:
            print(f"Fingerprint review regression: {violation}", file=sys.stderr)
        return 1
    print(f"Fingerprint review history passes against {arguments.base}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
