#!/usr/bin/env python3
"""Publish one verified stable release formula to an existing Homebrew tap.

GH_TOKEN authenticates source API reads. Tap API calls use HOMEBREW_TAP_TOKEN;
neither credential is persisted in a checkout or passed as an argument.
The tap must already contain a canonical generated formula; unexpected edits,
old release runs and concurrent formula changes fail without overwriting them.
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import quote

import release


FORMULA_PATH = "Formula/wafme0w.rb"
MAX_FORMULA_BYTES = 65536


def github_api(path, *, tap=False, payload=None, paginate=False):
    environment = os.environ.copy()
    tap_token = environment.pop("HOMEBREW_TAP_TOKEN", "")
    if tap:
        release.require(bool(tap_token), "HOMEBREW_TAP_TOKEN is required to update the Homebrew tap")
        environment["GH_TOKEN"] = tap_token
    args = ["gh", "api", "--hostname", "github.com", path]
    if paginate:
        args.extend(["--paginate", "--slurp"])
    if payload is not None:
        args.extend(["--method", "PUT", "--input", "-"])
    try:
        result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                                env=environment, capture_output=True, text=True, check=True, timeout=180)
    except subprocess.CalledProcessError as error:
        # Report a useful API status without echoing subprocess output or any
        # credential, including when a caller has enabled gh debug logging.
        status = re.search(r"\bHTTP ([0-9]{3})\b", error.stderr or "")
        reason = f"HTTP {status.group(1)}" if status else f"exit {error.returncode}"
        target = "tap" if tap else "source"
        raise ValueError(f"GitHub {target} API request failed ({reason}); no write was retried") from error
    return json.loads(result.stdout)


def formula_identity(formula, repository):
    """Recognize the generated template without evaluating any Ruby from the tap."""
    header = re.match(r"# Generated from verified release ([^,\n]+), source ([0-9a-f]{40})\.\n", formula)
    release.require(header is not None, "Tap formula is not a recognized generated release formula")
    tag, revision = header.groups()
    release.require(release.version_key(tag)[3], "Tap formula must name a stable release")
    expected = {name for name in release.archive_names(tag) if name.endswith(".tar.gz")}
    urls = re.findall(r'^\s+url "([^"\n]+)"\n\s+sha256 "([0-9a-f]{64})"$', formula, re.MULTILINE)
    archives = {}
    prefix = f"https://github.com/{repository}/releases/download/{tag}/"
    for url, digest in urls:
        release.require(url.startswith(prefix), "Tap formula contains an unexpected release URL")
        name = url[len(prefix):]
        release.require(name in expected and name not in archives, "Tap formula archive set is unexpected")
        archives[name] = {"archive_sha256": digest}
    release.require(set(archives) == expected and
                    formula == release.homebrew_formula(tag, revision, archives, repository),
                    "Tap formula has manual or unrecognized changes; review them before publishing")
    return tag, revision


def tap_state(tap, source):
    release.repository_name(tap)
    release.repository_name(source)
    release.require(tap.lower() != source.lower(), "Homebrew tap must be a separate repository")
    metadata = github_api(f"repos/{tap}", tap=True)
    release.require(metadata.get("full_name", "").lower() == tap.lower(), "Tap repository identity mismatch")
    release.require(metadata.get("permissions", {}).get("push") is True,
                    "HOMEBREW_TAP_TOKEN must have permission to push to the Homebrew tap")
    branch = metadata.get("default_branch")
    release.require(isinstance(branch, str) and bool(branch), "Homebrew tap has no default branch")
    current = github_api(f"repos/{tap}/contents/{FORMULA_PATH}?ref={quote(branch, safe='')}", tap=True)
    release.require(current.get("type") == "file" and current.get("path") == FORMULA_PATH and
                    current.get("encoding") == "base64" and
                    isinstance(current.get("size"), int) and 0 < current["size"] <= MAX_FORMULA_BYTES and
                    re.fullmatch(r"[0-9a-f]{40}", current.get("sha", "")),
                    "Tap formula response is not a bounded regular file")
    try:
        content = base64.b64decode("".join(current["content"].split()), validate=True)
        formula = content.decode("utf-8")
    except (KeyError, ValueError, binascii.Error, UnicodeError) as error:
        raise ValueError("Tap formula is not valid base64-encoded UTF-8") from error
    release.require(len(content) == current["size"], "Tap formula length mismatch")
    expected_sha = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    release.require(current["sha"] == expected_sha, "Tap formula blob identity mismatch")
    tag, _ = formula_identity(formula, source)
    return {"branch": branch, "sha": current["sha"], "formula": formula, "tag": tag}


def check_access(tap):
    source = release.repository_name(os.environ["GH_REPO"])
    state = tap_state(tap, source)
    print(f"Homebrew tap {tap} is accessible on {state['branch']} at {state['tag']}")


def check_published(tag, revision, dist, repository):
    release.require(release.remote_revision("origin", tag) == revision,
                    "Remote release tag moved before Homebrew publication")
    pages = github_api(f"repos/{repository}/releases?per_page=100", paginate=True)
    versions = release.release_versions([item for page in pages for item in page])
    stable = [(key, item) for key, item in versions if key[3]]
    release.require(bool(stable), "No published stable release is available for the Homebrew tap")
    _, current = max(stable, key=lambda pair: pair[0])
    release.require(current["tag_name"] == tag,
                    "Only the highest published stable release may update the Homebrew tap")
    expected = {path.name: path for path in dist.iterdir()}
    assets = current["assets"]
    release.require(len(assets) == len(expected) and {asset["name"] for asset in assets} == set(expected),
                    "Published release asset set differs from the verified bundle")
    for asset in assets:
        path = expected[asset["name"]]
        release.require(asset.get("state") == "uploaded" and asset.get("size") == path.stat().st_size and
                        asset.get("digest") == "sha256:" + release.digest(path),
                        f"Published release asset differs from verified bytes: {path.name}")


def verified_bundle(args):
    release.require(release.version_key(args.tag)[3], "Prereleases cannot update the stable Homebrew tap")
    source = release.repository_name(os.environ["GH_REPO"])
    manifest = release.check_bundle(args.dist, args.tag, args.revision)
    release.require(manifest["repository"] == source, "Verified repository differs from the source repository")
    release.require((args.dist / "SHA256SUMS").is_file(), "Missing verified checksums")
    formula = (args.dist / release.FORMULA).read_text(encoding="utf-8")
    return source, formula


def verify_only(args):
    source, _ = verified_bundle(args)
    check_published(args.tag, args.revision, args.dist, source)
    print(f"Verified {args.tag} formula and published release bytes before Homebrew execution")


def publish(args):
    source, formula = verified_bundle(args)
    state = tap_state(args.tap, source)
    # Keep the exact blob SHA observed before the version check. A later edit
    # must cause a conflict rather than becoming permission to overwrite it.
    release.require(formula == state["formula"] or
                    release.version_key(args.tag) > release.version_key(state["tag"]),
                    "Refusing to downgrade or replace the tap's existing release")
    check_published(args.tag, args.revision, args.dist, source)
    if formula == state["formula"]:
        print(f"Homebrew tap {args.tap} already contains the verified {args.tag} formula")
        return
    content = formula.encode("utf-8")
    updated = github_api(f"repos/{args.tap}/contents/{FORMULA_PATH}", tap=True, payload={
        "message": f"wafme0w {args.tag}",
        "content": base64.b64encode(content).decode("ascii"),
        "sha": state["sha"],
        "branch": state["branch"],
    })
    expected_sha = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
    release.require(updated.get("content", {}).get("sha") == expected_sha,
                    "Homebrew update returned an unexpected formula identity; inspect the tap before retrying")
    print(f"Updated {args.tap}/{FORMULA_PATH} to the verified {args.tag} formula")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tap")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-access", action="store_true", help="Check tap access without writing")
    mode.add_argument("--verify-only", action="store_true", help="Verify published bytes without tap credentials")
    parser.add_argument("--tag")
    parser.add_argument("--revision")
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    if not args.verify_only and not args.tap:
        parser.error("--tap is required unless --verify-only is used")
    if args.check_access:
        check_access(args.tap)
    else:
        if not args.tag or not args.revision:
            parser.error("--tag and --revision are required unless --check-access is used")
        if args.verify_only:
            verify_only(args)
        else:
            publish(args)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"Homebrew publication failed: {error}") from error
