#!/usr/bin/env python3
"""Allocate a release only for an explicit workflow_dispatch on main.

The dispatch commit is frozen before version selection. An annotated tag records
the workflow run that owns it, so retrying that run cannot allocate another
version. This helper never updates or deletes an existing tag or release.
"""

import argparse
import json
import os
import re
import subprocess

import release


def api(repository, path, **fields):
    args = ["gh", "api", f"repos/{repository}/{path}"]
    if fields:
        args.extend(("--method", "POST"))
        for name, value in fields.items():
            args.extend(("-f", f"{name}={value}"))
    return json.loads(release.command(*args))


def validate_request(tag, version, event_name, ref):
    """Validate the form before credential preflight or any release mutation."""
    release.require(not (tag and version),
                    "Choose either an exact new version or an existing tag, not both")
    if not tag:
        release.require(event_name == "workflow_dispatch" and ref == "refs/heads/main",
                        "Start a new release with Run workflow on main")
    selected = version or tag
    return not selected or release.version_key(selected)[3]


def stable_base(releases):
    stable = [(key, item) for key, item in release.release_versions(releases) if key[3]]
    release.require(stable, "No published stable release; supply an existing initial version tag instead")
    return max(stable, key=lambda pair: pair[0])[1]["tag_name"]


def next_version(tag, bump):
    major, minor, patch, stable, _ = release.version_key(tag)
    release.require(stable, "The automatic version baseline must be stable")
    release.require(bump in ("patch", "minor", "major"), "Invalid release increment")
    if bump == "major":
        return f"v{major + 1}.0.0"
    if bump == "minor":
        return f"v{major}.{minor + 1}.0"
    return f"v{major}.{minor}.{patch + 1}"


def owner_line(repository, run_id):
    return f"wafme0w manual release run {repository}#{run_id}"


def annotation_message(repository, run_id, tag, bump, revision):
    metadata = {"schema_version": 1, "repository": repository, "run_id": run_id,
                "ref": "refs/heads/main", "tag": tag, "bump": bump, "revision": revision}
    return owner_line(repository, run_id) + "\n" + json.dumps(metadata, sort_keys=True)


def require_sha(value):
    release.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value),
                    "Expected a full Git object SHA")
    return value


def owned_tag(repository, refs, run_id, bump, revision, *, version=""):
    matches = []
    for ref in refs:
        name = ref["ref"]
        release.require(name.startswith("refs/tags/"), "Unexpected reference in tag listing")
        tag = name[len("refs/tags/"):]
        try:
            release.version_key(tag)
        except ValueError:
            continue
        obj = ref["object"]
        release.require(obj["type"] in ("commit", "tag"), "Release tag must point to a commit or annotated tag")
        if obj["type"] != "tag":
            continue
        sha = require_sha(obj["sha"])
        annotation = api(repository, "git/tags/" + sha)
        release.require(annotation["sha"] == sha, "Tag annotation identity disagrees with its reference")
        message = annotation["message"]
        release.require(isinstance(message, str), "Invalid tag annotation")
        if not message or message.splitlines()[0] != owner_line(repository, run_id):
            continue
        release.require(message.rstrip("\n") == annotation_message(repository, run_id, tag, bump, revision),
                        "This workflow run's release tag has different version, source or increment metadata")
        release.require(annotation["tag"] == tag and annotation["object"]["type"] == "commit"
                        and annotation["object"]["sha"] == revision,
                        "This workflow run's tag no longer points directly to its frozen commit")
        if version:
            release.require(tag == version, "This workflow run owns a different exact version")
        else:
            release.require(release.version_key(tag)[3], "Automatic release tag must be stable")
        matches.append(tag)
    release.require(len(matches) <= 1, "Multiple release tags claim this workflow run; refusing ambiguous recovery")
    return matches[0] if matches else None


def require_unpublished(tag, releases):
    release.require(not any(item["tag_name"] == tag for item in releases),
                    f"Release {tag} already exists; refusing overwrite (including drafts)")


def start(bump, revision, *, version=""):
    validate_request("", version, os.environ.get("GITHUB_EVENT_NAME"), os.environ.get("GITHUB_REF"))
    require_sha(revision)
    release.require(os.environ.get("GITHUB_SHA") == revision,
                    "Release source must equal the frozen workflow dispatch SHA")
    repository = release.repository_name(os.environ["GH_REPO"])
    release.require(repository == os.environ.get("GITHUB_REPOSITORY"),
                    "Release repository must match the workflow repository")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    release.require(re.fullmatch(r"[1-9][0-9]*", run_id), "Invalid workflow run identifier")
    release.require(re.fullmatch(r"[1-9][0-9]*", attempt), "Invalid workflow run attempt")
    release.require(bump in ("patch", "minor", "major"), "Invalid release increment")

    refs = api(repository, "git/matching-refs/tags/")
    release.require(isinstance(refs, list), "Expected a complete tag reference listing")
    # The annotation records the effective selection, not an ignored dropdown.
    selection = "exact" if version else bump
    tag = owned_tag(repository, refs, run_id, selection, revision, version=version)
    releases = release.repository_releases()
    if tag:
        require_unpublished(tag, releases)
        print(f"Recovering {tag} owned by workflow run {run_id}")
        release.prepare(tag, expected_revision=revision)
        return tag

    # A failed API response may leave an unreferenced tag object, or an operator
    # may have removed a tag. Neither permits a rerun to choose a new version.
    release.require(attempt == "1", "No release tag owned by this rerun; start a new manual workflow run")
    previous_tag = stable_base(releases)
    tag = version or next_version(previous_tag, bump)
    release.require(release.version_key(tag) > release.version_key(previous_tag),
                    f"New version {tag} must be newer than the latest stable release {previous_tag}")
    require_unpublished(tag, releases)
    release.require(not any(item["ref"] == "refs/tags/" + tag for item in refs),
                    f"Tag {tag} already exists; retry its original run or supply that existing tag")
    release.validate_candidate(tag, revision)
    previous = release.remote_revision("origin", previous_tag)
    release.require(previous != revision, "No new commits since the latest stable release")
    try:
        release.command("git", "merge-base", "--is-ancestor", previous, revision)
    except subprocess.CalledProcessError as error:
        if error.returncode != 1:
            raise
        raise ValueError("Latest stable release is not an ancestor of the selected source") from error

    # Full-history checkout proves ancestry; the live ref check also stops an
    # old queued dispatch from silently releasing a superseded main revision.
    main = api(repository, "git/ref/heads/main")
    release.require(main["ref"] == "refs/heads/main" and main["object"]["type"] == "commit"
                    and main["object"]["sha"] == revision,
                    "main advanced after this dispatch; start a new manual workflow run")
    message = annotation_message(repository, run_id, tag, selection, revision)
    annotation = api(repository, "git/tags", tag=tag, message=message, object=revision, type="commit")
    sha = require_sha(annotation["sha"])
    release.require(annotation["tag"] == tag and annotation["message"].rstrip("\n") == message
                    and annotation["object"]["type"] == "commit" and annotation["object"]["sha"] == revision,
                    "Created tag object does not match the selected release")
    # GitHub's create-reference API fails if another publisher won this name.
    # Never turn that failure into a force update or an automatic version bump.
    created = api(repository, "git/refs", ref="refs/tags/" + tag, sha=sha)
    release.require(created["ref"] == "refs/tags/" + tag and created["object"]["type"] == "tag"
                    and created["object"]["sha"] == sha, "Created tag reference has an unexpected identity")
    print(f"Created {tag} at {revision} for workflow run {run_id}")
    release.prepare(tag, expected_revision=revision)
    return tag


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bump", choices=("patch", "minor", "major"), default="patch")
    parser.add_argument("--version", default="",
                        help="Exact new vMAJOR.MINOR.PATCH[-PRERELEASE]; overrides --bump")
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    start(args.bump, args.revision, version=args.version)


if __name__ == "__main__":
    main()
