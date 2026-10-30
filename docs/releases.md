# Releases and security maintenance

[Quick start](../README.md) · [Operations](operations.md)

## Release when ready

Merge the changes you want to ship, then open **Actions → Release → Run workflow**
on `main`. Leave **bump** as `patch` and **tag** empty for a normal fix release.
The workflow chooses the next version, creates its annotated tag, runs all release
gates, publishes the GitHub archives and GHCR images, and updates the Homebrew tap.
For example, after `v2.0.0`, the default selection is `v2.0.1`.

The same action is available from an authenticated GitHub CLI:

```sh
gh workflow run release.yml --repo Lu1sDV/wafme0w --ref main -f bump=patch
```

Choose `minor` for compatible features or `major` for an incompatible release;
the numbers are calculated from the highest published stable version. Drafts
and prereleases do not change that baseline. A major bump must already agree
with the candidate's Go module path. This is an explicit release policy, not
an attempt to infer compatibility from commit messages.

The source SHA is fixed when you click **Run workflow**. A new release requires
that SHA to still be the tip of `main` when the queued run starts, with new commits
since the latest stable tag and that tag in its history. If `main` advances while
the request waits, start a fresh run. The workflow records the version and exact
source in its summary; subsequent merges cannot change that candidate.

Merging a PR runs CI. Delivery starts only with **Run workflow** or an explicitly
pushed `v*` tag. The manually created tag and all delivery stages run in the same
workflow, because a tag created with `GITHUB_TOKEN` does not trigger another push
workflow. [GitHub's token documentation](https://docs.github.com/en/actions/concepts/security/github_token)
explains this behavior.

### One-time delivery setup

Before the first stable delivery:

1. Keep the repository Actions variable `WAFME0W_PUBLISH_GHCR` set to `true`,
   with package access and visibility configured as described
   [below](#versioned-ghcr-publication).
2. Create a fine-grained personal access token owned by `Lu1sDV`, limited to
   **`homebrew-tap`**, with **Contents: Read and write**. Store it in this
   repository's **Settings → Secrets and variables → Actions → New repository
   secret** as **`HOMEBREW_TAP_TOKEN`**. Set an appropriate expiry and renew it
   before it expires. The tap's default branch must permit this identity to
   commit its formula update.
3. Allow the repository's Actions token to create new release tags and publish
   releases under the repository's rules. The workflow requests `contents: write`
   only in tag preparation and archive publication; existing tags are never
   force-updated.

The dedicated tap credential is necessary because `GITHUB_TOKEN` is restricted
to the workflow's repository. It is exposed only to the access preflight and the
final tap API update, never to Homebrew's formula audit, install or test. The
preflight checks for a configured credential, a writable tap and its expected
formula before creating a new tag. Repository rules and token scopes can still
reject a later write; that failure remains visible in the release run.

### Existing tags and interrupted runs

The optional **tag** input accepts an existing
`vMAJOR.MINOR.PATCH[-PRERELEASE]` tag and ignores **bump**. Use it for a prerelease
or to resume an unpublished candidate; its source must contain the current
release helpers. An existing tag must never be moved to fix a failed candidate.
Prereleases publish their archives and the configured GHCR channel, and leave
the stable Homebrew formula alone.

Release runs queue without cancelling a running delivery. An annotated tag
created by the manual flow records its owning workflow run, allowing preparation
to recover that exact tag on a rerun. It cannot claim another run's tag, allocate
another version on a retry, or replace a published release. A fresh run that
finds its next version already tagged stops and asks you to recover that candidate
instead of silently skipping a version.

Use **Re-run failed jobs** after fixing a transient failure. A failure before
tag creation with no recorded tag requires a new manual dispatch. If a GitHub
draft or any GHCR version tags were already created, inspect the partial
publication first: the existing publication helpers deliberately refuse to
overwrite them. Do not rerun all jobs after a successful GitHub publication.
A failed Homebrew-only job can be retried; an already identical formula is a
successful no-op, and a newer or unexpected formula is never overwritten.

GitHub, GHCR and Homebrew are separate publication steps. Treat delivery as
complete when all configured delivery jobs succeed; the normal new-release
flow requires all three. This workflow distributes
the CLI and container image; running a container on a server remains a separate
deployment decision.

## Build and install

Use a security-patched **Go 1.26 or newer** toolchain. Release and container builds
use **Go 1.27.3**.

### Build from source

From the repository root:

```sh
go build -o wafme0w ./cmd/wafme0w
./wafme0w --help
```

### Release archives

[GitHub Releases](https://github.com/Lu1sDV/wafme0w/releases) is the binary
distribution channel. New releases from this source require native validation
for the following matrix; older releases may have fewer archives:

| Platform | Archive suffix |
| --- | --- |
| Linux x64 | `_linux_amd64.tar.gz` |
| Linux ARM64 | `_linux_arm64.tar.gz` |
| macOS Apple silicon | `_darwin_arm64.tar.gz` |
| macOS Intel | `_darwin_amd64.tar.gz` |
| Windows x64 | `_windows_amd64.zip` |

Verify the archive against the release's `SHA256SUMS` before extraction, then put
`wafme0w` (`wafme0w.exe` on Windows) on `PATH`. Archives include synthetic demo
captures under `assets/demo/` and `LICENSE.md` with project and third-party
redistribution notices. Keep those notices with redistributed binaries.

**Legacy release warning:** v1.0.0 archives predate the dependency and toolchain
security hardening in this source tree. Do not treat them as patched binaries;
production deployment requires a newly built, scanned release that passes the
[publication gates](#publication-gates).

### Install a published Go module

The library and CLI use the v2 module path. Once a v2 release is published:

```sh
go install github.com/Lu1sDV/wafme0w/v2/cmd/wafme0w@latest
```

This command installs published module versions, not unreleased source. Use the
source build above to evaluate an unreleased revision.

### Homebrew

The verification job generates `wafme0w.rb` from the four verified Unix archive
hashes, covering Linux and macOS on x64 and ARM64. The formula installs the binary,
redistribution notices and synthetic demo captures; its test runs the offline
demo. Both `manifest.json` and `SHA256SUMS` bind the formula to the same release.

Published formulae are maintained in the
[`Lu1sDV/homebrew-tap`](https://github.com/Lu1sDV/homebrew-tap) tap:

```sh
brew install Lu1sDV/tap/wafme0w
```

Stable delivery verifies the formula and archive hashes against the published
GitHub assets, runs `brew audit --strict --online`, installs the fresh formula
and runs `brew test` on macOS before updating only `Formula/wafme0w.rb` in the tap.
The update checks the existing blob SHA to detect concurrent edits, rejects
downgrades and unexpected formula changes, and accepts an already identical
formula on retry. Until that job succeeds, `brew install` can still serve the
previous version. The [one-time credential setup](#one-time-delivery-setup) enables
this step without a manual formula copy for each release.

## Container image

The [Dockerfile](../Dockerfile) pins the official Go 1.27.3 Alpine image by
multi-platform digest, verifies module downloads, and builds a static binary.
Only allowlisted source/module/license inputs enter the build context. The
`scratch` runtime contains CA certificates and redistribution notices, but no
shell, package manager, or Chromium. Browser capture requires native Linux.
The default identity is UID/GID `65532:65532`; the binary, CA bundle, and license
are root-owned and not writable by that identity.

```sh
git clone https://github.com/Lu1sDV/wafme0w.git
cd wafme0w
docker build -t wafme0w:latest .
```

Inspect the container without sending requests:

```sh
docker run --rm --network none wafme0w:latest --help
docker run --rm --network none wafme0w:latest --silent --list --no-colors
```

The default working directory is `/work`. `/work` and the private `/tmp`
directory belong to UID/GID 65532; human scans need writable temporary storage
for their final URL table. A hardened offline run is:

```sh
docker run --rm --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 128 --memory 512m --cpus 2 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m,mode=0700,uid=65532,gid=65532 \
  -v "$PWD/assets/demo:/captures:ro" wafme0w:latest \
  --evidence /captures/captures.jsonl --no-colors
```

These runtime controls cannot be enforced by a Dockerfile. Keep the runtime's
default seccomp and host security policies. Active scans need explicitly
authorized network access instead of `--network none`; network attachment alone
does not enforce destination scope.

`--jsonl` and `--silent` do not need the human-table spool. Saved reports need
a writable output mount owned by the selected UID. To use a host UID via
`--user`, also provide a writable working directory and `/tmp` mount for it.
Size memory, PID and temporary-storage limits for the selected concurrency and
input volume; the example limits are not universal sizing guarantees.

### Versioned GHCR publication

GHCR publication is prepared in the release workflow and is disabled until an
administrator sets the repository variable `WAFME0W_PUBLISH_GHCR=true`. This
source change does not publish an image. Before enabling it, confirm the
repository's Actions token may create/write its container package; if a package
already exists, link it to the repository and grant the workflow access. The
first successful publication must also have its intended package visibility
verified before documenting a public pull command.

Both Linux native jobs build the Dockerfile's `release` target using the exact
packaged CLI binary and license, run the hardened offline container smoke, and
retain the tested image as a workflow artifact. They have no registry write
permissions. After all source, native, archive-scan and GitHub-release gates
pass, a separate job loads those images, compares their binaries to the verified
manifest, and publishes:

- `ghcr.io/lu1sdv/wafme0w:<release-tag>`: a Linux x64/ARM64 manifest list.
- `<release-tag>-linux-amd64` and `<release-tag>-linux-arm64`: native images.
- An attestation for the manifest digest with the frozen source SHA and child
  image digests. The `published-container-identity` workflow artifact retains
  `container-manifest.json`.

There is no floating `latest` tag. The helper refuses existing version tags and
fails closed on authentication or registry errors; registry tags themselves are
not an immutability guarantee. Pin `ghcr.io/lu1sdv/wafme0w@sha256:<verified-digest>`
for deployment. If publication stops after an architecture image is uploaded,
inspect that partial publication before recovery; the helper will not overwrite
it automatically. GitHub releases and GHCR cannot be published atomically, so
check both workflow jobs before announcing both distribution channels.

The package is publicly readable, and `actions/attest` reads
`$HOME/.docker/config.json` rather than `DOCKER_CONFIG`, so the publication job logs
in to the default credential file and removes it again afterwards. Images published
before that fix, including v2.0.0, carry no registry attestation: verify those by
matching the digest to the release run's `published-container-identity` artifact and
the container binary hash to `manifest.json`.

## Publication gates

The [release workflow](../.github/workflows/release.yml) creates or resolves the
requested tag once and validates that exact commit before publication:

| Gate | Required evidence |
| --- | --- |
| Source validation | Formatting, vet, race tests, Go source and optional Python dependency vulnerability scans, bounded matcher and evidence fuzzing, isolated offline comparison, httpx pipeline checks, Chromium integration, and container checks |
| Native packages | Tests and extracted-archive smoke checks on Linux x64/ARM64, macOS x64/ARM64, and Windows x64 |
| Binary identity | Packaged binaries identify the prepared source SHA, an unmodified tree, the intended target, and Go 1.27.3 |
| Artifact verification | Binary vulnerability scans, verified hashes and identities in `manifest.json`, and `SHA256SUMS` covering the manifest and generated Homebrew formula |
| Containers | Native x64/ARM64 build and hardened offline smoke of the exact archived binaries; GHCR writes occur only after successful archive publication and explicit repository opt-in |
| Publication | Attestation, remote tag and hash rechecks, and no asset overwrite |
| Stable Homebrew delivery | Published asset hashes match the verified bundle; formula audit, install and offline test pass; tap update is an optimistic, monotonic change |

The [CI workflow](../.github/workflows/ci.yml) defines the source-validation
commands and host prerequisites. Run hosted native jobs and attestations on the
committed candidate; local cross-builds do not establish native runtime behavior.

Tags use `vMAJOR.MINOR.PATCH[-PRERELEASE]` without build metadata. The tag's major
version must agree with `go.mod` at the frozen candidate SHA, including when a
manual dispatch runs from another checkout. This source uses `/v2`, so its
release tags must be `v2.*`; CI derives its synthetic smoke tag from the module.
Prereleases do not become latest, and older stable releases cannot replace a higher stable
release as latest. Cross-tag publication is serialized without cancelling
in-progress publication.

### Repository controls

Require all eight CI jobs on an up-to-date `main` pull request, one approving
review of the latest push, stale-review dismissal, and resolved conversations.
Apply checks to administrators too, and prohibit force-pushes and branch deletion.
Protect `v*` tags against updates/deletion without bypass actors; enable immutable
releases before publication.

Default Actions tokens should be read-only and unable to approve pull requests.
The tag preparation and archive publication jobs explicitly request `contents: write`; only the
separate GHCR publication job requests `packages: write`, with attestation/OIDC
permissions. Grant additional release access only to trusted maintainers.

These are administrator-controlled repository settings, not guarantees supplied
by workflow YAML. Recheck them before release; tag rechecks alone do not provide
atomic protection against concurrent changes.

## Security maintenance

The [weekly security workflow](../.github/workflows/security.yml) scans maintained
Go source, optional Python dependency pins, and supported published binaries as
independent failure gates. CI and release validation also audit the fully pinned
optional benchmark requirements with `pip-audit` 2.10.1. The scanner runs in its
own environment and audits the manifest without installing the benchmark
packages; keep every transitive runtime dependency pinned in that manifest.
Findings and audit errors fail validation, and reports are retained for review.

A source fix does not clear findings in an already published binary. Rebuild,
scan, validate, and publish a new release; deploy the new artifact rather than
assuming a source update repairs existing downloads. The current `/v2` source
must supersede v1.0.0 through a new validated `v2.*` release. Do not replace or
overwrite the old tag or its assets. Until that release is published, use a
reviewed source revision built with the patched toolchain above.

