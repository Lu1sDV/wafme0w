# Releases and security maintenance

[Quick start](../README.md) · [Operations](operations.md)

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
distribution channel. Choose the archive for the host platform:

| Platform | Archive suffix |
| --- | --- |
| Linux x64 | `_linux_amd64.tar.gz` |
| macOS Apple silicon | `_darwin_arm64.tar.gz` |
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

## Publication gates

The [release workflow](../.github/workflows/release.yml) resolves the requested tag
once and validates that exact commit before publication:

| Gate | Required evidence |
| --- | --- |
| Source validation | Formatting, vet, race tests, source vulnerability scans, bounded matcher and evidence fuzzing, isolated offline comparison, httpx pipeline checks, Chromium integration, and container checks |
| Native packages | Tests and extracted-archive smoke checks on Linux x64, macOS arm64, and Windows x64 |
| Binary identity | Packaged binaries identify the prepared source SHA, an unmodified tree, the intended target, and Go 1.27.3 |
| Artifact verification | Binary vulnerability scans, verified hashes and identities in `manifest.json`, and `SHA256SUMS` covering the manifest |
| Publication | Attestation, remote tag and hash rechecks, and no asset overwrite |

The [CI workflow](../.github/workflows/ci.yml) defines the source-validation
commands and host prerequisites. Run hosted native jobs and attestations on the
committed candidate; local cross-builds do not establish native runtime behavior.

Tags use `vMAJOR.MINOR.PATCH[-PRERELEASE]` without build metadata. Prereleases do
not become latest, and older stable releases cannot replace a higher stable
release as latest. Cross-tag publication is serialized without cancelling
in-progress publication.

### Repository controls

Require all six CI jobs on an up-to-date `main` pull request, one approving
review of the latest push, stale-review dismissal, and resolved conversations.
Apply checks to administrators too, and prohibit force-pushes and branch deletion.
Protect `v*` tags against updates/deletion without bypass actors; enable immutable
releases before publication.

Default Actions tokens should be read-only and unable to approve pull requests.
The publication job explicitly requests `contents: write`; grant additional
release access only to trusted maintainers.

These are administrator-controlled repository settings, not guarantees supplied
by workflow YAML. Recheck them before release; tag rechecks alone do not provide
atomic protection against concurrent changes.

## Security maintenance

The [weekly security workflow](../.github/workflows/security.yml) scans maintained
source and supported published binaries independently. A source fix does not
clear findings in an already published binary. Rebuild, scan, validate, and
publish a new release; deploy the new artifact rather than assuming a source
update repairs existing downloads.

