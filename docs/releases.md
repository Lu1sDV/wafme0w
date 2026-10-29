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
captures under `assets/demo/`.

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

The [Dockerfile](../Dockerfile) builds the source tree with Go 1.27.3 and copies
the static binary and CA certificates into a `scratch` runtime image. It contains
neither a shell nor Chromium. Browser capture requires a native Linux installation.

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

Human scans spool their final URL table under `/tmp`; the image provides this
directory with mode 1777. For a read-only runtime, mount writable temporary
storage (size it for the number and length of result rows). For example, an
offline, non-root scan with captures mounted read-only:

```sh
docker run --rm --network none --read-only --user 65532:65532 \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m,mode=1777 \
  -v "$PWD/assets/demo:/captures:ro" wafme0w:latest \
  --evidence /captures/captures.jsonl --no-colors
```

`--jsonl` and `--silent` do not need the human-table spool. Saved report files
still require their own writable output location.

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

Administrators must enforce required branch checks, prevent version-tag
updates/deletion, restrict release permissions, and enable immutable releases.
These are repository settings, not guarantees supplied by workflow YAML. Tag
rechecks alone do not provide atomic protection against concurrent changes.

## Security maintenance

The [weekly security workflow](../.github/workflows/security.yml) scans maintained
source and supported published binaries independently. A source fix does not
clear findings in an already published binary. Rebuild, scan, validate, and
publish a new release; deploy the new artifact rather than assuming a source
update repairs existing downloads.

