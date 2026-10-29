# Releases and security maintenance

[Quick start](../README.md) · [Operations](operations.md)

## Build and install

The published [v1.0.0](https://github.com/Lu1sDV/wafme0w/releases/tag/v1.0.0) archives below are historical builds, not patched builds of this checkout. They predate the current dependency and toolchain security refresh. Production deployment requires a newly built, scanned patch release; updating source does not repair downloaded binaries.

| Platform | Archive |
| --- | --- |
| Linux x64 | [tar.gz](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_linux_amd64.tar.gz) |
| macOS Apple silicon | [tar.gz](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_darwin_arm64.tar.gz) |
| Windows x64 | [zip](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_windows_amd64.zip) |

Check the archive's SHA-256 against [SHA256SUMS](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/SHA256SUMS), extract it, and put `wafme0w` (`wafme0w.exe` on Windows) on your `PATH`. Archives include the synthetic demo captures under `assets/demo/`.

### Install with Go

Building from source requires **Go >= 1.26** and a supported security-patched toolchain. Release builds pin **Go 1.27.3**. This checkout targets the v2 Go module; after a v2 release is published, install it with:

```sh
go install -v github.com/Lu1sDV/wafme0w/v2/cmd/wafme0w@latest
```

Until v2 is published, build this checkout instead (the command above does not publish or install unreleased work):

```sh
go build -o wafme0w ./cmd/wafme0w
```

## Container image

The image builds the local checkout with Go 1.27.3, then copies the static binary and CA certificates into a minimal runtime image.
Browser capture runs locally on Linux and requires installed Chromium; the minimal scratch image does not include a browser.

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

The checked-in release workflow resolves the requested tag once and validates
that exact commit. Publication requires formatting, vet, race tests, source
vulnerability checks, bounded matcher fuzzing, isolated offline comparison, real
Chromium integration, container checks, and native tests on all three release OSes.
Archives are extracted outside the checkout; their actual binaries must identify
the prepared SHA, an unmodified tree, the intended target, and Go 1.27.3 before
binary vulnerability scans. `manifest.json` records those identities and hashes;
`SHA256SUMS` also covers the manifest, and publication requires an attestation.

Tags use `vMAJOR.MINOR.PATCH[-PRERELEASE]` without build metadata. Prereleases never
become latest, and older stable releases cannot replace a higher stable release
as latest. Weekly security checks reassess maintained source and supported
published binaries independently; a source fix does not clear an old binary.

Before publishing, administrators must enforce required branch checks, prevent
version-tag updates/deletion, restrict release permissions, and enable immutable
releases. Tag rechecks alone are not atomic protection against concurrent changes.
These are repository settings, not guarantees supplied by YAML. Hosted native
jobs and attestations must pass on the committed candidate; local cross-builds
and agent reviews do not substitute for them.

Publications use a non-cancelling queue with up to 100 pending jobs. Archive checks
limit compressed input to 64 MiB, individual and aggregate member payloads to
128 MiB, and total TAR expansion (including extension headers) to 160 MiB.
Scanner output is written as it arrives, including diagnostics retained on timeout.

The current actionlint 1.7.12 parser does not recognize GitHub’s documented
`concurrency.queue: max` field; its syntax diagnostic is a checker limitation, not
a reason to remove the queue. Hosted GitHub validation is still required. See
[GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
and the [actionlint parser](https://github.com/rhysd/actionlint/blob/v1.7.12/parse.go#L809-L825).
