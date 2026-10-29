<p align="center">
  <img src="assets/wafme0w.webp" width="280" height="280" alt="The Wafme0w cat peeking over a brick firewall">
</p>

<h1 align="center">Wafme0w</h1>

<p align="center">Identify WAF fingerprints from live HTTP responses or saved captures.<br>A Go CLI and library with structured reports.</p>

<p align="center">
  <a href="go.mod"><img src="assets/badges/go.svg" alt="Go: 1.26+" height="26"></a>
  <a href="docs/usage.md"><img src="assets/badges/catalogue.svg" alt="Catalogue: 172 products" height="26"></a>
  <a href="LICENSE.md"><img src="assets/badges/license.svg" alt="License: MIT" height="26"></a>
</p>

<p align="center">
  <a href="#3-automate-and-save-results"><img src="assets/badges/output.svg" alt="Export: JSONL, JSON, CSV and TXT" height="26"></a>
  <a href="docs/usage.md#offline-captures"><img src="assets/badges/offline.svg" alt="Offline captures: no network" height="26"></a>
  <a href="https://github.com/Lu1sDV/wafme0w/actions/workflows/ci.yml"><img src="assets/badges/ci.svg" alt="CI: view workflows" height="26"></a>
</p>

<p align="center"><a href="#1-build">Quick start</a> · <a href="#benchmarks">Benchmarks</a> · <a href="#documentation">Documentation</a></p>

## 1. Build

Use a security-patched Go toolchain; release builds pin **Go 1.27.3**.

```sh
git clone https://github.com/Lu1sDV/wafme0w.git
cd wafme0w
go build -o wafme0w ./cmd/wafme0w
./wafme0w --help
```

**Release caveat:** published v1.0.0 binaries predate this checkout’s security
hardening. Use a newly scanned patch release for production; source changes do
not update existing downloads. [Installation, Docker and release details](docs/releases.md).

## 2. Scan an authorized target

```sh
# Use your own local HTTP server on port 8080.
./wafme0w --target http://127.0.0.1:8080 --baseline --jsonl
```

`--baseline` sends a normal request; default mode sends up to nine active probes,
and `--fast` selects three. Redirects remain subject to scope and request budgets.

### ProjectDiscovery httpx pipelines

```sh
# URL discovery followed by NEW wafme0w requests:
httpx -l authorized-hosts.txt -silent |
  ./wafme0w --input - --baseline --jsonl --silent

# Reuse exported observations with ZERO additional wafme0w requests:
httpx -l authorized-hosts.txt -silent -json -irr -probe -rstr 1048576 -rsts 1048576 |
  ./wafme0w --evidence - --evidence-format httpx --jsonl --silent
```

The importer targets **httpx v1.12.0**. Exported bodies lack completeness proof:
content matching stays unknown, while faithful status/header/cookie evidence can
match. This is not equivalent to active acquisition or proof of WAF absence.
Use `set -o pipefail` when upstream process failures must fail the shell pipeline.
[Encoding, limitations, limits and downstream recipes](docs/usage.md#httpx-response-import).

This checkout uses the Go module **`github.com/Lu1sDV/wafme0w/v2`** for the expanded
evidence API; result JSON remains schema 1 with optional nested metadata.

## 3. Automate and save results

```sh
# targets.txt: one authorized URL per line.
./wafme0w --input targets.txt --jsonl --output results.json --strict --rate 5
```

JSONL stays on stdout; human diagnostics go to stderr. `--strict` exits **2** after
publishing results when evidence or browser capture is incomplete/failed/diagnosed.
Configuration, input and output failures exit **1**; cancellation exits **130**.

## Benchmarks

**wafme0w vs wafw00f 2.4.2**, the same 500 Tranco targets, measured 29 October 2026.
Single sequential sweep using saved wafme0w build `347f547`, not this checkout's newer v2/httpx-import changes:

| Workers / processes | <img src="assets/wafme0w.svg" width="20" height="20" alt=""> wafme0w fast | <img src="assets/wafme0w.svg" width="20" height="20" alt=""> wafme0w full | wafw00f |
| --- | ---: | ---: | ---: |
| 1 | 6m 49.44s | 15m 51.93s | 14m 38.21s |
| 10 | 52.89s | 1m 45.62s | 2m 53.39s |
| 50 | 24.06s | 44.26s | 1m 50.93s |

Observed wall times, not equivalent-work speedups or accuracy. wafme0w emitted
500 results per cell; wafw00f omitted 157–159 targets. Higher concurrency changed
evidence completeness. [Settings, outcome counts, limitations and historical results](docs/benchmarks.md#live-cli-comparison--29-october-2026).

## Major caveats

- Scan only systems you own or are authorized to test. Default and fast modes are active.
- A fingerprint match is evidence, not proof of WAF enforcement. No match is not proof of absence; incomplete is not negative.
- Optional Chromium capture is not an OS-enforced network or resource sandbox.

## Documentation

| Guide | Contents |
| --- | --- |
| [CLI usage](docs/usage.md) | Modes, headers, scope, byte limits and cancellation |
| [Browser capture](docs/browser.md) | Chromium setup, screenshots and sanitized exports |
| [Operations](docs/operations.md) | Result semantics, safe report consumption, deployment and soak checks |
| [Releases](docs/releases.md) | Installation, Docker, validation, security scans and publication controls |
| [Go library](docs/library.md) | Working example, ownership and streaming contracts |
| [Benchmarks](docs/benchmarks.md) | Reproducible measurements, offline comparison and historical results |

[MIT license](LICENSE.md) · Fingerprints from [wafw00f](https://github.com/EnableSecurity/wafw00f/) · Contributor [@Fibonaccispiralz](https://github.com/Fibonaccispiralz)
