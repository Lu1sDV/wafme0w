<p align="center">
  <img src="assets/wafme0w.webp" width="280" height="280" alt="A gray cat peeking over a brick firewall — the Wafme0w mascot">
</p>

<h1 align="center">Wafme0w</h1>

<p align="center">Blazingfast, lightweight WAF detector.</p>

<p align="center">
  <a href="go.mod">Go 1.26+</a> &nbsp;·&nbsp;
  <a href="#overview">172 products</a> &nbsp;·&nbsp;
  <a href="LICENSE.md">MIT license</a>
</p>

<p align="center">
  <a href="#installation">Installation</a> &nbsp;·&nbsp;
  <a href="#usage">Usage</a> &nbsp;·&nbsp;
  <a href="#benchmarks">Benchmarks</a> &nbsp;·&nbsp;
  <a href="#go-library">Go library</a>
</p>

---

[Synthetic captures](assets/demo/captures.jsonl) · [Text transcript](assets/demo/transcript.txt) · [Replayable terminal recording](assets/demo/demo.cast)

## Overview

Wafme0w identifies web application firewall fingerprints in HTTP responses. Built in Go with signatures sourced from [wafw00f](https://github.com/EnableSecurity/wafw00f/), it pairs concurrent collection with clear, structured results.

Use it from your terminal, feed results into your scripts, or bring the same matcher into a Go application. Already have saved responses? Analyze them offline without sending another request.

| What you need | What Wafme0w offers |
| --- | --- |
| **Recognize WAF fingerprints** | A bundled catalogue covering 172 products |
| **Stay in control** | Configurable concurrency, request budgets and redirect scope |
| **Work with your tools** | JSONL, JSON, CSV and TXT output for scripts and reports |
| **Revisit saved responses** | Offline analysis with zero network requests |
| **Inspect rendered pages** | Optional local headless Chromium navigation and viewport screenshots |
| **Build with Go** | A reusable, concurrency-safe compiled matcher |

> **Know what a match means:** Fingerprints are clues, not proof of active WAF enforcement. An incomplete result is not a clean negative. Only assess systems you own or are authorized to test.

## Installation
Download a tested binary from [v1.0.0](https://github.com/Lu1sDV/wafme0w/releases/tag/v1.0.0); no Go installation is needed:

| Platform | Archive |
| --- | --- |
| Linux x64 | [tar.gz](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_linux_amd64.tar.gz) |
| macOS Apple silicon | [tar.gz](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_darwin_arm64.tar.gz) |
| Windows x64 | [zip](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/wafme0w_v1.0.0_windows_amd64.zip) |

Check the archive's SHA-256 against [SHA256SUMS](https://github.com/Lu1sDV/wafme0w/releases/download/v1.0.0/SHA256SUMS), extract it, and put `wafme0w` (`wafme0w.exe` on Windows) on your `PATH`. Archives include the synthetic demo captures under `assets/demo/`.

### Install with Go

Building from source requires **Go >= 1.26**. To install the latest published version:

```sh
go install -v github.com/Lu1sDV/wafme0w/cmd/wafme0w@latest
```

To build this checkout instead:

```sh
go build -o wafme0w ./cmd/wafme0w
```

### Docker

<details>
<summary>Build and inspect the container without networking</summary>

The image builds the local checkout with Go 1.27, then copies the static binary and CA certificates into a minimal runtime image.
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

</details>

## Usage

Inspect the CLI or list the bundled catalogue without sending requests:

```sh
wafme0w --help
wafme0w --silent --list --no-colors
```

### Collection modes

| Mode | Network behavior |
| --- | --- |
| Default | Up to nine selected active requests, before redirects |
| `--fast` | Three selected active requests; fewer requests, **not passive** or a latency guarantee |
| `--baseline` | One normal request, subject to redirect and request budgets |


### Headless browser capture

The options below are included in the v1.0.0 binaries. They require Linux, a non-root user and an installed native Chromium executable:

```sh
# Metadata and rendered DOM acquisition, without an image or saved files
./wafme0w --target http://127.0.0.1:8080 --baseline --browser=navigate

# One viewport PNG, with explicit local saving
./wafme0w --target http://127.0.0.1:8080 --baseline \
  --browser=screenshot --save-screenshots ./screenshots --jsonl
```

Chromium is discovered only when selected; `--browser-path /path/to/native/chromium` overrides discovery. Shell wrappers and automatic downloads are not used. Its sandbox, native user agent and certificate checks stay enabled. No container, AI provider or API key is required.

- `--browser=off|navigate|screenshot` defaults to `off`. Each valid in-scope input occurrence, including duplicates, gets its own browser attempt after HTTP acquisition—even after an HTTP failure or fingerprint match.
- `--browser-timeout` defaults to 30 seconds per admitted capture; `--browser-settle` defaults to a 2-second quiet interval. One Chromium process is active per run. HTTP timeouts, rates and request budgets remain separate.
- Capture observes load, DOM/network quiet, visible images and fonts, then one 1440×900 viewport. It does not scroll, click, solve challenges, exhaust future timers or stitch a full page. Retained DOM is limited to 1 MiB and PNG data to 2 MiB.
- Main-document scope follows the existing redirect policy. `--browser-allow-origin https://assets.example.test` permits an extra resource origin, still restricted by a nonempty `--allow-origin` list. CDP admits scoped GET/HEAD requests, with 40 intercepted starts and at most 3 main-document redirects (or the lower configured redirect cap).
- `--save-screenshots DIR` saves masked PNGs and requires screenshot mode; it does not select a browser implicitly. Files use generated names under a private per-run directory.

**Local browser limits:** CDP request checks are not OS-enforced network isolation or hard Chromium resource limits. Browser-internal/speculative traffic and unsupported channels have no complete pre-transmission guarantee. Restricted or broken resources are reported; this is not necessarily the site's unrestricted appearance. `--header` configures Go HTTP acquisition, not Chromium.

Browser metadata appears in a separate `browser` result field and never changes fingerprint matches. `--strict` also reports capture/export failures with exit 2 after report publication. Browser-off JSON remains unchanged; CSV now always ends with a `browser` JSON cell (`null` when off). `--evidence` rejects live browser selection and remains zero-network.

As of v1.0.0, result schema 1 (with the optional `browser` field), the CSV column layout, CLI flags and exit codes, and the Go library API below form the stable 1.x baseline; backward-incompatible changes require a new major version.

### Request headers

Use `-H` / `--header` to add comma-separated `Name: value` entries. Names are case-insensitive: later entries and repeated flags replace earlier values and built-in defaults, including `Origin` and `User-Agent`.

```sh
wafme0w --target http://127.0.0.1:8080 --baseline \
  -H 'Origin: https://example.test, User-Agent: my-client' \
  --header 'X-Tag: demo, "Accept: text/html, application/json"'
```

CSV-quote the **whole entry** when its value contains a comma; double embedded quotes inside a quoted entry. A quoted entry cannot be the **first** field: a value beginning with `"` is treated as one fully quoted argument and rejected. `-H 'User-Agent:'` suppresses the wire User-Agent. An explicit User-Agent also overrides the no-UA request's default.

Overrides apply to every selected request.

### Inputs and limits

| Setting | Behavior |
| --- | --- |
| URL input precedence | `--input`, then `--target`, then stdin; blank lines ignored |
| Target line size | Go's 64 KiB scanner token limit |
| Catalogue size | At most 8 MiB; one JSON array with known fields and valid HTTP header names |
| Concurrency | `--concurrency` defaults to 20 and must be positive |
| Response body size | `--max-body-bytes` defaults to 1,048,576 decoded bytes and must be positive |
| Request / target deadlines | `--request-timeout` defaults to 5s; `--target-timeout` to 30s |
| Requests per target | `--max-requests` defaults to 54, including redirects |
| Globally in-flight requests | `--max-connections` defaults to 20, including body reads |
| Redirect limit | `--max-redirects` defaults to 5 per request; 0 follows none |

Bodies are bounded after gzip/deflate decoding. Unsupported encodings, truncation and read errors retain usable response metadata without treating unavailable content as a clean negative. The header option is `-H` / `--header` (singular); the old `--headers` spelling remains unsupported.

## Benchmarks

### Saved runs · 1,000 targets

These tables summarize previously saved runs with corrected detection counts; they are not a fresh benchmark of this checkout. “WAFs found” counts targets with named detections, not distinct WAF products. Named and generic detections can overlap.

#### Parallelism: 1

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 1 worker | 19min 10.43s | 359 | 180 | 0% |
| **wafme0w** | Full, 1 worker | 30min 2.91s | 354 | 206 | +56.7% |
| wafw00f | 1 process | 47min 3.94s | 354 | 166 | +145.5% |

#### Parallelism: 10

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 10 workers | 3min 39.69s | 358 | 178 | 0% |
| **wafme0w** | Full, 10 workers | 2min 49.17s | 355 | 207 | −23.0% |
| wafw00f | 10 processes | 9min 31.50s | 353 | 167 | +160.1% |

#### Parallelism: 50

| Tool | Mode / parallelism | Time elapsed | WAFs found | Generic WAFs found | Diff¹ |
| --- | --- | ---: | ---: | ---: | ---: |
| **wafme0w** | Fast, 50 workers | 52.33s | 358 | 176 | 0% |
| **wafme0w** | Full, 50 workers | 1min 19.59s | 357 | 205 | +52.1% |
| wafw00f | 50 processes | 4min 1.22s | 351 | 162 | +361.0% |

## Go library

Match an already captured response without sending any requests:
```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func main() {
	responses := []wafme0w.Evidence{{
		Role: "Normal", StatusCode: 403, Reason: "Forbidden",
		Body: []byte("Blocked by Example WAF"),
	}}
	wafs := []wafme0w.WAF{{
		Name: "Example WAF",
		Schemas: []wafme0w.Scheme{{
			FingerPrints: []wafme0w.FingerPrint{{
				Type: "Content", Pattern: "(?i)blocked by example waf",
			}},
		}},
	}}
	engine, err := wafme0w.Compile(wafs)
	if err != nil {
		log.Fatal(err)
	}
	outcome := engine.Classify(responses)
	if err := json.NewEncoder(os.Stdout).Encode(outcome); err != nil {
		log.Fatal(err)
	}
}

```

## Credits and contact

- **Fingerprint source:** [wafw00f](https://github.com/EnableSecurity/wafw00f/).
- **Contributor:** [@Fibonaccispiralz](https://github.com/Fibonaccispiralz).
- **Project:** [github.com/Lu1sDV/wafme0w](https://github.com/Lu1sDV/wafme0w).

## License

Released under the [MIT License](LICENSE.md). Copyright © 2022.
