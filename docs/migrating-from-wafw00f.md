# Moving from wafw00f

[Quick start](../README.md) · [CLI usage](usage.md) · [Result semantics](operations.md)

This guide compares **wafw00f 2.4.2** with the wafme0w v2 CLI. Flag spellings and
input/output schemas differ; wafme0w is not a drop-in replacement. The upstream
reference is the [2.4.2 CLI source](https://github.com/EnableSecurity/wafw00f/blob/v2.4.2/wafw00f/main.py).

## Common commands

| Intent | wafw00f 2.4.2 | wafme0w v2 |
| --- | --- | --- |
| Scan one URL | `wafw00f URL` | `wafme0w --target URL` |
| Read a target list | `-i targets.txt` | `--input targets.txt` or `-I targets.txt`; one HTTP(S) URL per line |
| Read URLs from stdin | Supply an input file | `--input -`; `./-` is a literal filename |
| Continue after a named match | `-a` / `--findall` | All compiled catalogue products are classified by default; the probe sets and matching semantics differ |
| Disable redirects | `-r` / `--noredirect` | `--redirect-policy none --max-redirects 0` |
| Test one product | `-t PRODUCT` | No product-selection flag; provide an explicitly reviewed reduced catalogue with `--fingerprints FILE` |
| List products | `-l` / `--list` | `--list --silent --no-colors` |
| Save results | `-o report.json` | `--output report.json` or `-O report.json`; replacement is atomic |
| Choose file format | `-f json` | Use the output extension: `.json`, `.jsonl`, `.csv`, or `.txt`; other extensions select TXT |
| Write structured stdout | `-o - -f json`; one JSON array after the scan | `--jsonl`; streams one result object per line, including incomplete/failed targets |
| Add headers | `-H headers.txt` | Repeat inline `-H 'Name: value'`; this flag does not read a header file |
| Set request timeout | `-T 5` | `--request-timeout 5s`; separately set `--target-timeout 30s` |
| Select an HTTP proxy | `-p http://proxy:8080` | The default Go HTTP transport uses `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`; optional Chromium capture disables proxies and does not inherit those settings |
| Inspect diagnostics | `-v` / repeated `-v` | `--debug` emits body-free recorded observations to stderr |
| Disable colors | `--no-colors` | `--no-colors` or `NO_COLOR`; redirected human output is uncolored |
| Print version | `-V` / `--version` | `--version` |

wafw00f accepts additional CSV/JSON target-list formats. wafme0w's `--input`
expects plain URL lines. For ProjectDiscovery httpx JSONL, use
`--evidence - --evidence-format httpx`; see the
[producer/import contract](usage.md#httpx-response-import). A wafw00f result
report is not a saved HTTP response capture and cannot be imported as evidence.

## Choose collection intentionally

wafme0w's default mode selects up to nine active probes; `--fast` selects three.
`--baseline` sends the normal request only. Redirects and budgets can change the
actual request count. None of these modes is equivalent to every wafw00f run.

Offline `--evidence` classification sends no requests. Its conclusions depend on
the channels and completeness recorded in the capture; an imported prefix does
not become complete merely because it contains a marker.

## Update automation

A useful starting point for an authorized URL list is:

```sh
wafme0w --input authorized-urls.txt --baseline --jsonl --silent \
  --output results.json --strict --rate 5
```

Parse each JSONL record's `outcome.state`, `outcome.matches`, diagnostics, and
optional browser result. Keep incomplete/failed and unmatched results. Named
matches can coexist with incomplete evidence, and generic anomalies are separate.

| Exit | Meaning |
| --- | --- |
| 0 | No fatal run error; without `--strict`, individual results can still need review |
| 1 | Configuration, input, or output failure |
| 2 | Strict mode found incomplete, failed, or diagnosed results after report publication |
| 130 | Cancellation |

`--silent` requires `--jsonl` or an output file during scans. JSONL stdout stays
machine-readable; human summaries and debug messages go to stderr. See
[operations](operations.md) for publication and journal recovery details.

For Go integrations, import `github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w` and use
keyed public struct literals. The module major and result JSON schema 1 are
separate contracts.

