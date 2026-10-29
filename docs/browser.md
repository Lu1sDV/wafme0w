# Browser capture

[Quick start](../README.md) · [CLI usage](usage.md)

Browser capture adds rendering metadata and optional sanitized artifacts. It does
not contribute evidence to fingerprint matching.

## Requirements

Use Linux, a non-root user, and an installed native Chromium executable.
Chromium is discovered only when a browser mode is selected;
`--browser-path /path/to/native/chromium` overrides discovery. Shell wrappers and
automatic downloads are not supported. The sandbox, native user agent, and
certificate checks remain enabled.

## Capture modes

```sh
# Metadata and rendered DOM acquisition, without an image or saved files
./wafme0w --target http://127.0.0.1:8080 --baseline --browser=navigate

# One viewport PNG, with explicit local saving
./wafme0w --target http://127.0.0.1:8080 --baseline \
  --browser=screenshot --save-screenshots ./screenshots --jsonl
```

## Limits and scheduling

- `--browser=off|navigate|screenshot` defaults to `off`. Each valid in-scope input occurrence, including duplicates, gets its own browser attempt after HTTP acquisition—even after an HTTP failure or fingerprint match.
- `--browser-timeout` defaults to 30 seconds per admitted capture; `--browser-settle` defaults to a 2-second quiet interval. One Chromium process is active per run. HTTP timeouts, rates and request budgets remain separate.
- HTTP acquisition uses a separate bounded queue of at most `min(concurrency, 20)` body-free results. Two export workers can overlap sanitized asset saves with the next capture; library artifact callbacks must support concurrent calls. Result callbacks remain serial, in completion order.
- Capture observes load, DOM/network quiet, visible images and fonts, then one 1440×900 viewport. It does not scroll, click, solve challenges, exhaust future timers or stitch a full page. Retained DOM is limited to 1 MiB and PNG data to 2 MiB.
- Main-document scope follows the existing redirect policy. `--browser-allow-origin https://assets.example.test` permits an extra resource origin, still restricted by a nonempty `--allow-origin` list. CDP admits scoped GET/HEAD requests, with 40 intercepted starts and at most 3 main-document redirects (or the lower configured redirect cap).

## Artifacts

- `--save-screenshots DIR` saves masked PNGs and requires screenshot mode; it does not select a browser implicitly. Files use generated names under a private per-run directory.
- Library `BrowserConfig.SaveText` receives inert JSON, not raw HTML. Both export
  paths recognize exact normalized credential names in name/id/property fields,
  whitespace-delimited autocomplete tokens, password-type attributes, and
  credential `data-*` names or values. Substrings are not credential names;
  arbitrary text and pixels are not guaranteed secret-free.

## Scope and isolation

CDP request checks are not OS-enforced network isolation or hard Chromium resource
limits. Browser-internal/speculative traffic and unsupported channels have no
complete pre-transmission guarantee. Restricted or broken resources are reported;
the capture may differ from the site's unrestricted appearance. `--header`
configures Go HTTP acquisition, not Chromium.

## Results and compatibility

Browser metadata appears in the separate `browser` result field and never changes
fingerprint matches. `--strict` exits 2 for capture/export failures after report
publication. Result JSON uses schema 1 and omits browser metadata when capture is
off. CSV always ends with a `browser` JSON cell (`null` when off).
`--evidence` rejects live browser selection and remains zero-network.

The Go library uses the v2 module path. See [library versioning](library.md#versioning)
for API and report-schema compatibility.

