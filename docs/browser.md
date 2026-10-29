# Browser capture

[Quick start](../README.md) · [CLI usage](usage.md)

Browser capture is optional and currently requires Linux, a non-root user, and an installed native Chromium executable:

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
- HTTP acquisition uses a separate bounded queue of at most `min(concurrency, 20)` body-free results. Two export workers can overlap sanitized asset saves with the next capture; library artifact callbacks must support concurrent calls. Result callbacks remain serial, in completion order.
- Capture observes load, DOM/network quiet, visible images and fonts, then one 1440×900 viewport. It does not scroll, click, solve challenges, exhaust future timers or stitch a full page. Retained DOM is limited to 1 MiB and PNG data to 2 MiB.
- Main-document scope follows the existing redirect policy. `--browser-allow-origin https://assets.example.test` permits an extra resource origin, still restricted by a nonempty `--allow-origin` list. CDP admits scoped GET/HEAD requests, with 40 intercepted starts and at most 3 main-document redirects (or the lower configured redirect cap).
- `--save-screenshots DIR` saves masked PNGs and requires screenshot mode; it does not select a browser implicitly. Files use generated names under a private per-run directory.
- Library `BrowserConfig.SaveText` receives inert JSON, not raw HTML. Both export
  paths recognize exact normalized credential names in name/id/property fields,
  whitespace-delimited autocomplete tokens, password-type attributes, and
  credential `data-*` names or values. Substrings are not credential names;
  arbitrary text and pixels are not guaranteed secret-free.

**Local browser limits:** CDP request checks are not OS-enforced network isolation or hard Chromium resource limits. Browser-internal/speculative traffic and unsupported channels have no complete pre-transmission guarantee. Restricted or broken resources are reported; this is not necessarily the site's unrestricted appearance. `--header` configures Go HTTP acquisition, not Chromium.

Browser metadata appears in a separate `browser` result field and never changes fingerprint matches. `--strict` also reports capture/export failures with exit 2 after report publication. Browser-off JSON remains unchanged; CSV now always ends with a `browser` JSON cell (`null` when off). `--evidence` rejects live browser selection and remains zero-network.

As of v1.0.0, result schema 1 (with the optional `browser` field), the CSV column layout, CLI flags and exit codes, and the Go library API below form the stable 1.x baseline; backward-incompatible changes require a new major version.
