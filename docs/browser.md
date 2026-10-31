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
./wafmeow --target http://127.0.0.1:8080 --baseline --browser=navigate

# One viewport PNG, with explicit local saving
./wafmeow --target http://127.0.0.1:8080 --baseline \
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
- Text export records actual element/text ancestry in the isolated browser world,
  before HTML parsing could move content out of a recognized credential subtree.
  It acquires this additional structural snapshot only when `SaveText` is selected,
  with limits of 1 MiB, 16,384 nodes and 128 levels. Unsupported or over-limit
  snapshots withhold the text callback and mark `dom.save_state` as `failed`;
  screenshot export remains independent. Raw acquired DOM bytes and their
  `acquired_sha256` remain separate from the sanitized `wafmeow.browser-dom.v1`
  JSON artifact. Scripts, foreign content and the other excluded active subtrees
  are omitted structurally, so their text is never reparsed as HTML.
- Screenshot export requires actual clipping of recognized credential content
  to its mask rectangle. Layout rectangles alone do not bound glyph ink, even
  with upright fonts. Supported regions are native text inputs and textareas
  with clipping overflow and no authored element children, or ordinary
  block/flow-root/inline-block/flex/grid boxes with explicit CSS paint containment
  (`contain: paint`, `content`, or `strict`). Generic credential text without that
  containment makes screenshot saving fail closed. The page is not modified to
  add clipping or change its appearance.
- Expanded or uncertain `overflow-clip-margin`, inapplicable inline containment,
  dialog/popover descendants, visible overflow, zero-sized or `display:contents`
  wrappers, visibility uncertainty, generated content, and expanding paint
  effects also withhold image export. Subtrees hidden by `display:none` can be
  skipped safely, including ordinary hidden CSRF inputs. Credential-subtree
  checks inspect at most 4,096 nodes per capture, and ancestor checks stop at 128
  levels. On uncertainty or an exceeded limit, the screenshot callback is not
  invoked, `screenshot.save_state` is `failed`, and `--strict` exits 2 after
  publishing the report. DOM export remains independent. These checks do not
  guarantee secrecy for arbitrary page pixels.

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

