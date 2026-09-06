# Browser capture subsystem design

**Status:** written design set approved for planning on 2026-09-06. Browser-capture implementation planning is authorized; application implementation is not.

[Shared contracts, budgets and acceptance ownership](2026-09-06-ai-integration-design.md) are normative for this subsystem. Delivery order is browser capture, AI enrichment, then controlled-edge TLS comparison; this document does not remove the later features.

## Responsibility and non-goals

Acquire a bounded initial browser observation for each explicitly supplied URL occurrence, independently of deterministic matches and AI eligibility. Return useful local metadata/DOM and, when selected, one viewport screenshot. Own containment, readiness, privacy for saved artifacts, lifecycle and browser reporting.

Do not classify browser observations as catalogue matches, crawl links, solve challenges, modify TLS identity, add stealth, scroll to load off-screen content, operate a logged-in user browser or invoke a provider. Browser-induced challenges are observations; their cause is not established merely by a different response.

Use Rod directly, following the capture-only boundary already confirmed. Do not embed httpx or gowitness runners, databases, viewers or executables. No generic browser-engine interface or browser pool is needed for one implementation.

## Inputs, outputs and integration

**Proposed configuration:** `--browser=off|navigate|screenshot`, `--browser-path`, `--browser-timeout`, `--browser-settle`, `--artifacts`, `--save-screenshots DIR`, plus explicit caller-supplied resource origins/destination policy. Both browser and AI remain off by default. Screenshot-saving requires screenshot mode; it does not select that mode implicitly.

CLI resolves a configured existing browser binary and artifact destinations; the library receives values and policy. Never download Chromium during a scan. Invalid selected configuration is rejected before acquisition; help/list and browser-off operation do not discover or require Chromium. Stage-one browser-only operation needs no provider key or TLS observation service.

Reuse the current URL parser and `classifyTarget` orchestration. Every valid admitted supplied occurrence, including duplicates, gets its selected attempt; HTTP failures, named matches and future AI refusals do not suppress it. Maintain current run-level input/sink/cancellation behavior and serial completion-order emission.

A capture contains:

- Stable capture ID, input occurrence, selected mode and queue/acquisition timestamps.
- Initial/final URL, actual main-document request/loader/connection identity where available, status and repeated response headers; redirect and source provenance.
- Bounded rendered DOM with acquisition/truncation status, never substituted for Go HTTP response bytes.
- Browser version, viewport, readiness signals, effective limits, admitted/denied request counts, known resource failures/restrictions and stop reason.
- For an acquired image only: MIME, dimensions, encoded digest and image reference, with separate acquired/transmitted/saved status.

Collect actual CDP response events: the reviewed httpx capture helper's basic metadata does not satisfy the full response-header requirement. Headers, DOM and image refer to their actual document; they are not an atomic snapshot. Reset readiness identity on navigation rather than associating later pixels with an earlier document.

Browser owns acquisition data and its lifetime. Report builders, artifact writers and later AI/TLS consumers use the shared capture identity without duplicating image ownership or mutating raw evidence. No TLS-specific parser or unused AI scaffold is required in this delivery; ordinary main-document metadata is the future integration boundary.

## Proposed supported runtime and containment

Start with a **Linux browser-capable container deployment**, an explicitly selected alternative to the existing minimal scratch image. Keep the minimal deterministic image as default. The supported browser deployment runs non-root Chromium with its sandbox and certificate verification intact. Direct host-browser portability is not claimed before equivalent enforcement is proved.

There are two separate enforcement boundaries:

1. **Logical requests:** before navigation, a Rod/CDP adapter applies shared URL/origin decisions, method restrictions, redirect/request budgets and controls for new browsing/worker contexts. Target origins alone are allowed by default; extra resource origins require caller configuration. Block state-changing methods, downloads, unsolicited windows and unaccounted channels before transmission. Logs after transmission are not enforcement.
2. **Network destinations:** the browser's isolated runtime enforces an external address/port egress policy derived from the caller's permitted destinations, with controlled resolution and protection against address changes escaping that policy. Apply it across supported address families and network paths; Chromium must not have an unrestricted alternate route. Hostname matching, a container by itself, and Go's `RoundTripper` do not provide this guarantee.

The first browser implementation plan must make that deployment policy concrete and demonstrate denial using owned fixtures before exposing the mode as supported. A runtime unable to establish the boundary fails capture explicitly. This is a required deployment capability, not a claim that existing code or a generic Docker launch already supplies it. Do not replace browser acquisition with Go fetches or terminate/recreate TLS elsewhere and call it a Chromium connection.

Report restrictions and failed resources. Same-origin defaults can exclude external fonts/scripts/images; a restricted render must not be represented as the site's unrestricted appearance. Chromium memory/network use is not capped by Go's retained-DOM limit. Use OS/container resource controls where hard renderer limits are required and only advertise guarantees actually verified.

## Lifecycle and readiness

Use one run-owned capture permit and a fresh owned Chromium process/profile per capture. Start the acquisition deadline only after permit admission; queued work holds no browser process. Cancellation interrupts waiting and active work. Release handles, terminate the owned process and remove its temporary profile on every exit path. Pass a minimal environment without provider credentials or unrelated secrets.

Retain native Chromium identity. With Rod, select `NoDefaultDevice` before setting the capture viewport; do not copy device/user-agent overrides, script-injection features, relaxed certificate checks or `--no-sandbox` defaults from another scanner. Pin and verify Rod/Chromium compatibility during implementation; source-branch inspection is not a tested dependency pin.

`navigate` acquires metadata and DOM only. `screenshot` uses the same navigation and adds one image after readiness. Neither mode clicks, scrolls, stitches a full page or retries a challenge.

Within the shared acquisition deadline:

1. Observe main-document load and retain its identity. A new main-document navigation invalidates the previous readiness state.
2. Observe a configurable quiet interval for DOM changes and finite relevant document/script/style/fetch activity. Record exclusions; long-lived streams must not require endless waiting.
3. Require currently visible viewport images to finish loading/decoding and used fonts to finish loading, or record explicit failure/denial. New visible elements reset the applicable checks.
4. After settling, observe a rendering opportunity and collect bounded DOM/metadata and the selected image. Do not start capture work after the deadline.

The shared initial proposal is 60 seconds including launch and capture, with a 2-second quiet window. `Navigate`, `DOMContentLoaded`, a fixed sleep, DOM stability or Rod request-idle alone is insufficient for the visible-image/font contract. Future timers and off-screen lazy content need not be exhausted. Continuously changing pages can time out; never report "all DOM loaded."

## Failure and artifact semantics

A challenge page may be a successfully acquired observation. A successfully acquired render with blocked/broken resources is restricted and carries limitations. Missing required metadata/DOM, failed selected screenshot or readiness timeout is failed/incomplete capture, with any already obtained metadata preserved honestly.

The retained shared proposal skips later assessment on a selected required-modality failure. Intentionally unselected images are not failures. No browser error erases a valid deterministic result or establishes WAF absence, anti-bot causation or enforcement.

Acquisition and saving are independent. `--artifacts` may retain bounded sanitized text, not image bytes without `--save-screenshots`. With saving off, wafme0w retains no screenshot file or image-bearing evidence bundle; ordinary output may include metadata/digests. Temporary Chromium cache/profile data is separately disclosed and best-effort deletion is not secure erasure.

Saved images use the shared privacy boundary, including masking identified secret-field regions. This boundary belongs to export/artifact handling, not the AI adapter; browser-only saving must be safe without an AI dependency. Sanitization/write failures are explicit, never raw-content fallback, claimed saving or an automatic revisit. Reuse private generated filenames, path-collision checks and atomic publication where applicable.

## Files and ownership

- `pkg/wafme0w/options.go`: selected-capability validation and browser execution defaults.
- `pkg/wafme0w/runner.go`: independent capture phase and optional browser report; retain callback/input ownership.
- A small browser acquisition area: Rod/CDP controls, readiness, provenance and lifecycle. Split by genuine responsibility only if needed; do not put AI or TLS comparison logic here.
- Existing acquisition/URL utilities: reuse decisions and parser behavior rather than inventing a second HTTP policy. Chromium still needs its own enforcement adapter.
- Shared export helpers and existing output writers: sanitized artifacts, browser JSON/TXT/CSV and terminal state.
- `cmd/wafme0w/main.go`: flags, binary resolution, file ownership and safe rendering.
- `go.mod`, `go.sum`, `Dockerfile`: pinned Rod and explicit supported browser packaging, without changing the default scratch runtime into a browser image.

Use LSP references before exported-symbol changes and migrate affected callers/tests/docs in the same implementation change. Stage one adds only the browser output contract; no empty future AI report/column or TLS parser.

## Independent acceptance gate

Use owned fixtures and launch the actual CLI/Chromium surface; no arbitrary public-site probing.

1. **Independence:** browser off causes no Chromium activity; browser-only needs no key; help/non-network listings need neither. Explicit provider-model discovery belongs to the AI delivery and must not launch Chromium. Every admitted input occurrence is attempted despite HTTP match/failure. Verify duplicate handling, cancellation and serial output.
2. **Identity/provenance:** a fixture returns different Go HTTP and browser-rendered content. Preserve case-sensitive URL path/query/escaping, actual browser headers and document IDs. Visually confirm the screenshot describes its browser document, not the original HTTP response.
3. **Containment:** observe blocked origins, resolution/destination restrictions, redirects, workers/new contexts and denied channels outside Chromium, not just in event logs. Verify TLS certificate failure, sandbox operation and selected runtime resource restrictions. Unsupported enforcement fails before claiming a successful supported capture.
4. **Readiness:** delayed JavaScript, visible images and fonts appear in the initial viewport; a scroll-only asset is not requested. Continuous mutation and slow/broken assets yield bounded timeout or explicit restriction. Navigation mode produces no image.
5. **Lifecycle/privacy:** exercise launch failure, timeout and cancellation; verify no orphaned processes/profiles or leaked child-environment secrets. Inspect actual sanitized artifacts and confirm raw HTTP inputs are unchanged.
6. **Saving/output:** saving off produces no image artifact/bundle; saving on with AI off publishes a private sanitized image and truthful reference. Exercise write/sink errors, empty reports and cancellation through actual JSON/CSV/TXT and terminal paths. Preserve journaling and aggregate atomic replacement.

Passing this gate completes browser capture only. AI and TLS acceptance remain separate. No runtime checks above have been performed for this design-only change.

## Research references

Historical source research informed the reuse boundary: [httpx capture](https://github.com/projectdiscovery/httpx/blob/dev/runner/headless.go), [Rod page/readiness helpers](https://github.com/go-rod/rod/blob/main/page.go), [Rod browser/device defaults](https://github.com/go-rod/rod/blob/main/browser.go). Recheck selected pinned versions during implementation.

[Rod](https://github.com/go-rod/rod/blob/main/LICENSE) and [httpx](https://github.com/projectdiscovery/httpx/blob/dev/LICENSE.md) were reviewed as MIT-licensed; [gowitness](https://github.com/sensepost/gowitness/blob/master/LICENSE) as GPLv3. Sharing Rod does not authorize copying gowitness code under a different license. Review the actual pinned dependencies' licenses; no full-scanner code reuse is proposed.
