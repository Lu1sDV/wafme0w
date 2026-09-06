# Browser capture implementation plan

**Status:** plan drafted after written-design approval on 2026-09-06; application implementation is not authorized. The user approved preparing this browser-only plan, not executing it.

**Authority:** [shared contracts](../specs/2026-09-06-ai-integration-design.md) and [browser design](../specs/2026-09-06-browser-capture-design.md). Screenshot capture remains in active scope. AI enrichment is retained as `soon` and disabled, not a required delivery or a task in this plan. Controlled-edge TLS comparison remains a separate later delivery.

**Planning method:** `writing-plans` was unavailable in the installed skill registry and checked local skill paths. This is a direct repository-grounded plan; no skill was installed. No browser feature, dependency compatibility, containment profile or runtime acceptance check has been implemented or demonstrated by writing it.

## Goal and cutover

Deliver independently selected, bounded initial browser observations for every valid admitted input occurrence. Support metadata/DOM-only navigation and one viewport screenshot, with explicit local saving, honest limitations and the existing deterministic result preserved.

Keep browser-off execution and offline `RunCaptured` independent of Chromium. Keep AI disabled: no AI flags, credential/login access, providers, model discovery, generation/replay or AI reports/columns. Do not add TLS observation parsing, crawling, stealth, challenge interaction, TLS identity manipulation, browser pooling or a generic browser-engine interface. Do not change catalogue rules or matching behavior.

The smallest complete supported deployment is the existing application plus an optional Linux browser image and one concrete isolation helper. A normal container or CDP interception alone cannot meet the destination boundary. Establish that boundary first; do not ship a host-browser fallback if it fails.

## Current repository seams

| Existing path and symbols | Observed contract / planned use |
|---|---|
| [options.go](../../../pkg/wafme0w/options.go): `Config`, `DefaultConfig`, `normalized`, `validate` | Copied configuration; finite defaults and validation before input. Add only selected browser configuration. |
| [runner.go](../../../pkg/wafme0w/runner.go): `Run`, `classifyTarget`, `makeResult`, `Result` | Unbuffered queues, bounded workers, serial completion-order callbacks. `classifyTarget` currently scopes `TargetTimeout` to `sendRequests`; keep browser work outside that child context. |
| [acquisition.go](../../../pkg/wafme0w/acquisition.go): `normalizedOrigin`, `parseAllowedOrigin`, `wwwAliasOrigin`, `targetTransport.allowed` | Reuse exact-origin normalization, fixed alias and allowlist precedence. These functions do not enforce IP containment. |
| [capture.go](../../../pkg/wafme0w/capture.go): `RunCaptured` | Zero-network, input-order classification. Reject selected browser acquisition here rather than silently performing or ignoring it. |
| [output.go](../../../pkg/wafme0w/output.go): `NewResultWriter`, `ResultWriter.Write`, `Close` | Fixed CSV header at construction; JSON/JSONL serialize `Result`; first sink error retained. Extend in place. |
| [main.go](../../../cmd/wafme0w/main.go): `options`, `runContext`, `validateOptions` | CLI owns binary/path resolution, input and report publication. Journal callback runs before fallible report sinks. |
| [journal.go](../../../cmd/wafme0w/journal.go): `checkFileCollisions`, `diagnosticsJournal.result` | Canonical-path/inode alias checks and independently synced body-free recovery records. |
| [banner.go](../../../cmd/wafme0w/banner.go): `printResult`, `resultCounts.add`, `printSummary`, `terminalText` | Deterministic summary counts and terminal escaping; add separate browser status and strictness, not altered match truth. |
| [atomicfile.go](../../../internal/atomicfile/atomicfile.go): `Write` | Private temporary file and atomic replacement after successful write/flush/sync/close; reuse inside a private generated artifact directory. |
| [offlinebench/run.go](../../../internal/offlinebench/run.go): `sandboxBase` | Existing namespace, minimal-environment and parent-death conventions. Reuse those conventions, not the optional benchmark package or its Python runtime in the scan path. |
| [Dockerfile](../../../Dockerfile), [CI](../../../.github/workflows/ci.yml) | Scratch is the current default image; CI already uses a scoped bubblewrap/AppArmor setup for a different subsystem. Neither proves browser containment. |

The planning session's gopls references were stale even after reload; this was reported as a tool issue. The map above was grounded in current disk sections and caller searches instead. Before implementation changes any exported API, retry LSP references and reconcile them with current source. If the tool remains unavailable, document the current-source fallback rather than using stale positions as a migration list.

## Concrete runtime and policy to review

These details implement the approved containment requirement; they are plan choices, not verified capabilities.

### Explicit destination policy

Add `--browser-policy FILE`, required when a browser mode is selected. The bounded, versioned JSON document contains `version`, `resource_origins` and `destinations`; each destination has an exact HTTP(S) `origin` and a nonempty list of literal IPv4/IPv6 `addresses`. Port comes from the normalized origin. The library receives parsed immutable values, not a policy filename.

Use a 1 MiB policy-file ceiling. Reject duplicate JSON keys, unknown fields, trailing values, duplicate normalized origins, invalid/unbounded address collections, unspecified/multicast/zoned addresses and ambiguous origins before allocation or acquisition. A finite file ceiling bounds the collection; do not add a configuration framework. An explicit loopback/private destination is valid for an owned fixture; it is not silently authorized by a hostname.

This version uses caller-provided address pins instead of a DNS resolver or automatic address refresh. Chromium has no external DNS route, and the broker dials only numeric addresses from the frozen policy. A changed address cannot widen access. No wildcards, CIDRs, environment-proxy inheritance or broad public-network fallback are needed. Document the operational consequence: the operator must update pins when an authorized service changes address.

Destination entries grant network reachability only, not logical URL authority. Starting URLs and main-document redirects retain current allowlist/fixed-alias precedence. Extra resource origins are an explicit additional resource permission, still intersected with a nonempty global `AllowedOrigins` ceiling. Subresources do not become allowed top-level navigations. Missing destination entries fail the affected capture/request; unread stream inputs are not pre-scanned or silently deduplicated.

### Two enforcement layers

1. **Outside Chromium:** a run-owned broker admits only TCP connections to exact permitted authority/address/port tuples for the current capture. Use a minimal TCP-CONNECT-only SOCKS5 endpoint over a private local channel; reject other commands and UDP association. Resolve no names in the broker: match the requested authority to its frozen pins. Do not terminate TLS or fetch a replacement response with a Go HTTP client. Bound broker clients/connections by the capture request ceiling and close all tunnels on cancellation.
2. **Inside isolation:** bubblewrap establishes a fresh network namespace with loopback only, plus private PID/IPC and temporary profile state. A packaged `wafme0w-browser` helper relays a loopback proxy socket to the private broker channel and launches the selected Chromium binary. There is no veth, default route, alternate interface or external UDP route in that namespace. The broker remains outside it. The helper is a fixed bootstrap/relay, not a general command execution service.
3. **Logical admission:** Rod/CDP attaches before navigation and applies the shared origin decision, GET/HEAD-only policy, 40-start budget and redirect cap across supported frames/worker contexts. Block downloads, unsolicited windows, WebSocket/other unsupported channels and state-changing requests before transmission. Ordinary page scripts and resources necessary for rendering remain observable within scope; no links are crawled.

Use Chromium's private CDP pipe through inherited descriptors, not a publicly listening DevTools port. The first gate must prove the pinned Rod transport can consume that channel; a thin required CDP transport adapter is acceptable, a new browser abstraction is not. Do not expose control descriptors or provider/environment secrets to renderer children.

A TCP-only tunnel means QUIC is unavailable in this supported profile. Report that restriction and the actual observed protocol. This is not a promise of an unrestricted browser appearance or transport, and does not justify changing Chromium's TLS handshake implementation. Later TLS comparisons must account for transport differences.

Run the controller/helper/browser non-root with Chromium's sandbox and certificate verification intact. Add only the scoped namespace permissions required by the measured container profile; no privileged container, host-network mode, blanket security-profile disablement or sandbox-disable flag. Keep the existing scratch stage last/default, and add an explicit `browser` image target before it.

Pin Rod and the browser image/package versions during Gate 1 after the owned-fixture compatibility check; record exact versions/digests and licenses in the implementation commit. Do not use moving dependency selectors or automatic Chromium downloads at scan time. The supported launch recipe must set finite memory, CPU, process and shared-memory limits and record the tested values. These are container-level limits, not a claim that a retained-DOM byte cap bounds Chromium memory.

## Implementation contracts

### Configuration and ownership

- Add a concrete optional browser configuration and `Result.Browser` with `omitempty`. Keep `Run`, `RunCaptured` and `NewResultWriter` signatures. Browser-off results do not acquire an empty browser/settings placeholder.
- Browser configuration carries mode, selected browser/helper paths, timeout, settle interval and parsed policy. CLI resolves packaged helper/binary paths only after selecting browser capability; reusable-library callers supply those values. Unsupported OS/runtime fails selected capture explicitly while browser-off still works.
- Give optional text and image saving separate callbacks receiving acquisition-owned bounded readers and returning truthful artifact references/errors; destination writers remain caller-owned. Callbacks run synchronously in their worker, may overlap across workers, must honor cancellation/return, and must not retain readers after returning. A nonnil text callback does not authorize an image callback or image-bearing bundle. CLI constructs callbacks from explicit saving flags; no storage-backend interface or AI dependency.
- Public browser reports contain bounded sanitized metadata, states, limits, digests and artifact references, not raw DOM or image bytes. Raw capture buffers remain acquisition-owned until their last selected consumer finishes and are not retained in result queues or journals.
- Assign a run-local capture ID and monotonically increasing nonblank input occurrence before dispatch. Duplicate URLs receive distinct occurrences. Carry that small work item through the existing unbuffered worker channel; do not buffer the input or build a second target scheduler.
- One run-owned browser permit. Waiting is cancellation-aware and starts no process. The 60-second acquisition deadline starts after admission and includes launch/readiness/DOM/image work; waiting is separately recorded. Release the permit and terminate owned processes before any potentially blocking caller artifact sink.
- HTTP target/request timeouts stay 30/5 seconds by default and remain separately configurable. Explicitly cancel the HTTP child context when acquisition ends. Browser uses the run context plus its own deadline, never the expired HTTP child context.

### Fixed initial limits

| Item | Initial value / observable boundary |
|---|---|
| Concurrent browser captures | 1 per run |
| Capture timeout / settle | Configurable 60 seconds / 2 seconds; positive settle smaller than timeout |
| Logical HTTP(S) starts | 40 total, including redirects, frames and subresources |
| Main-document redirects | At most 3, also bounded by the existing configured redirect cap/policy |
| Retained DOM | 1 MiB; truncate on a valid text boundary and report truncation |
| Screenshot | One viewport, at most 1440×900, at most 2 MiB encoded before and after redaction |
| Retained main-document headers | 64 KiB total and 256 fields; limit excess is explicit incomplete metadata, not silent loss |
| Private helper bootstrap/control messages | 64 KiB; policy remains with the outside broker, not in child bootstrap messages |
| Native CDP message framing | 8 MiB before decoding; DOM/image retained limits above still apply |

The native CDP framing allowance accommodates JSON escaping of the bounded DOM and base64 image responses. It is not permission to retain an 8 MiB DOM/image, or a claim that native CDP returns those values through a separate bulk protocol.

The header/control caps are implementation-plan choices for otherwise unbounded metadata, not measured optima. Enforce encoded/decoded bounds before allocations, including CDP event framing, image dimensions and repeated-header expansion. Browser/native transport activity not represented by logical HTTP starts must not be silently called exact outbound-attempt accounting: instrument the owned edge in Gate 2 and fail the supported-runtime gate if the claimed guarantee cannot be enforced. No counter after transmission is a substitute.

### Provenance and states

Collect actual CDP main-document response events, including extra-info/raw-header data when available, and correlate request, loader, frame and connection IDs. Preserve repeated fields such as `Set-Cookie` without comma splitting. If the selected protocol/CDP combination cannot supply required headers, mark metadata incomplete rather than inventing values. Record HTTP version, browser version, viewport, redirect chain, final URL and cache/service-worker source provenance when available.

Use shared stage statuses and stable reason codes. Complete means all selected required modalities were acquired within bounds; restricted/broken resources remain explicit limitations. Earlier metadata plus a required-modality timeout/failure is partial; no usable required observation is failed. Off emits no browser report; invalid/out-of-scope admitted input may carry a skipped reason without a launch. Image acquisition, sanitization and saving have separate states. Saving failure does not retroactively erase an acquired observation or imply saving succeeded.

Never replace `Outcome`, `Generic` or the Go response body with browser content. Required capture failure remains incompatible with a later silent partial-evidence AI fallback. No AI gate or TLS-specific report/parser belongs in this change.

### Export boundary

Use structural URL/header/JSON/HTML handling, not regex-only secret scrubbing. Existing dependencies have no HTML parser: add the standard Go ecosystem `golang.org/x/net/html` parser, pinned compatibly with the module, instead of building a parser. Use stdlib JSON, image decoding/drawing/PNG encoding, hashing and private-file primitives. Reuse `internal/httpmeta` validation.

Define one explicit credential-field set for this export boundary: authorization/proxy-authorization values, cookie values, URL/form/JSON/meta fields identifying passwords, access/refresh/ID tokens, API keys, client secrets, session and CSRF secrets. Compare structural field names, preserve redaction markers/cookie names where appropriate, and document coverage rather than claiming arbitrary text is secret-free. Remove active script/style payloads from saved HTML projections instead of interpreting them as instructions or publishing executable page bundles.

Acquire recognized secret-field rectangles with the same document identity as the image, including supported frames. Mask pixels in memory using stdlib image operations; do not change the observed page to make it look sanitized. Uncertain required geometry, document changes, decode/encode limits or failed sanitization stop that export. Verify geometry around capture and disclose non-atomicity; do not promise arbitrary pixels are secret-free.

All new browser report/journal fields are sanitized before emission. Text/PNG artifacts receive their own sanitized projection and transformation/digest metadata; raw acquisition buffers and deterministic classifier inputs are untouched. Existing deterministic report fields retain their established contract: do not imply that browser saving makes all historical output fields secret-free or alter browser-off serialization.

## Sequenced implementation work

Execute only after this plan is approved for implementation. Finish and verify each dependent slice before exposing the next public behavior. Keep each commit coherent; do not land a selectable browser mode backed by a stub. Independent file ownership can be parallelized after Gate 1, but runner/config/output integration has one owner and validation runs after concurrent edits settle.

### Task 1 — Establish and prove the contained runtime

**Files:** new `internal/browserruntime/runtime_linux.go`, `internal/browserruntime/runtime_other.go`, `cmd/wafme0w-browser/main_linux.go`; `Dockerfile`, `go.mod`, `go.sum`; new `deploy/browser/seccomp.json` and `deploy/browser/apparmor` only for the required supported profile; new `internal/browserruntime/runtime_integration_test.go` under a `browser_integration` build tag.

1. Implement the concrete helper, namespace/process ownership, private CDP/proxy channels, frozen-destination TCP broker and strict bounded bootstrap decoding. Use the existing `golang.org/x/sys` dependency where OS descriptors are needed; no general proxy framework.
2. Establish a positive owned HTTPS fixture through the broker with Chromium's normal certificate verification. Trust only the fixture's isolated test CA in the test deployment; never add a runtime certificate-ignore switch. Confirm the service sees the Chromium connection, not a TLS-terminating proxy.
3. Prove denial from outside Chromium using owned allowed/denied fixture counters and network-namespace inspection. Cover IPv4/IPv6, unconfigured authority/address/port, alternate resolver/proxy settings, direct routes and unsupported channels. Do not exercise arbitrary third-party targets.
4. Exercise launch failure, parent death, timeout and cancellation. Confirm no reachable public CDP socket, orphan child/profile or inherited canary secret. Verify Chromium sandbox operation and the documented finite container resource profile.
5. Pin the tested Rod/Chromium/helper/image dependencies and licenses. Confirm private-pipe CDP compatibility before finalizing the adapter. Keep browser runtime dependencies absent from the default scratch runtime.

**Gate 1:** `TestBrowserRuntimeContainment` launches the actual helper and Chromium, succeeds only for configured owned destinations, fails closed for the denial cases and leaves no owned processes. On a designated browser CI job, a missing prerequisite is failure, not skip. If the namespace/CDP/sandbox combination cannot pass, stop for a runtime-design change; do not weaken containment.

### Task 2 — Implement navigation, admission and response provenance

**Files:** new `pkg/wafme0w/browser.go`; `pkg/wafme0w/acquisition.go` only where a small shared decision extraction avoids duplicate policy; new `pkg/wafme0w/browser_integration_test.go` with the browser integration tag.

1. Define the concrete capture/settings/report value types where they are first consumed; Task 5 wires these same types into the existing API, without duplicate internal/public forms. Construct the one concrete Rod controller around Gate 1's private channel. Apply `NoDefaultDevice` before a bounded viewport; no stealth/device/user-agent overrides, browser downloads, certificate relaxation or challenge retry.
2. Install CDP admission controls before navigation and auto-attach supported new execution contexts while paused. Count admitted starts across frames/workers/redirects; block unsupported contexts/channels before they can issue network work. Keep externally verified destination checks independent.
3. Reuse existing URL/origin/alias validation. Separate main-document navigation scope from explicitly permitted resource origins; neither policy can widen the global allowlist.
4. Collect bounded response/provenance data and raw DOM as separate browser evidence. Decode repeated headers according to the pinned CDP protocol. Record source/resource errors and identity transitions without substituting Go HTTP response data.

**Gate 2:** an owned fixture observes exact path/query/escaping, permitted methods, redirect and request-budget boundaries, and denied-origin counters. Return distinct Go/browser content and repeated response headers. Match screenshot/document provenance to the actual browser observation. The fixture's outbound observations, not only the CDP log, substantiate admission claims; unresolved pre-transmission gaps block support.

### Task 3 — Implement initial-render readiness and selected image acquisition

**Files:** `pkg/wafme0w/browser.go`; new `pkg/wafme0w/browser_readiness.go` for the actual readiness state machine; extend `pkg/wafme0w/browser_integration_test.go`.

1. Track main-document identity; reset readiness on each new main document. Observe load, relevant finite network activity and DOM changes within the shared deadline.
2. Require a quiet interval plus currently visible image completion/decoding and used-font completion, with explicit broken/denied-resource handling. New visible elements invalidate the applicable readiness checks. Record which long-lived streams are excluded from idle accounting.
3. Observe a rendering opportunity, collect bounded DOM and, only in screenshot mode, one viewport image. No clicking, scrolling, full-page stitching or fixed-sleep claim of full loading. Do not start another capture step after deadline expiry.
4. Preserve partial metadata honestly on timeout/truncation/capture failure. Bound native/CDP bulk transfer and decoded image dimensions; check cancellation during postprocessing.

**Gate 3:** deterministic owned delayed-script/image/font fixtures visibly appear in the initial viewport. A scroll-only asset has zero server requests; navigate mode has no image. A continuously changing page terminates at a short configured deadline. Navigation during settling resets identity instead of attributing later pixels to an earlier response. Inspect the produced screenshot visually, not just its byte count.

### Task 4 — Implement sanitized text and image export

**Files:** new `pkg/wafme0w/browser_export.go`, `pkg/wafme0w/browser_export_test.go`; `go.mod`, `go.sum`; extend the browser integration check for actual image geometry.

1. Implement the shared browser-local export boundary described above, with explicit per-modality acquisition/redaction/truncation/saving markers. Keep raw DOM/headers/image unexported and avoid redundant buffer copies.
2. Enforce all pre/post-transform limits and safe geometry handling. Retain no raw image file or base64 bundle when image saving is unselected. An acquired in-memory image can remain available to a later selected consumer; do not implement such a consumer now.
3. Invoke separate optional text/image sink callbacks with bounded sanitized content and source/capture metadata. Propagate errors; never fall back to raw bytes, silently reduce required sanitization or revisit a target.

**Gate 4:** `TestBrowserExportBoundary` inspects actual resulting text/decoded pixels for planted recognized secrets and verifies raw input bytes are unchanged. Cover malformed/truncated structures, field-name boundaries, repeated cookies, geometry/document mismatch and output-limit failures. Keep only assertions that defend these trust-boundary behaviors, not field-copy or sanitizer-wording tests.

### Task 5 — Integrate independent capture into the streaming runner

**Files:** `pkg/wafme0w/options.go`, `pkg/wafme0w/runner.go`, `pkg/wafme0w/capture.go`; extend `pkg/wafme0w/runner_test.go`, `pkg/wafme0w/capture_test.go` and the browser integration check.

1. Add the concrete optional configuration/report types and normalization/selected-mode validation. Clone parsed policy data once per run; do not mutate caller configuration or response-local state into the engine.
2. Add occurrence identity to dispatched work without changing unbuffered queues or completion-order callbacks. Validate scope once through shared decisions, acquire HTTP evidence, then independently run selected browser acquisition for each eligible occurrence regardless of HTTP match/failure.
3. Keep one run-owned capture permit and separate acquisition deadline. Release HTTP resources before browser work and release browser resources before artifact callbacks. Preserve `CancelInput`, sink-error cancellation and normal-EOF ownership.
4. Build the sanitized browser report and finish selected artifact callbacks before result emission so the journal sees truthful references/errors. Deterministic `makeResult` remains the shared classification path; `RunCaptured` stays zero-network and rejects live browser selection before reading.

**Gate 5:** named-match, clean no-match, HTTP failure and duplicate cases each receive their selected capture once. Invalid/out-of-scope targets do not. Verify queued/active cancellation, serial callbacks, bounded retained image ownership and sink-error shutdown. Extend existing `TestSinkFailureCancelsActiveWorkers`, `TestSinkFailureWakesBlockedOwnedInput` and `TestSuccessfulRunDoesNotCancelInput` only where new behavior changes their observable contract.

### Task 6 — Wire CLI, private artifacts and all report surfaces

**Files:** `cmd/wafme0w/main.go`, `cmd/wafme0w/journal.go`, `cmd/wafme0w/banner.go`, `pkg/wafme0w/output.go`; extend existing CLI/output tests; new `cmd/wafme0w/browser_integration_test.go` for the real browser CLI scenarios.

1. Add `--browser=off|navigate|screenshot`, `--browser-path`, `--browser-policy`, `--browser-timeout`, `--browser-settle`, `--artifacts DIR` and `--save-screenshots DIR`. Require screenshot mode for saving images; neither saving option selects a browser implicitly. Discover the packaged helper and browser only for selected browser work, after help/version/list exits. No provider settings or key lookup.
2. Validate selected options/policy and path collisions before acquisition. Keep passive evidence input incompatible with live browser modes. Clarify `--target-timeout` as HTTP-acquisition time in enhanced-mode help rather than silently changing its deadline semantics.
3. Create a private generated per-run artifact directory and generated per-capture filenames, never names derived from untrusted URLs. Text and image roots may intentionally be the same; each generated file must remain separate from inputs, reports and journals. Anchor operations within a verified private directory, reject unsafe symlink/alias cases and use `atomicfile.Write` where appropriate. Ordinary temporary-profile cleanup is not secure erasure.
4. Add optional browser JSON reporting, one final `browser` JSON cell to the fixed CSV schema, and explicit TXT/terminal browser states. No AI column or TLS object. Keep metadata-only journaling before report sinks; raw DOM/image data must not enter the journal or ordinary results.
5. Preserve deterministic counts, while selected browser/artifact failures contribute separate diagnostics and strict failure after report publication. A usable restricted render is reported with limitations, not falsely called a failed deterministic scan. Preserve JSONL-only stdout and escaping of every new untrusted terminal string.
6. Propagate artifact errors as truthful per-target optional-stage failures; configuration/input/context/journal/aggregate-sink failures retain existing run-level semantics. No automatic rescan or deletion of an independently published artifact just because the later aggregate report fails.

**Gate 6:** run browser-only CLI with no provider key, including duplicate input and both save modes. Inspect files, decoded JSON/CSV/TXT, terminal output and journal ordering. Cover empty CSV/header output, unwritable artifacts, symlink aliases, cancellation, strict exit after publication and final-report failure. Reuse the existing child-process CLI harness for short scenarios; a separate bounded browser integration deadline must not inherit its fixed 10-second limit for the production 60-second timeout. Also exercise the separately built application/helper inside the supported image.

### Task 7 — Run acceptance and integrate the supported deployment

**Files:** `.github/workflows/ci.yml`, `Dockerfile`, supported browser deployment profile and the integration tests already introduced above.

1. Keep all unit checks deterministic/offline and browser-independent by default. Add one designated Linux browser integration job using the exact supported image, helper, permissions and resource profile. Its explicit integration tag selects runtime checks; missing Chromium, namespace permission, test CA or required enforcement is a hard failure there.
2. Launch the actual CLI/Chromium against the owned fixtures and collect denial counters, protocol/version/limit metadata, terminal/output results and one visually inspected screenshot. No arbitrary public-site probes or synthetic result mocks as runtime acceptance.
3. Run the existing formatting, vet and race commands once after concurrent edits settle; run the focused browser checks and the full designated integration gate. Keep the ordinary scratch image help smoke test without network access.

**Commands for implementation verification (not executed for this document):**

```sh
gofmt -l .
go vet ./...
go test -race -covermode=atomic -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
go test -tags browser_integration ./internal/browserruntime ./pkg/wafme0w ./cmd/wafme0w -run '^TestBrowser' -count=1 -timeout=10m
go build -o wafme0w ./cmd/wafme0w
go build -o wafme0w-browser ./cmd/wafme0w-browser
docker build --target browser -t wafme0w:browser-ci .
docker build -t wafme0w:ci .
docker run --rm --network none wafme0w:ci --help
```

Run the integration command inside its declared controlled runtime, not an arbitrary host environment. Set the required runtime-check environment so absence cannot become a successful skipped suite; the integration test binary's entry gate must enforce it. Use focused per-task checks while implementing; do not repeat project-wide suites for every intermediate edit. A successful build or mock protocol check does not replace any of the six acceptance gates.

## Acceptance coverage and stopping conditions

| Browser-design acceptance group | Owning gates |
|---|---|
| Independence: off, no key for browser-only, help/non-network listing, all admitted occurrences, cancellation | Gates 5 and 6 |
| Identity/provenance: actual browser document/headers, exact URL, visual correspondence | Gates 2 and 3 |
| Containment: origin/destination/context/channel restrictions, sandbox/certificates/resources | Gates 1 and 2 |
| Readiness: delayed visible content, no scrolling, honest timeout, navigate has no image | Gate 3 |
| Lifecycle/privacy: launch/cancellation cleanup, child secrets, actual sanitized bytes | Gates 1, 4 and 5 |
| Saving/output: explicit image retention, atomic/private artifacts, errors/journals/all formats | Gates 4 and 6 |

Completion also requires `README.md`, `docs/incomplete-is-not-negative.md` and the browser design to describe the verified flags, explicit address-pin deployment, separate deadlines, privacy/saving, strictness, CSV cutover and compatibility/resource limits. Perform the repository's post-smoke documentation and cleanup process only after actual runtime proof; no cleanup task is pre-allocated here. Preserve historical accuracy/benchmark caveats and user-owned artifacts.

The implementation handoff must contain exact runtime evidence and the supported-platform limitation, with every affected API/output consumer migrated and no placeholder future fields or duplicate writers. Generated captures, local assistant state and coverage/build outputs do not belong in the feature commit.

Before implementation, review this plan's concrete static address-pin policy and Linux namespace/private-tunnel profile. If either cannot meet the approved browser contract, request an explicit design change rather than quietly dropping the gate. Otherwise implement Tasks 1–7 in dependency order and require every mapped gate before calling browser capture complete.

**Current stopping point:** written plan review. Creating or updating this plan does not authorize application implementation, install dependencies, launch a target browser or establish runtime compatibility. Screenshot capture remains an active planned feature; AI is retained as `soon` and disabled, and TLS scope is unchanged. No application code was changed and no browser runtime acceptance checks were run for this planning deliverable.
