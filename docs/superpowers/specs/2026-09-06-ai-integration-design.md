# Browser-first AI integration: shared design contracts

**Status:** browser/screenshot capture remains in active scope. AI is retained as **soon — disabled**, not merely off by default. Browser-capture implementation planning is approved; application implementation is not authorized.

## Purpose and authority

Extend wafme0w with independently selected browser acquisition and controlled-edge TLS comparison. Retain AI enrichment as a disabled future feature (`soon`), not a current delivery requirement. Preserve the deterministic classifier and its offline API.

This index and the three linked subsystem designs replace the monolithic architecture as the working design. The original interviews, corrections and scoring remain in the local historical record `.omc/specs/deep-interview-wafme0w-ai-integration.md`; they are not implementation-readiness measurements. This design set is self-contained and does not require that local record to build or review it.

**Confirmed** denotes an interview decision. **Proposed** denotes an engineering choice in the approved planning baseline, including numerical defaults, rather than an existing capability or measured result. Written-design approval authorizes browser-first planning; it does not adopt the alternative partial-evidence fallback or authorize code changes.

**Current scope override:** keep the AI design and its TDD requirements for later, but do not expose AI flags, provider/model discovery, credential or Codex-login access, provider calls, generation/replay, or AI reports/columns. There is no AI opt-in while this feature is disabled. AI-specific contracts below are retained future requirements, not work required to complete screenshot capture. Reactivation requires a separate explicit request and review. Screenshot capture remains independently selectable in the browser plan; neither subsystem is implemented by this scope update.

## Delivery boundaries

| Status | Focused design | Owns | Dependencies and independent completion |
|---|---|---|---|
| Active | [Browser capture](2026-09-06-browser-capture-design.md) | Rod/Chromium acquisition, containment, readiness, provenance, local artifacts and browser reporting | Existing HTTP/classification/runner boundaries only; works with AI disabled and no TLS instrumentation |
| soon — disabled | [AI enrichment](2026-09-06-ai-enrichment-design.md) | Retained future native providers, model selection/discovery, projections, routing, hypotheses, generation and replay | No active implementation, credentials, provider calls or browser-delivery dependency |
| Later | [Controlled-edge TLS comparison](2026-09-06-tls-comparison-design.md) | Attributable service observations, local prior-capture import and comparison | Browser response/provenance contract and operator-supplied TLS-edge observations; no AI dependency |

Each active subsystem gets its own reviewed implementation plan, implementation and acceptance cycle. Browser capture is first because acquisition, isolation and readiness can be proved independently of model interpretation. AI planning and implementation are paused; its acceptance gates do not block screenshot delivery. Controlled-edge TLS comparison remains a separate later delivery.

Delivery order is not per-target execution order. The retained future flow below applies only after each subsystem is separately activated; while AI is disabled, omit its steps entirely and do not make browser work wait for them:

1. Existing selected HTTP acquisition and deterministic/generic classification.
2. Eligible, explicitly selected header generation; validated execution; reclassification of the actual combined HTTP evidence.
3. Independently selected browser acquisition, even if a provider refused, generation failed, a product matched or AI became ineligible.
4. Optional local saving and TLS observation/comparison from that capture.
5. Final eligible AI assessment, at most once.
6. One result emitted through the existing serial callback and report pipeline.

## Existing boundaries to reuse

- [`runner.go`](../../../pkg/wafme0w/runner.go): `classifyTarget` orchestrates acquisition and `makeResult`; `Run` has bounded workers, unbuffered work/result channels and serial completion-order emission.
- [`evidence.go`](../../../pkg/wafme0w/evidence.go), [`identify.go`](../../../pkg/wafme0w/identify.go): HTTP `Evidence`, deterministic `Outcome`, immutable concurrent-safe `Engine.Classify`, and separate generic anomalies. Offline classification remains network-free.
- [`acquisition.go`](../../../pkg/wafme0w/acquisition.go), [`http.go`](../../../pkg/wafme0w/http.go), [`request.go`](../../../pkg/wafme0w/request.go): reuse URL-origin validation, HTTP admission, context propagation and decoded-body limits. These Go transports do not govern Chromium.
- [`httputil.go`](../../../pkg/utils/http/httputil.go): preserve the corrected parser's path/query case, escapes, authority validation and caller error handling. No duplicate browser/AI parser or repeat of the historical lowercasing fix.
- [`output.go`](../../../pkg/wafme0w/output.go), [`main.go`](../../../cmd/wafme0w/main.go), [`atomicfile`](../../../internal/atomicfile): reuse result serialization, CLI-owned I/O, journaling, path-collision checks and atomic aggregate publication.

Do not change existing active request families, add an agent framework, embed a second scanner, or create a generic plugin infrastructure. Design names below describe data and responsibilities, not one interface/file/class per noun.

## Shared data and ownership

| Contract | Producer / consumer | Required invariant |
|---|---|---|
| HTTP observation envelope | Existing acquisition and later header executor / classifier and projection builder | Run-local observation/attempt IDs, source, request role, actual URL/method, timing, redirect relationships and completeness reference the original `Evidence` without copying its body just to add metadata |
| Deterministic outcome | `Engine.Classify` / runner, outputs and AI gate | Only actual HTTP evidence enters named-product matching; generic anomalies, browser observations and hypotheses stay separate |
| Browser capture | Browser subsystem / local reporting, optional AI and TLS consumers | Capture ID and input occurrence; actual document/request identity, metadata/DOM, per-modality status, readiness/restrictions, optional image; never overwrite an HTTP response body |
| Export projection | Shared privacy boundary / artifact writer or selected provider | Bounded sanitized copies/references, source IDs, redaction/truncation/omission markers; classifier inputs stay unchanged |
| Header plan and ledger | AI subsystem / validated executor and replay | Frozen ordinary-header inputs, policy version/digest, attempt accounting and stop reasons; no saved authorization |
| AI assessment | Selected native provider plus local validator / outputs | Ranked unverified hypotheses or abstention, valid transmitted-evidence references and locally computed catalogue membership; never `Outcome.Matches` |
| TLS comparison | TLS subsystem / browser report | Current/prior attributable service observations; fingerprint and response comparisons remain separate; never changes capture success or deterministic/AI truth |

Library `Config` receives resolved values, clients and typed bounded inputs. CLI code owns flag/environment resolution, files, browser discovery and artifact publication. The library does not discover provider keys or read arbitrary replay/prior paths. Caller-owned readers/writers remain caller-owned.

Requested, acquired, transmitted and saved modalities are distinct. Browser DOM, response headers and pixels are associated observations, not an atomic snapshot. Preserve actual document identity and missing provenance rather than inventing it. Ordinary results contain metadata/status/references, not raw DOM or image bytes.

## Modes, scope and privacy

**Confirmed:** browser acquisition can operate with AI off; AI never implicitly selects a browser. Every admitted supplied URL occurrence, including duplicates, receives the selected bounded browser attempt. No crawling of discovered pages. Invalid/out-of-scope input is explicitly not attempted. Cancellation and input/sink failure retain existing `Run` semantics; there is no promise to process unread input after cancellation.

**Active proposed controls:** `--browser=off|navigate|screenshot`, defaulting off. Screenshot mode includes one navigation, not a second visit. Saving requires its own opt-in, and screenshot-only options require screenshot mode instead of selecting it silently. Browser-only needs no provider key or login; help/non-network listings need no Chromium. AI assessment, provider/model selection, model discovery and replay controls remain disabled future interfaces in the AI design, not selectable options for this delivery.

Caller scope and code-enforced budgets govern acquisition; provider content refusal does not authorize targets. Redirects, subresources, new contexts and address resolution do not expand authority. Current HTTP origin policy is not an IP/network sandbox; the browser design owns its additional containment boundary. Never use a Go-fetched substitute and call its handshake browser TLS.

Treat response content, pixels and model output as untrusted data. No evidence-embedded instruction may alter scope, routing, tools, budgets or provider configuration. No arbitrary raw requests, new paths/queries/methods, executable payloads, stealth, TLS impersonation, challenge solving, response-driven request adaptation or automatic catalogue-rule creation.

Before export, remove defined credential fields from headers, URLs, structured content and recognized HTML form/meta fields; cookie names may remain after secret values are removed. Use structural parsing where needed. Mask identified visible secret-field regions in outgoing/saved images and record transformations. Failure of a required sanitizer stops that export; never upload or save raw content as a fallback. This does not guarantee arbitrary HTML or pixels are secret-free.

Transient acquisition does not imply persistence. Explicit artifact saving may retain sanitized text; screenshot bytes, including image-bearing bundles, require the independent screenshot-saving option. Use private paths with generated names and preserve write errors. Browser temporary storage and best-effort profile removal are not RAM-only processing or secure erasure guarantees.

## Scheduling and deadline ownership

**Proposed:** retain the current target worker and serial per-target phases, with bounded browser/AI admission rather than a second unbounded task list. Queue admission is cancellable; no Chromium process/profile exists while waiting. Browser queue capacity is bounded by workers, not a promise of a fixed wait duration. Slow enrichment occupies its worker; measure this before introducing a separate scheduling architecture.

The existing `Config.TargetTimeout` / `--target-timeout` currently encloses HTTP acquisition in `classifyTarget`. **Proposed clarification:** retain that ownership and its 30-second default for the existing HTTP acquisition phase. In enhanced modes document explicitly that it is not a whole enriched-result deadline. HTTP-only behavior is unchanged; do not silently reuse this context for browser or AI work.

The run context is the outer cancellation/deadline authority. Browser acquisition and AI work use independent budgets under it. A browser acquisition deadline starts after its permit is obtained and includes launch, navigation, readiness and capture. The AI work allowance counts AI admission/generation/generated execution/assessment, excluding browser queue/acquisition; exhaustion stops AI work, not the selected browser attempt. Generated requests use their own request timeout and AI allowance, not an expired baseline context.

No new overall per-target timeout flag is introduced by this design. The enhanced-mode interpretation above is submitted for review, not attributed to the interview. CLI help, resolved settings and docs must disclose it in the same implementation change.

## Shared initial resource proposals

These are starting limits, not measured optima, hard renderer-memory limits or dollar-cost promises. Report effective limits and shortfalls; validate inputs before allocating. AI entries are retained future proposals only: do not allocate AI resources or perform AI work while the feature is disabled.

| Resource | Proposed allowance / owner |
|---|---|
| Existing target workers | Current default 20 / runner |
| Existing HTTP acquisition | Current scope, redirects, rate and admission limits; separate ledger from generated/browser traffic |
| Baseline HTTP target / request deadlines | Current defaults 30 seconds / 5 seconds; retain configured values |
| Browser concurrency / acquisition deadline | 1 owned capture at a time / configurable 60 seconds |
| Initial-render settling | Configurable 2-second quiet window, plus explicit visible-image/font checks |
| Browser requests / navigation redirects | 40 admitted HTTP(S) starts, including subresources/redirects / at most 3 navigation redirects |
| Browser DOM / screenshot | 1 MiB retained DOM / one viewport up to 1440×900 pixels and 2 MiB encoded |
| AI phase admission / work allowance | 2 concurrently active AI phases; release AI permits around browser work / 240 seconds of counted AI work per target |
| Inference calls / individual deadlines | At most 1 generation and 1 assessment per target / 30 and 60 seconds, no retries |
| Standalone model discovery | 30 seconds total, at most 32 pages, 1 MiB decoded per page and 4 MiB decoded aggregate; explicit failure on exhaustion, no redirects/retries or inference |
| Generated HTTP | Configurable `k`, default 20 additional attempts; sequential per target; at most 1 start/second per origin shared across duplicate targets |
| Retained HTTP with AI enabled | 16 MiB per target, with concurrent reservations; keep metadata and mark bodies truncated on exhaustion |
| Decoded HTTP body | Existing 1 MiB per-response default |
| Inference text / decoded response / output tokens | 64 KiB total sanitized evidence text / 64 KiB / explicit initial 4096 ceiling on compatible models |
| Provider hypotheses / references | At most 5 hypotheses and 6 references each, with bounded strings |
| TLS observation / prior input | 4 KiB service record / 1 MiB decoded prior-capture input |

Count actual generated HTTP attempts, including any redirects/retries, rather than wrapping `Client.Do` and assuming it sees transport-internal replays. TCP retransmissions and TLS handshakes are not HTTP attempts. A supported browser runtime must separately demonstrate its request-admission and destination-containment guarantees.

## Failure, output and cutover

**Retained proposal:** a selected browser/required modality failure skips assessment rather than silently using less evidence. Intentionally unselected images remain valid text-only operation. A successfully captured restricted render may be assessed with limitations. The review suggestion to allow explicit partial-evidence fallback was not approved and is not adopted here.

Optional failures never erase deterministic matches or turn an otherwise valid deterministic outcome into `Failed`. Actual failed/truncated generated HTTP observations remain in the combined evidence and can legitimately affect completeness. TLS unavailability does not invalidate a successful screenshot. Artifact-write failures do not imply that content was saved and never trigger a rescan.

Use stage statuses `skipped`, `complete`, `partial`, `refused`, `failed`, `cancelled`, with stable reason codes. Partial collection is not valid malformed model output. TLS comparison has its separate four-state contract. Configuration/input/context/aggregate-sink failures remain run-level errors; target acquisition and optional-stage failures are reported at their existing appropriate boundaries.

Browser delivery adds optional `Result.browser`; AI delivery later adds optional `Result.ai`, also used for an explicitly selected saved-plan replay ledger without provider invocation. No inactive placeholder report is emitted. With all new optional workflows off, existing JSON behavior remains unchanged. Extend the current writers, not parallel legacy/v2 writer trees. Proposed CSV delivery appends the browser JSON cell in the browser change and the AI JSON cell in the AI change, with fixed headers even for empty runs; document and migrate consumers at each actual cutover, without reserving an unused AI column. TLS nests in the browser report. TXT/terminal output distinguishes all states and escapes untrusted control characters; JSONL stdout remains machine-readable. Warnings may hide detail, not state or uncertainty.

## Acceptance ownership

Keep the original fourteen acceptance areas below for traceability. Browser obligations remain active; AI-specific obligations are deferred while AI is disabled and do not block screenshot completion. TLS retains its separate later gate. Subsystem documents specify observable checks, not claims of passing runtime work.

| Original area | Primary owner / shared obligation |
|---|---|
| 1. Disabled and independent modes | Browser and AI: no unintended acquisition, keys, images or provider calls |
| 2. URL identity | Browser and AI: current parser invariants across acquisition and replay |
| 3. Gates and every-input coverage | Browser and AI: independent capture, truthful reclassification and provider counts |
| 4. Untrusted generation | AI: rejected plans cause zero generated traffic |
| 5. Attempt boundaries | AI plus HTTP admission: actual attempts, shared origin pacing and cancellation |
| 6. Browser provenance and lifecycle | Browser: containment, document identity, cleanup, sandbox and secret isolation |
| 7. Native provider behavior | AI: provider/model selection and discovery, both protocols, refusal/schema behavior, test-first implementation and authorized synthetic live smoke |
| 8. Privacy | Browser and AI: inspect actual saved/uploaded bytes; raw classifier input unchanged |
| 9. Separation and output | All three: actual serializers/CLI, state separation and atomic publication |
| 10. Replay | AI: same validated request inputs, no generator or inherited authorization |
| 11. Functional acceptance | AI: honest capability/accounting, no required or claimed accuracy uplift |
| 12. Initial-render readiness | Browser: delayed visible content, failures, timeout and no scrolling |
| 13. Independent saving | Browser: private sanitized artifacts, no implicit image retention or provider calls |
| 14. Actual-browser TLS comparison | TLS: attributable current/prior observations, no extra visit or Go surrogate |

Verification uses saved captures, synthetic evidence and owned/authorized fixtures, never arbitrary public targets. Implementation needs real CLI/browser/provider checks where applicable; document structure checks and protocol mocks alone do not establish runtime compatibility or identification accuracy.

## Review gate

The user approved this shared contract and the three subsystem designs for planning on 2026-09-06. Enhanced-mode timeout ownership, first supported browser runtime, retained strict modality-failure policy, defaults, staged CSV cutovers and the explicit TLS observation-only workflow are the planning baseline. None changes the confirmed no-stealth, independent-mode, evidence, privacy or authorization boundaries.

The previous AI refinement for explicit authenticated provider-model discovery and red → green → refactor TDD remains preserved for reactivation. The user's subsequent `soon` instruction disables AI and supersedes its earlier required-delivery status. It does not disable screenshot capture, select a Codex login/backend, or authorize application implementation.

The requested `writing-plans` skill was unavailable in the installed registry and checked local skill paths. A direct repository-grounded [browser-capture implementation plan](../plans/2026-09-06-browser-capture-implementation-plan.md) records the next steps without installing a skill. That plan requires review before application implementation. AI planning is paused; TLS remains a later delivery.
