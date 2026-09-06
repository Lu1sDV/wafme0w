# AI enrichment subsystem design

**Status: soon — disabled.** Preserve the previously approved design and TDD requirements below for later. AI is not implemented, selectable or authorized for activation; browser/screenshot capture remains independently in active scope.

<!-- soon -->

This is not an off-by-default feature with an opt-in. Do not implement or register AI flags, provider/model discovery, credential or Codex-login access, provider clients/calls, generation/replay, or AI reports/columns in the active browser delivery. The remaining sections are retained future requirements, subject to an explicit reactivation request and review.

[Shared contracts, budgets and acceptance ownership](2026-09-06-ai-integration-design.md) define the common boundaries. This is a deferred design, not a required second delivery or a prerequisite for screenshots. If reactivated, text-only assessment and saved-plan replay must not acquire a browser implicitly.

## Responsibility and non-goals

Provide native OpenAI and Anthropic assessment of selected evidence, plus an independently opted-in, one-shot ordinary-header generation/execution/replay capability. Support both native protocols; select one provider/model for a run, with no failover after refusal.

**Confirmed output:** ranked product hypotheses, supporting evidence references, qualitative uncertainty and explicit abstention. Outside-catalogue products are allowed and labelled unverified/outside-catalogue. Catalogue membership is computed locally. No hypothesis becomes a deterministic match, creates a fingerprint, proves enforcement or proves absence.

Captured response content and separately rendered browser DOM are the relevant source material, not server-side repositories. No model tools, autonomous browser actions, arbitrary HTTP, response-driven regeneration, challenge solving, payload generation, target expansion or model-authorized access. Existing active request families are not extended by this subsystem.

Correct optional collection is sufficient for functional acceptance. Improved identification accuracy is not required or claimed without independently labelled measurements.

## Provider selection and model discovery

**Confirmed refinement:** select the provider explicitly with `--ai-provider=openai|anthropic`, and select the exact model ID with `--ai-model` when requesting inference. `anthropic` identifies the provider; Claude is its model family. Never infer a provider from a model-name prefix, choose a default/latest model implicitly, or switch models/providers after an error. Discovery does not persist or change the selected model.

CLI resolves only the selected provider's credential: `OPENAI_API_KEY` for OpenAI or `ANTHROPIC_API_KEY` for Anthropic. The library receives resolved credentials through the existing native-provider boundary; it does not read environment variables or another application's login store. Selection does not require a discovery preflight: an explicit ID can be used even when the account cannot list models.

**Retained discovery interface — soon; disabled and not implemented:**

```sh
wafme0w --ai-provider openai --ai-list-models
wafme0w --ai-provider anthropic --ai-list-models
```

`--ai-list-models` is an explicit standalone provider-metadata operation, not a scan or an assessment mode. It requires a provider and that provider's key, but no model, target, Chromium or evidence. Do not read stdin, open scan inputs/artifacts, call `Run`/`RunCaptured`, acquire a browser or send inference requests. Reject combinations with target/input/evidence, selected browser, generation/replay, non-off AI assessment, model-selection or scan-report/journal files before any acquisition. Shared presentation controls such as `--jsonl` and `--no-colors` remain valid. Help remains local and needs no credential. Ordinary scans with AI off still make no provider calls.

Use each provider's authenticated native `GET /v1/models` endpoint. Follow documented pagination, including Anthropic's `has_more`/`last_id` cursor contract; OpenAI's currently documented list is not paginated. Keep subsequent requests on the selected native endpoint. Reject missing, repeated or non-progressing required cursors rather than looping. Do not introduce a hardcoded model catalogue, cache, automatic probes or a provider-management service.

Return provider and exact model ID, an optional display name, and image-input/structured-output capabilities when supplied. Capabilities are supported, unsupported or unknown; absent/null metadata is unknown, not false or true. OpenAI's current list supplies basic model metadata rather than these capabilities; Anthropic may supply nullable capability information. Do not filter unfamiliar model IDs or claim endpoint/feature compatibility from a name or presence in the list. Actual inference still must satisfy the native endpoint and response contract; unsupported selections fail explicitly without a downgrade or replacement.

Collect the bounded complete list before publishing, with one row per exact model ID and deterministic ID ordering. Print a human-readable listing by default; existing `--jsonl` emits discovery records, with unknown capabilities represented by null, and no human text on stdout. This is not a scan `Result`, CSV report or diagnostics journal. Preserve terminal escaping and output errors. Missing credentials, malformed/error responses, pagination/size/deadline failures and output failures return an error, not a fabricated empty list, successful partial inventory or cached fallback.

Discovery uses the selected provider's separate verified-HTTPS client, no redirects/retries, caller cancellation and the shared discovery-specific limits. It sends no target/evidence data and consumes neither inference tokens nor the per-target generation/assessment allowance. It is never an implicit part of a normal scan or offline saved-response analysis.

## Routing and per-target flow

**Retained future scan flags (disabled):** `--ai=off|undetected|always`, `--ai-provider`, `--ai-model`, `--ai-generate-headers`, `--ai-k`, and explicit saved-plan replay with separately selected reassessment. The standalone discovery operation above is separate from this per-target routing. If reactivated, CLI resolves provider-specific environment keys, not command-line secrets; library configuration receives resolved credentials and decoded inputs.

During a scan, `off` invokes no provider or generation. `undetected` uses the confirmed predicate: deterministic state `Complete`, zero named matches and zero diagnostics. A generic anomaly neither opens nor closes this gate. `always` is a proposed explicit analysis mode that permits named/incomplete results only when usable HTTP evidence exists, with limitations retained; it is not an override for scope, refusal, privacy or evidence requirements.

| HTTP outcome | Undetected assessment/generation eligibility |
|---|---|
| Complete, no named matches, no diagnostics | Eligible, with or without a generic anomaly |
| Any named match | Ineligible |
| Incomplete or failed | Ineligible |
| Any diagnostic | Ineligible |

Generation is separate from assessment opt-in. The generator receives the bounded grammar, requested quantity and at most sanitized content-negotiation metadata, not arbitrary HTML, pixels, credentials or the full target URL.

For each target:

1. Retain baseline HTTP outcome/generic result and actual observation provenance.
2. If selected and initially eligible, make at most one generation call, validate/freeze the entire plan, and execute accepted inputs under the shared scope and attempt policy.
3. Reclassify once over the actual baseline plus generated HTTP observations, including failures/truncation. Recompute generic output separately. Never choose only successful observations to fabricate a clean negative.
4. Let the runner perform independently selected browser acquisition regardless of AI eligibility, refusal or generation failure. AI does not own or suppress this phase.
5. Recheck the final HTTP gate, selected-modality policy and privacy boundary, then make at most one assessment call if eligible.

**Proposed failure policy:** generation refusal/failure ends this target's AI workflow without repair, fallback traffic or another provider attempt; independently selected browser work still runs. Assessment refusal/failure is likewise terminal. Browser-acquisition failure follows the retained strict shared policy rather than silent text-only fallback. Intentionally text-only input remains valid and does not require an image-capable model or Chromium.

The shared AI work budget and provider deadlines are independent of browser time. Do not hold an AI admission permit while waiting for or running the browser; reacquisition is bounded/cancellable and counts against remaining AI work. No unbounded task queue, automatic retry or provider router is introduced.

## Provider projection and assessment validation

Construct a separate bounded sanitized projection after classification. Reuse the browser/export privacy boundary; never redact or truncate the classifier's raw evidence in place.

Each included header, content segment and image has a stable evidence reference, source, acquisition time and completeness/redaction markers. Original Go HTTP content and rendered browser DOM use separate fields. Prioritize the original normal response and distinct additional responses deterministically; record omitted observations/bytes. The provider must not be described as having seen omitted content.

Include browser headers/DOM only when selected, and an inline image only when screenshot mode succeeded. Send image bytes, not a target URL for the provider to fetch. The configured TLS diagnostic header and local comparison records are excluded from all provider projections, including original HTTP headers carrying similarly named telemetry.

**Proposed response contract:**

- `decision` is `hypotheses` or `abstain`.
- A hypothesis decision contains one or more ordered hypotheses: bounded product label, short supporting explanation, valid evidence references and qualitative uncertainty.
- Abstention contains a reason and no hypotheses.
- Limitations and conflicting evidence are explicit; do not request hidden chain-of-thought or present uncertainty as a calibrated probability.

Validate the complete bounded response locally, including consistency, field bounds and referenced transmitted content. Require at least one valid reference per hypothesis; cited quotes/fields must exist, and any cited image region must fit the supplied image. Reference validity does not establish correct visual interpretation or product attribution. Reject malformed/inconsistent output rather than publishing a partial success or asking another model to repair it.

Determine membership against the loaded `Engine.Products()` snapshot. Do not trust model-supplied membership or fuzzy-map unfamiliar labels into catalogue matches. All hypotheses remain unverified, even when their label occurs in the catalogue.

## Native protocol adapters

**Proposed implementation:** standard `net/http` and `encoding/json`, with one narrow common provider contract and two native adapters. Two real implementations justify that interface; no compatibility gateway, SDK merely wrapping one endpoint, or agent framework is required.

| Concern | OpenAI | Anthropic |
|---|---|---|
| Endpoint | Responses API, `/v1/responses` | Messages API, `/v1/messages` |
| Model discovery | Native `GET /v1/models` | Native `GET /v1/models`, with documented cursor pagination |
| Image representation | Inline `input_image` data URL | Base64 `image` content block |
| Structured response | JSON Schema through `text.format` on compatible models | JSON Schema through `output_config.format` on compatible models |
| Non-success response handling | Inspect refusal content and incomplete status before success decoding | Inspect `stop_reason`, including refusal and token exhaustion, before success decoding |

Use correct native authentication/version headers and current documented shapes. Explicitly select a model supporting the chosen endpoint and structured outputs; require image support only when an image is selected. Record requested/returned model identity, request ID and usage where supplied; absent usage is unknown, not zero. Sampling controls and outputs need not be equivalent between providers.

Provider clients are separate from target clients: verified HTTPS, bounded decoding, context deadlines, no redirects/retries, and no target-controlled endpoint. Keep keys out of prompts, results, URLs, logs, browser configuration and child environments. Treat HTTP-200 refusal, token truncation, auth/rate-limit errors, malformed schema output and invalid evidence references as their actual states, not hypotheses.

Use static schemas without target/private catalogue values in schema enums. Put catalogue names in request content when supplied, then validate locally. OpenAI requests explicitly set `store:false`; this is not a zero-retention promise. Account/model/feature policies and exceptions apply to both providers and schema caching can differ from message retention. Never alter retention settings to access a restricted model without approval.

Respect provider restrictions, including restricted challenge/CAPTCHA content. No failover, repackaging to evade refusal, challenge-solving request or unstructured downgrade follows an unsupported model/schema or refusal.

### Codex models and authentication

API-exposed Codex models use the same `openai` provider, `OPENAI_API_KEY` and Responses API; no separate Codex provider, CLI subprocess or agent execution is needed. For example, the current GPT-5.3-Codex API documentation lists Responses, structured outputs and image input as supported. This is a documented example, not a default, frozen allowlist or proof of access for the operator's account. Keep model IDs opaque and apply the same selected-modality/schema validation, refusal and no-tools boundaries as for other models.

Codex API-key usage is billed through the OpenAI Platform account, separately from included ChatGPT subscription usage. ChatGPT sign-in, Codex workspace/access tokens and Codex cloud access are different authentication/product paths, not interchangeable Platform API keys. Do not import `~/.codex/auth.json`, perform OAuth, call private subscription endpoints or assume every model visible in a Codex client is available through the public API. Public API availability and the required feature support govern selection.

## Ordinary-header plans and replay

**Confirmed:** only ordinary `Accept` and `Accept-Language` variation, one batch up front, default configurable `k=20` additional generated HTTP attempts. Code fixes the actual URL and method. No new path/query/body, credentials, cookies, host or user-agent changes.

**Proposed representation:** arrays of allowed media/language tokens and quality values, one to four ordinary alternatives per header. The validator owns documented bounded vocabularies, lengths and ordinary quality values. The compiler owns header spelling/separators and the normal fixed `GET` shape. No raw HTTP strings, arbitrary parameters, control characters or unknown structural fields.

1. Decode exactly one bounded JSON response; reject trailing data and unknown structural fields.
2. Validate the whole batch before any generated traffic. A forbidden member fails the batch rather than executing a safe-looking prefix.
3. Permit a valid short batch. Deduplicate identical compiled header pairs in order; do not refill duplicates or shortages.
4. Freeze the canonical plan, validation-policy version and digest.
5. Execute sequentially per target with current scope, origin pacing, per-request timeout, AI work allowance and `k` accounting.
6. Record actual attempts/responses/errors, then perform the single final deterministic reclassification.

Default to no generated redirects or retries. If follow-ups are ever enabled, each must pass scope and consume `k`. Select a transport/accounting boundary that disables uncounted replays or exposes actual attempts; a `Client.Do` counter is not proof. Keep baseline/browser/provider ledgers separate. A shortfall reports why; `k` is not a success count, total scan count or allocation size for unchecked input. Increasing `k` does not enlarge provider response/token bounds automatically.

Serialized results include the canonical plan and ledger. Explicit artifact saving may retain a sanitized evidence bundle/standalone plan under shared retention rules. Replaying a saved plan uses the same validator/executor and current caller scope; it never calls the generator, restores authorization or promises identical live responses/model output. Reject incompatible policy versions and altered scope/URL/method fields. Rebind credentials from current configuration. If redaction removed required URL values, require explicit resupply rather than guessing.

**Proposed replay mode:** explicit saved-plan execution selects the enrichment report/ledger even without a provider. `--ai=off` in that mode means no provider assessment; reassessment is a separate explicit selection. Do not require a key when no provider call is selected. Live request replay and offline saved-evidence analysis are different operations; preserve `RunCaptured` as network-free and do not make an offline capture label a target to request.

## Reporting and code ownership

The optional AI report owns baseline outcome/generic snapshot, final HTTP evidence IDs, canonical plan and policy version, provider/model metadata, stage statuses/reasons and hypotheses/abstention. Record requested `k`, validated/duplicate/rejected counts, attempted and usable counts, shortfall and stop reason. Reference the browser report's capture ID rather than duplicating capture ownership. Report presence or skipped provider work is not provider acceptance.

`Result.Outcome` and `Result.Generic` describe the actual final HTTP set, or baseline when no additional observations exist. Provider/capture errors do not overwrite deterministic results; real generated HTTP errors remain evidence and may change completeness.

Implementation ownership stays within existing configuration, runner, acquisition and output seams, plus small provider/validation/projection files. Extend HTTP provenance/accounting where necessary, but keep header execution separate from the existing active request factory. CLI owns keys, decoded replay input and artifact files. Append the AI CSV cell only in this delivery, update affected consumers/docs and keep default JSON behavior unchanged when no enrichment workflow is selected. Use LSP references before public API changes.

## Independent acceptance gate

This gate is deferred while AI is disabled and is not required for screenshot delivery.

Browser acquisition itself is a dependency already verified by its own gate; test integration without treating browser/provider mocks as runtime proof.

1. **Gates and state transitions:** exercise all table rows, generic anomalies, generated matches/errors/truncation and selected capture failure. Observe actual provider counts. A closed AI gate or refusal never suppresses selected capture or erases matches.
2. **Native APIs:** controlled responders cover both envelopes, HTTP-200 refusal, truncation, schema/reference errors and auth/rate limits. Then explicitly authorized minimal calls with synthetic text and text-plus-image evidence verify selected compatible models. Local protocol tests alone do not prove live compatibility.
3. **Privacy and output:** inspect actual outgoing provider bodies and saved artifacts seeded with recognized secrets. Raw HTTP evidence remains unchanged; sanitizer failure exports nothing unsanitized. Serialize outside-catalogue hypotheses, abstention, refusal/failure and browser references through actual CLI/JSON/CSV/TXT with safe terminal escaping and atomic publication.
4. **Generation and attempts:** rejected batches cause zero generated traffic. Valid short/duplicate batches preserve URL/method and account honestly. Owned endpoints observe at most `k` actual attempts, including connection-reuse/follow-up cases; duplicate targets share origin pacing and cancellation prevents future admissions.
5. **Replay:** save and replay canonical inputs against an owned endpoint without any generator/provider call unless reassessment was selected. Compare emitted inputs, not nondeterministic responses. Reject tampered/incompatible plans and preserve network-free offline classification.
6. **Resource/failure boundaries:** bounded input/output, evidence retention reservations, provider/AI deadlines and permit cleanup remain deterministic. Browser-only needs no keys, text-only AI needs no Chromium, and all optional workflows off produces no new activity/report.
7. **Model discovery and selection:** native fixtures expose provider-specific models and capabilities, including unknown metadata and Anthropic pagination. Verify that the selected credentials/protocol produce the correct observable listing, an explicit model remains usable without a listing preflight, and no inference, target read/request, browser or other-provider work occurs during discovery. Invalid options/keys, malformed responses, repeated cursors, budgets, cancellation and sink errors fail honestly. A Codex model uses the ordinary OpenAI API boundary without a subprocess or login-store access. Model IDs and provider text cannot corrupt terminal or JSONL output.

### Test-driven implementation requirement

**Retained development method for reactivation:** implement this AI delivery with red → green → refactor TDD. Before changing production behavior, write a focused test of its observable contract, run it and observe the intended failure; implement the smallest change that passes, then refactor while it remains green. Record the actual focused commands and red/green results during implementation. A compile-only scaffold, source-text assertion or provider mock that merely echoes supplied fields is not behavioral proof.

Start discovery/selection with these behavior boundaries, using the existing Go test and CLI harness conventions and controlled native-protocol responders:

1. **Standalone dispatch:** valid discovery works without target input or a browser and contacts only the selected provider's metadata endpoint. Help and AI-off scans need no key or provider access; invalid discovery combinations fail before reading input or making a request.
2. **Inventory truth:** native results, additional pages, unfamiliar IDs and supported/unsupported/unknown capabilities produce the corresponding complete human/JSONL listing. Empty valid inventories differ from malformed data. Pagination cannot silently truncate results or repeat indefinitely.
3. **Failure boundaries:** controlled responders and failing sinks exercise authentication/rate-limit errors, malformed/oversized responses, page/aggregate bounds, cancellation, output failure and untrusted display strings. No failure produces a successful partial list, retry, fallback model/provider or leaked key.
4. **Explicit model execution:** a controlled native inference service accepts only the selected model/protocol while denying model listing. The observed assessment succeeds without preflight; unsupported model/schema/image requests remain errors. Include an API-exposed Codex model under the OpenAI contract without reading another application's credentials or launching its CLI.

Keep these tests offline and deterministic; do not use real keys or make model inference calls in CI. Then run the actual CLI against controlled responders, and perform the separately authorized minimal live-provider acceptance checks already required above. Fixture success is not proof of account entitlement or live compatibility. TDD is a requirement for the later implementation, not a claim that runtime tests were written or executed for this specification update.

Functional completion requires valid bounded replayable behavior and honest reporting, not accuracy uplift. When independently labelled cases are available, compare baseline, equal-budget fixed/random ordinary-header controls and the LLM batch over all cases. Report abstention/refusal, false hypotheses, top-k quality, outcome changes, requests, latency and usage; generated catalogue witnesses are not independent truth.

No native-provider calls, feature implementation or accuracy experiments were performed for this design-only change.

## Protocol references

Historical research: OpenAI [images](https://developers.openai.com/api/docs/guides/images-vision), [structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs), [retention](https://developers.openai.com/api/docs/guides/your-data); Anthropic [images](https://platform.claude.com/docs/en/build-with-claude/vision), [structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs), [retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention). Verify current model/API compatibility during the approved implementation cycle rather than treating this research as a live API test.

Discovery/authentication references checked for this refinement: [OpenAI model listing](https://developers.openai.com/api/reference/resources/models/methods/list), [Anthropic model listing](https://platform.claude.com/docs/en/api/models/list), [GPT-5.3-Codex API capabilities](https://developers.openai.com/api/docs/models/gpt-5.3-codex), [Codex authentication and billing](https://learn.chatgpt.com/docs/auth), and [Codex client model availability](https://learn.chatgpt.com/docs/models). These are documentation checks, not authenticated requests or availability guarantees.
