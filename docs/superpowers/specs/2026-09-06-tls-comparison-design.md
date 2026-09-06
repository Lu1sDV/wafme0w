# Controlled-edge TLS comparison subsystem design

**Status:** written design set approved for planning on 2026-09-06. This remains the third delivery; only browser-capture implementation planning is currently authorized. No application implementation is authorized.

[Shared contracts, budgets and acceptance ownership](2026-09-06-ai-integration-design.md) apply. This is the third delivery, consuming the browser capture contract. It has no provider dependency and must work with AI off.

## Responsibility and boundaries

**Confirmed:** during an explicitly selected screenshot acquisition at a user-controlled service, compare actual native Chromium connection observations against an explicitly supplied previous capture. Compare returned response observations separately. Current comparison adds no browser visit, baseline request or separate Go TLS probe.

Use Chromium as-is: no TLS-randomization/impersonation flag, modified ClientHello, stealth, challenge solving, adaptive retries or per-request uniqueness guarantee. The earlier TLS-changing request was replaced by the user's native-browser choice, not deferred.

This is diagnostic comparison, not a bypass tool or proof that TLS caused blocking. Browser version, session/connection reuse, timing, application state, routing and acquisition policy can change responses. A difference is an observation; fingerprint equality is also a valid result.

## Prerequisite and observation contract

The operator must supply instrumentation at the **browser-facing TLS-terminating edge** of the controlled service. Chromium screenshot metadata alone cannot recover an arbitrary remote server's ClientHello observations. An upstream reverse-proxy connection, browser flags, a configured JA3 string or a Go-client observation is not a substitute.

**Proposed source:** that edge emits a bounded versioned record in a configurable main-document response header, suggested name `X-Wafme0w-TLS-Observation`. This is a new controlled-service contract, not an existing Chromium/httpx API. The record contains:

- Observation format version and observation-point identity.
- Service request/connection IDs and observation time.
- Actual transport/protocol.
- Fingerprint algorithm, normalization version and observed value.

**Proposed encoding:** one compact JSON object under the versioned observation schema. Enforce the record bound before decoding; reject duplicate fields, repeated observation-header values, trailing content and unsupported format versions rather than merging records.

Browser capture already owns actual main-document response events and document/request/connection identity where available. The TLS consumer joins the service record to that response and retains relevant cache/service-worker/connection-reuse provenance. Missing attribution is explicit; do not synthesize a connection ID or compare an unrelated response. A cached or service-worker-synthesized response cannot establish a current edge observation merely by replaying this header; without attributable current edge evidence, report unavailable.

Treat the service header as reported measurement, not cryptographically proven truth. Operator instrumentation is an external prerequisite, not a new server product to build into wafme0w. Missing or unsupported telemetry yields a diagnostic unavailable result while leaving ordinary capture usable; shipping the consumer without demonstrating real controlled-edge data does not satisfy this subsystem's acceptance gate.

## Explicit current/prior workflow

**Proposed controls:** screenshot mode plus `--tls-origin` selects observation at one designated controlled origin inside caller scope. `--tls-compare PRIOR.json` additionally selects local comparison; the observation-header name is configurable. Navigation/off modes reject TLS-specific options before acquisition rather than silently taking a screenshot.

The observation-only combination is an explicit proposal to make the prior-capture workflow complete without introducing another flag or an automatic visit:

1. The operator separately runs screenshot mode with `--tls-origin`, without a prior file, to obtain a normal capture and its local observation metadata. Save its single JSONL result if it will be used later. Image-file saving is not required.
2. In a later invocation, the operator supplies that prior result through `--tls-compare`, with screenshot mode and `--tls-origin` again selected.
3. The current run performs its one ordinary screenshot acquisition. Extract current telemetry from its already received main-document response and compare locally; no observation fetch or baseline visit is added.

A prior input is exactly one JSON object carrying a versioned prior capture report, such as one saved result from JSONL output. Reject multiple records/report arrays rather than guessing which capture the operator meant. CLI owns bounded file reading/decoding; the library receives a typed prior capture. Use the shared 1 MiB decoded input and 4 KiB service-record bounds before unbounded allocation.

Malformed/oversized/unsupported-format input is a configuration error. A valid record missing a corresponding TLS observation yields unavailable; missing identity needed to establish comparability yields incomparable. Current/prior screenshot metadata must establish that the observations belong to screenshot-producing captures; absent image files alone do not disqualify a capture whose image acquisition succeeded.

This proposed observation-only workflow clarifies how the confirmed previous capture is obtained. It does not require an automatic baseline, change Chromium's identity or treat a prior file as current target authorization.

## Comparability and results

Use actual initial/final request/document identity, not display host alone. Preserve the shared URL parser's path/query case and escaping. Prior connection IDs identify their own acquisition; they need not equal current IDs. What must hold is attribution within each capture and compatible endpoint, observation point, fingerprint algorithm/normalization and transport between captures.

Missing/redacted identity that prevents those checks is incomparable; never guess. TCP and QUIC fingerprints are not interchangeable. Unsupported protocol telemetry is unavailable, not a reason to alter Chromium's transport or fingerprint. Different browser versions can be compared when representations are compatible, but the version change remains an explicit confounder.

Produce independent comparisons:

- **Fingerprint:** `same`, `different`, `unavailable` or `incomparable`, with stable reason codes and current/prior references.
- **Response:** differences in status, retained sanitized headers and DOM/encoded-image digests where representations, redaction and dimensions are compatible. Missing/incompatible fields do not manufacture equality or erase a valid fingerprint comparison. Exclude volatile diagnostic request/connection IDs from ordinary header differences.

Record viewport, timing, browser version, redirects, reuse and known policy/restriction differences. Byte-different DOM/images do not establish semantically different blocking, and neither response nor fingerprint differences establish causation.

Telemetry parse failure is a failed diagnostic stage with fingerprint comparison `unavailable`; it does not introduce a fifth fingerprint-comparison state or convert capture success into failure.

Capture failure, missing observation, telemetry parse failure and incompatibility remain distinct. A missing current screenshot cannot be called a comparison of screenshot-producing connections. Malformed current telemetry fails the diagnostic, not otherwise valid capture. No diagnostic outcome changes `Outcome.Matches`, generic detection, provider eligibility or AI hypotheses.

## Data minimization, output and ownership

Extract configured telemetry into local browser metadata. Exclude that header from every normal provider projection, including Go HTTP evidence that happens to carry a same-named header. Never use a Go response's telemetry as the browser's observation. Comparison does not invoke a provider and does not transmit the prior record.

Ordinary serialized browser reports retain sanitized current/prior references, comparison status, limitations and successful-capture metadata/digests. Raw credentials are never required in a saved prior. If redaction removed identity necessary for comparison, report incomparable rather than reconstructing secrets. Screenshot bytes remain governed by the independent saving option.

A small TLS consumer owns observation parsing, validation and local comparison, not a second browser or transport. Browser capture exposes the main-document metadata already needed for local reporting and AI. Shared configuration validates selected modes; CLI reads the prior file; existing serializers render the nested browser diagnostic. No new top-level CSV column, catalogue rule, generic-anomaly heuristic or custom metrics service is needed.

## Independent acceptance gate

Use an instrumented TLS edge the operator controls, together with the supported actual Chromium runtime. Synthetic parser records may check validation but cannot stand in for this end-to-end gate.

1. **Real attribution:** obtain a prior in an explicitly separate screenshot invocation, then compare during one current screenshot acquisition. Service observations and browser request/document records must identify the actual browser-facing connections, not proxy-upstream or Go connections.
2. **No extra acquisition:** observe request/navigation counts and verify comparison causes no extra visit, telemetry retrieval, provider call, automatic baseline or Go TLS probe. Keep ordinary page resources distinct from comparison-induced traffic.
3. **Four-state semantics:** exercise equal and different compatible observations, missing telemetry, missing/redacted identity, wrong document/observation point, and incompatible TCP/QUIC/normalization representations. Do not fabricate differences by changing Chromium fingerprints.
4. **Input and capture failures:** reject malformed/oversized/unsupported prior records before acquisition. Exercise malformed current telemetry, absent current screenshot and valid prior records without usable observations; ordinary capture and diagnostic failure remain separate.
5. **Privacy/output:** with image saving off, retain enough sanitized capture metadata to make a subsequent explicit comparison, but no image artifact. Verify telemetry/prior inputs are absent from actual provider projections and serialize statuses/limitations through the real browser report and terminal output.
6. **Interpretation:** report fingerprint and response differences independently, including browser/timing/policy confounders. No output claims a fingerprint or HTTP error proves the cause of blocking.

A missing controlled-edge implementation is an explicit external prerequisite for runtime acceptance, not permission to substitute mocks or claim the TLS feature complete. No such experiment or browser implementation was performed for this design-only change.
