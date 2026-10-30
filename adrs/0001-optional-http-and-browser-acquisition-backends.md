# ADR 0001: Optional curl_cffi and Patchright acquisition backends

[ADR index](README.md) · [Browser guide](../docs/browser.md) · [Library guide](../docs/library.md)

| Field | Value |
| --- | --- |
| Status | **Proposed** |
| Recorded | 2026-10-30 |
| Decision owner | wafmeow maintainers |
| Implementation | No collector, helper protocol, backend selector, or browser adapter is introduced by this ADR |
| Validation | Source and documentation review only; the experiments below have not been executed for these integrations |
| Repository baseline | [`5a1866d6e5021fddf5972d4a6d3c020ff08538b1`](https://github.com/Lu1sDV/wafmeow/tree/5a1866d6e5021fddf5972d4a6d3c020ff08538b1) |
| Review point | After the curl_cffi feasibility experiments, before any supported integration or default change |
| Supersedes / superseded by | None |

## Proposed decision

Evaluate optional acquisition backends while preserving native Go acquisition
as the default and preserving the independence of offline classification.
Prototype **curl_cffi as an external capture producer first**. Evaluate
**Patchright as a separate browser implementation later**, against the existing
Chromium capture implementation. Promote either only when experiments establish
useful incremental evidence and the implementation satisfies its declared
operational contracts.

This is a proposal for an evaluation strategy and its design constraints.
Committing this record does not establish detection or performance gains, add
supported CLI flags, approve a new default, or authorize scans of additional
targets. These integrations are not prerequisites for the current release.

| Decision area | Proposed direction |
| --- | --- |
| Ordinary scanning and Go library | Retain the native implementation and existing defaults |
| First experiment | A separately installed curl_cffi collector producing native capture JSONL plus a versioned provenance manifest |
| Classification | Classify coherent observation sets independently, then compare findings with their sources |
| Browser experiment | Compare Patchright with current Chromium capture; retain browser metadata outside fingerprint matching |
| Dependencies | Optional and explicitly installed; no package, profile, or browser download during scanning |
| Fallback | Explicit selection or an explicit second pass initially; no silent client switching |
| Promotion | Separate decisions for an experimental collector, supported integrated HTTP backend, and supported browser backend |
| Marketing | Describe observed capabilities and measured workloads; make no universal access, accuracy, or speed claim |

## Contents

- [Context and existing architecture](#context-and-existing-architecture)
- [Capabilities and expected benefits](#capabilities-and-expected-benefits)
- [Decision drivers and scope](#decision-drivers-and-scope)
- [Alternatives considered](#alternatives-considered)
- [Proposed architecture and evidence contracts](#proposed-architecture-and-evidence-contracts)
- [Operational contracts](#operational-contracts)
- [CLI and public API direction](#cli-and-public-api-direction)
- [Experiments and acceptance criteria](#experiments-and-acceptance-criteria)
- [Distribution, licensing, and maintenance](#distribution-licensing-and-maintenance)
- [Consequences and risks](#consequences-and-risks)
- [Rollout, rollback, and ownership](#rollout-rollback-and-ownership)
- [Open questions and review triggers](#open-questions-and-review-triggers)
- [Sources and evidence record](#sources-and-evidence-record)

## Context and existing architecture

wafmeow acquires HTTP responses and evaluates them with a shared fingerprint
engine. Saved native captures and supported httpx exports use the same engine
without issuing requests. Named matches, generic anomalies, evidence
completeness, and optional browser metadata are separate concepts.

At the repository baseline:

- `Run` obtains observations, calls `Engine.Classify`, and separately evaluates
  generic anomalies. `Config.Client` accepts an injected `*http.Client`.
- The default transport deliberately uses fresh HTTP/1 connections, disables
  keepalive and HTTP/2, and maintains a bounded TLS session cache. This avoids
  transparent probe replay inside the owned transport escaping accounting.
  The default request headers include a Chrome User-Agent; that header does
  not make Go's TLS and HTTP behavior equivalent to Chrome.
- The outbound wrapper checks scope and request budgets and applies rate and
  active-exchange admission. Slots remain occupied until response-body closure.
  Caller-supplied transports retain responsibility for hidden network effects,
  retries, and wire-level allocations.
- `RunCaptured` accepts native JSONL records containing `target` and `evidence`.
  The decoder rejects unknown fields. Bodies use JSON's base64 representation
  for Go byte slices. Existing record and queue limits protect the importer,
  not a separate producer.
- Chromium capture uses Go Rod, direct CDP operations, and a repository-owned
  launcher. Its reports and artifacts do not alter fingerprint matches. Browser
  capture is opt-in, Linux-only, non-root, and uses a fresh process/profile per
  target occurrence, private debugging pipes, certificate validation, and the
  Chromium sandbox. Browser and HTTP budgets are separate.

These are source-backed facts, not requirements inferred from either proposed
dependency. See [configuration][r-config], [HTTP acquisition][r-acquisition],
[request construction][r-http], [runner][r-runner], [capture import][r-capture],
and [browser contracts][r-browser-guide].

### Why investigate alternative clients?

A server can return different responses to clients with different TLS, HTTP,
header, JavaScript, or session behavior. An alternative client may expose useful
headers, cookies, or content that the native client did not receive. It may also
receive ordinary application content after the native client received a highly
identifiable challenge. Either observation can be valuable.

Successful application access is therefore a separate outcome from correct WAF
identification. An HTTP 200 response is not evidence of improved detection; a
403 response is not inherently a failed acquisition. A product-specific block
page may be the most useful response for fingerprinting. A later response
without that marker must not erase an earlier positive observation.

A changed response also does not isolate its cause. A browser profile can change
TLS, negotiated protocol, headers, connection reuse, and cookies together.
Experiments must report client-dependent behavior unless narrower controls
support a more specific explanation. Additional product markers do not by
themselves establish the order or topology of protection layers.

### Existing benchmark evidence

The published 2,000-target comparison completed on 2026-10-30 used build
`836252b`, not the repository baseline reviewed for this ADR. Its three-block
ranges include:

| Configuration | Complete targets | Incomplete targets |
| --- | ---: | ---: |
| Fast, 100 workers | 1,437–1,460 | 540–563 |
| Full, 50 workers | 1,433–1,446 | 554–567 |
| Full, 100 workers | 1,368–1,410 | 590–632 |

These counts measure classifier evidence completeness; named matches can coexist
with incomplete observations. They do not identify TLS discrimination, browser
challenges, or any other cause. The published aggregates lack a causal diagnostic
breakdown, and raw records are not distributed with the repository. The record
supports investigating acquisition limitations but cannot predict gains from
either integration. Preserve the measured build, workload, and limitations when
using these numbers. [Published benchmark record][r-benchmarks].

## Capabilities and expected benefits

### curl_cffi

curl_cffi is a Python binding around a curl-impersonate fork. The reviewed
`v0.17.0` release uses curl-impersonate 2.3.0 / curl 8.23.0 and requires Python
3.10 or newer. It supports selected browser TLS/HTTP characteristics, custom
fingerprint controls, synchronous and asynchronous requests, cookies, and
proxies. Current open-source documentation includes HTTP/3 support; available
QUIC/HTTP/3 fingerprints vary by profile. It is an HTTP client, without a page
JavaScript engine or renderer. [Project][c-project], [release][c-release],
[installation][c-start], [profile support][c-targets].

Potential advantages to test:

- More informative responses where the native client sees generic refusals.
- Additional evidence associated with negotiated protocol or client profile.
- Explanations of differences between ordinary scan responses and responses to
  a selected browser profile.
- An intermediate acquisition option with less work than browser rendering.
  Its actual latency, throughput, and resource cost remain unmeasured here.
- Reproducible fixtures for infrastructure whose responses vary by client.

Limitations and costs:

- It does not add product fingerprints or prove the accuracy of existing rules.
- It cannot execute JavaScript challenges or reproduce all browser behavior.
  Upstream explicitly notes that matching selected fingerprints is incomplete.
- Profile defaults, URL normalization, decompression, sessions, redirects, and
  native retries can change probe or evidence semantics unless controlled.
- Python and native dependencies add installation, lifecycle, release, and
  security-maintenance work to this optional capability.
- Browser aliases and externally managed profile data can change independently
  of the intended experiment identity. [Impersonation limits][c-impersonation],
  [profile updates][c-fingerprints].

### Patchright

Patchright patches the Playwright driver to reduce observable automation
behavior. Its patches support Chromium-based browsers and include avoiding
`Runtime.enable`, alternative execution-context handling, console-related
changes, and different launch arguments. Python and Node packages are available;
the project also links a community .NET package. This is not a special browser
executable that can replace the current `--browser-path`. Continuing to drive a
browser through Rod would not inherit the patched Playwright operations.
[Patchright project][p-project].

Expected value is incremental to the existing Chromium implementation:

- Usable captures on targets that distinguish the current automation behavior.
- Better rendering context for manual examination of ambiguous responses.
- A controlled comparison of different automation clients under the same
  capture requirements.

Most JavaScript, cookie, navigation, and screenshot capabilities already come
from Chromium. They must not be attributed as new Patchright benefits. As long
as browser metadata remains separate from matching, the immediate benefit is
capture quality rather than a new named-product detection path.

Upstream recommends headed Chrome, a persistent context, and no custom browser
headers or User-Agent for its preferred setup. Headless operation is possible,
but that recommendation does not validate wafmeow's restricted configuration.
A persistent-context API can use an owned temporary profile; it does not require
sharing the user's ordinary profile or retaining state between targets.
[Python package guidance][p-python].

Patchright documents differences from Playwright, including console/error
observability and other unsupported behavior. Its initialization-script path
can conditionally inject HTML and modify CSP. This does not mean every response
is modified, but instrumented content must not be represented as untouched
server evidence. [Known limitations][p-bugs], [reviewed driver source][p-network].

### Using both

The libraries represent independent network paths. Chromium traffic does not
automatically use curl_cffi when both are installed. A browser-to-HTTP cookie
handoff would be an additional feature, with explicit IP, profile, session,
credential, and expiry semantics. It is outside the initial evaluation.

Fulfilling browser requests with curl_cffi responses would alter the acquisition
model and complicate origin, redirect, cache, and response attribution. A
TLS-terminating intermediary also changes the TLS identity seen upstream.
Evaluate separate observations first; do not build a hybrid by assumption.

## Decision drivers and scope

The proposal prioritizes:

1. **Evidence fidelity:** retain the observation that supports each finding,
   its acquisition conditions, and its completeness.
2. **Bounded, explicit work:** make network acquisition, additional attempts,
   deadlines, queues, and resource ownership understandable.
3. **Useful incremental outcomes:** demonstrate value beyond the existing Go
   and Chromium paths, including the cost and adverse outcomes.
4. **Reproducibility:** bind results to exact builds, profiles, configuration,
   request plans, and input identities.
5. **Compatibility:** preserve default behavior, structured output, offline
   guarantees, exit semantics, and the ordinary static Go installation.
6. **Maintainability:** prefer the smallest supported integration surface and
   keep its dependency lifecycle separately accountable.

The initial scope is an optional external curl_cffi capture producer, followed
by controlled assessment of integrated HTTP and browser implementations. It
excludes automatic challenge solving, authentication workflows, shared browser
profiles, proxy rotation, a remote hosted acquisition service, arbitrary dynamic
plugins, default-client replacement, and a browser-DOM fingerprinting engine.
Those additions would need their own evidence and design review.

## Alternatives considered

| Option | Advantages | Disadvantages / unresolved work | Disposition |
| --- | --- | --- | --- |
| Continue with native Go and current Chromium only | Smallest maintenance surface; preserves existing behavior and distribution | No direct investigation of browser-profile HTTP behavior or alternate automation | Valid baseline and rollback path |
| External curl_cffi capture producer | Reuses offline classification; isolates dependencies; creates replayable evidence; easy to evaluate independently | Must implement acquisition controls itself; separate provenance and installation; not a ready-made supported backend | **First experiment** |
| Managed curl_cffi helper behind the Go client seam | Can share Go orchestration while amortizing Python startup; exposes an explicit optional backend | IPC, cancellation, hidden native work, concurrency, and response fidelity need a supported contract | Conditional on collector results and contract tests |
| curl-impersonate executable | Similar underlying capability without a Python wrapper | Process/output handling, platform packaging, and per-request startup costs; not equivalent to stock curl | Compare if packaging or Python overhead is material |
| libcurl-impersonate through cgo | Direct native integration and potentially lower IPC overhead | C toolchains, native dependency maintenance, build/release matrix, and static-linking choices | Defer until measured need justifies the build complexity |
| Go-native browser-profile HTTP stack | Closer to current distribution and library model | TLS and HTTP behavior, transport types, hidden negotiation/retries, and maintenance must still be audited | Evaluate before choosing a permanent supported implementation |
| uTLS alone | Focused control over TLS ClientHello in Go | Does not by itself reproduce HTTP/2, HTTP/3, header behavior, JavaScript, or a complete browser | Insufficient as a claim of curl_cffi equivalence |
| Patchright browser helper | Access to the patched driver; can remain optional | Separate driver implementation, browser dependencies, scope and export parity; benefit beyond existing Chromium unknown | Later experiment |
| Replace defaults or automatically try all backends | More observations without user selection | Changes workload, latency, state, interpretation, and installation; can hide failed limits behind extra attempts | Not selected |

The existing `Config.Client` is a seam, not proof of compatibility with every
client implementation. Go-native alternatives such as tls-client merit
evaluation, but may use different HTTP types and protocol behavior. uTLS states
its focus on ClientHello; it is not a full HTTP/browser emulator.
[uTLS][a-utls], [TLS-Client][a-tls-client].

## Proposed architecture and evidence contracts

### Stage A: external collector and offline classification

The collector would own acquisition and emit native captures plus a separate
manifest. A working offline interface already exists:

```sh
# captures/curl-cffi.jsonl would be produced by the future collector.
wafmeow --evidence captures/curl-cffi.jsonl --jsonl
```

The collector and manifest do not exist yet. This example documents the existing
consumer boundary, not an available end-to-end integration.

**The producer must enforce its own network limits.** Request, rate, or timeout
options supplied to a later `--evidence` invocation cannot constrain traffic
already sent upstream. Record acquisition settings separately from replay and
classifier settings. Keep replay zero-network, including when the optional
dependencies are installed but unavailable.

The collector must write an explicit, validated availability object for every
observation. Existing nil/missing/null availability preserves legacy behavior
and can treat an omitted body as complete when status is valid and no error or
truncation is recorded. New output must not rely on that inference. Missing,
truncated, unsupported, or unverified channels remain unavailable or incomplete;
bytes being present is not proof that the complete body was received.
[Evidence semantics][r-evidence], [availability implementation][r-availability].

### Coherent observation sets

Identify each acquisition group by target occurrence, backend and version,
resolved profile revision, session identifier/epoch and policy, and probe plan.
Repeated identical URLs remain distinct occurrences. Keep Normal and active probe observations
within the same group.

Classify each group independently. `Engine.Classify` permits AND terms to match
across responses, and `GenericDetect` compares probes with a Normal response.
Blindly concatenating profiles could satisfy a fingerprint with unrelated
observations or mistake a client difference for a probe effect. Retain the
native result and each alternative result; a comparison layer can report
agreements, additional findings, lost markers, and unresolved differences with
source references. [Classifier implementation][r-classifier].

Preserve both a product-specific challenge and a later application response.
Do not automatically turn their sequence into proof of bypass, enforcement,
product absence, or infrastructure topology. Browser DOM and screenshot data
remain separate. A future proposal to classify browser network evidence must
define and validate that new evidence contract explicitly.

### Provenance and artifact identity

Initially use a versioned manifest rather than incompatible extra fields in
native capture records. Bind each record to its capture-file digest, record
index, occurrence identifier, and exact record/body digests. Specify hashing
and serialization rules; a human target label is not a metadata transport.

The manifest should contain:

- Collector source/binary identity, Python version, dependency lock/digests,
  curl_cffi and native curl versions; for browser experiments, driver and actual
  browser versions and executable identity.
- Concrete profile name, operating-system variant, and profile-data digest.
  Resolve floating aliases before acquisition and disable updates during a run.
- Input identity, target occurrence, experiment arm/block/order, probe role,
  request plan, and timings, including queue and acquisition time.
- Actual negotiated protocol, effective URL and redirects, explicit header
  overrides, cookie/session policy, TLS trust policy, and proxy/egress policy.
- Applied limits, attempt counts, truncation, errors, partial completion,
  readiness limitations, and artifact hashes.
- Classifier version and catalogue digest for replay, recorded separately from
  the producer's acquisition configuration.

Avoid recording raw secrets in command lines or manifests. Use redacted policy
descriptions and non-secret configuration identities. Retain sensitive original
captures only in an approved private location; publish reviewed, sanitized
fixtures and distinguish sanitized hashes from original hashes. Sanitization
can remove identifying evidence and must be documented.

### Stage B: managed HTTP adapter

If Stage A establishes value, evaluate a bounded helper implementing a
single-exchange transport behind the existing Go client seam. Go should retain
ownership of its request plan, per-hop scope checks, pacing, and result pipeline.
An adapter call must not independently follow redirects or hide additional
HTTP exchanges. If the underlying stack cannot satisfy a claimed bound, reject
that configuration or document a narrower capability before supporting it.

The helper protocol would need version/capability negotiation, correlation IDs,
bounded framing and queues, explicit deadlines, streaming cancellation, and
rejection of unexpected or duplicate responses. Use a fixed executable and
structured arguments without shell interpretation of targets. Protocol stdout
must remain machine-readable; stderr diagnostics must also be bounded.

Amortize interpreter startup with a bounded worker pool while isolating target
and session state. Define process ownership, body-close behavior, crash handling,
and shutdown/reaping of the entire owned process tree. A helper process is a
dependency boundary, not automatically a security or memory sandbox.

### Stage C: optional browser implementation

Implement Patchright through its patched driver rather than mixing Rod and
Playwright commands opportunistically. Keep browser action selection separate
from driver selection. Preserve the current browser reporting contract and
revalidate sandboxing, temporary profiles, network admission, identity
correlation, readiness, bounded artifacts, and credential-aware export.

HTTP acquisition budgets and browser budgets remain distinct unless a later
design explicitly changes their meaning. Report both costs. An OS-enforced
egress or renderer resource boundary, if required for a deployment, needs
separate implementation and testing; CDP or Playwright routing is insufficient
as that guarantee.

## Operational contracts

The following are requirements for a future supported integration. Their
presence here does not establish that the proposed libraries already meet them.

### HTTP acquisition

| Area | Required behavior and validation |
| --- | --- |
| Scope and redirects | Check each destination before the next exchange. Preserve canonical-host/allowlist semantics and credential forwarding rules. A generic private-address redirect filter is not equivalent to user scope. |
| Attempts and pacing | Account for every probe, redirect, retry, authentication retry, and other HTTP exchange. Begin with retries disabled; test native/protocol behavior, not just wrapper counters. Additional profiles consume an explicit acquisition budget. |
| Concurrency | Distinguish target workers, active exchanges, helper handles, connections, streams, and dial attempts. Existing `MaxConnections` is an active-exchange slot bound through body close, not a universal socket/DNS bound. |
| Deadlines | Include helper queueing, transfer, decoding, and cleanup in declared deadlines. Interrupt slow-progress streams and blocked IPC; do not substitute a low-speed timeout for a wall-clock deadline. |
| Request fidelity | Preserve method, encoded path/query, probe roles, header values, and intentional User-Agent suppression unless explicitly overridden by the user. Test actual requests received by owned fixtures. |
| TLS and proxy policy | Keep certificate verification enabled and define trust-store behavior. Configure environment inheritance, proxy use, hostname/SNI behavior, and egress identity explicitly. Do not silently relax validation to increase success counts. |
| Session policy | Do not introduce a shared cookie jar accidentally. Declare cookie persistence, connection/session reuse, and TLS resumption; isolate target occurrences and experimental arms as required by the protocol. |
| Headers and status | Preserve repeated header values and distinguish absent from unavailable channels. Do not fabricate HTTP/1 reason phrases for protocols that do not carry them. |
| Body representation | Define whether IPC contains encoded or decoded bytes. Decode once, preserve relevant metadata, and apply decoded-size limits before full buffering. Record unsupported/stacked encoding behavior. |
| Resource boundaries | Bound header buffers, decoded bodies, retained per-target evidence, encoded/base64 frames, queues, pending results, and diagnostics. These bounds are distinct from helper/process RSS and native-library allocations. |
| Publication | Preserve result/journal ordering and atomic report contracts. Sink failure and cancellation must stop further admissions and release resources. No helper diagnostics may enter result JSONL. |

The current Go path decodes identity/gzip/zlib-deflate and rejects unsupported
content encoding. curl_cffi can automatically decode responses; retaining its
encoding headers with already decoded bytes can create double-decoding errors.
Its default URL requoting and browser headers can change probes. In the reviewed
version, redirects default to enabled with a maximum of 30, environment proxies
are trusted, retry count defaults to zero, and `AsyncSession.max_clients` counts
curl handles. Streaming timeout behavior differs from a total deadline, and
redirect history does not contain intermediate bodies. These are integration
inputs to configure and test, not defects asserted in either project.
[Go HTTP path][r-http], [curl_cffi session][c-session], [request options][c-utils],
[response model][c-models].

The native importer's 16 MiB record and 32 MiB in-flight raw-record limits do not
constrain the producer's earlier allocations or network traffic. Similarly,
the retained-evidence budget is not a process-RSS limit. A managed adapter must
enforce its own upstream and IPC boundaries before data reaches the importer.
[Importer limits][r-capture], [configuration contract][r-config].

### Browser acquisition and export

Preserve the existing restricted model: fresh owned profile, native browser,
non-root execution, sandbox and certificate validation, controlled environment,
bounded process ownership, and sanitized exports. Browser support remains
Linux-only until a deliberate platform expansion is validated.

Playwright documents that route handlers do not provide a fresh interception
decision for every redirect hop; service-worker interception can bypass normal
routes, and enabling routing changes caching behavior. Patchright also documents
unsupported behavior. Test redirects, frames, workers, popups, speculative
traffic, unsupported channels, downloads, and resource origins against the
precise guarantees claimed. Do not equate a route counter with complete egress
control. [Playwright networking][p-network-docs], [context routing][p-routing],
[Patchright limitations][p-bugs].

Playwright's launch API documents `chromiumSandbox` as false by default. Configure
and verify the effective launch explicitly; a convenience launch example does
not establish parity with wafmeow's launcher. Preserve private control channels
and cleanup. Dependencies or display requirements must fail clearly rather than
triggering a less restricted browser configuration. [Launch API][p-launch].

Re-run the existing screenshot credential/geometry regression suite against the
new driver. Plain screenshot capture is not the sanitized artifact contract.
Maintain independent DOM and image export failures, byte caps, hashes, and
fail-closed behavior. Keep original network content distinguishable from
rendered or instrumented content. Capture restrictions may prevent a challenge
flow from completing; report that limitation rather than silently widening
methods, origins, or session access. [Export contract][r-browser-guide].

### Errors and offline behavior

Unsupported profiles, missing dependencies, incompatible helper versions, and
invalid flag combinations should fail before target acquisition. Recoverable
per-target acquisition failures should produce diagnosed results. Protocol
corruption or an unusable helper pool can be a run-level failure; the supported
implementation must document that classification and preserve already published
or journaled results.

Preserve current exit meanings: strict incomplete/failed/diagnosed results exit
2 after publication, configuration/input/output failures exit 1, and cancellation
exits 130. An optional backend must not convert an earlier failure into success
by switching clients without a recorded, selected attempt. Offline input remains
zero-network and must not initialize either helper. [Operations][r-operations].

## CLI and public API direction

The following names are illustrative proposals. They are not implemented or
reserved compatibility promises:

| Proposed option | Meaning / validation |
| --- | --- |
| `--http-backend native\|curl-cffi` | Select HTTP acquisition; default stays native |
| `--http-profile PROFILE` | Require a compatible alternative backend; resolve and record a concrete supported profile |
| `--browser off\|navigate\|screenshot` | Preserve the existing browser action selector |
| `--browser-backend native\|patchright` | Select the browser implementation only when a browser action is enabled |

Illustrative future usage, not executable with the current CLI:

```text
wafmeow --target https://app.example.test --baseline \
  --http-backend curl-cffi --http-profile chrome152 --jsonl

wafmeow --target https://app.example.test --baseline \
  --browser screenshot --browser-backend patchright \
  --save-screenshots ./screenshots --jsonl
```

Reject inactive modifiers and incompatible offline selection. Keep target/file
input handling, output format selection, stdout/stderr separation, and help
grouping consistent with the current CLI. Help/version/list operations must not
require optional runtimes. Dependency installation and profile/browser updates
are explicit setup operations outside scans.

Start with explicit backend selection or a separately invoked comparison. Any
future automatic follow-up policy needs its own eligible outcomes, total budget,
attempt order, cancellation behavior, and provenance. A TLS validation error,
scope refusal, exhausted budget, or deadline is not an invitation to bypass the
original control through another client.

Preserve the v2 library API and result schema contract. A generic plugin system
is unnecessary for the first collector. Before adding public interfaces or
backend metadata, review source compatibility, strict capture decoding, report
consumers, and schema-version behavior. Browser-derived fingerprint evidence
requires a separate explicit decision; this proposal retains the current
separation. [Library contracts][r-library].

## Experiments and acceptance criteria

All experiments in this section are **planned**. No recovery rate, detection
gain, performance improvement, or scope-compliance result is established by this
ADR. Maintainers should assign an experiment owner and freeze its protocol
before acquisition. A public ranking list is not authorization; use owned
fixtures and independently authorized systems.

### Shared protocol

Use deterministic fixtures for contract tests and a separately labeled panel
for empirical utility. Include known WAF configurations, bot-protection-only
cases where distinguishable, and no-WAF controls. Obtain ground truth from
controlled configuration or independently reviewed evidence; agreement with
wafw00f or another detector is not ground truth.

Keep client arms separate and classify each coherent group independently.
Control request plan, egress identity, trust policy, scope, deadlines, response
limits, and intentional session behavior. A profile's protocol/header changes
are treatment differences and must be recorded, not concealed as equivalent
requests. Separate protocol-only/TLS-only investigations from a whole-profile
comparison when causal attribution is needed.

Randomize or rotate client order within repeated blocks, use fresh profiles/jars
where specified, and record timing and order. Reset owned server-side challenge
and rate state when possible, or balance/separate traffic that may change it.
Fresh cookie jars alone do not eliminate server-side carryover. Report carryover,
rate limiting, time variation, and unavailable controls as limitations. Freeze selection,
exclusions, block count, stopping rules, and the confirmation panel before
examining favorable outcomes. Pilot tuning and confirmation runs must remain
distinguishable.

Record selected candidates and pre-admission exclusions separately. Keep every
admitted target occurrence in the operational denominator, including failures,
timeouts, cancelled or unstarted work, and missing upstream records.
Report attempted and completed subsets explicitly.
Do not replace difficult targets or rerun an inconvenient completed cell without
retaining and explaining the original. Report denominators and per-arm workload;
successful-response-only timing can hide the cost of failures.

### Experiment sequence

| ID | Question and procedure | Evidence to retain | Advancement condition |
| --- | --- | --- | --- |
| E0: diagnostic inventory | If privately retained records are available, classify the existing native failures by DNS/transport, certificate, deadline, scope, encoding/size, budget, and usable-response categories. Inspect existing markers as well as completeness. Leave ambiguous causes unknown. | Measured build, parser version, exact counts, multi-cause handling, missing-data accounting, reviewed examples | Select a justified pilot panel; do not infer causes from aggregate incomplete counts |
| E1: deterministic contracts | Implement collector/adapter fixtures for request fidelity, redirects, limits, compression, availability, sessions, cancellation, IPC, and output. Verify requests at owned servers and network boundaries. | Inputs, expected behavior, received request bytes, attempt/cancellation traces, resource checks, replay output | No unexplained contract violations; source and runtime behavior agree with the stated capabilities |
| E2: baseline-only curl pilot | Compare native Normal acquisition with one fixed curl_cffi profile on labeled controls. Classify independently and review all differences. Begin with no persistent cross-target state. | Original/sanitized captures, manifests, paired outcomes, correctness review, extra cost | Demonstrated acquisition usefulness and interpretable findings; a pilot establishes feasibility only |
| E3: matched active probe evaluation | After E1/E2, run the same approved probe plan within each profile. Preserve deliberate probe deviations. Keep each profile's Normal and matched active probes in one coherent group; classify profiles separately. | Per-probe outcomes, exact requests, lost/new markers, named/generic differences, completeness, budgets | Confirmed incremental findings under predeclared benefit/cost criteria, with adverse outcomes resolved |
| E4: browser comparison | Compare current Chromium capture with Patchright under the same declared restrictions and fresh state. Include known automation-sensitive fixtures. Keep browser results outside matching. | Usable-capture/readiness criteria, screenshots/DOM with provenance, scope traces, sandbox and export results, cost | Useful additional captures beyond current Chromium; all required browser/export contracts pass |
| E5: resource and portability qualification | Measure cold and warm helper/browser behavior, supported native platforms, packaging, cancellation, repeated runs, dependency absence, and default/offline operation. | Exact builds, platform/runtime versions, wall time, CPU, peak memory, request/byte counts, process/fd cleanup, failures | A declared support matrix and resource envelope; no default-path or offline regression |
| E6: confirmation and release review | Repeat a frozen candidate on the held-out confirmation panel and validate the exact distribution artifacts. Independently review interpretation and operational limits. | Protocol, manifests, all cells, uncertainty estimates, review decisions, artifact identities, release checks | Maintainer decision recorded before supported promotion; inconclusive results remain experimental |

If E0 records are unavailable, record that limitation and use newly authorized
controlled experiments. Do not reconstruct a causal history from the published
table. If E2 adds no useful evidence, reconsider the capability before expanding
into active probes or more profiles.

For E4, hold the compatible browser build, headless mode, viewport, and other
capture settings constant where possible. A headed Chrome configuration compared
with headless Chromium measures the whole configuration difference; it cannot
isolate the Patchright driver. Preserve the current fresh process/profile per
occurrence and one-active-browser scheduling in the first comparison. Reusing a
warm browser is a separate architecture experiment, not an assumed optimization.
For E5, include helper and browser subprocesses in CPU/memory accounting and
distinguish installation, process startup, warm-helper operation, and total scan
cost. Keeping a helper alive does not permit sharing target sessions.

### Required contract fixture matrix

At minimum, cover:

- Encoded paths/query strings, explicit empty User-Agent, user overrides,
  repeated response headers/cookies, and protocol-specific missing fields.
- Allowed/disallowed redirects, redirect loops and caps, cookie/authorization
  forwarding, invalid certificates, explicit proxies, and environment isolation.
- Slow headers, slow-progress bodies, reset/retry behavior, H2/H3 negotiation
  when enabled, and actual attempts versus reported counters.
- Exact body/header/evidence boundaries, excess bytes, compressed expansion,
  unsupported encodings, interrupted reads, explicit availability, and malformed
  capture/helper records.
- Duplicate target occurrences, interleaved profile results, same-host sessions,
  cross-target contamination, queue saturation, oversized frames, helper crash,
  blocked pipes, cancellation, sink failure, and process cleanup.
- Regression cases where combining two profiles would create a cross-profile
  AND match or an invalid generic baseline comparison.
- Existing browser scope, readiness, cancellation, credential-mask geometry,
  sanitized DOM, withheld screenshots, and artifact-save failure cases.
- Native help/scanning with optional backend dependencies absent, zero-network offline replay, report
  publication and exit behavior, and compatibility with existing consumers.

Test observable behavior rather than only mocked API returns or self-reported
counts. Network isolation and resource assertions must identify the mechanisms
that enforce them; passing a fixture is not proof about every possible browser
channel or future version.

### Metrics and decision rules

| Metric | Definition / interpretation |
| --- | --- |
| Incremental correct identification | A reviewed, correct product finding from an alternative group that native acquisition did not establish for the paired target occurrence |
| Targets with additional correct findings | Target-level utility, reported separately from product-level counts because one target can have multiple product findings |
| False product finding | A product claim contradicted by independently established ground truth; report separately from findings awaiting adjudication |
| Unadjudicated finding | A claim without sufficient independent evidence to determine correctness; retain as unresolved rather than counting it as a demonstrated false positive |
| Lost identification | An independently confirmed baseline finding absent in the alternative group, even when the combined presentation preserves the baseline; report disappearance of unconfirmed native findings separately |
| Completeness and unresolved rate | Per-group channel/overall completeness and unresolved outcomes over all admitted occurrences; report alongside named/generic results |
| Capture utility | Browser capture satisfying predeclared readiness/content criteria; distinct from HTTP 200, challenge completion, or WAF detection |
| Acquisition cost | Actual exchanges, redirects, retries, bytes, elapsed time, CPU, peak memory, and setup cost, including failures |
| Stability | Repeatability across blocks and clean sessions; report profile/session/order-dependent differences |
| Contract conformance | Observed agreement with scope, budget, evidence, lifecycle, output, and offline requirements on the defined matrix |

Before confirmation, maintainers must record a minimum useful incremental gain
and acceptable extra cost for the intended use case, together with sample-size
and uncertainty reasoning. This ADR deliberately does not invent a universal
percentage or hosts-per-minute threshold. Use paired analysis and account for
repeated observations of the same host; do not treat correlated repeats as
independent accuracy samples. Publish per-stratum outcomes and uncertainty,
including null or negative findings.

Hard promotion gates are:

1. Exact admitted-attempt accounting and faithful availability/provenance.
2. No observed unexplained scope, budget, session isolation, lifecycle, or
   evidence-contract violation in the required matrix.
3. Independent classification of profile groups and review of all new false
   product claims on negative controls. A new false claim blocks promotion
   until explained and corrected. Narrowing the supported use case requires
   retaining the failed result, freezing a new narrower protocol, and fresh
   confirmation; it cannot retroactively pass the original gate.
4. Confirmed useful outcomes within the predeclared cost envelope. Browser
   capture improvement alone must not be advertised as named-detection gain.
5. Native-platform, dependency-security, packaging, documentation, and
   compatibility gates for the exact candidate and declared support matrix.

Stop or defer if gains disappear in confirmation, the same benefit is attainable
through simpler existing behavior, maintaining constraints removes the proposed
value, or dependency/operational costs exceed the agreed envelope. Keep the
results and rationale; a rejected experiment is still useful evidence.

### Evidence bundle

Retain the frozen protocol, target-selection identity and authorization scope,
source and artifact hashes, dependency/profile manifests, per-arm settings,
request observations, raw/private and sanitized/public capture identities,
classification output, correctness review, resource measurements, and all
excluded/incomplete cells. Preserve commands without credentials and distinguish
setup time from end-to-end scan time.

Store sensitive records privately under an explicit retention policy. Commit
only reviewed sanitized fixtures and non-sensitive summaries. Offline replay
can validate matching and preservation; it cannot establish whether a different
live client would have received a different response.

## Distribution, licensing, and maintenance

Keep ordinary releases and the existing minimal container independent of Python,
Node, native impersonation libraries, and browser downloads. If an advanced
distribution is justified, publish it separately with explicit prerequisites,
supported platform combinations, version checks, and reproducible dependency
installation. A compatible upstream wheel does not validate our adapter on that
platform. Do not promise that upstream browser platform support expands
wafmeow's current Linux browser support automatically.

Pin and audit the actual package/native/browser graph. Record driver/browser
compatibility, update profiles outside runs, and repeat affected contract tests
when upgrading. A Go vulnerability scan does not cover a Python package,
bundled libcurl/TLS components, or Chromium. Assign responsibility for those
updates before declaring the integration supported. Playwright documents
version-specific browser requirements. [Browser versions][p-browsers],
[current release policy][r-releases].

curl_cffi and the reviewed curl-impersonate fork use MIT licenses; Patchright
uses Apache-2.0. Distribution must preserve the applicable licenses and notices
of the actual shipped components. The native build includes separately licensed
TLS, HTTP, compression, and resolver components; browser distribution also has
its own notices and terms. An upstream recommendation to use branded Chrome
does not establish redistribution rights for a bundled Chrome image.
[curl_cffi license][c-license], [curl-impersonate license][c-native-license],
[native notice inventory][c-notices], [Patchright license][p-license],
[Playwright notice][p-notice], [Chromium license][p-chromium-license].

Prefer user-installed optional dependencies for the first prototype. Before
bundling a helper or image, generate a component inventory, check the actual
build options and notices, and include them with the artifact. Do not reduce
the inventory to the two top-level license names.

## Consequences and risks

### Positive consequences

The proposal adds a path to investigate difficult acquisitions without changing
the default installation or losing native evidence. Separate profile results
make differences explainable. Capture-first development reuses the existing
classifier and produces fixtures that can be reviewed without repeating network
requests. Stage-specific gates make it possible to retain a useful experimental
collector even if a supported integrated backend is not justified.

### Negative consequences

Optional integrations still cost maintenance: another runtime, native updates,
profile drift, more test environments, process supervision, and more complex
provenance. More observations can increase ambiguity and false-positive
opportunities. Browser follow-up can be much more expensive than HTTP acquisition.
Preserving budgets or restricting browser behavior may reduce the apparent
access benefit advertised upstream. These costs remain even if installation is
optional.

### Risk register

| Risk | Consequence | Mitigation / decision response |
| --- | --- | --- |
| A challenge is hidden by the alternative client | Lost identifying markers or misleading no-match | Retain native evidence and report each group independently |
| Profiles or sessions are mixed | Cross-profile AND matches or spurious generic anomalies | Explicit group identity and classifier regression fixtures |
| Hidden redirects/retries/negotiation | Extra traffic or scope/accounting mismatch | One-exchange contract and observed network tests; reject unsupported guarantees |
| Unbounded native or IPC buffering | Memory pressure despite Go retention caps | Producer-side streaming/limits, bounded frames/queues, measured resource envelope |
| Driver or profile updates change behavior | Non-reproducible results and new regressions | Pin/hash inputs, forbid in-run updates, requalify affected contracts |
| Browser control or export differs | Scope leakage, unsafe launch, or credential exposure | Full browser/runtime/export parity tests and fail-closed unsupported paths |
| Egress/session/time differs between arms | Incorrect explanation of the response change | Paired protocol, balanced order, recorded state, cautious causal claims |
| More dependencies than measurable value | Release and support burden | Separate promotion decisions, simpler-alternative comparison, explicit stop criteria |

## Rollout, rollback, and ownership

| Stage | Deliverable | Owner / gate |
| --- | --- | --- |
| 0: record and protocol | This proposed ADR, assigned experiment owner, frozen pilot questions | Maintainers review the evaluation scope |
| 1: experimental collector | Optional collector, manifest, deterministic tests, private pilot evidence | Acquisition owner; E1/E2 review; clearly marked experimental |
| 2: supported HTTP integration | Selected implementation, versioned protocol/API, provenance, installation and support matrix | Maintainers plus acquisition/release reviewers; E3/E5/E6 and exact-candidate gates |
| 3: browser experiment | Patchright implementation compared with current Chromium | Browser/export reviewers; E4 and applicable lifecycle/resource tests |
| 4: supported browser integration | Qualified optional adapter and distribution | Maintainers plus browser/release reviewers; separate recorded promotion decision |

Roles identify responsibilities, not assigned individuals or promised dates.
Assign actual owners before each stage. The current release can proceed
independently. Do not enable an untested profile or platform merely because the
upstream dependency supports it.

Rollback disables or removes the optional implementation while preserving the
native default and replayable evidence. Keep historical profile/version
identities and comparison reports. Do not silently substitute a different
backend mid-run or reinterpret earlier results after an upgrade. A vulnerable
or incompatible optional dependency may require suspending that capability;
ordinary native/offline operation should remain independent.

When experiments finish, append a dated outcome with protocol/report links,
candidate identities, benefits, adverse findings, support limits, and the
maintainer decision. Update this ADR's status and the index. A material change
to default behavior, evidence meaning, or the chosen architecture should be
recorded in a superseding ADR.

## Open questions and review triggers

Resolve before the relevant promotion:

- Which actual native failure categories justify a second client, and which
  are better addressed through existing timeout, encoding, or acquisition work?
- Does curl_cffi provide enough value to justify a supported helper, or can a
  Go-native implementation deliver the same useful observations with lower
  total maintenance cost?
- What cookie, connection-reuse, TLS-resumption, and header policy best supports
  reproducible per-profile probes? Which profile revisions will be supported?
- Can each implementation account for hidden native/protocol exchanges and
  enforce its declared pre-buffer limits? What narrower capabilities are needed
  if it cannot?
- What are the exact helper framing, capability-negotiation, error, hashing,
  and provenance schemas? How are repeated target occurrences joined reliably?
- What minimum gain, uncertainty, and maximum extra cost justify each intended
  workflow? How large and representative must the confirmation panel be?
- Does Patchright add capture utility under the existing sandbox/scope/export
  restrictions beyond the current Chromium implementation?
- Who owns dependency/profile/browser updates, native-platform qualification,
  security response, and support of the optional distributions?
- Is any future browser-network fingerprinting feature justified? If so, what
  separate evidence model and compatibility decision would it require?

Revisit on experimental evidence, an upstream API or browser-version change,
new supported platforms, a dependency security finding, a scope/export failure,
profile-driven detection regressions, or a proposal to change defaults. Merely
adding more profiles or achieving HTTP 200 is not a promotion trigger.

## Sources and evidence record

Sources were reviewed on **2026-10-30**. Repository links below pin the analyzed
commit. curl_cffi code links use `v0.17.0`; the Patchright network-patch link pins
the reviewed driver commit, which is not asserted to identify every published
package build. Upstream documentation is mutable. Freeze full package, native
library, driver, browser, and profile identities for actual experiments.

### wafmeow source and contracts

- [Configuration and injected-client contract][r-config]
- [Scope, request, pacing, and exchange admission][r-acquisition]
- [HTTP headers, response retention, and decoding][r-http]
- [Probe construction][r-probes]
- [Result construction and browser scheduling][r-runner]
- [Classifier and generic detection][r-classifier]
- [Native capture format and importer limits][r-capture]
- [Bounded native decoding][r-capture-decode]
- [Evidence representation][r-evidence] and [availability semantics][r-availability]
- [Browser guide][r-browser-guide] and [native process ownership][r-browser-runtime]
- [Library compatibility][r-library], [operations][r-operations], and [release policy][r-releases]
- [Published 2,000-target benchmark and limitations][r-benchmarks]

### Upstream projects and alternatives

- [curl_cffi project][c-project], [reviewed release][c-release], and [installation/API guide][c-start]
- [Supported profiles][c-targets], [impersonation limitations][c-impersonation], and [profile updates][c-fingerprints]
- [Session defaults][c-session], [request normalization/options][c-utils], and [response history][c-models]
- [curl_cffi license][c-license], [curl-impersonate license][c-native-license], and [native notice collection][c-notices]
- [Patchright driver][p-project], [Python guidance][p-python], and [known limitations][p-bugs]
- [Conditional HTML/CSP instrumentation][p-network]
- [Playwright networking][p-network-docs], [routing limits][p-routing], [launch configuration][p-launch], and [browser versioning][p-browsers]
- [Patchright license][p-license], [Playwright notice][p-notice], and [Chromium license][p-chromium-license]
- [uTLS scope][a-utls] and [Go TLS-Client alternative][a-tls-client]

[r-config]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/options.go
[r-acquisition]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/acquisition.go
[r-http]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/http.go
[r-probes]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/request.go
[r-runner]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/runner.go
[r-classifier]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/identify.go
[r-capture]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/capture.go
[r-capture-decode]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/capture_decode.go
[r-evidence]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/evidence.go
[r-availability]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/pkg/wafme0w/availability.go
[r-browser-guide]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/docs/browser.md
[r-browser-runtime]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/internal/browserruntime/runtime_linux.go
[r-library]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/docs/library.md
[r-operations]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/docs/operations.md
[r-releases]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/docs/releases.md
[r-benchmarks]: https://github.com/Lu1sDV/wafmeow/blob/5a1866d6e5021fddf5972d4a6d3c020ff08538b1/docs/benchmarks.md
[c-project]: https://github.com/lexiforest/curl_cffi
[c-release]: https://github.com/lexiforest/curl_cffi/releases/tag/v0.17.0
[c-start]: https://curl-cffi.readthedocs.io/en/latest/quick_start.html
[c-targets]: https://curl-cffi.readthedocs.io/en/latest/impersonate/targets.html
[c-impersonation]: https://curl-cffi.readthedocs.io/en/latest/impersonate/faq.html
[c-fingerprints]: https://curl-cffi.readthedocs.io/en/latest/fingerprints.html
[c-session]: https://github.com/lexiforest/curl_cffi/blob/v0.17.0/curl_cffi/requests/session.py
[c-utils]: https://github.com/lexiforest/curl_cffi/blob/v0.17.0/curl_cffi/requests/utils.py
[c-models]: https://github.com/lexiforest/curl_cffi/blob/v0.17.0/curl_cffi/requests/models.py
[c-license]: https://github.com/lexiforest/curl_cffi/blob/v0.17.0/LICENSE
[c-native-license]: https://github.com/lexiforest/curl-impersonate/blob/main/LICENSE
[c-notices]: https://github.com/lexiforest/curl-impersonate/blob/main/cmake/CollectLicenses.cmake.in
[p-project]: https://github.com/Kaliiiiiiiiii-Vinyzu/patchright
[p-python]: https://github.com/Kaliiiiiiiiii-Vinyzu/patchright-python
[p-bugs]: https://github.com/Kaliiiiiiiiii-Vinyzu/patchright/issues/30
[p-network]: https://github.com/Kaliiiiiiiiii-Vinyzu/patchright/blob/e2876b7bc0bef67b38164794b3108eadbc2eb647/driver_patches/crNetworkManagerPatch.ts
[p-network-docs]: https://playwright.dev/docs/network
[p-routing]: https://playwright.dev/docs/api/class-browsercontext#browser-context-route
[p-launch]: https://playwright.dev/docs/api/class-browsertype#browser-type-launch-option-chromium-sandbox
[p-browsers]: https://playwright.dev/docs/browsers
[p-license]: https://github.com/Kaliiiiiiiiii-Vinyzu/patchright/blob/main/LICENSE
[p-notice]: https://github.com/microsoft/playwright/blob/main/NOTICE
[p-chromium-license]: https://chromium.googlesource.com/chromium/src/+/main/LICENSE
[a-utls]: https://github.com/refraction-networking/utls
[a-tls-client]: https://github.com/bogdanfinn/tls-client
