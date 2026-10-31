# ADR 0002: Reuse HTTP/1 connections between a target's probes

[ADR index](README.md) · [Usage](../docs/usage.md) · [Benchmarks](../docs/benchmarks.md)

| Field | Value |
| --- | --- |
| Status | **Accepted** |
| Recorded | 2026-10-30 |
| Decision owner | wafmeow maintainers |
| Implementation | The owned transport keeps verified HTTP/1 connections alive between a target's probes. Transparent transport retries are counted against `--max-requests` and request pacing; a retry that would exceed either limit aborts the probe instead of being sent. |
| Validation | Package and race tests, the owned loopback acquisition benchmark, and an authorized Tranco sample comparison at one target worker. Measurements are recorded in [benchmarks](../docs/benchmarks.md#connection-reuse-comparison). |
| Review point | Reviewed captures or live comparisons showing changed evidence completeness or named/generic findings attributable to connection reuse, or unexpected `request_budget` diagnostics under default limits. |
| Supersedes / superseded by | None |

> **Terminology note:** The active scan called *full* in these historical
> measurements is now called `--deep`. Its request behavior is unchanged.

## Context

At one target worker, full mode was slower than stock wafw00f 2.4.2 on the same
500-target Tranco sample (951.9 s versus 878.2 s, one observation per cell). Fast
mode, which issues three probes concurrently, completed the same sample in
409.4 s. Probe tracing on 30 targets at one worker showed a median 238 ms per
probe, of which a median 111 ms was a fresh TCP connect plus TLS handshake; the
remainder was request wait, with body reads negligible. The owned transport
deliberately disabled keep-alive so a transparent retry could not escape the
request budget or pacing.

## Decision

Reuse verified HTTP/1 connections between probes to the same origin. Keep
HTTP/2 disabled, certificate verification enabled, and the run-local TLS session
cache. Make transparent retries visible: every `httptrace.GetConn` attempt after
the first is charged to the target request budget and passes through the same
global and per-origin pacing admissions as a first attempt. If the budget is
exhausted, cancel that probe and report `request_budget`; do not send the retry.
Cancellation alone can race with selecting another idle connection. The owned
dialer therefore wraps sockets with a write guard: `GotConn` records a refusal
before HTTP/1 can enqueue a write, and the wrapper rejects that write without
sending bytes. The transport retains ownership of connection closure. TLS
handshakes and verification remain in the standard transport, above the guard.
An owned clone with a custom TLS dialer retains fresh connections because that
dialer does not expose a socket the runner can safely wrap below TLS.
Close run-owned idle connections when `Run` returns; caller-supplied transports
remain caller-owned and are neither inspected nor closed.

## Alternatives considered

- **Keep fresh connections and raise the default probe concurrency.** This
  reduces wall time but increases simultaneous connections to one origin and
  changes the documented default request cadence. `--probe-concurrency` remains
  the explicit control.
- **Enable HTTP/2 multiplexing.** It would remove per-probe handshakes but
  changes the TLS/HTTP fingerprint surface and stream/retry accounting.
- **Pipeline HTTP/1.1 requests or implement a custom connection pool.** Both
  move response framing and retry behavior outside the standard library, with
  more correctness risk than the measured gain justifies.
- **Accept retries outside the budget.** This would weaken the documented
  request-budget and pacing contract.

## Consequences

- A reachable target typically pays one connection setup for its probe sequence
  instead of one per probe. In the recorded sample, full mode at one worker changed
  from slower than wafw00f to faster; see the measurements.
- Servers that close idle connections can cause one retry per probe. With the
  default 54-request budget and nine probes, retries fit; a caller setting
  `MaxRequests` equal to the probe count can now see `request_budget` where a
  fresh connection might have succeeded. This is the intended strict-budget
  behavior, not a hidden replay.
- Classifier behavior and evidence fields are unchanged; acquisition evidence
  still records one observation per probe role.
- Reuse changes the connection-level request pattern seen by an origin. Live
  detection differences attributable to that pattern remain a review trigger,
  not a claimed property of this decision.

## Evidence

The comparison method, sample identity, observed timings, detection counts, and
limitations are recorded in [benchmarks](../docs/benchmarks.md#connection-reuse-comparison).
At one worker, the 500-target medians were 580.9 s with reuse and 874.6 s for
stock wafw00f 2.4.2; a paired simultaneous run on 100 shared targets took
119.7 s with reuse and 198.1 s with fresh connections. The per-probe trace is a
local diagnostic, not a throughput claim: it used one worker and a short
authorized sample, and network state changed between runs.
