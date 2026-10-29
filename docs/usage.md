# CLI usage

[Quick start](../README.md) · [Operations](operations.md) · [Browser capture](browser.md)

Inspect the CLI or list the bundled catalogue without sending requests:

```sh
wafme0w --help
wafme0w --silent --list --no-colors
```

### Collection modes

| Mode | Network behavior |
| --- | --- |
| Default | Up to nine selected active requests, before redirects; serial after the normal request unless `--probe-concurrency` is raised |
| `--fast` | Three selected active requests launched without a fixed stagger; fewer requests, **not passive** or a latency guarantee |
| `--baseline` | One normal request, subject to redirect and request budgets |

## Offline captures

From the repository root after building:

```sh
./wafme0w --evidence assets/demo/captures.jsonl --jsonl
```

No network requests. The synthetic examples demonstrate a match, a clean response,
and incomplete evidence. [Captures](../assets/demo/captures.jsonl) · [Demo recording](../assets/demo/demo.cast).

## Request headers

Use `-H` / `--header` to add comma-separated `Name: value` entries. Names are case-insensitive: later entries and repeated flags replace earlier values and built-in defaults, including `Origin` and `User-Agent`.

```sh
wafme0w --target http://127.0.0.1:8080 --baseline \
  -H 'Origin: https://example.test, User-Agent: my-client' \
  --header 'X-Tag: demo, "Accept: text/html, application/json"'
```

CSV-quote the **whole entry** when its value contains a comma; double embedded quotes inside a quoted entry. A quoted entry cannot be the **first** field: a value beginning with `"` is treated as one fully quoted argument and rejected. `-H 'User-Agent:'` suppresses the wire User-Agent. An explicit User-Agent also overrides the no-UA request's default.

Overrides apply to every selected request.

## Inputs and limits

| Setting | Behavior |
| --- | --- |
| URL input precedence | Explicit `--input` or `--target` overrides stdin; those flags are mutually exclusive; blank lines ignored |
| Target line size | Go's 64 KiB scanner token limit |
| Catalogue size | At most 8 MiB; one JSON array with known fields and valid HTTP header names |
| Target concurrency | `--concurrency` defaults to 20 and must be positive |
| Full-mode probe concurrency | `--probe-concurrency` defaults to 1; values 2..8 run active probes concurrently after the normal response succeeds |
| Response body size | `--max-body-bytes` defaults to 1,048,576 decoded bytes and must be positive |
| Response header size | `--max-response-header-bytes` defaults to 65,536 bytes; 0 selects that default |
| Retained HTTP evidence | `--max-target-evidence-bytes` defaults to 16,777,216 bytes per target across all probes; 0 selects that default |
| Request / target deadlines | `--request-timeout` defaults to 5s; `--target-timeout` to 30s |
| Requests per target | `--max-requests` defaults to 54, including redirects |
| Globally in-flight requests | `--max-connections` defaults to 0, following `--concurrency` (20 unless changed). Slots include response-body reads |
| Redirect limit | `--max-redirects` defaults to 5 per request; 0 follows none |

Bodies are bounded after gzip/deflate decoding. Unsupported encodings, truncation and read errors retain usable response metadata without treating unavailable content as a clean negative. The header option is `-H` / `--header` (singular); the old `--headers` spelling remains unsupported.

Header/evidence limits reject negative values. Owned transports enforce the
header limit while parsing; injected library transports retain responsibility
for their own parsing allocations, but oversized parsed headers are rejected
before redirects and retention. Header sets are kept whole or marked unavailable,
never truncated into a misleading clean negative. Exhausted body/evidence budgets
retain only usable evidence and emit diagnostics.

The target budget counts retained bodies, header strings and descriptors, status
reasons, and request/effective/redirect URLs. Fixed observation fields and bounded
diagnostics are additional overhead. Transport buffers, temporary allocations,
classifier indexes, and Chromium are separate: this is **not a process RSS cap**.
Size worker concurrency and container memory together. Offline JSONL retains its
separate record/body limits; live acquisition budgets do not reinterpret captures.

Offline capture classification uses at most `min(--concurrency, GOMAXPROCS)`
workers. Records remain bounded by a 32 MiB raw in-flight byte budget and emit in
input order; valid records before an invalid line are emitted before its error.

`--journal-batch-size` defaults to 1, preserving a sync per result. Larger values
batch up to 256 results and 1 MiB of encoded records; a partial batch syncs within
25 ms. Results reach reports and console output only after their journal batch is
synced. Batching can improve journal throughput at the cost of delaying each
result until the batch is durable.
Saved HTTP reasons and header values reject C0 controls other than HTAB and reject
DEL. TXT renders invisible formatting characters visibly; JSON/JSONL/CSV preserve
their original values.

Output failures, including an unwritable stdout for help or version output, exit with status 1 and report the error on stderr.
On Linux, piped target input and `--evidence=-` remain cancellable with SIGINT or SIGTERM even while the producer keeps its pipe open; cancellation exits 130 without replacing the previous atomic report.
Stdin is a single-consumer stream. If Linux cannot reopen an inherited pipe, the
CLI temporarily sets its shared nonblocking flag and restores it on close;
concurrent readers of that same pipe are not isolated.

The built-in HTTP transport opens a fresh HTTP/1 connection for each request and
uses a bounded, run-local TLS session cache. TLS certificate verification remains
enabled. Connection reuse and HTTP/2 are disabled to prevent transparent retries
from bypassing `--max-requests` and request pacing. TLS session resumption can
reduce handshake cost when the origin supports it, without reusing HTTP connections.
Library callers supplying a transport (including a replacement
`http.DefaultTransport`) own any retries or network effects inside its
`RoundTrip` calls; the runner cannot enforce a wire-request ceiling inside that
opaque implementation.
