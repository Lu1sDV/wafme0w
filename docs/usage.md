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

## httpx response import

`--input -` explicitly selects target stdin, even when terminal auto-detection
does not identify a pipe. A literal file named `-` is available as `./-`.
Supply one undecorated URL per line; do not append httpx status/title/probe
annotations. Invalid annotated input receives a format hint, never silent repair.
Existing scheme-less target support and URI normalization remain unchanged.

For a continuing upstream URL feed:

```sh
httpx -stream -silent < authorized-hosts.txt |
  wafme0w --input - --jsonl --silent
```

This performs new wafme0w requests. Each network-producing stage has its own
rate/concurrency budgets; one stage's limit is not a pipeline-wide limit.
`--silent` alone is not a URL output selector.

To reuse responses instead, select offline evidence and the explicit format:

```sh
httpx -l authorized-hosts.txt -silent -json -irr -probe -rstr 1048576 -rsts 1048576 |
  wafme0w --evidence - --evidence-format httpx --jsonl --silent
```

The compatibility profile is **httpx v1.12.0**, not a detected producer version.
Native captures remain the default and still reject unknown fields. The importer
tolerates unrelated upstream fields but rejects malformed JSON, duplicate
consumed fields and incorrect consumed types. These input errors stop the stream
with exit 1; earlier JSONL remains visible and a previous named report is preserved.
Valid records with upstream failures or unusable channels still produce results.

Encoding is declared, never detected. For base64 exports:

```sh
httpx -l authorized-hosts.txt -silent -json -irrb -no-decode -probe \
  -rstr 1048576 -rsts 1398104 |
  wafme0w --evidence - --evidence-format httpx \
    --httpx-response-encoding base64 --jsonl --silent
```

Do not combine that producer invocation with `-irr` or DSL settings that force
httpx's text-export branch. The pinned producer caps `body` after encoding;
invalid/cut base64 is diagnosed, not salvaged. Its default read/save sizes are
50mb, larger than the importer's 16 MiB serialized-record limit. The recipes cap
selected body exports; oversized unrelated fields can still exceed the record
limit. No cap or encoding establishes body completeness.
Base64 padding must terminate the entire field; concatenated separately padded
values are rejected even when they cross a streaming decoder's read boundary.

### Evidence and attribution

| Channel | Imported interpretation |
| --- | --- |
| Status | Valid explicit status is usable; a valid whole dump supplies omitted/null/zero status; conflicting statuses remain unavailable |
| Reconstructed `raw_header` | Intact retained values can match; absence remains unknown |
| Normalized `header` only | Unavailable for named and generic matching; names/cookie boundaries cannot be reconstructed |
| Reason | Unavailable; reconstructed reason phrases are not trusted as observed |
| Body supplied, including empty | Completeness unknown; **no content predicates run** |
| Body omitted/null/invalid encoding | Unavailable |
| Body beyond local decoded limit | Known incomplete; no prefix matching |

Repeated headers and Set-Cookie boundaries are preserved. Reconstructed framing
fields (`Content-Length`, `Transfer-Encoding`, `Trailer`, `Connection`) are
excluded. Text values containing U+FFFD are withheld because original bytes
cannot be established; base64 bytes do not inherit that text-only ambiguity.
The producer's special 100–103 header dump is unsupported and diagnosed.
An exact empty chunk terminator emitted by the producer's reconstructed
`Transfer-Encoding: chunked` dump is accepted (including bodyless 304 responses).
Other trailing nonblank material or another response block makes headers
unavailable rather than silently selecting the first response.
The importer never reads paths or fetches URLs mentioned in upstream records.
Upstream technology/CDN labels never become wafme0w matches.

Each nonblank record is one independent Normal observation. Duplicates stay
separate, in input order. Requested `url` and original `input` remain distinct;
`EffectiveURL` is populated only from supplied `final_url`, never Location or a
guessed destination. Import provenance records occurrence, input line, declared
encoding, compatibility profile, limitations and upstream result-construction
timestamp—not request-start time. No bodies or request dumps enter results.
Offline HTTP(S) attribution preserves producer fragments, Unicode hosts and
userinfo without changing the stricter live-request validator. URLs containing
credentials remain sensitive in reports and journals; they are not fetched.

Classification completeness is catalogue-relative. Human output therefore
shows **classification** plus independent channel states for explicit evidence,
including under `--no-warning`. Named matches remain possible with unknown bodies.
This profile always has import limitations; `--strict` exits 2 even if all relevant
rules resolve. Do not interpret an empty match array as a negative finding.
Full-body matching requires a native capture whose producer actually knows the
body is complete, not an `--assume-complete` override.

### Limits and downstream use

Imported records are bounded before decoding (16 MiB). Header blocks use
`--max-response-header-bytes` (default 64 KiB), at most 4,096 values; overflow
discards the entire header channel while preserving independent status. Body
inspection uses `--max-body-bytes` (default 1 MiB), without retaining unusable
body copies. Required identities must be shorter than 64 KiB. Optional input
metadata is capped at 64 KiB, timestamp at 128 bytes and upstream error at 1,024
bytes; omission/shortening is diagnosed.

`--max-target-evidence-bytes` charges imported identity strings first, whole
headers next, then optional source metadata. String accounting includes 16-byte
descriptors; each header includes 32 bytes plus its name/value bytes. An identity
that cannot fit fails the record; a header set that cannot fit becomes unavailable.
Fixed state, catalogue references and bounded diagnostics are separate overhead;
this is not an RSS cap. Native capture limits remain unchanged.

For JSON URL extraction (new acquisition, not reuse):

```sh
httpx -l authorized-hosts.txt -silent -json |
  jq --unbuffered -r 'select(.failed != true) | .url // empty' |
  wafme0w --jsonl --silent
```

For a reverse pipeline selecting named matches:

```sh
wafme0w --input urls.txt --jsonl --silent |
  jq --unbuffered -r 'select(((.outcome.matches // []) | length) > 0) | .target' |
  httpx -stream -silent -status-code
```

Use shell `pipefail` to include upstream process failures. Even `httpx -probe`
does not emit every possible failed attempt; no importer can count absent records.
Avoid upstream filters that discard challenge/block responses.

### Reproduce the producer boundary check

Install httpx separately; it is not a wafme0w runtime dependency:

```sh
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
go build -o wafme0w ./cmd/wafme0w
python3 tools/httpx_smoke.py --binary ./wafme0w --httpx "$(go env GOPATH)/bin/httpx"
```

The Linux smoke requires `strace` and GNU `time`, runs only owned loopback fixtures, verifies
text/base64 attribution and strict outcomes, traces the importer for Internet
network attempts, and checks 50,000 independent records with incremental validation
and child peak-RSS measurements against a smaller run. Frozen real-producer
fixtures and their invocation/hash manifest live under
`pkg/wafme0w/testdata/httpx-v1.12.0/`; they are synthetic conformance evidence,
not real-world detector-accuracy labels.

For the CLI usage matrix, supply each installed producer version explicitly:

```sh
python3 tools/httpx_usage_matrix.py --binary ./wafme0w \
  --httpx /path/to/httpx-v1.9.0 --httpx /path/to/httpx-v1.12.0 \
  --output /new/usage-matrix-results
```

This Linux-only matrix exercises real URL pipelines, native/text/base64 imports,
producer field exclusion, fragments and chunked responses, all report formats,
journals, atomic failures, file aliases, pre-EOF publication, blocked-input and
blocked-output signals, early downstream closure and backpressure. It retains
per-case commands, input/output and assertions in `report.json`; a failed case
returns nonzero. Targets are owned loopback fixtures, not public sites, and
upstream omissions are never treated as negative detections.

## Human results and final overview

Without `--jsonl` or `--silent`, results stream in completion order as compact
Signal reports. Saved captures retain input order. Each product lists **matched
on** observation numbers, request roles and HTTP statuses from its actual
fingerprint evidence. Numbers start at 1 for each target and identify observations,
not wire-request attempts or retries. Live probes retain their final response and
redirect-chain metadata in one observation; followed redirects do not receive
separate numbers. A match does not prove that a probe triggered blocking.
The debug and JSON evidence indexes remain zero-based.

| Label | Meaning |
| --- | --- |
| `WAF MATCH` (red) | A named fingerprint matched; HTTP evidence may still be incomplete |
| `NO WAF MATCH` (green) | Complete evaluation with no named match, unusual response signal or HTTP diagnostic—not proof of WAF absence |
| `INCOMPLETE` (amber) | No named match and insufficient evidence for a complete evaluation |
| `REVIEW` (amber) | Complete evaluation with an unusual response signal or HTTP diagnostic |
| `ERROR` (red) | Target evaluation failed |

HTTP completeness is shown separately, including amber incomplete evidence on
matched targets. Browser outcomes and artifact failures remain separate from HTTP.
No latency, byte count or confidence is inferred from unavailable metadata.

At scan end, stderr receives a disjoint outcome overview, separate HTTP/browser
totals, and a full URL/result/evidence table including supporting observation
numbers. URL rows retain completion order (input order for captures); no targets
are silently omitted or abbreviated. Input/acquisition failures label the available
tables partial. Cancellation exits 130 and may stop console output immediately;
a report file already atomically published before final replay remains published.
Human-mode table rows use a private temporary file, removed on normal/error exits,
so replay does not retain the whole scan in memory. Large scans produce large
tables; use `--jsonl` for automation rather than parsing human layout.
On Unix, cancellation also interrupts blocked CLI pipe outputs. Windows checks
cancellation between writes but cannot interrupt an already blocked synchronous
output write. Library/test writers remain caller-owned.

JSONL stdout and JSON/JSONL/CSV/TXT report files retain their existing schemas.
`--jsonl` prints only the overview to stderr, not the URL table. `--silent`
suppresses human scan output; `--no-warning` hides diagnostic prose but preserves
outcome and completeness. Color is disabled for redirected output, `NO_COLOR`,
`TERM=dumb`, or `--no-colors`. Diagnostics are plain text on stderr.

### Certificate verification failures

A TLS verification error means that request could not provide an accepted HTTP
response. Other observations may still supply usable evidence or a named match;
the CLI preserves them and shows the original cause. Recognized certificate
causes also receive targeted guidance: inspect the trust chain, correct the
hostname/SAN, or check validity dates and the scanner clock.

For an authorized private-CA target on Linux, supply an approved, maintained PEM
trust bundle:

```sh
SSL_CERT_FILE=/path/to/approved-ca-bundle.pem \
  ./wafme0w --target https://internal.example --baseline
```

This replaces Go's default certificate-file location; do not blindly trust a
certificate fetched from the failing endpoint. Expired or wrong-host certificates
still require correction. The CLI does not disable verification, downgrade HTTPS,
or retry a deterministically invalid certificate.

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
