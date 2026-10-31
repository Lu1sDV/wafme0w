# CLI usage

[Quick start](../README.md) · [Operations](operations.md) · [Browser capture](browser.md)

Inspect the CLI or list the bundled catalogue without sending requests:

```sh
wafmeow --help
wafmeow --silent --list --no-colors
```

Help uses the portable `--flag value` / `--flag=value` spellings on every
supported platform. Native Windows `/flag:value` spellings remain accepted;
the option names and values have the same meaning.

## Choose input

| Source | Flags | Behavior |
| --- | --- | --- |
| Direct URLs | `--target URL` or `-t URL` | One URL per occurrence; repeat the flag for several URLs |
| URL list file | `--target-file PATH` | One URL per line; blank lines are ignored |
| URL lines on stdin | `--target-file -` | Explicitly reads stdin, including a terminal or continuing pipe |
| Saved response records | `--evidence PATH` or `--evidence -` | Offline JSONL classification; sends no requests |

The spellings `--target-file PATH`, `--input PATH`, and `-I PATH` select the same
URL-list source. Existing `--input` and `-I` commands remain supported without
deprecation warnings. Supply one spelling once: combining aliases or repeating
the file flag is an error. `--evidence` is also a single source, supplied once.
Direct targets, a target file, and evidence are mutually exclusive.

With no explicit source, piped or redirected stdin supplies URL lines. An explicit
source takes precedence over inherited stdin; the CLI does not merge sources.
A literal input file named `-` is selected with `./-`. Direct URLs require
`--target` / `-t`; the standard `--` terminates option parsing.

Each direct target must be nonblank and contain no carriage return or newline.
Repeat `--target` for separate URLs; repeated URLs remain separate occurrences.
Quote URLs containing shell metacharacters such as `&`. Scheme-less URLs use
HTTPS; specify `http://` for plain HTTP. These examples use your own local servers
or an authorized URL file:

```sh
wafmeow --target http://127.0.0.1:8080 --target http://127.0.0.1:8081 \
  --fast
wafmeow --target-file authorized-urls.txt --fast --jsonl
printf '%s\n' http://127.0.0.1:8080 |
  wafmeow --target-file - --fast --jsonl
```

Empty or multiline direct-target arguments and conflicting/repeated singular
source flags are configuration errors and exit 1. Errors within a streamed input
can occur after earlier valid results have been emitted; see [operations](operations.md).
An empty or blank-only target stream is a successful zero-target run, including
with `--strict`; a named report is replaced with its empty-result representation.
See [empty-input handling](operations.md#reports-and-durable-journals) for automation.

### Updating existing scripts

This release keeps `--input` and `-I` while making `--target-file` the primary
documented spelling. Repeated `--target` values now all run instead of retaining
only the last value. A multiline direct-target argument is rejected; supply a
file, stdin, or repeated flags instead. Repeated singular sources are rejected
instead of silently overriding earlier values.

Explicit browser modifiers need an enabled browser, explicit journal batching
needs a journal, and probe parallelism above 1 needs deep mode. Target concurrency
is limited to 1..65,536 before workers are created. The sections below describe
those dependencies and defaults. Arguments already quoted by the shell retain
their literal contents; headers use the documented CSV quoting rules.

## Collection modes

| Goal | Mode | Network behavior |
| --- | --- | --- |
| Quick active fingerprinting | `--fast` | Three selected request types: normal, no-user-agent and combined; launched without a fixed stagger |
| Broader active probing | `--deep` (default) | Eight selected request types; serial after the normal request unless `--probe-concurrency` is raised |
| Inspect normal responses only | `--baseline` | One normal request, without active probes |
| Reuse saved responses | `--evidence FILE` | Offline classification; no network requests |

Choose `--baseline` when you want to inspect ordinary responses without active
probes. It still classifies headers, cookies and usable bodies, and can find
fingerprints already present there. It cannot expose a fingerprint that appears
only in a response to an omitted probe. Baseline is a complete optional workflow,
not a saved comparison file or a preparation step: fast and deep already include
the normal request. All live request counts are before redirects and subject to
budgets; fast is not passive or a latency guarantee.

`--fast`, `--deep` and `--baseline` are mutually exclusive; omitting all three
selects `--deep`. Values 2..8 for `--probe-concurrency` apply only to deep mode;
fast and baseline require the default value of 1. Explicit
`--probe-concurrency 1` is also valid. `--evidence` cannot be combined with any
live mode flag.

In result provenance, the default live `scan_mode` is now `"deep"` instead of
`"active"`; `"fast"`, `"baseline"` and offline `"passive"` are unchanged.
Result JSON remains schema 1. Consumers of historical and current reports need
the [mode-value migration guidance](library.md#versioning).

### Active probe payloads

Deep mode sends one normal request, one no-user-agent request, one random-path
request, and five active probes: separate XSS, XXE and LFI probes (`p`), one
combined probe (`l`, `l2`, `d`, `v`, `c`, `r`, `h`), and a JNDI canary (`p`).
`--fast` sends only the normal, no-user-agent and combined requests. The JNDI
canary and the standalone XSS, XXE and LFI requests are never sent in fast mode,
but the combined request still carries XSS, LFI and the SQLi/XSS polyglot in its
query: fast mode omits separate probe requests, not those payload values.
`--baseline` sends no probes at all.

SQL-injection and command-injection payloads travel inside the combined probe,
because one request per payload multiplied the requests a target sees. A
blocking response to that probe is recorded against `CentralAttack`;
acquisition cannot tell which of its payloads triggered the block. Removing the
standalone SQL-injection and command-injection probes therefore trades
diagnostic precision for fewer requests, and it is not evidence of equivalent
detection coverage. Use saved captures or an authorized comparison run when you
need to know which payload a specific target rejects.

The JNDI canary is `${jndi:ldap://127.0.0.1:1/a}`. It contacts no external
callback endpoint, but a vulnerable target can still attempt an LDAP connection
to port 1 on its own loopback interface. Active mode, including this probe, has
target-side effects; use it only on systems you are authorized to test.

HTTP acquisition settings such as request/target timeouts, request and connection
budgets, redirect limits and request rates apply to live requests. Supplying them
with `--evidence` does not turn offline classification into a network scan. The
HTTP acquisition settings do not establish completeness for saved responses.

Optional browser capture is enabled with `--browser navigate` or
`--browser screenshot` during a live scan. Explicit `--browser-path`,
`--browser-timeout` and `--browser-settle` require an enabled browser mode;
`--save-screenshots` requires screenshot mode. Help, catalogue listing and version
output do not require an installed browser. See [browser capture](browser.md) for
its separate dependencies, scope and resource limits.

## Offline captures

`--evidence` reads response captures, not wafmeow result reports. Native JSONL
records contain `target` and `evidence` observations with the response channels
needed for classification; see the [example captures](../assets/demo/captures.jsonl)
and [evidence contract](library.md#evidence-api). `--jsonl`, `--output` and
diagnostics journals contain results and evidence summaries, not the original
response bodies, and cannot be replayed as native captures. Use
`--evidence-format httpx` for supported httpx response exports.

From the repository root after building:

```sh
./wafmeow --evidence assets/demo/captures.jsonl --jsonl
```

No network requests. The synthetic examples demonstrate a match, a clean response,
and incomplete evidence. [Captures](../assets/demo/captures.jsonl) ·
[Gruvbox GIF](../assets/demo/tern-demo.gif) · [Cyberpunk GIF](../assets/demo/tern-demo-dark.gif) ·
[Split workflow demo](../assets/demo/tern-demo-split.gif) · [Video](../assets/demo/tern-demo.mp4) ·
[Earlier asciicast](../assets/demo/demo.cast).

Each native JSONL record is limited to 16 MiB and 64 observations. Each
observation may contain at most 4,096 header values and 4,096 redirect
destinations. Collection limits are enforced during decoding, before allocating
the first excess element. Oversized collections fail the import; they are not
silently truncated. Decoded bodies also obey `--max-body-bytes` (default 1 MiB).
The separate 32 MiB raw in-flight budget bounds queued record bytes, not total
process memory.

The Tern demo runs the real CLI: human-readable evidence, a JSONL pipeline, and
`--strict` returning exit 2 **after** saving a report containing incomplete evidence.
It uses synthetic captures only; typing and pauses are paced for readability,
not a speed or deployed-detection benchmark.

The README pairs two different jobs: human-readable evidence in `dark-cyberpunk`
on the left, JSONL processing and strict report publication in `light-gruvbox`
on the right. It uses a still frame when reduced motion is preferred.
These are two real Tern recordings composed side by side, not a per-pane theme setting.
Recording starts before either command runs, showing typing and actual output.
The evidence pane then scrolls to the results and incomplete-body warning,
followed by the summary; the full walkthrough includes all output.

To record it again, install Tern, Go, Bash, jq, and FFmpeg with the `libx264`
encoder. From the repository root, choose a fresh output directory:

```sh
tern shot assets/demo/tern-demo.txt --theme both --scale 1 \
  --out /tmp/wafmeow-demo --flat
for suffix in '' '-dark'; do
  ffmpeg -i "/tmp/wafmeow-demo/wafmeow-tern${suffix}.mp4" \
    -filter_complex '[0:v]fps=15,scale=1200:-1:flags=lanczos,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle' \
    -loop 0 "/tmp/wafmeow-demo/tern-demo${suffix}.gif"
done
tern shot assets/demo/tern-split.txt --theme dark --scale 1 \
  --out /tmp/wafmeow-demo/split --flat
ffmpeg -i /tmp/wafmeow-demo/split/human-dark.mp4 \
  -i /tmp/wafmeow-demo/split/automation-dark.mp4 \
  -filter_complex '[0:v]fps=15[l];[1:v]fps=15[r];[l][r]hstack=shortest=1,split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=3:diff_mode=rectangle' \
  -loop 0 /tmp/wafmeow-demo/tern-demo-split.gif
ffmpeg -i /tmp/wafmeow-demo/tern-demo-split.gif \
  -frames:v 1 /tmp/wafmeow-demo/tern-demo-split.png
```

The presentation script builds an isolated temporary binary and removes its
temporary captures and report when it exits. Run `bash assets/demo/tern-demo.sh`
for an interactive walkthrough without recording.

## URL pipelines

`--target-file -` explicitly selects target stdin, even when terminal auto-detection
does not identify a pipe. A literal file named `-` is available as `./-`.
Supply one undecorated URL per line; do not append httpx status/title/probe
annotations. Invalid annotated input receives a format hint, never silent repair.
Scheme-less targets use HTTPS. Specify `http://` explicitly for plain HTTP.

For a continuing upstream URL feed:

```sh
httpx -stream -silent < authorized-hosts.txt |
  wafmeow --target-file - --fast --jsonl --silent
```

This performs new wafmeow requests. Each network-producing stage has its own
rate/concurrency budgets; one stage's limit is not a pipeline-wide limit.
`--silent` alone is not a URL output selector.

## httpx response import

To reuse responses instead, select offline evidence and the explicit format:

```sh
httpx -l authorized-hosts.txt -silent -json -irr -probe -rstr 1048576 -rsts 1048576 |
  wafmeow --evidence - --evidence-format httpx --jsonl --silent
```

The compatibility profile is **httpx v1.12.0**, not a detected producer version.
Native captures are the default evidence format and reject unknown fields. The importer
ignores unrelated upstream values, including nested numeric metadata outside
floating-point range, but rejects malformed JSON, duplicate consumed fields and
incorrect consumed types. These input errors stop the stream
with exit 1; earlier JSONL remains visible and a previous named report is preserved.
Valid records with upstream failures or unusable channels still produce results.

Encoding is declared, never detected. For base64 exports:

```sh
httpx -l authorized-hosts.txt -silent -json -irrb -no-decode -probe \
  -rstr 1048576 -rsts 1398104 |
  wafmeow --evidence - --evidence-format httpx \
    --httpx-response-encoding base64 --jsonl --silent
```

Do not combine that producer invocation with `-irr` or DSL settings that force
httpx's text-export branch. The pinned producer caps `body` after encoding;
invalid/cut base64 is diagnosed, not salvaged. Its default read/save sizes are
50mb, larger than the importer's 16 MiB serialized-record limit. The recipes cap
selected body exports; oversized unrelated fields can still exceed the record
limit. No cap or encoding establishes body completeness.
Base64 padding must terminate the entire field; concatenated separately padded
values are invalid.

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
Upstream technology/CDN labels never become wafmeow matches.

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
this is not an RSS cap. These httpx-specific budgets do not replace the
[native capture limits](#offline-captures).

For JSON URL extraction (new acquisition, not reuse):

```sh
httpx -l authorized-hosts.txt -silent -json |
  jq --unbuffered -r 'select(.failed != true) | .url // empty' |
  wafmeow --target-file - --fast --jsonl --silent
```

For a reverse pipeline selecting named matches:

```sh
wafmeow --target-file urls.txt --fast --jsonl --silent |
  jq --unbuffered -r 'select(((.outcome.matches // []) | length) > 0) | .target' |
  httpx -stream -silent -status-code
```

Use shell `pipefail` to include upstream process failures. Even `httpx -probe`
does not emit every possible failed attempt; no importer can count absent records.
Avoid upstream filters that discard challenge/block responses.

### Reproduce the producer boundary check

Install httpx separately; it is not a wafmeow runtime dependency:

```sh
go install github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0
go build -o wafmeow ./cmd/wafmeow
python3 tools/httpx_smoke.py --binary ./wafmeow --httpx "$(go env GOPATH)/bin/httpx"
```

The Linux smoke requires `strace` and GNU `time`, runs only owned loopback fixtures, verifies
text/base64 attribution and strict outcomes, traces the importer for Internet
network attempts, and checks 50,000 independent records with incremental validation
and child peak-RSS measurements against a smaller run. Frozen real-producer
fixtures and their invocation/hash manifest live under
`pkg/wafmeow/testdata/httpx-v1.12.0/`; they are synthetic conformance evidence,
not real-world detector-accuracy labels.

For the CLI usage matrix, supply each installed producer version explicitly:

```sh
python3 tools/httpx_usage_matrix.py --binary ./wafmeow \
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

## Save and stream results

| Goal | Flags |
| --- | --- |
| Stream machine-readable results on stdout | `--jsonl` |
| Save a final report atomically | `--output results.json` or `-O results.json` |
| Stream and save the same run | `--jsonl --output results.csv` |
| Suppress human scan output | `--silent` together with `--jsonl` or `--output` |
| Treat incomplete or diagnosed results as a failing check | `--strict`; exit 2 after report publication |

`--output` selects a **file**, with its case-insensitive extension choosing JSON,
JSONL, CSV or TXT; other extensions select TXT. The old destination is replaced
atomically when the report is published. `--output -` creates a literal TXT file
named `-`. Use `--jsonl` for stdout. A named JSONL report is also published
atomically; `--diagnostics-journal` provides append-and-sync recording during the
run. See [report and journal behavior](operations.md#reports-and-durable-journals).
Result reports are not [response captures](#offline-captures) and cannot be fed
back to `--evidence`.

`--strict` is an evidence-quality check, not a fail-on-WAF switch. A complete
result with a named match can exit 0; an incomplete result without any match can
exit 2. A successful zero-target run also exits 0, so automation that requires
results must check their count separately.

JSONL stdout contains only result objects. The run plan, human summaries and
explicit `--debug` output use stderr. `--silent` suppresses human scan output but does not hide fatal
errors or explicitly requested debug output. `--no-warning` hides diagnostic
prose without changing result states, diagnostics in reports, or strict-mode
outcomes.

This offline example streams results and publishes a report before returning
exit 2 for the synthetic incomplete-evidence case:

```sh
wafmeow --evidence assets/demo/captures.jsonl --jsonl --silent \
  --output results.json --strict
```

## Human results and final overview

Interactive human scans show the cat climbing an orange brick wall **first**.
After the first frame, stderr shows a compact `RUN PLAN`: normally one line
with the scan mode, effective worker/parallelism counts and deadlines. Only
non-default controls (such as a rate cap, origin allowlist, report or browser)
add short settings lines. Offline plans state that no network requests are sent.
The plan omits target URLs, header values, origin values and file paths, and
`--silent` suppresses it. A custom User-Agent is noted without revealing its
value. The run plan remains on stderr, even for human scans.

The animation normally finishes in about 540 ms and runs alongside acquisition;
the first result stops it immediately, without waiting for the remaining frames.
The logo settles before any result, warning, debug line, overview or error is printed,
including when stdout and stderr share one terminal. It never hides the cursor.

The wider cat-and-brick-wall logo uses 54 columns and 13 rows, with a blank
line after the bottom course of bricks. The `wafmeow vX.Y.Z` title and
`WAF fingerprinting` subtitle are centered over the **wall**, not the cat.
Long development pseudo-versions are abbreviated with an ellipsis in this
visual header; `--version` and JSON provenance retain the complete identity.

Use `--no-animation` to keep the cat still. Animation requires ANSI-capable
interactive stdout wider than 54 columns, enough rows for the heading, art and
any shared-terminal plan, and a stable measured terminal size. Redirected
stdout, narrow or unknown-size terminals, and `TERM=dumb` use the compact
static header. Piped target input can still animate when stdout is eligible. `--no-colors` or
`NO_COLOR` gives static, escape-free output. Help, version, product listings,
`--jsonl` and `--silent` never animate. If a terminal resize is detected between
frames, startup redraws stop because terminal reflow invalidates their coordinates.

The final frame of the four-pose animation (shown without ANSI color):

```text
                              wafmeow v3.0.1
                            WAF fingerprinting

          /\_/\
        =( o.o )=
         / >^< \
     ___/       ____o+-------+-------+-------+-------+
    /   /\      /    |       |       |       |       |
   /___/  \___/      +---+-------+-------+-------+---+
   \  \  \      /    |   |       |       |       |   |
    \__\  \_/\_/     +-------+-------+-------+-------+
       \___/         |       |       |       |       |
                     +---+-------+-------+-------+---+
                     |   |       |       |       |   |
                     +-------+-------+-------+-------+

```

A CLI run plays the movement once and may end it early when a result arrives.

Without `--jsonl` or `--silent`, results stream in completion order as compact
per-target blocks. A matched product is indented below its target; supporting
observations, review signals, and HTTP completeness follow underneath it.
The HTTP line groups status counts (for example, `200×3 / 403×4 / 404`) rather
than printing eight separate probes in a long horizontal run. Repeated warnings
from different probes are grouped by reason and list their contributing roles.
When several products match, shared HTTP evidence and warnings stay at the
target level rather than being attributed to one product. In color-capable
human output, the `[ WAF MATCH ]` label stays **red**, while recognized
product names are **green** both under the target and in the end-of-run
results table; redirected output and `--no-colors` remain ANSI-free. On shared interactive
terminals, warnings appear directly beneath the result; when stdout is redirected,
stderr keeps standalone target-labeled diagnostics so messages remain attributable.
The summary is separated from the last warning by a blank line.
Saved captures retain input order. Matched observation numbers start at 1 per
target and identify observations, not wire-request attempts or retries.
Live probes retain their final response and redirect-chain metadata in one
observation; followed redirects do not receive separate numbers. Detailed
per-probe statuses and URLs remain available through `--debug` and JSONL.
A match does not prove a probe triggered blocking. The debug and JSON evidence
indexes remain zero-based.

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

Use JSONL stdout or JSON/JSONL/CSV/TXT report files for structured output.
`--jsonl` prints the run plan and overview to stderr, not the URL table. `--silent`
suppresses human scan output; `--no-warning` hides diagnostic prose but preserves
outcome and completeness. Color is disabled for redirected output, `NO_COLOR`,
`TERM=dumb`, or `--no-colors`. Diagnostics use stderr's own terminal status for
color, independently of stdout. On a shared terminal, repeated HTTP diagnostics
are grouped by reason under the result with escaped role labels. Redirected
stderr retains a standalone target-labeled warning block and separate colors.
A blank line follows the final warning group.

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
  ./wafmeow --target https://internal.example --baseline
```

This replaces Go's default certificate-file location; do not blindly trust a
certificate fetched from the failing endpoint. Expired or wrong-host certificates
still require correction. The CLI does not disable verification, downgrade HTTPS,
or retry a deterministically invalid certificate.

## Request headers

Use `-H` / `--header` once per `Name: value` entry. The flag takes inline values,
not a header-file path. Names are case-insensitive: later entries replace earlier
values and built-in defaults, including `Origin` and `User-Agent`.

```sh
wafmeow --target http://127.0.0.1:8080 --baseline \
  -H 'Origin: https://example.test' \
  -H 'User-Agent: my-client' \
  --header 'X-Tag: demo'
```

The existing comma-separated header-list syntax is also supported. When a value
contains a comma, CSV-quote the **whole `Name: value` entry**, even if it is the
first or only entry. Double embedded quotes inside a CSV-quoted entry. The outer
single quotes in these POSIX-shell examples preserve the inner CSV quotes:

```sh
wafmeow --target http://127.0.0.1:8080 --baseline \
  -H '"Accept: text/html, application/json"' \
  -H '"X-Label: say ""hello""", X-Tag: demo'
```

`-H 'User-Agent:'` suppresses the wire User-Agent. An explicit User-Agent also
overrides the no-UA request's default. Empty lists, malformed names/values, and
carriage returns or newlines are rejected.

Overrides apply to every selected request.

## Inputs and limits

| Setting | Behavior |
| --- | --- |
| URL input precedence | Explicit `--target-file` (`--input` / `-I`) or repeated `--target` (`-t`) overrides stdin; source modes are mutually exclusive; blank file/stdin lines are ignored |
| Target line size | Go's 64 KiB scanner token limit |
| Catalogue size | At most 8 MiB; one JSON array with known fields and valid HTTP header names |
| Target concurrency | `--concurrency` / `-c` accepts 1..65536; default 20 |
| Deep-mode probe concurrency | `--probe-concurrency` defaults to 1; values 2..8 run active probes concurrently after the normal response succeeds and cannot be combined with `--fast` or `--baseline` |
| Response body size | `--max-body-bytes` defaults to 1,048,576 decoded bytes and must be positive |
| Response header size | `--max-response-header-bytes` defaults to 65,536 bytes; 0 selects that default |
| Retained HTTP evidence | `--max-target-evidence-bytes` defaults to 16,777,216 bytes per target across all probes; 0 selects that default |
| Request / target deadlines | `--request-timeout` defaults to 5s; `--target-timeout` to 30s |
| Requests per target | `--max-requests` defaults to 54, including redirects |
| Globally in-flight requests | `--max-connections` defaults to 0, following the larger of `--concurrency` and `--probe-concurrency`. Slots include response-body reads |
| Redirect limit | `--max-redirects` defaults to 5 per request; 0 follows none |

### Rate and deadline tuning

`--rate` limits global HTTP requests per second; `--per-origin-rate` limits each
origin separately. Both default to 0 (no pacing), and redirects count as requests.
These limits are independent of target workers (`--concurrency`), in-flight HTTP
slots (`--max-connections`) and deep-mode probe workers (`--probe-concurrency`).
They do not limit an upstream process such as httpx.

For a conservative starting point with one target at a time and at most five
HTTP requests per second:

```sh
wafmeow --target-file authorized-urls.txt --fast --concurrency 1 --rate 5 \
  --jsonl --output results.json --strict
```

The request deadline starts before a probe waits for a local rate/connection slot
and covers its redirects and body reads. The target deadline covers the HTTP
probe set, including these waits, once a worker starts acquisition; it does not
limit time waiting for input, browser capture, or report output. Browser capture
has its own deadline. Low rates combined with many workers can therefore exhaust
HTTP deadlines while requests are still waiting locally. Start with lower
concurrency and adjust deadlines for the chosen rate and workload; a timeout
alone does not establish that the remote server was slow.

### Other limit interactions

Parallel probes are also bounded by `--max-connections`. At 0 it follows the
larger of target concurrency and probe concurrency, so raising
`--probe-concurrency` alone takes effect. On 100 Tranco targets at one worker,
probe concurrency 4 and 8 reduced deep-mode elapsed time from 113.2 s to 68.0 s
and 58.7 s with unchanged named, generic and complete counts. Lowering
`--max-body-bytes` to 102,400 saved about 3% but truncated 24 probes and reduced
complete evidence by five targets; lowering `--request-timeout` to 1 s saved
about 27% but added five incomplete targets. Keep the evidence-driven defaults
unless throughput matters more than completeness.

Bodies are bounded after gzip/deflate decoding. Responses that cannot carry a
message body, such as 204 and 304, have complete empty content regardless of
encoding metadata. For body-bearing responses, unsupported encodings, truncation
and read errors retain usable response metadata without treating unavailable
content as a clean negative. Add request headers with `-H` / `--header` (singular).

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
The concurrency ceiling of 65,536 is a validation bound. Size worker concurrency
and container memory for the actual workload and available resources. Offline
JSONL retains its separate record/body limits; live acquisition budgets do not
reinterpret captures.

Offline capture classification uses at most `min(--concurrency, GOMAXPROCS)`
workers. Records remain bounded by a 32 MiB raw in-flight byte budget and emit in
input order; valid records before an invalid line are emitted before its error.

Set `--journal-batch-size` only with `--diagnostics-journal PATH`. Its default is
1, preserving a sync per result. Larger values
batch up to 256 results and 1 MiB of encoded records; a partial batch syncs within
25 ms. Results reach reports and console output only after their journal batch is
synced. Batching can improve journal throughput at the cost of delaying each
result until the batch is durable.
Saved HTTP reasons and header values reject C0 controls other than HTAB and reject
DEL. TXT renders invisible formatting characters visibly; JSON/JSONL/CSV preserve
their original values.

Output failures, including an unwritable stdout for help or version output, exit with status 1 and report the error on stderr.
On Linux, piped stdin and named FIFO paths selected by `--target-file` (also
`--input` / `-I`), `--evidence`,
or `--fingerprints` remain cancellable with SIGINT or SIGTERM while waiting for a
producer or more data. Cancellation exits 130 without replacing the previous
atomic report. Named FIFOs wait for their producer and finish at its EOF.
Named inputs on other platforms require regular files; use stdin for streams.
Other named input types, such as devices and directories, are rejected.
Stdin is a single-consumer stream. If Linux cannot reopen an inherited pipe, the
CLI temporarily sets its shared nonblocking flag and restores it on close;
concurrent readers of that same pipe are not isolated.

The built-in HTTP transport keeps verified HTTP/1 connections alive for reuse
between a target's probes and uses a bounded, run-local TLS session cache. TLS
certificate verification remains enabled. HTTP/2 is disabled. A transparent
transport retry on a reused connection is counted against `--max-requests` and
request pacing; when either limit would be exceeded, the probe is aborted instead
of sending the retry. TLS session resumption can reduce handshake cost when the
origin supports it.
An owned clone of `http.DefaultTransport` with a custom TLS dialer uses fresh
connections to preserve the request ceiling. Library callers supplying an
explicit transport, or replacing `http.DefaultTransport` with an implementation
other than `*http.Transport`, own any retries or network effects inside its
`RoundTrip` calls; the runner cannot enforce a wire-request ceiling inside that
opaque implementation.

## Reproduce the CLI option checks

On Linux, build the CLI and choose a fresh output directory:

```sh
go build -o wafmeow ./cmd/wafmeow
python3 tools/cli_options_smoke.py --binary ./wafmeow \
  --output benchmarks/cli-options-01
```

This exercises argument parsing, source selection, literal filenames, numeric
limits, output publication and help text using synthetic saved records and
deliberately invalid target schemes. It sends no network requests. The output
records the tested binary's SHA-256, each case's stdout/stderr, and a summary;
any mismatch exits nonzero. CI runs the same checks and retains their evidence.
