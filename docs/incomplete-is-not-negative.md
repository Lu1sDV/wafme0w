# An incomplete WAF fingerprinting result is not a negative

A fingerprinting tool returns no product names. Can you record “no WAF” and move on? Not safely. There are two separate questions: did any known fingerprint match, and could the tool resolve all the fingerprint checks from the supplied evidence?

[wafme0w](https://github.com/Lu1sDV/wafme0w) exposes those questions separately. Its `outcome.matches` lists named matches; `outcome.state` describes evaluation completeness. An empty match list is not enough to interpret the result.

## Read the state before drawing a conclusion

The [result types](../pkg/wafme0w/evidence.go) define three states:

| State | Meaning | Practical response |
| --- | --- | --- |
| `complete` | Every product's fingerprint decision was resolved from the supplied observations. | Report the matches, or “no known fingerprint matched this evidence.” |
| `incomplete` | At least one product remains unresolved. Other products may already have matched. | Preserve positive matches and inspect `incomplete_products` and `diagnostics`. |
| `failed` | Evaluation could not proceed in a supported way. | Inspect the diagnostic rather than treating it as a negative. |

For example, the [live runner](../pkg/wafme0w/runner.go) returns `failed` for an invalid target or a starting URL outside the configured permitted origins. Do not assume every transport failure produces this state: missing response evidence ordinarily leaves fingerprint checks **incomplete**. Malformed offline input, meanwhile, stops the invocation with an error rather than necessarily producing a `failed` result record.

“Complete” describes the catalogue's decisions over these observations, not complete knowledge of a deployment. A WAF might omit recognizable markers, expose different responses on other paths, or be absent from the catalogue. Conversely, a recognizable header or page can be copied or supplied by another component. A match identifies a fingerprint; it does not prove enforcement, blocking, or a security configuration.

## Unknown is not false

The [classifier](../pkg/wafme0w/identify.go) uses three-valued logic: a fingerprint can match, not match, or remain unknown because its evidence is unavailable.

Consider a hypothetical schema requiring both a particular header and a body marker:

- A known header mismatch makes that AND schema false, even if the body is unavailable.
- A matching header with an unavailable body leaves that AND schema unknown.
- In an OR schema, a matching header is sufficient even when the body check is unknown.

Products can also have alternative schemas: one satisfied alternative resolves that product positively. Checks can use different responses in the supplied evidence set; they are not necessarily claims about one response alone.

This explains why `incomplete` and positive matches can coexist. A header-based product can match while another product's body-based checks remain unresolved. Keep both facts. Replacing the whole result with either “detected” or “not detected” discards useful information.

## A bounded body is not necessarily a complete body

The [HTTP reader](../pkg/wafme0w/http.go) retains at most `--max-body-bytes` decoded bytes per response, then checks for another byte to detect truncation. The [default](../pkg/wafme0w/options.go) is 1 MiB. This bounds retained body data; it does not make the retained prefix a full response.

When `body_truncated`, `error_code`, or `transport_error` is set, content checks do not use that body as complete evidence. Even a visible marker in the retained prefix is not accepted as a content match from that observation. Headers, cookies, status, and reason can remain usable when valid response metadata exists.

Truncation therefore adds a diagnostic but does not mechanically force every catalogue to return `incomplete`: other known terms can settle decisions. Diagnostics and state must both survive downstream processing.

For [offline captures](../pkg/wafme0w/capture.go), the body is base64-encoded JSON data. A saved body exceeding the configured decoded limit is **rejected**, not silently shortened. The producer must accurately mark already-truncated evidence; the classifier cannot reconstruct omitted bytes or discover an unreported truncation.

## Try it without sending a request

From the repository root, with the published `wafme0w` executable on `PATH` and `jq` installed:

```sh
results=$(mktemp)
wafme0w --evidence assets/demo/captures.jsonl --jsonl > "$results"
jq '{target, state: .outcome.state,
     products: [.outcome.matches[]?.product],
     unresolved: (.outcome.incomplete_products // []),
     diagnostics: [.outcome.diagnostics[]?.code]}' "$results"
rm "$results"
```

The [demo captures](../assets/demo/captures.jsonl) are synthetic examples, not observations of deployed WAFs. Their labels are `synthetic-cloudflare`, `synthetic-clean`, and `synthetic-truncated`. Compare the state and matches together, especially for the truncated example. The command prints actual projected fields rather than a fabricated sample transcript. `--evidence` performs no network requests; capture targets are identifying labels.

## An exit code answers a different question

[`--jsonl`](../pkg/wafme0w/output.go) streams result records to stdout; the human summary goes to stderr. A normally completed invocation returns **0** even if individual results are incomplete or failed.

With `--strict`, the [CLI](../cmd/wafme0w/main.go) returns **2** after successful report publication if any result is non-complete **or has diagnostics**, including a complete result with diagnostics. It is not an “exit nonzero when a WAF matches” flag.

```sh
results=$(mktemp)
if wafme0w --evidence assets/demo/captures.jsonl --jsonl --strict > "$results"; then
  status=0
else
  status=$?
fi
printf 'CLI exit: %s\n' "$status"
jq '{target, state: .outcome.state}' "$results"
rm "$results"
```

Capturing the status directly avoids confusing it with `jq`'s pipeline exit status. Invocation errors return **1**; cancellation returns **130**. Streamed records may precede a later error, so consume both the records and the exit code. Use matches for fingerprint findings, state for unresolved decisions, and diagnostics for evidence problems—not one Boolean for all three.
