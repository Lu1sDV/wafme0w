# Go library

[Quick start](../README.md) · [API reference](https://pkg.go.dev/github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w)

Match an already captured response without sending any requests:
```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w"
)

func main() {
	responses := []wafme0w.Evidence{{
		Role: "Normal", StatusCode: 403, Reason: "Forbidden",
		Body: []byte("Blocked by Example WAF"),
	}}
	wafs := []wafme0w.WAF{{
		Name: "Example WAF",
		Schemas: []wafme0w.Scheme{{
			FingerPrints: []wafme0w.FingerPrint{{
				Type: "Content", Pattern: "(?i)blocked by example waf",
			}},
		}},
	}}
	engine, err := wafme0w.Compile(wafs)
	if err != nil {
		log.Fatal(err)
	}
	outcome := engine.Classify(responses)
	if err := json.NewEncoder(os.Stdout).Encode(outcome); err != nil {
		log.Fatal(err)
	}
}

```

## Ownership and streaming

`Compile` owns its rules; an `Engine` is safe for concurrent classification.
`Classify` borrows evidence bodies read-only until it returns and does not retain
them. Callers must not mutate evidence during a call.

`Run` performs bounded live acquisition and emits serially in completion order.
`RunCaptured` performs no network access and emits serially in input order.
Readers, injected clients/transports, and writers remain caller-owned. Blocking
input needs `Config.CancelInput` or another caller-provided wakeup; callbacks and
transports must honor cancellation and return.

## v2 evidence API

The module path is now `github.com/Lu1sDV/wafme0w/v2`. Import-path migration is
intentional: adding availability/provenance fields to exported structs can break
external positional literals. Use keyed literals. Existing `Run`, `RunCaptured`,
`Classify` and writer signatures remain; there are no legacy aliases.

`Evidence.Availability` and `EvidenceSummary.Availability` are optional
`*EvidenceAvailability` values containing `Status`, `Headers`, `Reason`, and
`Body` channel states. Missing or JSON-null availability retains legacy behavior,
including its caller assertion that valid-status observations have complete
metadata and, absent errors/truncation, complete body evidence. It is not proof
that omitted evidence was collected.

Explicit availability must populate every channel. Status/reason accept
`ChannelComplete` or `ChannelUnavailable`; headers additionally accept
`ChannelIncomplete`; body additionally accepts `ChannelIncomplete` and
`ChannelUnknown`. A complete empty channel is observed, unlike an unavailable
one. Empty, missing, or null channel members are invalid. Contradictory or
invalid states are rejected by capture decoding; `Classify` returns
`Failed/invalid_evidence`, and `GenericDetect` makes no conclusion for invalid
explicit input. JSON decoding of `Evidence` rejects unknown fields, repeated
availability objects, and repeated channel members (including casing variants),
rather than merging them into earlier complete values. A single absent or null
availability object still preserves legacy behavior. Summary availability is
copied, not aliased.

Partial intact headers/cookies can establish positives; absence remains unknown.
Content predicates require complete bodies, even when an unknown/truncated
prefix contains a matching literal. Classification completeness is relative to
the catalogue, not an assertion that all channels were acquired.

For ProjectDiscovery httpx exports:

```go
err := wafme0w.RunHTTPXCaptured(ctx, engine, reader, config,
    wafme0w.HTTPXImportOptions{ResponseEncoding: wafme0w.HTTPXBase64}, emit)
```

The zero-value options select text; `HTTPXText` and `HTTPXBase64` are explicit
choices, never detection heuristics. Invalid encoding and incompatible browser
configuration fail before reading. The runner establishes passive mode and uses
the same bounded, serial, input-order and caller-ownership contract as
`RunCaptured`. Callback errors stop logical emission; buffered input may read
ahead. Imported records never invoke `Config.Client` or open upstream file paths.
`Result.Provenance.Import` records compatibility profile and source information,
not inferred producer identity. See [import policy and limits](usage.md#httpx-response-import).

Result JSON remains schema 1 with optional nested import/availability metadata.
CSV columns and TXT keys remain unchanged; native/live output omits the new
metadata when unused. Go module major versions and JSON schema versions are
separate contracts. Subsequent incompatible documented API/schema changes require
appropriate versioning. See [CLI limits](usage.md#inputs-and-limits) and
[browser capture](browser.md) for the remaining ownership and acquisition rules.
