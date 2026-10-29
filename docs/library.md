# Go library

[Quick start](../README.md) · [API reference](https://pkg.go.dev/github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w)

The module path is `github.com/Lu1sDV/wafme0w/v2`. Use keyed literals for exported
structs. Go module versions and result JSON schema versions are separate contracts;
see [versioning](#versioning).

## Add the module

Use Go 1.26 or newer. In your application's module, select a reviewed v2
tag or commit:

```sh
go mod init example.com/waf-client # Skip if go.mod already exists.
go get 'github.com/Lu1sDV/wafme0w/v2@<v2-tag-or-commit>'
```

Replace the placeholder with an actual revision; do not use a v1 release with
the `/v2` import path. To develop against a local source checkout instead:

```sh
go mod edit -replace github.com/Lu1sDV/wafme0w/v2=/absolute/path/to/wafme0w
go get github.com/Lu1sDV/wafme0w/v2
```

## Classify a saved response

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

## Scan authorized URLs

The library does not automatically load the CLI's embedded catalogue. Supply
your own rules or load the JSON catalogue from
[`cmd/wafme0w/resources/waf-fingerprints.json`](../cmd/wafme0w/resources/waf-fingerprints.json)
with `ReadCatalogue`, then compile it once and reuse the engine.

Save this as `main.go`. It accepts a catalogue path and one authorized URL and
writes one result as JSONL:

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: waf-client catalogue.json authorized-url")
	}
	if err := scan(os.Args[1], os.Args[2]); err != nil {
		log.Fatal(err)
	}
}

func scan(cataloguePath, target string) error {
	catalogue, err := os.Open(cataloguePath)
	if err != nil {
		return err
	}
	defer catalogue.Close()
	rules, err := wafme0w.ReadCatalogue(catalogue)
	if err != nil {
		return err
	}
	engine, err := wafme0w.Compile(rules)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	interruptsDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		stop() // Restore default handling so a second Ctrl-C can terminate.
		close(interruptsDone)
	}()
	defer func() {
		stop()
		<-interruptsDone
	}()
	config := wafme0w.DefaultConfig()
	config.BaselineOnly = true
	config.RequestsPerSecond = 5
	encoder := json.NewEncoder(os.Stdout)
	return wafme0w.Run(ctx, engine, strings.NewReader(target+"\n"), config,
		func(result wafme0w.Result) error {
			if err := encoder.Encode(result); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			return nil
		})
}
```

```sh
go mod tidy
# Start your own HTTP server on port 8080 first.
go run . /path/to/waf-fingerprints.json http://127.0.0.1:8080
```

`BaselineOnly` sends a normal request rather than active probes; redirects can
still produce additional requests. Without it, the default mode sends active
probes. Only scan targets you own or are authorized to test.

The first Ctrl-C cancels acquisition; a subsequent Ctrl-C terminates the process
after default interrupt handling is restored. Context cancellation cannot
interrupt this example's stdout write if a downstream reader stops consuming.
For unattended services, supply a sink with a bounded write deadline or a
caller-owned cancellation/unblock mechanism; callbacks must return for graceful
shutdown. Forced termination can leave a partial JSONL record.

Target failures and incomplete evidence appear in `Result`; a nil `Run` error
does not establish a successful acquisition or a clean negative. Inspect
`result.Outcome`, evidence diagnostics, and channel availability. Configuration,
input, cancellation, and callback errors are returned by the runner.

For native capture JSONL, replace the `Run` call with `RunCaptured` and pass an
opened capture file as the reader. It performs no network requests. For httpx
exports, use `RunHTTPXCaptured` with explicit encoding as described below.

## Ownership and streaming

`Compile` owns its rules; an `Engine` is safe for concurrent classification.
`Classify` borrows evidence bodies read-only until it returns and does not retain
them. Callers must not mutate evidence during a call.

`Run` performs bounded live acquisition and emits serially in completion order.
Its HTTP workers remain free while the optional single-browser stage acquires a
fresh Chromium capture; bounded export workers may overlap sanitized asset saves.
`RunCaptured` decodes and classifies with at most `min(Config.Concurrency,
GOMAXPROCS)` workers, then emits serially in input order. At most twice that many
records and 32 MiB of raw records are admitted ahead of emission.
Native records have a 16 MiB serialized limit, 64 observations, and at most
4,096 headers and 4,096 redirect destinations per observation. The importer
enforces collection limits before decoding an excess element; these limits do
not change direct `Evidence` JSON unmarshalling or the `Classify` API.
Readers, injected clients/transports, and writers remain caller-owned. Blocking
input needs `Config.CancelInput` or another caller-provided wakeup; callbacks and
transports must honor cancellation and return. After successful configuration
validation, cancellation invokes `CancelInput` once, including when the supplied
context is already cancelled.

`Config.Concurrency` defaults to 20 and must be between 1 and
`wafme0w.MaxConcurrency` (65,536). Values outside that supported range fail
configuration validation before reading inputs or allocating workers. The upper
bound prevents excessive worker fan-out and counter overflow; it is not a
recommended setting or a process memory limit.

`Config.ProbeConcurrency` defaults to 1; values up to 8 parallelize later
full-mode probes after the normal response. `Config.MaxConnections == 0`
follows `Config.Concurrency`; `DefaultConfig()` retains its explicit limit of 20.
Set it to zero when changing library target concurrency should also resize the
connection limit. The CLI selects zero by default.

## v2 evidence API

v2 adds explicit channel availability and import provenance to the evidence API.
Applications migrating from v1 must update their import paths and use keyed
struct literals.

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

## Versioning

Result JSON uses schema 1 with optional nested import/availability metadata.
Native/live output omits that metadata when unused. CSV columns and TXT keys do
not depend on whether import metadata is present. Incompatible documented Go API
or report-schema changes require appropriate versioning.

See [CLI limits](usage.md#inputs-and-limits), [browser capture](browser.md), and
[deployment boundaries](operations.md#deployment-boundaries) for the remaining
ownership, acquisition, and hosted-service isolation requirements. URL/redirect
validation is not an SSRF defense for a service accepting arbitrary targets.

