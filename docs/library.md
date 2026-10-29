# Go library

[Quick start](../README.md) · [API reference](https://pkg.go.dev/github.com/Lu1sDV/wafme0w/pkg/wafme0w)

Match an already captured response without sending any requests:
```go
package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
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
Its HTTP workers remain free while the optional single-browser stage acquires a
fresh Chromium capture; bounded export workers may overlap sanitized asset saves.
`RunCaptured` decodes and classifies with at most `min(Config.Concurrency,
GOMAXPROCS)` workers, then emits serially in input order. At most twice that many
records and 32 MiB of raw records are admitted ahead of emission.
Readers, injected clients/transports, and writers remain caller-owned. Blocking
input needs `Config.CancelInput` or another caller-provided wakeup; callbacks and
transports must honor cancellation and return.

`Config.ProbeConcurrency` defaults to 1; values up to 8 parallelize later
full-mode probes after the normal response. `Config.MaxConnections == 0`
follows `Config.Concurrency`; `DefaultConfig()` retains its explicit limit of 20.
Set it to zero when changing library target concurrency should also resize the
connection limit. The CLI selects zero by default.

See [CLI limits](usage.md#inputs-and-limits) for the corresponding `Config` byte
budgets and [browser capture](browser.md) for optional artifact callbacks. The
result schema, CSV layout, flags, exit codes, and documented Go API form the stable
1.x baseline; incompatible changes require a new major version.
