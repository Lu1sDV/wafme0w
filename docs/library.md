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
`RunCaptured` performs no network access and emits serially in input order.
Readers, injected clients/transports, and writers remain caller-owned. Blocking
input needs `Config.CancelInput` or another caller-provided wakeup; callbacks and
transports must honor cancellation and return.

See [CLI limits](usage.md#inputs-and-limits) for the corresponding `Config` byte
budgets and [browser capture](browser.md) for optional artifact callbacks. The
result schema, CSV layout, flags, exit codes, and documented Go API form the stable
1.x baseline; incompatible changes require a new major version.
