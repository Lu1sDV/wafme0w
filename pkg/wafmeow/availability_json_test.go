package wafmeow

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestAvailabilityJSONRejectsMergeBypasses(t *testing.T) {
	const complete = `{"status":"complete","headers":"complete","reason":"complete","body":"complete"}`
	engine := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "blocked"}}})
	for name, members := range map[string]string{
		"duplicate body null":       `"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete","body":null}`,
		"duplicate status null":     `"availability":{"status":"complete","status":null,"headers":"complete","reason":"complete","body":"complete"}`,
		"duplicate headers null":    `"availability":{"status":"complete","headers":"complete","headers":null,"reason":"complete","body":"complete"}`,
		"duplicate reason null":     `"availability":{"status":"complete","headers":"complete","reason":"complete","reason":null,"body":"complete"}`,
		"duplicate body unchanged":  `"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete","body":"complete"}`,
		"duplicate body escaped":    `"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete","bo\u0064y":null}`,
		"duplicate body case alias": `"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete","Body":null}`,
		"repeated empty object":     `"availability":` + complete + `,"availability":{}`,
		"repeated null object":      `"availability":` + complete + `,"availability":null`,
		"repeated complete object":  `"availability":` + complete + `,"availability":` + complete,
		"repeated null then full":   `"availability":null,"availability":` + complete,
		"repeated case alias":       `"availability":` + complete + `,"Availability":null`,
		"merged partial objects":    `"availability":{"status":"complete","headers":"complete"},"availability":{"reason":"complete","body":"complete"}`,
		"unknown promoted legacy":   `"availability":{"status":"complete","headers":"complete","reason":"complete","body":"unknown"},"availability":null`,
	} {
		t.Run(name, func(t *testing.T) {
			observation := `{"role":"Normal","status_code":200,"body":"YmxvY2tlZA==",` + members + `}`
			t.Run("direct evidence", func(t *testing.T) {
				var evidence Evidence
				if err := json.Unmarshal([]byte(observation), &evidence); err != nil {
					return
				}
				outcome := engine.Classify([]Evidence{evidence})
				if outcome.State != Failed || len(outcome.Matches) != 0 {
					t.Fatalf("ambiguous availability classified instead of rejected: %+v", outcome)
				}
			})
			t.Run("native capture", func(t *testing.T) {
				emitted := 0
				record := `{"target":"saved","evidence":[` + observation + `]}`
				err := RunCaptured(context.Background(), engine, strings.NewReader(record), DefaultConfig(), func(Result) error {
					emitted++
					return nil
				})
				if err == nil || emitted != 0 {
					t.Fatalf("ambiguous availability accepted: emitted=%d err=%v", emitted, err)
				}
			})
		})
	}
}

func TestAvailabilityJSONLegacyAndComplete(t *testing.T) {
	engine := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "blocked"}}})
	for name, members := range map[string]string{
		"absent":   ``,
		"null":     `,"availability":null`,
		"complete": `,"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete"}`,
	} {
		t.Run(name, func(t *testing.T) {
			observation := `{"role":"Normal","status_code":200,"body":"YmxvY2tlZA=="` + members + `}`
			var evidence Evidence
			if err := json.Unmarshal([]byte(observation), &evidence); err != nil {
				t.Fatal(err)
			}
			if (evidence.Availability == nil) != (name != "complete") {
				t.Fatalf("legacy availability changed: %+v", evidence.Availability)
			}
			if got := engine.Classify([]Evidence{evidence}); got.State != Complete || len(got.Matches) != 1 {
				t.Fatalf("valid availability changed direct classification: %+v", got)
			}
			emitted := 0
			record := `{"target":"saved","evidence":[` + observation + `]}`
			err := RunCaptured(context.Background(), engine, strings.NewReader(record), DefaultConfig(), func(result Result) error {
				emitted++
				if result.Outcome.State != Complete || len(result.Outcome.Matches) != 1 {
					t.Errorf("valid availability changed capture classification: %+v", result.Outcome)
				}
				return nil
			})
			if err != nil || emitted != 1 {
				t.Fatalf("valid availability rejected: emitted=%d err=%v", emitted, err)
			}
		})
	}
}

func TestRunCapturedAvailabilityPreservesUnknownFieldRejection(t *testing.T) {
	for name, record := range map[string]string{
		"capture":      `{"target":"saved","evidence":[],"extra":true}`,
		"evidence":     `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"extra":true}]}`,
		"header":       `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"headers":[{"name":"Server","value":"origin","extra":true}]}]}`,
		"availability": `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"availability":{"status":"complete","headers":"complete","reason":"complete","body":"complete","extra":true}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			emitted := 0
			err := RunCaptured(context.Background(), emptyEngine(t), strings.NewReader(record), DefaultConfig(), func(Result) error {
				emitted++
				return nil
			})
			if err == nil || emitted != 0 {
				t.Fatalf("unknown field accepted: emitted=%d err=%v", emitted, err)
			}
		})
	}
}
