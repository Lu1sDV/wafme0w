package wafmeow

import (
	"context"
	"strings"
	"testing"
)

func TestHTTPXAbsoluteIdentityCannotBorrowQueryScheme(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Status", Pattern: "200"})
	for _, field := range []string{"url", "final_url"} {
		t.Run(field, func(t *testing.T) {
			record := map[string]any{"url": "https://example.test/", "status_code": 200}
			record[field] = "example.test/?next=https://elsewhere.test/"
			emitted := false
			err := RunHTTPXCaptured(context.Background(), engine, strings.NewReader(makeHTTPXRecord(t, record)), DefaultConfig(), HTTPXImportOptions{}, func(Result) error { emitted = true; return nil })
			if err == nil || emitted {
				t.Fatalf("relative %s accepted: emitted=%t err=%v", field, emitted, err)
			}
		})
	}
}

func TestHTTPXHeaderValueLimitUsesParserLineBoundaries(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "X", HeaderValue: "^a$"})
	for _, ending := range []string{"\r\n", "\n"} {
		for _, count := range []int{4096, 4097} {
			raw := "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: a"+ending, count) + "\r\n\r\n"
			results := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw}), DefaultConfig(), HTTPXImportOptions{})
			result := results[0]
			if count == 4097 {
				if len(result.Outcome.Matches) != 0 || result.Evidence[0].Availability.Headers != ChannelUnavailable {
					t.Fatalf("%q framing admitted %d values: %+v", ending, count, result.Outcome)
				}
			} else if len(result.Outcome.Matches) != 1 {
				t.Fatalf("exact bound rejected with %q framing: %+v", ending, result.Outcome)
			}
		}
	}
}

func FuzzHTTPXImportCannotInventCompleteChannels(f *testing.F) {
	for _, seed := range []string{
		`{"url":"https://example.test/","status_code":200}`,
		`{"url":"https://example.test/","status_code":200,"body":"marker"}`,
		`{"url":"https://example.test/","raw_header":"HTTP/1.1 200 OK\r\nServer: marker\r\n\r\n"}`,
		`{"input":"failed target","failed":true,"error":"fixture failure"}`,
	} {
		f.Add(seed, false)
		f.Add(seed, true)
	}
	engine, err := Compile([]WAF{{Name: "body", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "marker"}}}}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, record string, encoded bool) {
		if len(record) > 64<<10 {
			t.Skip()
		}
		options := HTTPXImportOptions{}
		if encoded {
			options.ResponseEncoding = HTTPXBase64
		}
		_ = RunHTTPXCaptured(context.Background(), engine, strings.NewReader(record), DefaultConfig(), options, func(result Result) error {
			if len(result.Outcome.Matches) != 0 || len(result.Evidence) != 1 || result.Provenance.Import == nil {
				t.Fatalf("import invented body support or lost identity: %+v", result)
			}
			a := result.Evidence[0].Availability
			if a == nil || a.Body == ChannelComplete || a.Headers == ChannelComplete || a.Reason != ChannelUnavailable {
				t.Fatalf("export completeness invented: %+v", a)
			}
			for _, diagnostic := range result.Outcome.Diagnostics {
				if len(diagnostic.Message) > 1024 {
					t.Fatalf("unbounded import diagnostic: %d", len(diagnostic.Message))
				}
			}
			return nil
		})
	})
}
