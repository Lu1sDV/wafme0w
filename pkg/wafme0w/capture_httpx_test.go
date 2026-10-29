package wafme0w

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func httpxEngine(t *testing.T, fingerprints ...FingerPrint) *Engine {
	t.Helper()
	var definitions []WAF
	for i, fingerprint := range fingerprints {
		definitions = append(definitions, WAF{Name: fmt.Sprintf("rule-%d", i), Schemas: []Scheme{{FingerPrints: []FingerPrint{fingerprint}}}})
	}
	engine, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func makeHTTPXRecord(t *testing.T, fields map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func httpxResults(t *testing.T, engine *Engine, input string, config Config, options HTTPXImportOptions) []Result {
	t.Helper()
	var results []Result
	if err := RunHTTPXCaptured(context.Background(), engine, strings.NewReader(input), config, options, func(result Result) error {
		results = append(results, result)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return results
}

func TestHTTPXRealProducerFixtures(t *testing.T) {
	engine := httpxEngine(t,
		FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "^first$"},
		FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "^second$"},
		FingerPrint{Type: "Cookie", Pattern: "^fixture=a"},
		FingerPrint{Type: "Cookie", Pattern: "^second=b"},
		FingerPrint{Type: "Content", Pattern: "fixture-body-marker"},
	)
	for _, name := range []string{"summary", "text", "base64"} {
		t.Run(name, func(t *testing.T) {
			input, err := os.ReadFile("testdata/httpx-v1.12.0/" + name + ".jsonl")
			if err != nil {
				t.Fatal(err)
			}
			options := HTTPXImportOptions{}
			if name == "base64" {
				options.ResponseEncoding = HTTPXBase64
			}
			results := httpxResults(t, engine, string(input), DefaultConfig(), options)
			if len(results) != 1 {
				t.Fatalf("results = %d", len(results))
			}
			result := results[0]
			wantMatches := 4
			if name == "summary" {
				wantMatches = 0
			}
			if len(result.Outcome.Matches) != wantMatches || result.Outcome.State != Incomplete {
				t.Fatalf("producer fixture classification: %+v", result.Outcome)
			}
			if result.Evidence[0].Availability == nil || result.Provenance.Import == nil || len(result.Outcome.Diagnostics) == 0 {
				t.Fatalf("missing import limitations: %+v", result)
			}
		})
	}
}

func TestHTTPXAttributionAndOccurrences(t *testing.T) {
	record := `{"url":"https://example.test/request","input":"original label","status_code":302,"raw_header":"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.test/\r\n\r\n","timestamp":"2026-10-29T00:00:00Z"}`
	results := httpxResults(t, emptyEngine(t), "\n"+record+"\n \n"+record+"\n", DefaultConfig(), HTTPXImportOptions{})
	if len(results) != 2 {
		t.Fatalf("duplicates merged: %d", len(results))
	}
	for i, result := range results {
		metadata := result.Provenance.Import
		if result.Target != "https://example.test/request" || result.Evidence[0].RequestURL != result.Target || result.Evidence[0].EffectiveURL != "" {
			t.Fatalf("invented effective identity: %+v", result)
		}
		if metadata == nil || metadata.Format != "httpx" || metadata.Profile != "httpx-v1.12.0" || metadata.ResponseEncoding != HTTPXText || metadata.Occurrence != i+1 || metadata.InputLine != 2+i*2 || metadata.OriginalInput != "original label" || metadata.SourceTimestamp != "2026-10-29T00:00:00Z" || metadata.TimestampMeaning != "result_construction" {
			t.Fatalf("incorrect provenance: %+v", metadata)
		}
	}
	result := httpxResults(t, emptyEngine(t), `{"url":"https://example.test/a","final_url":"https://reached.test/b","status_code":200}`, DefaultConfig(), HTTPXImportOptions{})[0]
	if result.Evidence[0].EffectiveURL != "https://reached.test/b" {
		t.Fatalf("final_url lost: %+v", result.Evidence)
	}
}

func TestHTTPXConservativeChannels(t *testing.T) {
	engine := httpxEngine(t,
		FingerPrint{Type: "Status", Pattern: "403"},
		FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "^marker$"},
		FingerPrint{Type: "Content", Pattern: "marker"},
		FingerPrint{Type: "Reason", Pattern: "Forbidden"},
	)
	for _, tc := range []struct {
		name, extra   string
		status        int
		headers, body ChannelState
		matches       int
	}{
		{"status only", ``, 403, ChannelUnavailable, ChannelUnavailable, 1},
		{"normalized only", `,"header":{"x_fixture":"marker"}`, 403, ChannelUnavailable, ChannelUnavailable, 1},
		{"raw repeated", `,"raw_header":"HTTP/1.1 403 Forbidden\r\nX-Fixture: marker\r\n\r\n"`, 403, ChannelIncomplete, ChannelUnavailable, 2},
		{"empty body", `,"body":""`, 403, ChannelUnavailable, ChannelUnknown, 1},
		{"body prefix", `,"body":"marker"`, 403, ChannelUnavailable, ChannelUnknown, 1},
		{"preview only", `,"body_preview":"marker"`, 403, ChannelUnavailable, ChannelUnavailable, 1},
		{"conflict", `,"raw_header":"HTTP/1.1 200 OK\r\nX-Fixture: marker\r\n\r\n"`, 0, ChannelIncomplete, ChannelUnavailable, 1},
		{"unsupported interim dump", `,"raw_header":"HTTP/1.1 103 Early Hints\nX-Fixture: [marker]\n"`, 0, ChannelUnavailable, ChannelUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := httpxResults(t, engine, `{"url":"https://example.test/","status_code":403`+tc.extra+`}`, DefaultConfig(), HTTPXImportOptions{})[0]
			evidence := result.Evidence[0]
			if evidence.StatusCode != tc.status || evidence.Availability.Headers != tc.headers || evidence.Availability.Body != tc.body || evidence.Availability.Reason != ChannelUnavailable || len(result.Outcome.Matches) != tc.matches {
				t.Fatalf("channels not conservative: %+v %+v", evidence, result.Outcome)
			}
		})
	}
}

func TestHTTPXExcludedFramingAndTextReplacement(t *testing.T) {
	for _, key := range []string{"Content-Length", "Transfer-Encoding", "Trailer", "Connection", "X-Fixture"} {
		engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: key, HeaderValue: "marker"})
		value := "marker"
		if key == "X-Fixture" {
			value = "marker\ufffd"
		}
		record := makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": "HTTP/1.1 200 OK\r\n" + key + ": " + value + "\r\n\r\n"})
		result := httpxResults(t, engine, record, DefaultConfig(), HTTPXImportOptions{})[0]
		if len(result.Outcome.Matches) != 0 || result.Outcome.State != Incomplete {
			t.Fatalf("lossy field %s matched: %+v", key, result.Outcome)
		}
	}
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "marker"})
	raw := base64.StdEncoding.EncodeToString([]byte("HTTP/1.1 200 OK\r\nX-Fixture: marker\ufffd\r\n\r\n"))
	result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "raw_header": raw}), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: HTTPXBase64})[0]
	if len(result.Outcome.Matches) != 1 {
		t.Fatalf("base64 bytes wrongly withheld: %+v", result.Outcome)
	}
}

func TestHTTPXBodyLimitsAndEncoding(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Content", Pattern: "marker"}, FingerPrint{Type: "Status", Pattern: "200"})
	for _, tc := range []struct {
		name, body string
		encoding   HTTPXResponseEncoding
		want       ChannelState
	}{
		{"text exact", "abc", HTTPXText, ChannelUnknown},
		{"text over", "abcd", HTTPXText, ChannelIncomplete},
		{"base64 exact", "YWJj", HTTPXBase64, ChannelUnknown},
		{"base64 over", "YWJjZA==", HTTPXBase64, ChannelIncomplete},
		{"cut base64", "YWJjZ", HTTPXBase64, ChannelUnavailable},
		{"valid base64 prefix", "YWJj", HTTPXBase64, ChannelUnknown},
		{"base64-looking text", "YWJj", HTTPXText, ChannelIncomplete},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultConfig()
			config.MaxBodyBytes = 3
			result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "body": tc.body}), config, HTTPXImportOptions{ResponseEncoding: tc.encoding})[0]
			if result.Evidence[0].Availability.Body != tc.want || len(result.Outcome.Matches) != 1 {
				t.Fatalf("body limit/encoding: %+v", result)
			}
		})
	}
}

func TestHTTPXRejectsMalformedStreamPreservingPriorResults(t *testing.T) {
	for name, record := range map[string]string{
		"array": `[]`, "null": `null`, "trailing": `{"url":"https://example.test/"} {}`,
		"missing identity": `{}`, "bare identity": `{"url":"example.test"}`, "invalid final": `{"url":"https://example.test/","final_url":"file:///etc/passwd"}`,
		"wrong string": `{"url":3}`, "wrong status": `{"url":"https://example.test/","status_code":"200"}`, "fractional status": `{"url":"https://example.test/","status_code":200.5}`,
		"wrong failed": `{"url":"https://example.test/","failed":"false"}`, "wrong body": `{"url":"https://example.test/","body":[]}`, "wrong normalized": `{"url":"https://example.test/","header":{"server":[]}}`,
		"duplicate": `{"url":"https://example.test/","status_code":200,"status_code":403}`, "escaped duplicate": `{"url":"https://example.test/","bo\u0064y":"a","body":"b"}`,
		"oversized identity": makeHTTPXRecord(t, map[string]any{"url": "https://example.test/" + strings.Repeat("a", 64<<10)}),
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			err := RunHTTPXCaptured(context.Background(), emptyEngine(t), strings.NewReader("{\"url\":\"https://first.test/\"}\n"+record), DefaultConfig(), HTTPXImportOptions{}, func(Result) error { calls++; return nil })
			if err == nil || calls != 1 || !strings.Contains(err.Error(), "line 2") {
				t.Fatalf("stream rejection: calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestHTTPXUnknownNumbersPreserveStreamAndStrictStatus(t *testing.T) {
	for name, metadata := range map[string]string{
		"top-level": `"unrelated":1e400`,
		"nested":    `"unrelated":{"values":[1e400,{"value":-1e400}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, status := range []string{`1e400`, `200.5`, `"200"`} {
				t.Run(status, func(t *testing.T) {
					input := `{"url":"https://first.test/","status_code":200,` + metadata + "}\n" +
						"{\"url\":\"https://second.test/\",\"status_code\":403}\n" +
						`{"url":"https://invalid.test/","status_code":` + status + "}\n" +
						"{\"url\":\"https://unreached.test/\"}\n"
					var results []Result
					err := RunHTTPXCaptured(context.Background(), emptyEngine(t), strings.NewReader(input), DefaultConfig(), HTTPXImportOptions{}, func(result Result) error {
						results = append(results, result)
						return nil
					})
					var typeErr *json.UnmarshalTypeError
					if !errors.As(err, &typeErr) || !strings.Contains(err.Error(), "line 3") || !strings.Contains(err.Error(), `"status_code"`) {
						t.Fatalf("invalid consumed status was not rejected on line 3: %v", err)
					}
					if len(results) != 2 {
						t.Fatalf("unknown numeric metadata interrupted stream or invalid status emitted: results=%d err=%v", len(results), err)
					}
					for i, want := range []struct {
						target string
						status int
					}{{"https://first.test/", 200}, {"https://second.test/", 403}} {
						if results[i].Target != want.target || results[i].Evidence[0].StatusCode != want.status {
							t.Fatalf("record %d lost identity or status: %+v", i, results[i])
						}
					}
				})
			}
		})
	}
}

func TestHTTPXFailureAndIgnoredEnrichment(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "marker"})
	for _, extra := range []string{`,"failed":true`, `,"error":"upstream timeout"`} {
		result := httpxResults(t, engine, `{"url":"https://example.test/","raw_header":"HTTP/1.1 200 OK\r\nX-Fixture: marker\r\n\r\n"`+extra+`}`, DefaultConfig(), HTTPXImportOptions{})[0]
		if result.Outcome.State == Failed || len(result.Outcome.Matches) != 1 || !result.Provenance.Import.UpstreamFailed {
			t.Fatalf("upstream error erased evidence: %+v", result)
		}
	}
	result := httpxResults(t, engine, `{"input":"opaque failed label","failed":true,"tech":["Cloudflare"],"stored_response_path":"/not/read","request":"secret"}`, DefaultConfig(), HTTPXImportOptions{})[0]
	if result.Target != "opaque failed label" || result.Evidence[0].RequestURL != "" || len(result.Outcome.Matches) != 0 {
		t.Fatalf("invented identity or detection: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("/not/read")) {
		t.Fatal("retained ignored source data")
	}
}

func TestHTTPXBudgetAdmissionBoundaries(t *testing.T) {
	url := "https://example.test/"
	identityBytes := int64(2 * (len(url) + 16))
	raw := "HTTP/1.1 200 OK\r\nX-Fixture: marker\r\n\r\n"
	headerBytes := int64(32 + len("X-Fixture") + len("marker"))
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "marker"})
	for _, tc := range []struct {
		name     string
		budget   int64
		matches  int
		metadata bool
		reject   bool
	}{
		{"identity one below", identityBytes - 1, 0, false, true},
		{"identity exact", identityBytes, 0, false, false},
		{"header one below", identityBytes + headerBytes - 1, 0, true, false},
		{"header exact", identityBytes + headerBytes, 1, false, false},
		{"metadata exact", identityBytes + headerBytes + 17, 1, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultConfig()
			config.MaxTargetEvidenceBytes = tc.budget
			var results []Result
			err := RunHTTPXCaptured(context.Background(), engine, strings.NewReader(makeHTTPXRecord(t, map[string]any{"url": url, "raw_header": raw, "input": "x", "body": strings.Repeat("z", 1024)})), config, HTTPXImportOptions{}, func(r Result) error { results = append(results, r); return nil })
			if tc.reject {
				if err == nil || len(results) != 0 {
					t.Fatalf("mandatory identities admitted: %v", err)
				}
				return
			}
			if err != nil || len(results) != 1 {
				t.Fatalf("budget rejected record: %v", err)
			}
			if len(results[0].Outcome.Matches) != tc.matches || (results[0].Provenance.Import.OriginalInput != "") != tc.metadata {
				t.Fatalf("admission order incorrect: %+v", results[0])
			}
		})
	}
}

func TestHTTPXHeaderBoundsAndMetadataCaps(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Status", Pattern: "200"}, FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "marker"})
	raw := "HTTP/1.1 200 OK\r\nX-Fixture: marker\r\n\r\n"
	for _, delta := range []int64{0, -1} {
		config := DefaultConfig()
		config.MaxResponseHeaderBytes = int64(len(raw)) + delta
		result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw}), config, HTTPXImportOptions{})[0]
		want := 2
		if delta < 0 {
			want = 1
		}
		if len(result.Outcome.Matches) != want {
			t.Fatalf("header block boundary %d: %+v", delta, result)
		}
	}
	raw = "HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Fixture: marker\r\n", 4097) + "\r\n"
	config := DefaultConfig()
	config.MaxResponseHeaderBytes = 1 << 20
	result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw, "input": strings.Repeat("i", (64<<10)+1), "timestamp": strings.Repeat("t", 129), "error": strings.Repeat("e", 1025)}), config, HTTPXImportOptions{})[0]
	metadata := result.Provenance.Import
	if len(result.Outcome.Matches) != 1 || metadata.OriginalInput != "" || metadata.SourceTimestamp != "" || len(metadata.UpstreamError) > 1024 || !strings.Contains(metadata.UpstreamError, "truncated") {
		t.Fatalf("caps failed: %+v", result)
	}
	if len(result.Outcome.Diagnostics) > 8 {
		t.Fatalf("unbounded diagnostics: %d", len(result.Outcome.Diagnostics))
	}
	for _, diagnostic := range result.Outcome.Diagnostics {
		if len(diagnostic.Message) > 1024 {
			t.Fatal("unbounded diagnostic message")
		}
	}
}

func TestHTTPXNoNetworkAndLifecycle(t *testing.T) {
	config := DefaultConfig()
	config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("offline importer attempted network")
		return nil, errors.New("forbidden")
	})}
	reader := &trackedReader{Reader: strings.NewReader("{\"url\":\"https://example.test/\"}\n{\"url\":\"https://second.test/\"}\n")}
	sinkErr := errors.New("sink failure")
	wakeups := 0
	config.CancelInput = func() { wakeups++ }
	calls := 0
	err := RunHTTPXCaptured(context.Background(), emptyEngine(t), reader, config, HTTPXImportOptions{}, func(Result) error { calls++; return sinkErr })
	if !errors.Is(err, sinkErr) || calls != 1 || wakeups != 1 || reader.closed {
		t.Fatalf("sink ownership: calls=%d wakeups=%d closed=%v err=%v", calls, wakeups, reader.closed, err)
	}
	for _, options := range []HTTPXImportOptions{{ResponseEncoding: "invalid"}} {
		wakeups = 0
		err := RunHTTPXCaptured(context.Background(), emptyEngine(t), failingReader{io.ErrUnexpectedEOF}, config, options, func(Result) error { t.Error("invalid options emitted"); return nil })
		if err == nil || errors.Is(err, io.ErrUnexpectedEOF) || wakeups != 0 {
			t.Fatalf("option validation touched input: %v", err)
		}
	}
	config.Browser = &BrowserConfig{Mode: "navigate"}
	err = RunHTTPXCaptured(context.Background(), emptyEngine(t), failingReader{io.ErrUnexpectedEOF}, config, HTTPXImportOptions{}, func(Result) error { return nil })
	if err == nil || errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("browser reached importer input: %v", err)
	}
}

func TestRunHTTPXCapturedPrecancelledInputWakesWithoutReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inputErr := errors.New("input must not be read")
	config := DefaultConfig()
	var wakeups atomic.Int32
	config.CancelInput = func() { wakeups.Add(1) }
	err := RunHTTPXCaptured(ctx, emptyEngine(t), failingReader{inputErr}, config, HTTPXImportOptions{}, func(Result) error {
		t.Error("pre-cancelled stream emitted a result")
		return nil
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, inputErr) || wakeups.Load() != 1 {
		t.Fatalf("pre-cancelled stream acquired input or lost cancellation: err=%v wakeups=%d", err, wakeups.Load())
	}
}

func TestHTTPXCancellationAndOpenProducer(t *testing.T) {
	reader, writer := io.Pipe()
	t.Cleanup(func() { reader.Close(); writer.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wakeups atomic.Int32
	config := DefaultConfig()
	config.CancelInput = func() { wakeups.Add(1); reader.Close() }
	emitted := make(chan Result, 1)
	done := make(chan error, 1)
	engine := emptyEngine(t)
	go func() {
		done <- RunHTTPXCaptured(ctx, engine, reader, config, HTTPXImportOptions{}, func(r Result) error { emitted <- r; return nil })
	}()
	if _, err := io.WriteString(writer, "{\"url\":\"https://example.test/\"}\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-emitted:
	case <-time.After(time.Second):
		t.Fatal("waited for producer EOF")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || wakeups.Load() != 1 {
			t.Fatalf("cancellation: wakeups=%d err=%v", wakeups.Load(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked importer abandoned")
	}
}

func TestHTTPXSerializedRecordBoundary(t *testing.T) {
	prefix := `{"url":"https://example.test/","ignored":"`
	suffix := `"}`
	for _, extra := range []int{0, 1} {
		record := prefix + strings.Repeat("x", maxCaptureRecordBytes-len(prefix)-len(suffix)+extra) + suffix
		calls := 0
		err := RunHTTPXCaptured(context.Background(), emptyEngine(t), strings.NewReader(record), DefaultConfig(), HTTPXImportOptions{}, func(Result) error { calls++; return nil })
		if extra == 0 && (err != nil || calls != 1) {
			t.Fatalf("exact record limit rejected: calls=%d err=%v", calls, err)
		}
		if extra == 1 && (err == nil || calls != 0) {
			t.Fatalf("over record limit accepted: calls=%d err=%v", calls, err)
		}
	}
}

func TestHTTPXDoesNotRetainUnmatchableBody(t *testing.T) {
	for _, encoding := range []HTTPXResponseEncoding{HTTPXText, HTTPXBase64} {
		body := strings.Repeat("private-marker", 1000)
		if encoding == HTTPXBase64 {
			body = base64.StdEncoding.EncodeToString([]byte(body))
		}
		decoded, err := decodeHTTPXCapture([]byte(makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "body": body})), DefaultConfig(), encoding, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.capture.Evidence[0].Body) != 0 || decoded.capture.Evidence[0].Availability.Body != ChannelUnknown {
			t.Fatal("unmatchable imported body retained")
		}
	}
}

func TestHTTPXHeaderCountExactAndOneOver(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "X-Fixture", HeaderValue: "marker"})
	config := DefaultConfig()
	config.MaxResponseHeaderBytes = 1 << 20
	for _, count := range []int{4096, 4097} {
		raw := "HTTP/1.1 200 OK\r\n" + strings.Repeat("X-Fixture: marker\r\n", count) + "\r\n"
		result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "raw_header": raw}), config, HTTPXImportOptions{})[0]
		want := 1
		if count > 4096 {
			want = 0
		}
		if len(result.Outcome.Matches) != want {
			t.Fatalf("header count %d: %+v", count, result.Outcome)
		}
	}
}

func TestHTTPXDoesNotMergeRecordsAndHonorsBackpressure(t *testing.T) {
	engine, err := Compile([]WAF{{Name: "both", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "X-A", HeaderValue: "yes"}, {Type: "Header", HeaderKey: "X-B", HeaderValue: "yes"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	first := makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "raw_header": "HTTP/1.1 200 OK\r\nX-A: yes\r\n\r\n"})
	second := makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "raw_header": "HTTP/1.1 200 OK\r\nX-B: yes\r\n\r\n"})
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var calls atomic.Int32
	go func() {
		done <- RunHTTPXCaptured(context.Background(), engine, strings.NewReader(first+"\n"+second), DefaultConfig(), HTTPXImportOptions{}, func(result Result) error {
			if len(result.Outcome.Matches) != 0 {
				return errors.New("merged independent observations")
			}
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not start")
	}
	if calls.Load() != 1 {
		t.Fatal("emitted speculatively across blocked callback")
	}
	close(release)
	select {
	case err := <-done:
		if err != nil || calls.Load() != 2 {
			t.Fatalf("backpressure completion: calls=%d err=%v", calls.Load(), err)
		}
	case <-time.After(time.Second):
		t.Fatal("runner did not join")
	}
}
