package wafmeow

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestCancelledResponseRetainsMetadataWithinLimits(t *testing.T) {
	for _, test := range []struct {
		name        string
		cause       error
		abortProbe  bool
		headerLimit int64
		wantCode    string
		wantStatus  int
	}{
		{name: "caller cancellation", cause: context.Canceled, wantCode: "cancelled", wantStatus: http.StatusForbidden},
		{name: "request deadline", cause: context.DeadlineExceeded, wantCode: "deadline_exceeded", wantStatus: http.StatusForbidden},
		{
			name: "retry budget", cause: &acquisitionError{"request_budget", "per-target outbound request budget exhausted"},
			abortProbe: true, wantCode: "request_budget", wantStatus: http.StatusForbidden,
		},
		{name: "oversized headers", cause: context.Canceled, headerLimit: 16, wantCode: "response_header_limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			body := &trackedResponseBody{Reader: failingResponseReader{err: test.cause}}
			config := DefaultConfig()
			config.MaxConnections = 1
			if test.headerLimit != 0 {
				config.MaxResponseHeaderBytes = test.headerLimit
			}
			config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				// A parsed response can race with cancellation. Its metadata is
				// still evidence, while its canceled body cannot prove content.
				response := &http.Response{
					StatusCode: http.StatusForbidden, Status: "403 Forbidden", Proto: "HTTP/1.1",
					Header: http.Header{"Server": {"firewall"}}, Body: body, Request: req,
				}
				if test.abortProbe {
					trace := req.Context().Value(requestTraceKey{}).(*requestTrace)
					trace.abort(test.cause)
				} else {
					cancel(test.cause)
				}
				return response, nil
			})}
			policy := newOutboundPolicy(config)
			evidence, err := sendHTTP(ctx, requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid", Type: "Normal"}, policy.client("http://fixture.invalid"), 1024)
			if err == nil || evidence.ErrorCode != test.wantCode || evidence.TransportError == "" {
				t.Fatalf("cancellation or header-limit diagnostic lost: evidence=%+v err=%v", evidence, err)
			}
			if test.headerLimit == 0 && !errors.Is(err, test.cause) {
				t.Fatalf("cancellation cause = %v, want %v", err, test.cause)
			}
			if evidence.StatusCode != test.wantStatus {
				t.Fatalf("received status = %d, want %d: %+v", evidence.StatusCode, test.wantStatus, evidence)
			}
			if test.wantStatus != 0 {
				if evidence.Reason != "Forbidden" || !slices.Equal(evidence.Headers, []Header{{Name: "Server", Value: "firewall"}}) {
					t.Fatalf("received response metadata lost: %+v", evidence)
				}
			} else if evidence.Reason != "" || len(evidence.Headers) != 0 {
				t.Fatalf("oversized response metadata retained: %+v", evidence)
			}
			if len(evidence.Body) != 0 || availableEvidenceChannels(evidence).body {
				t.Fatalf("canceled body became usable evidence: %+v", evidence)
			}
			if body.closes != 1 || len(policy.slots) != 0 {
				t.Fatalf("response cleanup changed: body closes=%d occupied slots=%d", body.closes, len(policy.slots))
			}
		})
	}
}

func TestRunPreservesHeaderMatchAtRequestDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		engine, err := Compile([]WAF{
			{Name: "header", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "Server", HeaderValue: "^firewall$"}}}}},
			{Name: "body", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "blocked"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		body := &trackedResponseBody{Reader: failingResponseReader{err: context.DeadlineExceeded}}
		config := DefaultConfig()
		config.Concurrency, config.MaxConnections = 1, 1
		config.BaselineOnly, config.RequestTimeout = true, time.Second
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			response := &http.Response{
				StatusCode: http.StatusForbidden, Status: "403 Forbidden", Proto: "HTTP/1.1",
				Header: http.Header{"Server": {"firewall"}}, Body: body, Request: req,
			}
			<-req.Context().Done()
			return response, nil
		})}
		var results []Result
		if err := Run(context.Background(), engine, strings.NewReader("http://fixture.invalid\n"), config, func(result Result) error {
			results = append(results, result)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(results) != 1 {
			t.Fatalf("emitted %d results, want one target deadline result", len(results))
		}
		result := results[0]
		if len(result.Evidence) != 1 || result.Evidence[0].StatusCode != http.StatusForbidden || result.Evidence[0].ErrorCode != "deadline_exceeded" {
			t.Fatalf("received status or deadline diagnostic lost: %+v", result.Evidence)
		}
		if result.Outcome.State != Incomplete || len(result.Outcome.Matches) != 1 || result.Outcome.Matches[0].Product != "header" ||
			!slices.Equal(result.Outcome.IncompleteProducts, []string{"body"}) {
			t.Fatalf("deadline changed metadata matching or body completeness: %+v", result.Outcome)
		}
		if body.closes != 1 {
			t.Fatalf("canceled response body closed %d times, want one", body.closes)
		}
	})
}
