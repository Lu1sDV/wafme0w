package wafmeow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

func TestAdmissionFailureIdentifiesUnsentAttempt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		globalRate float64
		originRate float64
		cancel     bool
	}{
		{name: "global pacing", globalRate: 1},
		{name: "origin pacing", originRate: 1},
		{name: "connection slot"},
		{name: "cancelled slot", cancel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				const origin = "http://fixture.invalid"
				config := DefaultConfig()
				config.MaxConnections = 1
				config.RequestsPerSecond, config.PerOriginRequestsPerSecond = tc.globalRate, tc.originRate
				calls := 0
				config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls++
					return nil, errors.New("unexpected outbound attempt")
				})}
				policy := newOutboundPolicy(config)
				if err := policy.acquire(context.Background(), origin); err != nil {
					t.Fatal(err)
				}
				if tc.globalRate != 0 || tc.originRate != 0 {
					<-policy.slots
				} else {
					defer func() { <-policy.slots }()
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
				defer cancel()
				wantCause, wantCode := context.DeadlineExceeded, "deadline_exceeded"
				if tc.cancel {
					wantCause, wantCode = context.Canceled, "cancelled"
					go func() {
						time.Sleep(time.Millisecond)
						cancel()
					}()
				}
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin, nil)
				if err != nil {
					t.Fatal(err)
				}
				transport := &targetTransport{policy: policy, origin: origin}
				_, err = transport.RoundTrip(req)
				if !errors.Is(err, wantCause) || acquisitionCode(err) != wantCode || calls != 0 {
					t.Fatalf("admission changed cause, code or transport calls: err=%v code=%s calls=%d", err, acquisitionCode(err), calls)
				}
				for _, want := range []string{"local rate/connection admission", "this request attempt was not sent"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("admission error lacks %q: %v", want, err)
					}
				}
				if !tc.cancel && !strings.Contains(err.Error(), "reduce concurrency or increase request/target timeouts") {
					t.Errorf("timeout lacks corrective guidance: %v", err)
				}
			})
		})
	}
}

func TestRedirectAdmissionFailurePreservesEarlierResponse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const origin = "http://fixture.invalid"
		config := DefaultConfig()
		config.RequestsPerSecond = 1
		calls := 0
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{
				StatusCode: http.StatusFound, Status: "302 Found", Request: req,
				Header: http.Header{"Location": []string{origin + "/next"}},
				Body:   io.NopCloser(strings.NewReader("")),
			}, nil
		})}
		policy := newOutboundPolicy(config)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		evidence, err := sendHTTP(ctx, requestOpts{Method: http.MethodGet, Target: origin, Type: "Normal"}, policy.client(origin), 1024)
		if !errors.Is(err, context.DeadlineExceeded) || evidence.ErrorCode != "deadline_exceeded" || calls != 1 {
			t.Fatalf("redirect admission changed cause, code or prior attempt: err=%v evidence=%+v calls=%d", err, evidence, calls)
		}
		if evidence.StatusCode != http.StatusFound || !strings.Contains(evidence.TransportError, "this request attempt was not sent") {
			t.Fatalf("earlier response lost or later attempt unclear: %+v", evidence)
		}
		if strings.Contains(evidence.TransportError, "target was not sent") {
			t.Fatalf("diagnostic incorrectly describes the whole target: %s", evidence.TransportError)
		}
	})
}

func TestTransportDeadlineIsNotReportedAsAdmissionFailure(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const origin = "http://fixture.invalid"
		config := DefaultConfig()
		calls := 0
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		policy := newOutboundPolicy(config)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()
		evidence, err := sendHTTP(ctx, requestOpts{Method: http.MethodGet, Target: origin, Type: "Normal"}, policy.client(origin), 1024)
		if !errors.Is(err, context.DeadlineExceeded) || evidence.ErrorCode != "deadline_exceeded" || calls != 1 {
			t.Fatalf("transport deadline contract changed: err=%v evidence=%+v calls=%d", err, evidence, calls)
		}
		if strings.Contains(evidence.TransportError, "admission") || strings.Contains(evidence.TransportError, "not sent") {
			t.Fatalf("transport timeout mislabeled as unsent: %s", evidence.TransportError)
		}
	})
}
