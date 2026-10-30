package wafmeow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestClassifyCookiesBeyondHTTPParserLimit(t *testing.T) {
	// net/http's aggregate cookie parser silently drops all cookies above this
	// limit. Faithful admitted fields must still support positive evidence.
	t.Setenv("GODEBUG", "httpcookiemaxnum=3000")
	engine, want := cookieLimitEngine(t)
	for _, count := range []int{3000, 3001, maxCaptureHeaders} {
		for _, partial := range []bool{false, true} {
			t.Run(fmt.Sprintf("count-%d/partial-%t", count, partial), func(t *testing.T) {
				observation := Evidence{Role: "Normal", StatusCode: 200}
				for range count - 1 {
					observation.Headers = append(observation.Headers, Header{Name: "Set-Cookie", Value: "a=b"})
				}
				observation.Headers = append(observation.Headers, Header{Name: "set-cookie", Value: "firewall=blocked; Path=/"})
				if partial {
					observation.Availability = &EvidenceAvailability{
						Status: ChannelComplete, Headers: ChannelIncomplete,
						Reason: ChannelUnavailable, Body: ChannelUnavailable,
					}
				}
				if got := engine.Classify([]Evidence{observation}); !reflect.DeepEqual(got, want) {
					t.Fatalf("cookie evidence lost at %d fields: got %+v, want %+v", count, got, want)
				}
			})
		}
	}
}

func TestRunCookiesBeyondHTTPParserLimit(t *testing.T) {
	t.Setenv("GODEBUG", "httpcookiemaxnum=3000")
	engine, want := cookieLimitEngine(t)
	for _, count := range []int{3000, 3001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				for range count - 1 {
					writer.Header().Add("Set-Cookie", "a=b")
				}
				writer.Header().Add("Set-Cookie", "firewall=blocked; Path=/")
				writer.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			config := DefaultConfig()
			config.BaselineOnly = true
			calls := 0
			err := Run(context.Background(), engine, strings.NewReader(server.URL+"\n"), config, func(result Result) error {
				calls++
				if !reflect.DeepEqual(result.Outcome, want) {
					t.Errorf("admitted HTTP cookies lost: got %+v, want %+v", result.Outcome, want)
				}
				if len(result.Evidence) != 1 || result.Evidence[0].StatusCode != http.StatusOK || result.Evidence[0].ErrorCode != "" {
					t.Errorf("response exceeded default acquisition bounds: %+v", result.Evidence)
				}
				return nil
			})
			if err != nil || calls != 1 {
				t.Fatalf("baseline run: calls=%d err=%v", calls, err)
			}
		})
	}
}

func cookieLimitEngine(t *testing.T) (*Engine, Outcome) {
	t.Helper()
	engine, err := Compile([]WAF{{
		Name:    "cookie marker",
		Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Cookie", Pattern: "^firewall=blocked"}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := Outcome{State: Complete, Matches: []Match{{
		Product: "cookie marker", Schema: 1,
		Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}},
	}}}
	return engine, want
}
