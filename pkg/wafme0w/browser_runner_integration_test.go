//go:build linux && browser_integration

package wafme0w

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserRunnerIndependentOccurrencesAndSinkRelease(t *testing.T) {
	path := os.Getenv("WAFME0W_TEST_BROWSER")
	if path == "" {
		t.Fatal("WAFME0W_TEST_BROWSER must name native Chromium for browser integration")
	}
	var browserRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Sec-Fetch-Mode") == "navigate" {
			if r.URL.Path != "/favicon.ico" {
				browserRequests.Add(1)
			}
			fmt.Fprint(w, "<!doctype html><h1>browser-only marker</h1>")
		} else {
			fmt.Fprint(w, "<!doctype html><h1>http-only marker</h1>")
		}
	}))
	defer server.Close()
	engine, err := Compile([]WAF{{Name: "HTTP fixture", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "http-only marker"}}}}}, {Name: "Browser must not classify", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "browser-only marker"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	config := DefaultConfig()
	config.BaselineOnly = true
	config.Concurrency = 3
	config.Client = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/failure" {
			return nil, errors.New("owned HTTP acquisition failure")
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
	secondSink := make(chan struct{})
	var sinks atomic.Int32
	config.Browser = &BrowserConfig{Mode: "navigate", Path: path, Timeout: 8 * time.Second, Settle: 100 * time.Millisecond,
		SaveText: func(ctx context.Context, artifact BrowserArtifact) (string, error) {
			data, err := io.ReadAll(artifact.Content)
			if err != nil {
				return "", err
			}
			if !strings.Contains(string(data), "browser-only marker") {
				return "", errors.New("saved browser DOM missing")
			}
			switch sinks.Add(1) {
			case 1:
				select {
				case <-secondSink:
				case <-ctx.Done():
					return "", ctx.Err()
				}
			case 2:
				close(secondSink)
			}
			return "owned-artifact-" + artifact.CaptureID, nil
		},
	}
	var results []Result
	input := server.URL + "/failure\n" + server.URL + "/failure\n" + server.URL + "/normal\n"
	if err := Run(ctx, engine, strings.NewReader(input), config, func(result Result) error {
		results = append(results, result)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(results) != 3 || sinks.Load() != 3 || browserRequests.Load() != 3 {
		t.Fatalf("lost occurrence: results=%d sinks=%d browser=%d", len(results), sinks.Load(), browserRequests.Load())
	}
	ids := map[string]bool{}
	occurrences := map[uint64]bool{}
	for _, result := range results {
		b := result.Browser
		if b == nil || b.State != "complete" || b.DOM.SaveState != "saved" || b.Screenshot.State == "acquired" || b.Screenshot.Bytes != 0 {
			t.Fatalf("browser capture/export: %+v", b)
		}
		if ids[b.ID] || occurrences[b.Occurrence] {
			t.Fatalf("duplicate identity: %+v", b)
		}
		ids[b.ID], occurrences[b.Occurrence] = true, true
		for _, match := range result.Outcome.Matches {
			if match.Product != "HTTP fixture" {
				t.Fatalf("browser content altered deterministic matches: %+v", result.Outcome)
			}
		}
		if strings.HasSuffix(result.Target, "/normal") && len(result.Outcome.Matches) != 1 {
			t.Fatalf("HTTP match lost: %+v", result.Outcome)
		}
		if strings.HasSuffix(result.Target, "/failure") && len(result.Outcome.Matches) != 0 {
			t.Fatalf("failed HTTP acquisition gained browser matches: %+v", result.Outcome)
		}
	}
}
