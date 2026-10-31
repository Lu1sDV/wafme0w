package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
)

func TestRunPlanExplainsSelectedLiveModeAndEffectiveLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fast     bool
		baseline bool
		want     []string
	}{
		{name: "default deep", want: []string{"RUN PLAN  deep", "normal request, then up to 7 probes", "probe concurrency: 1 after normal"}},
		{name: "fast", fast: true, want: []string{"RUN PLAN  fast", "normal, no-user-agent and combined probe", "per-target parallel request limit: 3"}},
		{name: "baseline", baseline: true, want: []string{"RUN PLAN  baseline", "normal request only", "1 request/target"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := wafmeow.DefaultConfig()
			config.FastMode, config.BaselineOnly = tc.fast, tc.baseline
			config.MaxConnections = 0
			config.RequestsPerSecond = 5
			opts := newOptions(config)
			opts.JSONL, opts.Strict = true, true
			opts.OutputFile = "/private/not-for-terminal.JSON"
			opts.Headers = []string{"Authorization: private-token"}
			config.Headers = []wafmeow.Header{{Name: "Authorization", Value: "private-token"}}
			opts.Target = "https://private.invalid/token"
			config.AllowedOrigins = []string{"https://private.invalid"}
			var output bytes.Buffer
			if err := printRunPlan(&output, opts, config); err != nil {
				t.Fatal(err)
			}
			for _, want := range append(tc.want, "target workers: 20", "global in-flight request limit: 20", "54 attempts/target", "5 redirects/request", "5 requests/s global", "5s/request", "30s/target", "include local rate/connection waits", "JSONL stdout", "atomic JSON report", "strict on") {
				if !strings.Contains(output.String(), want) {
					t.Errorf("plan lacks %q: %s", want, output.String())
				}
			}
			for _, secret := range []string{"private-token", "private.invalid", "not-for-terminal"} {
				if strings.Contains(output.String(), secret) {
					t.Errorf("plan leaked %q: %s", secret, output.String())
				}
			}
		})
	}
}

func TestRunPlanAutomaticRequestCapAndBoundedDeepFanout(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.Concurrency, config.ProbeConcurrency, config.MaxConnections = 2, 8, 0
	var output bytes.Buffer
	if err := printRunPlan(&output, newOptions(config), config); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"target workers: 2", "global in-flight request limit: 8", "probe concurrency: 7 after normal", "rate: unlimited"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("effective plan lacks %q: %s", want, output.String())
		}
	}
}

func TestRunPlanExplicitRequestCapAndDisabledRedirects(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.MaxConnections, config.RedirectPolicy = 1, "none"
	for _, fast := range []bool{false, true} {
		config.FastMode = fast
		var output bytes.Buffer
		if err := printRunPlan(&output, newOptions(config), config); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"global in-flight request limit: 1", "0 redirects/request (none)", "origin allowlist: off"} {
			if !strings.Contains(output.String(), want) {
				t.Errorf("effective plan lacks %q: %s", want, output.String())
			}
		}
		if fast && !strings.Contains(output.String(), "per-target parallel request limit: 1") {
			t.Errorf("fast plan ignores the global cap: %s", output.String())
		}
	}
}

func TestRunPlanOfflineWorkerCountsAndInactiveControls(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	for _, tc := range []struct {
		format string
		want   string
	}{
		{format: "native", want: "classification workers: 2 (requested 20; CPU cap 2)"},
		{format: "httpx", want: "1 classification worker (httpx import is serial)"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			config := wafmeow.DefaultConfig()
			opts := newOptions(config)
			opts.EvidenceFile, opts.EvidenceFormat = "/private/captures.jsonl", tc.format
			var output bytes.Buffer
			if err := printRunPlan(&output, opts, config); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"RUN PLAN  offline " + tc.format, "no network requests", tc.want, "live HTTP timeouts, rate, redirects and connection controls: inactive", "1048576 bytes/body"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("offline plan lacks %q: %s", want, output.String())
				}
			}
			for _, unwanted := range []string{"target workers", "requests/s", "5s/request", "/private/"} {
				if strings.Contains(output.String(), unwanted) {
					t.Errorf("offline plan implies active acquisition or leaks input: %s", output.String())
				}
			}
		})
	}
}

func TestRunPlanSilenceAndOutputErrors(t *testing.T) {
	config := wafmeow.DefaultConfig()
	opts := newOptions(config)
	opts.Silent = true
	if err := printRunPlan(failedConsole{}, opts, config); err != nil {
		t.Fatalf("silent plan wrote to output: %v", err)
	}
	opts.Silent = false
	if err := printRunPlan(failedConsole{}, opts, config); err == nil {
		t.Fatal("plan swallowed writer failure")
	}
	if err := printRunPlan(shortPlanWriter{}, opts, config); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("plan swallowed short write: %v", err)
	}
}

func TestCLIRunPlanKeepsJSONLAndSilentContracts(t *testing.T) {
	for _, silent := range []bool{false, true} {
		args := []string{"--target=invalid://fixture", "--fast", "--jsonl"}
		if silent {
			args = append(args, "--silent")
		}
		code, stdout, stderr := runCLI(t, nil, args...)
		if code != 0 || len(decodeResultLines(t, stdout)) != 1 {
			t.Fatalf("plan polluted result stream: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if silent && stderr != "" || !silent && !strings.Contains(stderr, "RUN PLAN  fast") {
			t.Fatalf("plan ignored human output selection: silent=%t stderr=%q", silent, stderr)
		}
	}
}

func TestCLIRunPlanFailureStopsBeforeRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	var stdout bytes.Buffer
	code := runContext(context.Background(), []string{"--target", server.URL, "--baseline", "--jsonl"}, nil, false, &stdout, failedConsole{})
	if code != 1 || calls.Load() != 0 || stdout.Len() != 0 {
		t.Fatalf("failed plan publication started acquisition: exit=%d requests=%d stdout=%q", code, calls.Load(), stdout.String())
	}
}

func TestRunPlanDisclosesUserAgentOverrideWithoutValue(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.FastMode = true
	config.Headers = []wafmeow.Header{{Name: "user-agent", Value: "private-client"}}
	var output bytes.Buffer
	if err := printRunPlan(&output, newOptions(config), config); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "custom User-Agent overrides every probe") || strings.Contains(output.String(), "private-client") {
		t.Fatalf("misleading probe plan or leaked header: %s", output.String())
	}
}

type shortPlanWriter struct{}

func (shortPlanWriter) Write(data []byte) (int, error) { return len(data) / 2, nil }
