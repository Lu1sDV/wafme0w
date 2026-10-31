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

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
)

func TestRunPlanExplainsSelectedLiveModeAndEffectiveLimits(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fast     bool
		baseline bool
		want     []string
	}{
		{name: "default deep", want: []string{"RUN PLAN  deep (7 probes)", "1 at a time"}},
		{name: "fast", fast: true, want: []string{"RUN PLAN  fast (3 requests)", "3 at a time"}},
		{name: "baseline", baseline: true, want: []string{"RUN PLAN  baseline (normal only)"}},
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
			for _, want := range append(tc.want, "20 workers", "5 requests/s global", "origin allowlist on", "5s/req", "30s/target", "JSONL", "JSON report", "strict") {
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

func TestDefaultRunPlanIsOneBriefLine(t *testing.T) {
	plan := runPlanText(newOptions(wafmeow.DefaultConfig()), wafmeow.DefaultConfig())
	if strings.Count(plan, "\n") != 1 || len(strings.TrimSuffix(plan, "\n")) >= 80 {
		t.Fatalf("default run plan must fit one 80-column line: %q", plan)
	}
	for _, redundant := range []string{"global in-flight", "redirects/request", "unlimited", "strict off", "HTTP limits", "output: human"} {
		if strings.Contains(plan, redundant) {
			t.Errorf("default plan contains redundant detail %q: %s", redundant, plan)
		}
	}
}

func TestCustomizedRunPlanShowsOnlyOverridesWithoutWrapping(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.MaxConnections, config.MaxRequests = 1, 4
	config.RedirectPolicy = "none"
	config.AllowedOrigins = []string{"https://private.invalid"}
	config.RequestsPerSecond, config.PerOriginRequestsPerSecond = 5, 2
	opts := newOptions(config)
	opts.OutputFile, opts.Strict = "/private/report.json", true
	plan := runPlanText(opts, config)
	for _, want := range []string{"1 in flight", "4 attempts/target", "redirects off", "origin allowlist on", "5 requests/s global", "2 requests/s per origin", "JSON report", "strict"} {
		if !strings.Contains(plan, want) {
			t.Errorf("missing customized setting %q: %s", want, plan)
		}
	}
	if strings.Contains(plan, "private.invalid") || strings.Contains(plan, "/private") {
		t.Fatalf("plan leaked sensitive values: %q", plan)
	}
	for _, line := range strings.Split(strings.TrimSuffix(plan, "\n"), "\n") {
		if len(line) >= 80 {
			t.Errorf("plan wraps on a normal terminal: %q", line)
		}
	}
}

func TestRunPlanAutomaticRequestCapAndBoundedDeepFanout(t *testing.T) {
	config := wafmeow.DefaultConfig()
	config.Concurrency, config.ProbeConcurrency, config.MaxConnections = 2, 8, 0
	var output bytes.Buffer
	if err := printRunPlan(&output, newOptions(config), config); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 workers", "8 in flight", "7 at a time"} {
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
		for _, want := range []string{"1 in flight", "redirects off"} {
			if !strings.Contains(output.String(), want) {
				t.Errorf("effective plan lacks %q: %s", want, output.String())
			}
		}
		if fast && !strings.Contains(output.String(), "1 at a time") {
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
		{format: "native", want: "2 workers"},
		{format: "httpx", want: "serial import"},
	} {
		t.Run(tc.format, func(t *testing.T) {
			config := wafmeow.DefaultConfig()
			opts := newOptions(config)
			opts.EvidenceFile, opts.EvidenceFormat = "/private/captures.jsonl", tc.format
			var output bytes.Buffer
			if err := printRunPlan(&output, opts, config); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"RUN PLAN  offline " + tc.format, "no network", tc.want} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("offline plan lacks %q: %s", want, output.String())
				}
			}
			for _, unwanted := range []string{"attempts/target", "requests/s", "5s/req", "1048576", "/private/"} {
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
