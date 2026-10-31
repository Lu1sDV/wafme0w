package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestCLIQuotedFirstHeaderPreservesCSV(t *testing.T) {
	requests := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, header := range []string{
		`"Accept: text/plain, application/json"`,
		`"Accept: text/plain, application/json", X-Tag: fixture`,
		`"Accept: text/plain, application/json", "X-Tag: say ""hello"""`,
	} {
		t.Run(header, func(t *testing.T) {
			code, _, stderr := runCLI(t, nil, "--target", server.URL, "--baseline", "--jsonl", "--silent", "-H", header)
			if code != 0 || stderr != "" {
				t.Fatalf("quoted first header rejected: exit=%d stderr=%q", code, stderr)
			}
			select {
			case got := <-requests:
				if got.Get("Accept") != "text/plain, application/json" {
					t.Fatalf("quoted header changed on wire: %v", got)
				}
				if strings.Contains(header, "fixture") && got.Get("X-Tag") != "fixture" || strings.Contains(header, "hello") && got.Get("X-Tag") != `say "hello"` {
					t.Fatalf("CSV quoting changed on wire: %v", got)
				}
			default:
				t.Fatal("baseline request missing")
			}
		})
	}
}

func TestCLIRejectsInactiveOptionDependencies(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--browser-timeout=1s"}, "requires --browser"},
		{[]string{"--browser-settle=1s"}, "requires --browser"},
		{[]string{"--browser=off", "--browser-timeout=30s"}, "requires --browser"},
		{[]string{"--journal-batch-size=8"}, "requires --diagnostics-journal"},
		{[]string{"--fast", "--probe-concurrency=2"}, "deep mode"},
		{[]string{"--baseline", "--probe-concurrency=2"}, "deep mode"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			args := append([]string{"--target=invalid://fixture", "--jsonl", "--silent"}, tc.args...)
			code, stdout, stderr := runCLI(t, nil, args...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Fatalf("ineffective option accepted: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCLIRejectsExcessiveConcurrencyWithoutPanic(t *testing.T) {
	for _, value := range []string{"65537", "2147483648", "9223372036854775807"} {
		t.Run(value, func(t *testing.T) {
			// Informational mode exercises CLI validation without ever creating
			// the excessive number of workers on a failing implementation.
			code, stdout, stderr := runCLI(t, nil, "--version", "--concurrency="+value)
			if code != 1 || stdout != "" || !strings.Contains(stderr, "concurrency") || strings.Contains(stderr, "panic") {
				t.Fatalf("unbounded concurrency accepted: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCLIHelpShowsWorkflowAndGroups(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"-h"}} {
		var stdout, stderr bytes.Buffer
		code := runContext(context.Background(), args, nil, false, &stdout, &stderr)
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("help: exit=%d stderr=%q", code, stderr.String())
		}
		for _, want := range []string{"--fast", "--deep", "Input:", "Scan modes:", "HTTP requests:", "Rate and concurrency:", "Evidence limits:", "Output:", "Offline import and matching:", "Diagnostics and journals:", "Browser:", "Information:", "Examples:", "--evidence captures.jsonl", "Exit codes:", "--strict"} {
			if !strings.Contains(stdout.String(), want) {
				t.Errorf("help omits %q", want)
			}
		}
		// The CLI documents portable --name=VALUE syntax on every platform;
		// keep accepting go-flags' native Windows form in this contract check.
		for name, value := range map[string]string{"target": "URL", "target-file": "FILE", "input": "FILE", "output": "FILE"} {
			posix, windows := "--"+name+"="+value, "/"+name+":"+value
			if !strings.Contains(stdout.String(), posix) && !strings.Contains(stdout.String(), windows) {
				t.Errorf("help omits %s with value name %s", name, value)
			}
		}
	}
}

func TestCLITargetKeepsLiteralShellQuotes(t *testing.T) {
	value := `"invalid://quoted"`
	code, stdout, stderr := runCLI(t, nil, "--target", value, "--jsonl", "--silent")
	if code != 0 || stderr != "" {
		t.Fatalf("literal argument: exit=%d stderr=%q", code, stderr)
	}
	assertCLIContractTargets(t, stdout, []string{value})
}

func TestCLIDetectionModesKeepProbeSelectionAndProvenance(t *testing.T) {
	deepRoles := []string{"Normal", "NoUserAgent", "NonExistent", "XssAttack", "XxeAttack", "LfiAttack", "CentralAttack", "JndiAttack"}
	for _, tc := range []struct {
		name     string
		flags    []string
		wantMode string
		wantFast bool
		roles    []string
	}{
		{"default deep", nil, "deep", false, deepRoles},
		{"explicit deep", []string{"--deep"}, "deep", false, deepRoles},
		{"parallel deep", []string{"--deep", "--probe-concurrency=4"}, "deep", false, deepRoles},
		{"fast", []string{"--fast"}, "fast", true, []string{"Normal", "NoUserAgent", "CentralAttack"}},
		{"baseline", []string{"--baseline"}, "baseline", false, []string{"Normal"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			args := append([]string{"--target", server.URL, "--jsonl", "--silent", "--max-redirects=0"}, tc.flags...)
			code, stdout, stderr := runCLI(t, nil, args...)
			if code != 0 || stderr != "" {
				t.Fatalf("mode %s: exit=%d stderr=%q", tc.name, code, stderr)
			}
			results := decodeResultLines(t, stdout)
			if len(results) != 1 {
				t.Fatalf("mode %s: got %d results, want one", tc.name, len(results))
			}
			got := results[0]
			if got.Provenance.ScanMode != tc.wantMode || got.Provenance.Settings.FastMode != tc.wantFast {
				t.Fatalf("mode %s: incorrect provenance: %+v", tc.name, got.Provenance)
			}
			var roles []string
			for _, evidence := range got.Evidence {
				roles = append(roles, evidence.Role)
			}
			if !slices.Equal(roles, tc.roles) {
				t.Fatalf("mode %s: evidence roles %q, want %q", tc.name, roles, tc.roles)
			}
		})
	}
}
