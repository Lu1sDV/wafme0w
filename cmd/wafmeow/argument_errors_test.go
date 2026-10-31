package main

import (
	"strings"
	"testing"
)

func TestCLIArgumentRecoveryHints(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"positional URL", []string{"http://127.0.0.1:1"}, []string{"positional", "--target URL", "--target-file FILE"}},
		{"positional after delimiter", []string{"--", "http://127.0.0.1:1"}, []string{"positional", "--target URL"}},
		{"transposed mode", []string{"--fats"}, []string{"unknown flag", "--fast"}},
		{"lowercase output", []string{"-o", "report.json"}, []string{"unknown flag", "--output", "-O"}},
		{"lowercase input", []string{"-i", "targets.txt"}, []string{"unknown flag", "--target-file", "-I"}},
		{"plural header", []string{"--headers", "X-Tag: fixture"}, []string{"unknown flag", "--header"}},
		{"unrecognized option", []string{"--unrelated-unknown-option"}, []string{"unknown flag", "--help"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--target=invalid://fixture", "--jsonl", "--silent"}, tc.args...)
			code, stdout, stderr := runCLI(t, nil, args...)
			if code != 1 || stdout != "" {
				t.Fatalf("recovery hint must not accept or execute the command: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("missing recovery %q in %q", want, stderr)
				}
			}
		})
	}
}

func TestCLIArgumentRecoveryKeepsTerminalEscaping(t *testing.T) {
	for _, arg := range []string{"--unknown\x1b[31m", "http://127.0.0.1:1/\x1b[31m"} {
		code, stdout, stderr := runCLI(t, nil, arg)
		if code != 1 || stdout != "" || strings.ContainsRune(stderr, '\x1b') || !strings.Contains(stderr, "\\x1b") {
			t.Fatalf("argument diagnostic was not safely escaped: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	}
}

func TestCLIHeaderRecoveryGuidance(t *testing.T) {
	for _, header := range []string{
		"Accept: text/html, application/json",
		`If-None-Match: "abc"`,
		"Authorization: Bearer do-not-echo, application/json",
	} {
		t.Run(header, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, "--target=invalid://fixture", "--jsonl", "--silent", "-H", header)
			if code != 1 || stdout != "" {
				t.Fatalf("malformed CSV must remain rejected: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, want := range []string{"--header", "CSV", `-H '"Accept: text/html, application/json"'`, "POSIX"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("missing header recovery %q in %q", want, stderr)
				}
			}
			if strings.Contains(stderr, "do-not-echo") {
				t.Fatal("header diagnostic echoed a credential value")
			}
		})
	}
}

func TestCLIFlagSpecificLimitErrors(t *testing.T) {
	for _, tc := range []struct {
		arg  string
		want []string
	}{
		{"--max-body-bytes=0", []string{"--max-body-bytes", "positive"}},
		{"--max-requests=0", []string{"--max-requests", "positive"}},
		{"--max-connections=-1", []string{"--max-connections", "0", "automatic"}},
		{"--probe-concurrency=0", []string{"--probe-concurrency", "1", "8"}},
		{"--journal-batch-size=0", []string{"--journal-batch-size", "1", "256"}},
		{"--max-response-header-bytes=-1", []string{"--max-response-header-bytes", "0", "default"}},
		{"--max-target-evidence-bytes=-1", []string{"--max-target-evidence-bytes", "0", "default"}},
		{"--request-timeout=0s", []string{"--request-timeout", "positive", "5s"}},
		{"--target-timeout=0s", []string{"--target-timeout", "positive", "30s"}},
		{"--max-redirects=-1", []string{"--max-redirects", "0", "none"}},
		{"--rate=NaN", []string{"--rate", "finite", "0"}},
		{"--per-origin-rate=+Inf", []string{"--per-origin-rate", "finite", "0"}},
		{"--redirect-policy=elsewhere", []string{"--redirect-policy", "canonical-host", "same-origin", "none", "allowlist"}},
		{"--redirect-policy=allowlist", []string{"--redirect-policy=allowlist", "--allow-origin"}},
	} {
		t.Run(tc.arg, func(t *testing.T) {
			// Informational mode reaches validation without starting acquisition
			// or opening journals for the explicitly invalid options.
			code, stdout, stderr := runCLI(t, nil, "--version", tc.arg)
			if code != 1 || stdout != "" {
				t.Fatalf("invalid limit accepted: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr, want) {
					t.Errorf("missing limit guidance %q in %q", want, stderr)
				}
			}
		})
	}
}

func TestCLINativeReportInputGuidance(t *testing.T) {
	const report = `{"schema_version":1,"target":"report","outcome":{"state":"complete"}}` + "\n"
	const capture = `{"target":"saved-before-report","evidence":[{"role":"Normal","status_code":204}]}` + "\n"
	for _, prefix := range []string{"", capture} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, strings.NewReader(prefix+report), "--evidence=-", "--jsonl", "--silent")
			if code != 1 {
				t.Fatalf("result report accepted as capture: exit=%d stderr=%q", code, stderr)
			}
			for _, want := range []string{`unknown field "schema_version"`, "result report", "--evidence", "--evidence-format=httpx"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("missing capture recovery %q in %q", want, stderr)
				}
			}
			if prefix == "" {
				if stdout != "" {
					t.Fatalf("rejected first record emitted stdout: %q", stdout)
				}
			} else if got := decodeResultLines(t, stdout); len(got) != 1 || got[0].Target != "saved-before-report" {
				t.Fatalf("valid earlier capture was not preserved: %+v", got)
			}
		})
	}
	code, stdout, stderr := runCLI(t, strings.NewReader(`{"target":"capture","evidence":[],"unrelated":true}`), "--evidence=-", "--jsonl", "--silent")
	if code != 1 || stdout != "" || strings.Contains(stderr, "result report") {
		t.Fatalf("unrelated unknown field misidentified as result report: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
