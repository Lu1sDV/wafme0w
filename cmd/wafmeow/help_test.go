package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestCLIHelpPutsTasksBeforeReference(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "--help")
	if code != 0 || stderr != "" {
		t.Fatalf("help: exit=%d stderr=%q", code, stderr)
	}
	firstExample := strings.Index(stdout, "wafmeow --target URL --fast")
	firstOption := strings.Index(stdout, "--target=URL")
	if firstExample < 0 || firstOption < 0 || firstExample > firstOption {
		t.Fatalf("a quick human scan must precede the flag reference:\n%s", stdout)
	}
	if lines := strings.Count(stdout[:firstExample], "\n"); lines > 18 {
		t.Fatalf("first runnable example is below the opening screen: line %d", lines+1)
	}
	for _, want := range []string{
		"wafmeow --target URL [--target URL ...] [OPTIONS]",
		"wafmeow --target-file FILE|- [OPTIONS]",
		"wafmeow --evidence FILE|- [OPTIONS]",
		"Choose one input source", "choose one live mode", "default: --deep",
		"captures, not result reports", "Empty input succeeds",
		"https://github.com/Lu1sDV/wafmeow/blob/main/docs/usage.md",
	} {
		if !strings.Contains(strings.Join(strings.Fields(stdout), " "), want) {
			t.Errorf("help omits workflow contract %q", want)
		}
	}
	if strings.Index(stdout, "Output:") > strings.Index(stdout, "HTTP requests:") {
		t.Error("output selection must precede request tuning")
	}
}

func TestCLIHelpRecoversFromArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--unknown", "--help"}, {"--concurrency=abc", "-h"},
		{"--target", "--help"}, {"--browser-path=/missing", "--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, args...)
			if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage:") {
				t.Fatalf("help should remain available: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCLIHelpDoesNotReinterpretLiteralValues(t *testing.T) {
	for _, args := range [][]string{{"--", "--help"}, {"--header=--help"}, {"--help=false"}} {
		code, stdout, stderr := runCLI(t, nil, args...)
		if code != 1 || stdout != "" || stderr == "" {
			t.Fatalf("literal/invalid help argument %q: exit=%d stdout=%q stderr=%q", args, code, stdout, stderr)
		}
	}
}

func TestCLIHelpShowsDefaultsWithoutSuppliedSecrets(t *testing.T) {
	var stdout, stderr bytes.Buffer
	args := []string{"--concurrency=42", "--header=Authorization: private-fixture", "--help"}
	code := runContext(context.Background(), args, nil, false, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 || !strings.Contains(stdout.String(), "(default: 20)") {
		t.Fatalf("help lost defaults: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "private-fixture") || strings.Contains(stdout.String(), "(default: 42)") {
		t.Fatal("help displayed supplied values as defaults")
	}
}

func TestCLIHelpDescribesSharedLimitsAndDeadlineWaits(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "--help")
	if code != 0 || stderr != "" {
		t.Fatalf("help: exit=%d stderr=%q", code, stderr)
	}
	normalized := strings.Join(strings.Fields(stdout), " ")
	for _, want := range []string{"live responses and httpx imports", "including local rate/connection waits", "Matches alone do not fail"} {
		if !strings.Contains(normalized, want) {
			t.Errorf("help omits scope %q", want)
		}
	}
}

func TestCLIHelpReadableAtNarrowWidths(t *testing.T) {
	for _, width := range []int{60, 80, 120} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var output bytes.Buffer
			if err := writeHelpWidth(&output, width); err != nil {
				t.Fatal(err)
			}
			for i, line := range strings.Split(output.String(), "\n") {
				if len(line) > width {
					t.Errorf("line %d exceeds %d columns (%d): %s", i+1, width, len(line), line)
				}
			}
			for _, option := range []string{"--httpx-response-encoding=ENCODING", "--max-response-header-bytes=BYTES", "--max-target-evidence-bytes=BYTES"} {
				if !strings.Contains(output.String(), option) {
					t.Errorf("long option lost or broken across lines: %s", option)
				}
			}
		})
	}
}
