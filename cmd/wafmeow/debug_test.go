package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
)

func TestDebugPreservesRequestsAndEscapesDetails(t *testing.T) {
	result := wafmeow.Result{
		Target: "saved\nFORGED",
		Evidence: []wafmeow.EvidenceSummary{
			{Role: "Normal", StatusCode: 200, RequestURL: "https://example.test/", EffectiveURL: "https://www.example.test/", RedirectChain: []string{"https://www.example.test/"}},
			{Role: "Probe", ErrorCode: "transport_error", BlockedRedirectURL: "https://other.test/\x1b"},
		},
		Outcome: wafmeow.Outcome{Diagnostics: []wafmeow.Diagnostic{
			{Evidence: 1, Code: "transport_error", Message: "dial tcp: connection refused\nFORGED"},
			{Evidence: -1, Code: "target_timeout", Message: "deadline exceeded"},
		}},
	}
	var output bytes.Buffer
	if err := printDebug(&output, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"role=Normal status=200", "role=Probe status=0", "redirect=1 destination=https://www.example.test/", "blocked_redirect=https://other.test/\\x1b", "connection refused\\nFORGED", "evidence=-1 code=target_timeout"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, &output)
		}
	}
	if strings.Contains(output.String(), "\nFORGED") || strings.Contains(output.String(), "\x1b") {
		t.Fatalf("unsafe terminal output: %q", &output)
	}
	if err := printDebug(failedConsole{}, result); err == nil {
		t.Fatal("lost debug sink failure")
	}
}
