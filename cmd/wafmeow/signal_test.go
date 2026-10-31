package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
)

func signalResult(state wafmeow.EvaluationState) wafmeow.Result {
	return wafmeow.Result{
		Target:   "https://fixture.invalid/",
		Outcome:  wafmeow.Outcome{State: state},
		Evidence: []wafmeow.EvidenceSummary{{Role: "Normal", RequestURL: "https://fixture.invalid/", StatusCode: 200}},
	}
}

func TestSignalHumanOutcomeDistinctions(t *testing.T) {
	for _, test := range []struct {
		name        string
		state       wafmeow.EvaluationState
		matched     bool
		generic     wafmeow.GenericDetection
		diagnostics []wafmeow.Diagnostic
		browser     *wafmeow.BrowserReport
		want        string
	}{
		{name: "clean complete", state: wafmeow.Complete, want: "NO WAF MATCH"},
		{name: "complete named", state: wafmeow.Complete, matched: true, want: "WAF MATCH"},
		{name: "incomplete named", state: wafmeow.Incomplete, matched: true, want: "WAF MATCH"},
		{name: "failed named is error", state: wafmeow.Failed, matched: true, want: "ERROR"},
		{name: "incomplete unnamed", state: wafmeow.Incomplete, want: "INCOMPLETE"},
		{name: "failed unnamed", state: wafmeow.Failed, want: "ERROR"},
		{name: "unknown state is not clean", want: "INCOMPLETE"},
		{name: "response difference", state: wafmeow.Complete, generic: wafmeow.GenericDetection{Mode: wafmeow.ChangeInStatus}, want: "REVIEW"},
		{name: "reason only", state: wafmeow.Complete, generic: wafmeow.GenericDetection{Reason: "unusual response"}, want: "REVIEW"},
		{name: "HTTP diagnostic", state: wafmeow.Complete, diagnostics: []wafmeow.Diagnostic{{Code: "transport_error"}}, want: "REVIEW"},
		{name: "browser-prefixed HTTP diagnostic", state: wafmeow.Complete, diagnostics: []wafmeow.Diagnostic{{Code: "browser_capture_failed"}}, want: "REVIEW"},
		{name: "browser-named HTTP diagnostic", state: wafmeow.Complete, diagnostics: []wafmeow.Diagnostic{{Code: "browser"}}, want: "REVIEW"},
		{name: "mixed diagnostics", state: wafmeow.Complete, diagnostics: []wafmeow.Diagnostic{{Code: "browser_export_failed"}, {Code: "body_truncated"}}, want: "REVIEW"},
		{name: "browser failure separate", state: wafmeow.Complete, browser: &wafmeow.BrowserReport{State: "failed"}, want: "NO WAF MATCH"},
		{name: "incomplete before review", state: wafmeow.Incomplete, generic: wafmeow.GenericDetection{Mode: wafmeow.ChangeInStatus}, want: "INCOMPLETE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := signalResult(test.state)
			result.Generic, result.Outcome.Diagnostics, result.Browser = test.generic, test.diagnostics, test.browser
			if test.matched {
				result.Outcome.Matches = []wafmeow.Match{{Product: "Fixture WAF"}}
			}
			if got := humanOutcome(result); got != test.want {
				t.Fatalf("humanOutcome() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSignalCapturedHTTPDiagnosticCannotBecomeBrowserFailure(t *testing.T) {
	catalogue := filepath.Join(t.TempDir(), "catalogue.json")
	if err := os.WriteFile(catalogue, []byte(`[{"name":"Fixture","schemas":[{"fingerprints":[{"type":"Status","pattern":"403"}]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	const cause = "saved HTTP body acquisition failed"
	for _, diagnosticCode := range []string{"browser_capture_failed", "browser"} {
		for _, suppressWarnings := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/no-warning=%t", diagnosticCode, suppressWarnings), func(t *testing.T) {
				input := captureLines(t, wafmeow.Capture{
					Target: "saved HTTP response",
					Evidence: []wafmeow.Evidence{{
						Role: "Normal", StatusCode: 200, ErrorCode: diagnosticCode, TransportError: cause,
					}},
				})
				args := []string{"--evidence=-", "--fingerprints", catalogue, "--no-colors"}
				if suppressWarnings {
					args = append(args, "--no-warning")
				}
				var stdout, stderr bytes.Buffer
				if code := runContext(context.Background(), args, strings.NewReader(input), true, &stdout, &stderr); code != 0 {
					t.Fatalf("capture run failed: code=%d stderr=%q", code, stderr.String())
				}
				for _, want := range []string{"[ REVIEW ]", "HTTP diagnostics need review", "HTTP  1 observation: 200", "evidence  complete"} {
					if !strings.Contains(stdout.String(), want) {
						t.Fatalf("HTTP diagnostic lost %q: %q", want, stdout.String())
					}
				}
				for _, want := range []string{"NO WAF MATCH | 0", "REVIEW       | 1", "HTTP diagnostics 1"} {
					if !strings.Contains(stderr.String(), want) {
						t.Fatalf("HTTP summary lost %q: %q", want, stderr.String())
					}
				}
				if strings.Contains(stdout.String(), "[ NO WAF MATCH ]") || strings.Contains(stdout.String(), "   browser  ") ||
					strings.Contains(stderr.String(), "[browser]") || strings.Contains(stderr.String(), "browser/artifact failures") {
					t.Fatalf("HTTP diagnostic became a browser result: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if suppressWarnings {
					if strings.Contains(stderr.String(), "WARN") || strings.Contains(stderr.String(), cause) {
						t.Fatalf("suppressed HTTP warning leaked: %q", stderr.String())
					}
				} else if !diagnosticRow(stderr.String(), "Normal", cause) {
					t.Fatalf("HTTP warning lost its observation role: %q", stderr.String())
				}
			})
		}
	}
}

// diagnosticRow reports whether output contains role's tag followed by text on
// the same row, tolerating the alignment padding between tag and description.
func diagnosticRow(output, role, text string) bool {
	tag := "[" + role + "]"
	for _, line := range strings.Split(output, "\n") {
		if index := strings.Index(line, tag); index >= 0 && strings.Contains(line[index+len(tag):], text) {
			return true
		}
	}
	return false
}

func TestSignalDiagnosticsFollowStderrColorSupport(t *testing.T) {
	result := signalResult(wafmeow.Complete)
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Code: "fixture_diagnostic", Message: "inspect HTTP evidence"}}
	var stdout, stderr bytes.Buffer
	au := aurora.New(aurora.WithColors(true))
	if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false)), au); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprint(au.Bold(au.Yellow("WARN"))); !strings.HasPrefix(stderr.String(), want+"  ") {
		t.Fatalf("warning label did not use the stderr colorizer: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), fmt.Sprint(au.Cyan("[Normal]"))) {
		t.Fatalf("probe role tag was not colorized: %q", stderr.String())
	}
	if strings.Contains(stdout.String(), "\x1b") {
		t.Fatalf("stderr color setting styled stdout: %q", stdout.String())
	}
}

func TestSignalOutcomeColors(t *testing.T) {
	au := aurora.New(aurora.WithColors(true))
	for _, test := range []struct {
		name    string
		state   wafmeow.EvaluationState
		matched bool
		review  bool
		label   string
		color   aurora.Color
	}{
		{name: "matched red", state: wafmeow.Complete, matched: true, label: "WAF MATCH", color: aurora.RedFg},
		{name: "matched incomplete remains red", state: wafmeow.Incomplete, matched: true, label: "WAF MATCH", color: aurora.RedFg},
		{name: "clean green", state: wafmeow.Complete, label: "NO WAF MATCH", color: aurora.GreenFg},
		{name: "error red", state: wafmeow.Failed, label: "ERROR", color: aurora.RedFg},
		{name: "incomplete amber", state: wafmeow.Incomplete, label: "INCOMPLETE", color: aurora.YellowFg},
		{name: "review amber", state: wafmeow.Complete, review: true, label: "REVIEW", color: aurora.YellowFg},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := signalResult(test.state)
			if test.matched {
				result.Outcome.Matches = []wafmeow.Match{{Product: "Fixture WAF", Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 0}}}}
			}
			if test.review {
				result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Code: "fixture_diagnostic", Message: "inspect HTTP evidence"}}
			}
			var stdout, stderr bytes.Buffer
			if err := printResult(&stdout, &stderr, result, false, au, aurora.New(aurora.WithColors(false))); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprint(au.Bold(au.Colorize("[ "+test.label+" ]", test.color)))
			if !strings.HasPrefix(stdout.String(), want+"  ") {
				t.Fatalf("wrong label or color: %q, want prefix %q", stdout.String(), want)
			}
			evidenceState := string(test.state)
			switch test.state {
			case wafmeow.Incomplete:
				evidenceState = fmt.Sprint(au.Yellow(evidenceState))
			case wafmeow.Failed:
				evidenceState = fmt.Sprint(au.Red(evidenceState))
			}
			if !strings.Contains(stdout.String(), "evidence  "+evidenceState+"\n") {
				t.Fatalf("evidence state did not retain independent styling: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), "\x1b") {
				t.Fatalf("stdout color setting styled redirected diagnostics: %q", stderr.String())
			}
		})
	}
}

func TestSignalMatchedObservationsAreAttributedPerProduct(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Evidence = []wafmeow.EvidenceSummary{
		{Index: 91, Role: "Normal", StatusCode: 200, RequestURL: result.Target},
		{Index: 72, Role: "Probe", StatusCode: 403, RequestURL: result.Target + "?payload=recorded"},
		{Index: 53, Role: "Saved", StatusCode: 302, RequestURL: result.Target + "old", EffectiveURL: result.Target + "new", BodyTruncated: true},
	}
	result.Outcome.Matches = []wafmeow.Match{
		{Product: "Alpha", Fingerprints: []wafmeow.FingerprintMatch{{Fingerprint: 1, Evidence: 2}, {Fingerprint: 2, Evidence: 0}, {Fingerprint: 3, Evidence: 2}}},
		{Product: "Beta", Fingerprints: []wafmeow.FingerprintMatch{{Fingerprint: 1, Evidence: 1}}},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	text := stdout.String()
	alpha := "  Alpha\n    matched  #1 [Normal] HTTP 200\n    matched  #3 [Saved] HTTP 302 " + result.Target + "old -> " + result.Target + "new\n"
	beta := "  Beta\n    matched  #2 [Probe] HTTP 403 " + result.Target + "?payload=recorded\n"
	for _, want := range []string{"[ WAF MATCH ]", alpha, beta, "HTTP  3 observations: 200 / 403 / 302", "evidence  incomplete (1 truncated body)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
	}
	if strings.Count(text, "#3 [Saved]") != 1 || strings.Contains(text, "#92") || result.Outcome.Matches[0].Fingerprints[0].Evidence != 2 {
		t.Fatalf("support was duplicated, invented or mutated: %q", text)
	}
	for _, invented := range []string{"caused", "blocked by", " ms", " KiB", " req"} {
		if strings.Contains(text, invented) {
			t.Fatalf("invented acquisition/enforcement claim %q: %q", invented, text)
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %q", stderr.String())
	}
}

func TestHumanCompactSingleMatchKeepsSupportingEvidenceAndUncertainty(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Target = "https://www.cloudflare.com"
	result.Evidence = []wafmeow.EvidenceSummary{
		{Role: "Normal", StatusCode: 200, RequestURL: result.Target, BodyTruncated: true},
		{Role: "NoUserAgent", StatusCode: 200, BodyTruncated: true},
		{Role: "XssAttack", StatusCode: 403},
		{Role: "LfiAttack", StatusCode: 403, BodyTruncated: true},
		{Role: "CentralAttack", StatusCode: 404},
	}
	result.Outcome.Matches = []wafmeow.Match{{Product: "Cloudflare (Cloudflare Inc.)",
		Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 0}}}}
	result.Generic = wafmeow.GenericDetection{
		Mode: wafmeow.ChangeInStatus, BeforeStatus: 200, AfterStatus: 403,
		RequestType: "XssAttack", Reason: "status changed from 200 to 403 for \"XssAttack\"",
	}
	var out bytes.Buffer
	if err := printResult(&out, io.Discard, result, true,
		aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"[ WAF MATCH ]  https://www.cloudflare.com",
		"  Cloudflare (Cloudflare Inc.)\n    matched  #1 [Normal] HTTP 200",
		"    review  HTTP 200 → 403 on XssAttack (unusual response)",
		"    HTTP  5 observations: 200×2 / 403×2 / 404",
		"    evidence  incomplete (3 truncated bodies)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("compact human result lost %q: %q", want, got)
		}
	}
	if strings.Count(got, result.Target) != 1 || strings.Contains(got, "status changed from") {
		t.Fatalf("human result repeated target or expanded generic reason: %q", got)
	}
}

func TestHumanNestedWarningsGroupRepeatedReasonsByProbe(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Evidence = []wafmeow.EvidenceSummary{
		{Role: "Normal", StatusCode: 200, BodyTruncated: true},
		{Role: "NoUserAgent", StatusCode: 200, BodyTruncated: true},
		{Role: "LfiAttack", StatusCode: 200, BodyTruncated: true},
	}
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{
		{Code: "body_truncated", Evidence: 0, Message: "response body is incomplete"},
		{Code: "body_truncated", Evidence: 1, Message: "response body is incomplete"},
		{Code: "body_truncated", Evidence: 2, Message: "response body is incomplete"},
	}
	var stderr bytes.Buffer
	au := aurora.New(aurora.WithColors(false))
	if err := printNestedResultDiagnostics(&stderr, result, au, "    "); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	for _, want := range []string{
		"    WARN  response body is incomplete",
		"[Normal], [NoUserAgent], [LfiAttack]",
		"\n\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("nested warning lost %q: %q", want, got)
		}
	}
	if strings.Count(got, "WARN") != 1 || strings.Count(got, "response body is incomplete") != 1 ||
		strings.Contains(got, result.Target) {
		t.Fatalf("nested warnings repeat the target or duplicate the reason: %q", got)
	}
	// A redirected stderr still identifies its target, independent of stdout.
	stderr.Reset()
	if err := printResultDiagnostics(&stderr, result, au); err != nil ||
		!strings.Contains(stderr.String(), "WARN  "+result.Target) {
		t.Fatalf("standalone diagnostics must identify the target: %s / %v", &stderr, err)
	}
}

func TestHumanNestedWarningsKeepDistinctCausesAndEscapeRoles(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Evidence = []wafmeow.EvidenceSummary{
		{Role: "Normal"}, {Role: "Probe"}, {Role: "a\nINJECT"},
	}
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{
		{Code: "transport_error", Evidence: 0, Message: "connection failed"},
		{Code: "transport_error", Evidence: 1, Message: "TLS failed"},
		{Code: "transport_error", Evidence: 2, Message: "other"},
	}
	var stderr bytes.Buffer
	if err := printNestedResultDiagnostics(&stderr, result, aurora.New(aurora.WithColors(false)), "  "); err != nil {
		t.Fatal(err)
	}
	got := stderr.String()
	for _, want := range []string{
		"  WARN  [Normal] connection failed",
		"  WARN  [Probe] TLS failed",
		"  WARN  [a\\nINJECT] other",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("distinct diagnostic lost %q: %q", want, got)
		}
	}
	if strings.Count(got, "WARN") != 3 || strings.Contains(got, "\nINJECT") {
		t.Fatalf("lost diagnostics or unescaped controls: %q", got)
	}
}

func TestSignalMissingSupportingObservationIsNotInvented(t *testing.T) {
	result := signalResult(wafmeow.Complete)
	result.Outcome.Matches = []wafmeow.Match{{Product: "Fixture", Fingerprints: []wafmeow.FingerprintMatch{{Evidence: -1}, {Evidence: 4}}}}
	var stdout bytes.Buffer
	if err := printResult(&stdout, io.Discard, result, false, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "matched  supporting observation unavailable") || strings.Contains(stdout.String(), "#0") || strings.Contains(stdout.String(), "#5") {
		t.Fatalf("missing reference became invented support: %q", stdout.String())
	}
}

func TestSignalSuppressedWarningsKeepReviewAndBrowserState(t *testing.T) {
	result := signalResult(wafmeow.Complete)
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Code: "transport_error", Message: "private diagnostic"}}
	result.Browser = &wafmeow.BrowserReport{
		State: "failed", Mode: "text", Reason: "browser_failed", Error: "private browser cause",
		DOM: wafmeow.BrowserAsset{State: "not_acquired", SaveState: "failed"}, Screenshot: wafmeow.BrowserAsset{State: "not_selected"},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, true, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[ REVIEW ]", "HTTP diagnostics need review", "evidence  complete", "browser  failed (text)", "separate from HTTP", "text save failed"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("warning suppression lost %q: %q", want, stdout.String())
		}
	}
	if stderr.Len() != 0 || strings.Contains(stdout.String(), "private") {
		t.Fatalf("warning suppression leaked diagnostics: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestSignalCertificateGuidancePreservesCauseAndOtherEvidence(t *testing.T) {
	for _, test := range []struct {
		name  string
		cause string
		code  string
		want  string
	}{
		{name: "private CA", cause: "tls: failed to verify certificate: x509: certificate signed by unknown authority", want: "if a private CA is expected, on Linux set SSL_CERT_FILE to an approved CA bundle"},
		{name: "browser-prefixed HTTP private CA", code: "browser_capture_failed", cause: "tls: failed to verify certificate: x509: certificate signed by unknown authority", want: "if a private CA is expected, on Linux set SSL_CERT_FILE to an approved CA bundle"},
		{name: "browser-named HTTP private CA", code: "browser", cause: "tls: failed to verify certificate: x509: certificate signed by unknown authority", want: "if a private CA is expected, on Linux set SSL_CERT_FILE to an approved CA bundle"},
		{name: "expired", cause: "tls: failed to verify certificate: x509: certificate has expired or is not yet valid: current time is after expiry", want: "Correct the certificate validity dates and check the system clock"},
		{name: "hostname", cause: "tls: failed to verify certificate: x509: certificate is valid for other.invalid, not fixture.invalid", want: "Correct the target hostname or the certificate subject alternative names"},
		{name: "IP SAN", cause: "tls: failed to verify certificate: x509: cannot validate certificate for 127.0.0.1 because it doesn't contain any IP SANs", want: "Correct the target hostname or the certificate subject alternative names"},
		{name: "generic TLS failure", cause: "remote error: tls: handshake failure"},
		{name: "certificate rejection without x509 cause", cause: "tls: certificate rejected"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := signalResult(wafmeow.Incomplete)
			code := test.code
			if code == "" {
				code = "transport_error"
			}
			result.Evidence = append(result.Evidence, wafmeow.EvidenceSummary{Role: "Probe", ErrorCode: code})
			result.Outcome.Matches = []wafmeow.Match{{Product: "Header WAF", Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 0}}}}
			result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Evidence: 1, Code: code, Message: test.cause}}
			var stdout, stderr bytes.Buffer
			if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
				t.Fatal(err)
			}
			if !diagnosticRow(stderr.String(), "Probe", test.cause) || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("lost cause or conditional guidance: %q", stderr.String())
			}
			if test.want == "" && strings.Contains(stderr.String(), "Correct the") {
				t.Fatalf("invented a certificate cause: %q", stderr.String())
			}
			if !strings.Contains(test.want, "SSL_CERT_FILE") && strings.Contains(stderr.String(), "SSL_CERT_FILE") {
				t.Fatalf("unrelated certificate-trust guidance: %q", stderr.String())
			}
			if !strings.Contains(stdout.String(), "[ WAF MATCH ]") || !strings.Contains(stdout.String(), "HTTP  2 observations: 200 / ?") || !strings.Contains(stdout.String(), "evidence  incomplete") || strings.Contains(stdout.String(), "No HTTP response received") || strings.Contains(stdout.String(), test.cause) {
				t.Fatalf("TLS failure erased usable evidence or leaked diagnostic to stdout: %q", stdout.String())
			}
			for _, unsafe := range []string{"insecure", "skip verification", "disable validation", "retry"} {
				if strings.Contains(strings.ToLower(stderr.String()), unsafe) {
					t.Fatalf("unsafe or unrequested TLS guidance: %q", stderr.String())
				}
			}
		})
	}
}

func TestSignalDiagnosticsRetainDistinctObservations(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Evidence = append(result.Evidence, wafmeow.EvidenceSummary{Role: "Probe"})
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{
		{Evidence: 0, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 1, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 1, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 0, Code: "browser_export_failed", Message: "HTTP export cause"},
	}
	result.Browser = &wafmeow.BrowserReport{State: "failed", Reason: "browser_capture_failed", Error: "browser only cause"}
	var stderr bytes.Buffer
	if err := printResult(io.Discard, &stderr, result, false, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	want := "WARN  https://fixture.invalid/ | 3 diagnostics\n" +
		"  [Normal] same recorded cause\n" +
		"  [Probe]  same recorded cause\n" +
		"  [Normal] HTTP export cause\n" +
		"WARN  https://fixture.invalid/ | browser browser_capture_failed: browser only cause\n\n"
	if stderr.String() != want {
		t.Fatalf("diagnostic layout, order or attribution changed:\n got %q\nwant %q", stderr.String(), want)
	}
}

func TestSignalDiagnosticRoleAlignment(t *testing.T) {
	for _, test := range []struct {
		name, role, tag                        string
		afterTag, afterNormal, anonymousIndent int
	}{
		{"ASCII", "Probe", "[Probe]", 2, 1, 11},
		{"escaped newline", "A\n", `[A\n]`, 4, 1, 11},
		{"multibyte", "é", "[é]", 6, 1, 11},
		{"combining mark", "e\u0301", "[e\u0301]", 6, 1, 11},
		{"wide character", "猫", "[猫]", 5, 1, 11},
		{"emoji", "😀", "[😀]", 5, 1, 11},
		{"flag cluster", "🇩🇪", "[🇩🇪]", 5, 1, 11},
		{"escaped ANSI is widest", "\x1b[31m", `[\x1b[31m]`, 1, 3, 13},
		{"invalid UTF-8", string([]byte{0xff}), `[\xff]`, 3, 1, 11},
	} {
		for _, colors := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/colors=%t", test.name, colors), func(t *testing.T) {
				result := signalResult(wafmeow.Incomplete)
				result.Evidence = []wafmeow.EvidenceSummary{{Role: test.role}, {Role: "Normal"}, {}}
				result.Outcome.Diagnostics = []wafmeow.Diagnostic{
					{Evidence: 0, Code: "fixture_error", Message: "first cause"},
					{Evidence: 1, Code: "fixture_error", Message: "second cause"},
					{Evidence: -1, Code: "fixture_error", Message: "unattributed cause"},
					{Evidence: 3, Code: "fixture_error", Message: "invalid reference"},
					{Evidence: 2, Code: "fixture_error", Message: "empty role"},
				}
				au := aurora.New(aurora.WithColors(colors))
				var stderr bytes.Buffer
				if err := printResultDiagnostics(&stderr, result, au); err != nil {
					t.Fatal(err)
				}
				// Expected spacing is specified independently of the renderer's width calculation.
				want := fmt.Sprintf("%s  https://fixture.invalid/ | 5 diagnostics\n", au.Bold(au.Yellow("WARN"))) +
					fmt.Sprintf("  %s%sfirst cause\n", au.Bold(test.tag), strings.Repeat(" ", test.afterTag)) +
					fmt.Sprintf("  %s%ssecond cause\n", au.Cyan("[Normal]"), strings.Repeat(" ", test.afterNormal)) +
					strings.Repeat(" ", test.anonymousIndent) + "unattributed cause\n" +
					strings.Repeat(" ", test.anonymousIndent) + "invalid reference\n" +
					strings.Repeat(" ", test.anonymousIndent) + "empty role\n\n"
				if stderr.String() != want {
					t.Fatalf("diagnostic columns changed:\n got %q\nwant %q", stderr.String(), want)
				}
			})
		}
	}
}

func TestSignalDiagnosticsWithoutRoles(t *testing.T) {
	result := signalResult(wafmeow.Incomplete)
	result.Evidence = []wafmeow.EvidenceSummary{{}}
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{
		{Evidence: -1, Code: "fixture_error", Message: "unattributed cause"},
		{Evidence: 1, Code: "fixture_error", Message: "invalid reference"},
		{Evidence: 0, Code: "fixture_error", Message: "empty role"},
	}
	var stderr bytes.Buffer
	if err := printResultDiagnostics(&stderr, result, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	want := "WARN  https://fixture.invalid/ | 3 diagnostics\n" +
		"     unattributed cause\n" +
		"     invalid reference\n" +
		"     empty role\n\n"
	if stderr.String() != want {
		t.Fatalf("unattributed diagnostic layout changed:\n got %q\nwant %q", stderr.String(), want)
	}
}

func TestSignalEscapesAllDynamicResultDetails(t *testing.T) {
	poison := "safe\x1b[31m\r\nFORGED\t\u202e\u0085\u2028" + string([]byte{0xff})
	result := signalResult(wafmeow.Incomplete)
	result.Target = poison
	result.Evidence = []wafmeow.EvidenceSummary{{Role: poison, RequestURL: poison, EffectiveURL: poison + "/end", StatusCode: 403}}
	result.Outcome.Matches = []wafmeow.Match{{Product: poison, Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 0}}}}
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Code: poison, Evidence: 0, Message: poison}}
	result.Generic = wafmeow.GenericDetection{Reason: poison}
	result.Browser = &wafmeow.BrowserReport{
		Mode: poison, State: poison, Reason: poison, Error: poison, Limitations: []string{poison},
		DOM:        wafmeow.BrowserAsset{State: poison, Saved: poison, SaveState: poison},
		Screenshot: wafmeow.BrowserAsset{State: poison, Saved: poison, SaveState: poison},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false)), aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{stdout.String(), stderr.String()} {
		for _, r := range text {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029') {
				t.Fatalf("untrusted terminal control survived: %q", text)
			}
		}
		if !strings.Contains(text, `\x1b[31m\r\nFORGED\t\u202e\u0085\u2028\xff`) || strings.Contains(text, "\nFORGED") {
			t.Fatalf("dynamic details not visibly escaped: %q", text)
		}
	}
}

type signalFailWriter struct{ err error }

func (writer signalFailWriter) Write([]byte) (int, error) { return 0, writer.err }

func TestSignalPropagatesWriterErrors(t *testing.T) {
	failure := errors.New("signal writer failed")
	result := signalResult(wafmeow.Incomplete)
	result.Outcome.Diagnostics = []wafmeow.Diagnostic{{Code: "transport_error", Message: "recorded cause"}}
	au := aurora.New(aurora.WithColors(false))
	var stderr bytes.Buffer
	if err := printResult(signalFailWriter{failure}, &stderr, result, false, au, au); !errors.Is(err, failure) || stderr.Len() != 0 {
		t.Fatalf("stdout failure not propagated before diagnostics: err=%v stderr=%q", err, stderr.String())
	}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, false, au, au); !errors.Is(err, failure) {
		t.Fatalf("diagnostic failure lost: %v", err)
	}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, true, au, au); err != nil {
		t.Fatalf("suppressed warning attempted a write: %v", err)
	}
	result.Outcome.Diagnostics = nil
	result.Browser = &wafmeow.BrowserReport{State: "failed", Error: "recorded browser cause"}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, false, au, au); !errors.Is(err, failure) {
		t.Fatalf("browser diagnostic failure lost: %v", err)
	}
}
