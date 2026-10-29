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

	"github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w"
	"github.com/logrusorgru/aurora/v4"
)

func signalResult(state wafme0w.EvaluationState) wafme0w.Result {
	return wafme0w.Result{
		Target:   "https://fixture.invalid/",
		Outcome:  wafme0w.Outcome{State: state},
		Evidence: []wafme0w.EvidenceSummary{{Role: "Normal", RequestURL: "https://fixture.invalid/", StatusCode: 200}},
	}
}

func TestSignalHumanOutcomeDistinctions(t *testing.T) {
	for _, test := range []struct {
		name        string
		state       wafme0w.EvaluationState
		matched     bool
		generic     wafme0w.GenericDetection
		diagnostics []wafme0w.Diagnostic
		browser     *wafme0w.BrowserReport
		want        string
	}{
		{name: "clean complete", state: wafme0w.Complete, want: "NO WAF MATCH"},
		{name: "complete named", state: wafme0w.Complete, matched: true, want: "WAF MATCH"},
		{name: "incomplete named", state: wafme0w.Incomplete, matched: true, want: "WAF MATCH"},
		{name: "failed named is error", state: wafme0w.Failed, matched: true, want: "ERROR"},
		{name: "incomplete unnamed", state: wafme0w.Incomplete, want: "INCOMPLETE"},
		{name: "failed unnamed", state: wafme0w.Failed, want: "ERROR"},
		{name: "unknown state is not clean", want: "INCOMPLETE"},
		{name: "response difference", state: wafme0w.Complete, generic: wafme0w.GenericDetection{Mode: wafme0w.ChangeInStatus}, want: "REVIEW"},
		{name: "reason only", state: wafme0w.Complete, generic: wafme0w.GenericDetection{Reason: "unusual response"}, want: "REVIEW"},
		{name: "HTTP diagnostic", state: wafme0w.Complete, diagnostics: []wafme0w.Diagnostic{{Code: "transport_error"}}, want: "REVIEW"},
		{name: "browser-prefixed HTTP diagnostic", state: wafme0w.Complete, diagnostics: []wafme0w.Diagnostic{{Code: "browser_capture_failed"}}, want: "REVIEW"},
		{name: "browser-named HTTP diagnostic", state: wafme0w.Complete, diagnostics: []wafme0w.Diagnostic{{Code: "browser"}}, want: "REVIEW"},
		{name: "mixed diagnostics", state: wafme0w.Complete, diagnostics: []wafme0w.Diagnostic{{Code: "browser_export_failed"}, {Code: "body_truncated"}}, want: "REVIEW"},
		{name: "browser failure separate", state: wafme0w.Complete, browser: &wafme0w.BrowserReport{State: "failed"}, want: "NO WAF MATCH"},
		{name: "incomplete before review", state: wafme0w.Incomplete, generic: wafme0w.GenericDetection{Mode: wafme0w.ChangeInStatus}, want: "INCOMPLETE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := signalResult(test.state)
			result.Generic, result.Outcome.Diagnostics, result.Browser = test.generic, test.diagnostics, test.browser
			if test.matched {
				result.Outcome.Matches = []wafme0w.Match{{Product: "Fixture WAF"}}
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
				input := captureLines(t, wafme0w.Capture{
					Target: "saved HTTP response",
					Evidence: []wafme0w.Evidence{{
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
				for _, want := range []string{"[ REVIEW ]", "HTTP diagnostics need review", "HTTP  #1 200 | evidence complete"} {
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
				} else if !strings.Contains(stderr.String(), "[Normal] "+cause) {
					t.Fatalf("HTTP warning lost its observation role: %q", stderr.String())
				}
			})
		}
	}
}

func TestSignalOutcomeColors(t *testing.T) {
	au := aurora.New(aurora.WithColors(true))
	for _, test := range []struct {
		name    string
		state   wafme0w.EvaluationState
		matched bool
		review  bool
		label   string
		color   aurora.Color
	}{
		{name: "matched red", state: wafme0w.Complete, matched: true, label: "WAF MATCH", color: aurora.RedFg},
		{name: "matched incomplete remains red", state: wafme0w.Incomplete, matched: true, label: "WAF MATCH", color: aurora.RedFg},
		{name: "clean green", state: wafme0w.Complete, label: "NO WAF MATCH", color: aurora.GreenFg},
		{name: "error red", state: wafme0w.Failed, label: "ERROR", color: aurora.RedFg},
		{name: "incomplete amber", state: wafme0w.Incomplete, label: "INCOMPLETE", color: aurora.YellowFg},
		{name: "review amber", state: wafme0w.Complete, review: true, label: "REVIEW", color: aurora.YellowFg},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := signalResult(test.state)
			if test.matched {
				result.Outcome.Matches = []wafme0w.Match{{Product: "Fixture WAF", Fingerprints: []wafme0w.FingerprintMatch{{Evidence: 0}}}}
			}
			if test.review {
				result.Outcome.Diagnostics = []wafme0w.Diagnostic{{Code: "fixture_diagnostic", Message: "inspect HTTP evidence"}}
			}
			var stdout, stderr bytes.Buffer
			if err := printResult(&stdout, &stderr, result, false, au); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprint(au.Bold(au.Colorize("[ "+test.label+" ]", test.color)))
			if !strings.HasPrefix(stdout.String(), want+"  ") {
				t.Fatalf("wrong label or color: %q, want prefix %q", stdout.String(), want)
			}
			evidenceState := string(test.state)
			switch test.state {
			case wafme0w.Incomplete:
				evidenceState = fmt.Sprint(au.Yellow(evidenceState))
			case wafme0w.Failed:
				evidenceState = fmt.Sprint(au.Red(evidenceState))
			}
			if !strings.Contains(stdout.String(), " | evidence "+evidenceState+"\n") {
				t.Fatalf("evidence state did not retain independent styling: %q", stdout.String())
			}
			if strings.Contains(stderr.String(), "\x1b") {
				t.Fatalf("stdout color setting styled redirected diagnostics: %q", stderr.String())
			}
		})
	}
}

func TestSignalMatchedObservationsAreAttributedPerProduct(t *testing.T) {
	result := signalResult(wafme0w.Incomplete)
	result.Evidence = []wafme0w.EvidenceSummary{
		{Index: 91, Role: "Normal", StatusCode: 200, RequestURL: result.Target},
		{Index: 72, Role: "Probe", StatusCode: 403, RequestURL: result.Target + "?payload=recorded"},
		{Index: 53, Role: "Saved", StatusCode: 302, RequestURL: result.Target + "old", EffectiveURL: result.Target + "new", BodyTruncated: true},
	}
	result.Outcome.Matches = []wafme0w.Match{
		{Product: "Alpha", Fingerprints: []wafme0w.FingerprintMatch{{Fingerprint: 1, Evidence: 2}, {Fingerprint: 2, Evidence: 0}, {Fingerprint: 3, Evidence: 2}}},
		{Product: "Beta", Fingerprints: []wafme0w.FingerprintMatch{{Fingerprint: 1, Evidence: 1}}},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	text := stdout.String()
	alpha := "   product  Alpha\n   matched on  #1 [Normal] HTTP 200 " + result.Target + "; #3 [Saved] HTTP 302 " + result.Target + "old -> " + result.Target + "new\n"
	beta := "   product  Beta\n   matched on  #2 [Probe] HTTP 403 " + result.Target + "?payload=recorded\n"
	for _, want := range []string{"[ WAF MATCH ]", alpha, beta, "HTTP  #1 200 / #2 403 / #3 302 (body truncated) | evidence incomplete"} {
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

func TestSignalMissingSupportingObservationIsNotInvented(t *testing.T) {
	result := signalResult(wafme0w.Complete)
	result.Outcome.Matches = []wafme0w.Match{{Product: "Fixture", Fingerprints: []wafme0w.FingerprintMatch{{Evidence: -1}, {Evidence: 4}}}}
	var stdout bytes.Buffer
	if err := printResult(&stdout, io.Discard, result, false, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "matched on  supporting observation unavailable") || strings.Contains(stdout.String(), "#0") || strings.Contains(stdout.String(), "#5") {
		t.Fatalf("missing reference became invented support: %q", stdout.String())
	}
}

func TestSignalSuppressedWarningsKeepReviewAndBrowserState(t *testing.T) {
	result := signalResult(wafme0w.Complete)
	result.Outcome.Diagnostics = []wafme0w.Diagnostic{{Code: "transport_error", Message: "private diagnostic"}}
	result.Browser = &wafme0w.BrowserReport{
		State: "failed", Mode: "text", Reason: "browser_failed", Error: "private browser cause",
		DOM: wafme0w.BrowserAsset{State: "not_acquired", SaveState: "failed"}, Screenshot: wafme0w.BrowserAsset{State: "not_selected"},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, true, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[ REVIEW ]", "HTTP diagnostics need review", "evidence complete", "browser  failed (text)", "separate from HTTP", "text save failed"} {
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
			result := signalResult(wafme0w.Incomplete)
			code := test.code
			if code == "" {
				code = "transport_error"
			}
			result.Evidence = append(result.Evidence, wafme0w.EvidenceSummary{Role: "Probe", ErrorCode: code})
			result.Outcome.Matches = []wafme0w.Match{{Product: "Header WAF", Fingerprints: []wafme0w.FingerprintMatch{{Evidence: 0}}}}
			result.Outcome.Diagnostics = []wafme0w.Diagnostic{{Evidence: 1, Code: code, Message: test.cause}}
			var stdout, stderr bytes.Buffer
			if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false))); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stderr.String(), "[Probe] "+test.cause) || !strings.Contains(stderr.String(), test.want) {
				t.Fatalf("lost cause or conditional guidance: %q", stderr.String())
			}
			if test.want == "" && strings.Contains(stderr.String(), "Correct the") {
				t.Fatalf("invented a certificate cause: %q", stderr.String())
			}
			if !strings.Contains(test.want, "SSL_CERT_FILE") && strings.Contains(stderr.String(), "SSL_CERT_FILE") {
				t.Fatalf("unrelated certificate-trust guidance: %q", stderr.String())
			}
			if !strings.Contains(stdout.String(), "[ WAF MATCH ]") || !strings.Contains(stdout.String(), "#1 200 / #2 ? | evidence incomplete") || strings.Contains(stdout.String(), "No HTTP response received") || strings.Contains(stdout.String(), test.cause) {
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
	result := signalResult(wafme0w.Incomplete)
	result.Evidence = append(result.Evidence, wafme0w.EvidenceSummary{Role: "Probe"})
	result.Outcome.Diagnostics = []wafme0w.Diagnostic{
		{Evidence: 0, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 1, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 1, Code: "transport_error", Message: "same recorded cause"},
		{Evidence: 0, Code: "browser_export_failed", Message: "HTTP export cause"},
	}
	result.Browser = &wafme0w.BrowserReport{State: "failed", Reason: "browser_capture_failed", Error: "browser only cause"}
	var stderr bytes.Buffer
	if err := printResult(io.Discard, &stderr, result, false, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Normal] same recorded cause", "[Probe] same recorded cause", "[Normal] HTTP export cause", "browser browser_capture_failed: browser only cause"} {
		if strings.Count(stderr.String(), want) != 1 {
			t.Fatalf("lost attribution or duplicate diagnostic %q: %q", want, stderr.String())
		}
	}
}

func TestSignalEscapesAllDynamicResultDetails(t *testing.T) {
	poison := "safe\x1b[31m\r\nFORGED\t\u202e\u0085\u2028" + string([]byte{0xff})
	result := signalResult(wafme0w.Incomplete)
	result.Target = poison
	result.Evidence = []wafme0w.EvidenceSummary{{Role: poison, RequestURL: poison, EffectiveURL: poison + "/end", StatusCode: 403}}
	result.Outcome.Matches = []wafme0w.Match{{Product: poison, Fingerprints: []wafme0w.FingerprintMatch{{Evidence: 0}}}}
	result.Outcome.Diagnostics = []wafme0w.Diagnostic{{Code: poison, Evidence: 0, Message: poison}}
	result.Generic = wafme0w.GenericDetection{Reason: poison}
	result.Browser = &wafme0w.BrowserReport{
		Mode: poison, State: poison, Reason: poison, Error: poison, Limitations: []string{poison},
		DOM:        wafme0w.BrowserAsset{State: poison, Saved: poison, SaveState: poison},
		Screenshot: wafme0w.BrowserAsset{State: poison, Saved: poison, SaveState: poison},
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, false, aurora.New(aurora.WithColors(false))); err != nil {
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
	result := signalResult(wafme0w.Incomplete)
	result.Outcome.Diagnostics = []wafme0w.Diagnostic{{Code: "transport_error", Message: "recorded cause"}}
	au := aurora.New(aurora.WithColors(false))
	var stderr bytes.Buffer
	if err := printResult(signalFailWriter{failure}, &stderr, result, false, au); !errors.Is(err, failure) || stderr.Len() != 0 {
		t.Fatalf("stdout failure not propagated before diagnostics: err=%v stderr=%q", err, stderr.String())
	}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, false, au); !errors.Is(err, failure) {
		t.Fatalf("diagnostic failure lost: %v", err)
	}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, true, au); err != nil {
		t.Fatalf("suppressed warning attempted a write: %v", err)
	}
	result.Outcome.Diagnostics = nil
	result.Browser = &wafme0w.BrowserReport{State: "failed", Error: "recorded browser cause"}
	if err := printResult(io.Discard, signalFailWriter{failure}, result, false, au); !errors.Is(err, failure) {
		t.Fatalf("browser diagnostic failure lost: %v", err)
	}
}
