package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
)

func TestHumanReportReplaysManyRowsWithBoundedWrites(t *testing.T) {
	report, err := openHumanReport(options{})
	if err != nil {
		t.Fatal(err)
	}
	path := report.file.Name()
	defer report.close()
	info, err := report.file.Stat()
	if err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("spool is not private: info=%v err=%v", info, err)
	}
	const rows = 50000
	for i := range rows {
		if err := report.add(wafmeow.Result{Target: fmt.Sprintf("https://example.test/full/path/%d?query=preserved", i), Outcome: wafmeow.Outcome{State: wafmeow.Complete}}); err != nil {
			t.Fatal(err)
		}
	}
	var sink reportCountingWriter
	if err := report.replay(context.Background(), &sink, true); err != nil {
		t.Fatal(err)
	}
	if sink.lines != rows+4 || sink.largest > 32*1024 {
		t.Fatalf("lost rows or unbounded replay: lines=%d largest-write=%d", sink.lines, sink.largest)
	}
	if err := report.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("spool not removed: %v", err)
	}
}

type reportCountingWriter struct {
	lines   int
	largest int
}

func (writer *reportCountingWriter) Write(data []byte) (int, error) {
	writer.lines += bytes.Count(data, []byte{'\n'})
	writer.largest = max(writer.largest, len(data))
	return len(data), nil
}

func TestHumanReportPreservesFullEscapedURLAndSupportingObservations(t *testing.T) {
	report, err := openHumanReport(options{})
	if err != nil {
		t.Fatal(err)
	}
	defer report.close()
	target := "https://example.test/" + strings.Repeat("long-path/", 10000) + "?q=full\x1b\n"
	result := wafmeow.Result{
		Target:   target,
		Evidence: make([]wafmeow.EvidenceSummary, 3),
		Outcome: wafmeow.Outcome{State: wafmeow.Incomplete, Matches: []wafmeow.Match{
			{Product: "First\tWAF", Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 2}, {Evidence: 0}, {Evidence: 2}}},
			{Product: "Second WAF", Fingerprints: []wafmeow.FingerprintMatch{{Evidence: 1}}},
		}},
	}
	if err := report.add(result); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := report.replay(context.Background(), &output, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"PARTIAL URL / RESULT / EVIDENCE", "SUPPORTING OBSERVATIONS", "WAF MATCH | First\\tWAF (observations #1,#3); Second WAF (observations #2) | incomplete | " + terminalText(target)} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing full escaped row %q", want)
		}
	}
	if strings.ContainsAny(output.String(), "\x1b\r\t") {
		t.Fatal("unescaped terminal control in table")
	}
}

func TestHumanReportPropagatesSinkAndFileErrorsAndRemovesSpool(t *testing.T) {
	report, err := openHumanReport(options{})
	if err != nil {
		t.Fatal(err)
	}
	path := report.file.Name()
	if err := report.add(wafmeow.Result{Target: strings.Repeat("x", 4096), Outcome: wafmeow.Outcome{State: wafmeow.Complete}}); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("table sink failed")
	if err := report.replay(context.Background(), &reportFailingWriter{remaining: 1024, err: failure}, true); !errors.Is(err, failure) {
		t.Fatalf("replay lost sink error: %v", err)
	}
	if err := report.file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := report.add(wafmeow.Result{}); err == nil {
		t.Fatal("closed spool accepted a row")
	}
	if err := report.replay(context.Background(), io.Discard, true); err == nil {
		t.Fatal("closed spool replay succeeded")
	}
	if err := report.close(); err == nil {
		t.Fatal("spool close failure was lost")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed spool not removed: %v", err)
	}
}

type reportFailingWriter struct {
	remaining int
	err       error
}

func (writer *reportFailingWriter) Write(data []byte) (int, error) {
	if len(data) > writer.remaining {
		n := writer.remaining
		writer.remaining = 0
		return n, writer.err
	}
	writer.remaining -= len(data)
	return len(data), nil
}

func TestMachineModesDoNotCreateHumanReportSpool(t *testing.T) {
	catalogue := fixtureCatalogue(t)
	input := captureLines(t, wafmeow.Capture{Target: "saved target", Evidence: []wafmeow.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}})
	missing := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missing)
	t.Setenv("TMP", missing)
	t.Setenv("TEMP", missing)
	for _, args := range [][]string{{"--jsonl"}, {"--jsonl", "--silent"}} {
		var stdout, stderr bytes.Buffer
		args = append(args, "--evidence=-", "--fingerprints", catalogue)
		code := runContext(context.Background(), args, strings.NewReader(input), true, &stdout, &stderr)
		if code != 0 || len(decodeResultLines(t, stdout.String())) != 1 {
			t.Fatalf("machine scan failed without a temp directory: code=%d stderr=%q", code, stderr.String())
		}
		if strings.Contains(stderr.String(), "URL / RESULT / EVIDENCE") {
			t.Fatalf("machine mode emitted a URL table: %q", stderr.String())
		}
		if strings.Contains(strings.Join(args, " "), "--silent") {
			if stderr.Len() != 0 {
				t.Fatalf("silent mode emitted human output: %q", stderr.String())
			}
		} else if !strings.Contains(stderr.String(), "SUMMARY") {
			t.Fatal("JSONL lost its stderr overview")
		}
	}
	if report, err := openHumanReport(options{}); err == nil {
		_ = report.close()
		t.Fatal("human spool creation error was lost")
	}
}

func TestHumanReportSpoolCleanupOnEveryRunExit(t *testing.T) {
	catalogue := fixtureCatalogue(t)
	input := captureLines(t, wafmeow.Capture{Target: "saved target", Evidence: []wafmeow.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}})
	for _, name := range []string{"success", "banner failure", "summary failure", "aborted input"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			t.Setenv("TMP", directory)
			t.Setenv("TEMP", directory)
			var stdout, stderr bytes.Buffer
			var out, diagnostic io.Writer = &stdout, &stderr
			capture := input
			if name == "banner failure" {
				out = failedConsole{}
			}
			if name == "summary failure" {
				diagnostic = failedConsole{}
			}
			if name == "aborted input" {
				capture += "{not-json}\n"
			}
			code := runContext(context.Background(), []string{"--evidence=-", "--fingerprints", catalogue}, strings.NewReader(capture), true, out, diagnostic)
			if (code == 0) != (name == "success") {
				t.Fatalf("unexpected exit %d: %q", code, stderr.String())
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("spool leaked on %s: entries=%v err=%v", name, entries, err)
			}
			if name == "success" && !strings.Contains(stderr.String(), "URL / RESULT / EVIDENCE") {
				t.Fatal("human run omitted final URL table")
			}
			if name == "aborted input" && (!strings.Contains(stderr.String(), "PARTIAL SUMMARY") || !strings.Contains(stderr.String(), "PARTIAL URL / RESULT / EVIDENCE")) {
				t.Fatalf("aborted run was not clearly partial: %q", stderr.String())
			}
		})
	}
}

func TestHumanReportCancellationDuringFinalReplay(t *testing.T) {
	catalogue := fixtureCatalogue(t)
	for _, stage := range []string{"heading", "first chunk", "last chunk"} {
		t.Run(stage, func(t *testing.T) {
			directory := t.TempDir()
			t.Setenv("TMPDIR", directory)
			t.Setenv("TMP", directory)
			t.Setenv("TEMP", directory)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			target := "cancel-replay-row"
			trigger := target
			if stage == "heading" {
				trigger = "URL / RESULT / EVIDENCE"
			}
			if stage != "last chunk" {
				target += strings.Repeat("/full-path", 5000) + "/must-not-replay-tail"
			}
			input := captureLines(t, wafmeow.Capture{Target: target, Evidence: []wafmeow.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}})
			output := filepath.Join(t.TempDir(), "report.json")
			sink := &reportCancelWriter{trigger: trigger, cancel: cancel}
			code := runContext(ctx, []string{"--evidence=-", "--fingerprints", catalogue, "--output", output}, strings.NewReader(input), true, io.Discard, sink)
			if code != 130 || !sink.canceled {
				t.Fatalf("final replay cancellation: exit=%d canceled=%t stderr=%q", code, sink.canceled, sink.String())
			}
			if stage != "last chunk" && strings.Contains(sink.String(), "/must-not-replay-tail") {
				t.Fatal("table replay continued after cancellation")
			}
			if sink.closed {
				t.Fatal("runContext closed a caller-owned diagnostic writer")
			}
			if data, err := os.ReadFile(output); err != nil || !bytes.Contains(data, []byte("cancel-replay-row")) {
				t.Fatalf("already-published report was lost: bytes=%d err=%v", len(data), err)
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Fatalf("spool leaked after replay cancellation: entries=%v err=%v", entries, err)
			}
		})
	}
}

type reportCancelWriter struct {
	bytes.Buffer
	trigger  string
	cancel   context.CancelFunc
	canceled bool
	closed   bool
}

func (writer *reportCancelWriter) Write(data []byte) (int, error) {
	n, err := writer.Buffer.Write(data)
	if !writer.canceled && bytes.Contains(data, []byte(writer.trigger)) {
		writer.canceled = true
		writer.cancel()
	}
	return n, err
}

func (writer *reportCancelWriter) Close() error {
	writer.closed = true
	return nil
}

func TestOverviewOutcomeBucketsAreDisjointAndBrowserIsSeparate(t *testing.T) {
	var counts resultCounts
	for _, result := range []wafmeow.Result{
		{Outcome: wafmeow.Outcome{State: wafmeow.Failed, Matches: []wafmeow.Match{{Product: "failed match"}}}},
		{Outcome: wafmeow.Outcome{State: wafmeow.Incomplete, Matches: []wafmeow.Match{{Product: "partial match"}}}},
		{Outcome: wafmeow.Outcome{State: wafmeow.Incomplete}},
		{Outcome: wafmeow.Outcome{State: wafmeow.Complete, Diagnostics: []wafmeow.Diagnostic{{Code: "transport"}}}},
		{Outcome: wafmeow.Outcome{State: wafmeow.Complete, Diagnostics: []wafmeow.Diagnostic{{Code: "browser_navigation"}}}},
		{Outcome: wafmeow.Outcome{State: wafmeow.Complete}, Browser: &wafmeow.BrowserReport{State: "failed"}},
	} {
		counts.add(result)
	}
	if counts.Total != 6 || counts.WAFMatch != 1 || counts.NoWAFMatch != 1 || counts.Review != 2 || counts.OutcomeIncomplete != 1 || counts.OutcomeError != 1 {
		t.Fatalf("outcome buckets are not disjoint: %+v", counts)
	}
	if counts.Complete != 3 || counts.Incomplete != 2 || counts.Failed != 1 || counts.Browser != 1 || counts.BrowserFailed != 1 || counts.Diagnostics != 2 || !counts.StrictFailure {
		t.Fatalf("HTTP/browser counts or strict semantics changed: %+v", counts)
	}
	var output bytes.Buffer
	if err := printSummary(&output, counts, true, aurora.New(aurora.WithColors(false))); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"HTTP OUTCOME | TARGETS", "HTTP diagnostics 2", "browser 1 | browser/artifact failures 1 (separate from HTTP state)", "matched-on observations show supporting evidence, not causation"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("overview lost %q: %q", want, output.String())
		}
	}
}
