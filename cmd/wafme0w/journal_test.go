package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func TestCLIPostPublicationSinkFailureKeepsReport(t *testing.T) {
	dir := t.TempDir()
	report, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(report, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	input := captureLines(t, wafme0w.Capture{Target: "saved", Evidence: []wafme0w.Evidence{}})
	var stdout bytes.Buffer
	code := runContext(context.Background(), []string{"--evidence=-", "--jsonl", "--output", report, "--diagnostics-journal", journal, "--journal-batch-size=4"}, strings.NewReader(input), true, &stdout, failedConsole{})
	if code != 1 {
		t.Fatalf("summary sink failure exit=%d, want 1", code)
	}
	published, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var results []wafme0w.Result
	if err := json.Unmarshal(published, &results); err != nil {
		t.Fatalf("post-publication failure damaged report: %v", err)
	}
	if len(results) != 1 || results[0].Target != "saved" || !reflect.DeepEqual(results, decodeResultLines(t, stdout.String())) {
		t.Fatalf("published report differs from completed stream: %+v", results)
	}
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var result, diagnostic journalRecord
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&diagnostic); err != nil {
		t.Fatal(err)
	}
	if result.Result == nil || result.Result.Target != "saved" || diagnostic.Diagnostic == nil || diagnostic.Diagnostic.Code != "run_error" || !strings.Contains(diagnostic.Diagnostic.Message, "console closed") {
		t.Fatalf("journal lost completed result or post-publication failure: %+v, %+v", result, diagnostic)
	}
	var extra journalRecord
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected journal tail: %+v, %v", extra, err)
	}
}

type resultChunks chan []byte

func (chunks resultChunks) Write(data []byte) (int, error) {
	chunks <- bytes.Clone(data)
	return len(data), nil
}

func TestCLIJournalPartialBatchFlushesLiveStdin(t *testing.T) {
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	chunks := make(resultChunks, 2)
	var stderr bytes.Buffer
	done := make(chan int, 1)
	joined := false
	defer func() {
		cancel()
		_ = reader.Close()
		_ = writer.Close()
		if !joined {
			<-done
		}
	}()
	go func() {
		done <- runContext(ctx, []string{"--evidence=-", "--jsonl", "--silent", "--diagnostics-journal", journal, "--journal-batch-size=4"}, reader, true, chunks, &stderr)
	}()
	input := captureLines(t, wafme0w.Capture{Target: "live", Evidence: []wafme0w.Evidence{}})
	if _, err := io.WriteString(writer, input); err != nil {
		t.Fatal(err)
	}
	var data []byte
	select {
	case data = <-chunks:
	case <-time.After(5 * time.Second):
		t.Fatal("partial journal batch waited for stdin EOF")
	}
	results := decodeResultLines(t, string(data))
	if len(results) != 1 || results[0].Target != "live" {
		t.Fatalf("partial batch output changed: %+v", results)
	}
	journalData, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	records := journalRecords(t, journalData)
	if len(records) != 1 || records[0].Result == nil || records[0].Result.Target != "live" {
		t.Fatalf("live output preceded its recovery record: %+v", records)
	}
	select {
	case code := <-done:
		joined = true
		t.Fatalf("live scan returned before EOF: exit=%d stderr=%q", code, stderr.String())
	default:
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	code := <-done
	joined = true
	if code != 0 || stderr.Len() != 0 || len(chunks) != 0 {
		t.Fatalf("EOF lost or duplicated live batch: exit=%d stderr=%q extra writes=%d", code, stderr.String(), len(chunks))
	}
}

func TestCLIJournalAsyncSinkFailureWakesInputAndPreservesReport(t *testing.T) {
	for _, captured := range []bool{false, true} {
		name, input := "targets", "invalid://saved\n"
		args := []string{"--jsonl", "--silent", "--journal-batch-size=4"}
		if captured {
			name = "captures"
			input = captureLines(t, wafme0w.Capture{Target: "saved", Evidence: []wafme0w.Evidence{}})
			args = append(args, "--evidence=-")
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			report, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
			if err := os.WriteFile(report, []byte("previous report"), 0600); err != nil {
				t.Fatal(err)
			}
			args := append(append([]string{}, args...), "--output", report, "--diagnostics-journal", journal)
			reader, writer := io.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			var stderr bytes.Buffer
			done := make(chan int, 1)
			joined := false
			defer func() {
				cancel()
				_ = reader.Close()
				_ = writer.Close()
				if !joined {
					<-done
				}
			}()
			go func() {
				done <- runContext(ctx, args, reader, true, failedConsole{}, &stderr)
			}()
			if _, err := io.WriteString(writer, input); err != nil {
				t.Fatal(err)
			}
			select {
			case code := <-done:
				joined = true
				if code != 1 || !strings.Contains(stderr.String(), "console closed") {
					t.Fatalf("original asynchronous output error lost: exit=%d stderr=%q", code, stderr.String())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("asynchronous sink failure left stdin blocked")
			}
			data, err := os.ReadFile(report)
			if err != nil || string(data) != "previous report" {
				t.Fatalf("asynchronous failure published partial report: %q %v", data, err)
			}
			data, err = os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			records := journalRecords(t, data)
			if len(records) != 2 || records[0].Result == nil || records[1].Diagnostic == nil ||
				records[1].Diagnostic.Code != "run_error" || !strings.Contains(records[1].Diagnostic.Message, "console closed") {
				t.Fatalf("result or original run diagnostic lost or reordered: %+v", records)
			}
		})
	}
}

func TestCLIJournalDrainsTailBeforeInputDiagnostic(t *testing.T) {
	dir := t.TempDir()
	report, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(report, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	input := captureLines(t,
		wafme0w.Capture{Target: "first", Evidence: []wafme0w.Evidence{}},
		wafme0w.Capture{Target: "second", Evidence: []wafme0w.Evidence{}},
	) + "{\n"
	code, stdout, stderr := runCLI(t, strings.NewReader(input), "--evidence=-", "--jsonl", "--silent",
		"--output", report, "--diagnostics-journal", journal, "--journal-batch-size=4")
	if code != 1 || !strings.Contains(stderr, "line 3") {
		t.Fatalf("input error changed: exit=%d stderr=%q", code, stderr)
	}
	results := decodeResultLines(t, stdout)
	if len(results) != 2 || results[0].Target != "first" || results[1].Target != "second" {
		t.Fatalf("accepted tail lost on input failure: %+v", results)
	}
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	records := journalRecords(t, data)
	if len(records) != 3 || records[0].Result == nil || records[0].Result.Target != "first" ||
		records[1].Result == nil || records[1].Result.Target != "second" || records[2].Diagnostic == nil ||
		!strings.Contains(records[2].Diagnostic.Message, "line 3") {
		t.Fatalf("input diagnostic preceded drained tail: %+v", records)
	}
	if data, err := os.ReadFile(report); err != nil || string(data) != "previous report" {
		t.Fatalf("input error published partial report: %q %v", data, err)
	}
}
