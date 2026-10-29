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
	code := runContext(context.Background(), []string{"--evidence=-", "--jsonl", "--output", report, "--diagnostics-journal", journal}, strings.NewReader(input), true, &stdout, failedConsole{})
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
