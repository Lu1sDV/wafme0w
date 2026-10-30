package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
)

func runImportCLI(t *testing.T, stdin io.Reader, piped bool, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := runContext(ctx, args, stdin, piped, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestCLIInputDashSelectsStdin(t *testing.T) {
	for _, piped := range []bool{false, true} {
		t.Run(map[bool]string{false: "explicit stdin", true: "piped stdin"}[piped], func(t *testing.T) {
			code, stdout, stderr := runImportCLI(t, strings.NewReader("invalid://from-stdin\n"), piped,
				"--input=-", "--jsonl", "--silent")
			if code != 0 {
				t.Fatalf("stdin selection exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			results := decodeResultLines(t, stdout)
			if len(results) != 1 || results[0].Target != "invalid://from-stdin" {
				t.Fatalf("stdin selection results=%+v", results)
			}
		})
	}
}

func TestCLIInputDashRejectsRealFileAliases(t *testing.T) {
	for _, sink := range []string{"output", "diagnostics-journal", "stdout"} {
		t.Run(sink, func(t *testing.T) {
			dir := t.TempDir()
			source, alias := filepath.Join(dir, "targets.txt"), filepath.Join(dir, "alias.jsonl")
			content := "invalid://must-not-overwrite\n"
			if err := os.WriteFile(source, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(source, alias); err != nil {
				t.Skipf("hardlinks unavailable: %v", err)
			}
			stdin, err := os.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stdin.Close() })
			args := []string{"--input=-", "--jsonl", "--silent"}
			var output bytes.Buffer
			var stdout io.Writer = &output
			if sink == "stdout" {
				file, err := os.OpenFile(alias, os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = file.Close() })
				stdout = file
			} else {
				args = append(args, "--"+sink, alias)
			}
			var stderr bytes.Buffer
			code := runContext(context.Background(), args, stdin, false, stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), "same file") || output.Len() != 0 {
				t.Fatalf("alias not rejected before input/output: exit=%d stdout=%q stderr=%q", code, output.String(), stderr.String())
			}
			if data, err := os.ReadFile(source); err != nil || string(data) != content {
				t.Fatalf("source changed: %q %v", data, err)
			}
		})
	}
}

func TestCLIHTTPXStatusOnlyIsNotCleanNegative(t *testing.T) {
	input := "{\"url\":\"https://example.test/\",\"status_code\":200}\n"
	code, stdout, stderr := runImportCLI(t, strings.NewReader(input), false,
		"--evidence=-", "--evidence-format=httpx", "--jsonl", "--strict", "--silent", "--fingerprints", fixtureCatalogue(t))
	if code != 2 {
		t.Fatalf("missing metadata exit=%d want=2 stdout=%q stderr=%q", code, stdout, stderr)
	}
	results := decodeResultLines(t, stdout)
	if len(results) != 1 || results[0].Outcome.State != wafmeow.Incomplete || len(results[0].Outcome.Matches) != 0 {
		t.Fatalf("status-only import claimed clean classification: %+v", results)
	}
	var wire struct {
		Evidence []struct {
			Availability map[string]string `json:"availability"`
		} `json:"evidence"`
		Provenance struct {
			Import map[string]any `json:"import"`
		} `json:"provenance"`
	}
	if err := json.Unmarshal([]byte(stdout), &wire); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"status": "complete", "headers": "unavailable", "reason": "unavailable", "body": "unavailable"}
	if len(wire.Evidence) != 1 || !reflect.DeepEqual(wire.Evidence[0].Availability, want) || wire.Provenance.Import["format"] != "httpx" {
		t.Fatalf("missing explicit channel/provenance metadata: %s", stdout)
	}
}

func TestCLIHTTPXResponseEncodingDispatch(t *testing.T) {
	header := "HTTP/1.1 200 OK\r\nX-Saved: marker\r\n\r\n"
	catalogue := filepath.Join(t.TempDir(), "headers.json")
	if err := os.WriteFile(catalogue, []byte(`[{"name":"Header fixture","schemas":[{"fingerprints":[{"type":"Header","header_key":"X-Saved","header_value":"marker"}]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"text", "base64"} {
		t.Run(encoding, func(t *testing.T) {
			raw := header
			if encoding == "base64" {
				raw = base64.StdEncoding.EncodeToString([]byte(raw))
			}
			record, err := json.Marshal(map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw})
			if err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runImportCLI(t, bytes.NewReader(append(record, '\n')), true,
				"--evidence=-", "--evidence-format=httpx", "--httpx-response-encoding="+encoding,
				"--jsonl", "--silent", "--fingerprints", catalogue)
			if code != 0 {
				t.Fatalf("encoding dispatch exit=%d stderr=%q", code, stderr)
			}
			results := decodeResultLines(t, stdout)
			if len(results) != 1 || len(results[0].Outcome.Matches) != 1 || results[0].Outcome.Matches[0].Product != "Header fixture" {
				t.Fatalf("declared %s header not classified: %+v", encoding, results)
			}
		})
	}
}

func TestCLIExplicitAvailabilityLabelsSurviveNoWarning(t *testing.T) {
	for _, format := range []string{"native", "httpx"} {
		t.Run(format, func(t *testing.T) {
			input := `{"target":"saved native","evidence":[{"role":"Normal","status_code":200,"availability":{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}}]}` + "\n"
			if format == "httpx" {
				input = `{"url":"https://example.test/","status_code":200,"raw_header":"HTTP/1.1 200 OK\r\nX-Saved: marker\r\n\r\n","body":"ordinary"}` + "\n"
			}
			code, stdout, stderr := runImportCLI(t, strings.NewReader(input), false,
				"--evidence=-", "--evidence-format="+format, "--no-warning", "--no-colors", "--fingerprints", fixtureCatalogue(t))
			if code != 0 {
				t.Fatalf("human import exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			for _, output := range []string{stdout, stderr} {
				for _, want := range []string{"classification incomplete", "headers partial", "reason unavailable", "body unknown"} {
					if !strings.Contains(output, want) {
						t.Errorf("missing %q in human output %q", want, output)
					}
				}
				if strings.Contains(output, "evidence complete") || strings.Contains(output, "[ NO WAF MATCH ]") || strings.Contains(output, "NO WAF MATCH | 1") || strings.Contains(output, "WARN ") {
					t.Errorf("misleading completeness or unsuppressed warning: %q", output)
				}
			}
		})
	}
}

func TestCLIHTTPXOptionsRejectInvalidCombinations(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"format requires evidence", []string{"--input=-", "--evidence-format=native"}, "requires --evidence"},
		{"unknown format", []string{"--evidence=-", "--evidence-format=guess"}, "evidence format"},
		{"empty format", []string{"--evidence=-", "--evidence-format="}, "nonempty"},
		{"encoding requires httpx", []string{"--evidence=-", "--httpx-response-encoding=text"}, "requires --evidence-format=httpx"},
		{"encoding rejects live", []string{"--input=-", "--httpx-response-encoding=base64"}, "requires --evidence-format=httpx"},
		{"unknown encoding", []string{"--evidence=-", "--evidence-format=httpx", "--httpx-response-encoding=guess"}, "response encoding"},
		{"empty encoding", []string{"--evidence=-", "--evidence-format=httpx", "--httpx-response-encoding="}, "nonempty"},
		{"target conflict", []string{"--evidence=-", "--evidence-format=httpx", "--target=https://example.test"}, "exclusive"},
		{"input conflict", []string{"--evidence=-", "--evidence-format=httpx", "--input=-"}, "exclusive"},
		{"baseline conflict", []string{"--evidence=-", "--evidence-format=httpx", "--baseline"}, "exclusive"},
		{"browser conflict", []string{"--evidence=-", "--evidence-format=httpx", "--browser=navigate"}, "evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runImportCLI(t, strings.NewReader(""), false, append(tc.args, "--jsonl", "--silent")...)
			if code != 1 || stdout != "" || !strings.Contains(stderr, tc.want) {
				t.Fatalf("invalid options exit=%d stdout=%q stderr=%q; want diagnostic %q", code, stdout, stderr, tc.want)
			}
		})
	}
}

func TestCLIHTTPXMalformedTailPreservesPublishedReportAndPriorJournal(t *testing.T) {
	dir := t.TempDir()
	output, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
	if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	input := "{\"url\":\"https://example.test/\",\"status_code\":200}\n{\n"
	code, stdout, stderr := runImportCLI(t, strings.NewReader(input), false,
		"--evidence=-", "--evidence-format=httpx", "--jsonl", "--silent", "--output", output, "--diagnostics-journal", journal)
	if code != 1 || !strings.Contains(stderr, "line 2") {
		t.Fatalf("malformed tail exit=%d stderr=%q", code, stderr)
	}
	if results := decodeResultLines(t, stdout); len(results) != 1 || results[0].Target != "https://example.test/" {
		t.Fatalf("lost prior streamed record: %+v", results)
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != "previous report" {
		t.Fatalf("failed import replaced report: %q %v", data, err)
	}
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var first, second journalRecord
	if err := decoder.Decode(&first); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&second); err != nil {
		t.Fatal(err)
	}
	if first.Result == nil || first.Result.Target != "https://example.test/" || second.Diagnostic == nil || second.Diagnostic.Code != "run_error" {
		t.Fatalf("journal lost ordered recovery records: %s", data)
	}
}

func TestCLIAnnotatedURLInputGivesHintWithoutRepair(t *testing.T) {
	for _, input := range []string{"https://example.test [200] [Example]", `{"url":"https://example.test/","status_code":200}`} {
		code, stdout, stderr := runImportCLI(t, strings.NewReader(input+"\n"), false, "--input=-", "--jsonl", "--silent")
		if code != 0 {
			t.Fatalf("invalid target should be a result: exit=%d stderr=%q", code, stderr)
		}
		results := decodeResultLines(t, stdout)
		if len(results) != 1 || results[0].Target != input || results[0].Outcome.State != wafmeow.Failed {
			t.Fatalf("annotated input was repaired or lost: %+v", results)
		}
		if !strings.Contains(stdout, "one HTTP(S) URL per line") || !strings.Contains(stdout, "--evidence-format=httpx") {
			t.Fatalf("invalid-target result lacks actionable input hint: %s", stdout)
		}
	}
}

type notifyingCLIWriter struct {
	bytes.Buffer
	wrote chan struct{}
	once  sync.Once
}

func (writer *notifyingCLIWriter) Write(data []byte) (int, error) {
	n, err := writer.Buffer.Write(data)
	writer.once.Do(func() { close(writer.wrote) })
	return n, err
}

func TestCLIHTTPXEmitsBeforeInputEOF(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	input, producer := io.Pipe()
	stdout := &notifyingCLIWriter{wrote: make(chan struct{})}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	finished, producerFinished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		done <- runContext(ctx, []string{"--evidence=-", "--evidence-format=httpx", "--jsonl", "--silent"},
			input, false, stdout, &stderr)
	}()
	written := make(chan error, 1)
	go func() {
		defer close(producerFinished)
		_, err := io.WriteString(producer, "{\"url\":\"https://example.test/\",\"status_code\":200}\n")
		written <- err
	}()
	t.Cleanup(func() {
		cancel()
		_ = input.Close()
		_ = producer.Close()
		<-finished
		<-producerFinished
	})
	select {
	case <-stdout.wrote:
	case code := <-done:
		t.Fatalf("runner exited before streaming: exit=%d stderr=%q", code, stderr.String())
	case <-ctx.Done():
		t.Fatal("runner waited for EOF before emitting a complete input record")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := producer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("runner exit=%d stderr=%q", code, stderr.String())
		}
	case <-ctx.Done():
		t.Fatal("runner did not finish after input EOF")
	}
	if results := decodeResultLines(t, stdout.String()); len(results) != 1 {
		t.Fatalf("streamed results=%+v", results)
	}
}

func TestCLICompleteClassificationDoesNotImplyCompleteChannels(t *testing.T) {
	catalogue := filepath.Join(t.TempDir(), "status.json")
	if err := os.WriteFile(catalogue, []byte(`[{"name":"Status fixture","schemas":[{"fingerprints":[{"type":"Status","pattern":"403"}]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	input := `{"target":"saved native","evidence":[{"role":"Normal","status_code":200,"availability":{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unknown"}}]}` + "\n"
	code, stdout, stderr := runImportCLI(t, strings.NewReader(input), false,
		"--evidence=-", "--no-warning", "--no-colors", "--fingerprints", catalogue)
	if code != 0 {
		t.Fatalf("native classification exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	for _, output := range []string{stdout, stderr} {
		if !strings.Contains(output, "classification complete") || !strings.Contains(output, "body unknown") ||
			strings.Contains(output, "[ NO WAF MATCH ]") || strings.Contains(output, "NO WAF MATCH | 1") {
			t.Errorf("channel availability hidden by classification completeness: %q", output)
		}
	}
}
