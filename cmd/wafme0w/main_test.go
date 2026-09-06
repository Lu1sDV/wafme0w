package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
	"github.com/logrusorgru/aurora/v4"
)

func TestMain(m *testing.M) {
	if os.Getenv("WAFME0W_CLI_TEST_PROCESS") == "1" {
		os.Exit(run(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func runCLI(t *testing.T, stdin io.Reader, args ...string) (int, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append(os.Environ(), "WAFME0W_CLI_TEST_PROCESS=1")
	cmd.Stdin = stdin
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("CLI did not finish: %v", ctx.Err())
	}
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatal(err)
	return -1, "", ""
}

func TestCLIRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"--unknown"},
		{"--concurrency"},
		{"--concurrency=invalid"},
		{"--concurrency=0", "--list"},
		{"--concurrency=-1", "--list"},
		{"--max-body-bytes=0", "--list"},
		{"--max-body-bytes=-1", "--list"},
		{"--request-timeout=0s", "--list"},
		{"--target-timeout=-1s", "--list"},
		{"--max-requests=0", "--list"},
		{"--max-connections=0", "--list"},
		{"--rate=NaN", "--list"},
		{"--per-origin-rate=+Inf", "--list"},
		{"--max-redirects=-1", "--list"},
		{"--redirect-policy=unknown", "--list"},
		{"--redirect-policy=allowlist", "--list"},
		{"--target", "invalid://one", "--input", "missing.txt"},
		{"--evidence=-", "--target", "invalid://one"},
		{"--evidence=-", "--input", "missing.txt"},
		{"--evidence=-", "--fast"},
		{"--evidence=-", "--baseline"},
		{"--fast", "--baseline", "--target", "invalid://one"},
		{"--jsonl", "--list"},
		{"--jsonl", "--version"},
		{"--target=", "--jsonl"},
		{"--target=  ", "--jsonl"},
		{"--evidence=", "--jsonl"},
		{"--output=", "--target=invalid://fixture"},
		{"--headers", "unused"},
		{"-H", "unused"},
		{"unexpected-target"},
		{"--silent", "--target", "invalid://target"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			code, stdout, stderr := runCLI(t, nil, args...)
			if code == 0 || stdout != "" || stderr == "" {
				t.Fatalf("invalid arguments: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestCLILoadFailures(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte("["), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing catalogue list", []string{"--silent", "--list", "--fingerprints", missing}},
		{"missing catalogue scan", []string{"--target", "invalid://target", "--fingerprints", missing}},
		{"malformed catalogue list", []string{"--silent", "--list", "--fingerprints", malformed}},
		{"missing input", []string{"--input", missing}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, strings.NewReader(""), tc.args...)
			if code == 0 || stderr == "" {
				t.Fatalf("load failure: exit=%d stderr=%q", code, stderr)
			}
		})
	}
}

func TestCLISilentList(t *testing.T) {
	catalogue := filepath.Join(t.TempDir(), "fingerprints.json")
	if err := os.WriteFile(catalogue, []byte(`[{"name":"Zulu (Zed)","schemas":[{"fingerprints":[{"type":"Content","pattern":"zulu"}]}]},{"name":"Alpha (Acme)","schemas":[{"fingerprints":[{"type":"Content","pattern":"alpha"}]}]}]`), 0600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, nil, "--no-colors", "--silent", "--list", "--fingerprints", catalogue)
	alpha, zulu := strings.Index(stdout, "Alpha"), strings.Index(stdout, "Zulu")
	if code != 0 || stderr != "" || alpha < 0 || zulu <= alpha || !strings.Contains(stdout, "Acme") || !strings.Contains(stdout, "Zed") {
		t.Fatalf("silent list: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCLISelectsExplicitInputBeforePipe(t *testing.T) {
	dir := t.TempDir()
	catalogue := filepath.Join(dir, "fingerprints.json")
	input := filepath.Join(dir, "input.txt")
	if err := os.WriteFile(catalogue, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, []byte("invalid://from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"target before pipe", "invalid://from-stdin\n", []string{"--target", "invalid://from-target"}, "invalid://from-target"},
		{"target before empty pipe", "", []string{"--target", "invalid://from-target"}, "invalid://from-target"},
		{"file before pipe", "invalid://from-stdin\n", []string{"--input", input}, "invalid://from-file"},
		{"file before empty pipe", "", []string{"--input", input}, "invalid://from-file"},
		{"pipe without explicit input", "invalid://from-stdin\n", nil, "invalid://from-stdin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "results.json")
			args := append([]string{"--silent", "--no-colors", "--output", output, "--fingerprints", catalogue}, tc.args...)
			code, stdout, stderr := runCLI(t, strings.NewReader(tc.stdin), args...)
			if code != 0 || stdout != "" || stderr != "" {
				t.Fatalf("scan: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var results []struct{ Target string }
			if err := json.Unmarshal(data, &results); err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 || results[0].Target != tc.want {
				t.Fatalf("selected input: got %s, want target %q", data, tc.want)
			}
		})
	}
}

func TestCLIRegularFileStdin(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "stdin.txt")
	output := filepath.Join(dir, "results.json")
	if err := os.WriteFile(input, []byte("invalid://from-redirect\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	code, stdout, stderr := runCLI(t, stdin, "--silent", "--output", output)
	if code != 0 || stdout != "" || stderr != "" {
		t.Fatalf("redirected stdin: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var results []struct{ Target string }
	if err := json.Unmarshal(data, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Target != "invalid://from-redirect" {
		t.Fatalf("redirected input: got %s", data)
	}
}

func TestCLIInputFailureDoesNotPublishPartialOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "results.json")
	if err := os.WriteFile(input, []byte("invalid://completed\n"+strings.Repeat("x", 1<<17)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, nil, "--silent", "--input", input, "--output", output)
	if code == 0 || stderr == "" {
		t.Fatalf("input failure was hidden: exit=%d stderr=%q", code, stderr)
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "previous report" {
		t.Fatalf("partial report published: %q %v", data, err)
	}
}

func TestCLIEmptyInputReplacesStaleReport(t *testing.T) {
	for _, extension := range []string{".JSON", ".JSONL", ".CsV", ".txt"} {
		path := filepath.Join(t.TempDir(), "results"+extension)
		if err := os.WriteFile(path, []byte("stale report"), 0600); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCLI(t, strings.NewReader(" \n\t\n"), "--silent", "--output", path)
		if code != 0 || stdout != "" || stderr != "" {
			t.Fatalf("empty scan failed: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "stale report") {
			t.Fatalf("stale output survived: %q", data)
		}
		if extension == ".JSON" {
			var results []wafme0w.Result
			if err := json.Unmarshal(data, &results); err != nil || results == nil || len(results) != 0 {
				t.Fatalf("empty report invalid: %q %v", data, err)
			}
		}
	}
}

func TestCLICancelledContextDoesNotPublish(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	path := filepath.Join(t.TempDir(), "output.json")
	var stdout, stderr bytes.Buffer
	code := runContext(ctx, []string{"--silent", "--output", path, "--target", "invalid://target"}, nil, false, &stdout, &stderr)
	if code != 130 {
		t.Fatalf("cancelled execution exit=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled execution published output: %v", err)
	}
}

func TestConsolePreservesUncertaintyWhenWarningsSuppressed(t *testing.T) {
	au := aurora.New(aurora.WithColors(false))
	for _, state := range []wafme0w.EvaluationState{wafme0w.Incomplete, wafme0w.Failed} {
		var stdout, stderr bytes.Buffer
		result := wafme0w.Result{Target: "invalid://fixture", Outcome: wafme0w.Outcome{
			State: state, Diagnostics: []wafme0w.Diagnostic{{Code: "fixture_error", Evidence: 0, Message: "diagnostic detail"}},
		}}
		if err := printResult(&stdout, &stderr, result, true, au); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(stdout.String(), "FOUND ") || strings.HasPrefix(stdout.String(), "NO MATCH ") || !strings.Contains(stdout.String(), "Could not") || stderr.Len() != 0 {
			t.Fatalf("warning suppression lost evaluation state: stdout=%q stderr=%q", stdout.String(), stderr.String())
		}
	}
}

func TestConsoleSummarizesIncompleteEvidence(t *testing.T) {
	result := wafme0w.Result{
		Target: "saved-response",
		Outcome: wafme0w.Outcome{
			State:   wafme0w.Incomplete,
			Matches: []wafme0w.Match{{Product: "Known WAF"}},
			Diagnostics: []wafme0w.Diagnostic{
				{Code: "redirect_scope", Message: "request-detail-one"},
				{Code: "redirect_scope", Message: "request-detail-two"},
				{Code: "body_truncated", Message: "request-detail-three"},
			},
		},
	}
	for i := 0; i < 200; i++ {
		result.Outcome.IncompleteProducts = append(result.Outcome.IncompleteProducts, fmt.Sprintf("Unconfirmed product %d", i))
		result.Evidence = append(result.Evidence, wafme0w.EvidenceSummary{RequestURL: "request-detail"})
	}
	var stdout, stderr bytes.Buffer
	if err := printResult(&stdout, &stderr, result, false, colorizer(&stdout, true)); err != nil {
		t.Fatal(err)
	}
	if strings.Count(stdout.String(), "\n") != 1 || strings.Count(stderr.String(), "\n") != 1 {
		t.Fatalf("console expanded evidence instead of summarizing: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "FOUND ") || !strings.Contains(stdout.String(), "Known WAF") || !strings.Contains(stdout.String(), "partial scan") {
		t.Fatalf("summary lost the finding or its limitation: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	for _, r := range stdout.String() + stderr.String() {
		if unicode.IsDigit(r) {
			t.Fatal("per-target output exposed internal counts")
		}
	}
	if strings.Contains(stdout.String()+stderr.String(), "request-detail") || strings.Contains(stdout.String(), "Unconfirmed product") {
		t.Fatal("console leaked per-observation detail or the unconfirmed product list")
	}
}

func fixtureCatalogue(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "catalogue.json")
	data := `[{"name":"Saved fixture","schemas":[{"fingerprints":[{"type":"Content","pattern":"saved-marker"}]}]}]`
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func captureLines(t *testing.T, captures ...wafme0w.Capture) string {
	t.Helper()
	var input bytes.Buffer
	for _, capture := range captures {
		if err := json.NewEncoder(&input).Encode(capture); err != nil {
			t.Fatal(err)
		}
	}
	return input.String()
}

func decodeResultLines(t *testing.T, data string) []wafme0w.Result {
	t.Helper()
	var results []wafme0w.Result
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		var result wafme0w.Result
		if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
			t.Fatalf("stdout is not one result per line: %q: %v", scanner.Text(), err)
		}
		if result.SchemaVersion != wafme0w.ResultSchemaVersion || result.Target == "" {
			t.Fatalf("stdout contains a non-result record: %q", scanner.Text())
		}
		results = append(results, result)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return results
}

func TestCLIPassiveJSONLDoesNotRequestTarget(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	target := server.URL + "/saved/path?retained=yes"
	evidence := wafme0w.Evidence{
		Role: "NormalRequest", StatusCode: 200, Body: []byte("saved-marker"),
		RequestURL: target, EffectiveURL: server.URL + "/saved/final",
		RedirectChain: []string{server.URL + "/saved/final"},
	}
	input := captureLines(t,
		wafme0w.Capture{Target: target, Evidence: []wafme0w.Evidence{evidence}},
		wafme0w.Capture{Target: "saved second capture", Evidence: []wafme0w.Evidence{{Role: "NormalRequest", StatusCode: 200, Body: []byte("ordinary response")}}},
	)
	code, stdout, stderr := runCLI(t, strings.NewReader(input), "--evidence=-", "--jsonl", "--fingerprints", fixtureCatalogue(t))
	if code != 0 {
		t.Fatalf("passive CLI exit=%d stderr=%q", code, stderr)
	}
	results := decodeResultLines(t, stdout)
	if len(results) != 2 || results[0].Target != target || results[1].Target != "saved second capture" {
		t.Fatalf("lost or altered captures: %+v", results)
	}
	if len(results[0].Outcome.Matches) != 1 || results[0].Outcome.Matches[0].Product != "Saved fixture" || len(results[1].Outcome.Matches) != 0 {
		t.Fatalf("saved bodies were not classified: %+v", results)
	}
	if requests.Load() != 0 {
		t.Fatalf("passive mode made %d requests", requests.Load())
	}
	if results[0].Provenance.ProgramVersion != wafme0w.Version() || len(results[0].Provenance.CatalogueSHA256) != 64 || results[0].Provenance.ScanMode != "passive" {
		t.Fatalf("missing reproducibility metadata: %+v", results[0].Provenance)
	}
	if len(results[0].Evidence) != 1 || results[0].Evidence[0].EffectiveURL != evidence.EffectiveURL || !reflect.DeepEqual(results[0].Evidence[0].RedirectChain, evidence.RedirectChain) {
		t.Fatalf("lost request/redirect evidence: %+v", results[0].Evidence)
	}
	if stderr == "" || strings.Contains(stdout, "saved-marker") || strings.ContainsAny(stdout+stderr, "\x1b\r") {
		t.Fatalf("machine stream leaked body/banner/color or lost summary: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestCLIStrictPublishesFullReportBeforeExit(t *testing.T) {
	for _, tc := range []struct {
		name      string
		evidence  []wafme0w.Evidence
		wantState wafme0w.EvaluationState
		wantCode  int
	}{
		{"clean", []wafme0w.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}, wafme0w.Complete, 0},
		{"diagnosed match", []wafme0w.Evidence{
			{Role: "Normal", StatusCode: 200, Body: []byte("saved-marker")},
			{Role: "Auxiliary", TransportError: "saved connection failure"},
		}, wafme0w.Complete, 2},
		{"incomplete", []wafme0w.Evidence{{Role: "Normal", StatusCode: 200, BodyTruncated: true}}, wafme0w.Incomplete, 2},
		{"missing response", []wafme0w.Evidence{{Role: "Normal", TransportError: "saved connection failure"}}, wafme0w.Incomplete, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
				t.Fatal(err)
			}
			input := captureLines(t,
				wafme0w.Capture{Target: "first", Evidence: []wafme0w.Evidence{{Role: "NormalRequest", StatusCode: 200, Body: []byte("saved-marker")}}},
				wafme0w.Capture{Target: "second", Evidence: tc.evidence},
			)
			capturePath := filepath.Join(filepath.Dir(output), "captures.jsonl")
			if err := os.WriteFile(capturePath, []byte(input), 0600); err != nil {
				t.Fatal(err)
			}
			code, stdout, stderr := runCLI(t, nil, "--evidence", capturePath, "--jsonl", "--strict", "--output", output, "--fingerprints", fixtureCatalogue(t))
			if code != tc.wantCode {
				t.Fatalf("strict exit=%d want=%d stderr=%q", code, tc.wantCode, stderr)
			}
			streamed := decodeResultLines(t, stdout)
			data, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			var published []wafme0w.Result
			if err := json.Unmarshal(data, &published); err != nil {
				t.Fatalf("strict exit lost completed report: %q: %v", data, err)
			}
			if len(published) != 2 || published[1].Outcome.State != tc.wantState || !reflect.DeepEqual(published, streamed) {
				t.Fatalf("strict publication incomplete: %+v; streamed %+v", published, streamed)
			}
		})
	}
}

func TestCLIJournalSurvivesFinalPublicationFailure(t *testing.T) {
	dir := t.TempDir()
	output, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(output, "previous")
	if err := os.WriteFile(old, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	previous := "{\"type\":\"diagnostic\",\"diagnostic\":{\"code\":\"earlier\",\"evidence\":-1,\"message\":\"retained\"}}\n"
	if err := os.WriteFile(journal, []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	input := captureLines(t, wafme0w.Capture{Target: "saved", Evidence: []wafme0w.Evidence{{Role: "NormalRequest", StatusCode: 200, Body: []byte("saved-marker")}}})
	code, _, stderr := runCLI(t, strings.NewReader(input), "--evidence=-", "--silent", "--strict", "--output", output, "--diagnostics-journal", journal, "--fingerprints", fixtureCatalogue(t))
	if code != 1 || stderr == "" {
		t.Fatalf("publication failure exit=%d stderr=%q", code, stderr)
	}
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(previous)) || bytes.Contains(data, []byte("saved-marker")) {
		t.Fatalf("journal was overwritten or leaked response body: %q", data)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []journalRecord
	for {
		var record journalRecord
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("unrecoverable journal: %v", err)
		}
		records = append(records, record)
	}
	if len(records) != 3 || records[1].Type != "result" || records[1].Result == nil || records[1].Result.Target != "saved" || len(records[1].Result.Outcome.Matches) != 1 || records[2].Diagnostic == nil || records[2].Diagnostic.Code != "run_error" {
		t.Fatalf("missing recovery evidence or publication diagnostic: %+v", records)
	}
	if data, err := os.ReadFile(old); err != nil || string(data) != "preserved" {
		t.Fatalf("failed publication replaced previous data: %q %v", data, err)
	}
}

func TestCLIJournalRejectsFileAliases(t *testing.T) {
	for _, kind := range []string{"same path", "symlink", "hardlink", "output", "dangling output symlink", "stdin"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			source, journal := filepath.Join(dir, "saved.jsonl"), filepath.Join(dir, "journal.jsonl")
			content := captureLines(t, wafme0w.Capture{Target: "saved", Evidence: []wafme0w.Evidence{}})
			if err := os.WriteFile(source, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"--evidence", source, "--jsonl"}
			var stdin io.Reader
			switch kind {
			case "same path":
				journal = filepath.Join(dir, ".", "saved.jsonl")
			case "symlink":
				if err := os.Symlink(source, journal); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			case "hardlink":
				if err := os.Link(source, journal); err != nil {
					t.Skipf("hardlinks unavailable: %v", err)
				}
			case "output":
				args = append(args, "--output", journal)
			case "dangling output symlink":
				output := filepath.Join(dir, "new-report.json")
				if err := os.Symlink(output, journal); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				args = append(args, "--output", output)
			case "stdin":
				file, err := os.Open(source)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				stdin, journal = file, source
				args = []string{"--evidence=-", "--jsonl"}
			}
			args = append(args, "--diagnostics-journal", journal)
			code, stdout, stderr := runCLI(t, stdin, args...)
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("journal alias accepted: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if data, err := os.ReadFile(source); err != nil || string(data) != content {
				t.Fatalf("alias check damaged source: %q %v", data, err)
			}
		})
	}
}

type failedConsole struct{}

func (failedConsole) Write([]byte) (int, error) { return 0, errors.New("console closed") }

func TestCLIConsoleFailureUnblocksOwnedInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runContext(ctx, []string{"--jsonl", "--output", output}, reader, true, failedConsole{}, &stderr)
	}()
	if _, err := io.WriteString(writer, "invalid://saved\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 1 {
			t.Fatalf("sink error exit=%d stderr=%q", code, stderr.String())
		}
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("sink failure left scanner blocked on owned input")
	}
	if data, err := os.ReadFile(output); err != nil || string(data) != "previous report" {
		t.Fatalf("sink failure published partial report: %q %v", data, err)
	}
}

func TestHumanOutputEscapesUntrustedControls(t *testing.T) {
	poison := "safe\x1b[31m\r\nFORGED\t\u202e\u0085"
	result := wafme0w.Result{
		Target: poison, Origin: poison + "/origin",
		Outcome: wafme0w.Outcome{
			State:              wafme0w.Incomplete,
			Matches:            []wafme0w.Match{{Product: poison, Schema: 1}},
			IncompleteProducts: []string{poison},
			Diagnostics:        []wafme0w.Diagnostic{{Code: poison, Message: poison}},
		},
		Generic:  wafme0w.GenericDetection{Mode: wafme0w.WAFHeaderDetected, Reason: poison},
		Evidence: []wafme0w.EvidenceSummary{{Role: poison, RequestURL: poison, EffectiveURL: poison + "/end", RedirectChain: []string{poison}, ErrorCode: poison}},
	}
	var stdout, stderr bytes.Buffer
	au := colorizer(&stdout, false)
	if err := printResult(&stdout, &stderr, result, false, au); err != nil {
		t.Fatal(err)
	}
	if err := printProducts(&stdout, []string{poison}, au); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{stdout.String(), stderr.String()} {
		for _, r := range text {
			if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				t.Fatalf("terminal control survived sanitization: %q", text)
			}
		}
		if strings.Contains(text, "\nFORGED") || !strings.Contains(text, `\x1b`) || !strings.Contains(text, `\nFORGED`) {
			t.Fatalf("untrusted line break or escape was not made visible: %q", text)
		}
	}
	code, _, errorText := runCLI(t, nil, "--unknown="+poison)
	if code != 1 || strings.ContainsAny(errorText, "\x1b\r") {
		t.Fatalf("CLI parser error injected terminal controls: %q", errorText)
	}
}

func TestCLIReportsVersionWithoutCatalogue(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "--version", "--fingerprints", filepath.Join(t.TempDir(), "missing.json"))
	if code != 0 || stdout != fmt.Sprintf("wafme0w %s\n", wafme0w.Version()) || stderr != "" {
		t.Fatalf("version output: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestCLIBaselineUsesOneNormalRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "saved-marker")
	}))
	defer server.Close()
	target := server.URL + "/normal?keep=yes"
	code, stdout, stderr := runCLI(t, nil,
		"--target", target, "--baseline", "--jsonl", "--no-generic", "--fingerprints", fixtureCatalogue(t),
		"--request-timeout=1s", "--target-timeout=2s", "--max-requests=1", "--max-connections=1",
		"--rate=100", "--per-origin-rate=50", "--max-redirects=0",
		"--redirect-policy=allowlist", "--allow-origin", server.URL, "--allow-origin=https://unused.example",
	)
	if code != 0 {
		t.Fatalf("baseline CLI exit=%d stderr=%q", code, stderr)
	}
	results := decodeResultLines(t, stdout)
	if requests.Load() != 1 || len(results) != 1 || results[0].Target != target || len(results[0].Evidence) != 1 || len(results[0].Outcome.Matches) != 1 {
		t.Fatalf("baseline did not classify one normal response: requests=%d results=%+v", requests.Load(), results)
	}
	settings := results[0].Provenance.Settings
	if results[0].Provenance.ScanMode != "baseline" || !settings.BaselineOnly || settings.FastMode || settings.Passive ||
		settings.RequestTimeout != time.Second || settings.TargetTimeout != 2*time.Second ||
		settings.MaxRequests != 1 || settings.MaxConnections != 1 || settings.RequestsPerSecond != 100 ||
		settings.PerOriginRequestsPerSecond != 50 || settings.MaxRedirects != 0 || settings.RedirectPolicy != "allowlist" ||
		len(settings.AllowedOrigins) != 2 {
		t.Fatalf("published provenance does not describe effective CLI controls: %+v", results[0].Provenance)
	}
}

func TestCLIJournalErrorsDoNotReplaceReport(t *testing.T) {
	for _, kind := range []string{"missing parent", "directory", "unfinished record"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			output, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
			if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing parent":
				journal = filepath.Join(dir, "missing", "journal.jsonl")
			case "directory":
				if err := os.Mkdir(journal, 0700); err != nil {
					t.Fatal(err)
				}
			case "unfinished record":
				if err := os.WriteFile(journal, []byte(`{"type":"result"`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			input := captureLines(t, wafme0w.Capture{Target: "saved", Evidence: []wafme0w.Evidence{}})
			code, stdout, stderr := runCLI(t, strings.NewReader(input), "--evidence=-", "--silent", "--output", output, "--diagnostics-journal", journal)
			if code != 1 || stdout != "" || stderr == "" {
				t.Fatalf("journal error was hidden: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			if data, err := os.ReadFile(output); err != nil || string(data) != "previous report" {
				t.Fatalf("journal failure replaced previous report: %q %v", data, err)
			}
			if kind == "unfinished record" {
				if data, err := os.ReadFile(journal); err != nil || string(data) != `{"type":"result"` {
					t.Fatalf("partial journal evidence was overwritten: %q %v", data, err)
				}
			}
		})
	}
}
