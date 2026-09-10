package wafme0w

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestSerializersRetainAllEvaluationStates(t *testing.T) {
	results := []Result{
		{Target: "invalid://clean", Outcome: Outcome{State: Complete}},
		{Target: "invalid://partial,quoted\"", Outcome: Outcome{State: Incomplete, Matches: []Match{{Product: "Named, WAF", Schema: 2}}, IncompleteProducts: []string{"Unknown"}, Diagnostics: []Diagnostic{{Code: "body_truncated", Evidence: 0, Message: "partial\nbody"}}}, Generic: GenericDetection{Reason: "generic\nanomaly"}},
		{Target: "invalid://failed", Outcome: Outcome{State: Failed, Diagnostics: []Diagnostic{{Code: "transport_error", Evidence: 0, Message: "connection failed"}}}},
	}
	results[1].SchemaVersion = ResultSchemaVersion
	results[1].Origin = "https://captured.example"
	results[1].Provenance = ResultProvenance{ProgramVersion: "fixture-version", CatalogueSHA256: strings.Repeat("a", 64)}
	results[1].Outcome.Matches[0].Fingerprints = []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}
	results[1].Evidence = []EvidenceSummary{{Index: 0, Role: "NormalRequest", RequestURL: "https://captured.example/path", EffectiveURL: "https://captured.example/end", RedirectChain: []string{"https://captured.example/end"}, StatusCode: 200, BodyTruncated: true, ErrorCode: "body_limit"}}
	results[1].Browser = &BrowserReport{ID: "capture-2", Mode: "screenshot", State: "partial", Reason: "image_failed\u202e\U000e0001", DOM: BrowserAsset{State: "complete", Saved: "/private/text.json"}, Screenshot: BrowserAsset{State: "failed"}}
	for _, format := range []string{"json", "jsonl", "csv", "txt"} {
		t.Run(format, func(t *testing.T) {
			var buffer bytes.Buffer
			writer, err := NewResultWriter(&buffer, format)
			if err != nil {
				t.Fatal(err)
			}
			for _, result := range results {
				if err := writer.Write(result); err != nil {
					t.Fatal(err)
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			var got []Result
			switch format {
			case "json":
				if err := json.Unmarshal(buffer.Bytes(), &got); err != nil {
					t.Fatal(err)
				}
			case "jsonl":
				scanner := bufio.NewScanner(&buffer)
				for scanner.Scan() {
					var result Result
					if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
						t.Fatal(err)
					}
					got = append(got, result)
				}
				if err := scanner.Err(); err != nil {
					t.Fatal(err)
				}
			case "csv":
				rows, err := csv.NewReader(&buffer).ReadAll()
				if err != nil {
					t.Fatal(err)
				}
				for _, row := range rows[1:] {
					result := Result{Target: row[0], Outcome: Outcome{State: EvaluationState(row[1])}}
					for i, value := range []any{&result.Outcome.Matches, &result.Generic, &result.Outcome.IncompleteProducts, &result.Outcome.Diagnostics, &result.SchemaVersion, &result.Origin, &result.Provenance, &result.Evidence, &result.Browser} {
						if err := json.Unmarshal([]byte(row[i+2]), value); err != nil {
							t.Fatal(err)
						}
					}
					got = append(got, result)
				}
			case "txt":
				if strings.ContainsAny(buffer.String(), "\u202e\U000e0001") {
					t.Fatalf("browser formatting controls entered TXT output: %q", buffer.String())
				}
				rows := strings.Split(strings.TrimSuffix(buffer.String(), "\n"), "\n")
				if len(rows) != len(results) {
					t.Fatalf("lost result rows: %q", buffer.String())
				}
				for _, row := range rows {
					fields := strings.Split(row, "\t")
					if len(fields) != 12 {
						t.Fatalf("missing result fields: %q", row)
					}
					target, err := strconv.Unquote(fields[0])
					if err != nil {
						t.Fatal(err)
					}
					_, stateField, ok := strings.Cut(fields[1], "=")
					state, err := strconv.Unquote(stateField)
					if !ok || err != nil {
						t.Fatalf("invalid state field: %q", fields[1])
					}
					result := Result{Target: target, Outcome: Outcome{State: EvaluationState(state)}}
					for j, value := range []any{&result.Outcome.Matches, &result.Generic, &result.Outcome.IncompleteProducts, &result.Outcome.Diagnostics, &result.SchemaVersion, &result.Origin, &result.Provenance, &result.Evidence, &result.Browser} {
						_, data, ok := strings.Cut(fields[j+2], "=")
						if !ok {
							t.Fatalf("missing field: %q", fields[j+2])
						}
						if err := json.Unmarshal([]byte(data), value); err != nil {
							t.Fatal(err)
						}
					}
					got = append(got, result)
				}
			}
			if !reflect.DeepEqual(got, results) {
				t.Fatalf("lossy output: got %+v, want %+v", got, results)
			}
		})
	}
}

type switchWriter struct {
	fail bool
	err  error
}

func (w *switchWriter) Write(p []byte) (int, error) {
	if w.fail {
		return 0, w.err
	}
	return len(p), nil
}

func TestSerializerPropagatesMidstreamWriterErrors(t *testing.T) {
	for _, format := range []string{"json", "jsonl", "csv", "txt"} {
		sentinel := errors.New("writer failed")
		sink := &switchWriter{err: sentinel}
		writer, err := NewResultWriter(sink, format)
		if err != nil {
			t.Fatal(err)
		}
		if err := writer.Write(Result{Target: "first", Outcome: Outcome{State: Complete}}); err != nil {
			t.Fatal(err)
		}
		sink.fail = true
		if err := writer.Write(Result{Target: "second", Outcome: Outcome{State: Failed}}); !errors.Is(err, sentinel) {
			t.Fatalf("%s lost writer error: %v", format, err)
		}
		if err := writer.Close(); !errors.Is(err, sentinel) {
			t.Fatalf("%s lost error on finalization: %v", format, err)
		}
	}
}

func TestEmptyJSONStreamIsAnArray(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewResultWriter(&buffer, ".JSON")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var results []Result
	if err := json.NewDecoder(&buffer).Decode(&results); err != nil {
		t.Fatal(err)
	}
	if results == nil || len(results) != 0 {
		t.Fatalf("empty stream is not an empty array: %#v", results)
	}
	if _, err := NewResultWriter(io.Discard, "unsupported"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestEmptyCSVRetainsBrowserColumn(t *testing.T) {
	var buffer bytes.Buffer
	writer, err := NewResultWriter(&buffer, "csv")
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buffer).ReadAll()
	want := []string{"target", "state", "matches", "generic", "incomplete_products", "diagnostics", "schema_version", "origin", "provenance", "evidence", "browser"}
	if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[0], want) {
		t.Fatalf("empty CSV lost its fixed schema: %v, %v", rows, err)
	}
}
