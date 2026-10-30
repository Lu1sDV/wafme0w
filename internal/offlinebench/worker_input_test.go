package offlinebench

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteRejectsExpandedWorkerInputBeforeIsolation(t *testing.T) {
	for _, test := range []struct {
		name   string
		bodies [][]byte
		review string
	}{
		{
			name: "base64 bodies",
			bodies: [][]byte{
				bytes.Repeat([]byte("x"), 1<<20), bytes.Repeat([]byte("x"), 1<<20),
				bytes.Repeat([]byte("x"), 1<<20), bytes.Repeat([]byte("x"), 1<<20),
			},
			review: strings.Repeat("x", 3<<20),
		},
		{name: "escaped metadata", review: strings.Repeat("<", 2<<20)},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest, bodies := writeBodyLimitCorpus(t, test.bodies)
			data, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var source Corpus
			if err := json.Unmarshal(data, &source); err != nil {
				t.Fatal(err)
			}
			source.Cases[0].Review = test.review
			var encoded bytes.Buffer
			encoder := json.NewEncoder(&encoded)
			encoder.SetEscapeHTML(false)
			if err := encoder.Encode(source); err != nil {
				t.Fatal(err)
			}
			if encoded.Len() > maxCorpusSize {
				t.Fatal("test source exceeds the manifest admission limit")
			}
			if err := os.WriteFile(manifest, encoded.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			corpus, err := LoadCorpus(manifest, bodies)
			if err != nil {
				t.Fatalf("source manifest and bodies should be admitted: %v", err)
			}
			output := filepath.Join(t.TempDir(), "not-published")
			_, _, _, err = Execute(context.Background(), corpus, manifest, Config{
				Executable: "unused", Catalogue: "unused", CoverageContract: "unused",
				Wafw00fPython: "unused", Wafw00fAdapter: "unused", OutputDir: output,
				// If process startup is attempted before preflight, this fails
				// with an isolation error instead of the required size error.
				Bubblewrap: filepath.Join(t.TempDir(), "must-not-be-started"),
				Iterations: 1, Blocks: 4,
			})
			want := fmt.Sprintf("expanded worker input exceeds %d bytes", maxWorkerInputSize)
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want preflight error containing %q", err, want)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("input-limit rejection created output: %v", err)
			}
		})
	}
}

func TestWafme0wWorkerReportsOversizedObjectAsInputLimit(t *testing.T) {
	input := `{"schema_version":3,"profile":"shared-products","iterations":1,"cases":[{"review":"` + strings.Repeat("x", maxWorkerInputSize) + `"}]}`
	var output bytes.Buffer
	err := RunWafme0wWorker(strings.NewReader(input), &output, "must-not-be-opened")
	if err == nil || !strings.Contains(err.Error(), "worker input exceeds") {
		t.Fatalf("oversized object should report the input limit, got %v", err)
	}
	if output.Len() != 0 {
		t.Fatal("oversized input produced a partial worker result")
	}
}

func TestMarshalWorkerInputChecksExpandedByteBoundary(t *testing.T) {
	request := WorkerInput{SchemaVersion: SchemaVersion, Profile: "shared-products", Iterations: 1, Cases: []Case{{ID: "boundary"}}}
	base, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	request.Cases[0].Review = strings.Repeat("x", maxWorkerInputSize-len(base))
	payload, err := marshalWorkerInput(request)
	if err != nil || len(payload) != maxWorkerInputSize {
		t.Fatalf("exact worker byte boundary rejected: size=%d err=%v", len(payload), err)
	}
	request.Cases[0].Review += "x"
	if payload, err := marshalWorkerInput(request); err == nil || payload != nil || !strings.Contains(err.Error(), "expanded worker input exceeds") {
		t.Fatalf("oversized encoded input was not rejected: size=%d err=%v", len(payload), err)
	}
}
