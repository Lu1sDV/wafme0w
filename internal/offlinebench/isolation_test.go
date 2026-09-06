package offlinebench

import (
	"context"
	"encoding/json"
	"os/exec"
	"testing"
	"time"
)

func TestNetworkIsolationCanary(t *testing.T) {
	bubblewrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Skip("bubblewrap unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := networkIsolationCanary(ctx, Config{Bubblewrap: bubblewrap}); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerOutputDecoderRejectsTrailingAndUnknownData(t *testing.T) {
	for _, data := range []string{
		`{"tool":"wafme0w"} {}`,
		`{"tool":"wafme0w","unexpected":true}`,
	} {
		if _, err := decodeWorkerOutput([]byte(data), "wafme0w"); err == nil {
			t.Fatalf("accepted untrusted worker output %q", data)
		}
	}
}

func TestExecuteRejectsInvalidSamplingAndGatesBeforeStartingWorkers(t *testing.T) {
	for _, config := range []Config{
		{Iterations: 1, Blocks: 3},
		{Iterations: 1, Blocks: 5},
		{Iterations: 1, Blocks: 4, MinimumCoverage: 1.01},
		{Iterations: 1, Blocks: 4, MinimumAccuracy: -0.01},
	} {
		if _, _, _, err := Execute(context.Background(), Corpus{}, "", config); err == nil {
			t.Fatalf("accepted invalid config: %+v", config)
		}
	}
}

func TestWorkerOutputRejectsInventedOrIncompletePythonProvenance(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*WorkerOutput)
	}{
		{"missing environment", func(o *WorkerOutput) { o.Python = nil }},
		{"missing runtime", func(o *WorkerOutput) { o.Python.Runtime = "" }},
		{"wrong installed version", func(o *WorkerOutput) { o.Python.Packages["wafw00f"] = "0.0" }},
		{"different module version", func(o *WorkerOutput) { o.Version = "0.0" }},
		{"changed source", func(o *WorkerOutput) { delete(o.Python.Sources, "main.py") }},
		{"invented digest", func(o *WorkerOutput) { o.Python.SourceTreeSHA256 = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			output := WorkerOutput{SchemaVersion: SchemaVersion, Tool: "wafw00f", Version: "2.4.2", Python: testManifest(t).Python}
			test.mutate(&output)
			data, err := json.Marshal(output)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeWorkerOutput(data, "wafw00f"); err == nil {
				t.Fatal("unobserved or inconsistent provenance accepted")
			}
		})
	}
}
