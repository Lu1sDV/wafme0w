package offlinebench

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func TestWafme0wWorkerPreservesEvidenceState(t *testing.T) {
	catalogue := filepath.Join(t.TempDir(), "catalogue.json")
	data := `[{"name":"Header","schemas":[{"any":true,"fingerprints":[{"type":"Header","header_key":"X-Example","header_value":"present"}]}]},{"name":"Content","schemas":[{"fingerprints":[{"type":"Content","pattern":"marker"}]}]}]`
	if err := os.WriteFile(catalogue, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata := Response{Role: "Normal", StatusCode: 200, Reason: "OK", Headers: []wafme0w.Header{{Name: "X-Example", Value: "present"}}, Body: []byte("marker")}
	truncated, errored := metadata, metadata
	truncated.BodyTruncated = true
	errored.TransportError = "unexpected EOF"
	input := WorkerInput{
		SchemaVersion: SchemaVersion, Profile: "shared-products", Iterations: 2,
		Products: []Product{{ID: "header", Names: map[string]string{"wafme0w": "Header"}}, {ID: "content", Names: map[string]string{"wafme0w": "Content"}}},
		Cases: []Case{
			{ID: "complete", Responses: []Response{metadata}},
			{ID: "missing"},
			{ID: "truncated", Responses: []Response{truncated}},
			{ID: "body-error", Responses: []Response{errored}},
		},
	}
	result := invokeNativeWorker(t, input, catalogue)
	if result.CatalogueSize != 2 || len(result.Results) != 4 {
		t.Fatalf("unexpected worker result: %+v", result)
	}
	if got := result.Results[0]; got.State != "complete" || !slices.Equal(got.RawProducts, []string{"Content", "Header"}) {
		t.Fatalf("complete evidence: %+v", got)
	}
	if got := result.Results[1]; got.State != "incomplete" || !slices.Equal(got.IncompleteProducts, []string{"Content", "Header"}) || len(got.RawProducts) != 0 {
		t.Fatalf("missing evidence became a clean negative: %+v", got)
	}
	for _, got := range result.Results[2:] {
		if got.State != "incomplete" || !slices.Equal(got.RawProducts, []string{"Header"}) || !slices.Equal(got.IncompleteProducts, []string{"Content"}) {
			t.Fatalf("body incompleteness discarded metadata or became conclusive: %+v", got)
		}
	}
	input.Profile = "full-native"
	input.Products = input.Products[:1]
	full := invokeNativeWorker(t, input, catalogue)
	if full.CatalogueSize != 2 || !slices.Equal(full.Results[0].RawProducts, []string{"Content", "Header"}) {
		t.Fatalf("full-native profile selected only shared products: %+v", full)
	}
}

func invokeNativeWorker(t *testing.T, input WorkerInput, catalogue string) WorkerOutput {
	t.Helper()
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := RunWafme0wWorker(bytes.NewReader(encoded), &output, catalogue); err != nil {
		t.Fatal(err)
	}
	var result WorkerOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func BenchmarkClassifyEvidence(b *testing.B) {
	definitions, err := loadCatalogue("../../cmd/wafme0w/resources/waf-fingerprints.json")
	if err != nil {
		b.Fatal(err)
	}
	engine, err := wafme0w.Compile(definitions)
	if err != nil {
		b.Fatal(err)
	}
	corpus, err := LoadCorpus("../../tools/offlinebench/testdata/corpus.json", "../../tools/offlinebench/testdata/bodies")
	if err != nil {
		b.Fatal(err)
	}
	cases := make([][]wafme0w.Evidence, len(corpus.Cases))
	for i, fixture := range corpus.Cases {
		cases[i] = nativeEvidence(fixture.Responses)
	}
	var diverse []byte
	for first := byte(32); first < 127; first++ {
		for second := byte(32); second < 127; second++ {
			diverse = append(diverse, first, second)
		}
	}
	html := []byte(`<a class="link" href="https://example.com/">Security module</a><script>window.location.href = "/"; const server = "origin";</script>`)
	workloads := []struct {
		name  string
		cases [][]wafme0w.Evidence
	}{{"corpus", cases}}
	for _, body := range []struct {
		name string
		text []byte
	}{
		{"ascii_32KiB", bytes.Repeat([]byte("ordinary origin response. "), 1261)},
		{"unicode_32KiB", bytes.Repeat([]byte("ordinary origin 世界 response. "), 1024)},
		{"ascii_256KiB", bytes.Repeat([]byte("ordinary origin response. "), 10083)},
		{"html_32KiB", bytes.Repeat([]byte(`<!doctype html><html><head><title>Example store</title></head><body><main><h1>Welcome</h1><p>Browse our products and services.</p><a href="/account">Account</a></main></body></html>`), 200)[:32768]},
		{"diverse_ascii_32KiB", bytes.Repeat(diverse, 2)[:32768]},
		// Saturate the filter, then repeat common prefixes without complete signatures.
		{"prefix_heavy_html_512KiB", append(bytes.Clone(diverse), bytes.Repeat(html, 524288/len(html)+1)...)[:524288]},
		{"uppercase_32KiB", bytes.Repeat([]byte("ORDINARY ORIGIN RESPONSE. "), 1261)},
		{"late_unicode_32KiB", append(bytes.Repeat([]byte("ordinary origin response. "), 1261), []byte("世界")...)},
		{"folding_unicode_32KiB", bytes.Repeat([]byte("Kelvin ſymbol ςigma İı 世界 response. "), 713)},
		{"invalid_utf8_32KiB", bytes.Repeat([]byte("ordinary \xffresponse. "), 1638)},
	} {
		workloads = append(workloads, struct {
			name  string
			cases [][]wafme0w.Evidence
		}{body.name, [][]wafme0w.Evidence{{{
			Role: "Normal", StatusCode: 200, Reason: "OK",
			Headers: []wafme0w.Header{{Name: "Server", Value: "nginx"}}, Body: body.text,
		}}}})
	}
	for _, workload := range workloads {
		b.Run(workload.name, func(b *testing.B) {
			b.ReportAllocs()
			var outcome wafme0w.Outcome
			for i := 0; b.Loop(); i++ {
				outcome = engine.Classify(workload.cases[i%len(workload.cases)])
			}
			runtime.KeepAlive(outcome)
		})
	}
}

func BenchmarkClassifySingleBody(b *testing.B) {
	engine, err := wafme0w.Compile([]wafme0w.WAF{{Name: "single", Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "(?i)absent marker"}}}}}})
	if err != nil {
		b.Fatal(err)
	}
	evidence := []wafme0w.Evidence{{StatusCode: 200, Body: bytes.Repeat([]byte("ordinary origin response. "), 1261)}}
	b.ReportAllocs()
	for b.Loop() {
		runtime.KeepAlive(engine.Classify(evidence))
	}
}

func BenchmarkClassifySmallCatalogue(b *testing.B) {
	definitions := make([]wafme0w.WAF, 9)
	for i := range definitions {
		definitions[i] = wafme0w.WAF{Name: string(rune('A' + i)), Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "(?i)absent marker"}}}}}
	}
	engine, err := wafme0w.Compile(definitions)
	if err != nil {
		b.Fatal(err)
	}
	evidence := []wafme0w.Evidence{{StatusCode: 200, Body: bytes.Repeat([]byte("ordinary origin response. "), 1261)}}
	b.ReportAllocs()
	for b.Loop() {
		runtime.KeepAlive(engine.Classify(evidence))
	}
}

func BenchmarkClassifyUnguardedContent(b *testing.B) {
	engine, err := wafme0w.Compile([]wafme0w.WAF{{Name: "single", Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: `(?i)k*[0-9]`}}}}}})
	if err != nil {
		b.Fatal(err)
	}
	body := bytes.Repeat([]byte("X"), 1<<20)
	body[0] = '7'
	evidence := []wafme0w.Evidence{{StatusCode: 200, Body: body}}
	b.ReportAllocs()
	for b.Loop() {
		runtime.KeepAlive(engine.Classify(evidence))
	}
}
