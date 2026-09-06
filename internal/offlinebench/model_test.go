package offlinebench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func TestLoadCorpusRejectsUntrustedEvidence(t *testing.T) {
	body := []byte("fixture")
	digestBytes := sha256.Sum256(body)
	digest := hex.EncodeToString(digestBytes[:])

	writeFixture := func(t *testing.T, mutate func(*Corpus), storedBody []byte, suffix string) error {
		t.Helper()
		directory := t.TempDir()
		bodies := filepath.Join(directory, "bodies")
		if err := os.Mkdir(bodies, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bodies, digest+".bin"), storedBody, 0o600); err != nil {
			t.Fatal(err)
		}
		corpus := Corpus{
			SchemaVersion: SchemaVersion,
			Profile:       "test",
			Products: []Product{{ID: "example", Names: map[string]string{
				"wafme0w": "Example", "wafw00f": "Example",
			}}},
			Cases: []Case{{
				ID: "case", Kind: "synthetic-conformance", Truth: Truth{State: "known", Products: []string{"example"}},
				Provenance: syntheticProvenance("case"),
				Review:     "Reviewed local example marker",
				Expected: map[string]Expectation{
					"wafme0w": {State: "complete", Products: []string{"example"}},
					"wafw00f": {State: "complete", Products: []string{"example"}},
				},
				Responses: []Response{{Role: "Normal", StatusCode: 200, Reason: "OK", BodySHA256: digest}},
			}},
		}
		mutate(&corpus)
		encoded, err := json.Marshal(corpus)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, suffix...)
		manifest := filepath.Join(directory, "corpus.json")
		if err := os.WriteFile(manifest, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err = LoadCorpus(manifest, bodies)
		return err
	}

	if err := writeFixture(t, func(*Corpus) {}, body, ""); err != nil {
		t.Fatalf("valid corpus rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Corpus)
		body   []byte
		suffix string
		want   string
	}{
		{name: "digest mismatch", mutate: func(*Corpus) {}, body: []byte("tampered"), want: "digest mismatch"},
		{name: "header injection", mutate: func(c *Corpus) {
			c.Cases[0].Responses[0].Headers = []wafme0w.Header{{Name: "X-Test", Value: "ok\r\nInjected: true"}}
		}, body: body, want: "invalid header"},
		{name: "embedded body", mutate: func(c *Corpus) { c.Cases[0].Responses[0].Body = []byte("hidden") }, body: body, want: "embeds body data"},
		{name: "trailing value", mutate: func(*Corpus) {}, body: body, suffix: `{}`, want: "trailing JSON value"},
		{name: "missing expectation", mutate: func(c *Corpus) { delete(c.Cases[0].Expected, "wafw00f") }, body: body, want: "expectations for both"},
		{name: "incomplete without products", mutate: func(c *Corpus) { c.Cases[0].Expected["wafme0w"] = Expectation{State: "incomplete"} }, body: body, want: "inconsistent"},
		{name: "unreviewed fixture", mutate: func(c *Corpus) { c.Cases[0].Review = "" }, body: body, want: "requires id, kind, and review"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := writeFixture(t, test.mutate, test.body, test.suffix)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("got %v, want error containing %q", err, test.want)
			}
		})
	}
}

func syntheticProvenance(id string) CaptureProvenance {
	return CaptureProvenance{Type: "synthetic", SourceID: "test-synthetic:" + id, CollectedOn: "unknown", ReviewStatus: "conformance", ReviewedOn: "unknown", Reviewer: "unknown"}
}

// These metadata-only test records exercise admission, not actual captures.
func testRealCase() Case {
	return Case{
		ID: "test-only-real-metadata", Kind: "real-capture", Review: "unit test of provenance admission",
		Truth: Truth{State: "known"},
		Provenance: CaptureProvenance{
			Type: "real-capture", SourceID: "test-only:capture", CollectedOn: "2026-09-01",
			ReviewStatus: "reviewed-real", ReviewedOn: "2026-09-03", Reviewer: "test-reviewer",
			Authorization:    &CaptureAssertion{By: "test-owner", Reference: "test-only:authorization", On: "2026-08-31"},
			Sanitization:     &CaptureAssertion{By: "test-sanitizer", Reference: "test-only:sanitization", On: "2026-09-02"},
			IndependentTruth: true, TruthSourceID: "test-only:independent-inventory",
		},
	}
}

func TestRealCaptureAdmissionRequiresTraceableIndependentReview(t *testing.T) {
	valid := testRealCase()
	if err := validateCaptureProvenance(valid); err != nil || !reviewedReal(valid) {
		t.Fatalf("complete review chain rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*Case)
	}{
		{"missing authorization", func(c *Case) { c.Provenance.Authorization = nil }},
		{"missing sanitization", func(c *Case) { c.Provenance.Sanitization = nil }},
		{"unknown reviewer", func(c *Case) { c.Provenance.Reviewer = "unknown" }},
		{"unknown review date", func(c *Case) { c.Provenance.ReviewedOn = "unknown" }},
		{"invalid collection date", func(c *Case) { c.Provenance.CollectedOn = "2026-02-30" }},
		{"late authorization", func(c *Case) { c.Provenance.Authorization.On = "2026-09-02" }},
		{"review before sanitization", func(c *Case) { c.Provenance.ReviewedOn = "2026-09-01" }},
		{"unknown truth", func(c *Case) { c.Truth.State = "unknown" }},
		{"detector-derived truth", func(c *Case) { c.Provenance.IndependentTruth = false }},
		{"missing independent source", func(c *Case) { c.Provenance.TruthSourceID = "" }},
		{"synthetic promoted to real review", func(c *Case) { c.Kind = "synthetic-conformance"; c.Provenance.Type = "synthetic" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := testRealCase()
			test.mutate(&fixture)
			if err := validateCaptureProvenance(fixture); err == nil || reviewedReal(fixture) {
				t.Fatal("invalid or synthetic provenance admitted as reviewed real")
			}
		})
	}
	unreviewed := testRealCase()
	unreviewed.Truth.State = "unknown"
	unreviewed.Provenance.ReviewStatus = "unreviewed"
	unreviewed.Provenance.ReviewedOn, unreviewed.Provenance.Reviewer = "unknown", "unknown"
	unreviewed.Provenance.IndependentTruth, unreviewed.Provenance.TruthSourceID = false, ""
	if err := validateCaptureProvenance(unreviewed); err != nil || reviewedReal(unreviewed) {
		t.Fatalf("authorized sanitized unreviewed input not retained as unknown: %v", err)
	}
}
