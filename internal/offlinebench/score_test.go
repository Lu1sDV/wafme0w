package offlinebench

import "testing"

func bothExpectations(expected Expectation) map[string]Expectation {
	return map[string]Expectation{"wafme0w": expected, "wafw00f": expected}
}

func scoreOutputs(products int, results []WorkerResult) map[string][]WorkerOutput {
	outputs := make(map[string][]WorkerOutput)
	for _, tool := range []string{"wafme0w", "wafw00f"} {
		outputs[tool] = []WorkerOutput{{SchemaVersion: SchemaVersion, Profile: "shared-products", CatalogueSize: products, Tool: tool, InitNS: 10, Results: results}}
	}
	return outputs
}

func TestAggregateKeepsFailuresAndUnknownTruthOutOfConfusionMatrix(t *testing.T) {
	products := []Product{
		{ID: "alpha", Names: map[string]string{"wafme0w": "Alpha", "wafw00f": "Alpha"}},
		{ID: "beta", Names: map[string]string{"wafme0w": "Beta", "wafw00f": "Beta"}},
	}
	corpus := Corpus{SchemaVersion: SchemaVersion, Profile: "test", Products: products, Cases: []Case{
		{ID: "wrong-product", Truth: Truth{State: "known", Products: []string{"alpha"}}, Expected: bothExpectations(Expectation{State: "complete", Products: []string{"alpha"}})},
		{ID: "failed-negative", Truth: Truth{State: "known"}, Expected: bothExpectations(Expectation{State: "complete"})},
		{ID: "unknown", Truth: Truth{State: "unknown"}, Expected: bothExpectations(Expectation{State: "complete", Products: []string{"beta"}})},
	}}
	outputs := scoreOutputs(2, []WorkerResult{
		{CaseID: "wrong-product", State: "complete", RawProducts: []string{"Beta"}, ElapsedNS: 10},
		{CaseID: "failed-negative", State: "failed", Reason: "timeout", ElapsedNS: 20},
		{CaseID: "unknown", State: "complete", RawProducts: []string{"Beta"}, ElapsedNS: 30},
	})
	_, summary, err := Aggregate(corpus, outputs)
	if err != nil {
		t.Fatal(err)
	}
	for tool, metrics := range summary.Metrics {
		if metrics.LabelledCases != 2 || metrics.EvaluatedLabelledCases != 1 || metrics.FailedCases != 1 {
			t.Fatalf("%s denominator accounting: %+v", tool, metrics)
		}
		if metrics.TruePositives != 0 || metrics.FalsePositives != 1 || metrics.FalseNegatives != 1 || metrics.ExactCases != 0 {
			t.Fatalf("%s confusion matrix: %+v", tool, metrics)
		}
		if metrics.LabelledEvaluationCoverage != 0.5 || metrics.ExactAccuracy == nil || *metrics.ExactAccuracy != 0 {
			t.Fatalf("%s rates: %+v", tool, metrics)
		}
	}
}

func TestExpectedIncompletePassesWithoutWeakeningCompleteCaseAccuracy(t *testing.T) {
	corpus := Corpus{SchemaVersion: SchemaVersion, Profile: "test", Products: []Product{{ID: "alpha", Names: map[string]string{"wafme0w": "Alpha", "wafw00f": "Alpha"}}}, Cases: []Case{
		{ID: "complete-positive", Truth: Truth{State: "known", Products: []string{"alpha"}}, Expected: bothExpectations(Expectation{State: "complete", Products: []string{"alpha"}})},
		{ID: "complete-negative", Truth: Truth{State: "known"}, Expected: bothExpectations(Expectation{State: "complete"})},
		{ID: "unavailable", Truth: Truth{State: "unknown"}, Expected: bothExpectations(Expectation{State: "incomplete", IncompleteProducts: []string{"alpha"}})},
	}}
	samples := []WorkerResult{
		{CaseID: "complete-positive", State: "complete", RawProducts: []string{"Alpha"}, ElapsedNS: 10},
		{CaseID: "complete-negative", State: "complete", ElapsedNS: 20},
		{CaseID: "unavailable", State: "incomplete", IncompleteProducts: []string{"Alpha"}, ElapsedNS: 1},
	}
	_, summary, err := Aggregate(corpus, scoreOutputs(1, samples))
	if err != nil {
		t.Fatal(err)
	}
	gates := Config{MinimumCoverage: 1, MinimumAccuracy: 1}
	if err := checkGates(summary, gates); err != nil {
		t.Fatalf("intentional incompleteness failed gate: %v", err)
	}
	if got := summary.Metrics["wafme0w"]; got.RawCompletionRate != 2.0/3 || got.ExpectedCompleteCoverage != 1 || got.StateConformance != 1 {
		t.Fatalf("wrong coverage denominator: %+v", got)
	}
	if summary.Comparison.PairedCases != 2 {
		t.Fatalf("incomplete cases entered timing comparison: %+v", summary.Comparison)
	}

	samples[1].State = "failed"
	_, summary, err = Aggregate(corpus, scoreOutputs(1, samples))
	if err != nil {
		t.Fatal(err)
	}
	if got := summary.Metrics["wafme0w"]; got.ExactAccuracy == nil || *got.ExactAccuracy != 0.5 || got.ExpectedCompleteCoverage != 0.5 {
		t.Fatalf("failure silently improved accuracy: %+v", got)
	}
	if err := checkGates(summary, gates); err == nil {
		t.Fatal("expected-complete failure passed")
	}

	samples[1].State = "complete"
	samples[2].State, samples[2].IncompleteProducts = "complete", nil
	_, summary, err = Aggregate(corpus, scoreOutputs(1, samples))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkGates(summary, gates); err == nil {
		t.Fatal("unconditional worker complete state passed expectations")
	}
}

func TestAggregateRejectsDuplicateOrMissingCases(t *testing.T) {
	corpus := Corpus{Products: []Product{{ID: "alpha"}}, Cases: []Case{{ID: "one", Expected: bothExpectations(Expectation{State: "complete"})}, {ID: "two", Expected: bothExpectations(Expectation{State: "complete"})}}}
	outputs := scoreOutputs(1, []WorkerResult{{CaseID: "one", State: "complete"}, {CaseID: "one", State: "complete"}})
	if _, _, err := Aggregate(corpus, outputs); err == nil {
		t.Fatal("duplicate result hid a missing fixture")
	}
}

func TestObservedDisagreementIsIndependentOfExpectedConformance(t *testing.T) {
	corpus := Corpus{Products: []Product{
		{ID: "alpha", Names: map[string]string{"wafme0w": "Native Alpha", "wafw00f": "Upstream Alpha"}},
		{ID: "beta", Names: map[string]string{"wafme0w": "Native Beta", "wafw00f": "Upstream Beta"}},
	}, Cases: []Case{
		{ID: "expected-difference", Expected: map[string]Expectation{
			"wafme0w": {State: "complete", Products: []string{"alpha"}},
			"wafw00f": {State: "incomplete", IncompleteProducts: []string{"alpha"}},
		}},
		{ID: "both-wrong-different", Expected: bothExpectations(Expectation{State: "complete", Products: []string{"alpha"}})},
		{ID: "both-wrong-same", Expected: bothExpectations(Expectation{State: "complete", Products: []string{"alpha"}})},
		{ID: "normalized-incomplete", Expected: bothExpectations(Expectation{State: "incomplete", IncompleteProducts: []string{"alpha", "beta"}})},
	}}
	outputs := scoreOutputs(2, []WorkerResult{
		{CaseID: "expected-difference", State: "complete", RawProducts: []string{"Native Alpha"}},
		{CaseID: "both-wrong-different", State: "complete", RawProducts: []string{"Native Beta"}},
		{CaseID: "both-wrong-same", State: "complete", RawProducts: []string{"Native Beta", "Native Beta"}},
		{CaseID: "normalized-incomplete", State: "incomplete", IncompleteProducts: []string{"Native Beta", "Native Alpha", "Native Beta"}},
	})
	outputs["wafw00f"][0].Results = []WorkerResult{
		{CaseID: "expected-difference", State: "incomplete", IncompleteProducts: []string{"Upstream Alpha"}},
		{CaseID: "both-wrong-different", State: "complete"},
		{CaseID: "both-wrong-same", State: "complete", RawProducts: []string{"Upstream Beta"}},
		{CaseID: "normalized-incomplete", State: "incomplete", IncompleteProducts: []string{"Upstream Alpha", "Upstream Beta"}},
	}
	results, summary, err := Aggregate(corpus, outputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, result := range results {
		if result.CaseID == "expected-difference" && (!result.StateConformant || !result.ProductsConformant) {
			t.Fatalf("reviewed difference lost per-tool conformance: %+v", result)
		}
	}
	differences := summary.Comparison.Disagreements
	if summary.Comparison.OutcomeCases != 4 || len(differences) != 2 ||
		differences[0].CaseID != "both-wrong-different" || differences[1].CaseID != "expected-difference" {
		t.Fatalf("observed disagreement hidden or invented: %+v", summary.Comparison)
	}
	if got := differences[1]; got.Wafme0w.State != "complete" || got.Wafw00f.State != "incomplete" ||
		len(got.Wafme0w.Products) != 1 || got.Wafme0w.Products[0] != "alpha" ||
		len(got.Wafw00f.IncompleteProducts) != 1 || got.Wafw00f.IncompleteProducts[0] != "alpha" {
		t.Fatalf("disagreement did not retain canonical outcomes: %+v", got)
	}
}

func TestPercentileInterpolatesSmallSamples(t *testing.T) {
	values := []int64{100, 200}
	if got := percentile(values, 0.5); got != 150 {
		t.Fatalf("median = %d, want 150", got)
	}
	if got := percentile(values, 0.95); got != 195 {
		t.Fatalf("p95 = %d, want 195", got)
	}
}

func TestReviewedRealMetricsExcludeSyntheticUnknownAndUnreviewedEvidence(t *testing.T) {
	real := testRealCase()
	real.Expected = bothExpectations(Expectation{State: "complete"})
	synthetic := Case{ID: "synthetic", Kind: "synthetic-conformance", Provenance: syntheticProvenance("synthetic"), Truth: Truth{State: "known"}, Expected: bothExpectations(Expectation{State: "complete"})}
	unreviewed := testRealCase()
	unreviewed.ID = "unreviewed"
	unreviewed.Provenance.ReviewStatus = "unreviewed"
	unreviewed.Provenance.ReviewedOn, unreviewed.Provenance.Reviewer = "unknown", "unknown"
	unreviewed.Provenance.IndependentTruth, unreviewed.Provenance.TruthSourceID = false, ""
	unreviewed.Truth.State = "unknown"
	unreviewed.Expected = bothExpectations(Expectation{State: "complete"})
	unknown := Case{ID: "unknown", Kind: "unknown", Truth: Truth{State: "unknown"}, Expected: bothExpectations(Expectation{State: "complete"}),
		Provenance: CaptureProvenance{Type: "unknown", SourceID: "test-only:unknown", CollectedOn: "unknown", ReviewStatus: "unreviewed", ReviewedOn: "unknown", Reviewer: "unknown"}}
	corpus := Corpus{Products: []Product{{ID: "alpha", Names: map[string]string{"wafme0w": "Alpha", "wafw00f": "Alpha"}}}, Cases: []Case{real, synthetic, unreviewed, unknown}, fixtureDigests: map[string]string{real.ID: "test-only-identity"}}
	results := []WorkerResult{{CaseID: real.ID, State: "failed"}, {CaseID: synthetic.ID, State: "complete"}, {CaseID: unreviewed.ID, State: "complete"}, {CaseID: unknown.ID, State: "complete"}}
	_, summary, err := Aggregate(corpus, scoreOutputs(1, results))
	if err != nil {
		t.Fatal(err)
	}
	for tool, realMetrics := range summary.ReviewedRealMetrics {
		if realMetrics.TotalCases != 1 || realMetrics.ExpectedLabelledCases != 1 || realMetrics.FailedCases != 1 || realMetrics.ExactAccuracy == nil || *realMetrics.ExactAccuracy != 0 {
			t.Fatalf("%s synthetic successes concealed real failure: %+v", tool, realMetrics)
		}
		if fixture := summary.Metrics[tool]; fixture.ExactAccuracy == nil || *fixture.ExactAccuracy != 0.5 {
			t.Fatalf("existing fixture-conformance dimension lost: %+v", fixture)
		}
	}
	corpus.Cases = corpus.Cases[1:]
	_, summary, err = Aggregate(corpus, scoreOutputs(1, results[1:]))
	if err != nil {
		t.Fatal(err)
	}
	for tool, metrics := range summary.ReviewedRealMetrics {
		if metrics.TotalCases != 0 || metrics.ExactAccuracy != nil {
			t.Fatalf("%s no real captures manufactured accuracy: %+v", tool, metrics)
		}
	}
}
