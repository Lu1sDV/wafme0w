package offlinebench

import (
	"testing"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func TestCoverageKeepsFullDenominatorAndRejectsUnreviewedChanges(t *testing.T) {
	alpha := wafme0w.WAF{Name: "Alpha", Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "alpha"}}}}}
	beta := wafme0w.WAF{Name: "Beta", Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "beta"}}}}}
	catalogue := []wafme0w.WAF{alpha, beta}
	corpus := Corpus{Cases: []Case{
		{ID: "positive", Review: "reviewed alpha marker", Responses: []Response{{Role: "Normal", StatusCode: 200, Body: []byte("alpha")}}},
		{ID: "negative", Review: "reviewed nonmatching control", Responses: []Response{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}},
	}, fixtureDigests: map[string]string{"positive": "positive-identity", "negative": "negative-identity"}}
	contract := CoverageContract{Fixtures: map[string]string{"positive": "positive-identity", "negative": "negative-identity"}}
	for index := range corpus.Cases {
		corpus.Cases[index].Kind = "synthetic-conformance"
		corpus.Cases[index].Provenance = syntheticProvenance(corpus.Cases[index].ID)
	}
	for index, product := range catalogue {
		digest, err := ruleDigest(product.Name, 1, product.Schemas[0])
		if err != nil {
			t.Fatal(err)
		}
		review := RuleReview{Product: product.Name, Schema: 1, SHA256: digest, Status: "baseline-untested"}
		if index == 0 {
			review.Status, review.Review, review.Positive, review.Negative = "reviewed", "positive and negative boundary reviewed", []string{"positive"}, []string{"negative"}
		}
		review.Provenance = ReviewProvenance{Scope: "unreviewed", SourceID: "test-rule:" + digest, ReviewedOn: "unknown", Reviewer: "unknown"}
		if review.Status == "reviewed" {
			review.Provenance.Scope = "synthetic-conformance"
		}
		contract.Rules = append(contract.Rules, review)
	}
	baseline, err := assessCoverage(corpus, catalogue, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Violations) != 0 || baseline.TotalProducts != 2 || baseline.TotalSchemas != 2 || baseline.TestedSchemas != 1 || baseline.UntestedSchemas != 1 || baseline.SchemaCoverage != 0.5 {
		t.Fatalf("execution was mistaken for reviewed full-catalogue coverage: %+v", baseline)
	}
	removed := corpus
	removed.Cases = corpus.Cases[:1]
	without, err := assessCoverage(removed, catalogue, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(without.Violations) == 0 || without.TotalSchemas != baseline.TotalSchemas || without.SchemaCoverage >= baseline.SchemaCoverage || without.ExpectedFixtures != 2 || without.PresentFixtures != 1 {
		t.Fatalf("removing negative fixture silently improved headline coverage: %+v", without)
	}
	if err := checkGates(Summary{Catalogue: without}, Config{}); err == nil {
		t.Fatal("missing reviewed fixture did not gate")
	}

	changed := []wafme0w.WAF{{Name: "Alpha", Schemas: []wafme0w.Scheme{{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "changed"}}}}}, beta}
	unreviewed, err := assessCoverage(corpus, changed, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(unreviewed.Violations) == 0 || unreviewed.TestedSchemas != 0 {
		t.Fatalf("changed rule retained old review: %+v", unreviewed)
	}

	corpus.fixtureDigests["positive"] = "changed-expectations"
	changedFixture, err := assessCoverage(corpus, catalogue, contract)
	if err != nil {
		t.Fatal(err)
	}
	if len(changedFixture.Violations) == 0 {
		t.Fatal("changed fixture/expectations escaped identity contract")
	}
}

func TestCoverageDoesNotCountIncompleteNegativeEvidence(t *testing.T) {
	rule := wafme0w.Scheme{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "alpha"}}}
	digest, err := ruleDigest("Alpha", 1, rule)
	if err != nil {
		t.Fatal(err)
	}
	corpus := Corpus{Cases: []Case{
		{ID: "positive", Review: "reviewed", Responses: []Response{{StatusCode: 200, Body: []byte("alpha")}}},
		{ID: "negative", Review: "reviewed", Responses: []Response{{StatusCode: 200, BodyTruncated: true}}},
	}, fixtureDigests: map[string]string{"positive": "p", "negative": "n"}}
	contract := CoverageContract{Fixtures: corpus.fixtureDigests, Rules: []RuleReview{{Product: "Alpha", Schema: 1, SHA256: digest, Status: "reviewed", Review: "reviewed", Positive: []string{"positive"}, Negative: []string{"negative"}}}}
	for index := range corpus.Cases {
		corpus.Cases[index].Kind = "synthetic-conformance"
		corpus.Cases[index].Provenance = syntheticProvenance(corpus.Cases[index].ID)
	}
	contract.Rules[0].Provenance = ReviewProvenance{Scope: "synthetic-conformance", SourceID: "test-rule:" + digest, ReviewedOn: "unknown", Reviewer: "unknown"}
	report, err := assessCoverage(corpus, []wafme0w.WAF{{Name: "Alpha", Schemas: []wafme0w.Scheme{rule}}}, contract)
	if err != nil {
		t.Fatal(err)
	}
	if report.TestedSchemas != 0 || len(report.Violations) == 0 {
		t.Fatalf("unknown body counted as reviewed negative: %+v", report)
	}
}

func TestSyntheticRuleReviewCannotClaimReviewedRealCoverage(t *testing.T) {
	rule := wafme0w.Scheme{FingerPrints: []wafme0w.FingerPrint{{Type: "Content", Pattern: "alpha"}}}
	digest, err := ruleDigest("Alpha", 1, rule)
	if err != nil {
		t.Fatal(err)
	}
	corpus := Corpus{Cases: []Case{
		{ID: "positive", Kind: "synthetic-conformance", Review: "unit synthetic positive", Provenance: syntheticProvenance("positive"), Responses: []Response{{StatusCode: 200, Body: []byte("alpha")}}},
		{ID: "negative", Kind: "synthetic-conformance", Review: "unit synthetic negative", Provenance: syntheticProvenance("negative"), Responses: []Response{{StatusCode: 200, Body: []byte("ordinary")}}},
	}, fixtureDigests: map[string]string{"positive": "p", "negative": "n"}}
	contract := CoverageContract{Fixtures: corpus.fixtureDigests, Rules: []RuleReview{{
		Product: "Alpha", Schema: 1, SHA256: digest, Status: "reviewed", Review: "unit rule review",
		Positive: []string{"positive"}, Negative: []string{"negative"},
		Provenance: ReviewProvenance{Scope: "reviewed-real", SourceID: "test-only:review", ReviewedOn: "2026-09-03", Reviewer: "test-reviewer"},
	}}}
	catalogue := []wafme0w.WAF{{Name: "Alpha", Schemas: []wafme0w.Scheme{rule}}}
	report, err := assessCoverage(corpus, catalogue, contract)
	if err != nil || report.ReviewedRealSchemas != 0 || report.TestedSchemas != 0 || len(report.Violations) == 0 {
		t.Fatalf("synthetic fixtures promoted to real coverage: %+v, %v", report, err)
	}
	contract.Rules[0].Provenance.Scope = "synthetic-conformance"
	report, err = assessCoverage(corpus, catalogue, contract)
	if err != nil || report.ReviewedRealSchemas != 0 || report.TestedSchemas != 1 || len(report.Violations) != 0 {
		t.Fatalf("honest synthetic conformance lost: %+v, %v", report, err)
	}
}
