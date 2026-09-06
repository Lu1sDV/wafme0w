package offlinebench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

// CoverageContract is a reviewed identity inventory, not generated detector truth.
// baseline-untested explicitly grandfathers only these exact existing rule hashes.
// New/changed rules require reviewed positive AND negative links before acceptance.
// There is deliberately no command that automatically blesses current observations.
type CoverageContract struct {
	SchemaVersion int               `json:"schema_version"`
	Policy        string            `json:"policy"`
	Fixtures      map[string]string `json:"fixtures"`
	Rules         []RuleReview      `json:"rules"`
}

type RuleReview struct {
	Product    string           `json:"product"`
	Schema     int              `json:"schema"`
	SHA256     string           `json:"sha256"`
	Status     string           `json:"status"`
	Review     string           `json:"review,omitempty"`
	Positive   []string         `json:"positive,omitempty"`
	Negative   []string         `json:"negative,omitempty"`
	Provenance ReviewProvenance `json:"provenance"`
}

type ReviewProvenance struct {
	Scope      string `json:"scope"`
	SourceID   string `json:"source_id"`
	ReviewedOn string `json:"reviewed_on"`
	Reviewer   string `json:"reviewer"`
}

type SchemaCoverage struct {
	RuleReview
	Tested         bool     `json:"tested"`
	PositivePassed []string `json:"positive_passed,omitempty"`
	NegativePassed []string `json:"negative_passed,omitempty"`
	ReviewedReal   bool     `json:"reviewed_real"`
}

type ProductCoverage struct {
	Product string           `json:"product"`
	State   string           `json:"state"`
	Schemas []SchemaCoverage `json:"schemas"`
}

type CatalogueCoverage struct {
	TotalProducts           int               `json:"total_products"`
	TestedProducts          int               `json:"tested_products"`
	PartiallyTestedProducts int               `json:"partially_tested_products"`
	UntestedProducts        int               `json:"untested_products"`
	TotalSchemas            int               `json:"total_schemas"`
	TestedSchemas           int               `json:"tested_schemas"`
	UntestedSchemas         int               `json:"untested_schemas"`
	ProductCoverage         float64           `json:"product_coverage"`
	SchemaCoverage          float64           `json:"schema_coverage"`
	ExpectedFixtures        int               `json:"expected_fixtures"`
	PresentFixtures         int               `json:"present_fixtures"`
	ReviewedRealSchemas     int               `json:"reviewed_real_schemas"`
	ReviewedRealProducts    int               `json:"reviewed_real_products"`
	Products                []ProductCoverage `json:"products"`
	Violations              []string          `json:"violations,omitempty"`
}

func AssessCatalogue(corpus Corpus, cataloguePath, contractPath string) (CatalogueCoverage, error) {
	data, err := readLimited(contractPath, maxCorpusSize)
	if err != nil {
		return CatalogueCoverage{}, fmt.Errorf("read coverage contract: %w", err)
	}
	var contract CoverageContract
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		return CatalogueCoverage{}, fmt.Errorf("decode coverage contract: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CatalogueCoverage{}, errors.New("coverage contract has trailing JSON")
	}
	if contract.SchemaVersion != 2 || contract.Policy == "" || len(contract.Fixtures) == 0 || len(contract.Rules) == 0 {
		return CatalogueCoverage{}, errors.New("invalid coverage contract")
	}
	catalogue, err := loadCatalogue(cataloguePath)
	if err != nil {
		return CatalogueCoverage{}, err
	}
	return assessCoverage(corpus, catalogue, contract)
}

func assessCoverage(corpus Corpus, catalogue []wafme0w.WAF, contract CoverageContract) (CatalogueCoverage, error) {
	report := CatalogueCoverage{TotalProducts: len(catalogue), ExpectedFixtures: len(contract.Fixtures), PresentFixtures: len(corpus.Cases)}
	violate := func(format string, args ...any) {
		report.Violations = append(report.Violations, fmt.Sprintf(format, args...))
	}
	fixtures := make(map[string]Case, len(corpus.Cases))
	reviewedFixtures := make(map[string]bool, len(corpus.Cases))
	for _, fixture := range corpus.Cases {
		fixtures[fixture.ID] = fixture
		reviewedFixtures[fixture.ID] = fixture.Review != "" && validateCaptureProvenance(fixture) == nil && fixture.Provenance.ReviewStatus != "unreviewed" && contract.Fixtures[fixture.ID] != "" && contract.Fixtures[fixture.ID] == corpus.fixtureDigests[fixture.ID]
		if expected, exists := contract.Fixtures[fixture.ID]; !exists || expected != corpus.fixtureDigests[fixture.ID] {
			violate("fixture %q is new or changed; review its evidence, truth and adapter expectations and update its identity", fixture.ID)
		}
	}
	for id := range contract.Fixtures {
		if _, exists := fixtures[id]; !exists {
			violate("reviewed fixture %q was removed", id)
		}
	}
	reviews := make(map[string]RuleReview, len(contract.Rules))
	for _, review := range contract.Rules {
		key := ruleKey(review.Product, review.Schema)
		if _, exists := reviews[key]; exists {
			violate("duplicate rule identity %s", key)
		}
		reviews[key] = review
	}
	for _, product := range catalogue {
		entry := ProductCoverage{Product: product.Name, State: "untested"}
		tested := 0
		realTested := 0
		for index, schema := range product.Schemas {
			report.TotalSchemas++
			key := ruleKey(product.Name, index+1)
			digest, err := ruleDigest(product.Name, index+1, schema)
			if err != nil {
				return CatalogueCoverage{}, err
			}
			review, exists := reviews[key]
			delete(reviews, key)
			item := SchemaCoverage{RuleReview: RuleReview{Product: product.Name, Schema: index + 1, SHA256: digest, Status: "unreviewed"}}
			if !exists || review.SHA256 != digest {
				violate("rule %s is new or changed; reviewed positive and negative fixtures and its identity are required", key)
			} else {
				item.RuleReview = review
				if err := validateReviewProvenance(review); err != nil {
					violate("rule %s provenance: %v", key, err)
					entry.Schemas = append(entry.Schemas, item)
					continue
				}
				switch review.Status {
				case "baseline-untested":
					if len(review.Positive)+len(review.Negative) != 0 {
						violate("untested rule %s must not claim reviewed fixtures", key)
					}
				case "reviewed":
					if review.Review == "" || len(review.Positive) == 0 || len(review.Negative) == 0 {
						violate("reviewed rule %s needs review rationale and both positive and negative fixtures", key)
						break
					}
					engine, err := wafme0w.Compile([]wafme0w.WAF{{Name: product.Name, Schemas: []wafme0w.Scheme{schema}}})
					if err != nil {
						return CatalogueCoverage{}, err
					}
					for _, positive := range []bool{true, false} {
						links := review.Negative
						if positive {
							links = review.Positive
						}
						for _, id := range links {
							fixture, ok := fixtures[id]
							if !ok || !reviewedFixtures[id] {
								violate("rule %s references absent or unreviewed fixture %q", key, id)
								continue
							}
							if (review.Provenance.Scope == "reviewed-real" && (!reviewedReal(fixture) || review.Provenance.ReviewedOn < fixture.Provenance.ReviewedOn)) || (review.Provenance.Scope == "synthetic-conformance" && fixture.Provenance.Type != "synthetic") {
								violate("rule %s fixture %q does not support review scope %q", key, id, review.Provenance.Scope)
								continue
							}
							outcome := engine.Classify(nativeEvidence(fixture.Responses))
							if outcome.State != wafme0w.Complete || (len(outcome.Matches) != 0) != positive {
								violate("rule %s fixture %q does not satisfy its reviewed positive=%t expectation (state=%s)", key, id, positive, outcome.State)
								continue
							}
							if positive {
								item.PositivePassed = append(item.PositivePassed, id)
							} else {
								item.NegativePassed = append(item.NegativePassed, id)
							}
						}
					}
					item.Tested = len(item.PositivePassed) == len(review.Positive) && len(item.NegativePassed) == len(review.Negative)
					item.ReviewedReal = item.Tested && review.Provenance.Scope == "reviewed-real"
				default:
					violate("rule %s has invalid review status %q", key, review.Status)
				}
			}
			if item.Tested {
				tested++
				report.TestedSchemas++
			}
			if item.ReviewedReal {
				realTested++
				report.ReviewedRealSchemas++
			}
			entry.Schemas = append(entry.Schemas, item)
		}
		if tested == len(product.Schemas) && tested != 0 {
			entry.State = "tested"
			report.TestedProducts++
		} else if tested != 0 {
			entry.State = "partially-tested"
			report.PartiallyTestedProducts++
		} else {
			report.UntestedProducts++
		}
		report.Products = append(report.Products, entry)
		if realTested == len(product.Schemas) && realTested != 0 {
			report.ReviewedRealProducts++
		}
	}
	for key := range reviews {
		violate("saved rule %s is absent from the catalogue; review the inventory change", key)
	}
	report.UntestedSchemas = report.TotalSchemas - report.TestedSchemas
	report.ProductCoverage = ratio(report.TestedProducts, report.TotalProducts)
	report.SchemaCoverage = ratio(report.TestedSchemas, report.TotalSchemas)
	return report, nil
}

func ruleKey(product string, schema int) string { return fmt.Sprintf("%s/schema/%d", product, schema) }

func ruleDigest(product string, schema int, rule wafme0w.Scheme) (string, error) {
	data, err := json.Marshal(map[string]any{"product": product, "schema": schema, "rule": rule})
	if err != nil {
		return "", err
	}
	// Canonical object ordering makes the saved identity independent of formatting.
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return "", err
	}
	data, err = json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func validateReviewProvenance(review RuleReview) error {
	p := review.Provenance
	if !knownIdentity(p.SourceID) || p.Reviewer == "" || (p.ReviewedOn != "unknown" && !validDate(p.ReviewedOn)) {
		return errors.New("source_id, reviewer and explicit reviewed_on date (or unknown) required")
	}
	switch review.Status {
	case "baseline-untested":
		if p.Scope != "unreviewed" || p.Reviewer != "unknown" || p.ReviewedOn != "unknown" {
			return errors.New("baseline-untested must not claim a review")
		}
	case "reviewed":
		if p.Scope != "synthetic-conformance" && p.Scope != "reviewed-real" {
			return errors.New("reviewed scope must be synthetic-conformance or reviewed-real")
		}
		if p.Scope == "reviewed-real" && (!knownIdentity(p.Reviewer) || !validDate(p.ReviewedOn)) {
			return errors.New("reviewed-real rule requires dated identified review")
		}
	}
	return nil
}
