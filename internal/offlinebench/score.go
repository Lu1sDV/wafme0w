package offlinebench

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"sort"
)

type ToolMetrics struct {
	TotalCases                 int      `json:"total_cases"`
	CompleteCases              int      `json:"complete_cases"`
	IncompleteCases            int      `json:"incomplete_cases"`
	FailedCases                int      `json:"failed_cases"`
	LabelledCases              int      `json:"labelled_cases"`
	EvaluatedLabelledCases     int      `json:"evaluated_labelled_cases"`
	ExactCases                 int      `json:"exact_cases"`
	TruePositives              int      `json:"true_positives"`
	FalsePositives             int      `json:"false_positives"`
	FalseNegatives             int      `json:"false_negatives"`
	RawCompletionRate          float64  `json:"raw_completion_rate"`
	ExpectedCompleteCases      int      `json:"expected_complete_cases"`
	ExpectedCompleteProcessed  int      `json:"expected_complete_processed"`
	ExpectedCompleteCoverage   float64  `json:"expected_complete_coverage"`
	ExpectedLabelledCases      int      `json:"expected_labelled_cases"`
	StateConformantCases       int      `json:"state_conformant_cases"`
	ProductConformantCases     int      `json:"product_conformant_cases"`
	StateConformance           float64  `json:"state_conformance"`
	ProductConformance         float64  `json:"product_conformance"`
	LabelledEvaluationCoverage float64  `json:"labelled_evaluation_coverage"`
	ExactAccuracy              *float64 `json:"exact_accuracy"`
	Precision                  *float64 `json:"precision"`
	Recall                     *float64 `json:"recall"`
	MedianCaseNS               int64    `json:"median_case_ns"`
	P95CaseNS                  int64    `json:"p95_case_ns"`
	MedianInitNS               int64    `json:"median_init_ns"`
	MedianPreparationNS        int64    `json:"median_preparation_ns"`
	MedianAdapterWallNS        int64    `json:"median_adapter_wall_ns"`
}

type Comparison struct {
	Scope                   string         `json:"scope"`
	PairedCases             int            `json:"paired_cases"`
	Wafw00fOverWafme0wRatio float64        `json:"wafw00f_over_wafme0w_latency_ratio"`
	Bootstrap95Low          float64        `json:"bootstrap_95_low"`
	Bootstrap95High         float64        `json:"bootstrap_95_high"`
	OutcomeCases            int            `json:"outcome_cases"`
	Disagreements           []Disagreement `json:"disagreements"`
}

type Disagreement struct {
	CaseID  string      `json:"case_id"`
	Wafme0w Expectation `json:"wafme0w"`
	Wafw00f Expectation `json:"wafw00f"`
}

type Summary struct {
	SchemaVersion       int                    `json:"schema_version"`
	Profile             string                 `json:"profile"`
	Metrics             map[string]ToolMetrics `json:"metrics"`
	Comparison          Comparison             `json:"comparison"`
	Catalogue           CatalogueCoverage      `json:"catalogue_coverage"`
	FullNative          WorkerOutput           `json:"full_native_profile"`
	StatementCoverage   string                 `json:"statement_coverage"`
	MetricsScope        string                 `json:"metrics_scope"`
	EvidenceCoverage    map[string]int         `json:"evidence_coverage"`
	ReviewedRealMetrics map[string]ToolMetrics `json:"reviewed_real_metrics"`
}

func Aggregate(corpus Corpus, blocks map[string][]WorkerOutput) ([]Result, Summary, error) {
	results := make([]Result, 0, len(corpus.Cases)*len(blocks))
	initSamples := make(map[string][]int64, len(blocks))
	preparationSamples := make(map[string][]int64, len(blocks))
	wallSamples := make(map[string][]int64, len(blocks))
	caseIDs := make(map[string]bool, len(corpus.Cases))
	for _, fixture := range corpus.Cases {
		caseIDs[fixture.ID] = true
	}
	for _, tool := range []string{"wafme0w", "wafw00f"} {
		outputs := blocks[tool]
		if len(outputs) == 0 {
			return nil, Summary{}, fmt.Errorf("no %s worker outputs", tool)
		}
		initSamples[tool] = make([]int64, 0, len(outputs))
		byCase := make(map[string][]WorkerResult, len(corpus.Cases))
		for _, output := range outputs {
			if output.SchemaVersion != SchemaVersion || output.Profile != "shared-products" || output.CatalogueSize != len(corpus.Products) {
				return nil, Summary{}, fmt.Errorf("%s worker contract/profile/catalogue mismatch", tool)
			}
			preparationSamples[tool] = append(preparationSamples[tool], output.PreparationNS)
			wallSamples[tool] = append(wallSamples[tool], output.AdapterWallNS)
			seen := make(map[string]bool, len(output.Results))
			initSamples[tool] = append(initSamples[tool], output.InitNS)
			for _, result := range output.Results {
				if !caseIDs[result.CaseID] || seen[result.CaseID] || !validState(result.State) {
					return nil, Summary{}, fmt.Errorf("%s has unknown/duplicate case or invalid state: %q", tool, result.CaseID)
				}
				if (result.State == "incomplete") != (len(result.IncompleteProducts) > 0) && result.State != "failed" {
					return nil, Summary{}, fmt.Errorf("%s case %q has inconsistent completeness", tool, result.CaseID)
				}
				seen[result.CaseID] = true
				byCase[result.CaseID] = append(byCase[result.CaseID], result)
			}
		}
		for _, fixture := range corpus.Cases {
			samples := byCase[fixture.ID]
			if len(samples) != len(outputs) {
				return nil, Summary{}, fmt.Errorf("%s case %q has %d of %d block results", tool, fixture.ID, len(samples), len(outputs))
			}
			first := samples[0]
			elapsed := make([]int64, 0, len(samples))
			prepared := make([]int64, 0, len(samples))
			for _, sample := range samples {
				if sample.State != first.State || sample.Reason != first.Reason || !slices.Equal(sample.RawProducts, first.RawProducts) || !slices.Equal(sample.IncompleteProducts, first.IncompleteProducts) || sample.Generic != first.Generic {
					return nil, Summary{}, fmt.Errorf("%s case %q differs across blocks", tool, fixture.ID)
				}
				elapsed = append(elapsed, sample.ElapsedNS)
				prepared = append(prepared, sample.PreparationNS)
			}
			products := normalizeProducts(corpus.Products, tool, first.RawProducts)
			incomplete := normalizeProducts(corpus.Products, tool, first.IncompleteProducts)
			expected, exists := fixture.Expected[tool]
			if !exists {
				return nil, Summary{}, fmt.Errorf("case %q lacks %s expectations", fixture.ID, tool)
			}
			results = append(results, Result{
				CaseID:             fixture.ID,
				Tool:               tool,
				State:              first.State,
				Reason:             first.Reason,
				RawProducts:        first.RawProducts,
				Products:           products,
				IncompleteProducts: first.IncompleteProducts,
				Generic:            first.Generic,
				MedianNS:           percentile(elapsed, 0.5),
				P95NS:              percentile(elapsed, 0.95),
				Expected:           expected,
				StateConformant:    first.State == expected.State && equalSets(makeSet(incomplete), makeSet(expected.IncompleteProducts)),
				ProductsConformant: equalSets(makeSet(products), makeSet(expected.Products)),
				PreparationNS:      percentile(prepared, 0.5),
				Provenance:         fixture.Provenance,
			})
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].CaseID == results[j].CaseID {
			return results[i].Tool < results[j].Tool
		}
		return results[i].CaseID < results[j].CaseID
	})

	summary := Summary{SchemaVersion: SchemaVersion, Profile: corpus.Profile, Metrics: make(map[string]ToolMetrics, 2), StatementCoverage: "Separate Go -coverprofile=coverage.out artifact; statement execution is not product/schema assurance."}
	summary.MetricsScope = "labelled-fixture-conformance; not production prevalence or catalogue-wide accuracy"
	summary.EvidenceCoverage = map[string]int{"synthetic": 0, "real-capture": 0, "unknown": 0, "reviewed-real": 0}
	summary.ReviewedRealMetrics = make(map[string]ToolMetrics, 2)
	realCorpus := Corpus{Products: corpus.Products}
	for _, fixture := range corpus.Cases {
		kind := fixture.Provenance.Type
		if kind == "" {
			kind = "unknown"
		}
		summary.EvidenceCoverage[kind]++
		if reviewedReal(fixture) && corpus.fixtureDigests[fixture.ID] != "" {
			realCorpus.Cases = append(realCorpus.Cases, fixture)
			summary.EvidenceCoverage["reviewed-real"]++
		}
	}
	for _, tool := range []string{"wafme0w", "wafw00f"} {
		metrics := scoreTool(corpus, results, tool, initSamples[tool])
		metrics.MedianPreparationNS = percentile(preparationSamples[tool], 0.5)
		metrics.MedianAdapterWallNS = percentile(wallSamples[tool], 0.5)
		summary.Metrics[tool] = metrics
		summary.ReviewedRealMetrics[tool] = scoreTool(realCorpus, results, tool, nil)
	}
	summary.Comparison = compareLatency(corpus, results)
	summary.Comparison.OutcomeCases = len(corpus.Cases)
	summary.Comparison.Disagreements = []Disagreement{}
	// Aggregate guarantees one result per tool/case, sorted by case then tool.
	// Compare observed outcomes even when expectations intentionally differ.
	for i := 0; i < len(results); i += 2 {
		native, upstream := results[i], results[i+1]
		a := Expectation{State: native.State, Products: native.Products,
			IncompleteProducts: normalizeProducts(corpus.Products, native.Tool, native.IncompleteProducts)}
		b := Expectation{State: upstream.State, Products: upstream.Products,
			IncompleteProducts: normalizeProducts(corpus.Products, upstream.Tool, upstream.IncompleteProducts)}
		if a.State != b.State || !slices.Equal(a.Products, b.Products) || !slices.Equal(a.IncompleteProducts, b.IncompleteProducts) {
			summary.Comparison.Disagreements = append(summary.Comparison.Disagreements, Disagreement{CaseID: native.CaseID, Wafme0w: a, Wafw00f: b})
		}
	}
	return results, summary, nil
}

func normalizeProducts(products []Product, tool string, raw []string) []string {
	lookup := make(map[string]string, len(products))
	for _, product := range products {
		lookup[product.Names[tool]] = product.ID
	}
	normalized := make([]string, 0, len(raw))
	for _, name := range raw {
		if id, ok := lookup[name]; ok {
			normalized = append(normalized, id)
		} else {
			normalized = append(normalized, "unmapped:"+name)
		}
	}
	sort.Strings(normalized)
	return slices.Compact(normalized)
}

func scoreTool(corpus Corpus, results []Result, tool string, initSamples []int64) ToolMetrics {
	metrics := ToolMetrics{TotalCases: len(corpus.Cases), MedianInitNS: percentile(initSamples, 0.5)}
	byCase := make(map[string]Result, len(corpus.Cases))
	caseTimes := make([]int64, 0, len(corpus.Cases))
	caseIDs := make(map[string]bool, len(corpus.Cases))
	for _, fixture := range corpus.Cases {
		caseIDs[fixture.ID] = true
	}
	for _, result := range results {
		if result.Tool == tool && caseIDs[result.CaseID] {
			byCase[result.CaseID] = result
			caseTimes = append(caseTimes, result.MedianNS)
			switch result.State {
			case "complete":
				metrics.CompleteCases++
			case "incomplete":
				metrics.IncompleteCases++
			default:
				metrics.FailedCases++
			}
		}
	}
	metrics.MedianCaseNS = percentile(caseTimes, 0.5)
	metrics.P95CaseNS = percentile(caseTimes, 0.95)
	for _, fixture := range corpus.Cases {
		result, ok := byCase[fixture.ID]
		expected := fixture.Expected[tool]
		if ok && result.StateConformant {
			metrics.StateConformantCases++
		}
		if ok && result.ProductsConformant {
			metrics.ProductConformantCases++
		}
		if expected.State == "complete" {
			metrics.ExpectedCompleteCases++
			if ok && result.State == "complete" {
				metrics.ExpectedCompleteProcessed++
			}
		}
		if fixture.Truth.State != "known" {
			continue
		}
		metrics.LabelledCases++
		if expected.State != "complete" {
			continue
		}
		metrics.ExpectedLabelledCases++
		if !ok || result.State != "complete" {
			continue
		}
		metrics.EvaluatedLabelledCases++
		truth := makeSet(fixture.Truth.Products)
		prediction := makeSet(result.Products)
		if equalSets(truth, prediction) {
			metrics.ExactCases++
		}
		for product := range prediction {
			if _, ok := truth[product]; ok {
				metrics.TruePositives++
			} else {
				metrics.FalsePositives++
			}
		}
		for product := range truth {
			if _, ok := prediction[product]; !ok {
				metrics.FalseNegatives++
			}
		}
	}
	metrics.RawCompletionRate = ratio(metrics.CompleteCases, metrics.TotalCases)
	metrics.ExpectedCompleteCoverage = ratio(metrics.ExpectedCompleteProcessed, metrics.ExpectedCompleteCases)
	metrics.StateConformance = ratio(metrics.StateConformantCases, metrics.TotalCases)
	metrics.ProductConformance = ratio(metrics.ProductConformantCases, metrics.TotalCases)
	metrics.LabelledEvaluationCoverage = ratio(metrics.EvaluatedLabelledCases, metrics.ExpectedLabelledCases)
	metrics.ExactAccuracy = optionalRatio(metrics.ExactCases, metrics.ExpectedLabelledCases)
	metrics.Precision = optionalRatio(metrics.TruePositives, metrics.TruePositives+metrics.FalsePositives)
	metrics.Recall = optionalRatio(metrics.TruePositives, metrics.TruePositives+metrics.FalseNegatives)
	return metrics
}

func compareLatency(corpus Corpus, results []Result) Comparison {
	byToolCase := make(map[string]map[string]int64, 2)
	for _, result := range results {
		if result.State != "complete" || result.Expected.State != "complete" || !result.StateConformant || !result.ProductsConformant {
			continue
		}
		if byToolCase[result.Tool] == nil {
			byToolCase[result.Tool] = make(map[string]int64)
		}
		byToolCase[result.Tool][result.CaseID] = result.MedianNS
	}
	ratios := make([]float64, 0, len(corpus.Cases))
	for _, fixture := range corpus.Cases {
		a, aOK := byToolCase["wafme0w"][fixture.ID]
		b, bOK := byToolCase["wafw00f"][fixture.ID]
		if aOK && bOK && a > 0 {
			ratios = append(ratios, float64(b)/float64(a))
		}
	}
	if len(ratios) == 0 {
		return Comparison{Scope: "shared products; paired expected-complete, conformant cases; warm named classification only; no generic"}
	}
	point := floatPercentile(ratios, 0.5)
	random := rand.New(rand.NewPCG(1, 2))
	bootstrap := make([]float64, 1000)
	resample := make([]float64, len(ratios))
	for i := range bootstrap {
		for j := range resample {
			resample[j] = ratios[random.IntN(len(ratios))]
		}
		bootstrap[i] = floatPercentile(resample, 0.5)
	}
	return Comparison{Scope: "shared products; paired expected-complete, conformant cases; warm named classification only; no generic", PairedCases: len(ratios), Wafw00fOverWafme0wRatio: point, Bootstrap95Low: floatPercentile(bootstrap, 0.025), Bootstrap95High: floatPercentile(bootstrap, 0.975)}
}

func percentile(values []int64, quantile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]int64(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	position := quantile * float64(len(ordered)-1)
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return ordered[lower]
	}
	return int64(math.Round(float64(ordered[lower]) + (float64(ordered[upper])-float64(ordered[lower]))*(position-float64(lower))))
}

func floatPercentile(values []float64, quantile float64) float64 {
	ordered := append([]float64(nil), values...)
	sort.Float64s(ordered)
	position := quantile * float64(len(ordered)-1)
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return ordered[lower]
	}
	return ordered[lower] + (ordered[upper]-ordered[lower])*(position-float64(lower))
}

func makeSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func equalSets(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for value := range a {
		if _, ok := b[value]; !ok {
			return false
		}
	}
	return true
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func optionalRatio(numerator, denominator int) *float64 {
	if denominator == 0 {
		return nil
	}
	value := ratio(numerator, denominator)
	return &value
}
