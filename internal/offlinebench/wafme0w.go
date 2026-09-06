package offlinebench

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"sort"
	"time"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func RunWafme0wWorker(input io.Reader, output io.Writer, cataloguePath string) error {
	var request WorkerInput
	decoder := json.NewDecoder(io.LimitReader(input, maxCorpusSize+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("decode worker input: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("decode worker input: trailing JSON value")
	}
	if request.SchemaVersion != SchemaVersion || request.Iterations < 1 || (request.Profile != "shared-products" && request.Profile != "full-native") {
		return errors.New("invalid worker schema, profile, or iteration count")
	}

	started := time.Now()
	catalogue, err := loadCatalogue(cataloguePath)
	if err != nil {
		return err
	}
	if request.Profile == "shared-products" {
		wanted := makeSet(toolNames(request.Products, "wafme0w"))
		selected := make([]wafme0w.WAF, 0, len(wanted))
		for _, waf := range catalogue {
			if _, ok := wanted[waf.Name]; ok {
				selected = append(selected, waf)
			}
		}
		if len(selected) != len(wanted) {
			return fmt.Errorf("catalogue contains %d of %d requested products", len(selected), len(wanted))
		}
		catalogue = selected
	}
	preparationNS := time.Since(started).Nanoseconds()
	var before, after runtime.MemStats
	if request.Profile == "full-native" {
		runtime.ReadMemStats(&before)
	}
	started = time.Now()
	engine, err := wafme0w.Compile(catalogue)
	initNS := time.Since(started).Nanoseconds()
	if err != nil {
		return fmt.Errorf("compile catalogue: %w", err)
	}
	if request.Profile == "full-native" {
		runtime.ReadMemStats(&after)
	}
	response := WorkerOutput{
		SchemaVersion: SchemaVersion,
		Profile:       request.Profile,
		Tool:          "wafme0w",
		Version:       wafme0w.Version(),
		AdapterMode:   "immutable-engine-evidence-replay",
		Semantics:     "named classification only; Attack is metadata; schemas may combine responses; three-valued field completeness; generic evaluated once outside timing",
		PreparationNS: preparationNS,
		InitNS:        initNS,
		InitBytes:     after.TotalAlloc - before.TotalAlloc,
		InitAllocs:    after.Mallocs - before.Mallocs,
		CatalogueSize: len(engine.Products()),
		Results:       make([]WorkerResult, 0, len(request.Cases)),
	}
	for _, fixture := range request.Cases {
		started = time.Now()
		evidence := nativeEvidence(fixture.Responses)
		prepareNS := time.Since(started).Nanoseconds()
		first := engine.Classify(evidence) // Untimed warm-up; no compilation in the timed loop.
		var elapsed int64
		for range request.Iterations {
			started = time.Now()
			outcome := engine.Classify(evidence)
			elapsed += time.Since(started).Nanoseconds()
			if !reflect.DeepEqual(outcome, first) {
				return fmt.Errorf("case %q produced nondeterministic output", fixture.ID)
			}
		}
		products := make([]string, 0, len(first.Matches))
		for _, match := range first.Matches {
			products = append(products, match.Product)
		}
		sort.Strings(products)
		sort.Strings(first.IncompleteProducts)
		result := WorkerResult{
			CaseID:             fixture.ID,
			State:              string(first.State),
			RawProducts:        products,
			IncompleteProducts: first.IncompleteProducts,
			Matches:            first.Matches,
			Generic:            wafme0w.GenericDetect(evidence).Reason,
			PreparationNS:      prepareNS,
			ElapsedNS:          elapsed / int64(request.Iterations),
		}
		if first.State == wafme0w.Complete {
			result.Workload = "clean-miss"
			if len(products) != 0 {
				result.Workload = "match"
			}
		} else {
			result.Workload = "incomplete-evidence"
		}
		if request.Profile == "full-native" {
			// Allocation sampling is separate from latency; process-wide counters in this single-worker process.
			runtime.ReadMemStats(&before)
			for range request.Iterations {
				outcome := engine.Classify(evidence)
				runtime.KeepAlive(outcome)
			}
			runtime.ReadMemStats(&after)
			result.BytesPerOp = (after.TotalAlloc - before.TotalAlloc) / uint64(request.Iterations)
			result.AllocsPerOp = float64(after.Mallocs-before.Mallocs) / float64(request.Iterations)
		}
		response.Results = append(response.Results, result)
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(response)
}

func loadCatalogue(path string) ([]wafme0w.WAF, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open catalogue: %w", err)
	}
	defer file.Close()
	return wafme0w.ReadCatalogue(file)
}

func nativeEvidence(responses []Response) []wafme0w.Evidence {
	evidence := make([]wafme0w.Evidence, 0, len(responses))
	for _, response := range responses {
		evidence = append(evidence, wafme0w.Evidence{
			Role: response.Role, StatusCode: response.StatusCode, Reason: response.Reason,
			Headers: response.Headers, Body: response.Body, BodyTruncated: response.BodyTruncated,
			TransportError: response.TransportError,
		})
	}
	return evidence
}
