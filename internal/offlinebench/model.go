package offlinebench

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

const (
	SchemaVersion = 3
	maxCorpusSize = 8 << 20
	maxBodySize   = 1 << 20
	maxHeaders    = 256
)

type Corpus struct {
	SchemaVersion  int       `json:"schema_version"`
	Profile        string    `json:"profile"`
	Products       []Product `json:"products"`
	Cases          []Case    `json:"cases"`
	Semantics      []string  `json:"semantics"`
	fixtureDigests map[string]string
}

type Product struct {
	ID    string            `json:"id"`
	Names map[string]string `json:"names"`
}

type Case struct {
	ID         string                 `json:"id"`
	Kind       string                 `json:"kind"`
	Review     string                 `json:"review"`
	Provenance CaptureProvenance      `json:"provenance"`
	Truth      Truth                  `json:"truth"`
	Expected   map[string]Expectation `json:"expected"`
	Responses  []Response             `json:"responses"`
}

// Provenance records assertions, not independent verification of their truth.
// Inherited synthetic review dates and reviewer identities remain "unknown".
type CaptureProvenance struct {
	Type             string            `json:"type"`
	SourceID         string            `json:"source_id"`
	CollectedOn      string            `json:"collected_on"`
	ReviewStatus     string            `json:"review_status"`
	ReviewedOn       string            `json:"reviewed_on"`
	Reviewer         string            `json:"reviewer"`
	Authorization    *CaptureAssertion `json:"authorization,omitempty"`
	Sanitization     *CaptureAssertion `json:"sanitization,omitempty"`
	IndependentTruth bool              `json:"independent_truth,omitempty"`
	TruthSourceID    string            `json:"truth_source_id,omitempty"`
}

type CaptureAssertion struct {
	By        string `json:"by"`
	Reference string `json:"reference"`
	On        string `json:"on"`
}

// Expectations are adapter conformance, not evidence of real-world product truth.
// Products and incomplete_products use the shared canonical product IDs.
type Expectation struct {
	State              string   `json:"state"`
	Products           []string `json:"products,omitempty"`
	IncompleteProducts []string `json:"incomplete_products,omitempty"`
}

type Truth struct {
	State    string   `json:"state"`
	Products []string `json:"products,omitempty"`
}

type Response struct {
	Role           string           `json:"role"`
	StatusCode     int              `json:"status_code"`
	Reason         string           `json:"reason"`
	Headers        []wafme0w.Header `json:"headers,omitempty"`
	BodySHA256     string           `json:"body_sha256"`
	Body           []byte           `json:"body,omitempty"`
	BodyTruncated  bool             `json:"body_truncated,omitempty"`
	TransportError string           `json:"transport_error,omitempty"`
}

type WorkerInput struct {
	SchemaVersion int       `json:"schema_version"`
	Iterations    int       `json:"iterations"`
	Products      []Product `json:"products"`
	Cases         []Case    `json:"cases"`
	Profile       string    `json:"profile"`
}

type WorkerOutput struct {
	SchemaVersion int               `json:"schema_version"`
	Profile       string            `json:"profile"`
	Semantics     string            `json:"semantics"`
	PreparationNS int64             `json:"preparation_ns"`
	AdapterWallNS int64             `json:"adapter_wall_ns"`
	InitBytes     uint64            `json:"init_bytes,omitempty"`
	InitAllocs    uint64            `json:"init_allocs,omitempty"`
	Tool          string            `json:"tool"`
	Version       string            `json:"version"`
	AdapterMode   string            `json:"adapter_mode"`
	InitNS        int64             `json:"init_ns"`
	CatalogueSize int               `json:"catalogue_size"`
	Results       []WorkerResult    `json:"results"`
	Python        *PythonProvenance `json:"python,omitempty"`
}

type WorkerResult struct {
	CaseID             string          `json:"case_id"`
	State              string          `json:"state"`
	Reason             string          `json:"reason,omitempty"`
	RawProducts        []string        `json:"raw_products,omitempty"`
	IncompleteProducts []string        `json:"incomplete_products,omitempty"`
	Generic            string          `json:"generic,omitempty"`
	ElapsedNS          int64           `json:"elapsed_ns"`
	Matches            []wafme0w.Match `json:"matches,omitempty"`
	PreparationNS      int64           `json:"preparation_ns"`
	BytesPerOp         uint64          `json:"bytes_per_op,omitempty"`
	AllocsPerOp        float64         `json:"allocs_per_op,omitempty"`
	Workload           string          `json:"workload,omitempty"`
}

type Result struct {
	CaseID             string            `json:"case_id"`
	Tool               string            `json:"tool"`
	State              string            `json:"state"`
	Reason             string            `json:"reason,omitempty"`
	RawProducts        []string          `json:"raw_products,omitempty"`
	Products           []string          `json:"products,omitempty"`
	IncompleteProducts []string          `json:"incomplete_products,omitempty"`
	Generic            string            `json:"generic,omitempty"`
	MedianNS           int64             `json:"median_ns"`
	P95NS              int64             `json:"p95_ns"`
	Expected           Expectation       `json:"expected"`
	StateConformant    bool              `json:"state_conformant"`
	ProductsConformant bool              `json:"products_conformant"`
	PreparationNS      int64             `json:"preparation_ns"`
	Provenance         CaptureProvenance `json:"provenance"`
}

func LoadCorpus(path, bodiesDir string) (Corpus, error) {
	data, err := readLimited(path, maxCorpusSize)
	if err != nil {
		return Corpus{}, fmt.Errorf("read corpus: %w", err)
	}
	var corpus Corpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, fmt.Errorf("decode corpus: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Corpus{}, errors.New("decode corpus: trailing JSON value")
	}
	var raw struct {
		Cases []json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Corpus{}, err
	}
	corpus.fixtureDigests = make(map[string]string, len(raw.Cases))
	for index, fixture := range raw.Cases {
		var value any
		if err := json.Unmarshal(fixture, &value); err != nil {
			return Corpus{}, err
		}
		canonical, err := json.Marshal(value)
		if err != nil {
			return Corpus{}, err
		}
		digest := sha256.Sum256(canonical)
		corpus.fixtureDigests[corpus.Cases[index].ID] = hex.EncodeToString(digest[:])
	}
	if err := validateCorpus(&corpus, bodiesDir); err != nil {
		return Corpus{}, err
	}
	return corpus, nil
}

func validateCorpus(corpus *Corpus, bodiesDir string) error {
	if corpus.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported corpus schema %d", corpus.SchemaVersion)
	}
	if corpus.Profile == "" || len(corpus.Products) == 0 || len(corpus.Cases) == 0 {
		return errors.New("corpus profile, products, and cases are required")
	}
	productIDs := make(map[string]struct{}, len(corpus.Products))
	for _, product := range corpus.Products {
		if product.ID == "" {
			return errors.New("empty product ID")
		}
		if _, exists := productIDs[product.ID]; exists {
			return fmt.Errorf("duplicate product ID %q", product.ID)
		}
		productIDs[product.ID] = struct{}{}
		for _, tool := range []string{"wafme0w", "wafw00f"} {
			if product.Names[tool] == "" {
				return fmt.Errorf("product %q has no %s name", product.ID, tool)
			}
		}
	}
	caseIDs := make(map[string]struct{}, len(corpus.Cases))
	for ci := range corpus.Cases {
		fixture := &corpus.Cases[ci]
		if fixture.ID == "" || fixture.Kind == "" || fixture.Review == "" {
			return fmt.Errorf("case %d requires id, kind, and review", ci+1)
		}
		if _, exists := caseIDs[fixture.ID]; exists {
			return fmt.Errorf("duplicate case ID %q", fixture.ID)
		}
		caseIDs[fixture.ID] = struct{}{}
		if err := validateCaptureProvenance(*fixture); err != nil {
			return fmt.Errorf("case %q provenance: %w", fixture.ID, err)
		}
		if fixture.Truth.State != "known" && fixture.Truth.State != "unknown" {
			return fmt.Errorf("case %q has invalid truth state %q", fixture.ID, fixture.Truth.State)
		}
		if fixture.Truth.State == "unknown" && len(fixture.Truth.Products) != 0 {
			return fmt.Errorf("case %q gives products for unknown truth", fixture.ID)
		}
		for _, product := range fixture.Truth.Products {
			if _, exists := productIDs[product]; !exists {
				return fmt.Errorf("case %q references unknown product %q", fixture.ID, product)
			}
		}
		if len(fixture.Expected) != 2 {
			return fmt.Errorf("case %q requires expectations for both tools", fixture.ID)
		}
		for _, tool := range []string{"wafme0w", "wafw00f"} {
			expected, exists := fixture.Expected[tool]
			if !exists || !validState(expected.State) {
				return fmt.Errorf("case %q has invalid %s evaluation expectation", fixture.ID, tool)
			}
			if expected.State != "failed" && (expected.State == "incomplete") != (len(expected.IncompleteProducts) > 0) {
				return fmt.Errorf("case %q has inconsistent %s incomplete products", fixture.ID, tool)
			}
			seen := make(map[string]bool)
			for _, id := range append(append([]string(nil), expected.Products...), expected.IncompleteProducts...) {
				if _, exists := productIDs[id]; !exists || seen[id] {
					return fmt.Errorf("case %q has unknown or repeated %s expected product %q", fixture.ID, tool, id)
				}
				seen[id] = true
			}
		}
		if err := loadResponses(fixture, bodiesDir); err != nil {
			return err
		}
	}
	return nil
}

func loadResponses(fixture *Case, bodiesDir string) error {
	roles := make(map[string]struct{}, len(fixture.Responses))
	for ri := range fixture.Responses {
		response := &fixture.Responses[ri]
		if response.Role == "" {
			return fmt.Errorf("case %q response %d has empty role", fixture.ID, ri+1)
		}
		if _, exists := roles[response.Role]; exists {
			return fmt.Errorf("case %q has duplicate response role %q", fixture.ID, response.Role)
		}
		roles[response.Role] = struct{}{}
		if response.StatusCode != 0 && (response.StatusCode < 100 || response.StatusCode > 999) {
			return fmt.Errorf("case %q role %q has invalid status %d", fixture.ID, response.Role, response.StatusCode)
		}
		if len(response.Headers) > maxHeaders {
			return fmt.Errorf("case %q role %q has too many headers", fixture.ID, response.Role)
		}
		for _, header := range response.Headers {
			if !httpmeta.ValidHeaderName(header.Name) || strings.ContainsAny(header.Value, "\r\n") {
				return fmt.Errorf("case %q role %q has invalid header %q", fixture.ID, response.Role, header.Name)
			}
		}
		if response.Body != nil {
			return fmt.Errorf("case %q role %q embeds body data", fixture.ID, response.Role)
		}
		if len(response.BodySHA256) != sha256.Size*2 {
			return fmt.Errorf("case %q role %q has invalid body digest", fixture.ID, response.Role)
		}
		if _, err := hex.DecodeString(response.BodySHA256); err != nil || response.BodySHA256 != strings.ToLower(response.BodySHA256) {
			return fmt.Errorf("case %q role %q has invalid body digest", fixture.ID, response.Role)
		}
		bodyPath := filepath.Join(bodiesDir, response.BodySHA256+".bin")
		body, err := readLimited(bodyPath, maxBodySize)
		if err != nil {
			return fmt.Errorf("case %q role %q read body: %w", fixture.ID, response.Role, err)
		}
		digest := sha256.Sum256(body)
		if hex.EncodeToString(digest[:]) != response.BodySHA256 {
			return fmt.Errorf("case %q role %q body digest mismatch", fixture.ID, response.Role)
		}
		response.Body = body
	}
	return nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}
func knownIdentity(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && !strings.EqualFold(value, "unknown")
}

func validDate(value string) bool {
	date, err := time.Parse(time.DateOnly, value)
	return err == nil && date.Format(time.DateOnly) == value
}

func validateCaptureProvenance(fixture Case) error {
	p := fixture.Provenance
	if !knownIdentity(p.SourceID) || p.Reviewer == "" || (p.CollectedOn != "unknown" && !validDate(p.CollectedOn)) || (p.ReviewedOn != "unknown" && !validDate(p.ReviewedOn)) {
		return errors.New("source_id, reviewer and explicit dates (or unknown) are required")
	}
	switch p.Type {
	case "synthetic":
		if fixture.Kind != "synthetic-conformance" || p.ReviewStatus != "conformance" || p.Authorization != nil || p.Sanitization != nil || p.IndependentTruth || p.TruthSourceID != "" {
			return errors.New("synthetic evidence permits only synthetic-conformance, never reviewed-real claims")
		}
	case "real-capture":
		if fixture.Kind != "real-capture" || !validDate(p.CollectedOn) {
			return errors.New("real captures require real-capture kind and collected_on date")
		}
		for name, assertion := range map[string]*CaptureAssertion{"authorization": p.Authorization, "sanitization": p.Sanitization} {
			if assertion == nil || !knownIdentity(assertion.By) || !knownIdentity(assertion.Reference) || !validDate(assertion.On) {
				return fmt.Errorf("real captures require traceable %s assertion (by, reference, on)", name)
			}
		}
		if p.Authorization.On > p.CollectedOn || p.Sanitization.On < p.CollectedOn {
			return errors.New("authorization must precede collection; sanitization must follow collection")
		}
		switch p.ReviewStatus {
		case "reviewed-real":
			if !knownIdentity(p.Reviewer) || !validDate(p.ReviewedOn) || p.ReviewedOn < p.Sanitization.On || fixture.Truth.State != "known" || !p.IndependentTruth || !knownIdentity(p.TruthSourceID) {
				return errors.New("reviewed-real requires independent known truth with truth_source_id and dated identified review after sanitization")
			}
		case "unreviewed":
			if fixture.Truth.State != "unknown" || p.ReviewedOn != "unknown" || p.Reviewer != "unknown" || p.IndependentTruth || p.TruthSourceID != "" {
				return errors.New("unreviewed captures must retain unknown truth and review identity/date")
			}
		default:
			return errors.New("invalid real capture review_status")
		}
	case "unknown":
		if fixture.Kind != "unknown" || fixture.Truth.State != "unknown" || p.ReviewStatus != "unreviewed" || p.ReviewedOn != "unknown" || p.Reviewer != "unknown" || p.Authorization != nil || p.Sanitization != nil || p.IndependentTruth || p.TruthSourceID != "" {
			return errors.New("unknown evidence must not claim reviewed or labelled truth")
		}
	default:
		return errors.New("type must be synthetic, real-capture, or unknown")
	}
	return nil
}

func reviewedReal(fixture Case) bool {
	return fixture.Review != "" && fixture.Provenance.Type == "real-capture" && fixture.Provenance.ReviewStatus == "reviewed-real" && validateCaptureProvenance(fixture) == nil
}

func toolNames(products []Product, tool string) []string {
	names := make([]string, 0, len(products))
	for _, product := range products {
		names = append(names, product.Names[tool])
	}
	sort.Strings(names)
	return names
}

func validState(state string) bool {
	return state == "complete" || state == "incomplete" || state == "failed"
}
