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

	"github.com/Lu1sDV/wafme0w/internal/atomicfile"
)

type ArtifactIdentity struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

var artifactNames = []string{"summary.json", "catalogue-coverage.json", "full-native-profile.json", "results.jsonl", "report.txt"}

type publicationOps struct {
	write   func(string, func(io.Writer) error) error
	rename  func(string, string) error
	syncDir func(string) error
}

// WriteArtifacts publishes one complete new generation. Existing nonempty
// destinations are never modified, including on write, sync or rename failure.
func WriteArtifacts(directory string, manifest RunManifest, results []Result, summary Summary) (RunManifest, error) {
	return writeArtifacts(directory, manifest, results, summary, publicationOps{atomicfile.Write, os.Rename, syncDirectory})
}

func newRunDestination(directory string) error {
	if directory == "" {
		return errors.New("output must name a new-run destination")
	}
	info, err := os.Lstat(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return errors.New("output must be an absent or empty directory, not a file or symlink")
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer file.Close()
	entries, err := file.ReadDir(1)
	if len(entries) != 0 {
		return fmt.Errorf("output directory %q is nonempty; choose a new run destination", directory)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func writeArtifacts(directory string, manifest RunManifest, results []Result, summary Summary, ops publicationOps) (RunManifest, error) {
	if err := newRunDestination(directory); err != nil {
		return RunManifest{}, err
	}
	directory = filepath.Clean(directory)
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return RunManifest{}, fmt.Errorf("create output parent: %w", err)
	}
	staging, err := os.MkdirTemp(parent, "."+filepath.Base(directory)+".staging-")
	if err != nil {
		return RunManifest{}, err
	}
	defer func() {
		if staging != "" {
			os.RemoveAll(staging)
		}
	}()
	manifest.Complete = false
	manifest.Artifacts = make(map[string]ArtifactIdentity, len(artifactNames))
	values := map[string]any{
		"summary.json":             summary,
		"catalogue-coverage.json":  summary.Catalogue,
		"full-native-profile.json": summary.FullNative,
	}
	for _, name := range artifactNames {
		path := filepath.Join(staging, name)
		err := ops.write(path, func(writer io.Writer) error {
			switch name {
			case "results.jsonl":
				encoder := json.NewEncoder(writer)
				encoder.SetEscapeHTML(false)
				for _, result := range results {
					if err := encoder.Encode(result); err != nil {
						return err
					}
				}
				return nil
			case "report.txt":
				_, err := io.WriteString(writer, renderReport(summary))
				return err
			default:
				encoder := json.NewEncoder(writer)
				encoder.SetIndent("", "  ")
				return encoder.Encode(values[name])
			}
		})
		if err != nil {
			return RunManifest{}, fmt.Errorf("stage %s: %w", name, err)
		}
		identity, err := artifactIdentity(path)
		if err != nil {
			return RunManifest{}, err
		}
		manifest.Artifacts[name] = identity
	}
	// This marker is written last, after every data artifact is closed and synced.
	manifest.Complete = true
	if err := ops.write(filepath.Join(staging, "run-manifest.json"), func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(manifest)
	}); err != nil {
		return RunManifest{}, fmt.Errorf("stage completion manifest: %w", err)
	}
	if _, err := VerifyArtifacts(staging); err != nil {
		return RunManifest{}, fmt.Errorf("verify staged generation: %w", err)
	}
	if err := ops.syncDir(staging); err != nil {
		return RunManifest{}, fmt.Errorf("sync staged generation: %w", err)
	}
	if err := newRunDestination(directory); err != nil {
		return RunManifest{}, err
	}
	// Rename is the commit point and last fallible operation. Directory rename
	// cannot replace a nonempty prior generation, even if one appears meanwhile.
	if err := ops.rename(staging, directory); err != nil {
		return RunManifest{}, fmt.Errorf("publish generation: %w", err)
	}
	staging = ""
	return manifest, nil
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func artifactIdentity(path string) (ArtifactIdentity, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	if !info.Mode().IsRegular() {
		return ArtifactIdentity{}, fmt.Errorf("artifact %q is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return ArtifactIdentity{}, err
	}
	return ArtifactIdentity{SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: size}, nil
}

// VerifyArtifacts is mandatory before consuming a saved generation. Hashes
// detect partial/mixed/tampered artifacts; they are not authenticity signatures.
func VerifyArtifacts(directory string) (RunManifest, error) {
	path := filepath.Join(directory, "run-manifest.json")
	info, err := os.Lstat(path)
	if err != nil {
		return RunManifest{}, fmt.Errorf("incomplete generation: %w", err)
	}
	if !info.Mode().IsRegular() {
		return RunManifest{}, errors.New("completion manifest is not a regular file")
	}
	data, err := readLimited(path, maxCorpusSize)
	if err != nil {
		return RunManifest{}, err
	}
	var manifest RunManifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return RunManifest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return RunManifest{}, errors.New("completion manifest has trailing JSON")
	}
	if manifest.SchemaVersion != SchemaVersion || !manifest.Complete || len(manifest.Artifacts) != len(artifactNames) {
		return RunManifest{}, errors.New("missing supported completion manifest or artifact inventory")
	}
	if err := validatePythonProvenance(manifest.Python); err != nil {
		return RunManifest{}, err
	}
	for _, name := range []string{"corpus", "coverage_contract", "wafme0w_executable", "wafme0w_catalogue", "wafw00f_adapter"} {
		if !validDigest(manifest.Digests[name]) {
			return RunManifest{}, fmt.Errorf("missing source identity: %s", name)
		}
	}
	if manifest.Python.RequestedExecutable == "" || manifest.Python.WorkerSHA256 != manifest.Digests["wafw00f_adapter"] || manifest.Tools["wafw00f"] != manifest.Python.Packages["wafw00f"] || manifest.Tools["wafme0w"] == "" {
		return RunManifest{}, errors.New("completion manifest sources disagree with observed workers")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return RunManifest{}, err
	}
	if len(entries) != len(artifactNames)+1 {
		return RunManifest{}, errors.New("generation contains missing or unlisted artifacts")
	}
	for _, name := range artifactNames {
		expected, exists := manifest.Artifacts[name]
		if !exists || !validDigest(expected.SHA256) || expected.Bytes < 0 {
			return RunManifest{}, fmt.Errorf("invalid artifact identity for %s", name)
		}
		actual, err := artifactIdentity(filepath.Join(directory, name))
		if err != nil {
			return RunManifest{}, err
		}
		if actual != expected {
			return RunManifest{}, fmt.Errorf("artifact integrity mismatch: %s", name)
		}
	}
	return manifest, nil
}

func renderReport(summary Summary) string {
	var report strings.Builder
	fmt.Fprintf(&report, "Offline WAF conformance and performance report\nProfile: %s\n\n", summary.Profile)
	fmt.Fprintf(&report, "Statement coverage: %s\n", summary.StatementCoverage)
	coverage := summary.Catalogue
	fmt.Fprintf(&report, "Native full-catalogue reviewed coverage: %d/%d products fully tested (%.2f%%), %d partially tested, %d untested; %d/%d schemas tested (%.2f%%), %d untested.\n", coverage.TestedProducts, coverage.TotalProducts, 100*coverage.ProductCoverage, coverage.PartiallyTestedProducts, coverage.UntestedProducts, coverage.TestedSchemas, coverage.TotalSchemas, 100*coverage.SchemaCoverage, coverage.UntestedSchemas)
	fmt.Fprintf(&report, "Saved fixture identities: %d expected / %d present; review-contract violations: %d. Untested rules have no measured accuracy; schema coverage requires reviewed positive AND negative evidence, not mere execution.\n\n", coverage.ExpectedFixtures, coverage.PresentFixtures, len(coverage.Violations))
	fmt.Fprintf(&report, "Evidence provenance: %d synthetic, %d real captures, %d unknown; %d independently reviewed real captures. Reviewed-real full-catalogue coverage: %d/%d schemas, %d/%d products.\n", summary.EvidenceCoverage["synthetic"], summary.EvidenceCoverage["real-capture"], summary.EvidenceCoverage["unknown"], summary.EvidenceCoverage["reviewed-real"], coverage.ReviewedRealSchemas, coverage.TotalSchemas, coverage.ReviewedRealProducts, coverage.TotalProducts)
	for _, violation := range coverage.Violations {
		fmt.Fprintf(&report, "  REVIEW GATE: %s\n", violation)
	}
	report.WriteString("Shared-product comparison only (not catalogue-wide accuracy):\n")
	tools := make([]string, 0, len(summary.Metrics))
	for tool := range summary.Metrics {
		tools = append(tools, tool)
	}
	sort.Strings(tools)
	for _, tool := range tools {
		metrics := summary.Metrics[tool]
		fmt.Fprintf(&report, "%s\n", tool)
		fmt.Fprintf(&report, "  raw completion: %d/%d (%.2f%%); expected-complete processing: %d/%d (%.2f%%)\n", metrics.CompleteCases, metrics.TotalCases, 100*metrics.RawCompletionRate, metrics.ExpectedCompleteProcessed, metrics.ExpectedCompleteCases, 100*metrics.ExpectedCompleteCoverage)
		fmt.Fprintf(&report, "  expected-state / expected-products conformance: %.2f%% / %.2f%%\n", 100*metrics.StateConformance, 100*metrics.ProductConformance)
		fmt.Fprintf(&report, "  labelled expected-complete evaluation: %d/%d (%.2f%%); all labelled fixtures: %d\n", metrics.EvaluatedLabelledCases, metrics.ExpectedLabelledCases, 100*metrics.LabelledEvaluationCoverage, metrics.LabelledCases)
		fmt.Fprintf(&report, "  labelled-fixture exact accuracy (conformance, not production accuracy): %s\n", formatRate(metrics.ExactAccuracy))
		fmt.Fprintf(&report, "  precision / recall: %s / %s\n", formatRate(metrics.Precision), formatRate(metrics.Recall))
		fmt.Fprintf(&report, "  median / p95 classification: %s / %s\n", formatDuration(metrics.MedianCaseNS), formatDuration(metrics.P95CaseNS))
		fmt.Fprintf(&report, "  median preparation / initialization / adapter wall: %s / %s / %s\n\n", formatDuration(metrics.MedianPreparationNS), formatDuration(metrics.MedianInitNS), formatDuration(metrics.MedianAdapterWallNS))
		real := summary.ReviewedRealMetrics[tool]
		fmt.Fprintf(&report, "  separately reviewed-real expected-complete evaluation: %d/%d; exact accuracy %s, precision %s, recall %s\n\n", real.EvaluatedLabelledCases, real.ExpectedLabelledCases, formatRate(real.ExactAccuracy), formatRate(real.Precision), formatRate(real.Recall))
	}
	fmt.Fprintf(&report, "Observed cross-detector disagreements: %d/%d cases (state, canonical products and incomplete products; independent of expected conformance).\n", len(summary.Comparison.Disagreements), summary.Comparison.OutcomeCases)
	for _, difference := range summary.Comparison.Disagreements {
		fmt.Fprintf(&report, "  %s: wafme0w=%s products=%v incomplete=%v; wafw00f=%s products=%v incomplete=%v\n", difference.CaseID,
			difference.Wafme0w.State, difference.Wafme0w.Products, difference.Wafme0w.IncompleteProducts,
			difference.Wafw00f.State, difference.Wafw00f.Products, difference.Wafw00f.IncompleteProducts)
	}
	fmt.Fprintf(&report, "wafw00f / wafme0w median latency ratio: %.3fx (bootstrap 95%% %.3f-%.3f), %d paired cases. %s\n\n", summary.Comparison.Wafw00fOverWafme0wRatio, summary.Comparison.Bootstrap95Low, summary.Comparison.Bootstrap95High, summary.Comparison.PairedCases, summary.Comparison.Scope)
	full := summary.FullNative
	fmt.Fprintf(&report, "Separate full-native profile: %d products; preparation %s, compile initialization %s (%d bytes / %d allocations), adapter wall %s.\n", full.CatalogueSize, formatDuration(full.PreparationNS), formatDuration(full.InitNS), full.InitBytes, full.InitAllocs, formatDuration(full.AdapterWallNS))
	for _, result := range full.Results {
		fmt.Fprintf(&report, "  %s: %s, %s, warm %s/op, %d bytes/op, %.2f allocations/op\n", result.CaseID, result.Workload, result.State, formatDuration(result.ElapsedNS), result.BytesPerOp, result.AllocsPerOp)
	}
	report.WriteString("\nTimings are informational, with no performance gate. Named classification is warm and generic is outside both timed scopes; memory counters are sampled in a separate native pass. Full-native match/miss labels describe classifier output, not additional reviewed truth.\n")
	report.WriteString("Scope: saved evidence only; inherited fixtures are synthetic conformance, with unknown historical review dates/identities. Reviewed-real metrics require explicit independent truth, identified dated review, authorization and sanitization assertions; metadata cannot itself establish the truth of those assertions or production representativeness. These metrics do not measure live scanning, network latency, production prevalence, WAF enforcement, or bypass resistance. Changed/new rule identities must not be re-labelled baseline-untested. Consume saved reports only after verifying the complete generation manifest and every artifact hash.\n")
	return report.String()
}

func formatRate(value *float64) string {
	if value == nil {
		return "undefined"
	}
	return fmt.Sprintf("%.2f%%", 100**value)
}

func formatDuration(nanoseconds int64) string {
	if nanoseconds < 1_000 {
		return fmt.Sprintf("%d ns", nanoseconds)
	}
	if nanoseconds < 1_000_000 {
		return fmt.Sprintf("%.2f us", float64(nanoseconds)/1_000)
	}
	return fmt.Sprintf("%.2f ms", float64(nanoseconds)/1_000_000)
}
