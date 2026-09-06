package offlinebench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"time"
)

type Config struct {
	Executable       string
	Bubblewrap       string
	Catalogue        string
	Wafw00fPython    string
	CoverageContract string
	Wafw00fAdapter   string
	OutputDir        string
	Iterations       int
	Blocks           int
	MinimumCoverage  float64
	MinimumAccuracy  float64
}

type RunManifest struct {
	Complete      bool                        `json:"complete"`
	Artifacts     map[string]ArtifactIdentity `json:"artifacts"`
	Python        *PythonProvenance           `json:"python"`
	SchemaVersion int                         `json:"schema_version"`
	GeneratedAt   string                      `json:"generated_at"`
	Profile       string                      `json:"profile"`
	Isolation     string                      `json:"isolation"`
	Runtime       string                      `json:"runtime"`
	Iterations    int                         `json:"iterations"`
	Blocks        int                         `json:"blocks"`
	BlockOrder    []string                    `json:"block_order"`
	Digests       map[string]string           `json:"digests"`
	Tools         map[string]string           `json:"tools"`
}

type PythonProvenance struct {
	RequestedExecutable  string            `json:"requested_executable,omitempty"`
	Executable           string            `json:"executable"`
	ExecutableRealPath   string            `json:"executable_real_path"`
	ExecutableSHA256     string            `json:"executable_sha256"`
	Runtime              string            `json:"runtime"`
	Implementation       string            `json:"implementation"`
	Platform             string            `json:"platform"`
	Packages             map[string]string `json:"packages"`
	PinnedWafw00fVersion string            `json:"pinned_wafw00f_version"`
	UpstreamRoot         string            `json:"upstream_root"`
	Sources              map[string]string `json:"sources"`
	SourceTreeSHA256     string            `json:"source_tree_sha256"`
	WorkerSHA256         string            `json:"worker_sha256"`
}

func Execute(ctx context.Context, corpus Corpus, corpusPath string, config Config) ([]Result, Summary, RunManifest, error) {
	if config.Iterations < 1 || config.Blocks < 4 || config.Blocks%4 != 0 {
		return nil, Summary{}, RunManifest{}, errors.New("iterations must be positive and blocks must be a positive multiple of four")
	}
	if config.MinimumCoverage < 0 || config.MinimumCoverage > 1 || config.MinimumAccuracy < 0 || config.MinimumAccuracy > 1 {
		return nil, Summary{}, RunManifest{}, errors.New("coverage and accuracy gates must be between zero and one")
	}
	for _, path := range []string{config.Executable, config.Bubblewrap, config.Catalogue, config.CoverageContract, config.Wafw00fPython, config.Wafw00fAdapter} {
		if path == "" {
			return nil, Summary{}, RunManifest{}, errors.New("all executable and adapter paths are required")
		}
	}
	if err := newRunDestination(config.OutputDir); err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	if err := networkIsolationCanary(ctx, config); err != nil {
		return nil, Summary{}, RunManifest{}, err
	}

	input := WorkerInput{SchemaVersion: SchemaVersion, Profile: "shared-products", Iterations: config.Iterations, Products: corpus.Products, Cases: corpus.Cases}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, Summary{}, RunManifest{}, fmt.Errorf("encode worker input: %w", err)
	}
	pattern := []string{"wafme0w", "wafw00f", "wafw00f", "wafme0w"}
	order := make([]string, config.Blocks)
	blocks := map[string][]WorkerOutput{"wafme0w": {}, "wafw00f": {}}
	for block := range config.Blocks {
		tool := pattern[block%len(pattern)]
		order[block] = tool
		output, err := runWorker(ctx, config, tool, payload)
		if err != nil {
			return nil, Summary{}, RunManifest{}, fmt.Errorf("%s block %d: %w", tool, block+1, err)
		}
		blocks[tool] = append(blocks[tool], output)
	}
	results, summary, err := Aggregate(corpus, blocks)
	if err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	summary.Catalogue, err = AssessCatalogue(corpus, config.Catalogue, config.CoverageContract)
	if err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	input.Profile = "full-native"
	fullPayload, err := json.Marshal(input)
	if err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	summary.FullNative, err = runWorker(ctx, config, "wafme0w", fullPayload)
	if err != nil {
		return nil, Summary{}, RunManifest{}, fmt.Errorf("full-native profile: %w", err)
	}
	if summary.FullNative.Profile != "full-native" || summary.FullNative.CatalogueSize != summary.Catalogue.TotalProducts {
		return nil, Summary{}, RunManifest{}, errors.New("full-native profile did not process the full catalogue")
	}
	manifest, err := buildManifest(corpus, corpusPath, config, order, blocks)
	if err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	manifest, err = WriteArtifacts(config.OutputDir, manifest, results, summary)
	if err != nil {
		return nil, Summary{}, RunManifest{}, err
	}
	return results, summary, manifest, checkGates(summary, config)
}

func checkGates(summary Summary, config Config) error {
	if len(summary.Catalogue.Violations) != 0 {
		return fmt.Errorf("catalogue/fixture review contract: %s", strings.Join(summary.Catalogue.Violations, "; "))
	}
	for tool, metrics := range summary.Metrics {
		if metrics.StateConformance != 1 || metrics.ProductConformance != 1 {
			return fmt.Errorf("%s adapter expectation conformance failed: state=%.4f products=%.4f", tool, metrics.StateConformance, metrics.ProductConformance)
		}
		if metrics.ExpectedCompleteCoverage < config.MinimumCoverage {
			return fmt.Errorf("%s expected-complete processing %.4f is below %.4f", tool, metrics.ExpectedCompleteCoverage, config.MinimumCoverage)
		}
		if metrics.ExactAccuracy == nil || *metrics.ExactAccuracy < config.MinimumAccuracy {
			return fmt.Errorf("%s expected-complete labelled accuracy is below %.4f", tool, config.MinimumAccuracy)
		}
	}
	return nil
}

func networkIsolationCanary(ctx context.Context, config Config) error {
	code := `import socket
assert [name for _, name in socket.if_nameindex()] in ([], ['lo'])
s = socket.socket()
assert s.connect_ex(('1.1.1.1', 443)) != 0
print('isolated')`
	args := append(sandboxBase(), "/usr/bin/python3", "-c", code)
	command := exec.CommandContext(ctx, config.Bubblewrap, args...)
	command.Env = []string{}
	output, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "isolated" {
		return fmt.Errorf("network isolation canary failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func runWorker(ctx context.Context, config Config, tool string, input []byte) (WorkerOutput, error) {
	args := sandboxBase()
	switch tool {
	case "wafme0w":
		args = append(args,
			"--ro-bind", config.Executable, "/work/offlinebench",
			"--ro-bind", config.Catalogue, "/work/catalogue.json",
			"/work/offlinebench", "-worker", "wafme0w", "-catalogue", "/work/catalogue.json")
	case "wafw00f":
		venv := filepath.Dir(filepath.Dir(config.Wafw00fPython))
		args = append(args,
			"--ro-bind", venv, "/venv",
			"--ro-bind", config.Wafw00fAdapter, "/work/wafw00f_adapter.py",
			"/venv/bin/"+filepath.Base(config.Wafw00fPython), "-I", "-B", "/work/wafw00f_adapter.py")
	default:
		return WorkerOutput{}, fmt.Errorf("unsupported worker %q", tool)
	}
	command := exec.CommandContext(ctx, config.Bubblewrap, args...)
	command.Env = []string{}
	command.Stdin = bytes.NewReader(input)
	stdout := &limitedBuffer{remaining: 4 << 20}
	stderr := &limitedBuffer{remaining: 1 << 20}
	command.Stdout, command.Stderr = stdout, stderr
	started := time.Now()
	if err := command.Run(); err != nil {
		return WorkerOutput{}, fmt.Errorf("worker failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	wallNS := time.Since(started).Nanoseconds()
	output, err := decodeWorkerOutput(stdout.Bytes(), tool)
	output.AdapterWallNS = wallNS
	return output, err
}

func decodeWorkerOutput(data []byte, tool string) (WorkerOutput, error) {
	var output WorkerOutput
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&output); err != nil {
		return WorkerOutput{}, fmt.Errorf("decode output: %w: %s", err, strings.TrimSpace(string(data)))
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return WorkerOutput{}, errors.New("decode output: trailing JSON value")
	}
	if output.Tool != tool || output.SchemaVersion != SchemaVersion {
		return WorkerOutput{}, fmt.Errorf("worker identified as %q schema %d", output.Tool, output.SchemaVersion)
	}
	if tool == "wafw00f" {
		if err := validatePythonProvenance(output.Python); err != nil {
			return WorkerOutput{}, err
		}
		if output.Version != output.Python.Packages["wafw00f"] {
			return WorkerOutput{}, errors.New("worker package and module versions disagree")
		}
	}
	return output, nil
}

func sandboxBase() []string {
	args := []string{
		"--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
		"--die-with-parent", "--new-session", "--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--setenv", "HOME", "/tmp",
		"--setenv", "PYTHONNOUSERSITE", "1",
		"--setenv", "PYTHONDONTWRITEBYTECODE", "1",
		"--ro-bind", "/usr", "/usr",
	}
	for _, directory := range []string{"/lib", "/lib64"} {
		if _, err := os.Stat(directory); err == nil {
			args = append(args, "--ro-bind", directory, directory)
		}
	}
	return append(args, "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--dir", "/work", "--chdir", "/work")
}

type limitedBuffer struct {
	bytes.Buffer
	remaining int
}

func (buffer *limitedBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.remaining {
		return 0, errors.New("worker output limit exceeded")
	}
	buffer.remaining -= len(data)
	return buffer.Buffer.Write(data)
}

func buildManifest(corpus Corpus, corpusPath string, config Config, order []string, blocks map[string][]WorkerOutput) (RunManifest, error) {
	digests := make(map[string]string, 4)
	for name, path := range map[string]string{"corpus": corpusPath, "coverage_contract": config.CoverageContract, "wafme0w_executable": config.Executable, "wafme0w_catalogue": config.Catalogue, "wafw00f_adapter": config.Wafw00fAdapter} {
		digest, err := fileDigest(path)
		if err != nil {
			return RunManifest{}, err
		}
		digests[name] = digest
	}
	tools := make(map[string]string, 2)
	for tool, outputs := range blocks {
		if len(outputs) != 0 {
			tools[tool] = outputs[0].Version
		}
	}
	pythonOutputs := blocks["wafw00f"]
	if len(pythonOutputs) == 0 {
		return RunManifest{}, errors.New("missing observed Python provenance")
	}
	python := pythonOutputs[0].Python
	if err := validatePythonProvenance(python); err != nil {
		return RunManifest{}, err
	}
	for _, output := range pythonOutputs[1:] {
		if !reflect.DeepEqual(python, output.Python) {
			return RunManifest{}, errors.New("Python runtime, packages or source identities changed across blocks")
		}
	}
	if python.WorkerSHA256 != digests["wafw00f_adapter"] {
		return RunManifest{}, errors.New("observed Python worker source differs from manifest input")
	}
	observedPython := *python
	observedPython.RequestedExecutable = config.Wafw00fPython
	return RunManifest{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Profile:       corpus.Profile,
		Isolation:     "bubblewrap pid/ipc/uts/network namespaces; read-only runtime and tool mounts",
		Runtime:       fmt.Sprintf("%s %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH),
		Iterations:    config.Iterations,
		Blocks:        config.Blocks,
		BlockOrder:    order,
		Digests:       digests,
		Tools:         tools,
		Python:        &observedPython,
	}, nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %q: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func validatePythonProvenance(p *PythonProvenance) error {
	if p == nil || p.Executable == "" || p.ExecutableRealPath == "" || p.Runtime == "" || p.Implementation == "" || p.Platform == "" || p.UpstreamRoot == "" || !validDigest(p.ExecutableSHA256) || !validDigest(p.WorkerSHA256) {
		return errors.New("missing or invalid observed Python runtime/source provenance")
	}
	if p.PinnedWafw00fVersion != "2.4.2" || p.Packages["wafw00f"] != p.PinnedWafw00fVersion || len(p.Sources) == 0 {
		return errors.New("observed wafw00f distribution must match pinned version 2.4.2 and include source identities")
	}
	for name, version := range p.Packages {
		if name == "" || version == "" {
			return errors.New("invalid observed Python package identity")
		}
	}
	for name, digest := range p.Sources {
		if name == "" || !validDigest(digest) {
			return errors.New("invalid observed Python source identity")
		}
	}
	if !validDigest(p.Sources["__init__.py"]) || !validDigest(p.Sources["main.py"]) {
		return errors.New("observed upstream source inventory omits package or engine source")
	}
	data, err := json.Marshal(p.Sources)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != p.SourceTreeSHA256 {
		return errors.New("observed upstream source tree digest mismatch")
	}
	return nil
}
