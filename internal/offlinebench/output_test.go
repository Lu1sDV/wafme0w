package offlinebench

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafme0w/internal/atomicfile"
)

// Test-only provenance is never part of the saved benchmark corpus.
func testManifest(t *testing.T) RunManifest {
	t.Helper()
	zero := strings.Repeat("0", 64)
	sources := map[string]string{"__init__.py": zero, "main.py": zero}
	encoded, err := json.Marshal(sources)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return RunManifest{SchemaVersion: SchemaVersion, Profile: "test-only",
		Digests: map[string]string{"corpus": zero, "coverage_contract": zero, "wafme0w_executable": zero, "wafme0w_catalogue": zero, "wafw00f_adapter": zero},
		Tools:   map[string]string{"wafme0w": "test-only", "wafw00f": "2.4.2"},
		Python: &PythonProvenance{
			RequestedExecutable: "/test/python", Executable: "/test/python", ExecutableRealPath: "/test/python", ExecutableSHA256: zero,
			Runtime: "test-only runtime", Implementation: "test-only", Platform: "test-only",
			Packages: map[string]string{"wafw00f": "2.4.2"}, PinnedWafw00fVersion: "2.4.2",
			UpstreamRoot: "/test/upstream", Sources: sources, SourceTreeSHA256: hex.EncodeToString(digest[:]), WorkerSHA256: zero,
		}}
}

func generationSnapshot(t *testing.T, directory string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string, len(entries))
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		files[entry.Name()] = string(data)
	}
	return files
}

func TestGenerationPublicationPreservesPriorArtifactsOnEveryFailure(t *testing.T) {
	parent := t.TempDir()
	prior := filepath.Join(parent, "prior")
	manifest := testManifest(t)
	if _, err := WriteArtifacts(prior, manifest, []Result{{CaseID: "old"}}, Summary{}); err != nil {
		t.Fatal(err)
	}
	before := generationSnapshot(t, prior)
	if _, err := WriteArtifacts(prior, manifest, []Result{{CaseID: "replacement"}}, Summary{}); err == nil {
		t.Fatal("nonempty generation was overwritten")
	}
	if !reflect.DeepEqual(before, generationSnapshot(t, prior)) {
		t.Fatal("prior generation changed")
	}
	failures := append(append([]string(nil), artifactNames...), "run-manifest.json", "sync", "rename")
	for _, failure := range failures {
		t.Run(failure, func(t *testing.T) {
			destination := filepath.Join(parent, "new")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(destination)
			injected := errors.New("injected publication failure")
			ops := publicationOps{write: atomicfile.Write, rename: os.Rename, syncDir: syncDirectory}
			ops.write = func(path string, encode func(io.Writer) error) error {
				if filepath.Base(path) == failure {
					return atomicfile.Write(path, func(writer io.Writer) error {
						if _, err := io.WriteString(writer, "partial staged bytes"); err != nil {
							return err
						}
						return injected
					})
				}
				return atomicfile.Write(path, encode)
			}
			if failure == "sync" {
				ops.syncDir = func(string) error { return injected }
			}
			if failure == "rename" {
				ops.rename = func(string, string) error { return injected }
			}
			if _, err := writeArtifacts(destination, manifest, []Result{{CaseID: "new"}}, Summary{}, ops); !errors.Is(err, injected) {
				t.Fatalf("missing injected failure: %v", err)
			}
			if _, err := VerifyArtifacts(destination); err == nil {
				t.Fatal("failed publication became a valid run")
			}
			if !reflect.DeepEqual(before, generationSnapshot(t, prior)) {
				t.Fatal("prior generation changed on failure")
			}
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if entry.Name() != "prior" && entry.Name() != "new" {
					t.Fatalf("temporary artifact leaked: %s", entry.Name())
				}
			}
			if entries, err := os.ReadDir(destination); err != nil || len(entries) != 0 {
				t.Fatalf("partial destination: %v %v", entries, err)
			}
		})
	}
}

func TestGenerationCommitDoesNotReplaceConcurrentPublisher(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "run")
	ops := publicationOps{write: atomicfile.Write, syncDir: syncDirectory}
	ops.rename = func(staging, final string) error {
		if err := os.Mkdir(final, 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(final, "existing"), []byte("concurrent publisher"), 0o600); err != nil {
			return err
		}
		return os.Rename(staging, final)
	}
	if _, err := writeArtifacts(destination, testManifest(t), nil, Summary{}, ops); err == nil {
		t.Fatal("concurrent generation overwritten")
	}
	if got := generationSnapshot(t, destination); !reflect.DeepEqual(got, map[string]string{"existing": "concurrent publisher"}) {
		t.Fatalf("concurrent artifacts changed: %v", got)
	}
}

func TestGenerationConsumersRequireCompletionAndIntegrity(t *testing.T) {
	for _, mutation := range []string{"artifact", "missing-manifest", "incomplete", "missing-identity", "symlink", "unlisted"} {
		t.Run(mutation, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "run")
			manifest, err := WriteArtifacts(destination, testManifest(t), []Result{{CaseID: "saved"}}, Summary{})
			if err != nil {
				t.Fatal(err)
			}
			if verified, err := VerifyArtifacts(destination); err != nil || !verified.Complete {
				t.Fatalf("published generation rejected: %v", err)
			}
			switch mutation {
			case "artifact":
				err = os.WriteFile(filepath.Join(destination, "results.jsonl"), []byte("different generation\n"), 0o600)
			case "missing-manifest":
				err = os.Remove(filepath.Join(destination, "run-manifest.json"))
			case "incomplete", "missing-identity":
				if mutation == "incomplete" {
					manifest.Complete = false
				} else {
					delete(manifest.Artifacts, "report.txt")
				}
				err = atomicfile.Write(filepath.Join(destination, "run-manifest.json"), func(writer io.Writer) error { return json.NewEncoder(writer).Encode(manifest) })
			case "symlink":
				path := filepath.Join(destination, "report.txt")
				if err = os.Remove(path); err == nil {
					err = os.Symlink("results.jsonl", path)
				}
			case "unlisted":
				err = os.WriteFile(filepath.Join(destination, "leftover"), []byte("old artifact"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyArtifacts(destination); err == nil {
				t.Fatal("invalid generation accepted")
			}
		})
	}
}
