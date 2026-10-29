package offlinebench

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These synthetic bytes exercise admission and storage, not fingerprint truth.
func writeBodyLimitCorpus(t *testing.T, bodies [][]byte) (string, string) {
	t.Helper()
	directory := t.TempDir()
	bodiesDir := filepath.Join(directory, "bodies")
	if err := os.Mkdir(bodiesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture := Case{
		ID: "body-limits", Kind: "synthetic-conformance", Review: "synthetic admission fixture",
		Provenance: syntheticProvenance("body-limits"), Truth: Truth{State: "unknown"},
		Expected: map[string]Expectation{"wafme0w": {State: "complete"}, "wafw00f": {State: "complete"}},
	}
	for i, body := range bodies {
		digest := sha256.Sum256(body)
		key := hex.EncodeToString(digest[:])
		if err := os.WriteFile(filepath.Join(bodiesDir, key+".bin"), body, 0o600); err != nil {
			t.Fatal(err)
		}
		fixture.Responses = append(fixture.Responses, Response{Role: fmt.Sprintf("response-%d", i), StatusCode: 200, BodySHA256: key})
	}
	corpus := Corpus{SchemaVersion: SchemaVersion, Profile: "test", Products: []Product{{ID: "example", Names: map[string]string{"wafme0w": "Example", "wafw00f": "Example"}}}, Cases: []Case{fixture}}
	encoded, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(directory, "corpus.json")
	if err := os.WriteFile(manifest, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifest, bodiesDir
}

func TestLoadCorpusReusesVerifiedBodies(t *testing.T) {
	body := []byte("shared immutable synthetic body")
	manifest, directory := writeBodyLimitCorpus(t, [][]byte{body, body})
	corpus, err := LoadCorpus(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	first, second := corpus.Cases[0].Responses[0].Body, corpus.Cases[0].Responses[1].Body
	if !bytes.Equal(first, body) || !bytes.Equal(second, body) {
		t.Fatal("body bytes changed")
	}
	if &first[0] != &second[0] {
		t.Fatal("repeated digest allocated independent body storage")
	}
	if cap(first) != len(first) || cap(second) != len(second) {
		t.Fatal("shared body exposes writable append capacity")
	}
}

func TestLoadCorpusBoundsReferencedBodies(t *testing.T) {
	// Four 1 MiB response bodies are admitted; a fifth is rejected. Repeated
	// digests also count because worker JSON expands every response separately.
	for _, distinct := range []bool{false, true} {
		for _, count := range []int{4, 5} {
			t.Run(fmt.Sprintf("distinct=%t/count=%d", distinct, count), func(t *testing.T) {
				body := bytes.Repeat([]byte("x"), 1<<20)
				bodies := make([][]byte, count)
				for i := range bodies {
					bodies[i] = body
					if distinct {
						bodies[i] = bytes.Clone(body)
						bodies[i][0] = byte(i)
					}
				}
				manifest, directory := writeBodyLimitCorpus(t, bodies)
				_, err := LoadCorpus(manifest, directory)
				if count == 4 {
					if err != nil {
						t.Fatalf("exact-limit corpus rejected: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), "referenced body bytes") {
					t.Fatalf("over-limit corpus admitted: %v", err)
				}
			})
		}
	}
}

func TestLoadCorpusContextRejectsCancellationBeforeOpening(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprintf("expired=%t", expired), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if expired {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			}
			cancel()
			// Missing paths prove cancellation is checked before file work.
			_, err := LoadCorpusContext(ctx, filepath.Join(t.TempDir(), "absent.json"), "absent-bodies")
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

func TestCorpusBodyCacheKeepsVerifiedSnapshotAndHonorsCancellation(t *testing.T) {
	body := []byte("immutable cache fixture")
	manifest, directory := writeBodyLimitCorpus(t, [][]byte{body})
	corpus, err := LoadCorpus(manifest, directory)
	if err != nil {
		t.Fatal(err)
	}
	key := corpus.Cases[0].Responses[0].BodySHA256
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cache := corpusBodies{ctx: ctx, directory: directory, remaining: 3 * int64(len(body)), verified: make(map[string][]byte)}
	first, err := cache.load(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, key+".bin"), []byte("changed after verification"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := cache.load(key)
	if err != nil || !bytes.Equal(first, body) || !bytes.Equal(second, body) {
		t.Fatalf("verified snapshot changed: body=%q, err=%v", second, err)
	}
	// A separate load must reject the changed body rather than trusting its name.
	if _, err := LoadCorpus(manifest, directory); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("unverified bytes reused across loads: %v", err)
	}
	cancel()
	if _, err := cache.load(key); !errors.Is(err, context.Canceled) {
		t.Fatalf("cached body bypassed cancellation: %v", err)
	}
	if cache.remaining != int64(len(body)) {
		t.Fatal("cancelled cache hit consumed body budget")
	}
}

func TestReadLimitedContextRejectsNonRegularFiles(t *testing.T) {
	if _, err := readLimitedContext(context.Background(), t.TempDir(), 1); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory admitted as input: %v", err)
	}
}

func TestLoadedCorpusPreservesReviewedNativeExpectations(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	corpus, err := LoadCorpusContext(ctx, "../../tools/offlinebench/testdata/corpus.json", "../../tools/offlinebench/testdata/bodies")
	if err != nil {
		t.Fatal(err)
	}
	result := invokeNativeWorker(t, WorkerInput{
		SchemaVersion: SchemaVersion, Profile: "shared-products", Iterations: 1,
		Products: corpus.Products, Cases: corpus.Cases,
	}, "../../cmd/wafme0w/resources/waf-fingerprints.json")
	if len(result.Results) != len(corpus.Cases) {
		t.Fatalf("worker returned %d of %d cases", len(result.Results), len(corpus.Cases))
	}
	for index, got := range result.Results {
		fixture := corpus.Cases[index]
		want := fixture.Expected["wafme0w"]
		products := normalizeProducts(corpus.Products, "wafme0w", got.RawProducts)
		incomplete := normalizeProducts(corpus.Products, "wafme0w", got.IncompleteProducts)
		if got.CaseID != fixture.ID || got.State != want.State || !equalSets(makeSet(products), makeSet(want.Products)) || !equalSets(makeSet(incomplete), makeSet(want.IncompleteProducts)) {
			t.Errorf("case %q changed reviewed expectation: state=%s products=%v incomplete=%v, want=%+v", fixture.ID, got.State, products, incomplete, want)
		}
	}
	coverage, err := AssessCatalogue(corpus, "../../cmd/wafme0w/resources/waf-fingerprints.json", "../../tools/offlinebench/testdata/coverage-contract.json")
	if err != nil || len(coverage.Violations) != 0 {
		t.Fatalf("fixture identity/review contract changed: %+v, %v", coverage.Violations, err)
	}
}
