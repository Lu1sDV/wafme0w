package offlinebench

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func emptyJSONArray(count int) string {
	return "[" + strings.TrimSuffix(strings.Repeat("{},", count), ",") + "]"
}

func TestLoadCorpusRejectsStructuralExpansionBeforeSemanticDecode(t *testing.T) {
	members := make([]string, 65)
	for i := range members {
		members[i] = fmt.Sprintf("%q:null", fmt.Sprintf("field-%d", i))
	}
	for _, test := range []struct{ name, data, want string }{
		{"cases", `{"cases":` + emptyJSONArray(4097) + `}`, "array exceeds 4096 entries"},
		{"products", `{"products":` + emptyJSONArray(4097) + `}`, "array exceeds 4096 entries"},
		{"responses", `{"cases":[{"responses":` + emptyJSONArray(65) + `}]}`, "array exceeds 64 entries"},
		{"folded responses", `{"cases":[{"Reſponſes":` + emptyJSONArray(65) + `}]}`, "array exceeds 64 entries"},
		{"escaped responses", `{"cases":[{"re\u0073ponses":` + emptyJSONArray(65) + `}]}`, "array exceeds 64 entries"},
		{"headers", `{"cases":[{"responses":[{"headers":` + emptyJSONArray(257) + `}]}]}`, "array exceeds 256 entries"},
		{"object members", "{" + strings.Join(members, ",") + "}", "object exceeds 64 fields"},
		{"nesting", strings.Repeat("[", 17) + "null" + strings.Repeat("]", 17), "nesting exceeds 16 levels"},
		{"total values", "[" + strings.Repeat(emptyJSONArray(4096)+",", 15) + emptyJSONArray(4096) + "]", "exceeds 65536 JSON values"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := filepath.Join(t.TempDir(), "corpus.json")
			if err := os.WriteFile(manifest, []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCorpus(manifest, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("structural limit was not enforced before semantic decoding: %v", err)
			}
		})
	}
}

func TestCorpusStructuralAdmissionBoundaries(t *testing.T) {
	members := make([]string, 64)
	for i := range members {
		members[i] = fmt.Sprintf("%q:null", fmt.Sprintf("field-%d", i))
	}
	// These are structural boundary inputs; semantic admission remains separate.
	for name, data := range map[string]string{
		"array":     emptyJSONArray(4096),
		"responses": `{"responses":` + emptyJSONArray(64) + `}`,
		"headers":   `{"headers":` + emptyJSONArray(256) + `}`,
		"object":    "{" + strings.Join(members, ",") + "}",
		"nesting":   strings.Repeat("[", 16) + "null" + strings.Repeat("]", 16),
		"values":    "[" + strings.Repeat(emptyJSONArray(4096)+",", 15) + emptyJSONArray(4079) + "]",
	} {
		t.Run(name, func(t *testing.T) {
			if err := admitCorpusJSON(context.Background(), []byte(data)); err != nil {
				t.Fatalf("exact structural boundary rejected: %v", err)
			}
		})
	}
}
