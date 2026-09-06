package wafme0w

import (
	"bufio"
	"fmt"
	"net/http"
	"net/textproto"
	"os"
	"regexp"
	"regexp/syntax"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func loadBundledCatalogue(t *testing.T) []WAF {
	t.Helper()
	file, err := os.Open("../../cmd/wafme0w/resources/waf-fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	definitions, err := ReadCatalogue(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(definitions) == 0 {
		t.Fatal("bundled catalogue contains no products")
	}
	if _, err := Compile(definitions); err != nil {
		t.Fatal(err)
	}
	return definitions
}

// fingerprintEvidence generates matcher/catalogue conformance evidence, not an
// independently observed product response or evidence of real-world accuracy.
// Every witness must satisfy its independent oracle in the captured field.
func fingerprintEvidence(t *testing.T, fp FingerPrint) Evidence {
	t.Helper()
	pattern := fp.Pattern
	if fp.Type == "Header" {
		pattern = fp.HeaderValue
	}
	if fp.Type == "Reason" {
		pattern = `\A` + regexp.QuoteMeta(pattern) + `\z`
	}
	oracle := catalogueRegexp(t, fp)
	expression, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		t.Fatal(err)
	}
	for seed := range 64 {
		sample := patternSample(expression, seed)
		if !oracle.MatchString(sample) {
			continue
		}
		observation := Evidence{Role: "Normal", StatusCode: http.StatusOK, Reason: "OK"}
		switch fp.Type {
		case "Content":
			observation.Body = []byte(sample)
			return observation
		case "Header":
			// Parse a real field so controls and normalization cannot create a
			// witness that could never occur in captured response headers.
			if strings.ContainsAny(sample, "\r\n") {
				continue
			}
			headers, err := textproto.NewReader(bufio.NewReader(strings.NewReader(fp.HeaderKey + ": " + sample + "\r\n\r\n"))).ReadMIMEHeader()
			if err != nil || len(headers.Values(fp.HeaderKey)) != 1 || !oracle.MatchString(headers.Get(fp.HeaderKey)) {
				continue
			}
			observation.Headers = []Header{{Name: fp.HeaderKey, Value: ""}, {Name: fp.HeaderKey, Value: headers.Get(fp.HeaderKey)}}
			return observation
		case "Cookie":
			// Prefix-only markers need a cookie value. Keep raw case and two
			// separate Set-Cookie fields; never merge or lowercase their values.
			for _, field := range []string{sample, sample + "=catalogue", "catalogue=" + sample} {
				cookie, err := http.ParseSetCookie(field)
				if err != nil || cookie.Valid() != nil || len(cookie.Unparsed) != 0 || !oracle.MatchString(cookie.String()) {
					continue
				}
				observation.Headers = []Header{{Name: "Set-Cookie", Value: "origin=ordinary"}, {Name: "Set-Cookie", Value: field}}
				return observation
			}
		case "Status":
			status, err := strconv.Atoi(sample)
			if err != nil || status < 100 || status > 999 || !oracle.MatchString(strconv.Itoa(status)) {
				continue
			}
			observation.StatusCode = status
			observation.Reason = http.StatusText(status)
			if observation.Reason == "" {
				observation.Reason = "Synthetic status"
			}
			return observation
		case "Reason":
			if strings.IndexFunc(sample, func(r rune) bool { return r < ' ' && r != '\t' || r == '\x7f' }) >= 0 {
				continue
			}
			observation.Reason = sample
			return observation
		default:
			t.Fatalf("unsupported fingerprint type %q: %+v", fp.Type, fp)
		}
	}
	t.Fatalf("no regexp-verified valid %s capture witness after 64 deterministic samples: %+v", fp.Type, fp)
	return Evidence{}
}

func schemaEvidence(t *testing.T, schema Scheme) []Evidence {
	t.Helper()
	evidence := make([]Evidence, len(schema.FingerPrints))
	valid := true
	for fi, fp := range schema.FingerPrints {
		// Keep the exact fingerprint index in failures, including when a
		// caller needs all observations before classifying an AND schema.
		if !t.Run(fmt.Sprintf("witness_%03d_%s", fi+1, fp.Type), func(t *testing.T) {
			evidence[fi] = fingerprintEvidence(t, fp)
		}) {
			valid = false
		}
	}
	if !valid {
		t.FailNow()
	}
	return evidence
}

func requireCataloguePositiveMatch(t *testing.T, engine *Engine, evidence []Evidence, want Match) {
	t.Helper()
	got := engine.Classify(evidence)
	if got.State != Complete || len(got.Diagnostics) != 0 || len(got.IncompleteProducts) != 0 || !slices.ContainsFunc(got.Matches, func(match Match) bool {
		return match.Product == want.Product && match.Schema == want.Schema
	}) {
		t.Fatalf("got %+v, want complete match %+v without diagnostics", got, want)
	}
}

// TestCataloguePositiveConformance derives witnesses from the bundled JSON and
// verifies classification, not the truth or completeness of upstream WAF rules.
// Each OR marker stands alone; AND markers are supplied across complete responses.
func TestCataloguePositiveConformance(t *testing.T) {
	definitions := loadBundledCatalogue(t)
	catalogue, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	for _, waf := range definitions {
		t.Run(waf.Name, func(t *testing.T) {
			product, err := Compile([]WAF{waf})
			if err != nil {
				t.Fatal(err)
			}
			for si, schema := range waf.Schemas {
				t.Run(fmt.Sprintf("schema_%03d", si+1), func(t *testing.T) {
					isolatedSchema, err := Compile([]WAF{{Name: waf.Name, Schemas: []Scheme{schema}}})
					if err != nil {
						t.Fatal(err)
					}
					evidence := schemaEvidence(t, schema)
					checkBranch := func(t *testing.T, observations []Evidence) {
						t.Helper()
						// Earlier alternatives may also match. Derive their original
						// one-based index with the independent regexp/field oracle,
						// never with another engine or generated golden output.
						firstSchema := 0
						for candidate, alternative := range waf.Schemas {
							if catalogueSchemaMatches(t, alternative, observations) {
								firstSchema = candidate + 1
								break
							}
						}
						if firstSchema == 0 || firstSchema > si+1 {
							t.Fatalf("witnesses do not satisfy schema %d or an earlier alternative", si+1)
						}
						for _, scope := range []struct {
							name   string
							engine *Engine
							schema int
						}{
							{"schema", isolatedSchema, 1},
							{"product", product, firstSchema},
							{"catalogue", catalogue, firstSchema},
						} {
							t.Run(scope.name, func(t *testing.T) {
								requireCataloguePositiveMatch(t, scope.engine, observations, Match{Product: waf.Name, Schema: scope.schema})
							})
						}
					}
					for fi, fp := range schema.FingerPrints {
						t.Run(fmt.Sprintf("fingerprint_%03d_%s", fi+1, fp.Type), func(t *testing.T) {
							isolated, err := Compile([]WAF{{Name: waf.Name, Schemas: []Scheme{{Any: schema.Any, FingerPrints: []FingerPrint{fp}}}}})
							if err != nil {
								t.Fatal(err)
							}
							observations := evidence[fi : fi+1]
							requireCataloguePositiveMatch(t, isolated, observations, Match{Product: waf.Name, Schema: 1})
							if schema.Any {
								checkBranch(t, observations)
							}
						})
					}
					if !schema.Any {
						t.Run("all_required_evidence", func(t *testing.T) {
							checkBranch(t, evidence)
						})
					}
				})
			}
		})
	}
}
