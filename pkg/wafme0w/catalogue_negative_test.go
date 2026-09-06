package wafme0w

import (
	"fmt"
	"net/http"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"testing"
)

// These are synthetic controls for the JSON rule contract, not reviewed site
// captures or an estimate of real-world detection accuracy.
func TestCatalogueOriginNegatives(t *testing.T) {
	definitions := loadBundledCatalogue(t)
	engine, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	origin := []Evidence{catalogueOriginEvidence()}
	outcome := engine.Classify(origin)
	schemas := 0
	for _, waf := range definitions {
		t.Run(waf.Name, func(t *testing.T) {
			catalogueRequireTarget(t, outcome, waf.Name, false)
			for si, schema := range waf.Schemas {
				schemas++
				t.Run(fmt.Sprintf("schema-%d", si+1), func(t *testing.T) {
					if catalogueSchemaMatches(t, schema, origin) {
						t.Fatal("ordinary origin is not a negative control for this schema")
					}
					isolated, err := Compile([]WAF{{Name: waf.Name, Schemas: []Scheme{schema}}})
					if err != nil {
						t.Fatal(err)
					}
					catalogueRequireTarget(t, isolated.Classify(origin), waf.Name, false)
				})
			}
		})
	}
	t.Logf("complete ordinary-origin negatives: %d products, %d schemas", len(definitions), schemas)
}

func TestCatalogueFingerprintNegatives(t *testing.T) {
	fingerprints, broadHeaders, presenceHeaders, emptyMatches := 0, 0, 0, 0
	for _, waf := range loadBundledCatalogue(t) {
		for si, schema := range waf.Schemas {
			for fi, fp := range schema.FingerPrints {
				fingerprints++
				t.Run(fmt.Sprintf("%s/schema-%d/fingerprint-%d-%s", waf.Name, si+1, fi+1, fp.Type), func(t *testing.T) {
					engine, err := Compile([]WAF{{Name: waf.Name, Schemas: []Scheme{{FingerPrints: []FingerPrint{fp}}}}})
					if err != nil {
						t.Fatal(err)
					}
					positive := fingerprintEvidence(t, fp)
					if !catalogueFingerprintMatches(t, fp, []Evidence{positive}) {
						t.Fatal("positive witness does not satisfy independent regexp oracle")
					}
					var headerExpression *syntax.Regexp
					if fp.Type == "Header" {
						headerExpression, err = syntax.Parse(fp.HeaderValue, syntax.Perl)
						if err != nil {
							t.Fatal(err)
						}
					}
					if headerExpression != nil && headerExpression.Op == syntax.OpStar &&
						(headerExpression.Sub[0].Op == syntax.OpAnyCharNotNL || headerExpression.Sub[0].Op == syntax.OpAnyChar) {
						presenceHeaders++
						t.Run("any-present-header-value-is-positive", func(t *testing.T) {
							for _, value := range []string{"", "origin/1.0"} {
								present, valid := catalogueWithValue(fp, positive, value)
								if !valid || !catalogueFingerprintMatches(t, fp, []Evidence{present}) {
									t.Fatal("presence rule must accept every valid field value, including empty")
								}
								catalogueRequireTarget(t, engine.Classify([]Evidence{present}), waf.Name, true)
							}
							t.Log("unconditional value regexp has no value near miss; absent and wrong-field negatives are checked separately")
						})
					} else {
						t.Run("valid-field-near-miss", func(t *testing.T) {
							near := catalogueNearMiss(t, fp, positive)
							if catalogueFingerprintMatches(t, fp, []Evidence{near}) {
								t.Fatal("near miss still satisfies independent regexp oracle")
							}
							catalogueRequireTarget(t, engine.Classify([]Evidence{near}), waf.Name, false)
						})
					}

					name := "missing-field"
					switch fp.Type {
					case "Content":
						name = "complete-empty-body"
					case "Reason":
						name = "empty-reason"
					case "Status":
						// Missing status is incomplete, not a usable negative.
						name = "different-valid-status"
					}
					t.Run(name, func(t *testing.T) {
						missing := catalogueWithoutField(fp, positive)
						want := catalogueFingerprintMatches(t, fp, []Evidence{missing})
						if want {
							emptyMatches++
							t.Log("empty field is accepted by this regexp; it is not a negative control")
						}
						catalogueRequireTarget(t, engine.Classify([]Evidence{missing}), waf.Name, want)
					})

					if headerExpression != nil {
						if headerExpression.Op == syntax.OpPlus && (headerExpression.Sub[0].Op == syntax.OpAnyCharNotNL || headerExpression.Sub[0].Op == syntax.OpAnyChar) {
							broadHeaders++
							t.Run("any-nonempty-header-value-is-positive", func(t *testing.T) {
								ordinary, valid := catalogueWithValue(fp, positive, "origin/1.0")
								if !valid || !catalogueFingerprintMatches(t, fp, []Evidence{ordinary}) {
									t.Fatal("nonempty-header rule must accept an ordinary valid field value")
								}
								catalogueRequireTarget(t, engine.Classify([]Evidence{ordinary}), waf.Name, true)
								t.Log("broad rule accepts every nonempty valid header value; only empty or absent fields are negatives")
							})
						}
					}

					if fp.Type != "Content" {
						t.Run("marker-in-wrong-field", func(t *testing.T) {
							marker := catalogueMatchingValue(t, fp, positive)
							wrong := catalogueWithoutField(fp, positive)
							switch fp.Type {
							case "Header":
								wrong.Headers = append(wrong.Headers, Header{"X-Catalogue-Wrong-Field", marker})
							case "Cookie":
								// A Cookie request header is not a Set-Cookie response field.
								wrong.Headers = append(wrong.Headers, Header{"Cookie", marker})
							case "Status":
								wrong.Reason = marker
							case "Reason":
								wrong.Body = []byte(marker)
							}
							if catalogueFingerprintMatches(t, fp, []Evidence{wrong}) {
								t.Fatal("wrong-field control still matches the intended field")
							}
							catalogueRequireTarget(t, engine.Classify([]Evidence{wrong}), waf.Name, false)
						})
					}
				})
			}
		}
	}
	t.Logf("%d fingerprints: %d valid regexp-rejected value near misses, %d presence-only header rules checked with missing fields; %d nonempty-header rules, %d empty-field positives", fingerprints, fingerprints-presenceHeaders, presenceHeaders, broadHeaders, emptyMatches)
}

func TestCatalogueANDBoundaries(t *testing.T) {
	schemas, removals, overlapping := 0, 0, 0
	for _, waf := range loadBundledCatalogue(t) {
		for si, schema := range waf.Schemas {
			if schema.Any {
				// OR branch retention and alternative schemas are exercised by
				// TestCataloguePositiveConformance using independent witnesses.
				continue
			}
			schemas++
			t.Run(fmt.Sprintf("%s/schema-%d", waf.Name, si+1), func(t *testing.T) {
				engine, err := Compile([]WAF{{Name: waf.Name, Schemas: []Scheme{schema}}})
				if err != nil {
					t.Fatal(err)
				}
				full := schemaEvidence(t, schema)
				if len(full) != len(schema.FingerPrints) || !catalogueSchemaMatches(t, schema, full) {
					t.Fatal("full AND fixture must provide one positive observation per fingerprint")
				}
				catalogueRequireTarget(t, engine.Classify(full), waf.Name, true)
				for fi, fp := range schema.FingerPrints {
					removals++
					t.Run(fmt.Sprintf("remove-fingerprint-%d-%s", fi+1, fp.Type), func(t *testing.T) {
						// Keep complete origin evidence even for a one-term AND.
						partial := append([]Evidence{catalogueOriginEvidence()}, full[:fi]...)
						partial = append(partial, full[fi+1:]...)
						want := catalogueSchemaMatches(t, schema, partial)
						catalogueRequireTarget(t, engine.Classify(partial), waf.Name, want)
						if !want {
							return
						}
						overlapping++
						t.Log("removed observation is redundant: remaining observations independently satisfy every AND term")
						// Remove this term's field everywhere, rather than assuming
						// its witness cannot also be supplied by another response.
						for i := range partial {
							partial[i] = catalogueWithoutField(fp, partial[i])
						}
						if catalogueFingerprintMatches(t, fp, partial) {
							t.Fatal("required term still matches after field removal; needs an explicit broad-rule boundary")
						}
						catalogueRequireTarget(t, engine.Classify(partial), waf.Name, false)
					})
				}
			})
		}
	}
	t.Logf("%d AND schemas, %d witness removals, %d overlapping removals additionally tested with required field absent", schemas, removals, overlapping)
}

func TestCatalogueIncompleteIsNotNegative(t *testing.T) {
	definitions := loadBundledCatalogue(t)
	engine, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("missing-observations", func(t *testing.T) {
		got := engine.Classify(nil)
		if got.State != Incomplete || len(got.Matches) != 0 || len(got.IncompleteProducts) != len(definitions) {
			t.Fatalf("missing observations must leave every product unresolved: %+v", got)
		}
		for i, waf := range definitions {
			if got.IncompleteProducts[i] != waf.Name {
				t.Fatalf("product %q not reported incomplete: %+v", waf.Name, got)
			}
		}
	})
	// One actual catalogue body rule is enough to guard the common evidence
	// completeness boundary; repeating truncation for all fingerprints adds none.
	var body FingerPrint
	for _, waf := range definitions {
		for _, schema := range waf.Schemas {
			for _, fp := range schema.FingerPrints {
				if body.Type == "" && fp.Type == "Content" {
					body = fp
				}
			}
		}
	}
	if body.Type == "" {
		t.Fatal("catalogue has no content rule for the incomplete-body control")
	}
	bodyEngine, err := Compile([]WAF{{Name: "body boundary", Schemas: []Scheme{{FingerPrints: []FingerPrint{body}}}}})
	if err != nil {
		t.Fatal(err)
	}
	positive := fingerprintEvidence(t, body)
	truncatedMiss := catalogueOriginEvidence()
	if catalogueFingerprintMatches(t, body, []Evidence{truncatedMiss}) {
		t.Fatal("origin must independently reject the representative body rule")
	}
	truncatedMiss.BodyTruncated = true
	truncatedHit := positive
	truncatedHit.BodyTruncated = true
	missingMetadata := positive
	missingMetadata.StatusCode = 0
	for _, test := range []struct {
		name     string
		evidence Evidence
	}{
		{"truncated-nonmatching-body", truncatedMiss},
		{"truncated-matching-body", truncatedHit},
		{"missing-response-metadata", missingMetadata},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := bodyEngine.Classify([]Evidence{test.evidence})
			if got.State != Incomplete || len(got.Matches) != 0 || len(got.IncompleteProducts) != 1 || got.IncompleteProducts[0] != "body boundary" {
				t.Fatalf("unavailable body evidence is not a clean negative: %+v", got)
			}
		})
	}
}

func catalogueOriginEvidence() Evidence {
	return Evidence{
		Role:       "baseline",
		StatusCode: http.StatusOK,
		Reason:     "OK",
		Headers: []Header{
			{"Server", "origin/1.0"},
			{"Content-Type", "text/html; charset=utf-8"},
			{"Set-Cookie", "session=ordinary; Path=/; HttpOnly"},
		},
		Body: []byte("<html><head><title>Example</title></head><body><p>Article published.</p></body></html>"),
	}
}

func catalogueRequireTarget(t *testing.T, got Outcome, product string, want bool) {
	t.Helper()
	if got.State != Complete || len(got.IncompleteProducts) != 0 {
		t.Fatalf("complete evidence must produce a complete decision: %+v", got)
	}
	found := false
	for _, match := range got.Matches {
		found = found || match.Product == product
	}
	if found != want {
		t.Fatalf("product %q matched = %v, want %v: %+v", product, found, want, got)
	}
}

func catalogueRegexp(t *testing.T, fp FingerPrint) *regexp.Regexp {
	t.Helper()
	pattern := fp.Pattern
	if fp.Type == "Header" {
		pattern = fp.HeaderValue
	}
	if fp.Type == "Reason" || fp.Type == "Status" {
		pattern = `\A` + regexp.QuoteMeta(pattern) + `\z`
	}
	expression, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return expression
}

// The oracle reads public evidence fields and uses stdlib regexp, never the
// engine's compiled matchers or verdicts. Call only with complete observations.
func catalogueFingerprintMatches(t *testing.T, fp FingerPrint, evidence []Evidence) bool {
	t.Helper()
	expression := catalogueRegexp(t, fp)
	for _, observation := range evidence {
		for _, value := range catalogueFieldValues(t, fp, observation) {
			if expression.MatchString(value) {
				return true
			}
		}
	}
	return false
}

func catalogueSchemaMatches(t *testing.T, schema Scheme, evidence []Evidence) bool {
	t.Helper()
	for _, fp := range schema.FingerPrints {
		matched := catalogueFingerprintMatches(t, fp, evidence)
		if matched == schema.Any {
			return schema.Any
		}
	}
	return !schema.Any
}

func catalogueFieldValues(t *testing.T, fp FingerPrint, observation Evidence) []string {
	t.Helper()
	if observation.StatusCode < 100 || observation.StatusCode > 999 || observation.BodyTruncated || observation.TransportError != "" {
		t.Fatal("regexp oracle requires complete response evidence")
	}
	switch fp.Type {
	case "Content":
		return []string{string(observation.Body)}
	case "Status":
		return []string{strconv.Itoa(observation.StatusCode)}
	case "Reason":
		if !catalogueValidField(observation.Reason) {
			t.Fatal("invalid HTTP reason phrase")
		}
		return []string{observation.Reason}
	case "Header", "Cookie":
		var values []string
		for _, header := range observation.Headers {
			if !catalogueValidField(header.Value) {
				t.Fatalf("invalid HTTP header value for %q", header.Name)
			}
			if fp.Type == "Header" && strings.EqualFold(header.Name, fp.HeaderKey) {
				values = append(values, header.Value)
			}
			if fp.Type == "Cookie" && strings.EqualFold(header.Name, "Set-Cookie") {
				cookie, err := http.ParseSetCookie(header.Value)
				if err != nil || cookie.Valid() != nil || len(cookie.Unparsed) != 0 {
					t.Fatalf("cookie control must contain a valid Set-Cookie field: %q", header.Value)
				}
				values = append(values, cookie.String())
			}
		}
		return values
	default:
		t.Fatalf("unsupported fingerprint type %q", fp.Type)
		return nil
	}
}

func catalogueMatchingValue(t *testing.T, fp FingerPrint, observation Evidence) string {
	t.Helper()
	expression := catalogueRegexp(t, fp)
	for _, value := range catalogueFieldValues(t, fp, observation) {
		if expression.MatchString(value) {
			return value
		}
	}
	t.Fatal("positive observation has no matching field value")
	return ""
}

func catalogueNearMiss(t *testing.T, fp FingerPrint, positive Evidence) Evidence {
	t.Helper()
	value := []rune(catalogueMatchingValue(t, fp, positive))
	try := func(candidate string) (Evidence, bool) {
		observation, valid := catalogueWithValue(fp, positive, candidate)
		return observation, valid && !catalogueFingerprintMatches(t, fp, []Evidence{observation})
	}
	// Prefer a one-character deletion or substitution of a real positive field,
	// retaining cookie syntax and HTTP field validity instead of arbitrary bytes.
	for i := range value {
		for _, candidate := range []string{
			string(value[:i]) + string(value[i+1:]),
			string(value[:i]) + "x" + string(value[i+1:]),
		} {
			if observation, rejected := try(candidate); rejected {
				return observation
			}
		}
	}
	for i := 1; i <= len(value); i++ {
		if observation, rejected := try(string(value[i:])); rejected {
			return observation
		}
	}
	for _, candidate := range []string{"origin/1.0", "session=ordinary; Path=/", "200", "201", ""} {
		if observation, rejected := try(candidate); rejected {
			return observation
		}
	}
	t.Fatalf("no valid regexp-rejected field for %s pattern %q; an unconditional rule needs an explicit positive-only limitation", fp.Type, catalogueRegexp(t, fp).String())
	return Evidence{}
}

func catalogueWithoutField(fp FingerPrint, observation Evidence) Evidence {
	switch fp.Type {
	case "Content":
		observation.Body = nil
	case "Reason":
		observation.Reason = ""
	case "Status":
		observation.StatusCode = http.StatusOK
		if fp.Pattern == "200" {
			observation.StatusCode = http.StatusCreated
		}
		observation.Reason = http.StatusText(observation.StatusCode)
	case "Header", "Cookie":
		key := fp.HeaderKey
		if fp.Type == "Cookie" {
			key = "Set-Cookie"
		}
		headers := make([]Header, 0, len(observation.Headers))
		for _, header := range observation.Headers {
			if !strings.EqualFold(header.Name, key) {
				headers = append(headers, header)
			}
		}
		observation.Headers = headers
	}
	return observation
}

func catalogueWithValue(fp FingerPrint, observation Evidence, value string) (Evidence, bool) {
	observation = catalogueWithoutField(fp, observation)
	if fp.Type != "Content" && !catalogueValidField(value) {
		return Evidence{}, false
	}
	switch fp.Type {
	case "Content":
		observation.Body = []byte(value)
	case "Header":
		observation.Headers = append(observation.Headers, Header{fp.HeaderKey, value})
	case "Cookie":
		cookie, err := http.ParseSetCookie(value)
		if err != nil || cookie.Valid() != nil || len(cookie.Unparsed) != 0 {
			return Evidence{}, false
		}
		observation.Headers = append(observation.Headers, Header{"Set-Cookie", value})
	case "Reason":
		observation.Reason = value
	case "Status":
		status, err := strconv.Atoi(value)
		if err != nil || len(value) != 3 || status < 100 || status > 999 {
			return Evidence{}, false
		}
		observation.StatusCode = status
		observation.Reason = http.StatusText(status)
		if observation.Reason == "" {
			observation.Reason = "Origin response"
		}
	}
	return observation, true
}

func catalogueValidField(value string) bool {
	for i := range len(value) {
		if value[i] < ' ' && value[i] != '\t' || value[i] == 127 {
			return false
		}
	}
	return true
}
