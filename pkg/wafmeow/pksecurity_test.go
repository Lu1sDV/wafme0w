package wafmeow

import (
	"slices"
	"testing"
)

const (
	pkSecurityProduct = "pkSecurity IDS (pkSec)"
	pkModuleMarker    = "pk Security Module"
	pkAlertMarker     = "Security Alert"
	pkAttackMarker    = "As this could be a potential hack attack"
	pkBlockedMarker   = "A safety critical request was detected and blocked"
	pkReloadMarker    = "maximum number of reloads per minute and prevented access"
)

// These literal cases and expectations were authored from the upstream source,
// before running the detector. They must not be regenerated from catalogue
// regexps or observed classifications. The source is identical in v2.4.2 and:
// https://github.com/EnableSecurity/wafw00f/blob/69fbe3956bba47a172cf87e40e9037535d32a130/wafw00f/plugins/pksec.py
// check_schema_01 accepts either marker; check_schema_02 requires all three.
// This checks source conformance, not independently captured product truth.
func TestPKSecuritySourceConformance(t *testing.T) {
	engine, err := Compile(loadBundledCatalogue(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		body   string
		schema int
	}{
		{"schema1/neither", "ordinary origin response", 0},
		{"schema1/module-only", pkModuleMarker, 1},
		{"schema1/alert-only", pkAlertMarker, 1},
		{"schema1/both", pkModuleMarker + "\n" + pkAlertMarker, 1},
		{"schema2/none", "ordinary origin response", 0},
		{"schema2/attack-only", pkAttackMarker, 0},
		{"schema2/blocked-only", pkBlockedMarker, 0},
		{"schema2/reload-only", pkReloadMarker, 0},
		{"schema2/missing-reload", pkAttackMarker + "\n" + pkBlockedMarker, 0},
		{"schema2/missing-blocked", pkAttackMarker + "\n" + pkReloadMarker, 0},
		{"schema2/missing-attack", pkBlockedMarker + "\n" + pkReloadMarker, 0},
		{"schema2/all", pkAttackMarker + "\n" + pkBlockedMarker + "\n" + pkReloadMarker, 2},
		{"schema2/alternative-words", pkAttackMarker + "\nA safety critical call was discovered and blocked\n" + pkReloadMarker, 2},
		{"schema1/case-and-optional-separators", "PKSECURITYMODULE", 1},
		{"schema1/near-miss-module", "pk  Security  Module", 0},
		{"schema1/near-miss-alert", "Security  Alert", 0},
		{"schema1/newline-is-not-dot", "Security\nAlert", 0},
		{"schema2/near-miss-attack", "As this could be a potential hack attempt\n" + pkBlockedMarker + "\n" + pkReloadMarker, 0},
		{"schema2/near-miss-blocked", pkAttackMarker + "\nA safety critical event was detected and blocked\n" + pkReloadMarker, 0},
		{"schema2/near-miss-reload", pkAttackMarker + "\n" + pkBlockedMarker + "\nmaximum number of reloads per hour and prevented access", 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Matching both roles isolates Boolean grouping from the intentional
			// difference in upstream Attack selection and native evidence pools.
			normal, attack := pkSecurityEvidence(test.body), pkSecurityEvidence(test.body)
			normal.Role = "Normal"
			outcome := engine.Classify([]Evidence{normal, attack})
			requirePKSecurityProducts(t, outcome, test.schema)
			if outcome.State != Complete || len(outcome.IncompleteProducts) != 0 || len(outcome.Diagnostics) != 0 {
				t.Fatalf("complete literal fixture produced unsettled evidence: %+v", outcome)
			}
		})
	}
}

func TestPKSecurityIncompleteEvidence(t *testing.T) {
	definitions := loadBundledCatalogue(t)
	engine, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	productIndex := slices.IndexFunc(definitions, func(waf WAF) bool { return waf.Name == pkSecurityProduct })
	if productIndex < 0 {
		t.Fatal("pkSecurity missing from bundled catalogue")
	}
	product, err := Compile([]WAF{definitions[productIndex]})
	if err != nil {
		t.Fatal(err)
	}
	markers := []struct{ name, body string }{
		{"module", pkModuleMarker},
		{"alert", pkAlertMarker},
		{"all-schema2-terms", pkAttackMarker + "\n" + pkBlockedMarker + "\n" + pkReloadMarker},
	}
	for _, marker := range markers {
		for _, kind := range []string{"truncated", "read-error", "unknown-completeness", "unavailable"} {
			t.Run(kind+"/"+marker.name, func(t *testing.T) {
				observation := pkSecurityEvidence(marker.body)
				switch kind {
				case "truncated":
					observation.BodyTruncated = true
				case "read-error":
					observation.ErrorCode = "body_read_error"
					observation.TransportError = "synthetic interrupted body"
				case "unknown-completeness", "unavailable":
					observation.Availability = &EvidenceAvailability{
						Status: ChannelComplete, Reason: ChannelComplete,
						Headers: ChannelComplete, Body: ChannelUnknown,
					}
					if kind == "unavailable" {
						observation.Availability.Body = ChannelUnavailable
						observation.Body = nil
					}
				}
				// A complete ordinary response must not turn the unusable marker
				// into either a positive or a confident product-level negative.
				evidence := []Evidence{pkSecurityEvidence("ordinary origin response"), observation}
				outcome := engine.Classify(evidence)
				requirePKSecurityProducts(t, outcome, 0)
				if outcome.State != Incomplete || !slices.Contains(outcome.IncompleteProducts, pkSecurityProduct) {
					t.Fatalf("unusable body settled pkSecurity: %+v", outcome)
				}
				isolated := product.Classify(evidence)
				if isolated.State != Incomplete || len(isolated.Matches) != 0 || !slices.Equal(isolated.IncompleteProducts, []string{pkSecurityProduct}) {
					t.Fatalf("pkSecurity must remain unknown: %+v", isolated)
				}
			})
		}
	}
}

func TestPKSecurityNativeEvidencePool(t *testing.T) {
	engine, err := Compile(loadBundledCatalogue(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		evidence []Evidence
		schema   int
	}{
		{
			name: "normal-role-marker",
			evidence: []Evidence{{
				Role: "Normal", StatusCode: 200, Reason: "OK", Body: []byte(pkAlertMarker),
			}},
			schema: 1,
		},
		{
			name:     "all-terms-across-complete-responses",
			evidence: []Evidence{pkSecurityEvidence(pkAttackMarker), pkSecurityEvidence(pkBlockedMarker), pkSecurityEvidence(pkReloadMarker)},
			schema:   2,
		},
		{
			name: "header-marker-does-not-satisfy-body",
			evidence: []Evidence{{
				Role: "Attack", StatusCode: 200, Reason: "OK", Body: []byte("ordinary origin response"),
				Headers: []Header{{Name: "X-Synthetic-Marker", Value: pkModuleMarker + "; " + pkAlertMarker}},
			}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outcome := engine.Classify(test.evidence)
			requirePKSecurityProducts(t, outcome, test.schema)
			if outcome.State != Complete || len(outcome.IncompleteProducts) != 0 || len(outcome.Diagnostics) != 0 {
				t.Fatalf("complete native evidence pool was not settled: %+v", outcome)
			}
		})
	}
}

func pkSecurityEvidence(body string) Evidence {
	return Evidence{Role: "Attack", StatusCode: 200, Reason: "OK", Body: []byte(body)}
}

func requirePKSecurityProducts(t *testing.T, outcome Outcome, schema int) {
	t.Helper()
	var want []string
	if schema != 0 {
		want = []string{pkSecurityProduct}
	}
	products := make([]string, len(outcome.Matches))
	for index, match := range outcome.Matches {
		products[index] = match.Product
	}
	// Assert the entire catalogue result, not just membership of pkSecurity.
	if !slices.Equal(products, want) {
		t.Fatalf("products = %q, want exactly %q (outcome %+v)", products, want, outcome)
	}
	if schema != 0 && outcome.Matches[0].Schema != schema {
		t.Fatalf("matched schema %d, want %d", outcome.Matches[0].Schema, schema)
	}
}
