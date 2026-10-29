package wafme0w

import (
	"encoding/json"
	"reflect"
	"testing"
)

// JSON keeps the initial regressions runnable before the optional API fields exist.
func availabilityEvidence(t *testing.T, fields, availability string) Evidence {
	t.Helper()
	data := `{` + fields
	if availability != "" {
		data += `,"availability":` + availability
	}
	data += `}`
	var evidence Evidence
	if err := json.Unmarshal([]byte(data), &evidence); err != nil {
		t.Fatal(err)
	}
	return evidence
}

func availabilityEngine(t *testing.T, schema Scheme) *Engine {
	t.Helper()
	engine, err := Compile([]WAF{{Name: "fixture", Schemas: []Scheme{schema}}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestAvailabilityIndependentChannels(t *testing.T) {
	status := FingerPrint{Type: "Status", Pattern: "403"}
	header := FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "^firewall$"}
	cookie := FingerPrint{Type: "Cookie", Pattern: "^firewall=blocked"}
	reason := FingerPrint{Type: "Reason", Pattern: "Custom Denial"}
	body := FingerPrint{Type: "Content", Pattern: "blocked"}
	tests := []struct {
		name         string
		fields       string
		availability string
		fingerprint  FingerPrint
		state        EvaluationState
		matched      bool
	}{
		{"status only cannot settle header", `"status_code":403`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unavailable"}`, header, Incomplete, false},
		{"status only cannot settle body", `"status_code":403`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unavailable"}`, body, Incomplete, false},
		{"usable status independent of absent channels", `"status_code":403`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unavailable"}`, status, Complete, true},
		{"header without status", `"status_code":0,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unavailable"}`, header, Complete, true},
		{"cookie without status", `"status_code":0,"headers":[{"name":"Set-Cookie","value":"firewall=blocked; Path=/"}]`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unavailable"}`, cookie, Complete, true},
		{"reason without status", `"status_code":0,"reason":"Custom Denial"`, `{"status":"unavailable","headers":"unavailable","reason":"complete","body":"unavailable"}`, reason, Complete, true},
		{"complete body without status", `"status_code":0,"body":"YmxvY2tlZA=="`, `{"status":"unavailable","headers":"unavailable","reason":"unavailable","body":"complete"}`, body, Complete, true},
		{"complete empty headers prove absence", `"status_code":0`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unavailable"}`, header, Complete, false},
		{"partial faithful header proves presence", `"status_code":200,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`, header, Complete, true},
		{"partial faithful header miss remains unknown", `"status_code":200,"headers":[{"name":"Server","value":"origin"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`, header, Incomplete, false},
		{"partial empty headers remain unknown", `"status_code":200`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`, header, Incomplete, false},
		{"partial faithful cookie proves presence", `"status_code":0,"headers":[{"name":"Set-Cookie","value":"firewall=blocked; Expires=Wed, 09 Jun 2027 10:18:14 GMT"}]`, `{"status":"unavailable","headers":"incomplete","reason":"unavailable","body":"unknown"}`, cookie, Complete, true},
		{"partial cookie miss remains unknown", `"status_code":200,"headers":[{"name":"Set-Cookie","value":"session=ordinary"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`, cookie, Incomplete, false},
		{"unknown visible body literal disabled", `"status_code":200,"body":"YmxvY2tlZA=="`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`, body, Incomplete, false},
		{"incomplete visible body literal disabled", `"status_code":200,"body":"YmxvY2tlZA=="`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"incomplete"}`, body, Incomplete, false},
		{"unknown body anchored regexp disabled", `"status_code":200,"body":"YmxvY2tlZA=="`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`, FingerPrint{Type: "Content", Pattern: "blocked[.!]?$"}, Incomplete, false},
		{"complete empty body is observed", `"status_code":0`, `{"status":"unavailable","headers":"unavailable","reason":"unavailable","body":"complete"}`, FingerPrint{Type: "Content", Pattern: "^$"}, Complete, true},
		{"unavailable reason is not known empty", `"status_code":200`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`, FingerPrint{Type: "Reason", Pattern: "^$"}, Incomplete, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			observation := availabilityEvidence(t, tt.fields, tt.availability)
			got := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{tt.fingerprint}}).Classify([]Evidence{observation})
			if got.State != tt.state || (len(got.Matches) == 1) != tt.matched {
				t.Fatalf("got %+v; want state %s matched %t", got, tt.state, tt.matched)
			}
			if tt.state == Incomplete && !reflect.DeepEqual(got.IncompleteProducts, []string{"fixture"}) {
				t.Fatalf("unknown product not reported: %+v", got)
			}
			if tt.matched && !reflect.DeepEqual(got.Matches[0].Fingerprints, []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}) {
				t.Fatalf("wrong supporting observation: %+v", got.Matches)
			}
		})
	}
}

func TestAvailabilityInvalidNeverClassifies(t *testing.T) {
	engine := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{{Type: "Status", Pattern: "200"}}})
	validMarker := Evidence{StatusCode: 200, Headers: []Header{{Name: "X-WAF-Protection", Value: "active"}}}
	tests := []struct {
		name         string
		fields       string
		availability string
	}{
		{"empty explicit object", `"status_code":200`, `{}`},
		{"missing member", `"status_code":200`, `{"status":"complete","headers":"complete","body":"unknown"}`},
		{"null member", `"status_code":200`, `{"status":"complete","headers":null,"reason":"unavailable","body":"unknown"}`},
		{"unknown enum", `"status_code":200`, `{"status":"complete","headers":"lossy","reason":"unavailable","body":"unknown"}`},
		{"partial status not permitted", `"status_code":200`, `{"status":"incomplete","headers":"complete","reason":"unavailable","body":"unknown"}`},
		{"unknown headers not permitted", `"status_code":200`, `{"status":"complete","headers":"unknown","reason":"unavailable","body":"unknown"}`},
		{"unknown reason not permitted", `"status_code":200`, `{"status":"complete","headers":"complete","reason":"unknown","body":"unknown"}`},
		{"complete status requires valid code", `"status_code":0`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`},
		{"unavailable status cannot carry code", `"status_code":200`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unknown"}`},
		{"unavailable headers cannot carry values", `"status_code":200,"headers":[{"name":"Server","value":"origin"}]`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unknown"}`},
		{"unavailable reason cannot carry phrase", `"status_code":200,"reason":"OK"`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`},
		{"unavailable body cannot carry bytes", `"status_code":200,"body":"eA=="`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unavailable"}`},
		{"complete body contradicts truncation", `"status_code":200,"body_truncated":true`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"complete"}`},
		{"complete body contradicts structured error", `"status_code":200,"error_code":"body_read_error"`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"complete"}`},
		{"complete body contradicts transport error", `"status_code":200,"transport_error":"read failed"`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"complete"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalid := availabilityEvidence(t, tt.fields, tt.availability)
			// A prior valid match must not escape whole-input validation.
			evidence := []Evidence{validMarker, invalid}
			got := engine.Classify(evidence)
			if got.State != Failed || len(got.Matches) != 0 || len(got.IncompleteProducts) != 0 || len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "invalid_evidence" || got.Diagnostics[0].Evidence != 1 {
				t.Fatalf("invalid explicit availability produced classification: %+v", got)
			}
			if got := GenericDetect(evidence); got.Mode != "" {
				t.Fatalf("invalid explicit availability produced generic conclusion: %+v", got)
			}
		})
	}
}

func TestAvailabilityLegacyNilUnchanged(t *testing.T) {
	engine := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "Server", HeaderValue: "firewall"}}})
	for _, fields := range []string{
		`"status_code":200,"headers":[{"name":"Server","value":"firewall"}]`,
		`"status_code":0,"headers":[{"name":"Server","value":"firewall"}]`,
		`"status_code":200`,
		`"status_code":200,"error_code":"body_read_error"`,
	} {
		absent := availabilityEvidence(t, fields, "")
		null := availabilityEvidence(t, fields, "null")
		if got, want := engine.Classify([]Evidence{null}), engine.Classify([]Evidence{absent}); !reflect.DeepEqual(got, want) {
			t.Fatalf("null availability changed legacy outcome: got %+v want %+v", got, want)
		}
		for _, observation := range []Evidence{absent, null} {
			encoded, err := json.Marshal(observation)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			if _, exists := fields["availability"]; exists {
				t.Fatalf("legacy serialization gained availability: %s", encoded)
			}
		}
	}
}

func TestAvailabilitySchemaLogicAndWitnesses(t *testing.T) {
	header := FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "^firewall$"}
	body := FingerPrint{Type: "Content", Pattern: "blocked"}
	status := FingerPrint{Type: "Status", Pattern: "403"}
	partial := availabilityEvidence(t, `"status_code":200,"headers":[{"name":"Server","value":"firewall"}],"body":"YmxvY2tlZA=="`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`)
	for _, tt := range []struct {
		name   string
		schema Scheme
		state  EvaluationState
		match  bool
	}{
		{"AND known false dominates unknown", Scheme{FingerPrints: []FingerPrint{status, body}}, Complete, false},
		{"AND true leaves unknown", Scheme{FingerPrints: []FingerPrint{header, body}}, Incomplete, false},
		{"OR known true dominates unknown", Scheme{Any: true, FingerPrints: []FingerPrint{body, header}}, Complete, true},
		{"OR false leaves unknown", Scheme{Any: true, FingerPrints: []FingerPrint{status, body}}, Incomplete, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := availabilityEngine(t, tt.schema).Classify([]Evidence{partial})
			if got.State != tt.state || (len(got.Matches) == 1) != tt.match {
				t.Fatalf("got %+v; want state %s match %t", got, tt.state, tt.match)
			}
		})
	}
	evidence := []Evidence{
		availabilityEvidence(t, `"status_code":0`, `{"status":"unavailable","headers":"incomplete","reason":"unavailable","body":"unknown"}`),
		availabilityEvidence(t, `"status_code":0,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"unavailable","headers":"incomplete","reason":"unavailable","body":"unknown"}`),
		availabilityEvidence(t, `"status_code":403`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unavailable"}`),
		availabilityEvidence(t, `"status_code":403,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"complete","headers":"complete","reason":"unavailable","body":"unknown"}`),
	}
	got := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{header, status}}).Classify(evidence)
	want := []Match{{Product: "fixture", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 1}, {Fingerprint: 2, Evidence: 2}}}}
	if got.State != Complete || !reflect.DeepEqual(got.Matches, want) {
		t.Fatalf("cross-observation first witnesses changed: got %+v want %+v", got, want)
	}
}

func TestAvailabilityGenericGates(t *testing.T) {
	for _, tt := range []struct {
		name     string
		evidence []Evidence
		mode     GenericDetectionMode
	}{
		{"partial marker without status", []Evidence{availabilityEvidence(t, `"role":"Normal","status_code":0,"headers":[{"name":"X-WAF-Protection","value":"active"}]`, `{"status":"unavailable","headers":"incomplete","reason":"unavailable","body":"unknown"}`)}, WAFHeaderDetected},
		{"partial headers cannot establish server change", []Evidence{
			availabilityEvidence(t, `"role":"Normal","status_code":200,"headers":[{"name":"Server","value":"origin"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`),
			availabilityEvidence(t, `"role":"Probe","status_code":200,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`),
		}, ""},
		{"status difference independent of headers", []Evidence{
			availabilityEvidence(t, `"role":"Normal","status_code":200`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unknown"}`),
			availabilityEvidence(t, `"role":"Probe","status_code":403`, `{"status":"complete","headers":"unavailable","reason":"unavailable","body":"unknown"}`),
		}, ChangeInStatus},
		{"complete headers compare without status", []Evidence{
			availabilityEvidence(t, `"role":"Normal","status_code":0,"headers":[{"name":"Server","value":"origin"}]`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unknown"}`),
			availabilityEvidence(t, `"role":"Probe","status_code":0,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"unavailable","headers":"complete","reason":"unavailable","body":"unknown"}`),
		}, ChangeInHeader},
		{"single normal has no differential conclusion", []Evidence{availabilityEvidence(t, `"role":"Normal","status_code":403,"headers":[{"name":"Server","value":"firewall"}]`, `{"status":"complete","headers":"incomplete","reason":"unavailable","body":"unknown"}`)}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := GenericDetect(tt.evidence); got.Mode != tt.mode {
				t.Fatalf("got %+v; want mode %s", got, tt.mode)
			}
		})
	}
}

func TestAvailabilityExplicitCompleteMatchesLegacy(t *testing.T) {
	definitions := []WAF{
		{Name: "header", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "Server", HeaderValue: "(?i)firewall"}}}}},
		{Name: "cookie", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Cookie", Pattern: "^firewall=blocked"}}}}},
		{Name: "status", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Status", Pattern: "403"}}}}},
		{Name: "reason", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Reason", Pattern: "^Custom Denial$"}}}}},
		{Name: "body", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "(?i)blocked.*tail$"}}}}},
	}
	engine, err := Compile(definitions)
	if err != nil {
		t.Fatal(err)
	}
	// Bounded cross-product checks the nil path against asserted complete
	// metadata, including empty channels, UTF-8 folding and legacy body errors.
	for _, status := range []int{200, 403} {
		for _, marker := range []bool{false, true} {
			for _, body := range []string{"", "ordinary", "BLOCKED tail", "\xffblocked tail"} {
				for _, failure := range []string{"", "body_read_error"} {
					for _, truncated := range []bool{false, true} {
						legacy := Evidence{Role: "Normal", StatusCode: status, Body: []byte(body), ErrorCode: failure, BodyTruncated: truncated}
						if marker {
							legacy.Reason = "Custom Denial"
							legacy.Headers = []Header{{Name: "Server", Value: "FIREWALL"}, {Name: "Set-Cookie", Value: "firewall=blocked"}}
						}
						explicit := legacy
						explicit.Availability = &EvidenceAvailability{
							Status: ChannelComplete, Headers: ChannelComplete, Reason: ChannelComplete, Body: ChannelComplete,
						}
						if failure != "" || truncated {
							explicit.Availability.Body = ChannelIncomplete
						}
						got, want := engine.Classify([]Evidence{explicit}), engine.Classify([]Evidence{legacy})
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("explicit/legacy diverged for %+v: got %+v want %+v", legacy, got, want)
						}
						if got, want := GenericDetect([]Evidence{explicit}), GenericDetect([]Evidence{legacy}); got != want {
							t.Fatalf("generic explicit/legacy diverged: got %+v want %+v", got, want)
						}
					}
				}
			}
		}
	}
}

func TestAvailabilitySummarySnapshotAndLegacyOmission(t *testing.T) {
	engine := availabilityEngine(t, Scheme{FingerPrints: []FingerPrint{{Type: "Status", Pattern: "200"}}})
	observation := Evidence{Role: "Normal", StatusCode: 200, Availability: &EvidenceAvailability{
		Status: ChannelComplete, Headers: ChannelIncomplete, Reason: ChannelUnavailable, Body: ChannelUnknown,
	}}
	result := makeResult(engine, "saved", "", []Evidence{observation}, DefaultConfig())
	summary := result.Evidence[0]
	if summary.Availability == nil || *summary.Availability != *observation.Availability {
		t.Fatalf("summary lost channel availability: %+v", summary)
	}
	observation.Availability.Headers = ChannelUnavailable
	if summary.Availability.Headers != ChannelIncomplete {
		t.Fatal("summary aliases the caller's availability")
	}
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var projected struct {
		Availability map[string]string `json:"availability"`
	}
	if err := json.Unmarshal(data, &projected); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"status": "complete", "headers": "incomplete", "reason": "unavailable", "body": "unknown"}
	if !reflect.DeepEqual(projected.Availability, want) {
		t.Fatalf("wrong channel JSON: got %s", data)
	}
	observation.Availability = nil
	legacy := makeResult(engine, "saved", "", []Evidence{observation}, DefaultConfig()).Evidence[0]
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, exists := fields["availability"]; exists {
		t.Fatalf("legacy summary gained availability: %s", data)
	}
}

func FuzzAvailabilityUnusableBody(f *testing.F) {
	engine, err := Compile([]WAF{{Name: "body", Schemas: []Scheme{{Any: true, FingerPrints: []FingerPrint{
		{Type: "Content", Pattern: "blocked"},
		{Type: "Content", Pattern: "blocked[.!]?$"},
		{Type: "Content", Pattern: "^$"},
		{Type: "Content", Pattern: "(?i)Kelvin"},
	}}}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte("blocked"), false)
	f.Add([]byte("blocked!"), true)
	f.Add([]byte{}, false)
	f.Add([]byte("\xffKELVIN"), true)
	f.Fuzz(func(t *testing.T, body []byte, incomplete bool) {
		if len(body) > 4096 {
			body = body[:4096]
		}
		before := string(body)
		state := ChannelUnknown
		if incomplete {
			state = ChannelIncomplete
		}
		observation := Evidence{StatusCode: 200, Body: body, Availability: &EvidenceAvailability{
			Status: ChannelComplete, Headers: ChannelComplete, Reason: ChannelUnavailable, Body: state,
		}}
		got := engine.Classify([]Evidence{observation})
		if got.State != Incomplete || len(got.Matches) != 0 || !reflect.DeepEqual(got.IncompleteProducts, []string{"body"}) {
			t.Fatalf("%s body must not supply positive or negative evidence: %+v", state, got)
		}
		if string(body) != before {
			t.Fatal("classification changed caller body")
		}
	})
}
