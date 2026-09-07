package wafme0w

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
)

func TestClassifyResponseEvidence(t *testing.T) {
	tests := []struct {
		name     string
		fp       FingerPrint
		evidence []Evidence
		want     bool
		witness  int
	}{
		{
			name: "duplicate response roles",
			fp:   FingerPrint{Type: "Content", Pattern: "blocked"},
			evidence: []Evidence{
				{Role: "Normal", StatusCode: 200, Body: []byte("welcome")},
				{Role: "Normal", StatusCode: 200, Body: []byte("blocked")},
			},
			want:    true,
			witness: 1,
		},
		{
			name:     "later repeated header value",
			fp:       FingerPrint{Type: "Header", HeaderKey: "x-firewall", HeaderValue: "^blocked$"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"X-Firewall", "welcome"}, {"x-firewall", "blocked"}}}},
			want:     true,
		},
		{
			name:     "missing header cannot match empty",
			fp:       FingerPrint{Type: "Header", HeaderKey: "X-Missing", HeaderValue: "^$"},
			evidence: []Evidence{{StatusCode: 200}},
		},
		{
			name:     "present empty header can match empty",
			fp:       FingerPrint{Type: "Header", HeaderKey: "X-Empty", HeaderValue: "^$"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"X-Empty", ""}}}},
			want:     true,
		},
		{
			name:     "repeated empty headers are not a nonempty joined value",
			fp:       FingerPrint{Type: "Header", HeaderKey: "X-Empty", HeaderValue: ".+"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"X-Empty", ""}, {"X-Empty", ""}}}},
		},
		{
			name:     "actual custom reason phrase",
			fp:       FingerPrint{Type: "Reason", Pattern: "Custom Firewall Denial"},
			evidence: []Evidence{{StatusCode: 403, Reason: "Custom Firewall Denial"}},
			want:     true,
		},
		{
			name:     "reason excludes numeric status",
			fp:       FingerPrint{Type: "Reason", Pattern: "403"},
			evidence: []Evidence{{StatusCode: 403, Reason: "Forbidden"}},
		},
		{
			name:     "reason does not substitute standard phrase",
			fp:       FingerPrint{Type: "Reason", Pattern: "Forbidden"},
			evidence: []Evidence{{StatusCode: 403, Reason: "Custom Denial"}},
		},
		{
			name:     "nonstandard HTTP status",
			fp:       FingerPrint{Type: "Status", Pattern: "999"},
			evidence: []Evidence{{StatusCode: 999}},
			want:     true,
		},
		{
			name:     "different integer status",
			fp:       FingerPrint{Type: "Status", Pattern: "403"},
			evidence: []Evidence{{StatusCode: 200}},
		},
		{
			name:     "attack remains metadata",
			fp:       FingerPrint{Type: "Content", Pattern: "blocked", Attack: true},
			evidence: []Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("blocked")}},
			want:     true,
		},
		{
			name:     "later cookie",
			fp:       FingerPrint{Type: "Cookie", Pattern: "^firewall=blocked"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"Set-Cookie", "session=ok"}, {"Set-Cookie", "firewall=blocked; Path=/"}}}},
			want:     true,
		},
		{
			name:     "bare cookie token is not a parsed cookie",
			fp:       FingerPrint{Type: "Cookie", Pattern: "^firewall"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"Set-Cookie", "firewall"}}}},
		},
		{
			name:     "space in cookie name is rejected",
			fp:       FingerPrint{Type: "Cookie", Pattern: "^firewall"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"Set-Cookie", "firewall name=blocked"}}}},
		},
		{
			name:     "invalid cookie does not hide later valid cookie",
			fp:       FingerPrint{Type: "Cookie", Pattern: "^firewall=blocked"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"Set-Cookie", "firewall name=bad"}, {"Set-Cookie", "firewall=blocked; Path=/"}}}},
			want:     true,
		},
		{
			name:     "unrecognized cookie attribute does not discard valid cookie",
			fp:       FingerPrint{Type: "Cookie", Pattern: "^firewall=blocked"},
			evidence: []Evidence{{StatusCode: 200, Headers: []Header{{"Set-Cookie", "firewall=blocked; SameSite=unknown"}}}},
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := Compile([]WAF{{Name: "fixture", Schemas: []Scheme{{FingerPrints: []FingerPrint{tt.fp}}}}})
			if err != nil {
				t.Fatal(err)
			}
			want := Outcome{State: Complete}
			if tt.want {
				want.Matches = []Match{{Product: "fixture", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: tt.witness}}}}
			}
			if got := engine.Classify(tt.evidence); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestReasonLiteralEquality(t *testing.T) {
	for _, pattern := range []string{"Custom Denial", "Denied [policy].", "(?i)Denied"} {
		engine, err := Compile([]WAF{{Name: "reason", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Reason", Pattern: pattern}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, reason := range []string{pattern, strings.ToLower(pattern), "prefix " + pattern, pattern + " suffix"} {
			got := engine.Classify([]Evidence{{StatusCode: 403, Reason: reason}})
			if got.State != Complete || (len(got.Matches) == 1) != (reason == pattern) {
				t.Fatalf("literal %q on %q: %+v", pattern, reason, got)
			}
		}
	}
}

func TestClassifySchemaLogic(t *testing.T) {
	found := FingerPrint{Type: "Content", Pattern: "blocked", Attack: true}
	missing := FingerPrint{Type: "Content", Pattern: "missing"}
	header := FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "firewall"}
	wafs := []WAF{
		{Name: "any", Schemas: []Scheme{{Any: true, FingerPrints: []FingerPrint{missing, found, header}}}},
		{Name: "all missing", Schemas: []Scheme{{FingerPrints: []FingerPrint{found, missing}}}},
		{Name: "all across responses", Schemas: []Scheme{{FingerPrints: []FingerPrint{found, header}}}},
		{Name: "alternative", Schemas: []Scheme{{FingerPrints: []FingerPrint{missing}}, {FingerPrints: []FingerPrint{found}}}},
		{Name: "only once", Schemas: []Scheme{{FingerPrints: []FingerPrint{found}}, {FingerPrints: []FingerPrint{found}}}},
	}
	engine, err := Compile(wafs)
	if err != nil {
		t.Fatal(err)
	}
	evidence := []Evidence{
		{Role: "Normal", StatusCode: 200, Body: []byte("blocked")},
		{Role: "Auxiliary", StatusCode: 200, Headers: []Header{{"Server", "firewall"}}},
		{Role: "Repeated", StatusCode: 200, Body: []byte("blocked"), Headers: []Header{{"Server", "firewall"}}},
	}
	want := Outcome{State: Complete, Matches: []Match{
		{Product: "any", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 2, Evidence: 0}}},
		{Product: "all across responses", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}, {Fingerprint: 2, Evidence: 1}}},
		{Product: "alternative", Schema: 2, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
		{Product: "only once", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
	}}
	if got := engine.Classify(evidence); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestClassifyThreeValuedLogic(t *testing.T) {
	body := FingerPrint{Type: "Content", Pattern: "blocked"}
	present := FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "firewall"}
	absent := FingerPrint{Type: "Header", HeaderKey: "X-Missing", HeaderValue: "^$"}
	evidence := []Evidence{{StatusCode: 200, Headers: []Header{{"Server", "firewall"}}, Body: []byte("blocked"), BodyTruncated: true}}
	tests := []struct {
		name    string
		schemas []Scheme
		state   EvaluationState
		schema  int
	}{
		{"AND false settles unknown", []Scheme{{FingerPrints: []FingerPrint{body, absent}}}, Complete, 0},
		{"AND true leaves unknown", []Scheme{{FingerPrints: []FingerPrint{body, present}}}, Incomplete, 0},
		{"OR true settles unknown", []Scheme{{Any: true, FingerPrints: []FingerPrint{body, present}}}, Complete, 1},
		{"OR false leaves unknown", []Scheme{{Any: true, FingerPrints: []FingerPrint{body, absent}}}, Incomplete, 0},
		{"true alternative settles unknown", []Scheme{{FingerPrints: []FingerPrint{body}}, {FingerPrints: []FingerPrint{present}}}, Complete, 2},
		{"false alternative leaves unknown", []Scheme{{FingerPrints: []FingerPrint{body}}, {FingerPrints: []FingerPrint{absent}}}, Incomplete, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := Compile([]WAF{{Name: "fixture", Schemas: tt.schemas}})
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Classify(evidence)
			want := Outcome{State: tt.state}
			if tt.schema != 0 {
				fingerprint := 1
				if tt.schema == 1 {
					fingerprint = 2
				}
				want.Matches = []Match{{Product: "fixture", Schema: tt.schema, Fingerprints: []FingerprintMatch{{Fingerprint: fingerprint, Evidence: 0}}}}
			}
			if tt.state == Incomplete {
				want.IncompleteProducts = []string{"fixture"}
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != "body_truncated" || got.Diagnostics[0].Evidence != 0 {
				t.Fatalf("missing truncation diagnostic: %+v", got.Diagnostics)
			}
			got.Diagnostics = nil
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestClassifyIncompleteObservations(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		evidence []Evidence
		want     bool
		code     string
		index    int
	}{
		{"missing observations", "blocked", nil, false, "missing_response", -1},
		{"missing metadata", "blocked", []Evidence{{Body: []byte("blocked")}}, false, "missing_response", 0},
		{"invalid metadata", "blocked", []Evidence{{StatusCode: 1000, Body: []byte("blocked")}}, false, "missing_response", 0},
		{"truncated literal hit", "blocked", []Evidence{{StatusCode: 200, Body: []byte("blocked"), BodyTruncated: true}}, false, "body_truncated", 0},
		{"truncated literal miss", "blocked", []Evidence{{StatusCode: 200, Body: []byte("welcome"), BodyTruncated: true}}, false, "body_truncated", 0},
		{"truncated end anchor", "blocked$", []Evidence{{StatusCode: 200, Body: []byte("blocked"), BodyTruncated: true}}, false, "body_truncated", 0},
		{"truncated regexp end anchor", "blocked[.!]?$", []Evidence{{StatusCode: 200, Body: []byte("blocked"), BodyTruncated: true}}, false, "body_truncated", 0},
		{"body read error", "blocked", []Evidence{{StatusCode: 200, Body: []byte("blocked"), TransportError: "read failed"}}, false, "transport_error", 0},
		{"structured body read error", "blocked", []Evidence{{StatusCode: 200, Body: []byte("blocked"), TransportError: "read failed", ErrorCode: "body_read_error"}}, false, "body_read_error", 0},
		{"structured error without legacy text", "blocked", []Evidence{{StatusCode: 200, Body: []byte("blocked"), ErrorCode: "request_timeout"}}, false, "request_timeout", 0},
		{"structured missing metadata", "blocked", []Evidence{{ErrorCode: "redirect_policy"}}, false, "redirect_policy", 0},
		{"missing response after known miss", "blocked", []Evidence{{StatusCode: 200, Body: []byte("welcome")}, {}}, false, "missing_response", 1},
		{"known match before missing response", "blocked", []Evidence{{StatusCode: 200, Body: []byte("blocked")}, {}}, true, "missing_response", 1},
		{"known match after missing response", "blocked", []Evidence{{}, {StatusCode: 200, Body: []byte("blocked")}}, true, "missing_response", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := Compile([]WAF{{Name: "fixture", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: tt.pattern}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Classify(tt.evidence)
			want := Outcome{State: Incomplete, IncompleteProducts: []string{"fixture"}}
			if tt.want {
				witness := 0
				if tt.evidence[0].StatusCode == 0 {
					witness = 1
				}
				want = Outcome{State: Complete, Matches: []Match{{Product: "fixture", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: witness}}}}}
			}
			if len(got.Diagnostics) != 1 || got.Diagnostics[0].Code != tt.code || got.Diagnostics[0].Evidence != tt.index {
				t.Fatalf("unexpected evidence diagnostics: %+v", got.Diagnostics)
			}
			got.Diagnostics = nil
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %+v, want %+v", got, want)
			}
		})
	}
}

func TestClassifyMetadataSurvivesBodyError(t *testing.T) {
	fingerprints := []FingerPrint{
		{Type: "Header", HeaderKey: "Server", HeaderValue: "firewall"},
		{Type: "Cookie", Pattern: "^firewall=blocked"},
		{Type: "Status", Pattern: "403"},
		{Type: "Reason", Pattern: "Custom Denial"},
		{Type: "Content", Pattern: "blocked"},
	}
	var wafs []WAF
	for _, fp := range fingerprints {
		wafs = append(wafs, WAF{Name: fp.Type, Schemas: []Scheme{{FingerPrints: []FingerPrint{fp}}}})
	}
	engine, err := Compile(wafs)
	if err != nil {
		t.Fatal(err)
	}
	got := engine.Classify([]Evidence{{
		StatusCode: 403, Reason: "Custom Denial", Body: []byte("blocked"), TransportError: "read failed", BodyTruncated: true,
		Headers: []Header{{"Server", "firewall"}, {"Set-Cookie", "firewall=blocked"}},
	}})
	if len(got.Diagnostics) != 2 || got.Diagnostics[0].Code != "transport_error" || got.Diagnostics[1].Code != "body_truncated" || got.Diagnostics[0].Evidence != 0 || got.Diagnostics[1].Evidence != 0 {
		t.Fatalf("missing evidence diagnostics: %+v", got.Diagnostics)
	}
	got.Diagnostics = nil
	want := Outcome{State: Incomplete, Matches: []Match{
		{Product: "Header", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
		{Product: "Cookie", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
		{Product: "Status", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
		{Product: "Reason", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}},
	}, IncompleteProducts: []string{"Content"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestCompileOwnsDefinitionsConcurrently(t *testing.T) {
	wafs := []WAF{{Name: "fixture", Schemas: []Scheme{{Any: true, FingerPrints: []FingerPrint{
		{Type: "Content", Pattern: "(?i)kelvin"},
		{Type: "Header", HeaderKey: "Server", HeaderValue: "missing"},
	}}}}}
	engine, err := Compile(wafs)
	if err != nil {
		t.Fatal(err)
	}
	digest := engine.Digest()
	wafs[0].Name = "changed"
	wafs[0].Schemas[0].Any = false
	wafs[0].Schemas[0].FingerPrints[0].Pattern = "missing"
	wafs[0].Schemas[0].FingerPrints[1].HeaderValue = "changed"
	wafs[0].Schemas = nil
	evidence := []Evidence{{StatusCode: 200, Body: []byte("KELVIN")}}
	want := Outcome{State: Complete, Matches: []Match{{Product: "fixture", Schema: 1, Fingerprints: []FingerprintMatch{{Fingerprint: 1, Evidence: 0}}}}}
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range 8 {
				got := engine.Classify(evidence)
				if !reflect.DeepEqual(got, want) {
					t.Errorf("got %+v, want %+v", got, want)
					return
				}
				got.Matches[0].Product = "caller changed result"
				got.Matches[0].Fingerprints[0].Evidence = 42
				if engine.Digest() != digest {
					t.Error("source mutation changed the catalogue digest")
					return
				}
				products := engine.Products()
				if !reflect.DeepEqual(products, []string{"fixture"}) {
					t.Errorf("catalogue changed: %v", products)
					return
				}
				products[0] = "caller changed products"
			}
		}()
	}
	workers.Wait()
}

func TestReadCatalogueStrictAndBounded(t *testing.T) {
	for _, input := range []string{
		`null`, `{}`, `[] []`, `[] trailing`, `[`,
		`[{"name":"fixture","unknown":true}]`,
		`[{"name":"fixture","schemas":[{"unknown":true}]}]`,
		`[{"name":"fixture","schemas":[{"fingerprints":[{"type":"Content","pattern":"x","unknown":true}]}]}]`,
	} {
		t.Run(input, func(t *testing.T) {
			if definitions, err := ReadCatalogue(strings.NewReader(input)); err == nil || definitions != nil {
				t.Fatalf("accepted invalid catalogue: %+v, %v", definitions, err)
			}
		})
	}
	if definitions, err := ReadCatalogue(nil); err == nil || definitions != nil {
		t.Fatalf("accepted nil reader: %+v, %v", definitions, err)
	}
	readErr := errors.New("catalogue read failed")
	if definitions, err := ReadCatalogue(iotest.ErrReader(readErr)); !errors.Is(err, readErr) || definitions != nil {
		t.Fatalf("lost reader failure: %+v, %v", definitions, err)
	}
	const limit = 8 << 20
	input := "[" + strings.Repeat(" ", limit-2) + "]"
	if definitions, err := ReadCatalogue(strings.NewReader(input)); err != nil || definitions == nil || len(definitions) != 0 {
		t.Fatalf("rejected valid boundary catalogue: %+v, %v", definitions, err)
	}
	reader := strings.NewReader(input + "  ")
	if definitions, err := ReadCatalogue(reader); err == nil || definitions != nil {
		t.Fatalf("accepted oversized catalogue: %+v, %v", definitions, err)
	}
	if reader.Len() != 1 {
		t.Fatalf("read beyond the one-byte overflow check: %d bytes remain", reader.Len())
	}
}

func TestGenericDetectionPrecedenceAnd404(t *testing.T) {
	normal := Evidence{Role: "Normal", StatusCode: 200, Headers: []Header{{"Server", "origin"}}}
	notFound := Evidence{Role: "Normal", StatusCode: 404, Headers: []Header{{"Server", "origin"}}}
	tests := []struct {
		name     string
		evidence []Evidence
		want     GenericDetection
	}{
		{"body changes alone are not an anomaly", []Evidence{normal, {Role: "Probe", StatusCode: 200, Headers: []Header{{"Server", "origin"}}, Body: []byte("different application page")}}, GenericDetection{}},
		{"ordinary redirect is still only a status anomaly", []Evidence{normal, {Role: "Probe", StatusCode: 302, Headers: []Header{{"Server", "origin"}, {"Location", "/login"}}}}, GenericDetection{Mode: ChangeInStatus, BeforeStatus: 200, AfterStatus: 302, RequestType: "Probe"}},
		{"no baseline", []Evidence{{Role: "Probe", StatusCode: 403}}, GenericDetection{}},
		{"marker without baseline", []Evidence{{Role: "Saved", StatusCode: 200, Headers: []Header{{"X-WAF-Protection", "active"}}}}, GenericDetection{Mode: WAFHeaderDetected, GenericWAFHeader: "X-WAF-Protection", GenericWAFHeaderValue: "active", RequestType: "Saved"}},
		{"marker on baseline repeated value", []Evidence{{Role: "Normal", StatusCode: 200, Headers: []Header{{"X-WAF-Protection", ""}, {"x-waf-protection", "active"}}}}, GenericDetection{Mode: WAFHeaderDetected, GenericWAFHeader: "X-WAF-Protection", GenericWAFHeaderValue: "active", RequestType: "Normal"}},
		{"marker metadata missing", []Evidence{{Role: "Saved", Headers: []Header{{"X-WAF-Protection", "active"}}}}, GenericDetection{}},
		{"empty marker", []Evidence{{Role: "Normal", StatusCode: 200, Headers: []Header{{"X-WAF-Protection", ""}}}}, GenericDetection{}},
		{"later marker precedes earlier difference", []Evidence{normal, {Role: "First", StatusCode: 403}, {Role: "Later", StatusCode: 200, Headers: []Header{{"X-Web-Application-Firewall", "active"}}}}, GenericDetection{Mode: WAFHeaderDetected, GenericWAFHeader: "X-Web-Application-Firewall", GenericWAFHeaderValue: "active", RequestType: "Later"}},
		{"missing probe metadata", []Evidence{normal, {Role: "Probe", TransportError: "failed"}}, GenericDetection{}},
		{"different status 404 skips server change", []Evidence{normal, {Role: "Probe", StatusCode: 404, Headers: []Header{{"Server", "edge"}}}}, GenericDetection{}},
		{"same status 404 detects server change", []Evidence{notFound, {Role: "Probe", StatusCode: 404, Headers: []Header{{"Server", "edge"}}}}, GenericDetection{Mode: ChangeInHeader, BeforeHeader: "origin", AfterHeader: "edge", RequestType: "Probe"}},
		{"generic header precedes 404 exclusion", []Evidence{normal, {Role: "Probe", StatusCode: 404, Headers: []Header{{"x-waf-protection", "active"}}}}, GenericDetection{Mode: WAFHeaderDetected, GenericWAFHeader: "X-WAF-Protection", GenericWAFHeaderValue: "active", RequestType: "Probe"}},
		{"status precedes server change", []Evidence{normal, {Role: "Probe", StatusCode: 403, Headers: []Header{{"Server", "edge"}}}}, GenericDetection{Mode: ChangeInStatus, BeforeStatus: 200, AfterStatus: 403, RequestType: "Probe"}},
		{"metadata survives body error", []Evidence{normal, {Role: "Probe", StatusCode: 200, Headers: []Header{{"Server", "edge"}}, TransportError: "read failed"}}, GenericDetection{Mode: ChangeInHeader, BeforeHeader: "origin", AfterHeader: "edge", RequestType: "Probe"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenericDetect(tt.evidence)
			got.Reason = ""
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestCatalogueDigestCanonicalSource(t *testing.T) {
	const canonical = `[{"name":"fixture","schemas":[{"fingerprints":[{"type":"Content","pattern":"marker"}]}]}]`
	const reordered = ` [ { "schemas": [ { "fingerprints": [ { "pattern": "marker", "attack": false, "type": "Content" } ], "any": false } ], "name": "fixture" } ] `
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(canonical)))
	for _, input := range []string{canonical, reordered} {
		definitions, err := ReadCatalogue(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		engine, err := Compile(definitions)
		if err != nil {
			t.Fatal(err)
		}
		if got := engine.Digest(); got != want {
			t.Fatalf("canonical digest %q, want %q", got, want)
		}
		definitions[0].Schemas[0].FingerPrints[0].Attack = true
		changed, err := Compile(definitions)
		if err != nil {
			t.Fatal(err)
		}
		if changed.Digest() == want || engine.Digest() != want {
			t.Fatal("source metadata must change a new digest, not an existing engine")
		}
	}
}

func TestGenericDetectionJSONAndSafeReason(t *testing.T) {
	for mode, want := range map[GenericDetectionMode]string{
		"": "", ChangeInHeader: "change_in_header", ChangeInStatus: "change_in_status",
		WAFHeaderDetected: "waf_header_detected", "invalid\n\x1b": "invalid\n\x1b",
	} {
		label := mode.String()
		if strings.ContainsAny(label, "\r\n\x1b") {
			t.Fatalf("mode label contains terminal controls: %q", label)
		}
		encoded, err := json.Marshal(GenericDetection{Mode: mode})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if fields["mode"] != want {
			t.Fatalf("mode must serialize as a stable string: %s", encoded)
		}
	}
	const unsafe = "quoted\"\n\x1b[31m"
	for _, detection := range []GenericDetection{
		{Mode: ChangeInHeader, BeforeHeader: unsafe, AfterHeader: unsafe, RequestType: unsafe},
		{Mode: ChangeInStatus, BeforeStatus: 200, AfterStatus: 403, RequestType: unsafe},
		{Mode: WAFHeaderDetected, GenericWAFHeader: "X-WAF-Protection", GenericWAFHeaderValue: unsafe, RequestType: unsafe},
	} {
		detection.generateReason()
		if strings.ContainsAny(detection.Reason, "\r\n\x1b") || !strings.Contains(detection.Reason, fmt.Sprintf("%q", unsafe)) {
			t.Fatalf("reason must safely quote captured values: %q", detection.Reason)
		}
		encoded, err := json.Marshal(detection)
		if err != nil {
			t.Fatal(err)
		}
		var decoded GenericDetection
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded != detection {
			t.Fatalf("generic structured reason did not round trip: %+v, %v", decoded, err)
		}
		var fields map[string]any
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatal(err)
		}
		if fields["request_type"] != unsafe || fields["reason"] != detection.Reason {
			t.Fatalf("missing snake_case reason fields: %s", encoded)
		}
		switch detection.Mode {
		case ChangeInHeader:
			if fields["before_header"] != unsafe || fields["after_header"] != unsafe {
				t.Fatalf("missing header-change fields: %s", encoded)
			}
		case ChangeInStatus:
			if fields["before_status"] != float64(200) || fields["after_status"] != float64(403) {
				t.Fatalf("missing status-change fields: %s", encoded)
			}
		case WAFHeaderDetected:
			if fields["generic_waf_header"] != "X-WAF-Protection" || fields["generic_waf_header_value"] != unsafe {
				t.Fatalf("missing marker fields: %s", encoded)
			}
		}
	}
}
