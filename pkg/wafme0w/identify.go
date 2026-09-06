package wafme0w

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type WAF struct {
	Name    string   `json:"name"`
	Schemas []Scheme `json:"schemas"`
}

type Scheme struct {
	FingerPrints []FingerPrint `json:"fingerprints,omitempty"`
	Any          bool          `json:"any,omitempty"`
}

type FingerPrint struct {
	Type        string `json:"type,omitempty"`
	HeaderKey   string `json:"header_key,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Attack      bool   `json:"attack,omitempty"` // Metadata, not a response-role constraint.
}

type compiledSchema struct {
	any          bool
	fingerprints []fingerprintMatcher
}

type compiledWAF struct {
	name    string
	schemas []compiledSchema
}

// Engine owns its compiled rules and is safe for concurrent classification.
// Mutating definitions after Compile cannot change an engine.
type Engine struct {
	wafs            []compiledWAF
	digest          string
	needsBody       bool
	needsCookies    bool
	needsFoldedBody bool
	filterBody      bool
}

// ReadCatalogue decodes one JSON array, rejecting unknown fields and inputs
// larger than 8 MiB. The caller retains ownership of the reader.
func ReadCatalogue(reader io.Reader) ([]WAF, error) {
	if reader == nil {
		return nil, fmt.Errorf("nil catalogue reader")
	}
	const limit = 8 << 20
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read catalogue: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("catalogue exceeds %d bytes", limit)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var definitions []WAF
	if err := decoder.Decode(&definitions); err != nil {
		return nil, fmt.Errorf("decode catalogue: %w", err)
	}
	if definitions == nil {
		return nil, fmt.Errorf("catalogue must be a JSON array")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("catalogue must contain exactly one JSON array")
	}
	return definitions, nil
}

// Compile validates every rule before publishing an independently owned engine.
func Compile(definitions []WAF) (*Engine, error) {
	engine := &Engine{wafs: make([]compiledWAF, len(definitions))}
	names := make(map[string]bool, len(definitions))
	filterableBodies := 0
	for wi, waf := range definitions {
		if strings.TrimSpace(waf.Name) == "" || names[waf.Name] {
			return nil, fmt.Errorf("WAF %q: empty or duplicate name", waf.Name)
		}
		names[waf.Name] = true
		if len(waf.Schemas) == 0 {
			return nil, fmt.Errorf("WAF %q: no schemas", waf.Name)
		}
		compiled := compiledWAF{name: waf.Name, schemas: make([]compiledSchema, len(waf.Schemas))}
		for si, schema := range waf.Schemas {
			if len(schema.FingerPrints) == 0 {
				return nil, fmt.Errorf("WAF %q schema %d: no fingerprints", waf.Name, si+1)
			}
			compiledSchema := compiledSchema{any: schema.Any, fingerprints: make([]fingerprintMatcher, len(schema.FingerPrints))}
			for fi, fp := range schema.FingerPrints {
				matcher, err := compileFingerprint(fp)
				if err != nil {
					return nil, fmt.Errorf("WAF %q schema %d fingerprint %d: %w", waf.Name, si+1, fi+1, err)
				}
				compiledSchema.fingerprints[fi] = *matcher
				engine.needsBody = engine.needsBody || fp.Type == "Content"
				engine.needsCookies = engine.needsCookies || fp.Type == "Cookie"
				if fp.Type == "Content" && (matcher.regex == nil && matcher.fold || len(matcher.required) > 0) {
					engine.needsFoldedBody = true
				}
				if matcher.mask != [4]uint64{} {
					filterableBodies++
				}
			}
			compiled.schemas[si] = compiledSchema
		}
		engine.wafs[wi] = compiled
	}
	// ponytail: amortize the shared filter only across many content searches.
	engine.filterBody = filterableBodies >= 16
	if definitions == nil {
		definitions = []WAF{}
	}
	canonical, err := json.Marshal(definitions)
	if err != nil {
		return nil, fmt.Errorf("encode catalogue: %w", err)
	}
	engine.digest = fmt.Sprintf("%x", sha256.Sum256(canonical))
	return engine, nil
}

// Digest identifies the canonical JSON encoding of the source catalogue.
// Source order and metadata are significant; whitespace and JSON key order are not.
func (e *Engine) Digest() string {
	if e == nil {
		return ""
	}
	return e.digest
}

// Products returns a catalogue-order snapshot, not the engine's internal state.
func (e *Engine) Products() []string {
	products := make([]string, len(e.wafs))
	for i, waf := range e.wafs {
		products[i] = waf.name
	}
	return products
}

type responseData struct {
	metadata      bool
	bodyComplete  bool
	bodyFilter    bool
	allowIndex    bool
	bodyMisses    uint8
	status        int
	reason        string
	headers       http.Header
	body          string
	foldedBody    string
	cookies       []string
	bodyMask      [4]uint64
	bodyQuadgrams *quadgramFilter
}

type verdict uint8

const (
	noMatch verdict = iota
	match
	unknown
)

// Classify evaluates supplied observations only. Fingerprints in an AND schema
// may match different responses. Incomplete evidence uses three-valued logic:
// a known false term settles AND, and a known true term settles OR.
func (e *Engine) Classify(evidence []Evidence) Outcome {
	outcome := Outcome{State: Complete}
	if e == nil {
		return Outcome{State: Failed, Diagnostics: []Diagnostic{{Code: "invalid_engine", Evidence: -1, Message: "nil classifier engine"}}}
	}
	responses := make([]responseData, len(evidence))
	for i, observation := range evidence {
		response := &responses[i]
		response.metadata = observation.StatusCode >= 100 && observation.StatusCode <= 999
		response.bodyComplete = response.metadata && !observation.BodyTruncated && observation.TransportError == "" && observation.ErrorCode == ""
		response.status, response.reason = observation.StatusCode, observation.Reason
		if observation.ErrorCode != "" || observation.TransportError != "" {
			code, message := observation.ErrorCode, observation.TransportError
			if code == "" {
				code = "transport_error"
			}
			if message == "" {
				message = code
			}
			outcome.Diagnostics = append(outcome.Diagnostics, Diagnostic{Code: code, Evidence: i, Message: message})
		}
		if observation.BodyTruncated {
			outcome.Diagnostics = append(outcome.Diagnostics, Diagnostic{Code: "body_truncated", Evidence: i, Message: "response body is incomplete"})
		}
		if !response.metadata {
			if observation.TransportError == "" && observation.ErrorCode == "" {
				outcome.Diagnostics = append(outcome.Diagnostics, Diagnostic{Code: "missing_response", Evidence: i, Message: "response metadata is unavailable or invalid"})
			}
			continue
		}
		if len(observation.Headers) != 0 {
			response.headers = make(http.Header, len(observation.Headers))
			for _, header := range observation.Headers {
				response.headers.Add(header.Name, header.Value)
			}
		}
		if e.needsBody && response.bodyComplete {
			response.body = string(observation.Body)
			if e.needsFoldedBody {
				response.foldedBody = foldText(response.body)
				if e.filterBody {
					response.allowIndex = true
					response.bodyMask = contentMask(response.foldedBody)
					if response.bodyMask[0]&response.bodyMask[1]&response.bodyMask[2]&response.bodyMask[3] != ^uint64(0) {
						response.bodyFilter = true
					}
				}
			}
		}
		if e.needsCookies {
			for _, cookie := range (&http.Response{Header: response.headers}).Cookies() {
				response.cookies = append(response.cookies, cookie.String())
			}
		}
	}
	if len(evidence) == 0 {
		outcome.Diagnostics = append(outcome.Diagnostics, Diagnostic{Code: "missing_response", Evidence: -1, Message: "no response evidence supplied"})
	}
	for _, waf := range e.wafs {
		result := noMatch
		for si, schema := range waf.schemas {
			current := schema.evaluate(responses)
			if current == match {
				outcome.Matches = append(outcome.Matches, Match{Product: waf.name, Schema: si + 1, Fingerprints: schema.witnesses(responses)})
				result = match
				break
			}
			if current == unknown {
				result = unknown
			}
		}
		if result == unknown {
			outcome.State = Incomplete
			outcome.IncompleteProducts = append(outcome.IncompleteProducts, waf.name)
		}
	}
	return outcome
}

func (s compiledSchema) evaluate(responses []responseData) verdict {
	result := match
	if s.any {
		result = noMatch
	}
	for i := range s.fingerprints {
		current, _ := s.fingerprints[i].evaluate(responses)
		if s.any && current == match || !s.any && current == noMatch {
			return current
		}
		if current == unknown {
			result = unknown
		}
	}
	return result
}

// Gather witnesses only after a schema matches, keeping negative paths allocation-free.
func (s compiledSchema) witnesses(responses []responseData) []FingerprintMatch {
	count := len(s.fingerprints)
	if s.any {
		count = 1
	}
	witnesses := make([]FingerprintMatch, 0, count)
	for fi := range s.fingerprints {
		if current, ei := s.fingerprints[fi].evaluate(responses); current == match {
			witnesses = append(witnesses, FingerprintMatch{Fingerprint: fi + 1, Evidence: ei})
			if s.any {
				break
			}
		}
	}
	return witnesses
}

func (m *fingerprintMatcher) evaluate(responses []responseData) (verdict, int) {
	result := noMatch
	if len(responses) == 0 {
		return unknown, -1
	}
	for ei := range responses {
		response := &responses[ei]
		if !response.metadata || m.typ == "Content" && !response.bodyComplete {
			result = unknown
			continue
		}
		switch m.typ {
		case "Cookie":
			for _, cookie := range response.cookies {
				if m.match(cookie) {
					return match, ei
				}
			}
		case "Header":
			for _, value := range response.headers[m.header] {
				if m.match(value) {
					return match, ei
				}
			}
		case "Content":
			if m.matchBody(response) {
				return match, ei
			}
		case "Status":
			if response.status == m.status {
				return match, ei
			}
		case "Reason":
			if m.match(response.reason) {
				return match, ei
			}
		}
	}
	return result, -1
}

// GenericDetect reports response anomalies separately from product matches.
// It does not establish that a firewall exists or that a request was blocked.
func GenericDetect(evidence []Evidence) GenericDetection {
	var normal *Evidence
	// Marker presence is independent of a baseline or response differences.
	for i := range evidence {
		response := &evidence[i]
		if response.StatusCode < 100 || response.StatusCode > 999 {
			continue
		}
		if normal == nil && response.Role == "Normal" {
			normal = response
		}
		for _, name := range genericWAFHeaders {
			if value := evidenceHeader(response.Headers, name); value != "" {
				detection := GenericDetection{Mode: WAFHeaderDetected, GenericWAFHeader: name, GenericWAFHeaderValue: value, RequestType: response.Role}
				detection.generateReason()
				return detection
			}
		}
	}
	if normal == nil {
		return GenericDetection{}
	}
	normalServer := evidenceHeader(normal.Headers, "Server")
	for _, response := range evidence {
		if response.Role == "Normal" || response.StatusCode < 100 || response.StatusCode > 999 {
			continue
		}
		var detection GenericDetection
		if normal.StatusCode != response.StatusCode {
			if response.StatusCode == 404 {
				continue
			}
			detection = GenericDetection{Mode: ChangeInStatus, BeforeStatus: normal.StatusCode, AfterStatus: response.StatusCode, RequestType: response.Role}
		} else if server := evidenceHeader(response.Headers, "Server"); normalServer != server {
			detection = GenericDetection{Mode: ChangeInHeader, BeforeHeader: normalServer, AfterHeader: server, RequestType: response.Role}
		}
		if detection.Mode != "" {
			detection.generateReason()
			return detection
		}
	}
	return GenericDetection{}
}

func evidenceHeader(headers []Header, name string) string {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) && header.Value != "" {
			return header.Value
		}
	}
	return ""
}
