package wafme0w

import (
	"bytes"
	"encoding/json"
	"net/http"
	"sync"
)

// Evidence is one captured response, not a request to perform. With nil
// Availability, a valid status makes metadata usable and an error or
// BodyTruncated makes the body incomplete, preserving legacy interpretation.
// Explicit Availability describes each channel independently. Incomplete
// headers contain faithful whole values, never truncated or lossy values.
type Evidence struct {
	Role           string                `json:"role"`
	RequestURL     string                `json:"request_url,omitempty"`
	EffectiveURL   string                `json:"effective_url,omitempty"`
	RedirectChain  []string              `json:"redirect_chain,omitempty"`
	StatusCode     int                   `json:"status_code"`
	Reason         string                `json:"reason"`
	Headers        []Header              `json:"headers,omitempty"`
	Body           []byte                `json:"body,omitempty"`
	BodyTruncated  bool                  `json:"body_truncated,omitempty"`
	ErrorCode      string                `json:"error_code,omitempty"`
	TransportError string                `json:"transport_error,omitempty"`
	Availability   *EvidenceAvailability `json:"availability,omitempty"`
}

// UnmarshalJSON rejects unknown fields and ambiguous availability members.
// Semantic channel validation remains shared by capture decoding and Classify.
func (e *Evidence) UnmarshalJSON(data []byte) error {
	type evidenceJSON Evidence
	decoded := evidenceJSON(*e)
	fields := struct {
		*evidenceJSON
		Availability availabilityJSON `json:"availability"`
	}{evidenceJSON: &decoded}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return err
	}
	if fields.Availability.seen {
		decoded.Availability = fields.Availability.value
	}
	*e = Evidence(decoded)
	return nil
}

// EvidenceSummary references an observation without retaining headers or bodies.
type EvidenceSummary struct {
	Index         int                   `json:"index"`
	Role          string                `json:"role"`
	RequestURL    string                `json:"request_url,omitempty"`
	EffectiveURL  string                `json:"effective_url,omitempty"`
	RedirectChain []string              `json:"redirect_chain,omitempty"`
	StatusCode    int                   `json:"status_code"`
	BodyTruncated bool                  `json:"body_truncated,omitempty"`
	ErrorCode     string                `json:"error_code,omitempty"`
	Availability  *EvidenceAvailability `json:"availability,omitempty"`
	// BlockedRedirectURL is the resolved Location of a scope-rejected redirect.
	BlockedRedirectURL string `json:"blocked_redirect_url,omitempty"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type EvaluationState string

const (
	Complete   EvaluationState = "complete"
	Incomplete EvaluationState = "incomplete"
	Failed     EvaluationState = "failed"
)

// Match identifies the first satisfied schema (one-based) in the compiled
// catalogue. References describe rules without retaining or copying bodies.
type Match struct {
	Product      string             `json:"product"`
	Schema       int                `json:"schema"`
	Fingerprints []FingerprintMatch `json:"fingerprints"`
}

// FingerprintMatch names a one-based fingerprint within the matched schema and
// its first supporting zero-based evidence index.
type FingerprintMatch struct {
	Fingerprint int `json:"fingerprint"`
	Evidence    int `json:"evidence"`
}

// Diagnostic.Evidence is a zero-based observation index, or -1 for a run error.
type Diagnostic struct {
	Code     string `json:"code"`
	Evidence int    `json:"evidence"`
	Message  string `json:"message"`
}

type Outcome struct {
	State              EvaluationState `json:"state"`
	Matches            []Match         `json:"matches,omitempty"`
	IncompleteProducts []string        `json:"incomplete_products,omitempty"`
	Diagnostics        []Diagnostic    `json:"diagnostics,omitempty"`
}

// One budget is shared by a target's concurrent fast probes. Charge actual
// decoded bytes, not an upfront reservation that could starve tiny responses.
type httpEvidenceBudget struct {
	mu        sync.Mutex
	remaining int64
	maxHeader int64
}

func (b *httpEvidenceBudget) retainMetadata(evidence *Evidence, headers http.Header) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.remaining
	take := func(n int64) bool {
		if n > remaining {
			return false
		}
		remaining -= n
		return true
	}
	fits := take(int64(len(evidence.RequestURL))) && take(int64(len(evidence.EffectiveURL))) && take(int64(len(evidence.Reason)))
	for _, destination := range evidence.RedirectChain {
		fits = fits && take(16) && take(int64(len(destination)))
	}
	for name, values := range headers {
		for _, value := range values {
			fits = fits && take(32) && take(int64(len(name))) && take(int64(len(value)))
		}
	}
	if !fits {
		*evidence = Evidence{Role: evidence.Role}
		return false
	}
	b.remaining = remaining
	return true
}

func (b *httpEvidenceBudget) retainBody(bytes int64) int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	retained := min(bytes, b.remaining)
	b.remaining -= retained
	return retained
}

func finishBody(evidence *Evidence) {
	if len(evidence.Body) == 0 {
		evidence.Body = nil
		return
	}
	if cap(evidence.Body) == len(evidence.Body) {
		return
	}
	// Spare capacity must not exclude a later probe's actual evidence.
	// The body budget has already charged every retained byte.
	body := make([]byte, len(evidence.Body))
	copy(body, evidence.Body)
	evidence.Body = body
}
