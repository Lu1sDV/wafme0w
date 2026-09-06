package wafme0w

// Evidence is one captured response, not a request to perform. A zero status
// means response metadata is unavailable. A transport error may coexist with
// usable headers; BodyTruncated, ErrorCode or TransportError makes body evidence incomplete.
type Evidence struct {
	Role           string   `json:"role"`
	RequestURL     string   `json:"request_url,omitempty"`
	EffectiveURL   string   `json:"effective_url,omitempty"`
	RedirectChain  []string `json:"redirect_chain,omitempty"`
	StatusCode     int      `json:"status_code"`
	Reason         string   `json:"reason"`
	Headers        []Header `json:"headers,omitempty"`
	Body           []byte   `json:"body,omitempty"`
	BodyTruncated  bool     `json:"body_truncated,omitempty"`
	ErrorCode      string   `json:"error_code,omitempty"`
	TransportError string   `json:"transport_error,omitempty"`
}

// EvidenceSummary references an observation without retaining headers or bodies.
type EvidenceSummary struct {
	Index         int      `json:"index"`
	Role          string   `json:"role"`
	RequestURL    string   `json:"request_url,omitempty"`
	EffectiveURL  string   `json:"effective_url,omitempty"`
	RedirectChain []string `json:"redirect_chain,omitempty"`
	StatusCode    int      `json:"status_code"`
	BodyTruncated bool     `json:"body_truncated,omitempty"`
	ErrorCode     string   `json:"error_code,omitempty"`
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
