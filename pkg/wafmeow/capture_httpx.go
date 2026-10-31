package wafmeow

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/internal/httpmeta"
)

// HTTPXResponseEncoding declares serialization of httpx raw_header and body.
// It does not describe charset decoding or establish response completeness.
type HTTPXResponseEncoding string

const (
	HTTPXText   HTTPXResponseEncoding = "text"
	HTTPXBase64 HTTPXResponseEncoding = "base64"
)

// HTTPXImportOptions selects a pinned httpx-v1.12.0 compatibility profile.
// Empty ResponseEncoding means text; encoding is never guessed.
type HTTPXImportOptions struct {
	ResponseEncoding HTTPXResponseEncoding
}

// ImportProvenance records attribution and representation limitations, not a
// claim about the actual producer version. Occurrence is local to this stream.
type ImportProvenance struct {
	Format               string                `json:"format"`
	AdapterRevision      string                `json:"adapter_revision"`
	Profile              string                `json:"profile"`
	ResponseEncoding     HTTPXResponseEncoding `json:"response_encoding"`
	Occurrence           int                   `json:"occurrence"`
	InputLine            int                   `json:"input_line"`
	OriginalInput        string                `json:"original_input,omitempty"`
	SourceTimestamp      string                `json:"source_timestamp,omitempty"`
	TimestampMeaning     string                `json:"timestamp_meaning,omitempty"`
	HeaderRepresentation string                `json:"header_representation,omitempty"`
	Limitations          []string              `json:"limitations"`
	UpstreamFailed       bool                  `json:"upstream_failed,omitempty"`
	UpstreamError        string                `json:"upstream_error,omitempty"`
}

// RunHTTPXCaptured classifies one independent Normal observation per nonblank
// JSONL object, in input order, without fetching URLs or opening source paths.
// Readers and callbacks have the same ownership and cancellation as RunCaptured.
// Malformed records stop the stream; already emitted results remain emitted.
func RunHTTPXCaptured(ctx context.Context, engine *Engine, inputs io.Reader, config Config, options HTTPXImportOptions, emit func(Result) error) error {
	if ctx == nil || engine == nil || inputs == nil || emit == nil {
		return errors.New("context, engine, inputs, and result callback are required")
	}
	encoding := options.ResponseEncoding
	if encoding == "" {
		encoding = HTTPXText
	}
	if encoding != HTTPXText && encoding != HTTPXBase64 {
		return errors.New("httpx response encoding must be text or base64")
	}
	return runCaptured(ctx, engine, inputs, config, func(record []byte, config Config, line, occurrence int) (decodedCapture, error) {
		return decodeHTTPXCapture(record, config, encoding, line, occurrence)
	}, emit)
}

type httpxRecord struct {
	url, input, finalURL, timestamp       *string
	rawHeader, body, preview, sourceError *string
	status                                *int
	failed                                *bool
	hasNormalizedHeaders                  bool
}

// Only consumed fields are retained. Unknown values are traversed without
// constructing maps, slices, or an upstream object that could escape decoding.
func parseHTTPXRecord(record []byte) (httpxRecord, error) {
	var result httpxRecord
	decoder := json.NewDecoder(bytes.NewReader(record))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return result, err
	}
	if token != json.Delim('{') {
		return result, errors.New("httpx record must be a JSON object")
	}
	var seen uint16
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return result, err
		}
		key, ok := token.(string)
		if !ok {
			return result, errors.New("invalid object key")
		}
		index := -1
		var destination any
		switch key {
		case "url":
			index, destination = 0, &result.url
		case "input":
			index, destination = 1, &result.input
		case "final_url":
			index, destination = 2, &result.finalURL
		case "timestamp":
			index, destination = 3, &result.timestamp
		case "status_code":
			index, destination = 4, &result.status
		case "raw_header":
			index, destination = 5, &result.rawHeader
		case "header":
			index = 6
		case "body":
			index, destination = 7, &result.body
		case "body_preview":
			index, destination = 8, &result.preview
		case "failed":
			index, destination = 9, &result.failed
		case "error":
			index, destination = 10, &result.sourceError
		}
		if index < 0 {
			if err := skipHTTPXValue(decoder); err != nil {
				return result, err
			}
			continue
		}
		bit := uint16(1) << index
		if seen&bit != 0 {
			return result, fmt.Errorf("duplicate consumed httpx field %q", key)
		}
		seen |= bit
		if key == "header" {
			present, err := validateHTTPXNormalizedHeader(decoder)
			if err != nil {
				return result, fmt.Errorf("httpx header: %w", err)
			}
			result.hasNormalizedHeaders = present
		} else if err := decoder.Decode(destination); err != nil {
			return result, fmt.Errorf("httpx field %q: %w", key, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return result, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return result, errors.New("httpx line must contain exactly one JSON object")
	}
	return result, nil
}

func skipHTTPXValue(decoder *json.Decoder) error {
	// Depth is tracked iteratively: hostile nested unknown fields do not grow a
	// recursive Go call stack. encoding/json enforces its own nesting bound.
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

func validateHTTPXNormalizedHeader(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if token == nil {
		return false, nil
	}
	if token != json.Delim('{') {
		return false, errors.New("must be an object of string values or null")
	}
	for decoder.More() {
		if _, err := decoder.Token(); err != nil {
			return false, err
		}
		token, err := decoder.Token()
		if err != nil {
			return false, err
		}
		if _, ok := token.(string); !ok {
			return false, errors.New("normalized header values must be strings")
		}
	}
	_, err = decoder.Token()
	return true, err
}

type httpxDiagnostics struct {
	entries  []Diagnostic
	overflow bool
}

func (d *httpxDiagnostics) add(category, message string) {
	code := "import_httpx_" + category
	for _, existing := range d.entries {
		if existing.Code == code {
			return
		}
	}
	if len(d.entries) == 8 {
		d.overflow = true
		return
	}
	if len(message) > 1024 {
		message = message[:1024]
	}
	d.entries = append(d.entries, Diagnostic{Code: code, Evidence: 0, Message: message})
}

func (d *httpxDiagnostics) finish() []Diagnostic {
	if d.overflow {
		d.entries[7] = Diagnostic{Code: "import_httpx_additional_limitations", Evidence: 0, Message: "Additional import limitations were omitted from the bounded diagnostic list."}
	}
	return d.entries
}

type httpxBudget struct{ remaining int64 }

func (b *httpxBudget) take(n int64) bool {
	if n > b.remaining {
		return false
	}
	b.remaining -= n
	return true
}

func httpxStringBytes(value string) int64 {
	if value == "" {
		return 0
	}
	return int64(len(value)) + 16
}

func validateHTTPXIdentity(value, field string) error {
	if value == "" || len(value) >= bufio.MaxScanTokenSize || strings.TrimSpace(value) != value {
		return fmt.Errorf("httpx %s requires an absolute HTTP(S) URL shorter than 64 KiB", field)
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("httpx %s: %w", field, err)
	}
	// Offline attribution is not request eligibility: retain producer fragments,
	// userinfo and Unicode hosts without relaxing the live acquisition validator.
	if (!strings.EqualFold(parsed.Scheme, "http") && !strings.EqualFold(parsed.Scheme, "https")) ||
		parsed.Opaque != "" || parsed.Hostname() == "" {
		return fmt.Errorf("httpx %s requires an absolute HTTP(S) URL shorter than 64 KiB", field)
	}
	return nil
}

func decodeHTTPXCapture(record []byte, config Config, encoding HTTPXResponseEncoding, line, occurrence int) (decodedCapture, error) {
	source, err := parseHTTPXRecord(record)
	if err != nil {
		return decodedCapture{}, err
	}
	metadata := &ImportProvenance{
		Format: "httpx", AdapterRevision: "httpx-v1.12.0", Profile: "httpx-v1.12.0",
		ResponseEncoding: encoding, Occurrence: occurrence, InputLine: line,
		Limitations: []string{"reconstructed_headers", "reason_unavailable", "body_completeness_unverified"},
	}
	metadata.UpstreamFailed = source.failed != nil && *source.failed || source.sourceError != nil && *source.sourceError != ""
	evidence := Evidence{Role: "Normal", Availability: &EvidenceAvailability{Status: ChannelUnavailable, Headers: ChannelUnavailable, Reason: ChannelUnavailable, Body: ChannelUnavailable}}
	var diagnostics httpxDiagnostics
	diagnostics.add("limitations", "httpx-v1.12.0 profile: reason unavailable; reconstructed headers can support positives only; exported body completeness is unverified.")
	var target string
	if source.url != nil && *source.url != "" {
		if err := validateHTTPXIdentity(*source.url, "url"); err != nil {
			return decodedCapture{}, err
		}
		target, evidence.RequestURL = *source.url, *source.url
	} else if metadata.UpstreamFailed && source.input != nil && strings.TrimSpace(*source.input) != "" && len(*source.input) < bufio.MaxScanTokenSize {
		target = *source.input
	} else {
		return decodedCapture{}, errors.New("httpx response requires url; a failed record may instead supply a nonempty input label shorter than 64 KiB")
	}
	if source.finalURL != nil && *source.finalURL != "" {
		if err := validateHTTPXIdentity(*source.finalURL, "final_url"); err != nil {
			return decodedCapture{}, err
		}
		evidence.EffectiveURL = *source.finalURL
	}
	budget := httpxBudget{config.MaxTargetEvidenceBytes}
	if !budget.take(httpxStringBytes(target) + httpxStringBytes(evidence.RequestURL) + httpxStringBytes(evidence.EffectiveURL)) {
		return decodedCapture{}, errors.New("httpx mandatory attribution identities exceed retained evidence budget")
	}
	if source.status != nil && *source.status != 0 {
		if *source.status >= 100 && *source.status <= 999 {
			evidence.StatusCode, evidence.Availability.Status = *source.status, ChannelComplete
		} else {
			diagnostics.add("status", "Invalid top-level status_code discarded; status unavailable.")
		}
	}
	if source.rawHeader != nil && *source.rawHeader != "" {
		metadata.HeaderRepresentation = "reconstructed"
		dump, overflow, decodeErr := httpxChannelBytes(*source.rawHeader, encoding, config.MaxResponseHeaderBytes)
		if decodeErr != nil {
			diagnostics.add("headers", "Invalid declared raw_header encoding; header channel discarded.")
		} else {
			dumpStatus, headers, headerErr := parseHTTPXHeaders(dump, encoding, &diagnostics)
			if dumpStatus != 0 && evidence.StatusCode != 0 && dumpStatus != evidence.StatusCode {
				evidence.StatusCode, evidence.Availability.Status = 0, ChannelUnavailable
				diagnostics.add("status_conflict", "Top-level and reconstructed dump statuses disagree; neither status is usable.")
			}
			if overflow {
				diagnostics.add("headers", "Local decoded raw_header limit exceeded; entire header channel discarded.")
			} else if headerErr != nil {
				diagnostics.add("headers", "Unsupported or malformed reconstructed header dump; entire header channel discarded.")
			} else {
				if evidence.StatusCode == 0 && (source.status == nil || *source.status == 0) {
					evidence.StatusCode, evidence.Availability.Status = dumpStatus, ChannelComplete
				}
				var retained int64
				for _, header := range headers {
					retained += int64(32 + len(header.Name) + len(header.Value))
				}
				if budget.take(retained) {
					evidence.Headers, evidence.Availability.Headers = headers, ChannelIncomplete
				} else {
					diagnostics.add("headers", "Local retained evidence budget discarded the entire header channel.")
				}
			}
		}
	} else if source.hasNormalizedHeaders {
		diagnostics.add("headers", "Normalized-only headers are lossy; header channel unavailable without raw_header.")
	}
	admitMetadata := func(value *string, limit int, field string) string {
		if value == nil || *value == "" {
			return ""
		}
		if len(*value) > limit || !budget.take(httpxStringBytes(*value)) {
			diagnostics.add("metadata_"+field, "Optional source "+field+" omitted due to a local metadata or retained-byte limit.")
			return ""
		}
		return *value
	}
	metadata.OriginalInput = admitMetadata(source.input, 64<<10, "input")
	metadata.SourceTimestamp = admitMetadata(source.timestamp, 128, "timestamp")
	if metadata.SourceTimestamp != "" {
		metadata.TimestampMeaning = "result_construction"
	}
	if source.sourceError != nil && len(*source.sourceError) > 1024 {
		shortened := (*source.sourceError)[:1024-len(" [truncated]")] + " [truncated]"
		source.sourceError = &shortened
		diagnostics.add("metadata_error", "Upstream error text locally shortened to 1024 bytes.")
	}
	metadata.UpstreamError = admitMetadata(source.sourceError, 1024, "error")
	if metadata.UpstreamFailed {
		diagnostics.add("upstream_failure", "Source reported failed:true or nonempty error; independently usable response evidence is retained.")
	}
	if source.body != nil {
		overflow, decodeErr := inspectHTTPXBody(*source.body, encoding, config.MaxBodyBytes)
		if decodeErr != nil {
			diagnostics.add("body", "Invalid or cut declared body encoding; body unavailable.")
		} else if overflow {
			evidence.Availability.Body, evidence.BodyTruncated = ChannelIncomplete, true
			diagnostics.add("body", "Local decoded body limit exceeded; no body bytes retained or matched.")
		} else {
			evidence.Availability.Body = ChannelUnknown
		}
	}
	// No body is retained: every v1.12.0 export lacks the completeness proof
	// required by body matching. Preview and upstream enrichment never qualify.
	capture := Capture{Target: target, Evidence: []Evidence{evidence}}
	return decodedCapture{capture: capture, importMetadata: metadata, diagnostics: diagnostics.finish()}, nil
}

func inspectHTTPXBody(value string, encoding HTTPXResponseEncoding, limit int64) (bool, error) {
	if encoding == HTTPXText {
		return int64(len(value)) > limit, nil
	}
	if err := validateHTTPXBase64Padding(value); err != nil {
		return false, err
	}
	// Count and validate bytes without allocating an unusable body. The record
	// bound independently limits the encoded input.
	decodedBytes, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(value)))
	return decodedBytes > limit, err
}

// NewDecoder can accept separately padded values at internal read boundaries.
// Validate terminal padding for the entire field before streaming either channel.
func validateHTTPXBase64Padding(value string) error {
	if padding := strings.IndexByte(value, '='); padding >= 0 && strings.Trim(value[padding:], "=\r\n") != "" {
		return errors.New("base64 data follows terminal padding")
	}
	return nil
}

// Retain a bounded decoded header prefix; validate its entire declared encoding
// before accepting any field. The record bound independently limits temporaries.
func httpxChannelBytes(value string, encoding HTTPXResponseEncoding, limit int64) (string, bool, error) {
	if encoding == HTTPXText {
		if int64(len(value)) > limit {
			return value[:limit], true, nil
		}
		return value, false, nil
	}
	if err := validateHTTPXBase64Padding(value); err != nil {
		return "", false, err
	}
	decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(value))
	readLimit := min(limit, int64(len(value))) + 1
	bounded, err := io.ReadAll(io.LimitReader(decoder, readLimit))
	if err != nil {
		return "", false, err
	}
	overflow := int64(len(bounded)) > limit
	if overflow {
		if _, err := io.Copy(io.Discard, decoder); err != nil {
			return "", false, err
		}
		bounded = bounded[:limit]
	}
	return string(bounded), overflow, nil
}

func parseHTTPXHeaders(dump string, encoding HTTPXResponseEncoding, diagnostics *httpxDiagnostics) (int, []Header, error) {
	statusLine, rest, ok := strings.Cut(dump, "\n")
	if !ok {
		return 0, nil, errors.New("missing status line terminator")
	}
	statusLine = strings.TrimSuffix(statusLine, "\r")
	protocol, statusText, ok := strings.Cut(statusLine, " ")
	if !ok {
		return 0, nil, errors.New("invalid status line")
	}
	if _, _, ok := http.ParseHTTPVersion(protocol); !ok {
		return 0, nil, errors.New("invalid HTTP version")
	}
	statusWord, _, _ := strings.Cut(statusText, " ")
	status, err := strconv.Atoi(statusWord)
	if err != nil || len(statusWord) != 3 || status < 100 || status > 999 {
		return 0, nil, errors.New("invalid dump status")
	}
	if status >= 100 && status <= 103 {
		return status, nil, errors.New("unsupported informational dump")
	}
	if !strings.HasSuffix(dump, "\r\n\r\n") {
		return status, nil, errors.New("incomplete header block")
	}
	count := 0
	for line := range strings.SplitSeq(rest, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		if line[0] != ' ' && line[0] != '\t' {
			count++
		}
		if count > 4096 {
			return status, nil, errors.New("more than 4096 header values")
		}
	}
	reader := textproto.NewReader(bufio.NewReader(strings.NewReader(rest)))
	fields, err := reader.ReadMIMEHeader()
	if err != nil {
		return status, nil, err
	}
	// DumpResponse(false) can append an empty chunk terminator for a bodyless
	// response (for example 304). This framing is not an additional observation.
	if encodings := fields.Values("Transfer-Encoding"); len(encodings) == 1 && strings.EqualFold(encodings[0], "chunked") {
		if next, _ := reader.R.Peek(1); len(next) == 1 && next[0] == '0' {
			var terminator [5]byte
			if _, err := io.ReadFull(reader.R, terminator[:]); err != nil || string(terminator[:]) != "0\r\n\r\n" {
				return status, nil, errors.New("unsupported reconstructed chunk framing")
			}
		}
	}
	for {
		b, err := reader.R.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status, nil, err
		}
		if b != '\r' && b != '\n' {
			return status, nil, errors.New("trailing material after header block")
		}
	}
	var headers []Header
	for name, values := range fields {
		if !httpmeta.ValidHeaderName(name) {
			return status, nil, errors.New("invalid header name")
		}
		switch strings.ToLower(name) {
		case "content-length", "transfer-encoding", "trailer", "connection":
			continue
		}
		for _, value := range values {
			if !httpmeta.ValidHeaderValue(value) {
				return status, nil, errors.New("invalid header value")
			}
			if encoding == HTTPXText && strings.ContainsRune(value, '\ufffd') {
				diagnostics.add("header_fidelity", "Text header values containing Unicode replacement characters withheld because JSON may have lost original bytes.")
				continue
			}
			headers = append(headers, Header{Name: name, Value: value})
		}
	}
	return status, headers, nil
}
