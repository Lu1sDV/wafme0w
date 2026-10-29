package wafme0w

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
)

var defaultHeaders = map[string]string{
	"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
	"Accept-Encoding":           "gzip, deflate",
	"Accept-Language":           "en-US,en;q=0.9",
	"DNT":                       "1", // Do Not Track request header
	"User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36",
	"Upgrade-Insecure-Requests": "1",
	"Referer":                   "https://www.google.com/",
}

func requestURL(options requestOpts) (string, error) {
	u, err := httputil.ParseURI(options.Target)
	if err != nil {
		return "", err
	}
	if options.Path != "" {
		escaped := u.EscapedPath()
		if !strings.HasSuffix(escaped, "/") {
			escaped += "/"
		}
		escaped += strings.TrimPrefix(options.Path, "/")
		path, err := url.PathUnescape(escaped)
		if err != nil {
			return "", err
		}
		u.Path, u.RawPath = path, escaped
	}
	if len(options.Params) != 0 {
		params := make(url.Values, len(options.Params))
		for name, value := range options.Params {
			params.Add(name, value)
		}
		if u.RawQuery != "" {
			u.RawQuery += "&"
		}
		u.RawQuery += params.Encode()
	}
	return u.String(), nil
}

// sendHTTP retains response metadata and partial decoded content on failures.
// HTTP deflate requires zlib framing; raw DEFLATE is deliberately not guessed.
// Unsupported or stacked codings are unavailable evidence, not ciphertext misses.
func sendHTTP(ctx context.Context, options requestOpts, client *http.Client, maxBodyBytes int64) (evidence Evidence, err error) {
	evidence.Role = options.Type
	trace := &requestTrace{}
	budget := options.evidenceBudget
	if budget == nil {
		budget = &httpEvidenceBudget{remaining: DefaultMaxTargetEvidenceBytes, maxHeader: DefaultMaxResponseHeaderBytes}
	}
	metadataRetained := false
	defer func() {
		if !metadataRetained {
			applyRequestTrace(&evidence, trace)
			if !budget.retainMetadata(&evidence, nil) {
				err = &acquisitionError{"evidence_budget", "per-target retained HTTP evidence byte budget exhausted"}
			}
		}
		if err != nil {
			message := err.Error()
			evidence.TransportError = strings.Clone(message[:min(len(message), 1024)])
			if evidence.ErrorCode == "" {
				evidence.ErrorCode = acquisitionCode(err)
			}
		}
	}()
	endPoint, err := requestURL(options)
	if err != nil {
		evidence.ErrorCode = "invalid_target"
		return evidence, fmt.Errorf("create endpoint: %w", err)
	}
	evidence.RequestURL = endPoint
	if maxBodyBytes <= 0 {
		return evidence, fmt.Errorf("decoded body limit must be positive")
	}
	req, err := http.NewRequestWithContext(context.WithValue(ctx, requestTraceKey{}, trace), options.Method, endPoint, options.PostBody)
	if err != nil {
		evidence.ErrorCode = "invalid_request"
		return evidence, fmt.Errorf("create request: %w", err)
	}
	for header, value := range options.Headers {
		req.Header.Set(header, value)
	}
	for _, header := range options.ExtraHeaders {
		if strings.EqualFold(header.Name, "Host") {
			req.Host = header.Value
		} else {
			req.Header.Set(header.Name, header.Value)
		}
	}
	resp, err := client.Do(req)
	// net/http returns nil on a failed later hop. Keep the last response's
	// metadata, whose body the redirect machinery has already closed.
	if resp == nil && err != nil {
		resp = trace.response
	}
	if resp != nil {
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		if !responseHeadersWithinLimit(resp, budget.maxHeader) {
			evidence.ErrorCode = "response_header_limit"
			return evidence, &acquisitionError{"response_header_limit", "response headers exceed configured byte limit"}
		}
		evidence.StatusCode = resp.StatusCode
		evidence.Reason = strings.TrimSpace(strings.TrimPrefix(resp.Status, strconv.Itoa(resp.StatusCode)))
		evidence.EffectiveURL = endPoint
		if resp.Request != nil && resp.Request.URL != nil {
			evidence.EffectiveURL = resp.Request.URL.String()
		} else if len(trace.urls) != 0 {
			evidence.EffectiveURL = trace.urls[len(trace.urls)-1]
		}
		applyRequestTrace(&evidence, trace)
		metadataRetained = true
		if !budget.retainMetadata(&evidence, resp.Header) {
			return evidence, &acquisitionError{"evidence_budget", "per-target retained HTTP evidence byte budget exhausted"}
		}
		evidence.Reason = strings.Clone(evidence.Reason)
		headerCount := 0
		for _, values := range resp.Header {
			headerCount += len(values)
		}
		evidence.Headers = make([]Header, 0, headerCount)
		names := make([]string, 0, len(resp.Header))
		for name := range resp.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, value := range resp.Header[name] {
				evidence.Headers = append(evidence.Headers, Header{Name: strings.Clone(name), Value: strings.Clone(value)})
			}
		}
	}
	if err != nil {
		return evidence, fmt.Errorf("send request: %w", err)
	}
	var reader io.Reader = resp.Body
	coding := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch coding {
	case "", "identity":
	case "gzip":
		decoded, decodeErr := gzip.NewReader(resp.Body)
		if decodeErr != nil {
			evidence.ErrorCode = "body_decode"
			return evidence, fmt.Errorf("decode gzip body: %w", decodeErr)
		}
		defer decoded.Close()
		reader = decoded
	case "deflate":
		decoded, decodeErr := zlib.NewReader(resp.Body)
		if decodeErr != nil {
			evidence.ErrorCode = "body_decode"
			return evidence, fmt.Errorf("decode deflate body: %w", decodeErr)
		}
		defer decoded.Close()
		reader = decoded
	default:
		evidence.ErrorCode = "unsupported_content_encoding"
		return evidence, fmt.Errorf("unsupported content encoding %q", coding)
	}
	defer finishBody(&evidence)
	limited := &retainedBodyReader{reader: reader, budget: budget}
	bodyReader := io.LimitReader(limited, maxBodyBytes)
	if (coding == "" || coding == "identity") && resp.ContentLength > bytes.MinRead && maxBodyBytes > bytes.MinRead {
		// Content-Length is only a bounded capacity hint, never an EOF or
		// admission decision. Leave room for ReadFrom's final EOF read.
		hint := min(resp.ContentLength, maxBodyBytes, 32<<10)
		buffer := bytes.NewBuffer(make([]byte, 0, int(hint)+bytes.MinRead))
		_, err = buffer.ReadFrom(bodyReader)
		evidence.Body = buffer.Bytes()
	} else {
		evidence.Body, err = io.ReadAll(bodyReader)
	}
	if err != nil {
		evidence.ErrorCode = "body_read"
		if acquisitionCode(err) == "evidence_budget" {
			evidence.ErrorCode, evidence.BodyTruncated = "evidence_budget", true
		}
		return evidence, fmt.Errorf("read decoded body: %w", err)
	}
	// Probe one decoded byte without retaining it to distinguish an exact fit.
	var extra [1]byte
	n, readErr := io.ReadFull(reader, extra[:])
	evidence.BodyTruncated = n != 0
	if readErr != nil && readErr != io.EOF {
		evidence.ErrorCode = "body_read"
		return evidence, fmt.Errorf("read decoded body: %w", readErr)
	}
	return evidence, nil
}

func applyRequestTrace(evidence *Evidence, trace *requestTrace) {
	if len(trace.urls) == 0 {
		return
	}
	if evidence.EffectiveURL == "" {
		evidence.EffectiveURL = trace.urls[len(trace.urls)-1]
	}
	if len(trace.urls) > 1 {
		evidence.RedirectChain = make([]string, len(trace.urls)-1)
		copy(evidence.RedirectChain, trace.urls[1:])
	}
}

type retainedBodyReader struct {
	reader io.Reader
	budget *httpEvidenceBudget
}

func (r *retainedBodyReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	retained := r.budget.retainBody(int64(n))
	if retained < int64(n) {
		return int(retained), &acquisitionError{"evidence_budget", "per-target retained HTTP evidence byte budget exhausted"}
	}
	return n, err
}
