package wafmeow

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

type bodyTrackingTransport struct{ response *http.Response }

func (t bodyTrackingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return t.response, nil
}

type trackedResponseBody struct {
	io.Reader
	closes int
}

func (b *trackedResponseBody) Close() error { b.closes++; return nil }

type failingResponseReader struct{ err error }

func (r failingResponseReader) Read([]byte) (int, error) { return 0, r.err }

func TestSendRetainsPartialEvidenceAndClosesBody(t *testing.T) {
	const content = "response content"
	var gzipBody, deflateBody bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBody)
	if _, err := io.WriteString(gzipWriter, content); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	deflateWriter := zlib.NewWriter(&deflateBody)
	if _, err := io.WriteString(deflateWriter, content); err != nil {
		t.Fatal(err)
	}
	if err := deflateWriter.Close(); err != nil {
		t.Fatal(err)
	}
	readErr := errors.New("response read failed")
	for _, tc := range []struct {
		name, encoding string
		reader         io.Reader
		wantErr        error
		wantBody       string
	}{
		{name: "plain", reader: strings.NewReader(content), wantBody: content},
		{name: "gzip", encoding: "gzip", reader: bytes.NewReader(gzipBody.Bytes()), wantBody: content},
		{name: "zlib deflate", encoding: "deflate", reader: bytes.NewReader(deflateBody.Bytes()), wantBody: content},
		{name: "invalid gzip", encoding: "gzip", reader: strings.NewReader("not a gzip response"), wantErr: gzip.ErrHeader},
		{name: "truncated gzip", encoding: "gzip", reader: bytes.NewReader(gzipBody.Bytes()[:gzipBody.Len()-4]), wantErr: io.ErrUnexpectedEOF, wantBody: content},
		{name: "reader failure", reader: io.MultiReader(strings.NewReader("partial"), failingResponseReader{err: readErr}), wantErr: readErr, wantBody: "partial"},
		{name: "truncated deflate", encoding: "deflate", reader: bytes.NewReader(deflateBody.Bytes()[:deflateBody.Len()-1]), wantErr: io.ErrUnexpectedEOF, wantBody: content},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedResponseBody{Reader: tc.reader}
			client := &http.Client{Transport: bodyTrackingTransport{response: &http.Response{
				StatusCode: 403, Status: "403 Custom Denial",
				Header: http.Header{"Content-Encoding": {tc.encoding}, "Set-Cookie": {"first=1", "second=2"}}, Body: body,
			}}}
			got, err := sendHTTP(context.Background(), requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid", Type: "Normal"}, client, DefaultMaxBodyBytes)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if body.closes != 1 {
				t.Errorf("body closed %d times", body.closes)
			}
			if got.StatusCode != 403 || got.Reason != "Custom Denial" || got.Role != "Normal" || string(got.Body) != tc.wantBody {
				t.Fatalf("lost partial evidence: %+v", got)
			}
			if (got.TransportError != "") != (tc.wantErr != nil) {
				t.Fatalf("read completeness lost: %+v", got)
			}
			wantHeaders := []Header{{Name: "Content-Encoding", Value: tc.encoding}, {Name: "Set-Cookie", Value: "first=1"}, {Name: "Set-Cookie", Value: "second=2"}}
			if !reflect.DeepEqual(got.Headers, wantHeaders) {
				t.Fatalf("lost repeated headers: %+v", got.Headers)
			}
		})
	}
}

func TestDecodedBodyLimitDistinguishesExactFit(t *testing.T) {
	for _, content := range []string{strings.Repeat("a", 32), strings.Repeat("a", 4096)} {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		if _, err := io.WriteString(writer, content); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		body := &trackedResponseBody{Reader: &compressed}
		client := &http.Client{Transport: bodyTrackingTransport{response: &http.Response{
			StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}, "Server": {"fixture"}}, Body: body,
		}}}
		got, err := sendHTTP(context.Background(), requestOpts{Method: "GET", Target: "http://fixture.invalid"}, client, 32)
		if err != nil {
			t.Fatal(err)
		}
		if string(got.Body) != strings.Repeat("a", 32) || got.BodyTruncated != (len(content) > 32) || got.StatusCode != 200 || len(got.Headers) != 2 {
			t.Fatalf("decoded cap lost data or completeness: %+v", got)
		}
	}
}

func TestCallerCancellationReachesActiveHTTP(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := sendHTTP(ctx, requestOpts{Method: "GET", Target: server.URL}, server.Client(), 32)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("active request did not stop")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("server did not observe cancellation")
	}
}

func TestUnsupportedEncodingNeverBecomesCompleteBodyEvidence(t *testing.T) {
	var raw bytes.Buffer
	compressor, err := flate.NewWriter(&raw, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(compressor, "inert saved content"); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		encoding []string
		body     []byte
		code     string
	}{
		{"unsupported", []string{"br"}, []byte("encoded bytes"), "unsupported_content_encoding"},
		{"stacked", []string{"gzip, deflate"}, []byte("encoded bytes"), "unsupported_content_encoding"},
		{"repeated header", []string{"gzip", "deflate"}, []byte("encoded bytes"), "unsupported_content_encoding"},
		{"raw deflate", []string{"deflate"}, raw.Bytes(), "body_decode"},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := &trackedResponseBody{Reader: bytes.NewReader(test.body)}
			client := &http.Client{Transport: bodyTrackingTransport{response: &http.Response{
				StatusCode: 403, Header: http.Header{"Content-Encoding": test.encoding, "Server": {"fixture"}}, Body: body,
			}}}
			got, err := sendHTTP(context.Background(), requestOpts{Method: "GET", Target: "http://fixture.invalid"}, client, 16)
			if err == nil || got.ErrorCode != test.code || got.TransportError == "" || len(got.Body) != 0 || got.StatusCode != 403 || body.closes != 1 {
				t.Fatalf("unavailable encoding lost completeness or metadata: %+v, closes=%d, err=%v", got, body.closes, err)
			}
		})
	}
}

func TestRequestComponentsAndNoUserAgentOnWire(t *testing.T) {
	type observed struct{ uri, userAgent string }
	requests := make(chan observed, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- observed{r.RequestURI, r.Header.Get("User-Agent")}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	target := server.URL + "/Case%2fKept/?Token=Ab%2F%2b&dup=one&dup=two"
	options := newTypeOptions(target)
	normal, noUA := options[0], options[1]
	auxiliary := requestOpts{Method: "GET", Target: target, Path: "/Next%2fPart", Params: map[string]string{"dup": "three", "p": "inert value"}}
	for _, option := range []requestOpts{normal, noUA, auxiliary} {
		if _, err := sendHTTP(context.Background(), option, server.Client(), 32); err != nil {
			t.Fatal(err)
		}
	}
	first, second, third := <-requests, <-requests, <-requests
	want := "/Case%2fKept/?Token=Ab%2F%2b&dup=one&dup=two"
	if first.uri != want || second.uri != want || first.userAgent == "" || second.userAgent != "" {
		t.Fatalf("baseline or no-UA wire contract lost: first=%+v second=%+v", first, second)
	}
	if third.uri != "/Case%2fKept/Next%2fPart?Token=Ab%2F%2b&dup=one&dup=two&dup=three&p=inert+value" {
		t.Fatalf("path/query components were changed: %q", third.uri)
	}
	noUA.ExtraHeaders = []Header{{Name: "user-agent", Value: "explicit-client"}}
	if _, err := sendHTTP(context.Background(), noUA, server.Client(), 32); err != nil {
		t.Fatal(err)
	}
	if got := <-requests; got.userAgent != "explicit-client" {
		t.Fatalf("explicit User-Agent did not override no-UA default: %+v", got)
	}
}

func TestHTTPDiagnosticRetentionIsBounded(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New(strings.Repeat("remote failure ", 1<<17))
	})}
	evidence, err := sendHTTP(context.Background(), requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid"}, client, DefaultMaxBodyBytes)
	if err == nil || evidence.ErrorCode != "transport_error" || len(evidence.TransportError) != 1024 {
		t.Fatalf("diagnostic failure or retention limit lost: code=%q bytes=%d err=%v", evidence.ErrorCode, len(evidence.TransportError), err != nil)
	}
}

func TestHTTPDiagnosticRetainsTLSCauseWithLongURL(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS request reached the HTTP handler")
	}))
	defer server.Close()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	for _, path := range []string{"/short", "/" + strings.Repeat("x", 2048)} {
		target := server.URL + path
		got, err := sendHTTP(context.Background(), requestOpts{Method: http.MethodGet, Target: target}, client, DefaultMaxBodyBytes)
		var unknownCA x509.UnknownAuthorityError
		if !errors.As(err, &unknownCA) {
			t.Fatalf("expected certificate verification failure, got %v", err)
		}
		var urlErr *url.Error
		if !errors.As(err, &urlErr) || urlErr.URL != target || !strings.Contains(err.Error(), target) {
			t.Fatalf("returned error lost original URL: %v", err)
		}
		if got.RequestURL != target || got.ErrorCode != "transport_error" || len(got.TransportError) > 1024 ||
			!strings.Contains(got.TransportError, "x509: certificate signed by unknown authority") {
			t.Fatalf("TLS cause lost behind URL: code=%q diagnostic=%q", got.ErrorCode, got.TransportError)
		}
	}
}

func TestSendHTTPBodylessResponsesIgnoreContentEncoding(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		status int
	}{
		{"no content", http.MethodGet, http.StatusNoContent},
		{"not modified", http.MethodGet, http.StatusNotModified},
		{"head success", http.MethodHead, http.StatusOK},
		{"head error", http.MethodHead, http.StatusForbidden},
		{"switching protocols", http.MethodGet, http.StatusSwitchingProtocols},
		{"connect tunnel", http.MethodConnect, http.StatusOK},
	} {
		for _, coding := range []string{"gzip", "deflate", "br"} {
			t.Run(test.name+"/"+coding, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Encoding", coding)
					w.Header().Set("X-Fixture", "metadata")
					w.WriteHeader(test.status)
				}))
				defer server.Close()
				client := server.Client()
				client.Timeout = 5 * time.Second
				got, err := sendHTTP(context.Background(), requestOpts{Method: test.method, Target: server.URL, Type: "Normal", Headers: defaultHeaders}, client, DefaultMaxBodyBytes)
				if err != nil || got.ErrorCode != "" || got.TransportError != "" || got.BodyTruncated || len(got.Body) != 0 {
					t.Fatalf("bodyless response produced incomplete evidence: %+v, err=%v", got, err)
				}
				if got.StatusCode != test.status || got.Reason != http.StatusText(test.status) || got.Role != "Normal" ||
					got.RequestURL != server.URL || got.EffectiveURL != server.URL {
					t.Fatalf("bodyless response lost metadata: %+v", got)
				}
				headers := make(http.Header)
				for _, header := range got.Headers {
					headers.Add(header.Name, header.Value)
				}
				if headers.Get("Content-Encoding") != coding || headers.Get("X-Fixture") != "metadata" {
					t.Fatalf("bodyless response lost headers: %+v", got.Headers)
				}
				if !availableEvidenceChannels(got).body {
					t.Fatal("bodyless response is not complete empty content")
				}
			})
		}
	}
}

func TestSendHTTPBodyBearingResponsesStillRejectInvalidEncoding(t *testing.T) {
	for _, test := range []struct {
		name   string
		method string
		status int
		body   string
	}{
		{"empty", http.MethodGet, http.StatusOK, ""},
		{"malformed", http.MethodGet, http.StatusOK, "not encoded"},
		{"reset content framing", http.MethodGet, http.StatusResetContent, ""},
		{"connect rejected", http.MethodConnect, http.StatusForbidden, "not encoded"},
	} {
		for _, coding := range []string{"gzip", "deflate", "br"} {
			t.Run(test.name+"/"+coding, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Encoding", coding)
					w.WriteHeader(test.status)
					if _, err := io.WriteString(w, test.body); err != nil {
						t.Errorf("write malformed body: %v", err)
					}
				}))
				defer server.Close()
				client := server.Client()
				client.Timeout = 5 * time.Second
				got, err := sendHTTP(context.Background(), requestOpts{Method: test.method, Target: server.URL, Headers: defaultHeaders}, client, DefaultMaxBodyBytes)
				wantCode := "body_decode"
				if coding == "br" {
					wantCode = "unsupported_content_encoding"
				}
				if err == nil || got.ErrorCode != wantCode || got.TransportError == "" || got.StatusCode != test.status || availableEvidenceChannels(got).body {
					t.Fatalf("invalid encoded body became complete: %+v, err=%v", got, err)
				}
			})
		}
	}
}

func TestRetainedHTTPBudgetDoesNotSpendLaterEvidenceOnBodySlack(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})}
	budget := &httpEvidenceBudget{remaining: 600, maxHeader: DefaultMaxResponseHeaderBytes}
	options := requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid", evidenceBudget: budget}
	for i := range 2 {
		evidence, err := sendHTTP(context.Background(), options, client, DefaultMaxBodyBytes)
		if err != nil || evidence.StatusCode != 200 || string(evidence.Body) != "x" || evidence.BodyTruncated {
			t.Fatalf("response %d lost usable evidence to spare capacity: %+v, %v", i, evidence, err)
		}
	}
}

type bodyReadSizeRecorder struct {
	io.Reader
	firstRead int
}

func (r *bodyReadSizeRecorder) Read(p []byte) (int, error) {
	if r.firstRead == 0 {
		r.firstRead = len(p)
	}
	return r.Reader.Read(p)
}

func TestContentLengthHintPreservesBodyReadSemantics(t *testing.T) {
	content := strings.Repeat("x", 32<<10)
	readErr := errors.New("late body failure")
	for _, test := range []struct {
		name          string
		contentLength int64
		content       string
		encoding      string
		limit         int64
		readErr       error
		wantTruncated bool
	}{
		{name: "known exact length", contentLength: int64(len(content)), content: content},
		{name: "explicit identity", contentLength: int64(len(content)), content: content, encoding: "IDENTITY"},
		{name: "understated length", contentLength: 513, content: content},
		{name: "overstated length", contentLength: int64(len(content)), content: "short"},
		{name: "hostile length is bounded", contentLength: math.MaxInt64, content: "short"},
		{name: "body limit exact fit", contentLength: int64(len(content)), content: content[:2048], limit: 2048},
		{name: "body limit overflow", contentLength: int64(len(content)), content: content, limit: 2048, wantTruncated: true},
		{name: "late read failure", contentLength: int64(len(content)), content: content, readErr: readErr},
		{name: "late unexpected EOF", contentLength: int64(len(content)), content: content, readErr: io.ErrUnexpectedEOF},
		{name: "cancelled read", contentLength: int64(len(content)), content: content[:1024], readErr: context.Canceled},
	} {
		t.Run(test.name, func(t *testing.T) {
			limit := test.limit
			if limit == 0 {
				limit = DefaultMaxBodyBytes
			}
			var reader io.Reader = strings.NewReader(test.content)
			if test.readErr != nil {
				reader = io.MultiReader(reader, failingResponseReader{err: test.readErr})
			}
			recorded := &bodyReadSizeRecorder{Reader: reader}
			body := &trackedResponseBody{Reader: recorded}
			client := &http.Client{Transport: bodyTrackingTransport{response: &http.Response{
				StatusCode: http.StatusOK, ContentLength: test.contentLength,
				Header: http.Header{"Content-Encoding": {test.encoding}}, Body: body,
			}}}
			evidence, err := sendHTTP(context.Background(), requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid"}, client, limit)
			if !errors.Is(err, test.readErr) {
				t.Fatalf("read error = %v, want %v", err, test.readErr)
			}
			wantBody := test.content[:min(int64(len(test.content)), limit)]
			if evidence.StatusCode != http.StatusOK || string(evidence.Body) != wantBody || evidence.BodyTruncated != test.wantTruncated || cap(evidence.Body) != len(evidence.Body) || body.closes != 1 {
				t.Fatalf("body semantics changed: bytes=%d/%d cap=%d truncated=%t/%t status=%d closes=%d", len(evidence.Body), len(wantBody), cap(evidence.Body), evidence.BodyTruncated, test.wantTruncated, evidence.StatusCode, body.closes)
			}
			if (evidence.ErrorCode != "") != (test.readErr != nil) || (evidence.TransportError != "") != (test.readErr != nil) {
				t.Fatalf("body failure lost its diagnostic: %+v", evidence)
			}
			if recorded.firstRead > 32<<10+bytes.MinRead {
				t.Fatalf("untrusted length caused an oversized first read: %d", recorded.firstRead)
			}
		})
	}
}

func TestContentLengthHintDoesNotReserveSharedBodyBudget(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: math.MaxInt64, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})}
	budget := &httpEvidenceBudget{remaining: 600, maxHeader: DefaultMaxResponseHeaderBytes}
	options := requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid", evidenceBudget: budget}
	for i := range 2 {
		evidence, err := sendHTTP(context.Background(), options, client, DefaultMaxBodyBytes)
		if err != nil || string(evidence.Body) != "x" || cap(evidence.Body) != 1 || evidence.BodyTruncated {
			t.Fatalf("response %d lost actual evidence to a length hint: %+v, %v", i, evidence, err)
		}
	}
}

func TestDecodedResponsesDoNotShareStreamState(t *testing.T) {
	for _, coding := range []string{"gzip", "deflate"} {
		t.Run(coding, func(t *testing.T) {
			t.Parallel()
			for _, test := range []struct {
				content string
				limit   int64
				corrupt bool
			}{
				{content: strings.Repeat("first stream ", 4000), limit: 17},
				{content: strings.Repeat("second stream ", 3000), limit: DefaultMaxBodyBytes},
				{content: "bad checksum", limit: DefaultMaxBodyBytes, corrupt: true},
				{content: "after failure", limit: DefaultMaxBodyBytes},
				{content: "", limit: DefaultMaxBodyBytes},
				{content: strings.Repeat("exact", 2048), limit: 5 * 2048},
			} {
				var encoded bytes.Buffer
				var writer io.WriteCloser
				if coding == "gzip" {
					writer = gzip.NewWriter(&encoded)
				} else {
					writer = zlib.NewWriter(&encoded)
				}
				if _, err := io.WriteString(writer, test.content); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if test.corrupt {
					encoded.Bytes()[encoded.Len()-1] ^= 0xff
				}
				body := &trackedResponseBody{Reader: bytes.NewReader(encoded.Bytes())}
				client := &http.Client{Transport: bodyTrackingTransport{response: &http.Response{
					StatusCode: http.StatusOK, Header: http.Header{"Content-Encoding": {coding}}, Body: body,
				}}}
				got, err := sendHTTP(context.Background(), requestOpts{Method: http.MethodGet, Target: "http://fixture.invalid"}, client, test.limit)
				want := test.content[:min(int64(len(test.content)), test.limit)]
				if (err != nil) != test.corrupt || string(got.Body) != want || got.BodyTruncated != (int64(len(test.content)) > test.limit) || body.closes != 1 {
					t.Fatalf("stream state leaked: body=%q want=%q truncated=%t closed=%d err=%v", got.Body, want, got.BodyTruncated, body.closes, err)
				}
			}
		})
	}
}

func TestBoundedBodyReaderRejectsRepeatedEmptyReads(t *testing.T) {
	reader := &intermittentEmptyReader{}
	body, err := readBoundedBody(reader, 100, 0)
	if !errors.Is(err, io.ErrNoProgress) || string(body) != "x" || reader.calls != 101 {
		t.Fatalf("no-progress read lost partial body or bounded retries: body=%q calls=%d err=%v", body, reader.calls, err)
	}
}

type intermittentEmptyReader struct{ calls int }

func (r *intermittentEmptyReader) Read(p []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		return copy(p, "x"), nil
	}
	return 0, nil
}
