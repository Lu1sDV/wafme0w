package wafme0w

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
