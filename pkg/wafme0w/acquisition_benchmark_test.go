package wafme0w

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
)

// BenchmarkAcquisitionPipeline measures completed targets through Run, including
// acquisition, classification with the bundled catalogue, generic detection and
// result delivery. One Run consumes b.N targets with four workers; compilation,
// server/transport construction, compression and shutdown are outside the timer.
// These are controlled loopback measurements, not Internet-throughput estimates.
func BenchmarkAcquisitionPipeline(b *testing.B) {
	catalogue, err := os.ReadFile("../../cmd/wafme0w/resources/waf-fingerprints.json")
	if err != nil {
		b.Fatal(err)
	}
	definitions, err := ReadCatalogue(bytes.NewReader(catalogue))
	if err != nil {
		b.Fatal(err)
	}
	engine, err := Compile(definitions)
	if err != nil {
		b.Fatal(err)
	}
	for _, protocol := range []string{"HTTP", "TLS"} {
		b.Run(protocol, func(b *testing.B) {
			for _, mode := range []string{"Baseline", "Full"} {
				b.Run(mode, func(b *testing.B) {
					for _, workload := range []struct {
						name string
						size int
						gzip bool
					}{
						{"Small", 256, false},
						{"Body32KiB", 32 << 10, false},
						{"Gzip32KiB", 32 << 10, true},
					} {
						b.Run(workload.name, func(b *testing.B) {
							benchmarkAcquisitionPipeline(b, engine, protocol == "TLS", mode == "Baseline", workload.size, workload.gzip)
						})
					}
				})
			}
		})
	}
}

func benchmarkAcquisitionPipeline(b *testing.B, engine *Engine, useTLS, baseline bool, bodySize int, compressed bool) {
	b.Helper()
	b.StopTimer()
	html := []byte(`<!doctype html><html><head><title>Example store</title></head><body><main><h1>Welcome</h1><p>Browse our products and services.</p><a href="/account">Account</a></main></body></html>`)
	body := bytes.Repeat(html, bodySize/len(html)+1)[:bodySize]
	wireBody := body
	if compressed {
		var encoded bytes.Buffer
		writer := gzip.NewWriter(&encoded)
		if _, err := writer.Write(body); err != nil {
			b.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			b.Fatal(err)
		}
		wireBody = encoded.Bytes()
	}
	contentLength := strconv.Itoa(len(wireBody))
	var requests, connections, serverErrors atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 1 || !r.Close || r.Method != http.MethodGet {
			serverErrors.Add(1)
		}
		w.Header().Set("Date", "Thu, 29 Oct 2026 00:00:00 GMT")
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", contentLength)
		w.Header().Set("Set-Cookie", "session=opaque; Path=/; HttpOnly")
		w.Header().Set("X-Request-Id", "0123456789abcdef0123456789abcdef")
		if compressed {
			w.Header().Set("Content-Encoding", "gzip")
		}
		if n, err := w.Write(wireBody); err != nil || n != len(wireBody) {
			serverErrors.Add(1)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	if useTLS {
		server.StartTLS()
	} else {
		server.Start()
	}
	b.Cleanup(server.Close)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	// Preserve the production anti-replay policy: no keep-alive, HTTP/2 or TLS
	// session cache. Every probe pays for a fresh HTTP/1 connection/handshake.
	transport.DisableKeepAlives = true
	transport.MaxResponseHeaderBytes = 64 << 10
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.TLSNextProto = nil
	if useTLS {
		roots := x509.NewCertPool()
		roots.AddCert(server.Certificate())
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, NextProtos: []string{"http/1.1"}}
	}
	b.Cleanup(transport.CloseIdleConnections)
	config := DefaultConfig()
	config.Concurrency, config.MaxConnections = 4, 4
	config.BaselineOnly = baseline
	config.Client = &http.Client{Transport: transport}
	roles := []string{"Normal", "NoUserAgent", "NonExistent", "XssAttack", "XxeAttack", "LfiAttack", "CentralAttack", "SqliAttack", "RceAttack"}
	if baseline {
		roles = roles[:1]
	}
	input := &acquisitionBenchmarkInput{line: server.URL + "/bench\n", remaining: b.N}
	completed := 0
	emit := func(result Result) error {
		if result.Outcome.State != Complete || len(result.Outcome.Diagnostics) != 0 || len(result.Evidence) != len(roles) {
			return fmt.Errorf("incomplete target: state=%s evidence=%d diagnostics=%+v", result.Outcome.State, len(result.Evidence), result.Outcome.Diagnostics)
		}
		for i, observation := range result.Evidence {
			if observation.Role != roles[i] || observation.StatusCode != http.StatusOK || observation.ErrorCode != "" || observation.BodyTruncated {
				return fmt.Errorf("probe %d did not complete: %+v", i, observation)
			}
		}
		completed++
		return nil
	}
	b.ReportAllocs()
	// MB/s counts decoded response bytes per completed target, including probes.
	b.SetBytes(int64(bodySize * len(roles)))
	b.ResetTimer()
	b.StartTimer()
	err := Run(context.Background(), engine, input, config, emit)
	b.StopTimer()
	server.Close()
	if err != nil {
		b.Fatal(err)
	}
	wantRequests := int64(b.N) * int64(len(roles))
	if completed != b.N || requests.Load() != wantRequests || connections.Load() != wantRequests || serverErrors.Load() != 0 {
		b.Fatalf("work changed: targets=%d/%d requests=%d/%d connections=%d server_errors=%d", completed, b.N, requests.Load(), wantRequests, connections.Load(), serverErrors.Load())
	}
	b.ReportMetric(float64(requests.Load())/float64(completed), "requests/target")
	b.ReportMetric(float64(connections.Load())/float64(completed), "connections/target")
	b.ReportMetric(float64(completed)/b.Elapsed().Seconds(), "targets/s")
}

// Stream the calibrated target count without retaining O(b.N) input bytes.
// Run owns the scanner goroutine, so this reader needs no synchronization.
type acquisitionBenchmarkInput struct {
	line      string
	remaining int
	offset    int
}

func (r *acquisitionBenchmarkInput) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && r.remaining > 0 {
		copied := copy(p[n:], r.line[r.offset:])
		n += copied
		r.offset += copied
		if r.offset == len(r.line) {
			r.offset = 0
			r.remaining--
		}
	}
	if n == 0 && r.remaining == 0 {
		return 0, io.EOF
	}
	return n, nil
}
