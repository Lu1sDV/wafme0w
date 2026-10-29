package wafme0w

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestOwnedTransportResumesTLSOnFreshVerifiedHTTP1Connections(t *testing.T) {
	for _, version := range []struct {
		name  string
		value uint16
	}{{"TLS12", tls.VersionTLS12}, {"TLS13", tls.VersionTLS13}} {
		t.Run(version.name, func(t *testing.T) {
			var requests, connections atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.ProtoMajor != 1 || !r.Close || r.TLS == nil {
					t.Errorf("probe did not use a fresh HTTP/1 TLS connection: proto=%s close=%v tls=%v", r.Proto, r.Close, r.TLS != nil)
				}
				_, _ = io.WriteString(w, "verified TLS fixture")
			}))
			server.TLS = &tls.Config{MinVersion: version.value, MaxVersion: version.value}
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			config := DefaultConfig()
			policy := newOutboundPolicy(config)
			transport := policy.base.Transport.(*http.Transport)
			transport.Proxy = nil
			transport.TLSClientConfig.RootCAs = roots
			defer transport.CloseIdleConnections()
			client := policy.client(server.URL)
			check := func(client *http.Client, wantResumed bool) {
				t.Helper()
				response, err := client.Get(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil || string(body) != "verified TLS fixture" {
					t.Fatalf("TLS response incomplete: body=%q read=%v close=%v", body, readErr, closeErr)
				}
				if response.TLS == nil || response.TLS.DidResume != wantResumed || len(response.TLS.VerifiedChains) == 0 {
					t.Fatalf("TLS resumption or certificate verification changed: want_resumed=%v state=%+v", wantResumed, response.TLS)
				}
			}
			for i := range 4 {
				check(client, i != 0)
			}
			// Another Run owns a distinct cache; no session state escapes this run.
			other := newOutboundPolicy(config)
			otherTransport := other.base.Transport.(*http.Transport)
			otherTransport.Proxy = nil
			otherTransport.TLSClientConfig.RootCAs = roots
			defer otherTransport.CloseIdleConnections()
			check(other.client(server.URL), false)
			if requests.Load() != 5 || connections.Load() != 5 {
				t.Fatalf("TLS caching changed wire work: requests=%d connections=%d, want 5 each", requests.Load(), connections.Load())
			}
		})
	}
}

func TestOwnedTransportTLSCachePreservesCertificateVerification(t *testing.T) {
	var requests, connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.StartTLS()
	defer server.Close()
	for _, wrongName := range []bool{false, true} {
		policy := newOutboundPolicy(DefaultConfig())
		transport := policy.base.Transport.(*http.Transport)
		transport.Proxy = nil
		if wrongName {
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			transport.TLSClientConfig.RootCAs = roots
			transport.TLSClientConfig.ServerName = "wrong.fixture.invalid"
		}
		response, err := policy.client(server.URL).Get(server.URL)
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		var verification *tls.CertificateVerificationError
		if !errors.As(err, &verification) {
			t.Fatalf("untrusted/wrong-name certificate was not rejected: wrong_name=%v err=%v", wrongName, err)
		}
	}
	if requests.Load() != 0 || connections.Load() != 2 {
		t.Fatalf("failed verification issued/retried probes: requests=%d connections=%d", requests.Load(), connections.Load())
	}
}

func TestTLSCallerTransportAndSessionCacheRemainCallerOwned(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	cache := tls.NewLRUClientSessionCache(2)
	tlsConfig := &tls.Config{RootCAs: roots, ClientSessionCache: cache, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	defer transport.CloseIdleConnections()
	config := DefaultConfig()
	config.Client = &http.Client{Transport: transport}
	for range 2 {
		result := runBaseline(t, server.URL, config)
		if result.Evidence[0].StatusCode != 204 || result.Evidence[0].ErrorCode != "" {
			t.Fatalf("caller-owned TLS transport failed: %+v", result)
		}
	}
	if config.Client.Transport != transport || transport.TLSClientConfig != tlsConfig || tlsConfig.ClientSessionCache != cache || tlsConfig.RootCAs != roots || transport.DisableKeepAlives || len(tlsConfig.NextProtos) != 1 || tlsConfig.NextProtos[0] != "http/1.1" || tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("Run mutated caller-owned transport/TLS configuration")
	}
}
