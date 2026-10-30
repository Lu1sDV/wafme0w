package wafme0w

import (
	"context"
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
	"time"
)

// These tests replace the process default only while their sequential subtest
// owns it. The cloned transport must preserve the configured dialer contracts.
func policyFromDefaultTransport(t *testing.T, transport *http.Transport) *outboundPolicy {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous })
	policy := newOutboundPolicy(DefaultConfig())
	t.Cleanup(policy.ownedTransport.CloseIdleConnections)
	return policy
}

func TestOwnedTransportPreservesDialerPrecedence(t *testing.T) {
	for _, test := range []struct {
		name        string
		withContext bool
		withLegacy  bool
	}{
		{name: "DialContext precedes Dial", withContext: true, withLegacy: true},
		{name: "Dial fallback", withLegacy: true},
		{name: "default dialer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var connections, requests, contextDials, legacyDials atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Close {
					t.Error("configured TCP dialer unexpectedly disabled connection reuse")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					connections.Add(1)
				}
			}
			server.Start()
			t.Cleanup(server.Close)
			transport := &http.Transport{}
			if test.withContext {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					contextDials.Add(1)
					var dialer net.Dialer
					return dialer.DialContext(ctx, network, addr)
				}
			}
			if test.withLegacy {
				transport.Dial = func(network, addr string) (net.Conn, error) {
					legacyDials.Add(1)
					return net.DialTimeout(network, addr, time.Second)
				}
			}
			policy := policyFromDefaultTransport(t, transport)
			client := policy.client(server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			for range 2 {
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				if err := response.Body.Close(); err != nil {
					t.Fatal(err)
				}
				if response.StatusCode != http.StatusNoContent {
					t.Fatalf("status = %d, want 204", response.StatusCode)
				}
			}
			wantContext, wantLegacy := int32(0), int32(0)
			if test.withContext {
				wantContext = 1
			} else if test.withLegacy {
				wantLegacy = 1
			}
			if contextDials.Load() != wantContext || legacyDials.Load() != wantLegacy || requests.Load() != 2 || connections.Load() != 1 {
				t.Fatalf("dialer or reuse changed: DialContext=%d/%d Dial=%d/%d requests=%d/2 connections=%d/1",
					contextDials.Load(), wantContext, legacyDials.Load(), wantLegacy, requests.Load(), connections.Load())
			}
		})
	}
}

func TestOwnedTransportCustomTLSDialerRetainsFreshVerifiedConnections(t *testing.T) {
	for _, withContext := range []bool{true, false} {
		name := "DialTLS"
		if withContext {
			name = "DialTLSContext"
		}
		for _, trusted := range []bool{true, false} {
			trustName := "untrusted"
			if trusted {
				trustName = "trusted"
			}
			t.Run(name+"/"+trustName, func(t *testing.T) {
				var requests, connections, contextDials, legacyDials atomic.Int32
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if !r.Close || r.TLS == nil || r.ProtoMajor != 1 {
						t.Errorf("custom TLS dialer did not use a fresh HTTP/1 TLS connection: close=%v tls=%v proto=%s", r.Close, r.TLS != nil, r.Proto)
					}
					w.WriteHeader(http.StatusNoContent)
				}))
				server.Config.ErrorLog = log.New(io.Discard, "", 0)
				server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
					if state == http.StateNew {
						connections.Add(1)
					}
				}
				server.StartTLS()
				t.Cleanup(server.Close)
				tlsConfig := &tls.Config{RootCAs: x509.NewCertPool(), NextProtos: []string{"http/1.1"}}
				if trusted {
					tlsConfig.RootCAs.AddCert(server.Certificate())
				}
				transport := &http.Transport{TLSClientConfig: tlsConfig}
				transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
					return nil, errors.New("HTTPS unexpectedly used the TCP dialer instead of its custom TLS dialer")
				}
				transport.DialTLS = func(network, addr string) (net.Conn, error) {
					legacyDials.Add(1)
					return tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, network, addr, tlsConfig)
				}
				if withContext {
					transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						contextDials.Add(1)
						dialer := tls.Dialer{Config: tlsConfig}
						return dialer.DialContext(ctx, network, addr)
					}
				}
				policy := policyFromDefaultTransport(t, transport)
				if !policy.ownedTransport.DisableKeepAlives || transport.DisableKeepAlives {
					t.Fatal("custom TLS fallback did not disable reuse only on the owned clone")
				}
				client := policy.client(server.URL)
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				attempts := 1
				if trusted {
					attempts = 2
				}
				for range attempts {
					request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
					if err != nil {
						t.Fatal(err)
					}
					response, err := client.Do(request)
					if response != nil {
						response.Body.Close()
					}
					if !trusted {
						var verification *tls.CertificateVerificationError
						if !errors.As(err, &verification) {
							t.Fatalf("untrusted custom TLS certificate was accepted or lost its cause: %v", err)
						}
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != http.StatusNoContent || response.TLS == nil || !response.TLS.HandshakeComplete || len(response.TLS.VerifiedChains) == 0 {
						t.Fatalf("custom TLS response lost verified connection state: %+v", response)
					}
				}
				wantRequests := int32(0)
				if trusted {
					wantRequests = 2
				}
				wantContext, wantLegacy := int32(0), int32(0)
				if withContext {
					wantContext = int32(attempts)
				} else {
					wantLegacy = int32(attempts)
				}
				if requests.Load() != wantRequests || connections.Load() != int32(attempts) || contextDials.Load() != wantContext || legacyDials.Load() != wantLegacy {
					t.Fatalf("custom TLS fallback changed wire work or dialer precedence: requests=%d/%d connections=%d/%d DialTLSContext=%d/%d DialTLS=%d/%d",
						requests.Load(), wantRequests, connections.Load(), attempts, contextDials.Load(), wantContext, legacyDials.Load(), wantLegacy)
				}
			})
		}
	}
}
