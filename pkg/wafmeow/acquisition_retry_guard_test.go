package wafmeow

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A delayed Close lets an already-enqueued write reach the peer. A write gate
// must reject before that enqueue, independently of when the socket closes.
type retryDelayedCloseConn struct{ net.Conn }

func (c *retryDelayedCloseConn) Close() error {
	time.Sleep(10 * time.Millisecond)
	return c.Conn.Close()
}

func TestRetryBudgetWithReadyIdleConnection(t *testing.T) {
	for _, useTLS := range []bool{false, true} {
		name := "http"
		if useTLS {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			// Both cancellation and an idle connection are ready. Require the
			// transport to actually choose the connection branch at least once.
			for trial := 0; trial < 32; trial++ {
				if retryBudgetWithReadyIdleConnection(t, useTLS) {
					return
				}
			}
			t.Fatal("fixture did not select an idle connection after retry refusal")
		})
	}
}

func retryBudgetWithReadyIdleConnection(t *testing.T, useTLS bool) bool {
	t.Helper()
	var warmCount, wireCount atomic.Int32
	ready := make(chan struct{})
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/warm" {
			if warmCount.Add(1) == 2 {
				close(ready)
			}
			select {
			case <-ready:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if wireCount.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	if useTLS {
		server.StartTLS()
	} else {
		server.Start()
	}
	defer server.Close()

	// Configure the dialer before the runner adds its own connection guard.
	// TLS uses the fixture's trusted roots, retaining certificate verification.
	previousTransport := http.DefaultTransport
	template := previousTransport.(*http.Transport).Clone()
	if useTLS {
		template.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	}
	dial := template.DialContext
	template.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dial(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &retryDelayedCloseConn{conn}, nil
	}
	config := DefaultConfig()
	config.MaxRequests, config.MaxConnections = 1, 2
	http.DefaultTransport = template
	policy := newOutboundPolicy(config)
	http.DefaultTransport = previousTransport
	defer policy.base.Transport.(*http.Transport).CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var warm sync.WaitGroup
	warm.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer warm.Done()
			_, err := sendHTTP(ctx, requestOpts{Method: "GET", Target: server.URL + "/warm"}, policy.client(server.URL), config.MaxBodyBytes)
			if err != nil {
				t.Error(err)
			}
		}()
	}
	warm.Wait()
	var attempts atomic.Int32
	var selectedAfterRefusal atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GetConn: func(string) { attempts.Add(1) },
		GotConn: func(httptrace.GotConnInfo) {
			if attempts.Load() == 2 {
				selectedAfterRefusal.Store(true)
			}
		},
	})
	evidence, err := sendHTTP(ctx, requestOpts{Method: "GET", Target: server.URL + "/retry"}, policy.client(server.URL), config.MaxBodyBytes)
	policy.base.Transport.(*http.Transport).CloseIdleConnections()
	server.Close()
	if got := wireCount.Load(); got != 1 {
		t.Fatalf("MaxRequests=1 sent %d retry-endpoint requests, want 1", got)
	}
	if err == nil || evidence.ErrorCode != "request_budget" || evidence.StatusCode != 0 {
		t.Fatalf("refused retry lost its policy error: err=%v evidence=%+v", err, evidence)
	}
	return selectedAfterRefusal.Load()
}
