package wafme0w

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
)

// rejectedWrite is immutable after publication to the connection's writer.
type rejectedWrite struct{ err error }

// guardedConn prevents a rejected retry from reaching the wire even if the
// transport selects an idle connection after GetConn cancels the request.
// The transport still owns connection closure; trace hooks never close it.
type guardedConn struct {
	net.Conn
	rejected atomic.Pointer[rejectedWrite]
}

func (c *guardedConn) Write(p []byte) (int, error) {
	if rejected := c.rejected.Load(); rejected != nil {
		return 0, rejected.err
	}
	return c.Conn.Write(p)
}

// rejectConnectionWrite runs in GotConn, before HTTP/1 can enqueue its write.
// Rejection is permanent: the transport retires the connection after the failed
// write or cancellation. TLS (including TLS through an HTTPS proxy) may wrap the
// guarded socket; leave its handshake and connection-state reporting intact.
func rejectConnectionWrite(conn net.Conn, cause error) {
	if cause == nil {
		return
	}
	for {
		switch c := conn.(type) {
		case *guardedConn:
			c.rejected.CompareAndSwap(nil, &rejectedWrite{cause})
			return
		case *tls.Conn:
			conn = c.NetConn()
		default:
			return
		}
	}
}

// guardOwnedConnections keeps the configured dialer's behavior and adds a
// write barrier below the transport's TLS layer. A custom TLS dialer hides that
// socket and must retain fresh connections rather than allow unguarded retries.
func guardOwnedConnections(transport *http.Transport) {
	if transport.DialTLSContext != nil || transport.DialTLS != nil {
		transport.DisableKeepAlives = true
		return
	}
	dialContext, dial := transport.DialContext, transport.Dial
	var defaultDialer net.Dialer
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		var conn net.Conn
		var err error
		switch {
		case dialContext != nil:
			conn, err = dialContext(ctx, network, addr)
		case dial != nil:
			conn, err = dial(network, addr)
		default:
			conn, err = defaultDialer.DialContext(ctx, network, addr)
		}
		if err != nil || conn == nil {
			return conn, err
		}
		return &guardedConn{Conn: conn}, nil
	}
}
