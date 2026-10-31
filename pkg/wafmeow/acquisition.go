package wafmeow

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	httputil "github.com/Lu1sDV/wafmeow/v2/pkg/utils/http"
)

func normalizedOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.String()
	}
	port := u.Port()
	if port != "" {
		n, _ := strconv.Atoi(port)
		port = strconv.Itoa(n)
	}
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return strings.ToLower(u.Scheme) + "://" + host
}

func parseAllowedOrigin(value string) (string, error) {
	u, err := httputil.ParseURI(value)
	if err != nil {
		return "", err
	}
	if !strings.Contains(value, "://") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery {
		return "", errors.New("origin must contain only an explicit HTTP(S) scheme and host/port")
	}
	return normalizedOrigin(u), nil
}

type acquisitionError struct {
	code    string
	message string
}

func (e *acquisitionError) Error() string { return e.message }

func acquisitionCode(err error) string {
	var policy *acquisitionError
	switch {
	case errors.As(err, &policy):
		return policy.code
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	default:
		return "transport_error"
	}
}

type requestTraceKey struct{}
type requestTrace struct {
	urls     []string
	response *http.Response
	// abort cancels the probe when a transport retry would exceed the
	// per-target request budget or pacing admission. sendHTTP owns the
	// context and clears its cancellation after the response body is closed.
	abort func(error)
}

// outboundPolicy is shared by every target in one Run. Slots remain occupied
// through response-body closure, including decoding, not merely until headers.
type outboundPolicy struct {
	config       Config
	base         http.Client
	slots        chan struct{}
	mu           sync.Mutex
	next         time.Time
	origins      map[string]time.Time
	cooldowns    []originCooldown
	cooldownHead int
	// ownedTransport is the run-local transport created here; nil when the
	// caller supplied one. Only an owned transport is closed after a Run.
	ownedTransport *http.Transport
}

type originCooldown struct {
	origin string
	until  time.Time
}

// The interval is fixed for a Run, so admissions expire in FIFO order.
// Reclaim only expired entries; there is no scan over still-active origins.
func (p *outboundPolicy) expireOrigins(now time.Time) {
	for p.cooldownHead < len(p.cooldowns) && !p.cooldowns[p.cooldownHead].until.After(now) {
		delete(p.origins, p.cooldowns[p.cooldownHead].origin)
		p.cooldowns[p.cooldownHead] = originCooldown{}
		p.cooldownHead++
	}
	if p.cooldownHead == len(p.cooldowns) {
		p.cooldowns = p.cooldowns[:0]
		p.cooldownHead = 0
	} else if len(p.cooldowns) == cap(p.cooldowns) && p.cooldownHead >= len(p.cooldowns)/2 {
		remaining := copy(p.cooldowns, p.cooldowns[p.cooldownHead:])
		clear(p.cooldowns[remaining:])
		p.cooldowns = p.cooldowns[:remaining]
		p.cooldownHead = 0
	}
}

func newOutboundPolicy(config Config) *outboundPolicy {
	p := &outboundPolicy{config: config, slots: make(chan struct{}, config.MaxConnections)}
	if config.Client != nil {
		p.base = *config.Client
	}
	if p.base.Transport == nil {
		p.base.Transport = http.DefaultTransport
		if transport, ok := http.DefaultTransport.(*http.Transport); ok {
			transport = transport.Clone()
			// Keep-alive reuses verified HTTP/1 connections between a target's
			// probes. Transparent transport retries are still visible: the
			// wrapper counts each GetConn attempt against the target budget and
			// paces it. Guarded writes prevent a refused retry from being sent
			// even if cancellation races with selecting an idle connection.
			transport.DisableKeepAlives = false
			guardOwnedConnections(transport)
			transport.MaxResponseHeaderBytes = config.MaxResponseHeaderBytes
			transport.Protocols = new(http.Protocols)
			transport.Protocols.SetHTTP1(true)
			transport.TLSNextProto = nil
			if transport.TLSClientConfig == nil {
				transport.TLSClientConfig = new(tls.Config)
			}
			transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
			transport.TLSClientConfig.ClientSessionCache = tls.NewLRUClientSessionCache(256)
			p.base.Transport = transport
			p.ownedTransport = transport
		}
	}
	if config.PerOriginRequestsPerSecond != 0 {
		p.origins = make(map[string]time.Time)
	}
	return p
}

func rateInterval(rate float64) time.Duration {
	if rate == 0 {
		return 0
	}
	ns := math.Ceil(float64(time.Second) / rate)
	if ns >= float64(math.MaxInt64) {
		return time.Duration(math.MaxInt64)
	}
	return max(time.Nanosecond, time.Duration(ns))
}

// acquire checks pacing before taking a connection slot and again after waiting
// for one. Waiting origins cannot monopolize slots, and queued requests cannot
// spend stale rate admissions in a burst when a slow response finally closes.
func (p *outboundPolicy) acquire(ctx context.Context, origin string) error {
	globalInterval := rateInterval(p.config.RequestsPerSecond)
	originInterval := rateInterval(p.config.PerOriginRequestsPerSecond)
	if globalInterval == 0 && originInterval == 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p.slots <- struct{}{}:
			return nil
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		next := p.nextAdmissionLocked(origin, time.Now())
		p.mu.Unlock()
		if delay := time.Until(next); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p.slots <- struct{}{}:
		}
		p.mu.Lock()
		now := time.Now()
		next = p.nextAdmissionLocked(origin, now)
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			<-p.slots
			return err
		}
		if now.Before(next) {
			p.mu.Unlock()
			<-p.slots
			continue
		}
		p.commitAdmissionLocked(origin, now, globalInterval, originInterval)
		p.mu.Unlock()
		return nil
	}
}

// waitRate commits a pacing admission without taking a connection slot. It is
// used for transport retries, which already hold their probe's slot.
func (p *outboundPolicy) waitRate(ctx context.Context, origin string) error {
	globalInterval := rateInterval(p.config.RequestsPerSecond)
	originInterval := rateInterval(p.config.PerOriginRequestsPerSecond)
	if globalInterval == 0 && originInterval == 0 {
		return ctx.Err()
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		p.mu.Lock()
		next := p.nextAdmissionLocked(origin, time.Now())
		p.mu.Unlock()
		if delay := time.Until(next); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		p.mu.Lock()
		now := time.Now()
		if now.Before(p.nextAdmissionLocked(origin, now)) {
			p.mu.Unlock()
			continue
		}
		p.commitAdmissionLocked(origin, now, globalInterval, originInterval)
		p.mu.Unlock()
		return nil
	}
}

// nextAdmissionLocked and commitAdmissionLocked require p.mu.
func (p *outboundPolicy) nextAdmissionLocked(origin string, now time.Time) time.Time {
	p.expireOrigins(now)
	next := p.next
	if p.origins[origin].After(next) {
		next = p.origins[origin]
	}
	return next
}

func (p *outboundPolicy) commitAdmissionLocked(origin string, now time.Time, globalInterval, originInterval time.Duration) {
	if globalInterval != 0 {
		p.next = now.Add(globalInterval)
	}
	if originInterval != 0 {
		p.origins[origin] = now.Add(originInterval)
		p.cooldowns = append(p.cooldowns, originCooldown{origin, p.origins[origin]})
	}
}

func (p *outboundPolicy) allowed(origin string) bool {
	return len(p.config.AllowedOrigins) == 0 || slices.Contains(p.config.AllowedOrigins, origin)
}

// The alias is fixed from the starting origin, never widened by a redirect chain.
func wwwAliasOrigin(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	bare := strings.TrimPrefix(host, "www.")
	dns := strings.TrimSuffix(bare, ".")
	if !strings.Contains(dns, ".") {
		return ""
	}
	if _, err := netip.ParseAddr(dns); err == nil {
		return ""
	}
	if host == bare {
		host = "www." + host
	} else {
		host = bare
	}
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	}
	u.Host = host
	return u.String()
}

type targetTransport struct {
	policy   *outboundPolicy
	origin   string
	alias    string
	mu       sync.Mutex
	requests int
}

func (t *targetTransport) allowed(origin string) bool {
	return t.policy.allowed(origin) &&
		(origin == t.origin || origin == t.alias || t.policy.config.RedirectPolicy == "allowlist")
}

func (p *outboundPolicy) client(origin string) *http.Client {
	client := p.base
	transport := &targetTransport{policy: p, origin: origin}
	if p.config.RedirectPolicy == "canonical-host" {
		transport.alias = wwwAliasOrigin(origin)
	}
	client.Transport = transport
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if p.config.RedirectPolicy == "none" || p.config.MaxRedirects == 0 {
			return http.ErrUseLastResponse
		}
		if len(via) > p.config.MaxRedirects {
			return &acquisitionError{"redirect_limit", "maximum redirect count reached"}
		}
		if p.base.CheckRedirect != nil {
			if err := p.base.CheckRedirect(req, via); err != nil {
				return err
			}
		}
		u, err := httputil.ParseURI(req.URL.String())
		if err != nil {
			return &acquisitionError{"redirect_scope", "invalid redirect destination: " + err.Error()}
		}
		destination := normalizedOrigin(u)
		if !transport.allowed(destination) {
			return &acquisitionError{"redirect_scope", "redirect destination is outside permitted origins"}
		}
		for _, prior := range via {
			if prior.URL.String() == req.URL.String() {
				return &acquisitionError{"redirect_loop", "redirect loop detected"}
			}
		}
		return nil
	}
	return &client
}

// reserve records one more outbound attempt, including transport retries, and
// reports whether the per-target request budget allows it.
func (t *targetTransport) reserve() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.requests >= t.policy.config.MaxRequests {
		return false
	}
	t.requests++
	return true
}

func (t *targetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p := t.policy
	u, err := httputil.ParseURI(req.URL.String())
	if err != nil {
		return nil, &acquisitionError{"invalid_target", err.Error()}
	}
	origin := normalizedOrigin(u)
	if !t.allowed(origin) {
		return nil, &acquisitionError{"target_scope", "request destination is outside permitted origins"}
	}
	t.mu.Lock()
	if t.requests >= p.config.MaxRequests {
		t.mu.Unlock()
		return nil, &acquisitionError{"request_budget", "per-target outbound request budget exhausted"}
	}
	t.requests++
	t.mu.Unlock()
	if err := p.acquire(req.Context(), origin); err != nil {
		// This RoundTrip has not reached the underlying transport. Earlier
		// redirect hops may already have been sent, so describe only this attempt.
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, fmt.Errorf("local rate/connection admission timed out (this request attempt was not sent; waiting counts toward request/target deadlines; reduce concurrency or increase request/target timeouts): %w", err)
		}
		return nil, fmt.Errorf("local rate/connection admission failed (this request attempt was not sent): %w", err)
	}
	release := func() { <-p.slots }
	if err := req.Context().Err(); err != nil {
		release()
		return nil, err
	}
	trace, _ := req.Context().Value(requestTraceKey{}).(*requestTrace)
	if trace != nil {
		trace.urls = append(trace.urls, req.URL.String())
	}
	baseReq := req
	if trace != nil && trace.abort != nil && p.ownedTransport != nil {
		// The owned transport may transparently retry an idempotent probe on a
		// reused connection. Count each such attempt against the target budget
		// and pacing, and abort the probe if either would be exceeded. Caller
		// transports keep their own retry behavior and accounting.
		attempts := 0
		baseReq = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GetConn: func(string) {
				attempts++
				if attempts == 1 {
					return
				}
				if !t.reserve() {
					trace.abort(&acquisitionError{"request_budget", "per-target outbound request budget exhausted"})
					return
				}
				if err := p.waitRate(req.Context(), origin); err != nil {
					trace.abort(err)
				}
			},
			GotConn: func(info httptrace.GotConnInfo) {
				rejectConnectionWrite(info.Conn, context.Cause(req.Context()))
			},
		}))
	}
	response, err := p.base.Transport.RoundTrip(baseReq)
	if response != nil && !responseHeadersWithinLimit(response, p.config.MaxResponseHeaderBytes) {
		if response.Body != nil {
			response.Body.Close()
		}
		release()
		return nil, &acquisitionError{"response_header_limit", "response headers exceed configured byte limit"}
	}
	if response != nil {
		if response.Body != nil {
			response.Body = &releaseBody{ReadCloser: response.Body, release: release}
		} else {
			release()
		}
		if response.Request == nil {
			response.Request = req
		}
		if trace, ok := req.Context().Value(requestTraceKey{}).(*requestTrace); ok {
			trace.response = response
		}
	} else {
		release()
	}
	// A response can race with cancellation. Keep its bounded metadata in the
	// trace before reporting the cause; sendHTTP must not lose received evidence
	// or treat the unread body as complete. The shared error path closes it once.
	if cause := context.Cause(req.Context()); cause != nil {
		err = cause
	}
	if err != nil || response == nil {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if err == nil {
			err = fmt.Errorf("HTTP transport returned no response")
		}
		return nil, err
	}
	return response, nil
}

type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
	err     error
}

func (b *releaseBody) Close() error {
	b.once.Do(func() {
		b.err = b.ReadCloser.Close()
		b.release()
	})
	return b.err
}

// Parsed-header accounting also protects callers that inject a transport with
// a larger wire limit. Check before redirects can retain or follow Location.
func responseHeadersWithinLimit(response *http.Response, limit int64) bool {
	take := func(n int) bool {
		if int64(n) > limit {
			return false
		}
		limit -= int64(n)
		return true
	}
	if !take(len(response.Proto)) || !take(1) || !take(len(response.Status)) || !take(4) {
		return false
	}
	for name, values := range response.Header {
		for _, value := range values {
			if !take(len(name)) || !take(len(value)) || !take(4) {
				return false
			}
		}
	}
	return true
}
