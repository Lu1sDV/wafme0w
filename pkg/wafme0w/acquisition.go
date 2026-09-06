package wafme0w

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
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

func (p *outboundPolicy) acquire(ctx context.Context, origin string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case p.slots <- struct{}{}:
	}
	globalInterval := rateInterval(p.config.RequestsPerSecond)
	originInterval := rateInterval(p.config.PerOriginRequestsPerSecond)
	for {
		if err := ctx.Err(); err != nil {
			<-p.slots
			return err
		}
		p.mu.Lock()
		now := time.Now()
		p.expireOrigins(now)
		next := p.next
		if p.origins[origin].After(next) {
			next = p.origins[origin]
		}
		if !now.Before(next) {
			if globalInterval != 0 {
				p.next = now.Add(globalInterval)
			}
			if originInterval != 0 {
				p.origins[origin] = now.Add(originInterval)
				p.cooldowns = append(p.cooldowns, originCooldown{origin, p.origins[origin]})
			}
			p.mu.Unlock()
			return nil
		}
		p.mu.Unlock()
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			<-p.slots
			return ctx.Err()
		case <-timer.C:
		}
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
		return nil, err
	}
	release := func() { <-p.slots }
	if err := req.Context().Err(); err != nil {
		release()
		return nil, err
	}
	if trace, ok := req.Context().Value(requestTraceKey{}).(*requestTrace); ok {
		trace.urls = append(trace.urls, req.URL.String())
	}
	response, err := p.base.Transport.RoundTrip(req)
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
