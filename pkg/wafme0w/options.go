package wafme0w

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"slices"
	"time"

	"github.com/Lu1sDV/wafme0w/internal/browserruntime"
	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
)

const DefaultMaxBodyBytes int64 = 1 << 20

// Config is copied by Run. Concurrency and MaxBodyBytes must be positive.
// Zero timeouts and request/connection budgets use finite legacy defaults;
// zero MaxRedirects means no redirects, and zero rates disable added pacing.
// AllowedOrigins, when nonempty, also restrict starting URLs.
// RedirectPolicy defaults to canonical-host: the starting origin and its exact
// www/non-www counterpart, with the same scheme and effective port.
// CancelInput is an optional caller-owned, concurrency-safe wakeup for blocked
// Read calls. Run invokes it once on cancellation/failure, never on normal EOF.
// It must return promptly; Run never closes an arbitrary caller-owned reader.
// Injected clients/transports must honor request contexts, as net/http does.
// Passive is set by RunCaptured; Run rejects it rather than issuing requests.
// Durations in JSON provenance are nanoseconds.
type Config struct {
	Concurrency                int
	FastMode                   bool
	BaselineOnly               bool
	Passive                    bool
	ExcludeGeneric             bool
	MaxBodyBytes               int64
	RequestTimeout             time.Duration
	TargetTimeout              time.Duration
	MaxRequests                int
	MaxConnections             int
	RequestsPerSecond          float64
	PerOriginRequestsPerSecond float64
	MaxRedirects               int
	RedirectPolicy             string
	AllowedOrigins             []string
	// Headers override request defaults in order, case-insensitively, including
	// the NoUserAgent request. Redirect forwarding follows net/http's rules.
	Headers     []Header
	Client      *http.Client
	CancelInput func()
	// Browser is independently selected live observation, never classifier evidence.
	Browser *BrowserConfig
}

func DefaultConfig() Config {
	return Config{
		Concurrency: 20, MaxBodyBytes: DefaultMaxBodyBytes,
		RequestTimeout: 5 * time.Second, TargetTimeout: 30 * time.Second,
		MaxRequests: 54, MaxConnections: 20, MaxRedirects: 5,
		RedirectPolicy: "canonical-host",
	}
}

func (c Config) normalized() Config {
	defaults := DefaultConfig()
	if c.RequestTimeout == 0 {
		c.RequestTimeout = defaults.RequestTimeout
	}
	if c.TargetTimeout == 0 {
		c.TargetTimeout = defaults.TargetTimeout
	}
	if c.MaxRequests == 0 {
		c.MaxRequests = defaults.MaxRequests
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = defaults.MaxConnections
	}
	if c.RedirectPolicy == "" {
		c.RedirectPolicy = defaults.RedirectPolicy
	}
	c.AllowedOrigins = slices.Clone(c.AllowedOrigins)
	c.Headers = slices.Clone(c.Headers)
	for i, value := range c.AllowedOrigins {
		if origin, err := parseAllowedOrigin(value); err == nil {
			c.AllowedOrigins[i] = origin
		}
	}
	slices.Sort(c.AllowedOrigins)
	c.AllowedOrigins = slices.Compact(c.AllowedOrigins)
	if c.Browser != nil {
		browser := *c.Browser
		browser.ResourceOrigins = slices.Clone(browser.ResourceOrigins)
		if browser.Mode == "" {
			browser.Mode = "off"
		}
		if browser.Timeout == 0 {
			browser.Timeout = 30 * time.Second
		}
		if browser.Settle == 0 {
			browser.Settle = 2 * time.Second
		}
		for i, value := range browser.ResourceOrigins {
			if origin, err := parseAllowedOrigin(value); err == nil {
				browser.ResourceOrigins[i] = origin
			}
		}
		slices.Sort(browser.ResourceOrigins)
		browser.ResourceOrigins = slices.Compact(browser.ResourceOrigins)
		c.Browser = &browser
	}
	return c
}

func (c Config) validate() error {
	if c.Concurrency <= 0 {
		return errors.New("concurrency must be positive")
	}
	if c.MaxBodyBytes <= 0 {
		return errors.New("decoded body limit must be positive")
	}
	if c.RequestTimeout <= 0 || c.TargetTimeout <= 0 {
		return errors.New("request and target timeouts must be positive")
	}
	if c.MaxRequests <= 0 || c.MaxConnections <= 0 {
		return errors.New("request and connection budgets must be positive")
	}
	if c.MaxRedirects < 0 {
		return errors.New("maximum redirects must be nonnegative")
	}
	for _, rate := range []float64{c.RequestsPerSecond, c.PerOriginRequestsPerSecond} {
		if rate < 0 || math.IsNaN(rate) || math.IsInf(rate, 0) {
			return errors.New("request rates must be finite and nonnegative")
		}
	}
	switch c.RedirectPolicy {
	case "canonical-host", "same-origin", "none":
	case "allowlist":
		if len(c.AllowedOrigins) == 0 {
			return errors.New("allowlist redirect policy requires allowed origins")
		}
	default:
		return errors.New("redirect policy must be canonical-host, same-origin, none, or allowlist")
	}
	for _, value := range c.AllowedOrigins {
		if _, err := parseAllowedOrigin(value); err != nil {
			return fmt.Errorf("allowed origin %q: %w", value, err)
		}
	}
	for _, header := range c.Headers {
		if !httpmeta.ValidHeaderName(header.Name) || !httpmeta.ValidHeaderValue(header.Value) {
			return fmt.Errorf("invalid request header %q", header.Name)
		}
	}
	if c.BaselineOnly && c.FastMode {
		return errors.New("baseline and fast modes are mutually exclusive")
	}
	if b := c.Browser; b != nil {
		switch b.Mode {
		case "off":
			if b.Path != "" || len(b.ResourceOrigins) != 0 || b.SaveText != nil || b.SaveScreenshot != nil {
				return errors.New("browser options require navigate or screenshot mode")
			}
			return nil
		case "navigate", "screenshot":
		default:
			return errors.New("browser mode must be off, navigate, or screenshot")
		}
		if c.Passive {
			return errors.New("saved evidence cannot select live browser capture")
		}
		if runtime.GOOS != "linux" {
			return errors.New("local browser capture currently supports Linux only")
		}
		if b.Timeout <= 0 || b.Settle <= 0 || b.Settle >= b.Timeout {
			return errors.New("browser settle interval must be positive and smaller than its timeout")
		}
		if b.SaveScreenshot != nil && b.Mode != "screenshot" {
			return errors.New("saving screenshots requires browser screenshot mode")
		}
		if err := browserruntime.ValidateExecutable(b.Path); err != nil {
			return err
		}
		for _, origin := range b.ResourceOrigins {
			if _, err := parseAllowedOrigin(origin); err != nil {
				return fmt.Errorf("browser resource origin %q: %w", origin, err)
			}
		}
	}
	return nil
}
