package wafme0w

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"slices"
	"time"
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
	Client                     *http.Client
	CancelInput                func()
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
	for i, value := range c.AllowedOrigins {
		if origin, err := parseAllowedOrigin(value); err == nil {
			c.AllowedOrigins[i] = origin
		}
	}
	slices.Sort(c.AllowedOrigins)
	c.AllowedOrigins = slices.Compact(c.AllowedOrigins)
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
	if c.BaselineOnly && c.FastMode {
		return errors.New("baseline and fast modes are mutually exclusive")
	}
	return nil
}
