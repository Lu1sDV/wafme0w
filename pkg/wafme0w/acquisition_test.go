package wafme0w

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func runBaseline(t *testing.T, target string, config Config) Result {
	t.Helper()
	config.BaselineOnly = true
	var result Result
	calls := 0
	if err := Run(context.Background(), emptyEngine(t), strings.NewReader(target), config, func(value Result) error {
		result = value
		calls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("emitted %d target results", calls)
	}
	return result
}

func TestBaselinePreservesTargetIdentityAndEffectiveSettings(t *testing.T) {
	requests := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.RequestURI
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := Config{Concurrency: 1, MaxBodyBytes: 32}
	target := server.URL + "/Case%2fPath?Token=MiXeD%2B"
	result := runBaseline(t, " \t"+target+" \n", config)
	if result.Target != target || result.Origin != server.URL || <-requests != "/Case%2fPath?Token=MiXeD%2B" {
		t.Fatalf("target identity or baseline changed: %+v", result)
	}
	if len(result.Evidence) != 1 || result.Evidence[0].Role != "Normal" || result.Evidence[0].RequestURL != target || result.Evidence[0].EffectiveURL != target {
		t.Fatalf("baseline evidence identity changed: %+v", result.Evidence)
	}
	defaults := DefaultConfig()
	settings := result.Provenance.Settings
	if settings.RequestTimeout != defaults.RequestTimeout || settings.TargetTimeout != defaults.TargetTimeout || settings.MaxRequests != defaults.MaxRequests || settings.MaxConnections != defaults.MaxConnections || settings.MaxRedirects != 0 {
		t.Fatalf("effective legacy configuration not reported: %+v", settings)
	}
	if result.SchemaVersion != ResultSchemaVersion || result.Provenance.ProgramVersion != Version() || result.Provenance.CatalogueSHA256 != emptyEngine(t).Digest() || result.Provenance.ScanMode != "baseline" {
		t.Fatalf("result provenance missing: %+v", result.Provenance)
	}
}

func TestRedirectScopeBudgetAndProvenance(t *testing.T) {
	for _, test := range []struct {
		name, path, destination, policy, code           string
		redirects, budget, localHits, otherHits, status int
		allowOther                                      bool
		chain                                           []string
	}{
		{name: "same origin", path: "/start", destination: "/done", redirects: 5, budget: 10, localHits: 2, status: 204, chain: []string{"/done"}},
		{name: "cross origin denied", path: "/start", destination: "other", redirects: 5, budget: 10, localHits: 1, status: 302, code: "redirect_scope"},
		{name: "exact allowlist", path: "/start", destination: "other", policy: "allowlist", redirects: 5, budget: 10, localHits: 1, otherHits: 1, status: 204, allowOther: true, chain: []string{"other"}},
		{name: "no redirects", path: "/start", destination: "/done", policy: "none", redirects: 5, budget: 10, localHits: 1, status: 302},
		{name: "zero redirect cap", path: "/start", destination: "/done", redirects: 0, budget: 10, localHits: 1, status: 302},
		{name: "hop bound", path: "/start", destination: "/middle", redirects: 1, budget: 10, localHits: 2, status: 302, code: "redirect_limit", chain: []string{"/middle"}},
		{name: "loop", path: "/start", destination: "/start", redirects: 5, budget: 10, localHits: 1, status: 302, code: "redirect_loop"},
		{name: "redirect consumes budget", path: "/start", destination: "/done", redirects: 5, budget: 1, localHits: 1, status: 302, code: "request_budget"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var localHits, otherHits atomic.Int32
			other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				otherHits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer other.Close()
			destination := test.destination
			if destination == "other" {
				destination = other.URL + "/done"
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				localHits.Add(1)
				switch r.URL.Path {
				case "/start":
					http.Redirect(w, r, destination, http.StatusFound)
				case "/middle":
					http.Redirect(w, r, "/done", http.StatusFound)
				default:
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()
			config := DefaultConfig()
			config.RedirectPolicy, config.MaxRedirects, config.MaxRequests = test.policy, test.redirects, test.budget
			if test.allowOther {
				config.AllowedOrigins = []string{server.URL, other.URL}
			}
			result := runBaseline(t, server.URL+test.path, config)
			observation := result.Evidence[0]
			if int(localHits.Load()) != test.localHits || int(otherHits.Load()) != test.otherHits || observation.StatusCode != test.status || observation.ErrorCode != test.code {
				t.Fatalf("redirect escaped policy: local=%d other=%d evidence=%+v", localHits.Load(), otherHits.Load(), observation)
			}
			var chain []string
			for _, path := range test.chain {
				if path == "other" {
					chain = append(chain, other.URL+"/done")
				} else {
					chain = append(chain, server.URL+path)
				}
			}
			if !reflect.DeepEqual(observation.RedirectChain, chain) {
				t.Fatalf("redirect provenance = %v, want %v", observation.RedirectChain, chain)
			}
			wantEffective := server.URL + test.path
			if len(chain) > 0 {
				wantEffective = chain[len(chain)-1]
			}
			if observation.RequestURL != server.URL+test.path || observation.EffectiveURL != wantEffective {
				t.Fatalf("request/effective URL lost: %+v", observation)
			}
		})
	}
}

func TestCanonicalRedirectScope(t *testing.T) {
	for _, test := range []struct {
		name, target, policy string
		redirects, allow     []string
		followed             int
	}{
		{name: "add www", target: "https://fixture.invalid/start", redirects: []string{"https://www.fixture.invalid/nl/nl/?lang=nl"}, followed: 1},
		{name: "remove www", target: "https://www.fixture.invalid/start", redirects: []string{"https://fixture.invalid/done"}, followed: 1},
		{name: "normalized host and port", target: "https://fixture.invalid:443/start", redirects: []string{"https://WWW.FIXTURE.INVALID/done"}, followed: 1},
		{name: "preserve custom port", target: "https://fixture.invalid:8443/start", redirects: []string{"https://www.fixture.invalid:8443/done"}, followed: 1},
		{name: "different port", target: "https://fixture.invalid/start", redirects: []string{"https://www.fixture.invalid:8443/done"}},
		{name: "scheme downgrade", target: "https://fixture.invalid/start", redirects: []string{"http://www.fixture.invalid/done"}},
		{name: "different subdomain", target: "https://fixture.invalid/start", redirects: []string{"https://shop.fixture.invalid/done"}},
		{name: "suffix lookalike", target: "https://fixture.invalid/start", redirects: []string{"https://www.fixture.invalid.other.invalid/done"}},
		{name: "IP is not a DNS alias", target: "http://127.0.0.1/start", redirects: []string{"http://www.127.0.0.1/done"}},
		{name: "single label is not a DNS alias", target: "https://fixture/start", redirects: []string{"https://www.fixture/done"}},
		{name: "explicit same-origin remains strict", target: "https://fixture.invalid/start", policy: "same-origin", redirects: []string{"https://www.fixture.invalid/done"}},
		{name: "explicit allowlist restricts aliases", target: "https://fixture.invalid/start", allow: []string{"https://fixture.invalid"}, redirects: []string{"https://www.fixture.invalid/done"}},
		{name: "both origins allowlisted", target: "https://fixture.invalid/start", allow: []string{"https://fixture.invalid", "https://www.fixture.invalid"}, redirects: []string{"https://www.fixture.invalid/done"}, followed: 1},
		{name: "chain cannot add another www", target: "https://fixture.invalid/start", redirects: []string{"https://www.fixture.invalid/middle", "https://www.www.fixture.invalid/done"}, followed: 1},
		{name: "alias can redirect back", target: "https://fixture.invalid/start", redirects: []string{"https://www.fixture.invalid/middle", "https://fixture.invalid/done"}, followed: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var visited []string
			config := DefaultConfig()
			config.RedirectPolicy, config.AllowedOrigins = test.policy, test.allow
			config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				visited = append(visited, req.URL.String())
				if len(visited) <= len(test.redirects) {
					return &http.Response{StatusCode: http.StatusFound, Header: http.Header{
						"Location": {test.redirects[len(visited)-1]},
					}, Body: http.NoBody}, nil
				}
				return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody}, nil
			})}
			result := runBaseline(t, test.target, config)
			wantVisited := append([]string{test.target}, test.redirects[:test.followed]...)
			if !reflect.DeepEqual(visited, wantVisited) {
				t.Fatalf("redirect scope reached %v, want %v", visited, wantVisited)
			}
			observation := result.Evidence[0]
			wantStatus, wantCode := http.StatusNoContent, ""
			if test.followed < len(test.redirects) {
				wantStatus, wantCode = http.StatusFound, "redirect_scope"
			}
			if observation.StatusCode != wantStatus || observation.ErrorCode != wantCode ||
				observation.RequestURL != test.target || observation.EffectiveURL != wantVisited[len(wantVisited)-1] ||
				!slices.Equal(observation.RedirectChain, wantVisited[1:]) {
				t.Fatalf("redirect result lost scope or provenance: %+v", observation)
			}
		})
	}
}

func TestAllowlistRestrictsStartingURLBeforeTransport(t *testing.T) {
	config := DefaultConfig()
	config.AllowedOrigins = []string{"HTTPS://Allowed.invalid:443/"}
	config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("out-of-scope target reached transport")
		return nil, errors.New("unexpected request")
	})}
	result := runBaseline(t, "https://other.invalid/Case", config)
	if result.Outcome.State != Failed || len(result.Outcome.Diagnostics) != 1 || result.Outcome.Diagnostics[0].Code != "target_scope" {
		t.Fatalf("scope violation not reported: %+v", result)
	}
	if !reflect.DeepEqual(result.Provenance.Settings.AllowedOrigins, []string{"https://allowed.invalid"}) {
		t.Fatalf("allowlist origins not canonical: %+v", result.Provenance.Settings)
	}
}

func TestCallerRedirectPolicyCannotWidenScopeOrBeMutated(t *testing.T) {
	var calls atomic.Int32
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"http://other.invalid/"}}, Body: io.NopCloser(strings.NewReader("inert"))}, nil
	})
	redirect := func(*http.Request, []*http.Request) error { return nil }
	client := &http.Client{Transport: transport, CheckRedirect: redirect, Timeout: time.Second}
	config := DefaultConfig()
	config.Client = client
	result := runBaseline(t, "http://fixture.invalid/", config)
	if calls.Load() != 1 || result.Evidence[0].ErrorCode != "redirect_scope" {
		t.Fatalf("injected redirect callback widened policy: %+v", result)
	}
	if reflect.ValueOf(client.Transport).Pointer() != reflect.ValueOf(transport).Pointer() || reflect.ValueOf(client.CheckRedirect).Pointer() != reflect.ValueOf(redirect).Pointer() || client.Timeout != time.Second {
		t.Fatal("caller client was mutated")
	}
}

func TestGlobalInflightLimitIncludesBodiesAndCancelsWaiters(t *testing.T) {
	started := make(chan struct{}, 2)
	config := DefaultConfig()
	config.Concurrency, config.MaxConnections, config.BaselineOnly = 2, 1, true
	config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		started <- struct{}{}
		return &http.Response{StatusCode: 200, Body: &contextBody{ctx: req.Context()}}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := emptyEngine(t)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, engine, strings.NewReader("http://one.invalid\nhttp://two.invalid\n"), config, func(Result) error { return nil })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first request did not start")
	}
	select {
	case <-started:
		t.Fatal("second request bypassed occupied response-body slot")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("connection wait or body reader leaked")
	}
}

type contextBody struct{ ctx context.Context }

func (b *contextBody) Read([]byte) (int, error) { <-b.ctx.Done(); return 0, b.ctx.Err() }
func (b *contextBody) Close() error             { return nil }

func TestRequestAndTargetDeadlinesBoundResponseBody(t *testing.T) {
	for _, targetDeadline := range []bool{false, true} {
		config := DefaultConfig()
		config.RequestTimeout = 30 * time.Millisecond
		if targetDeadline {
			config.RequestTimeout, config.TargetTimeout = time.Second, 30*time.Millisecond
		}
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: &contextBody{ctx: req.Context()}}, nil
		})}
		started := time.Now()
		result := runBaseline(t, "http://fixture.invalid", config)
		if time.Since(started) > time.Second || result.Evidence[0].ErrorCode == "" || result.Evidence[0].StatusCode != 200 {
			t.Fatalf("deadline or partial response was lost: %+v", result)
		}
	}
}

func TestPacingCombinesGlobalAndPerOriginAndCancels(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.RequestsPerSecond, config.PerOriginRequestsPerSecond = 100, 20
		policy := newOutboundPolicy(config)
		admit := func(origin string) time.Time {
			t.Helper()
			if err := policy.acquire(context.Background(), origin); err != nil {
				t.Fatal(err)
			}
			<-policy.slots
			return time.Now()
		}
		first := admit("http://one.invalid")
		other := admit("http://two.invalid")
		repeated := admit("http://one.invalid")
		if other.Sub(first) != 10*time.Millisecond || repeated.Sub(first) != 50*time.Millisecond {
			t.Fatalf("pacing failed: global=%v per-origin=%v", other.Sub(first), repeated.Sub(first))
		}
		waitCtx, stop := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- policy.acquire(waitCtx, "http://one.invalid") }()
		synctest.Wait()
		stop()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("pending pacing ignored cancellation: %v", err)
		}
		if len(policy.slots) != 0 {
			t.Fatal("cancelled pacing waiter retained an inflight slot")
		}
	})
}

func TestPolicyConfigurationFailsBeforeInput(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Config)
	}{
		{"negative timeout", func(c *Config) { c.RequestTimeout = -time.Second }},
		{"negative target timeout", func(c *Config) { c.TargetTimeout = -time.Second }},
		{"negative request budget", func(c *Config) { c.MaxRequests = -1 }},
		{"negative connection cap", func(c *Config) { c.MaxConnections = -1 }},
		{"negative redirect cap", func(c *Config) { c.MaxRedirects = -1 }},
		{"nonfinite global rate", func(c *Config) { c.RequestsPerSecond = math.NaN() }},
		{"nonfinite origin rate", func(c *Config) { c.PerOriginRequestsPerSecond = math.Inf(1) }},
		{"unknown redirect policy", func(c *Config) { c.RedirectPolicy = "unrestricted" }},
		{"missing allowlist", func(c *Config) { c.RedirectPolicy = "allowlist" }},
		{"origin contains path", func(c *Config) { c.AllowedOrigins = []string{"https://fixture.invalid/path"} }},
		{"conflicting live modes", func(c *Config) { c.BaselineOnly, c.FastMode = true, true }},
		{"passive live runner", func(c *Config) { c.Passive = true }},
		{"invalid header name", func(c *Config) { c.Headers = []Header{{Name: "Bad Name", Value: "value"}} }},
		{"invalid header value", func(c *Config) { c.Headers = []Header{{Name: "X-Test", Value: "value\r\nInjected: x"}} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultConfig()
			test.change(&config)
			readErr := errors.New("input was read")
			err := Run(context.Background(), emptyEngine(t), failingReader{readErr}, config, func(Result) error { t.Error("unexpected result"); return nil })
			if err == nil || errors.Is(err, readErr) {
				t.Fatalf("invalid policy reached input: %v", err)
			}
		})
	}
}

func TestRequestBudgetSharedAcrossExistingFastRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var requests atomic.Int32
		config := DefaultConfig()
		config.FastMode, config.MaxRequests = true, 1
		config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		})}
		var result Result
		if err := Run(context.Background(), emptyEngine(t), strings.NewReader("http://fixture.invalid/"), config, func(value Result) error { result = value; return nil }); err != nil {
			t.Fatal(err)
		}
		if requests.Load() != 1 || len(result.Evidence) != 3 || result.Evidence[0].StatusCode != 204 || result.Evidence[1].ErrorCode != "request_budget" || result.Evidence[2].ErrorCode != "request_budget" {
			t.Fatalf("parallel requests exceeded shared target budget: requests=%d evidence=%+v", requests.Load(), result.Evidence)
		}
	})
}
