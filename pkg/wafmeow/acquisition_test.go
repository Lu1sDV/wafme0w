package wafmeow

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
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
	if settings.RequestTimeout != defaults.RequestTimeout || settings.TargetTimeout != defaults.TargetTimeout || settings.MaxRequests != defaults.MaxRequests || settings.MaxConnections != config.Concurrency || settings.ProbeConcurrency != 1 || settings.MaxRedirects != 0 {
		t.Fatalf("effective legacy configuration not reported: %+v", settings)
	}
	if settings.MaxResponseHeaderBytes != DefaultMaxResponseHeaderBytes || settings.MaxTargetEvidenceBytes != DefaultMaxTargetEvidenceBytes {
		t.Fatalf("effective HTTP evidence limits not reported: %+v", settings)
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
		{"negative probe concurrency", func(c *Config) { c.ProbeConcurrency = -1 }},
		{"excess probe concurrency", func(c *Config) { c.ProbeConcurrency = 9 }},
		{"negative response header budget", func(c *Config) { c.MaxResponseHeaderBytes = -1 }},
		{"negative retained evidence budget", func(c *Config) { c.MaxTargetEvidenceBytes = -1 }},
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
		usable, exhausted := 0, 0
		for _, observation := range result.Evidence {
			if observation.StatusCode == 204 {
				usable++
			}
			if observation.ErrorCode == "request_budget" {
				exhausted++
			}
		}
		if requests.Load() != 1 || len(result.Evidence) != 3 || usable != 1 || exhausted != 2 {
			t.Fatalf("parallel requests exceeded shared target budget: requests=%d evidence=%+v", requests.Load(), result.Evidence)
		}
	})
}

func TestDefaultTransportDoesNotRetryOutsideRequestBudget(t *testing.T) {
	var connections sync.Map
	var retries atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, reused := connections.LoadOrStore(r.RemoteAddr, struct{}{})
		if r.URL.Path == "/retry" {
			retries.Add(1)
			if reused {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = connection.Close()
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Concurrency, config.MaxConnections, config.MaxRequests = 1, 1, 1
	config.BaselineOnly = true
	var results []Result
	input := strings.NewReader(server.URL + "/warm\n" + server.URL + "/retry\n")
	if err := Run(context.Background(), emptyEngine(t), input, config, func(result Result) error {
		results = append(results, result)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := retries.Load(); got != 1 {
		t.Fatalf("one-request target budget sent %d requests after a reused connection failed", got)
	}
	connectionCount := 0
	connections.Range(func(_, _ any) bool {
		connectionCount++
		return true
	})
	if connectionCount != 2 {
		t.Fatalf("two bounded requests used %d connections, want 2 fresh connections", connectionCount)
	}
	if len(results) != 2 {
		t.Fatalf("emitted %d results, want 2", len(results))
	}
	for _, result := range results {
		if len(result.Evidence) != 1 || result.Evidence[0].StatusCode != http.StatusNoContent || result.Evidence[0].ErrorCode != "" {
			t.Fatalf("lost successful target evidence: %+v", result)
		}
	}
}

func TestDefaultTransportRetainsUnansweredRequestFailure(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	config := DefaultConfig()
	config.MaxRequests = 1
	result := runBaseline(t, server.URL, config)
	if requests.Load() != 1 || len(result.Evidence) != 1 || result.Evidence[0].StatusCode != 0 ||
		result.Evidence[0].ErrorCode != "transport_error" || len(result.Outcome.Diagnostics) == 0 {
		t.Fatalf("unanswered probe was replayed or lost its failure: requests=%d result=%+v", requests.Load(), result)
	}
}

func TestRunPreservesCallerTransportConnectionReuse(t *testing.T) {
	var connections sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connections.Store(r.RemoteAddr, struct{}{})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	config := DefaultConfig()
	config.Client = server.Client()
	defer config.Client.CloseIdleConnections()
	for range 2 {
		result := runBaseline(t, server.URL, config)
		if result.Evidence[0].StatusCode != http.StatusNoContent || result.Evidence[0].ErrorCode != "" {
			t.Fatalf("caller transport lost response: %+v", result)
		}
	}
	connectionCount := 0
	connections.Range(func(_, _ any) bool {
		connectionCount++
		return true
	})
	if connectionCount != 1 {
		t.Fatalf("Run changed or closed caller transport reuse: observed %d connections", connectionCount)
	}
}

func acquireHTTPFixture(t *testing.T, target string, config Config) []Evidence {
	t.Helper()
	config = config.normalized()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	policy := newOutboundPolicy(config)
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	return sendRequests(ctx, target, policy.client(normalizedOrigin(u)), config)
}

// Match the documented payload accounting, not allocator-dependent heap sizes.
func retainedHTTPFixtureBytes(evidence []Evidence) int64 {
	var total int64
	for _, observation := range evidence {
		total += int64(len(observation.RequestURL) + len(observation.EffectiveURL) + len(observation.Reason) + cap(observation.Body))
		for _, destination := range observation.RedirectChain {
			total += 16 + int64(len(destination))
		}
		for _, header := range observation.Headers {
			total += 32 + int64(len(header.Name)+len(header.Value))
		}
	}
	return total
}

func TestHostileResponseHeadersRejectedBeforeRetention(t *testing.T) {
	huge := strings.Repeat("h", 2<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Hostile", huge)
		_, _ = io.WriteString(w, "x")
	}))
	defer server.Close()
	for _, injected := range []bool{false, true} {
		t.Run(map[bool]string{false: "owned transport", true: "injected transport"}[injected], func(t *testing.T) {
			config := DefaultConfig()
			config.MaxBodyBytes, config.BaselineOnly = 1, true
			if injected {
				transport := http.DefaultTransport.(*http.Transport).Clone()
				transport.MaxResponseHeaderBytes = 4 << 20
				defer transport.CloseIdleConnections()
				config.Client = &http.Client{Transport: transport}
			}
			evidence := acquireHTTPFixture(t, server.URL, config)
			if len(evidence) != 1 || evidence[0].StatusCode != 0 || len(evidence[0].Headers) != 0 || len(evidence[0].Body) != 0 || evidence[0].ErrorCode == "" {
				t.Fatalf("hostile headers retained or accepted as complete: %+v", evidence)
			}
			if injected && config.Client.Transport.(*http.Transport).MaxResponseHeaderBytes != 4<<20 {
				t.Fatal("caller transport header policy was mutated")
			}
			engine, err := Compile([]WAF{{Name: "header fixture", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "X-Hostile", HeaderValue: "h"}}}}}})
			if err != nil {
				t.Fatal(err)
			}
			if outcome := engine.Classify(evidence); outcome.State != Incomplete || len(outcome.Diagnostics) == 0 {
				t.Fatalf("rejected headers became a clean negative: %+v", outcome)
			}
		})
	}
}

func TestRetainedHTTPBudgetExactAndOverflow(t *testing.T) {
	var bodyBytes atomic.Int64
	bodyBytes.Store(64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT")
		w.Header().Set("Server", "fixture")
		_, _ = io.WriteString(w, strings.Repeat("x", int(bodyBytes.Load())))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.BaselineOnly = true
	original := acquireHTTPFixture(t, server.URL, config)
	exact := retainedHTTPFixtureBytes(original) - int64(cap(original[0].Body)) + int64(len(original[0].Body))
	config.MaxTargetEvidenceBytes = exact
	evidence := acquireHTTPFixture(t, server.URL, config)
	if len(evidence) != 1 || evidence[0].StatusCode != 200 || len(evidence[0].Body) != 64 || evidence[0].BodyTruncated || evidence[0].ErrorCode != "" || retainedHTTPFixtureBytes(evidence) != exact {
		t.Fatalf("exact retained budget rejected: %+v", evidence)
	}
	bodyBytes.Store(65)
	evidence = acquireHTTPFixture(t, server.URL, config)
	if evidence[0].StatusCode != 200 || len(evidence[0].Body) != 64 || !evidence[0].BodyTruncated || evidence[0].ErrorCode != "evidence_budget" || retainedHTTPFixtureBytes(evidence) > exact {
		t.Fatalf("body overflow lost metadata or exceeded budget: %+v", evidence)
	}
	engine, err := Compile([]WAF{
		{Name: "header", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Header", HeaderKey: "Server", HeaderValue: "fixture"}}}}},
		{Name: "body", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "x"}}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome := engine.Classify(evidence)
	if outcome.State != Incomplete || len(outcome.Matches) != 1 || outcome.Matches[0].Product != "header" || !slices.Equal(outcome.IncompleteProducts, []string{"body"}) {
		t.Fatalf("body budget changed three-valued matching: %+v", outcome)
	}
	config.MaxTargetEvidenceBytes = exact - 65 // One byte less than metadata alone.
	evidence = acquireHTTPFixture(t, server.URL, config)
	if evidence[0].StatusCode != 0 || len(evidence[0].Headers) != 0 || len(evidence[0].Body) != 0 || evidence[0].ErrorCode != "evidence_budget" || retainedHTTPFixtureBytes(evidence) != 0 {
		t.Fatalf("partial metadata retained as a usable header set: %+v", evidence)
	}
}

func TestRetainedHTTPBudgetConcurrentFastProbes(t *testing.T) {
	arrived := make(chan struct{}, 3)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Server", "fixture")
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}))
	defer server.Close()
	config := DefaultConfig()
	config.FastMode, config.MaxBodyBytes, config.MaxTargetEvidenceBytes = true, 4096, 5000
	done := make(chan []Evidence, 1)
	go func() {
		policy := newOutboundPolicy(config)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- sendRequests(ctx, server.URL, policy.client(server.URL), config)
	}()
	for range 3 {
		select {
		case <-arrived:
		case <-time.After(3 * time.Second):
			close(release)
			<-done
			t.Fatal("fast probes did not overlap")
		}
	}
	close(release)
	evidence := <-done
	if len(evidence) != 3 || retainedHTTPFixtureBytes(evidence) > config.MaxTargetEvidenceBytes {
		t.Fatalf("concurrent probes exceeded shared retained budget: %+v", evidence)
	}
	var usable, diagnosed bool
	for _, observation := range evidence {
		usable = usable || observation.StatusCode == 200
		diagnosed = diagnosed || observation.ErrorCode == "evidence_budget"
	}
	if !usable || !diagnosed {
		t.Fatalf("budget did not preserve usable evidence and report overflow: %+v", evidence)
	}
}

func TestDefaultRetainedHTTPBudgetPreservesNineFullBodies(t *testing.T) {
	body := strings.Repeat("x", int(DefaultMaxBodyBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "fixture")
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	evidence := acquireHTTPFixture(t, server.URL, DefaultConfig())
	if len(evidence) != 9 {
		t.Fatalf("captured %d probes, want 9", len(evidence))
	}
	for _, observation := range evidence {
		if observation.StatusCode != 200 || len(observation.Body) != len(body) || observation.BodyTruncated || observation.ErrorCode != "" {
			t.Fatalf("ordinary full body lost to default retained budget: %+v", observation)
		}
	}
	if retainedHTTPFixtureBytes(evidence) > DefaultMaxTargetEvidenceBytes {
		t.Fatal("default evidence exceeded its retained budget")
	}
}

func TestConfiguredHeaderLimitStillHonorsAggregateBudget(t *testing.T) {
	huge := strings.Repeat("h", 2<<20)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", huge)
		_, _ = io.WriteString(w, "x")
	}))
	defer server.Close()
	config := DefaultConfig()
	config.MaxBodyBytes = 1
	config.MaxResponseHeaderBytes = 3 << 20
	config.MaxTargetEvidenceBytes = 5 << 20
	evidence := acquireHTTPFixture(t, server.URL, config)
	if len(evidence) != 9 || retainedHTTPFixtureBytes(evidence) > config.MaxTargetEvidenceBytes {
		t.Fatalf("configured large headers escaped aggregate bound: observations=%d bytes=%d", len(evidence), retainedHTTPFixtureBytes(evidence))
	}
	for i, observation := range evidence {
		if i < 2 {
			if observation.StatusCode != 200 || observation.ErrorCode != "" || len(observation.Body) != 1 {
				t.Fatalf("usable early response %d lost: %+v", i, observation)
			}
		} else if observation.StatusCode != 0 || len(observation.Headers) != 0 || observation.ErrorCode != "evidence_budget" {
			t.Fatalf("overflow response %d retained partial metadata: %+v", i, observation)
		}
	}
}

func TestRetainedHTTPBudgetExtremeLimitsDoNotOverflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "small response")
	}))
	defer server.Close()
	config := DefaultConfig()
	config.BaselineOnly = true
	config.MaxTargetEvidenceBytes, config.MaxResponseHeaderBytes, config.MaxBodyBytes = math.MaxInt64, math.MaxInt64, math.MaxInt64
	evidence := acquireHTTPFixture(t, server.URL, config)
	if len(evidence) != 1 || evidence[0].StatusCode != 200 || string(evidence[0].Body) != "small response" || evidence[0].BodyTruncated || evidence[0].ErrorCode != "" {
		t.Fatalf("large configured limits overflowed: %+v", evidence)
	}
}

func TestRetainedHTTPBudgetDoesNotReserveUnusedFastBodyLimits(t *testing.T) {
	arrived := make(chan struct{}, 3)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1")
		w.Header().Set("Server", "fixture")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		arrived <- struct{}{}
		select {
		case <-release:
			_, _ = io.WriteString(w, "x")
		case <-r.Context().Done():
		}
	}))
	defer server.Close()
	config := DefaultConfig()
	config.FastMode, config.MaxTargetEvidenceBytes = true, 4<<10
	done := make(chan []Evidence, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		policy := newOutboundPolicy(config)
		done <- sendRequests(ctx, server.URL, policy.client(server.URL), config)
	}()
	for range 3 {
		select {
		case <-arrived:
		case <-time.After(3 * time.Second):
			close(release)
			<-done
			t.Fatal("fast response headers did not overlap blocked body reads")
		}
	}
	close(release)
	evidence := <-done
	if len(evidence) != 3 || retainedHTTPFixtureBytes(evidence) > config.MaxTargetEvidenceBytes {
		t.Fatalf("small concurrent responses exceeded budget: %+v", evidence)
	}
	for _, observation := range evidence {
		if observation.StatusCode != 200 || string(observation.Body) != "x" || observation.BodyTruncated || observation.ErrorCode != "" {
			t.Fatalf("unused 1 MiB body allowance starved a tiny response: %+v", evidence)
		}
	}
}
