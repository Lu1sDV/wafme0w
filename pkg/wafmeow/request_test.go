package wafmeow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// The encoded wire expectations below are authored from the reviewed payloads,
// not from request.go or requestURL. Deriving them from the implementation
// would bless the same payload regression these tests exist to catch. Spaces
// become "+", escapes are uppercase hexadecimal, and parameter names are
// sorted, as application/x-www-form-urlencoded requires.
const (
	wantXSSToken     = "p=%22%3E%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E"
	wantXXEToken     = "p=%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fshadow%22%3E%5D%3E%3Cpwn%3E%26hack%3B%3C%2Fpwn%3E"
	wantLFIToken     = "p=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
	wantJNDIToken    = "p=%24%7Bjndi%3Aldap%3A%2F%2F127.0.0.1%3A1%2Fa%7D"
	wantCentralToken = "c=%3Bwafmeow-canary&d=%22%3E%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E&h=%28%29+%7B+%3A%3B%7D%3B&l=..%2F..%2F..%2F..%2Fetc%2Fpasswd&l2=..%5C..%5C..%5C..%5Cetc%5Cpasswd&r=%0D%0AX-Wafmeow%3A+canary&v=%27+OR+1%3D1+UNION+SELECT+ALL+FROM+information_schema+AND+%27+or+SLEEP%285%29+or+%27--+-%22%3E%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E"
)

// newTypeOptions draws rand.Intn(900001)+100000, so the random-path probe
// spans 100000.html through the valid seven-digit 1000000.html.
var randomPathExpr = regexp.MustCompile(`^/(?:[1-9][0-9]{5}|1000000)\.html$`)

// activeProbes is the full-mode probe set after removing the standalone
// SqliAttack and RceAttack requests. Order follows the catalogue.
func activeProbes() []struct{ role, query string } {
	return []struct{ role, query string }{
		{"XssAttack", wantXSSToken},
		{"XxeAttack", wantXXEToken},
		{"LfiAttack", wantLFIToken},
		{"CentralAttack", wantCentralToken},
		{"JndiAttack", wantJNDIToken},
	}
}

func TestActiveProbePayloadsOnWire(t *testing.T) {
	type observed struct{ method, uri string }
	// Existing query bytes, duplicate keys, and keys also used by a probe must
	// survive unchanged. LFI remains a query value, not a rewritten target path.
	const existingQuery = "Token=Ab%2F%2b&dup=one&dup=two&p=before&d=keep%20me&l=keep%2fme&v=keep%2bme&c=keep%3bme&h=keep%20h&r=keep%0d%0a"
	for _, target := range []struct {
		name string
		path string
	}{
		{"escaped-path", "/Case%2fKept/"},
		{"literal-dot-segments", "/prefix/../../Case%2fKept/"},
		{"encoded-dot-segments", "/prefix/%2e%2E/Case%2fKept/"},
	} {
		t.Run(target.name, func(t *testing.T) {
			baseURI := target.path + "?" + existingQuery
			for _, probe := range activeProbes() {
				t.Run(probe.role, func(t *testing.T) {
					requests := make(chan observed, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						select {
						case requests <- observed{r.Method, r.RequestURI}:
						default:
							t.Error("unexpected extra probe request")
						}
						w.WriteHeader(http.StatusNoContent)
					}))
					defer server.Close()
					var option requestOpts
					found := false
					for _, candidate := range newTypeOptions(server.URL + baseURI) {
						if candidate.Type == probe.role {
							option, found = candidate, true
						}
					}
					if !found {
						t.Fatalf("missing active probe %q", probe.role)
					}
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					evidence, err := sendHTTP(ctx, option, server.Client(), 32)
					if err != nil {
						t.Fatal(err)
					}
					var got observed
					select {
					case got = <-requests:
					default:
						t.Fatal("probe returned without reaching the loopback server")
					}
					wantURI := target.path + "?" + existingQuery + "&" + probe.query
					if got.method != http.MethodGet || got.uri != wantURI {
						t.Fatalf("probe changed on wire: got %s %q, want GET %q", got.method, got.uri, wantURI)
					}
					if evidence.Role != probe.role || evidence.RequestURL != server.URL+wantURI || evidence.EffectiveURL != server.URL+wantURI || evidence.StatusCode != http.StatusNoContent {
						t.Fatalf("wire request lost probe provenance: %+v", evidence)
					}
				})
			}
		})
	}
}

func TestActiveProbeInventoryIsReviewed(t *testing.T) {
	var roles []string
	for _, option := range newTypeOptions("http://fixture.invalid/base") {
		roles = append(roles, option.Type)
	}
	want := []string{"Normal", "NoUserAgent", "NonExistent", "XssAttack", "XxeAttack", "LfiAttack", "CentralAttack", "JndiAttack"}
	if !slices.Equal(roles, want) {
		t.Fatalf("probe inventory = %q, want exactly %q", roles, want)
	}
}

func TestAppendedDotSegmentsOnWire(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		path   string
		want   string
	}{
		{
			"literal-dot-segments",
			"/prefix/Case%2fKept?dup=one&dup=two&Token=Ab%2b",
			"/../../leaf",
			"/prefix/Case%2fKept/../../leaf?dup=one&dup=two&Token=Ab%2b",
		},
		{
			"encoded-dot-segments",
			"/prefix/Case%2fKept/?dup=one&dup=two&Token=Ab%2b",
			"/%2e%2E/leaf",
			"/prefix/Case%2fKept/%2e%2E/leaf?dup=one&dup=two&Token=Ab%2b",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan string, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				select {
				case requests <- r.RequestURI:
				default:
					t.Error("unexpected extra path request")
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			option := requestOpts{Method: http.MethodGet, Target: server.URL + test.target, Path: test.path}
			if _, err := sendHTTP(ctx, option, server.Client(), 32); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-requests:
				if got != test.want {
					t.Fatalf("appended path normalized on wire: got %q, want %q", got, test.want)
				}
			default:
				t.Fatal("request returned without reaching the loopback server")
			}
		})
	}
}

// TestProbeModesOnWire pins which requests each mode actually sends. The JNDI
// canary is full-mode only, and fast mode replaces the five active probes with
// the combined probe.
func TestProbeModesOnWire(t *testing.T) {
	for _, test := range []struct {
		name   string
		config func(*Config)
		roles  []string
	}{
		{"baseline", func(c *Config) { c.BaselineOnly = true }, []string{"Normal"}},
		{"fast", func(c *Config) { c.FastMode = true }, []string{"Normal", "NoUserAgent", "CentralAttack"}},
		{"full", func(*Config) {}, []string{"Normal", "NoUserAgent", "NonExistent", "XssAttack", "XxeAttack", "LfiAttack", "CentralAttack", "JndiAttack"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mutex sync.Mutex
			var observed []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mutex.Lock()
				observed = append(observed, r.RequestURI)
				mutex.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			config := DefaultConfig()
			test.config(&config)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			evidence := sendRequests(ctx, server.URL, server.Client(), config)
			roles := make([]string, len(evidence))
			for index, observation := range evidence {
				roles[index] = observation.Role
				if observation.StatusCode != http.StatusOK || observation.TransportError != "" || observation.ErrorCode != "" || observation.BodyTruncated {
					t.Fatalf("mode %s did not retain a successful response: %+v", test.name, observation)
				}
			}
			if !slices.Equal(roles, test.roles) {
				t.Fatalf("mode %s probe roles = %q, want %q", test.name, roles, test.roles)
			}
			mutex.Lock()
			wire := append([]string(nil), observed...)
			mutex.Unlock()
			assertModeRequests(t, test.name, wire, test.roles)
			if got := GenericDetect(evidence); got != (GenericDetection{}) {
				t.Fatalf("mode %s invented a generic anomaly from unchanged responses: %+v", test.name, got)
			}
		})
	}
}

// assertModeRequests compares on-wire request URIs with literal expectations.
// NonExistent carries a random numeric path (100000..1000000.html), so it
// is checked by shape and range rather than a fixed value.
func assertModeRequests(t *testing.T, mode string, observed []string, roles []string) {
	t.Helper()
	var fixed, random []string
	for _, uri := range observed {
		if randomPathExpr.MatchString(uri) {
			random = append(random, uri)
		} else {
			fixed = append(fixed, uri)
		}
	}
	wantRandom := 0
	var wantFixed []string
	for _, role := range roles {
		switch role {
		case "Normal", "NoUserAgent":
			wantFixed = append(wantFixed, "/")
		case "NonExistent":
			wantRandom++
		case "XssAttack":
			wantFixed = append(wantFixed, "/?"+wantXSSToken)
		case "XxeAttack":
			wantFixed = append(wantFixed, "/?"+wantXXEToken)
		case "LfiAttack":
			wantFixed = append(wantFixed, "/?"+wantLFIToken)
		case "CentralAttack":
			wantFixed = append(wantFixed, "/?"+wantCentralToken)
		case "JndiAttack":
			wantFixed = append(wantFixed, "/?"+wantJNDIToken)
		default:
			t.Fatalf("mode %s has unreviewed probe role %q", mode, role)
		}
	}
	if len(random) != wantRandom {
		t.Fatalf("mode %s sends %d random-path requests, want %d (%q)", mode, len(random), wantRandom, observed)
	}
	sort.Strings(fixed)
	sort.Strings(wantFixed)
	if !slices.Equal(fixed, wantFixed) {
		t.Fatalf("mode %s requests on wire:\n got %q\nwant %q", mode, fixed, wantFixed)
	}
}

// TestBlockedCombinedProbeKeepsAttributionCoarse exercises acquisition against
// a server that blocks only the SQL injection payload. Generic detection must
// attribute the status change to CentralAttack, not to an individual payload.
// This demonstrates the documented trade-off;
// it is not evidence of equivalent coverage to the removed standalone
// SqliAttack and RceAttack requests.
func TestBlockedCombinedProbeKeepsAttributionCoarse(t *testing.T) {
	for _, test := range []struct {
		name    string
		fast    bool
		wantLen int
	}{
		{"full", false, 8},
		{"fast", true, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.RequestURI, "UNION+SELECT") {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte("synthetic-edge-block"))
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			config := DefaultConfig()
			config.FastMode = test.fast
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			evidence := sendRequests(ctx, server.URL, server.Client(), config)
			if len(evidence) != test.wantLen {
				t.Fatalf("evidence count = %d, want %d", len(evidence), test.wantLen)
			}
			var blocked []string
			for _, observation := range evidence {
				if observation.Role == "SqliAttack" || observation.Role == "RceAttack" {
					t.Fatalf("removed probe role resurfaced: %q", observation.Role)
				}
				if observation.StatusCode == http.StatusForbidden {
					blocked = append(blocked, observation.Role)
					if string(observation.Body) != "synthetic-edge-block" {
						t.Fatalf("blocked response body lost: %q", observation.Body)
					}
				}
			}
			if !slices.Equal(blocked, []string{"CentralAttack"}) {
				t.Fatalf("blocked evidence roles = %q, want only CentralAttack", blocked)
			}
			// Keep the expected anomaly independent of the detector's output and
			// reason formatter: this is status-change attribution, not WAF proof.
			want := GenericDetection{
				Mode:         ChangeInStatus,
				BeforeStatus: http.StatusOK,
				AfterStatus:  http.StatusForbidden,
				RequestType:  "CentralAttack",
				Reason:       `status changed from 200 to 403 for "CentralAttack"`,
			}
			if got := GenericDetect(evidence); got != want {
				t.Fatalf("combined probe generic attribution = %+v, want %+v", got, want)
			}
		})
	}
}

// TestRandomPathOracleCoversGeneratorRange pins the boundary that made the
// earlier six-digit-only oracle rare-flaky: the generator can draw 1000000.
func TestRandomPathOracleCoversGeneratorRange(t *testing.T) {
	for _, path := range []string{"/100000.html", "/999999.html", "/1000000.html"} {
		if !randomPathExpr.MatchString(path) {
			t.Fatalf("random-path oracle rejects reachable generator value %q", path)
		}
	}
	for _, path := range []string{"/99999.html", "/1000001.html", "/100000.htm"} {
		if randomPathExpr.MatchString(path) {
			t.Fatalf("random-path oracle accepts out-of-range value %q", path)
		}
	}
}
