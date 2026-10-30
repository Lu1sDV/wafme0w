package wafmeow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Keep these wire expectations independent of the probe constants and URL
// builder: deriving them with either would bless the same payload regression.
func TestActiveProbePayloadsOnWire(t *testing.T) {
	probes := []struct {
		role  string
		query string
	}{
		{"XssAttack", "p=%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E"},
		{"XxeAttack", "p=%3C%21ENTITY+xxe+SYSTEM+%22file%3A%2F%2F%2Fetc%2Fshadow%22%3E%5D%3E%3Cpwn%3E%26hack%3B%3C%2Fpwn%3E"},
		{"LfiAttack", "p=..%2F..%2F..%2F..%2Fetc%2Fpasswd"},
		{"CentralAttack", "d=%3Cscript%3Ealert%28%22XSS%22%29%3B%3C%2Fscript%3E&l=..%2F..%2F..%2F..%2Fetc%2Fpasswd&v=UNION+SELECT+ALL+FROM+information_schema+AND+%27+or+SLEEP%285%29+or+%27"},
		{"SqliAttack", "p=UNION+SELECT+ALL+FROM+information_schema+AND+%27+or+SLEEP%285%29+or+%27"},
		{"RceAttack", "p=%2Fbin%2Fcat+%2Fetc%2Fpasswd%3B+ping+127.0.0.1%3B+curl+google.com"},
	}
	type observed struct{ method, uri string }

	// Existing query bytes, duplicate keys, and keys also used by a probe must
	// survive unchanged. LFI remains a query value, not a rewritten target path.
	const existingQuery = "Token=Ab%2F%2b&dup=one&dup=two&p=before&d=keep%20me&l=keep%2fme&v=keep%2bme"
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
			for _, probe := range probes {
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
					options := make(map[string]requestOpts)
					for _, option := range newTypeOptions(server.URL + baseURI) {
						switch option.Type {
						case "Normal", "NoUserAgent", "NonExistent":
							continue
						}
						if _, exists := options[option.Type]; exists {
							t.Fatalf("duplicate active probe role %q", option.Type)
						}
						options[option.Type] = option
					}
					if len(options) != len(probes) {
						t.Fatalf("active probe inventory changed: got %d roles, want %d reviewed wire cases", len(options), len(probes))
					}
					option, exists := options[probe.role]
					if !exists {
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
					wantURI := baseURI + "&" + probe.query
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
