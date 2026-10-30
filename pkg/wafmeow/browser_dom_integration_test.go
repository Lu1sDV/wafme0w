//go:build browser_integration

package wafmeow

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBrowserDOMExportPreservesNativeAncestry(t *testing.T) {
	const secret = "REVIEW-CREDENTIAL-SECRET"
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<!doctype html><html><head></head><body><script src="/build.js"></script></body></html>`)
		case "/build.js":
			w.Header().Set("Content-Type", "text/javascript")
			io.WriteString(w, `
const secret = "REVIEW-CREDENTIAL-SECRET";
for (const name of ["p", "table"]) {
  const parent = document.createElement(name), child = document.createElement("div");
  parent.id = "token";
  child.textContent = secret;
  parent.appendChild(child);
  document.body.appendChild(parent);
}
const parent = document.createElement("div"), script = document.createElement("script");
parent.id = "token";
script.type = "application/json";
script.textContent = '</script></div><div>' + secret + '</div><div><script type="application/json">';
parent.appendChild(script);
document.body.appendChild(parent);
const foreign = document.createElementNS("http://www.w3.org/2000/svg", "svg"), child = document.createElement("p");
foreign.id = "token";
child.textContent = secret;
foreign.appendChild(child);
document.body.appendChild(foreign);
for (const name of ["id", "custom:id"]) {
  const namespaced = document.createElement("div"), child = document.createElement("span");
  namespaced.setAttributeNS("urn:credential-fixture", name, "token");
  child.textContent = secret;
  namespaced.appendChild(child);
  document.body.appendChild(namespaced);
}
const ordinaryScript = document.createElement("script");
ordinaryScript.type = "application/json";
ordinaryScript.textContent = JSON.stringify({template:"<div>ordinary script markup</div>"});
document.body.appendChild(ordinaryScript);
const publicSibling = document.createElement("span");
publicSibling.textContent = "public sibling";
document.body.appendChild(publicSibling);
`)
		default:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer fixture.Close()
	for _, selected := range []bool{false, true} {
		t.Run(fmt.Sprintf("save_text_%t", selected), func(t *testing.T) {
			config := browserFixtureConfig(t, "navigate")
			var saved []byte
			if selected {
				config.Browser.SaveText = func(_ context.Context, artifact BrowserArtifact) (string, error) {
					var err error
					saved, err = io.ReadAll(artifact.Content)
					return "sanitized-dom.json", err
				}
			}
			capture := captureBrowser(context.Background(), fixture.URL+"/", "native-dom-ancestry", 1, config)
			if capture.report.State != "complete" || !strings.Contains(capture.dom, secret) || !strings.Contains(capture.dom, `<p id="token"><div>`+secret+`</div></p>`) {
				t.Fatalf("fixture did not acquire the unrepaired native tree: %+v", capture.report)
			}
			if (capture.domSnapshot != "") != selected {
				t.Fatalf("structural snapshot selection changed: selected=%t bytes=%d", selected, len(capture.domSnapshot))
			}
			report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
			if report.State != "complete" || report.DOM.State != "acquired" {
				t.Fatalf("structural capture/export failed: %+v", report)
			}
			if selected && (report.DOM.SaveState != "saved" || bytes.Contains(saved, []byte(secret)) || !bytes.Contains(saved, []byte("public sibling"))) {
				t.Fatalf("native credential ancestry lost: report=%+v saved=%s", report, saved)
			}
			digest := sha256.Sum256([]byte(capture.dom))
			if report.DOM.AcquiredSHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("raw acquisition hash changed to identify structural/sanitized content")
			}
		})
	}
}

func TestBrowserDOMSnapshotLimitsWithholdTextExport(t *testing.T) {
	for _, test := range []struct{ name, script string }{
		{"nodes", fmt.Sprintf(`for (let i=0;i<%d;i++) document.body.appendChild(document.createTextNode(""));`, browserMaxDOMNodes)},
		{"depth", fmt.Sprintf(`let parent=document.body;for(let i=0;i<%d;i++){const child=document.createElement("div");parent.appendChild(child);parent=child;}`, browserMaxDOMDepth)},
		{"bytes", `document.body.appendChild(document.createTextNode('"'.repeat(600000)));`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				fmt.Fprintf(w, "<!doctype html><html><head></head><body><script>%s</script></body></html>", test.script)
			}))
			defer fixture.Close()
			config := browserFixtureConfig(t, "navigate")
			config.Browser.SaveText = func(context.Context, BrowserArtifact) (string, error) {
				t.Fatal("over-limit structural DOM reached SaveText")
				return "", nil
			}
			capture := captureBrowser(context.Background(), fixture.URL+"/", "native-dom-limit", 1, config)
			if capture.report.State != "complete" || capture.report.DOM.Truncated || capture.domSnapshot != "" {
				t.Fatalf("fixture did not isolate the structural snapshot limit: %+v snapshot_bytes=%d", capture.report, len(capture.domSnapshot))
			}
			report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
			if report.State != "partial" || report.DOM.State != "acquired" || report.DOM.SaveState != "failed" || !report.Failed() {
				t.Fatalf("missing structural DOM claimed successful export: %+v", report)
			}
		})
	}
}
