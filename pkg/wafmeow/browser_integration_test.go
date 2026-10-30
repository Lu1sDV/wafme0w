//go:build browser_integration

package wafmeow

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

func browserFixtureConfig(t *testing.T, mode string) Config {
	t.Helper()
	path := os.Getenv("WAFME0W_TEST_BROWSER")
	if path == "" || !filepath.IsAbs(path) {
		t.Fatal("browser_integration requires WAFME0W_TEST_BROWSER to name an absolute native Chromium executable")
	}
	config := DefaultConfig()
	config.Browser = &BrowserConfig{Mode: mode, Path: path, Timeout: 12 * time.Second, Settle: 150 * time.Millisecond}
	return config.normalized()
}

func TestBrowserDelayedViewportAssetsAndProvenance(t *testing.T) {
	config := browserFixtureConfig(t, "screenshot")
	var pngBytes bytes.Buffer
	red := image.NewNRGBA(image.Rect(0, 0, 80, 80))
	draw.Draw(red, red.Bounds(), image.NewUniform(color.NRGBA{R: 255, A: 255}), image.Point{}, draw.Src)
	if err := png.Encode(&pngBytes, red); err != nil {
		t.Fatal(err)
	}
	var lazy, posts, font atomic.Int32
	var requestMu sync.Mutex
	var exactRequest, userAgent string
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Case/Keep":
			requestMu.Lock()
			exactRequest, userAgent = r.RequestURI, r.UserAgent()
			requestMu.Unlock()
			w.Header().Add("Set-Cookie", "first=one; Path=/")
			w.Header().Add("Set-Cookie", "second=two; Path=/")
			w.Header().Add("X-Repeated", "first")
			w.Header().Add("X-Repeated", "second")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, `<!doctype html><style>body{margin:0} @font-face{font-family:Delayed;src:url('/delayed.woff2')} #label{font-family:Delayed,sans-serif}</style><img src="/delayed.png" width="80" height="80"><div id="label">before</div><input type="password" value="fixture-secret"><img loading="lazy" src="/scroll-only.png" style="position:absolute;top:20000px" width="80" height="80"><script src="/delayed.js"></script>`)
		case "/delayed.png":
			time.Sleep(250 * time.Millisecond)
			w.Header().Set("Content-Type", "image/png")
			w.Write(pngBytes.Bytes())
		case "/delayed.js":
			time.Sleep(350 * time.Millisecond)
			w.Header().Set("Content-Type", "text/javascript")
			io.WriteString(w, `document.getElementById('label').textContent='delayed-script-visible'; document.fonts.ready.then(()=>document.body.dataset.fonts='settled'); fetch('/must-not-post',{method:'POST',body:'fixture'}).catch(()=>{});`)
		case "/delayed.woff2":
			font.Add(1)
			time.Sleep(400 * time.Millisecond)
			// Deliberately invalid owned bytes exercise honest font failure/fallback
			// after a delayed used-font request, without vendoring a font license.
			w.Header().Set("Content-Type", "font/woff2")
			io.WriteString(w, "owned-invalid-font")
		case "/scroll-only.png":
			lazy.Add(1)
			w.Write(pngBytes.Bytes())
		case "/must-not-post":
			posts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case "/favicon.ico":
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	target := fixture.URL + "/Case%2FKeep?Token=AbC%2FDef&Repeat=One&Repeat=Two"
	capture := captureBrowser(context.Background(), target, "owned-assets", 1, config)
	if capture.report.State != "complete" {
		t.Fatalf("capture: %+v", capture.report)
	}
	requestMu.Lock()
	gotRequest, gotUA := exactRequest, userAgent
	requestMu.Unlock()
	if gotRequest != "/Case%2FKeep?Token=AbC%2FDef&Repeat=One&Repeat=Two" || capture.report.FinalURL != target {
		t.Fatalf("URL provenance changed: request=%q report=%q", gotRequest, capture.report.FinalURL)
	}
	if !strings.Contains(gotUA, "Chrome/") {
		t.Fatalf("fixture did not observe native Chromium: %q", gotUA)
	}
	if capture.report.Status != 200 || capture.report.RequestID == "" || capture.report.FrameID == "" || capture.report.LoaderID == "" || capture.report.Protocol != "http/1.1" {
		t.Fatalf("missing document provenance: %+v", capture.report)
	}
	var cookies, repeated []string
	for _, header := range capture.report.Headers {
		if strings.EqualFold(header.Name, "Set-Cookie") {
			cookies = append(cookies, header.Value)
		}
		if strings.EqualFold(header.Name, "X-Repeated") {
			repeated = append(repeated, header.Value)
		}
	}
	if len(cookies) != 2 || cookies[0] != "first=one; Path=/" || cookies[1] != "second=two; Path=/" || strings.Join(repeated, "|") != "first|second" {
		t.Fatalf("repeated headers lost: cookies=%q repeated=%q", cookies, repeated)
	}
	if !strings.Contains(capture.dom, "delayed-script-visible") || !strings.Contains(capture.dom, `data-fonts="settled"`) {
		t.Fatalf("captured before delayed DOM/font settlement: %s", capture.dom)
	}
	if font.Load() != 1 || lazy.Load() != 0 || posts.Load() != 0 || capture.report.DeniedRequests == 0 {
		t.Fatalf("fixture counters: font=%d lazy=%d POST=%d denied=%d", font.Load(), lazy.Load(), posts.Load(), capture.report.DeniedRequests)
	}
	if !capture.report.Readiness.Loaded || !capture.report.Readiness.VisibleImagesReady || !capture.report.Readiness.FontsReady {
		t.Fatalf("readiness: %+v", capture.report.Readiness)
	}
	if !capture.geometryOK || len(capture.secrets) != 1 {
		t.Fatalf("password field geometry unavailable: %+v", capture.report)
	}
	decoded, err := png.Decode(bytes.NewReader(capture.image))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bounds() != image.Rect(0, 0, 1440, 900) {
		t.Fatalf("viewport: %v", decoded.Bounds())
	}
	r, g, b, _ := decoded.At(30, 30).RGBA()
	if r < 60000 || g > 1000 || b > 1000 {
		t.Fatalf("delayed visible image absent: pixel=(%d,%d,%d)", r, g, b)
	}
}

func TestBrowserResourceOriginsDoNotGrantNavigation(t *testing.T) {
	config := browserFixtureConfig(t, "navigate")
	var denied, admitted, topNavigation atomic.Int32
	outside := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { denied.Add(1); w.WriteHeader(200) }))
	defer outside.Close()
	resource := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/asset.js" {
			admitted.Add(1)
			w.Header().Set("Content-Type", "text/javascript")
			io.WriteString(w, `document.body.dataset.resource='allowed';`)
			return
		}
		topNavigation.Add(1)
		io.WriteString(w, "must-not-be-a-document")
	}))
	defer resource.Close()
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/navigate" {
			fmt.Fprintf(w, `<script>location.href=%q</script>`, resource.URL+"/document")
			return
		}
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(204)
			return
		}
		fmt.Fprintf(w, `<!doctype html><body><script src=%q></script><img src=%q>`, resource.URL+"/asset.js", outside.URL+"/denied.png")
	}))
	defer fixture.Close()
	config.Browser.ResourceOrigins = []string{resource.URL}
	capture := captureBrowser(context.Background(), fixture.URL+"/", "owned-resource", 1, config)
	if capture.report.State != "complete" || !strings.Contains(capture.dom, `data-resource="allowed"`) || admitted.Load() != 1 || denied.Load() != 0 {
		t.Fatalf("resource restriction failed: admitted=%d denied=%d report=%+v DOM=%s", admitted.Load(), denied.Load(), capture.report, capture.dom)
	}
	if len(capture.image) != 0 || capture.report.Screenshot.State != "not_selected" {
		t.Fatal("navigate acquired image data")
	}
	capture = captureBrowser(context.Background(), fixture.URL+"/navigate", "owned-navigation", 2, config)
	if capture.report.State == "complete" || topNavigation.Load() != 0 {
		t.Fatalf("resource origin widened document scope: requests=%d report=%+v", topNavigation.Load(), capture.report)
	}
	// Explicit resource permission still intersects the global ceiling.
	config.AllowedOrigins = []string{fixture.URL}
	capture = captureBrowser(context.Background(), fixture.URL+"/", "owned-ceiling", 3, config)
	if admitted.Load() != 1 || strings.Contains(capture.dom, `data-resource="allowed"`) || capture.report.DeniedRequests == 0 {
		t.Fatalf("resource escaped global allowlist: requests=%d report=%+v", admitted.Load(), capture.report)
	}
}

func TestBrowserNavigationReadinessResetAndDeadline(t *testing.T) {
	config := browserFixtureConfig(t, "navigate")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		switch r.URL.Path {
		case "/first":
			io.WriteString(w, `<!doctype html><body>old-document<script>setTimeout(()=>location.href='/second',50)</script>`)
		case "/second":
			w.Header().Set("X-Document", "second")
			io.WriteString(w, `<!doctype html><body>new-document<script>setTimeout(()=>document.body.dataset.settled='second',100)</script>`)
		case "/changing":
			io.WriteString(w, `<!doctype html><body><p id="tick"></p><script>setInterval(()=>document.getElementById('tick').textContent=String(performance.now()),20)</script>`)
		default:
			w.WriteHeader(204)
		}
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/first", "owned-reset", 1, config)
	if capture.report.State != "complete" || capture.report.FinalURL != fixture.URL+"/second" || !strings.Contains(capture.dom, `data-settled="second"`) || strings.Contains(capture.dom, "old-document") {
		t.Fatalf("document readiness/provenance not reset: %+v DOM=%s", capture.report, capture.dom)
	}
	config.Browser.Timeout = 2 * time.Second
	started := time.Now()
	capture = captureBrowser(context.Background(), fixture.URL+"/changing", "owned-deadline", 2, config)
	if capture.report.State != "partial" || capture.report.Reason != "deadline_exceeded" || capture.report.DOM.State == "acquired" || capture.report.Status != 200 {
		t.Fatalf("changing document falsely completed: %+v", capture.report)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("capture failed to honor bounded acquisition and cleanup")
	}
}

func TestBrowserRequestAndRedirectBudgets(t *testing.T) {
	config := browserFixtureConfig(t, "navigate")
	var starts atomic.Int32
	var redirects atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		starts.Add(1)
		switch {
		case strings.HasPrefix(r.URL.Path, "/redirect/"):
			step := redirects.Add(1)
			http.Redirect(w, r, fmt.Sprintf("/redirect/%d", step), http.StatusFound)
		case r.URL.Path == "/many":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<!doctype html><body><script>Promise.allSettled(Array.from({length:60},(_,i)=>fetch('/asset/'+i))).then(()=>document.body.dataset.done='yes')</script>`)
		default:
			w.WriteHeader(204)
		}
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/many", "owned-starts", 1, config)
	if capture.report.State != "complete" || starts.Load() != 40 || capture.report.AdmittedRequests != 40 || capture.report.DeniedRequests == 0 || !strings.Contains(capture.dom, `data-done="yes"`) {
		t.Fatalf("request budget failed: server=%d report=%+v", starts.Load(), capture.report)
	}
	config.MaxRedirects = 1
	capture = captureBrowser(context.Background(), fixture.URL+"/redirect/0", "owned-redirects", 2, config)
	if redirects.Load() != 2 || capture.report.State == "complete" || capture.report.AdmittedRequests != 2 {
		t.Fatalf("redirect cap failed: server=%d report=%+v", redirects.Load(), capture.report)
	}
}

func TestBrowserChildFrameReadinessAndUncertainGeometry(t *testing.T) {
	config := browserFixtureConfig(t, "screenshot")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/child" {
			io.WriteString(w, `<!doctype html><body><input type="password" value="child-secret"><script>let tick=0;const timer=setInterval(()=>{document.body.dataset.tick=++tick;if(tick===40){clearInterval(timer);document.body.style.background='rgb(0,255,0)';}},25)</script>`)
			return
		}
		if r.URL.Path == "/favicon.ico" {
			w.WriteHeader(204)
			return
		}
		io.WriteString(w, `<!doctype html><style>body{margin:0}iframe{border:0;width:300px;height:200px}</style><iframe src="/child"></iframe>`)
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/", "owned-frame", 1, config)
	if capture.report.State != "complete" || capture.report.Screenshot.State != "acquired" {
		t.Fatalf("child render not acquired: %+v", capture.report)
	}
	if capture.geometryOK {
		t.Fatal("child credential geometry falsely asserted complete")
	}
	decoded, err := png.Decode(bytes.NewReader(capture.image))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := decoded.At(100, 100).RGBA()
	if g < 60000 || r > 1000 || b > 1000 {
		t.Fatalf("child delayed DOM not settled: pixel=(%d,%d,%d)", r, g, b)
	}
}

func TestBrowserCertificateAndDOMLimits(t *testing.T) {
	t.Run("certificate verification", func(t *testing.T) {
		config := browserFixtureConfig(t, "navigate")
		var requests atomic.Int32
		fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			io.WriteString(w, "<!doctype html><p>untrusted TLS fixture</p>")
		}))
		defer fixture.Close()
		capture := captureBrowser(context.Background(), fixture.URL, "untrusted-certificate", 1, config)
		if capture.report.State == "complete" || capture.report.Status != 0 || requests.Load() != 0 {
			t.Fatalf("untrusted TLS certificate accepted: %+v, requests=%d", capture.report, requests.Load())
		}
	})
	t.Run("bounded Unicode DOM", func(t *testing.T) {
		config := browserFixtureConfig(t, "navigate")
		body := "<!doctype html><p>" + strings.Repeat("λ", browserMaxDOM) + "</p>"
		fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, body)
		}))
		defer fixture.Close()
		capture := captureBrowser(context.Background(), fixture.URL, "bounded-dom", 1, config)
		if capture.report.State != "partial" || capture.report.Reason != "dom_limit" || !capture.report.DOM.Truncated || len(capture.dom) > browserMaxDOM || !utf8.ValidString(capture.dom) {
			t.Fatalf("DOM limit not preserved: %+v, bytes=%d", capture.report, len(capture.dom))
		}
	})
}

func TestBrowserCredentialAttributeExportAndGeometry(t *testing.T) {
	config := browserFixtureConfig(t, "screenshot")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><html><head><style>
body{margin:0}
input,div{position:absolute;left:20px;width:300px;height:30px;border:0;padding:0;background:rgb(255,0,0);contain:paint}
#autocomplete{top:20px}
#data-field{top:80px}
#unicode-type{top:140px}
#bom{top:200px}
#ordinary{top:260px;background:rgb(0,0,255)}
</style></head><body>
<input id="autocomplete" type="text" autocomplete="section-login current-password" value="AUDIT-CREDENTIAL-SECRET">
<div id="data-field" data-field="password">AUDIT-CREDENTIAL-SECRET</div>
<div id="unicode-type" type="paſſword">AUDIT-CREDENTIAL-SECRET</div>
<input id="bom" type="text" autocomplete="section-login`+"\ufeff"+`current-password" value="AUDIT-CREDENTIAL-SECRET">
<div id="ordinary" data-field="passwordHint" data-kind="apiKey" data-apİkey="ordinary-data-value" type="password&#10;">ordinary visible text</div>
</body></html>`)
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/", "credential-attributes", 1, config)
	if capture.report.State != "complete" || !capture.geometryOK || len(capture.secrets) != 4 {
		t.Fatalf("credential attribute capture or geometry incomplete: %+v, geometry=%t rects=%+v", capture.report, capture.geometryOK, capture.secrets)
	}
	var dom, screenshot []byte
	config.Browser.SaveText = func(_ context.Context, artifact BrowserArtifact) (string, error) {
		var err error
		dom, err = io.ReadAll(artifact.Content)
		return "sanitized-dom.json", err
	}
	config.Browser.SaveScreenshot = func(_ context.Context, artifact BrowserArtifact) (string, error) {
		var err error
		screenshot, err = io.ReadAll(artifact.Content)
		return "masked.png", err
	}
	report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
	if report.State != "complete" || report.DOM.SaveState != "saved" || report.Screenshot.SaveState != "saved" {
		t.Fatalf("credential artifacts failed export: %+v", report)
	}
	if bytes.Contains(dom, []byte("AUDIT-CREDENTIAL-SECRET")) {
		t.Fatal("recognized credential leaked into actual SaveText callback")
	}
	var artifact struct {
		DOM browserDOMNode `json:"dom"`
	}
	if err := json.Unmarshal(dom, &artifact); err != nil {
		t.Fatal(err)
	}
	nodes := browserExportNodes(artifact.DOM)
	for _, id := range []string{"autocomplete", "data-field", "unicode-type", "bom"} {
		field := browserExportNodeByID(t, nodes, id)
		if field.Tag == "input" && field.Attributes["value"] != browserRedacted || field.Tag == "div" && (field.Text != browserRedacted || len(field.Children) != 0) {
			t.Fatalf("credential field %q not redacted: %+v", id, field)
		}
	}
	ordinary := browserExportNodeByID(t, nodes, "ordinary")
	if ordinary.Attributes["data-field"] != "passwordHint" || ordinary.Attributes["data-kind"] != "apiKey" || ordinary.Attributes["type"] != "password\n" || len(ordinary.Children) != 1 || ordinary.Children[0].Text != "ordinary visible text" {
		t.Fatalf("ordinary DOM field changed: %+v", ordinary)
	}
	masked, err := png.Decode(bytes.NewReader(screenshot))
	if err != nil {
		t.Fatal(err)
	}
	for _, y := range []int{35, 95, 155, 215, 275} {
		want := color.RGBA{A: 255}
		if y == 275 {
			want.B = 255
		}
		if got := color.RGBAModel.Convert(masked.At(300, y)).(color.RGBA); got != want {
			t.Fatalf("masked pixel (300,%d) = %v, want %v", y, got, want)
		}
	}
}

func TestBrowserCredentialSubtreeGeometryRejectsUnsafeExports(t *testing.T) {
	const secret = "AUDIT-CREDENTIAL-SECRET"
	for _, test := range []struct {
		name   string
		markup string
	}{
		{"zero-sized wrapper", `<div class="credential" data-field="password" style="width:0;height:0"><span class="child">` + secret + `</span></div>`},
		{"display contents", `<div data-field="password" style="display:contents"><span class="credential">` + secret + `</span></div>`},
		{"overflowing text", `<div class="credential" data-field="password" style="width:10px;white-space:nowrap">` + secret + `</div>`},
		{"positioned descendant", `<div class="credential" data-field="password"><span class="child" style="position:absolute;left:400px">` + secret + `</span></div>`},
		{"visible descendant of hidden wrapper", `<div class="credential" data-field="password" style="visibility:hidden"><span class="child" style="visibility:visible">` + secret + `</span></div>`},
		{"visible descendant of offscreen wrapper", `<div class="credential" data-field="password" style="left:-500px"><span class="child" style="position:fixed;left:20px;top:20px">` + secret + `</span></div>`},
		{"generated credential text", `<style>.credential::after{content:attr(data-password);position:fixed;left:400px;top:20px}</style><div class="credential" data-password="` + secret + `"></div>`},
		{"credential text shadow", `<div class="credential" data-field="password" style="text-shadow:400px 0 red">` + secret + `</div>`},
		{"ancestor paint effect", `<section style="filter:drop-shadow(400px 0 0 red)"><div class="credential" data-field="password">` + secret + `</div></section>`},
		{"unclipped credential text", `<div class="credential" data-field="password">` + secret + `</div>`},
		{"italic glyph ink overhang", `<span class="credential" data-field="password" style="left:200px;display:block;width:max-content;height:auto;line-height:400px;font:italic 240px/400px serif;color:red;background:none">f</span>`},
		{"upright glyph ink overhang", `<span class="credential" data-field="password" style="left:200px;display:block;width:max-content;height:auto;line-height:400px;font:240px/400px serif;color:red;background:none">j</span>`},
		{"negative letter spacing", `<span class="credential" data-field="password" style="left:200px;display:block;width:max-content;height:auto;font:100px/400px monospace;letter-spacing:-30px;color:red;background:none">SECRET</span>`},
		{"ancestor first-line paint", `<style>section::first-line{text-shadow:400px 0 red}</style><section style="position:absolute;left:20px;top:20px;width:320px;height:40px"><span data-field="password">` + secret + `</span></section>`},
		{"inapplicable inline containment", `<span data-field="password" style="contain:paint;font:italic 240px/400px serif;color:red">f</span>`},
		{"top-layer descendant", `<div data-field="password" style="position:absolute;left:200px;top:20px;width:100px;height:400px;contain:paint"><span id="popup" popover style="position:fixed;left:200px;top:20px;width:100px;height:400px;margin:0;padding:0;border:0;font:italic 240px/400px serif;color:red">f</span></div><script>document.getElementById('popup').showPopover()</script>`},
		{"expanded paint clip margin", `<span class="credential" data-field="password" style="left:200px;display:block;width:max-content;height:auto;font:240px/400px serif;color:red;background:none;contain:paint;overflow-clip-margin:100px">j</span>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := browserFixtureConfig(t, "screenshot")
			fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				io.WriteString(w, `<!doctype html><html><head><style>body{margin:0;font:16px sans-serif}.credential{position:absolute;left:20px;top:20px;width:300px;height:30px;background:red}.child{display:block;width:300px;height:30px}</style></head><body>`+test.markup+`</body></html>`)
			}))
			defer fixture.Close()
			capture := captureBrowser(context.Background(), fixture.URL+"/", "credential-subtree", 1, config)
			if capture.report.State != "complete" || len(capture.image) == 0 {
				t.Fatalf("fixture did not acquire a screenshot: %+v", capture.report)
			}
			var dom []byte
			screenshotCalls := 0
			config.Browser.SaveText = func(_ context.Context, artifact BrowserArtifact) (string, error) {
				var err error
				dom, err = io.ReadAll(artifact.Content)
				return "sanitized-dom.json", err
			}
			config.Browser.SaveScreenshot = func(_ context.Context, artifact BrowserArtifact) (string, error) {
				screenshotCalls++
				return "must-not-save.png", nil
			}
			report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
			if capture.geometryOK || screenshotCalls != 0 || report.State != "partial" || report.Screenshot.SaveState != "failed" || !report.Failed() {
				t.Fatalf("unsafe credential subtree reached screenshot export: geometry=%t calls=%d report=%+v", capture.geometryOK, screenshotCalls, report)
			}
			if report.DOM.SaveState != "saved" || bytes.Contains(dom, []byte(secret)) {
				t.Fatalf("independent DOM export lost its redaction contract: %+v", report.DOM)
			}
		})
	}
}

func TestBrowserCredentialSubtreeGeometryPreservesContainedAndHiddenFields(t *testing.T) {
	config := browserFixtureConfig(t, "screenshot")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><html><head><meta name="csrf-token" content="hidden-secret"><style>body{margin:0;font:16px sans-serif}#ordinary{position:absolute;left:20px;top:100px;width:300px;height:30px;background:blue}</style></head><body>
<input type="hidden" name="csrf-token" value="hidden-secret">
<div style="display:none"><div data-field="password"><span style="position:fixed;left:400px;top:20px;visibility:visible">hidden-secret</span></div></div>
<div data-field="password" style="position:absolute;left:20px;top:20px;width:300px;height:60px;background:red;contain:paint"><span>AUDIT-CREDENTIAL-SECRET</span></div>
<div id="ordinary">ordinary visible text</div>
</body></html>`)
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/", "contained-credential", 1, config)
	if capture.report.State != "complete" || !capture.geometryOK || len(capture.secrets) != 1 {
		t.Fatalf("contained or hidden credential handling failed: %+v geometry=%t rectangles=%+v", capture.report, capture.geometryOK, capture.secrets)
	}
	var screenshot []byte
	config.Browser.SaveScreenshot = func(_ context.Context, artifact BrowserArtifact) (string, error) {
		var err error
		screenshot, err = io.ReadAll(artifact.Content)
		return "masked.png", err
	}
	report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
	if report.State != "complete" || report.Screenshot.SaveState != "saved" {
		t.Fatalf("ordinary screenshot was not exported: %+v", report)
	}
	masked, err := png.Decode(bytes.NewReader(screenshot))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		y    int
		want color.RGBA
	}{{35, color.RGBA{A: 255}}, {115, color.RGBA{B: 255, A: 255}}} {
		if got := color.RGBAModel.Convert(masked.At(300, test.y)).(color.RGBA); got != test.want {
			t.Fatalf("pixel (300,%d) = %v, want %v", test.y, got, test.want)
		}
	}
}

func TestBrowserCredentialInkClippingMasksNativeControlsAndContainedText(t *testing.T) {
	config := browserFixtureConfig(t, "screenshot")
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<!doctype html><html><head><style>body{margin:0;background:white}input,textarea{position:absolute;left:20px;width:300px;padding:0;border:0;color:red;background:red;font:italic 100px/200px serif}</style></head><body>
<input name="password" type="text" value="f" style="top:20px;height:40px">
<textarea name="password" style="top:100px;height:80px">jSECRET</textarea>
<span data-field="password" style="position:absolute;left:20px;top:200px;width:max-content;height:400px;contain:paint;font:italic 240px/400px serif;color:red">f</span>
<div style="position:absolute;left:500px;top:20px;width:300px;height:30px;background:blue">ordinary visible text</div>
</body></html>`)
	}))
	defer fixture.Close()
	capture := captureBrowser(context.Background(), fixture.URL+"/", "clipped-credential-ink", 1, config)
	if capture.report.State != "complete" || !capture.geometryOK || len(capture.secrets) != 3 {
		t.Fatalf("supported clipping was rejected: %+v geometry=%t rectangles=%+v", capture.report, capture.geometryOK, capture.secrets)
	}
	var screenshot []byte
	config.Browser.SaveScreenshot = func(_ context.Context, artifact BrowserArtifact) (string, error) {
		var err error
		screenshot, err = io.ReadAll(artifact.Content)
		return "masked.png", err
	}
	report := exportBrowserCapture(context.Background(), &capture, *config.Browser)
	if report.State != "complete" || report.Screenshot.SaveState != "saved" {
		t.Fatalf("clipped credential screenshot failed: %+v", report)
	}
	masked, err := png.Decode(bytes.NewReader(screenshot))
	if err != nil {
		t.Fatal(err)
	}
	for y := range masked.Bounds().Dy() {
		for x := range masked.Bounds().Dx() {
			pixel := color.RGBAModel.Convert(masked.At(x, y)).(color.RGBA)
			if pixel.R > pixel.G && pixel.R > pixel.B {
				t.Fatalf("credential glyph ink escaped actual clipping and masking at (%d,%d): %v", x, y, pixel)
			}
		}
	}
	if got := color.RGBAModel.Convert(masked.At(790, 35)).(color.RGBA); got != (color.RGBA{B: 255, A: 255}) {
		t.Fatalf("ordinary screenshot content changed: %v", got)
	}
}
