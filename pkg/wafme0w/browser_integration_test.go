//go:build browser_integration

package wafme0w

import (
	"bytes"
	"context"
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
