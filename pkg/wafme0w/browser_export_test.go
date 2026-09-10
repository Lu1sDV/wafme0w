package wafme0w

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestBrowserExportSanitizesStructuredContentWithoutChangingAcquisition(t *testing.T) {
	rawDOM := `<!doctype html><html><head><script>{"password":"script-secret"}</script><style>.x{background:url(style-secret)}</style><meta name="csrf-token" content="meta-secret"><meta property="id_token" content="id-secret"><meta http-equiv="set-cookie" content="sid=meta-cookie-secret; HttpOnly"></head><body onclick="event-secret" style="style-attribute-secret"><input name="password" value="form-secret"><input name="passwordHint" value="keep-hint"><input autocomplete="current-password" value="autocomplete-secret"><textarea name="refresh_token">textarea-secret</textarea><div id="data" data-api-key="data-secret">secret-region</div><a id="link" href="https://user:url-secret@example.test/view?access_token=query-secret&amp;passwordHint=keep-hint#fragment-secret" ping="https://ping-secret/">ordinary visible text</a><img id="image" src="javascript:image-secret" onerror="handler-secret"><iframe srcdoc="frame-secret"></iframe><pre id="json">{"API_Key":"json-secret","nested":{"client_secret":"nested-secret","passwordHint":"keep-json"},"url":"https://u:p@example.test/?session=s&amp;view=public"}</pre><p id="form">session_id=form-token&amp;view=public</p></body></html>`
	capture := browserCapture{
		report: BrowserReport{
			ID: "capture-1", Occurrence: 3, Mode: "navigate", State: "complete",
			URL:           "https://username:password-secret@example.test/?access_token=initial-secret&view=public",
			FinalURL:      "https://example.test/final?API_KEY=final-secret&passwordHint=keep-hint#fragment-secret",
			RedirectChain: []string{"https://u:redirect-secret@example.test/?id_token=redirect-token"},
			Headers: []Header{
				{Name: "Authorization", Value: "Bearer authorization-secret"},
				{Name: "Proxy-Authorization", Value: "Basic proxy-secret"},
				{Name: "Cookie", Value: "session=cookie-secret; preference=preference-secret"},
				{Name: "Set-Cookie", Value: "sid=set-cookie-secret; Path=/; HttpOnly; Secure; SameSite=Lax"},
				{Name: "Set-Cookie", Value: "theme=theme-secret; Path=/"},
				{Name: "Location", Value: "https://u:location-secret@example.test/?csrf=location-token"},
				{Name: "X-Config", Value: `{"access_token":"header-json-secret","tokenCount":2}`},
				{Name: "X-Form", Value: "client_secret=header-form-secret&public=yes"},
				{Name: "X-Password-Hint", Value: "keep-header"},
			},
			Error:       "raw error authorization=error-secret https://user:pass@example.test/",
			DOM:         BrowserAsset{State: "acquired", Bytes: len(rawDOM), SHA256: "raw-dom-hash"},
			Screenshot:  BrowserAsset{State: "not_selected"},
			Limitations: []string{"Resource denied: https://u:limitation-secret@example.test/?token=limitation-token"},
		},
		dom: rawDOM,
	}
	originalReport, err := json.Marshal(capture.report)
	if err != nil {
		t.Fatal(err)
	}
	var saved []byte
	var digest string
	report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(ctx context.Context, artifact BrowserArtifact) (string, error) {
		if artifact.MIME != "application/json" {
			t.Fatalf("text artifact is not inert JSON: %q", artifact.MIME)
		}
		var err error
		saved, err = io.ReadAll(artifact.Content)
		digest = artifact.SHA256
		return "https://u:saved-secret@storage.test/dom.json?token=saved-token&version=1", err
	}})
	if report.State != "complete" || report.DOM.State != "acquired" || report.DOM.SaveState != "saved" || report.DOM.Bytes != len(saved) {
		t.Fatalf("acquisition/save states or sanitized size incorrect: %+v", report)
	}
	sum := sha256.Sum256(saved)
	if digest != hex.EncodeToString(sum[:]) || report.DOM.SHA256 != digest {
		t.Fatal("artifact digest does not identify saved sanitized content")
	}
	for _, raw := range []string{report.URL, report.FinalURL, report.RedirectChain[0], report.DOM.Saved} {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.User != nil || parsed.Fragment != "" {
			t.Fatalf("URL credentials/fragment retained: %q, %v", raw, err)
		}
	}
	initial, _ := url.Parse(report.URL)
	if initial.Query().Get("access_token") != browserRedacted || initial.Query().Get("view") != "public" {
		t.Fatalf("URL query was not structurally redacted: %s", report.URL)
	}
	if report.Headers[0].Value != browserRedacted || report.Headers[1].Value != browserRedacted || report.Headers[2].Value != "session=[REDACTED]; preference=[REDACTED]" {
		t.Fatalf("authorization/cookie values retained: %+v", report.Headers[:3])
	}
	if report.Headers[3].Value != "sid=[REDACTED]; Path=/; HttpOnly; Secure; SameSite=Lax" || report.Headers[4].Value != "theme=[REDACTED]; Path=/" {
		t.Fatalf("repeated Set-Cookie metadata lost: %+v", report.Headers[3:5])
	}
	var headerJSON map[string]any
	if err := json.Unmarshal([]byte(report.Headers[6].Value), &headerJSON); err != nil || headerJSON["access_token"] != browserRedacted || headerJSON["tokenCount"] != float64(2) {
		t.Fatalf("JSON header not sanitized structurally: %q, %v", report.Headers[6].Value, err)
	}
	headerForm, err := url.ParseQuery(report.Headers[7].Value)
	if err != nil || headerForm.Get("client_secret") != browserRedacted || headerForm.Get("public") != "yes" || report.Headers[8].Value != "keep-header" {
		t.Fatalf("form/header field-name boundary lost: %+v, %v", report.Headers[7:], err)
	}
	var artifact struct {
		DOM browserDOMNode `json:"dom"`
	}
	if err := json.Unmarshal(saved, &artifact); err != nil {
		t.Fatal(err)
	}
	nodes := browserExportNodes(artifact.DOM)
	for _, node := range nodes {
		switch node.Tag {
		case "script", "style", "iframe":
			t.Fatalf("active DOM element retained: %q", node.Tag)
		}
		for _, attribute := range []string{"onclick", "onerror", "srcdoc", "style", "ping"} {
			if _, ok := node.Attributes[attribute]; ok {
				t.Fatalf("active attribute retained: %q", attribute)
			}
		}
		if node.Attributes["name"] == "password" && node.Attributes["value"] != browserRedacted {
			t.Fatalf("password form value retained: %+v", node)
		}
		if node.Attributes["name"] == "passwordHint" && node.Attributes["value"] != "keep-hint" {
			t.Fatalf("substring was treated as a credential name: %+v", node)
		}
		if node.Attributes["name"] == "csrf-token" && node.Attributes["content"] != browserRedacted || node.Attributes["property"] == "id_token" && node.Attributes["content"] != browserRedacted {
			t.Fatalf("meta credential value retained: %+v", node)
		}
	}
	jsonNode := browserExportNodeByID(t, nodes, "json")
	var embedded map[string]any
	if err := json.Unmarshal([]byte(jsonNode.Children[0].Text), &embedded); err != nil {
		t.Fatal(err)
	}
	if embedded["API_Key"] != browserRedacted || embedded["nested"].(map[string]any)["client_secret"] != browserRedacted || embedded["nested"].(map[string]any)["passwordHint"] != "keep-json" {
		t.Fatalf("DOM JSON key boundary lost: %+v", embedded)
	}
	link := browserExportNodeByID(t, nodes, "link")
	parsedLink, err := url.Parse(link.Attributes["href"])
	if err != nil || parsedLink.User != nil || parsedLink.Query().Get("access_token") != browserRedacted || parsedLink.Query().Get("passwordHint") != "keep-hint" || link.Children[0].Text != "ordinary visible text" {
		t.Fatalf("DOM URL/text projection incorrect: %+v, %v", link, err)
	}
	form := browserExportNodeByID(t, nodes, "form")
	formValues, err := url.ParseQuery(form.Children[0].Text)
	if err != nil || formValues.Get("session_id") != browserRedacted || formValues.Get("view") != "public" {
		t.Fatalf("DOM form text not sanitized: %+v, %v", form, err)
	}
	encodedReport, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"script-secret", "style-secret", "meta-secret", "id-secret", "meta-cookie-secret", "event-secret", "style-attribute-secret", "form-secret", "autocomplete-secret", "textarea-secret", "data-secret", "secret-region", "url-secret", "query-secret", "fragment-secret", "ping-secret", "image-secret", "handler-secret", "frame-secret", "json-secret", "nested-secret", "form-token", "password-secret", "initial-secret", "final-secret", "redirect-secret", "redirect-token", "authorization-secret", "proxy-secret", "cookie-secret", "preference-secret", "theme-secret", "location-secret", "location-token", "header-json-secret", "header-form-secret", "error-secret", "raw-dom-hash", "saved-secret", "saved-token", "limitation-secret", "limitation-token"} {
		if bytes.Contains(saved, []byte(secret)) || bytes.Contains(encodedReport, []byte(secret)) {
			t.Fatalf("recognized secret leaked into export: %q", secret)
		}
	}
	afterReport, err := json.Marshal(capture.report)
	if err != nil || !bytes.Equal(originalReport, afterReport) || capture.dom != rawDOM {
		t.Fatal("export changed acquisition-owned report or DOM")
	}
}

func TestBrowserExportMasksClampedPixelsWithoutChangingRawImage(t *testing.T) {
	capture := browserExportImageFixture(t, 4, 3)
	capture.secrets = []browserRect{{X: -1, Y: 0.25, Width: 2.2, Height: 1.1}, {X: 3.5, Y: 2.2, Width: 20, Height: 20}, {X: 20, Y: 20, Width: 1, Height: 1}}
	original := bytes.Clone(capture.image)
	rectangles := slices.Clone(capture.secrets)
	var saved []byte
	report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "screenshot", SaveScreenshot: func(ctx context.Context, artifact BrowserArtifact) (string, error) {
		if artifact.MIME != "image/png" {
			t.Fatalf("unexpected image MIME: %q", artifact.MIME)
		}
		var err error
		saved, err = io.ReadAll(artifact.Content)
		return "/private/capture.png", err
	}})
	if report.State != "complete" || report.Screenshot.State != "acquired" || report.Screenshot.SaveState != "saved" || report.Screenshot.Bytes != len(saved) {
		t.Fatalf("image acquisition/save states incorrect: %+v", report)
	}
	decoded, err := png.Decode(bytes.NewReader(saved))
	if err != nil {
		t.Fatal(err)
	}
	for y := range 3 {
		for x := range 4 {
			want := color.RGBA{R: 220, G: 80, B: 40, A: 255}
			if x < 2 && y < 2 || x == 3 && y == 2 {
				want = color.RGBA{A: 255}
			}
			got := color.RGBAModel.Convert(decoded.At(x, y)).(color.RGBA)
			if got != want {
				t.Fatalf("pixel (%d,%d) = %v, want %v", x, y, got, want)
			}
		}
	}
	sum := sha256.Sum256(saved)
	if report.Screenshot.SHA256 != hex.EncodeToString(sum[:]) || !bytes.Equal(capture.image, original) || !slices.Equal(rectangles, capture.secrets) {
		t.Fatal("masked digest is wrong or raw screenshot/geometry was mutated")
	}
}

func TestBrowserExportImageFailuresNeverReachSink(t *testing.T) {
	for name, change := range map[string]func(*browserCapture){
		"uncertain geometry":   func(c *browserCapture) { c.geometryOK = false },
		"invalid encoding":     func(c *browserCapture) { c.image = []byte("not a PNG") },
		"truncated encoding":   func(c *browserCapture) { c.image = c.image[:len(c.image)/2] },
		"oversized input":      func(c *browserCapture) { c.image = make([]byte, browserMaxImage+1) },
		"mismatched viewport":  func(c *browserCapture) { c.report.Width++ },
		"oversized dimensions": func(c *browserCapture) { *c = browserExportImageFixture(t, browserWidth+1, 1) },
		"truncated capture":    func(c *browserCapture) { c.report.Screenshot.Truncated = true },
		"NaN geometry":         func(c *browserCapture) { c.secrets = []browserRect{{X: math.NaN(), Width: 1, Height: 1}} },
		"infinite geometry":    func(c *browserCapture) { c.secrets = []browserRect{{Y: math.Inf(1), Width: 1, Height: 1}} },
		"overflow geometry": func(c *browserCapture) {
			c.secrets = []browserRect{{X: math.MaxFloat64, Width: math.MaxFloat64, Height: 1}}
		},
		"negative geometry": func(c *browserCapture) { c.secrets = []browserRect{{Width: -1, Height: 1}} },
		"empty geometry":    func(c *browserCapture) { c.secrets = []browserRect{{Width: 0, Height: 1}} },
	} {
		t.Run(name, func(t *testing.T) {
			capture := browserExportImageFixture(t, 4, 3)
			change(&capture)
			report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "screenshot", SaveScreenshot: func(context.Context, BrowserArtifact) (string, error) {
				t.Fatal("unsafe raw image reached sink")
				return "", nil
			}})
			if report.State != "partial" || report.Screenshot.State != "acquired" || report.Screenshot.SaveState != "failed" || report.Screenshot.Saved != "" || report.Screenshot.SHA256 != "" {
				t.Fatalf("unsafe screenshot claimed exported or acquisition lost: %+v", report)
			}
		})
	}
}

func TestBrowserExportRejectsImageThatExpandsPastOutputLimit(t *testing.T) {
	random := rand.New(rand.NewPCG(1, 2))
	palette := make(color.Palette, 256)
	for i := range palette {
		palette[i] = color.RGBA{R: uint8(random.Uint32()), G: uint8(random.Uint32()), B: uint8(random.Uint32()), A: 255}
	}
	indexed := image.NewPaletted(image.Rect(0, 0, browserWidth, browserHeight), palette)
	for i := range indexed.Pix {
		indexed.Pix[i] = uint8(random.Uint32())
	}
	var original bytes.Buffer
	if err := png.Encode(&original, indexed); err != nil {
		t.Fatal(err)
	}
	if original.Len() > browserMaxImage {
		t.Fatal("indexed PNG fixture exceeds acquisition limit")
	}
	capture := browserCapture{
		report: BrowserReport{State: "complete", Width: browserWidth, Height: browserHeight, Screenshot: BrowserAsset{State: "acquired"}},
		image:  original.Bytes(), geometryOK: true,
	}
	report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "screenshot", SaveScreenshot: func(context.Context, BrowserArtifact) (string, error) {
		t.Fatal("oversized transformed PNG reached sink")
		return "", nil
	}})
	if report.State != "partial" || report.Screenshot.State != "acquired" || report.Screenshot.SaveState != "failed" || report.Screenshot.SHA256 != "" {
		t.Fatalf("expanded screenshot claimed export success: %+v", report)
	}
}

func TestBrowserExportDOMFailuresNeverReachSink(t *testing.T) {
	for name, capture := range map[string]browserCapture{
		"incomplete":           {dom: "<html><body><p>unfinished"},
		"mismatched":           {dom: "<div><span>text</div></span>"},
		"partial tag":          {dom: "<html><body></body></html><input password=secret"},
		"oversized input":      {dom: strings.Repeat("x", browserMaxDOM+1)},
		"oversized projection": {dom: strings.Repeat("<p>"+strings.Repeat(`"`, 4096)+"</p>", 200)},
		"reported truncation":  {dom: "<p>complete prefix</p>", report: BrowserReport{DOM: BrowserAsset{Truncated: true}}},
		"invalid UTF-8":        {dom: "<p>\xff</p>"},
	} {
		t.Run(name, func(t *testing.T) {
			capture.report.State = "complete"
			capture.report.DOM.State = "acquired"
			report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(context.Context, BrowserArtifact) (string, error) {
				t.Fatal("unsafe DOM reached sink")
				return "", nil
			}})
			if report.State != "partial" || report.DOM.State != "acquired" || report.DOM.SaveState != "failed" || report.DOM.Saved != "" || report.DOM.SHA256 != "" {
				t.Fatalf("unsafe DOM claimed saved or acquisition lost: %+v", report)
			}
		})
	}
}

func TestBrowserExportCancellationAndSinkFailuresPreserveAcquisition(t *testing.T) {
	for _, stage := range []string{"DOM", "screenshot"} {
		for _, failure := range []string{"cancelled before", "sink error", "cancelled by sink", "empty reference"} {
			t.Run(stage+"/"+failure, func(t *testing.T) {
				capture := browserExportImageFixture(t, 4, 3)
				capture.dom = "<p>safe DOM</p>"
				capture.report.DOM.State = "acquired"
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if failure == "cancelled before" {
					cancel()
				}
				sink := func(got context.Context, artifact BrowserArtifact) (string, error) {
					if failure == "cancelled before" {
						t.Fatal("cancelled export called sink")
					}
					if got != ctx {
						t.Fatal("sink did not receive caller cancellation context")
					}
					switch failure {
					case "sink error":
						return "/private/claimed-but-failed", errors.New(strings.Repeat("password=callback-secret ", 1000))
					case "cancelled by sink":
						cancel()
						return "/private/claimed-but-cancelled", nil
					default:
						return "", nil
					}
				}
				config := BrowserConfig{Mode: "screenshot"}
				if stage == "DOM" {
					config.SaveText = sink
				} else {
					config.SaveScreenshot = sink
				}
				report := exportBrowserCapture(ctx, &capture, config)
				asset := report.DOM
				if stage == "screenshot" {
					asset = report.Screenshot
				}
				if report.State != "partial" || asset.State != "acquired" || asset.SaveState != "failed" || asset.Saved != "" || report.Error == "" || len(report.Error) > browserMetadataMax || strings.Contains(report.Error, "callback-secret") {
					t.Fatalf("save failure lied about acquisition/save or leaked error: %+v", report)
				}
			})
		}
	}
}

func TestBrowserExportUnselectedImageAndSinkPanic(t *testing.T) {
	capture := browserCapture{report: BrowserReport{State: "complete", DOM: BrowserAsset{State: "acquired"}, Screenshot: BrowserAsset{State: "acquired", Bytes: 12}}, dom: "<p>safe</p>", image: []byte("invalid raw image")}
	for _, config := range []BrowserConfig{
		{Mode: "screenshot"},
		{Mode: "navigate", SaveScreenshot: func(context.Context, BrowserArtifact) (string, error) {
			t.Fatal("navigate mode called image sink")
			return "", nil
		}},
	} {
		report := exportBrowserCapture(context.Background(), &capture, config)
		if report.State != "complete" || report.Screenshot.SaveState != "not_requested" || report.Screenshot.SHA256 != "" || report.Screenshot.Bytes != 12 {
			t.Fatalf("unselected image was transformed or treated as failed: %+v", report)
		}
	}
	defer func() {
		if recovered := recover(); recovered != "caller panic" {
			t.Fatalf("caller sink panic swallowed or changed: %v", recovered)
		}
	}()
	exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(context.Context, BrowserArtifact) (string, error) { panic("caller panic") }})
}

func browserExportImageFixture(t *testing.T, width, height int) browserCapture {
	t.Helper()
	original := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := range height {
		for x := range width {
			original.SetRGBA(x, y, color.RGBA{R: 220, G: 80, B: 40, A: 255})
		}
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, original); err != nil {
		t.Fatal(err)
	}
	return browserCapture{report: BrowserReport{ID: "image-1", Mode: "screenshot", State: "complete", Width: width, Height: height, Screenshot: BrowserAsset{State: "acquired", Bytes: encoded.Len()}}, image: encoded.Bytes(), geometryOK: true}
}

func browserExportNodes(root browserDOMNode) []browserDOMNode {
	nodes := []browserDOMNode{root}
	for i := 0; i < len(nodes); i++ {
		nodes = append(nodes, nodes[i].Children...)
	}
	return nodes
}

func browserExportNodeByID(t *testing.T, nodes []browserDOMNode, id string) browserDOMNode {
	t.Helper()
	for _, node := range nodes {
		if node.Attributes["id"] == id {
			return node
		}
	}
	t.Fatalf("DOM projection has no node with id %q", id)
	return browserDOMNode{}
}
