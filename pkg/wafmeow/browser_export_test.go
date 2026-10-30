package wafmeow

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

	"golang.org/x/net/html"
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
		dom: rawDOM, domSnapshot: browserDOMSnapshotFixture(t, rawDOM),
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

func TestBrowserExportRecognizesCredentialAttributeValues(t *testing.T) {
	for _, test := range []struct {
		name   string
		markup string
	}{
		{"autocomplete section", `<input id="field" type="text" autocomplete="section-login current-password" value="AUDIT-CREDENTIAL-SECRET">`},
		{"autocomplete whitespace", "<input id=\"field\" type=\"text\" autocomplete=\"section-login\tCURRENT-password\nwebauthn\" value=\"AUDIT-CREDENTIAL-SECRET\">"},
		{"autocomplete ECMAScript whitespace", `<input id="field" type="text" autocomplete="section-login` + "\ufeff" + `current-password" value="AUDIT-CREDENTIAL-SECRET">`},
		{"autocomplete new password", `<input id="field" type="text" autocomplete="section-signup new-password" value="AUDIT-CREDENTIAL-SECRET">`},
		{"data attribute value", `<div id="field" data-field="password">AUDIT-CREDENTIAL-SECRET</div>`},
		{"data attribute normalized value", `<div id="field" data-field="CLIENT_secret">AUDIT-CREDENTIAL-SECRET</div>`},
		{"data attribute name", `<div id="field" data-api-key="AUDIT-CREDENTIAL-SECRET">AUDIT-CREDENTIAL-SECRET</div>`},
		{"password type on non-input", `<div id="field" type="password">AUDIT-CREDENTIAL-SECRET</div>`},
		{"password type Unicode folding", `<div id="field" type="paſſword">AUDIT-CREDENTIAL-SECRET</div>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := `<html><head></head><body>` + test.markup + `<input id="ordinary" autocomplete="section-login current-password-hint" data-field="passwordHint" data-kind="apiKey" data-apİkey="ordinary-data-value" type="password&#10;" value="ordinary-field-value"><div id="ordinary-text" data-field="description">ordinary visible text</div></body></html>`
			capture := browserCapture{report: BrowserReport{
				ID: "credential-fields", Occurrence: 7, State: "complete",
				DOM: BrowserAsset{State: "acquired", Bytes: len(raw)},
			}, dom: raw, domSnapshot: browserDOMSnapshotFixture(t, raw)}
			var saved []byte
			report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(_ context.Context, artifact BrowserArtifact) (string, error) {
				if artifact.MIME != "application/json" || artifact.CaptureID != "credential-fields" || artifact.Occurrence != 7 {
					t.Fatalf("artifact identity or format changed: %+v", artifact)
				}
				var err error
				saved, err = io.ReadAll(artifact.Content)
				return "sanitized-dom.json", err
			}})
			if bytes.Contains(saved, []byte("AUDIT-CREDENTIAL-SECRET")) {
				t.Fatal("recognized credential reached SaveText callback")
			}
			var artifact struct {
				Format string         `json:"format"`
				DOM    browserDOMNode `json:"dom"`
			}
			if err := json.Unmarshal(saved, &artifact); err != nil {
				t.Fatal(err)
			}
			if artifact.Format != "wafmeow.browser-dom.v1" || report.State != "complete" || report.DOM.State != "acquired" || report.DOM.SaveState != "saved" || report.DOM.Bytes != len(saved) {
				t.Fatalf("sanitized format or artifact state changed: %+v", report)
			}
			digest := sha256.Sum256(saved)
			if report.DOM.SHA256 != hex.EncodeToString(digest[:]) {
				t.Fatal("saved digest does not identify sanitized callback content")
			}
			nodes := browserExportNodes(artifact.DOM)
			field := browserExportNodeByID(t, nodes, "field")
			if field.Tag == "input" && field.Attributes["value"] != browserRedacted || field.Tag == "div" && (field.Text != browserRedacted || len(field.Children) != 0) {
				t.Fatalf("credential field not redacted: %+v", field)
			}
			ordinary := browserExportNodeByID(t, nodes, "ordinary")
			if ordinary.Attributes["value"] != "ordinary-field-value" || ordinary.Attributes["data-field"] != "passwordHint" || ordinary.Attributes["autocomplete"] != "section-login current-password-hint" || ordinary.Attributes["data-kind"] != "apiKey" || ordinary.Attributes["type"] != "password\n" {
				t.Fatalf("ordinary field changed: %+v", ordinary)
			}
			ordinaryText := browserExportNodeByID(t, nodes, "ordinary-text")
			if len(ordinaryText.Children) != 1 || ordinaryText.Children[0].Text != "ordinary visible text" {
				t.Fatalf("ordinary text changed: %+v", ordinaryText)
			}
			if capture.dom != raw || capture.report.DOM.SaveState != "" || capture.report.DOM.SHA256 != "" || capture.report.DOM.Bytes != len(raw) {
				t.Fatal("export mutated acquisition-owned state")
			}
		})
	}
}

func TestBrowserExportPreservesAcquiredCredentialAncestry(t *testing.T) {
	const secret = "REVIEW-CREDENTIAL-SECRET"
	const namespace = "http://www.w3.org/1999/xhtml"
	for _, test := range []struct {
		name, raw, snapshot string
	}{
		{
			name:     "paragraph implicit closure",
			raw:      `<body><p id="token"><div>` + secret + `</div></p><span>public sibling</span></body>`,
			snapshot: `[{"parent":-1,"tag":"body","namespace":"` + namespace + `"},{"parent":0,"tag":"p","namespace":"` + namespace + `","attributes":[{"name":"id","value":"token"}]},{"parent":1,"tag":"div","namespace":"` + namespace + `"},{"parent":2,"text":"` + secret + `"},{"parent":0,"tag":"span","namespace":"` + namespace + `"},{"parent":4,"text":"public sibling"}]`,
		},
		{
			name:     "table foster parenting",
			raw:      `<body><table id="token"><div>` + secret + `</div></table><span>public sibling</span></body>`,
			snapshot: `[{"parent":-1,"tag":"body","namespace":"` + namespace + `"},{"parent":0,"tag":"table","namespace":"` + namespace + `","attributes":[{"name":"id","value":"token"}]},{"parent":1,"tag":"div","namespace":"` + namespace + `"},{"parent":2,"text":"` + secret + `"},{"parent":0,"tag":"span","namespace":"` + namespace + `"},{"parent":4,"text":"public sibling"}]`,
		},
		{
			// A script text node can contain literal closing/opening tags. Its
			// outerHTML is ambiguous even though the apparent tags are balanced.
			name:     "raw script text inside credential subtree",
			raw:      `<body><div id="token"><script></script></div><div>` + secret + `</div><div><script></script></div><span>public sibling</span></body>`,
			snapshot: `[{"parent":-1,"tag":"body","namespace":"` + namespace + `"},{"parent":0,"tag":"div","namespace":"` + namespace + `","attributes":[{"name":"id","value":"token"}]},{"parent":0,"tag":"span","namespace":"` + namespace + `"},{"parent":2,"text":"public sibling"}]`,
		},
		{
			name:     "foreign content breakout",
			raw:      `<body><svg id="token"><p>` + secret + `</p></svg><span>public sibling</span></body>`,
			snapshot: `[{"parent":-1,"tag":"body","namespace":"` + namespace + `"},{"parent":0,"tag":"span","namespace":"` + namespace + `"},{"parent":1,"text":"public sibling"}]`,
		},
		{
			name:     "namespaced credential marker",
			raw:      `<body><div id="token"><span>` + secret + `</span></div><span>public sibling</span></body>`,
			snapshot: `[{"parent":-1,"tag":"body","namespace":"` + namespace + `"},{"parent":0,"tag":"div","namespace":"` + namespace + `","attributes":[{"name":"id","value":"token","namespace":"urn:credential-fixture"}]},{"parent":1,"tag":"span","namespace":"` + namespace + `"},{"parent":2,"text":"` + secret + `"},{"parent":0,"tag":"span","namespace":"` + namespace + `"},{"parent":4,"text":"public sibling"}]`,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			capture := browserCapture{report: BrowserReport{State: "complete", DOM: BrowserAsset{State: "acquired", Bytes: len(test.raw)}}, dom: test.raw, domSnapshot: test.snapshot}
			var saved []byte
			report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(_ context.Context, artifact BrowserArtifact) (string, error) {
				var err error
				saved, err = io.ReadAll(artifact.Content)
				return "sanitized-dom.json", err
			}})
			if bytes.Contains(saved, []byte(secret)) {
				t.Fatalf("recognized credential escaped its acquired subtree: %s", saved)
			}
			if report.State != "complete" || report.DOM.SaveState != "saved" || !bytes.Contains(saved, []byte("public sibling")) {
				t.Fatalf("safe sibling or export state lost: report=%+v output=%s", report, saved)
			}
			rawHash := sha256.Sum256([]byte(test.raw))
			if report.DOM.AcquiredSHA256 != hex.EncodeToString(rawHash[:]) || capture.dom != test.raw || capture.domSnapshot != test.snapshot {
				t.Fatal("sanitization changed raw acquisition identity or content")
			}
		})
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
	validSnapshot := browserDOMSnapshotFixture(t, "<p>safe DOM</p>")
	for name, capture := range map[string]browserCapture{
		"missing snapshot": {dom: "<p>raw HTML alone cannot prove ancestry</p>"},
		"oversized input":  {dom: strings.Repeat("x", browserMaxDOM+1), domSnapshot: validSnapshot},
		// The browser's JSON.stringify keeps '<' literal. The final inert JSON
		// encoder escapes it, so a valid bounded snapshot can exceed output limits.
		"oversized projection": {
			dom:         "<p>" + strings.Repeat("&lt;", 200000) + "</p>",
			domSnapshot: `[{"parent":-1,"tag":"p","namespace":"` + browserHTMLNamespace + `"},{"parent":0,"text":"` + strings.Repeat("<", 200000) + `"}]`,
		},
		"reported truncation": {dom: "<p>complete prefix</p>", domSnapshot: validSnapshot, report: BrowserReport{DOM: BrowserAsset{Truncated: true}}},
		"invalid UTF-8":       {dom: "<p>\xff</p>", domSnapshot: validSnapshot},
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

func TestBrowserExportStructuralDOMFailuresNeverReachSink(t *testing.T) {
	root := browserDOMSnapshotEntry{Parent: -1, Tag: "div", Namespace: browserHTMLNamespace}
	encode := func(entries []browserDOMSnapshotEntry) string {
		t.Helper()
		data, err := json.Marshal(entries)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	tooMany := []browserDOMSnapshotEntry{root}
	for range browserMaxDOMNodes {
		tooMany = append(tooMany, browserDOMSnapshotEntry{Parent: 0})
	}
	tooDeep := []browserDOMSnapshotEntry{root}
	for i := range browserMaxDOMDepth {
		tooDeep = append(tooDeep, browserDOMSnapshotEntry{Parent: i, Tag: "div", Namespace: browserHTMLNamespace})
	}
	for name, snapshot := range map[string]string{
		"missing": "", "empty": "[]", "null": "null", "malformed": "[", "unknown fields": `[{"parent":-1,"unknown":true}]`,
		"forward parent":         encode([]browserDOMSnapshotEntry{root, {Parent: 2, Text: "secret"}}),
		"text parent":            encode([]browserDOMSnapshotEntry{root, {Parent: 0, Text: "text"}, {Parent: 1, Text: "secret"}}),
		"second root":            encode([]browserDOMSnapshotEntry{root, root}),
		"foreign root":           encode([]browserDOMSnapshotEntry{{Parent: -1, Tag: "svg", Namespace: "http://www.w3.org/2000/svg"}}),
		"ambiguous element text": encode([]browserDOMSnapshotEntry{{Parent: -1, Tag: "div", Namespace: browserHTMLNamespace, Text: "secret"}}),
		"text attributes":        encode([]browserDOMSnapshotEntry{root, {Parent: 0, Text: "secret", Attributes: []browserDOMSnapshotAttribute{{Name: "id", Value: "token"}}}}),
		"trailing data":          encode([]browserDOMSnapshotEntry{root}) + "{}",
		"oversized":              strings.Repeat(" ", browserMaxDOM+1),
		"too many nodes":         encode(tooMany), "too much depth": encode(tooDeep),
	} {
		t.Run(name, func(t *testing.T) {
			capture := browserCapture{report: BrowserReport{State: "complete", DOM: BrowserAsset{State: "acquired"}}, dom: "<div>raw acquisition remains available</div>", domSnapshot: snapshot}
			report := exportBrowserCapture(context.Background(), &capture, BrowserConfig{Mode: "navigate", SaveText: func(context.Context, BrowserArtifact) (string, error) {
				t.Fatal("invalid structural DOM reached SaveText")
				return "", nil
			}})
			if report.State != "partial" || report.DOM.State != "acquired" || report.DOM.SaveState != "failed" || report.DOM.Saved != "" {
				t.Fatalf("invalid structural DOM lost failure/acquisition state: %+v", report)
			}
		})
	}
	for name, entries := range map[string][]browserDOMSnapshotEntry{
		"node boundary": tooMany[:browserMaxDOMNodes], "depth boundary": tooDeep[:browserMaxDOMDepth],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := browserSanitizeDOM(context.Background(), encode(entries)); err != nil {
				t.Fatalf("exact structural DOM boundary rejected: %v", err)
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
				capture.domSnapshot = browserDOMSnapshotFixture(t, capture.dom)
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
	capture.domSnapshot = browserDOMSnapshotFixture(t, capture.dom)
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

// Existing fixtures use ordinary parsed HTML. Adversarial DOM ancestry tests
// provide explicit parent records instead, because parsing would repair them.
func browserDOMSnapshotFixture(t *testing.T, raw string) string {
	t.Helper()
	document, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var entries []browserDOMSnapshotEntry
	var visit func(*html.Node, int)
	visit = func(node *html.Node, parent int) {
		if node.Type == html.ElementNode || node.Type == html.TextNode {
			if node.Namespace != "" {
				return
			}
			entry := browserDOMSnapshotEntry{Parent: parent}
			if node.Type == html.ElementNode {
				entry.Tag, entry.Namespace = node.Data, browserHTMLNamespace
				for _, attribute := range node.Attr {
					entry.Attributes = append(entry.Attributes, browserDOMSnapshotAttribute{Name: attribute.Key, Value: attribute.Val, Namespace: attribute.Namespace})
				}
			} else {
				entry.Text = node.Data
			}
			parent = len(entries)
			entries = append(entries, entry)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child, parent)
		}
	}
	visit(document, -1)
	snapshot, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	return string(snapshot)
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
