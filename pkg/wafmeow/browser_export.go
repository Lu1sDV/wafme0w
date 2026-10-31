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
	"image/draw"
	"image/png"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lu1sDV/wafmeow/v3/internal/httpmeta"
	"golang.org/x/net/html"
)

// Names are exact after lowercasing and removing non-ASCII-alphanumeric
// separators. DOM export and screenshot geometry recognize these values in
// name/id/property, autocomplete tokens, and data-* names or values.
var browserCredentialFields = []string{
	"authorization", "proxyauthorization", "password", "currentpassword", "newpassword", "passwd", "pwd",
	"passphrase", "secret", "token", "accesstoken", "refreshtoken", "idtoken",
	"apikey", "clientsecret", "session", "sessionid", "sessiontoken",
	"csrf", "csrftoken", "xsrf", "xsrftoken",
}

const browserRedacted = "[REDACTED]"
const browserMetadataMax = 8 << 10
const browserExportLimitation = "Export redacts recognized credential fields, not arbitrary text or pixels; DOM metadata and masked pixels are not an atomic observation."

func exportBrowserCapture(ctx context.Context, capture *browserCapture, config BrowserConfig) *BrowserReport {
	report := capture.report
	report.ID = browserSanitizeText(report.ID, 0)
	report.Mode = browserSanitizeText(report.Mode, 0)
	report.State = browserSanitizeText(report.State, 0)
	report.Reason = browserSanitizeText(report.Reason, 0)
	// Diagnostics can contain arbitrary browser, URL, or filesystem content.
	// Stable stage errors preserve failure without publishing those payloads.
	if report.Error != "" {
		switch report.Error {
		case context.Canceled.Error(), context.DeadlineExceeded.Error():
		default:
			report.Error = "browser acquisition failed"
		}
	}
	report.URL = browserSanitizeURL(report.URL, 0)
	report.FinalURL = browserSanitizeURL(report.FinalURL, 0)
	report.RequestID = browserSanitizeText(report.RequestID, 0)
	report.LoaderID = browserSanitizeText(report.LoaderID, 0)
	report.FrameID = browserSanitizeText(report.FrameID, 0)
	report.Protocol = browserSanitizeText(report.Protocol, 0)
	report.Version = browserSanitizeText(report.Version, 0)
	if math.IsNaN(report.ConnectionID) || math.IsInf(report.ConnectionID, 0) {
		report.ConnectionID = 0
		browserExportFailure(&report, "invalid browser connection metadata")
	}
	report.RedirectChain = nil
	for i, raw := range capture.report.RedirectChain {
		if i == browserMaxRequests {
			browserExportFailure(&report, "browser redirect metadata exceeds export limit")
			break
		}
		report.RedirectChain = append(report.RedirectChain, browserSanitizeURL(raw, 0))
	}
	report.Headers = nil
	headerBytes, sanitizedHeaderBytes := 0, 0
	for i, header := range capture.report.Headers {
		headerBytes += len(header.Name) + len(header.Value)
		if i == 256 || headerBytes > 64<<10 {
			browserExportFailure(&report, "browser headers exceed export limit")
			break
		}
		if !httpmeta.ValidHeaderName(header.Name) {
			browserExportFailure(&report, "invalid browser header omitted")
			continue
		}
		value := browserSanitizeHeader(header.Name, header.Value)
		sanitizedHeaderBytes += len(header.Name) + len(value)
		if sanitizedHeaderBytes > 64<<10 {
			browserExportFailure(&report, "sanitized browser headers exceed export limit")
			break
		}
		report.Headers = append(report.Headers, Header{Name: header.Name, Value: value})
	}
	report.Limitations = nil
	for i, limitation := range capture.report.Limitations {
		if i == 64 {
			browserExportFailure(&report, "browser limitations exceed export limit")
			break
		}
		report.Limitations = append(report.Limitations, browserSanitizeText(limitation, 0))
	}
	report.Limitations = append(report.Limitations, browserExportLimitation)
	for _, asset := range []*BrowserAsset{&report.DOM, &report.Screenshot} {
		asset.State = browserSanitizeText(asset.State, 0)
		asset.Saved, asset.SHA256 = "", ""
		asset.SaveState = "not_requested"
	}
	report.DOM.AcquiredSHA256, report.Screenshot.AcquiredSHA256 = "", ""
	if report.DOM.State == "acquired" && len(capture.dom) <= browserMaxDOM {
		digest := sha256.Sum256([]byte(capture.dom))
		report.DOM.AcquiredSHA256 = hex.EncodeToString(digest[:])
	}
	if config.Mode == "screenshot" && report.Screenshot.State == "acquired" && len(capture.image) <= browserMaxImage {
		digest := sha256.Sum256(capture.image)
		report.Screenshot.AcquiredSHA256 = hex.EncodeToString(digest[:])
	}

	if config.SaveText != nil {
		report.DOM.SaveState = "not_saved"
		if report.DOM.State == "acquired" {
			var content []byte
			var err error
			if report.DOM.Truncated || len(capture.dom) == 0 || len(capture.dom) > browserMaxDOM || !utf8.ValidString(capture.dom) {
				err = errors.New("invalid or truncated DOM cannot be safely exported")
			} else {
				content, err = browserSanitizeDOM(ctx, capture.domSnapshot)
			}
			if err != nil {
				report.DOM.SaveState = "failed"
				browserExportFailure(&report, "DOM sanitization failed")
			} else {
				browserSaveArtifact(ctx, &report, &report.DOM, content, "application/json", "DOM", config.SaveText)
			}
		}
	}
	// Unselected screenshots must not even be decoded or re-encoded.
	if config.Mode == "screenshot" && config.SaveScreenshot != nil {
		report.Screenshot.SaveState = "not_saved"
		if report.Screenshot.State == "acquired" {
			content, err := browserMaskImage(ctx, capture)
			if err != nil {
				report.Screenshot.SaveState = "failed"
				browserExportFailure(&report, "screenshot sanitization failed")
			} else {
				browserSaveArtifact(ctx, &report, &report.Screenshot, content, "image/png", "screenshot", config.SaveScreenshot)
			}
		}
	}
	return &report
}

func browserExportFailure(report *BrowserReport, message string) {
	report.State = "partial"
	if report.Reason == "" {
		report.Reason = "export_failed"
	}
	if report.Error == "" {
		report.Error = message
	} else if len(report.Error)+len(message)+2 <= browserMetadataMax {
		report.Error += "; " + message
	}
}

func browserSaveArtifact(ctx context.Context, report *BrowserReport, asset *BrowserAsset, content []byte, mime, stage string, sink func(context.Context, BrowserArtifact) (string, error)) {
	digest := sha256.Sum256(content)
	asset.SHA256 = hex.EncodeToString(digest[:])
	asset.Bytes = len(content)
	asset.SaveState = "failed"
	if ctx.Err() != nil {
		browserExportFailure(report, stage+" export cancelled")
		return
	}
	reference, err := sink(ctx, BrowserArtifact{CaptureID: report.ID, Occurrence: report.Occurrence, MIME: mime, SHA256: asset.SHA256, Content: bytes.NewReader(content)})
	if err != nil || reference == "" || ctx.Err() != nil {
		browserExportFailure(report, stage+" artifact save failed")
		return
	}
	asset.Saved = browserSanitizeText(reference, 0)
	asset.SaveState = "saved"
}

func browserCredentialName(name string) bool {
	var normalized strings.Builder
	for _, c := range name {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			normalized.WriteRune(c)
		}
	}
	return slices.Contains(browserCredentialFields, normalized.String())
}

func browserSanitizeHeader(name, value string) string {
	if len(value) > browserMetadataMax || !httpmeta.ValidHeaderValue(value) {
		return browserRedacted
	}
	if browserCredentialName(name) {
		return browserRedacted
	}
	switch strings.ToLower(name) {
	case "cookie":
		cookies := (&http.Request{Header: http.Header{"Cookie": {value}}}).Cookies()
		if len(cookies) == 0 {
			return browserRedacted
		}
		var result strings.Builder
		for i, cookie := range cookies {
			if i != 0 {
				result.WriteString("; ")
			}
			result.WriteString(cookie.Name + "=" + browserRedacted)
		}
		return browserBoundMetadata(result.String())
	case "set-cookie":
		cookie, err := http.ParseSetCookie(value)
		if err != nil {
			return browserRedacted
		}
		cookie.Value, cookie.Raw, cookie.RawExpires = browserRedacted, "", ""
		cookie.Unparsed = nil
		cookie.Path = browserSanitizeURL(cookie.Path, 0)
		return browserBoundMetadata(cookie.String())
	case "location", "content-location", "referer":
		return browserSanitizeURL(value, 0)
	default:
		return browserSanitizeText(value, 0)
	}
}

func browserSanitizeURL(raw string, depth int) string {
	if raw == "" {
		return ""
	}
	if depth > 8 || len(raw) > browserMetadataMax || !utf8.ValidString(raw) {
		return browserRedacted
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return browserRedacted
	}
	parsed.User = nil
	parsed.Fragment, parsed.RawFragment = "", ""
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return browserRedacted
	}
	for key, values := range query {
		for i, value := range values {
			if browserCredentialName(key) {
				values[i] = browserRedacted
			} else {
				values[i] = browserSanitizeText(value, depth+1)
			}
		}
	}
	parsed.RawQuery = query.Encode()
	return browserBoundMetadata(parsed.String())
}

func browserBoundMetadata(value string) string {
	if len(value) > browserMetadataMax {
		return browserRedacted
	}
	return value
}

func browserSanitizeText(raw string, depth int) string {
	if len(raw) > browserMetadataMax {
		return browserRedacted
	}
	return browserBoundMetadata(browserSanitizeStructuredText(raw, depth))
}

func browserSanitizeStructuredText(raw string, depth int) string {
	if raw == "" || raw == browserRedacted {
		return raw
	}
	if depth > 8 || len(raw) > browserMaxDOM || !utf8.ValidString(raw) {
		return browserRedacted
	}
	trimmed := strings.TrimSpace(raw)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var value any
		decoder := json.NewDecoder(strings.NewReader(trimmed))
		decoder.UseNumber()
		if err := decoder.Decode(&value); err != nil {
			return browserRedacted
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return browserRedacted
		}
		value = browserSanitizeJSON(value, depth+1)
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) > browserMetadataMax {
			return browserRedacted
		}
		return string(encoded)
	}
	if before, after, ok := strings.Cut(trimmed, ":"); ok {
		if browserCredentialName(before) {
			return before + ": " + browserRedacted
		}
		if strings.EqualFold(before, "cookie") || strings.EqualFold(before, "set-cookie") {
			return before + ": " + browserSanitizeHeader(before, strings.TrimSpace(after))
		}
	}
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "?") {
		if !strings.ContainsFunc(trimmed, unicode.IsSpace) {
			return browserSanitizeURL(trimmed, depth+1)
		}
	}
	if strings.Contains(trimmed, "=") && !strings.ContainsFunc(trimmed, unicode.IsSpace) {
		query, err := url.ParseQuery(trimmed)
		if err != nil {
			return browserRedacted
		}
		changed := false
		for key, values := range query {
			for i, value := range values {
				if browserCredentialName(key) {
					values[i] = browserRedacted
				} else {
					values[i] = browserSanitizeText(value, depth+1)
				}
				changed = changed || values[i] != value
			}
		}
		if changed {
			return query.Encode()
		}
	}
	// Embedded URLs and field assignments are parsed individually, never matched
	// by credential-name substrings inside arbitrary prose.
	var result strings.Builder
	for len(raw) != 0 {
		end := strings.IndexFunc(raw, unicode.IsSpace)
		if end < 0 {
			end = len(raw)
		}
		word := raw[:end]
		core := strings.Trim(word, "\"'()<>[],;")
		if core != "" && (strings.HasPrefix(core, "http://") || strings.HasPrefix(core, "https://") || strings.Contains(core, "=")) {
			start := strings.Index(word, core)
			if core != trimmed {
				word = word[:start] + browserSanitizeText(core, depth+1) + word[start+len(core):]
			}
		}
		result.WriteString(word)
		raw = raw[end:]
		for len(raw) != 0 {
			r, size := utf8.DecodeRuneInString(raw)
			if !unicode.IsSpace(r) {
				break
			}
			result.WriteString(raw[:size])
			raw = raw[size:]
		}
	}
	return result.String()
}

func browserSanitizeJSON(value any, depth int) any {
	if depth > 16 {
		return browserRedacted
	}
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if browserCredentialName(key) || strings.EqualFold(key, "cookie") || strings.EqualFold(key, "set-cookie") {
				value[key] = browserRedacted
			} else {
				value[key] = browserSanitizeJSON(child, depth+1)
			}
		}
	case []any:
		for i, child := range value {
			value[i] = browserSanitizeJSON(child, depth+1)
		}
	case string:
		return browserSanitizeText(value, depth+1)
	}
	return value
}

type browserDOMNode struct {
	Tag        string            `json:"tag,omitempty"`
	Text       string            `json:"text,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Children   []browserDOMNode  `json:"children,omitempty"`
}

func browserSanitizeDOM(ctx context.Context, snapshot string) ([]byte, error) {
	document, err := browserReadDOMSnapshot(ctx, snapshot)
	if err != nil {
		return nil, err
	}
	projection, err := browserProjectDOM(ctx, document, 0)
	if err != nil {
		return nil, err
	}
	var output browserBoundedBuffer
	output.limit = browserMaxDOM
	if err := json.NewEncoder(&output).Encode(struct {
		Format     string         `json:"format"`
		Limitation string         `json:"limitation"`
		DOM        browserDOMNode `json:"dom"`
	}{"wafmeow.browser-dom.v1", browserExportLimitation, projection}); err != nil {
		return nil, errors.New("sanitized DOM exceeds export limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

type browserDOMSnapshotEntry struct {
	Parent     int                           `json:"parent"`
	Tag        string                        `json:"tag,omitempty"`
	Text       string                        `json:"text,omitempty"`
	Namespace  string                        `json:"namespace,omitempty"`
	Attributes []browserDOMSnapshotAttribute `json:"attributes,omitempty"`
}

type browserDOMSnapshotAttribute struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	Namespace string `json:"namespace,omitempty"`
}

// The isolated world records actual parent indexes before HTML serialization can
// lose ancestry. Never reparse outerHTML here: HTML repair, foreign-content rules
// and raw-text end tags can move a credential's descendants outside its subtree.
func browserReadDOMSnapshot(ctx context.Context, snapshot string) (*html.Node, error) {
	if len(snapshot) == 0 || len(snapshot) > browserMaxDOM || !utf8.ValidString(snapshot) {
		return nil, errors.New("invalid or unavailable structural DOM snapshot")
	}
	decoder := json.NewDecoder(strings.NewReader(snapshot))
	decoder.DisallowUnknownFields()
	if token, err := decoder.Token(); err != nil || token != json.Delim('[') {
		return nil, errors.New("invalid structural DOM snapshot")
	}
	document := &html.Node{Type: html.DocumentNode}
	var nodes []*html.Node
	var depths []int
	for decoder.More() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(nodes) >= browserMaxDOMNodes {
			return nil, errors.New("structural DOM node limit exceeded")
		}
		var entry browserDOMSnapshotEntry
		if err := decoder.Decode(&entry); err != nil {
			return nil, errors.New("invalid structural DOM entry")
		}
		parent, depth := document, 1
		if entry.Parent == -1 && len(nodes) == 0 && entry.Tag != "" {
			// Exactly one element root, followed only by backward parent references.
		} else if entry.Parent < 0 || entry.Parent >= len(nodes) || nodes[entry.Parent].Type != html.ElementNode {
			return nil, errors.New("invalid structural DOM parent")
		} else {
			parent, depth = nodes[entry.Parent], depths[entry.Parent]+1
		}
		if depth > browserMaxDOMDepth {
			return nil, errors.New("DOM nesting exceeds export limit")
		}
		node := &html.Node{Type: html.TextNode, Data: entry.Text}
		if entry.Tag != "" {
			if entry.Namespace != browserHTMLNamespace || entry.Text != "" {
				return nil, errors.New("unsupported structural DOM element")
			}
			node.Type, node.Data = html.ElementNode, browserDOMName(entry.Tag)
			for _, attribute := range entry.Attributes {
				node.Attr = append(node.Attr, html.Attribute{Namespace: attribute.Namespace, Key: browserDOMName(attribute.Name), Val: attribute.Value})
			}
		} else if entry.Namespace != "" || len(entry.Attributes) != 0 {
			return nil, errors.New("invalid structural DOM text")
		}
		parent.AppendChild(node)
		nodes, depths = append(nodes, node), append(depths, depth)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') || len(nodes) == 0 {
		return nil, errors.New("incomplete structural DOM snapshot")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing structural DOM content")
	}
	return document, nil
}

func browserDOMName(name string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, name)
}

func browserProjectDOM(ctx context.Context, node *html.Node, depth int) (browserDOMNode, error) {
	var result browserDOMNode
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if depth > browserMaxDOMDepth {
		return result, errors.New("DOM nesting exceeds export limit")
	}
	if node.Type == html.TextNode {
		result.Text = browserSanitizeStructuredText(node.Data, 0)
		return result, nil
	}
	if node.Type != html.ElementNode && node.Type != html.DocumentNode {
		return result, nil
	}
	if node.Type == html.ElementNode {
		result.Tag = node.Data
		switch node.Data {
		case "script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "link", "svg", "math", "template":
			return browserDOMNode{}, nil
		}
	}
	secret := false
	metaHeader := ""
	for _, attr := range node.Attr {
		if (attr.Key == "name" || attr.Key == "id" || attr.Key == "autocomplete" || attr.Key == "property") && browserCredentialName(attr.Val) || attr.Key == "type" && strings.EqualFold(attr.Val, "password") || strings.HasPrefix(attr.Key, "data-") && (browserCredentialName(strings.TrimPrefix(attr.Key, "data-")) || browserCredentialName(attr.Val)) {
			secret = true
		}
		if attr.Key == "autocomplete" {
			for token := range strings.FieldsFuncSeq(attr.Val, func(r rune) bool {
				// Match JavaScript \s in browserGeometryScript, including BOM but not NEL.
				return r == '\ufeff' || r != '\u0085' && unicode.IsSpace(r)
			}) {
				if browserCredentialName(token) {
					secret = true
					break
				}
			}
		}
		if node.Data == "meta" && attr.Key == "http-equiv" && strings.EqualFold(attr.Val, "refresh") {
			return browserDOMNode{}, nil
		}
		if node.Data == "meta" && attr.Key == "http-equiv" {
			metaHeader = attr.Val
		}
	}
	for _, attr := range node.Attr {
		if attr.Namespace != "" || strings.HasPrefix(attr.Key, "on") || attr.Key == "style" || attr.Key == "srcdoc" {
			continue
		}
		value := browserSanitizeText(attr.Val, 0)
		if browserCredentialName(attr.Key) || strings.HasPrefix(attr.Key, "data-") && browserCredentialName(strings.TrimPrefix(attr.Key, "data-")) || secret && attr.Key != "name" && attr.Key != "id" && attr.Key != "type" && attr.Key != "autocomplete" && attr.Key != "property" {
			value = browserRedacted
		} else {
			switch attr.Key {
			case "href", "src", "action", "formaction", "poster", "cite", "longdesc":
				value = browserSanitizeURL(attr.Val, 0)
			case "srcset", "ping":
				continue
			}
			if attr.Key == "content" && metaHeader != "" {
				value = browserSanitizeHeader(metaHeader, attr.Val)
			}
		}
		if result.Attributes == nil {
			result.Attributes = make(map[string]string)
		}
		result.Attributes[attr.Key] = value
	}
	if secret {
		if node.FirstChild != nil {
			result.Text = browserRedacted
		}
		return result, nil
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		projected, err := browserProjectDOM(ctx, child, depth+1)
		if err != nil {
			return browserDOMNode{}, err
		}
		if projected.Tag != "" || projected.Text != "" || len(projected.Children) != 0 {
			result.Children = append(result.Children, projected)
		}
	}
	return result, nil
}

type browserBoundedBuffer struct {
	bytes.Buffer
	limit int
}

func (buffer *browserBoundedBuffer) Write(value []byte) (int, error) {
	if len(value) > buffer.limit-buffer.Len() {
		return 0, errors.New("browser artifact exceeds export limit")
	}
	return buffer.Buffer.Write(value)
}

func browserMaskImage(ctx context.Context, capture *browserCapture) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !capture.geometryOK || capture.report.Screenshot.Truncated || len(capture.image) == 0 || len(capture.image) > browserMaxImage {
		return nil, errors.New("unsafe screenshot geometry or size")
	}
	config, err := png.DecodeConfig(bytes.NewReader(capture.image))
	if err != nil || config.Width <= 0 || config.Height <= 0 || config.Width > browserWidth || config.Height > browserHeight || config.Width != capture.report.Width || config.Height != capture.report.Height {
		return nil, errors.New("invalid screenshot dimensions or encoding")
	}
	bounds := image.Rect(0, 0, config.Width, config.Height)
	rectangles := make([]image.Rectangle, 0, len(capture.secrets))
	for _, secret := range capture.secrets {
		if math.IsNaN(secret.X) || math.IsNaN(secret.Y) || math.IsNaN(secret.Width) || math.IsNaN(secret.Height) || math.IsInf(secret.X, 0) || math.IsInf(secret.Y, 0) || math.IsInf(secret.Width, 0) || math.IsInf(secret.Height, 0) || secret.Width <= 0 || secret.Height <= 0 {
			return nil, errors.New("invalid secret-field rectangle")
		}
		right, bottom := secret.X+secret.Width, secret.Y+secret.Height
		if math.IsInf(right, 0) || math.IsInf(bottom, 0) {
			return nil, errors.New("overflowing secret-field rectangle")
		}
		left := math.Max(0, math.Min(float64(config.Width), math.Floor(secret.X)))
		top := math.Max(0, math.Min(float64(config.Height), math.Floor(secret.Y)))
		right = math.Max(0, math.Min(float64(config.Width), math.Ceil(right)))
		bottom = math.Max(0, math.Min(float64(config.Height), math.Ceil(bottom)))
		rectangles = append(rectangles, image.Rect(int(left), int(top), int(right), int(bottom)))
	}
	decoded, err := png.Decode(bytes.NewReader(capture.image))
	if err != nil {
		return nil, errors.New("screenshot decoding failed")
	}
	masked := image.NewRGBA(bounds)
	draw.Draw(masked, bounds, decoded, decoded.Bounds().Min, draw.Src)
	for _, rectangle := range rectangles {
		draw.Draw(masked, rectangle, &image.Uniform{C: color.Black}, image.Point{}, draw.Src)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var output browserBoundedBuffer
	output.limit = browserMaxImage
	if err := png.Encode(&output, masked); err != nil {
		return nil, errors.New("screenshot encoding failed or exceeds export limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
