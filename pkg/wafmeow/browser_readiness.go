package wafmeow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

const browserWorld = "wafmeow-capture"

type browserIdentity struct {
	session    proto.TargetSessionID
	frame      proto.PageFrameID
	loader     proto.NetworkLoaderID
	generation uint64
	context    proto.RuntimeExecutionContextID
	token      string
}

type browserReadySample struct {
	Identity     string  `json:"identity"`
	Loaded       bool    `json:"loaded"`
	QuietFor     float64 `json:"quietFor"`
	ImagesReady  bool    `json:"imagesReady"`
	BrokenImages int     `json:"brokenImages"`
	FontsReady   bool    `json:"fontsReady"`
	BrokenFonts  int     `json:"brokenFonts"`
}

type browserDOM struct {
	Identity  string `json:"identity"`
	HTML      string `json:"html"`
	Truncated bool   `json:"truncated"`
	Snapshot  string `json:"snapshot"`
}

type browserGeometry struct {
	Identity string        `json:"identity"`
	Revision uint64        `json:"revision"`
	OK       bool          `json:"ok"`
	Rects    []browserRect `json:"rects"`
}

func (s *browserSession) sameDocument(identity browserIdentity) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if identity.frame != s.frame {
		current, ok := s.frames[identity.frame]
		return ok && current.session == identity.session && current.loader == identity.loader
	}
	return s.session == identity.session && s.frame == identity.frame && s.loader == identity.loader && s.generation == identity.generation
}

func (s *browserSession) evaluate(identity browserIdentity, expression string, output any) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	deadline, _ := s.ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return context.DeadlineExceeded
	}
	result, err := (proto.RuntimeEvaluate{Expression: expression, ContextID: identity.context,
		ReturnByValue: true, AwaitPromise: true, Silent: true, Timeout: proto.RuntimeTimeDelta(max(1, remaining.Milliseconds()))}).Call(s.page(identity.session))
	if err != nil {
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		return err
	}
	if result.ExceptionDetails != nil || result.Result == nil {
		return errors.New("browser observation script failed")
	}
	return result.Result.Value.Unmarshal(output)
}

func (s *browserSession) prepareWorld(identity browserIdentity) (browserIdentity, error) {
	if err := s.ctx.Err(); err != nil {
		return identity, err
	}
	created, err := (proto.PageCreateIsolatedWorld{FrameID: identity.frame, WorldName: browserWorld}).Call(s.page(identity.session))
	if err != nil {
		return identity, err
	}
	identity.context = created.ExecutionContextID
	err = s.evaluate(identity, browserReadinessInit, &identity.token)
	return identity, err
}

func (s *browserSession) sampleFrames(cache map[proto.PageFrameID]browserIdentity, sample *browserReadySample) error {
	s.mu.Lock()
	frames := make([]browserIdentity, 0, len(s.frames))
	for _, identity := range s.frames {
		frames = append(frames, identity)
	}
	for frame := range cache {
		if _, exists := s.frames[frame]; !exists {
			delete(cache, frame)
		}
	}
	s.mu.Unlock()
	for _, frame := range frames {
		identity := cache[frame.frame]
		if identity.context == 0 || !s.sameDocument(identity) {
			var err error
			identity, err = s.prepareWorld(frame)
			if err != nil {
				if s.sameDocument(frame) {
					return err
				}
				sample.Loaded = false
				continue
			}
			cache[frame.frame] = identity
		}
		var child browserReadySample
		if err := s.evaluate(identity, browserReadinessPoll, &child); err != nil {
			if s.sameDocument(identity) {
				return err
			}
			sample.Loaded = false
			continue
		}
		if !s.sameDocument(identity) || child.Identity != identity.token {
			sample.Loaded = false
			continue
		}
		sample.Loaded = sample.Loaded && child.Loaded
		sample.QuietFor = min(sample.QuietFor, child.QuietFor)
		sample.ImagesReady = sample.ImagesReady && child.ImagesReady
		sample.FontsReady = sample.FontsReady && child.FontsReady
		sample.BrokenImages += child.BrokenImages
		sample.BrokenFonts += child.BrokenFonts
	}
	s.mu.Lock()
	if len(frames) != len(s.frames) {
		sample.Loaded = false
	}
	s.mu.Unlock()
	return nil
}

func (s *browserSession) waitReady() (browserIdentity, error) {
	var identity browserIdentity
	frames := make(map[proto.PageFrameID]browserIdentity)
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := s.ctx.Err(); err != nil {
			return identity, err
		}
		s.mu.Lock()
		current := browserIdentity{session: s.session, frame: s.frame, loader: s.loader, generation: s.generation}
		loaded := s.loaded
		hasResponse := s.report.Status != 0 && s.report.LoaderID == string(s.loader)
		s.mu.Unlock()
		if current.loader != "" && hasResponse {
			if identity.context == 0 || !s.sameDocument(identity) {
				var err error
				current, err = s.prepareWorld(current)
				if err != nil {
					if s.sameDocument(current) {
						return identity, err
					}
					continue
				}
				identity = current
			}
			var sample browserReadySample
			if err := s.evaluate(identity, browserReadinessPoll, &sample); err != nil {
				if s.sameDocument(identity) {
					return identity, err
				}
				continue
			}
			if !s.sameDocument(identity) || sample.Identity != identity.token {
				identity.context = 0
				continue
			}
			if err := s.sampleFrames(frames, &sample); err != nil {
				return identity, err
			}
			s.mu.Lock()
			networkQuiet := len(s.active) == 0 && time.Since(s.lastNetwork) >= s.config.Browser.Settle
			s.report.Readiness = BrowserReadiness{Loaded: loaded && sample.Loaded,
				DOMQuiet: sample.QuietFor >= float64(s.config.Browser.Settle)/float64(time.Millisecond), NetworkQuiet: networkQuiet,
				VisibleImagesReady: sample.ImagesReady, FontsReady: sample.FontsReady}
			ready := s.report.Readiness
			if sample.BrokenImages > 0 {
				s.limitLocked("One or more visible images failed loading or decoding.")
			}
			if sample.BrokenFonts > 0 {
				s.limitLocked("One or more used fonts failed to load; browser fallback fonts may be visible.")
			}
			s.mu.Unlock()
			if ready.Loaded && ready.DOMQuiet && ready.NetworkQuiet && ready.VisibleImagesReady && ready.FontsReady {
				// Two animation-frame callbacks observe a rendering opportunity after
				// decoding/fonts, then recheck instead of treating a sleep as readiness.
				if err := s.evaluate(identity, browserRenderingOpportunity, &sample); err != nil {
					if s.sameDocument(identity) {
						return identity, err
					}
					continue
				}
				if err := s.sampleFrames(frames, &sample); err != nil {
					return identity, err
				}
				s.mu.Lock()
				stillQuiet := len(s.active) == 0 && time.Since(s.lastNetwork) >= s.config.Browser.Settle
				s.mu.Unlock()
				if s.sameDocument(identity) && sample.Identity == identity.token && sample.Loaded && sample.ImagesReady && sample.FontsReady &&
					sample.QuietFor >= float64(s.config.Browser.Settle)/float64(time.Millisecond) && stillQuiet {
					return identity, nil
				}
			}
		}
		select {
		case <-s.ctx.Done():
			return identity, s.ctx.Err()
		case <-timer.C:
		}
	}
}

// This script runs in a named isolated world. It observes the shared DOM but
// does not replace page APIs, activate resources, scroll, or interact with UI.
const browserReadinessInit = `(() => {
  if (globalThis.__wafCapture) return globalThis.__wafCapture.identity;
  const state = {
    identity: String(performance.timeOrigin) + ":" + Math.random().toString(36),
    revision: 0, changed: performance.now(), images: new WeakMap(), fontsReady: false, brokenFonts: 0
  };
  const changed = () => { state.changed = performance.now(); state.revision++; };
  new MutationObserver(changed).observe(document, {subtree:true, childList:true, attributes:true, characterData:true});
  addEventListener("resize", changed);
  document.fonts.addEventListener("loading", () => { state.fontsReady = false; changed(); });
  document.fonts.addEventListener("loadingerror", e => { state.brokenFonts += e.fontfaces.length; changed(); });
  document.fonts.addEventListener("loadingdone", () => {
    document.fonts.ready.then(() => { state.fontsReady = true; changed(); });
  });
  document.fonts.ready.then(() => { state.fontsReady = true; changed(); });
  state.poll = () => {
    let imagesReady = true, brokenImages = 0;
    for (const image of document.images) {
      const rect = image.getBoundingClientRect(), style = getComputedStyle(image);
      if (rect.width <= 0 || rect.height <= 0 || rect.bottom <= 0 || rect.right <= 0 || rect.top >= innerHeight || rect.left >= innerWidth || style.visibility === "hidden" || style.display === "none") continue;
      const source = image.currentSrc || image.src;
      let observed = state.images.get(image);
      if (!observed || observed.source !== source) {
        observed = {source, done:false, failed:false, decoding:false};
        state.images.set(image, observed);
        changed();
      }
      if (!image.complete) { imagesReady = false; continue; }
      if (!observed.decoding && !observed.done) {
        observed.decoding = true;
        image.decode().then(() => { observed.done = true; changed(); }, () => { observed.done = true; observed.failed = true; changed(); });
      }
      if (!observed.done) imagesReady = false;
      if (observed.failed || (image.complete && image.naturalWidth === 0)) brokenImages++;
    }
    return {identity:state.identity, loaded:document.readyState === "complete", quietFor:performance.now()-state.changed,
      imagesReady, brokenImages, fontsReady:state.fontsReady && document.fonts.status === "loaded", brokenFonts:state.brokenFonts};
  };
  Object.defineProperty(globalThis, "__wafCapture", {value:state});
  return state.identity;
})()`

const browserReadinessPoll = `globalThis.__wafCapture.poll()`
const browserRenderingOpportunity = `new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve(globalThis.__wafCapture.poll()))))`

var browserDOMScript = fmt.Sprintf(`(saveText) => {
  const source = document.documentElement ? document.documentElement.outerHTML : "";
  const bytes = new TextEncoder().encode(source.slice(0, %d + 1));
  let end = Math.min(bytes.length, %d);
  if (end < bytes.length) while (end > 0 && (bytes[end] & 192) === 128) end--;
  const result = {identity:globalThis.__wafCapture.identity, html:new TextDecoder("utf-8", {fatal:true}).decode(bytes.subarray(0,end)), truncated:source.length > %d || bytes.length > end};
  if (!saveText || result.truncated || !document.documentElement) return result;
  // Record actual DOM ancestry in this same synchronous observation. Parsing
  // outerHTML would repair paragraphs/tables and can reinterpret raw-text or
  // foreign content. Neither operation is safe before credential redaction.
  const namespace = %q;
  const omitted = new Set(["script", "style", "iframe", "frame", "frameset", "object", "embed", "applet", "base", "link", "svg", "math", "template"]);
  const included = node => node.nodeType !== Node.ELEMENT_NODE || node.namespaceURI === namespace && !omitted.has(node.localName.toLowerCase());
  const root = document.documentElement;
  if (!included(root)) return result;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
    acceptNode: node => included(node) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT
  });
  const indexes = new WeakMap(), depths = [], records = [], encoder = new TextEncoder();
  let retained = 2;
  for (let node = root; node; node = walker.nextNode()) {
    if (records.length >= %d) return result;
    const parent = node === root ? -1 : indexes.get(node.parentNode);
    if (parent === undefined) return result;
    const depth = parent === -1 ? 1 : depths[parent] + 1;
    if (depth > %d) return result;
    const entry = {parent};
    if (node.nodeType === Node.ELEMENT_NODE) {
      entry.tag = node.localName;
      entry.namespace = node.namespaceURI;
      entry.attributes = [];
      for (const attribute of node.attributes) {
        // Namespaced markers still identify credential subtrees. Go omits
        // their values only after identifying the enclosing credential field.
        entry.attributes.push({name:attribute.localName, value:attribute.value, namespace:attribute.namespaceURI || ""});
      }
    } else entry.text = node.data;
    const encoded = JSON.stringify(entry);
    retained += encoder.encode(encoded).length + (records.length ? 1 : 0);
    if (retained > %d) return result;
    indexes.set(node, records.length);
    depths.push(depth);
    records.push(encoded);
  }
  result.snapshot = "[" + records.join(",") + "]";
  return result;
}`, browserMaxDOM, browserMaxDOM, browserMaxDOM, browserHTMLNamespace, browserMaxDOMNodes, browserMaxDOMDepth, browserMaxDOM)

const browserGeometryScript = `(fields) => {
  const state = globalThis.__wafCapture;
  const names = new Set(fields);
  const normalized = value => value.replace(/[^a-zA-Z0-9]/g, "").toLowerCase();
  let ok = innerWidth === 1440 && innerHeight === 900 && scrollX === 0 && scrollY === 0;
  if (document.getAnimations().some(animation => animation.playState === "running" || animation.pending)) ok = false;
  const rects = [];
  const styles = new WeakMap();
  const styleOf = element => {
    let style = styles.get(element);
    if (!style) { style = getComputedStyle(element); styles.set(element, style); }
    return style;
  };
  const finiteRect = rect => [rect.x,rect.y,rect.width,rect.height,rect.right,rect.bottom].every(Number.isFinite) && rect.width >= 0 && rect.height >= 0;
  // These effects can paint copies of credential text outside layout rectangles.
  const paintExpands = style => style.textShadow !== "none" || style.filter !== "none" ||
    (style.webkitBoxReflect || "none") !== "none" || parseFloat(style.webkitTextStrokeWidth || "0") !== 0 ||
    (style.textEmphasisStyle || "none") !== "none";
  const paintDisplays = new Set(["block", "flow-root", "inline-block", "flex", "inline-flex", "grid", "inline-grid"]);
  const textInputs = new Set(["text", "search", "url", "tel", "email", "password", "number"]);
  const clipsOverflow = value => ["clip", "hidden", "auto", "scroll"].includes(value);
  const clipsCredentialInk = (element, style) => {
    // Layout rectangles measure advances, not glyph ink: even upright letters
    // can overhang them. Only accept actual clipping on this exact mask box.
    if ((style.overflowClipMargin || "0px") !== "0px") return false;
    const nativeText = element.localName === "textarea" || element.localName === "input" && textInputs.has(element.type);
    if (nativeText && element.childElementCount === 0 && clipsOverflow(style.overflowX) && clipsOverflow(style.overflowY)) return true;
    const containment = style.contain.split(/\s+/);
    // Paint containment does not apply to ordinary non-replaced inline boxes
    // or table-internal rows/columns. Use a deliberately narrow display set.
    return paintDisplays.has(style.display) && containment.some(value => value === "paint" || value === "content" || value === "strict");
  };
  const displayHidden = element => {
    let depth = 0;
    for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
      if (++depth > 128) { ok = false; return true; }
      if (styleOf(ancestor).display === "none") return true;
    }
    return false;
  };
  let examined = 0;
  const subtreeContained = (element, bounds) => {
    const within = rect => finiteRect(rect) && (rect.width === 0 || rect.height === 0 ||
      rect.x >= bounds.x && rect.y >= bounds.y && rect.right <= bounds.right && rect.bottom <= bounds.bottom);
    // Reject ambiguous geometry instead of assuming that a wrapper bounds its
    // descendants, overflowing text, generated content, or ancestor effects.
    for (let ancestor = element; ancestor; ancestor = ancestor.parentElement) {
      if (paintExpands(styleOf(ancestor))) return false;
      for (const pseudo of ["::first-letter", "::first-line"]) {
        if (paintExpands(getComputedStyle(ancestor, pseudo))) return false;
      }
    }
    const walker = document.createTreeWalker(element, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT, {
      acceptNode: node => {
        // Accept the first over-budget node so nextNode returns and inspection
        // stops, even when every preceding sibling was hidden and rejected.
        if (++examined > 4096) return NodeFilter.FILTER_ACCEPT;
        return node.nodeType === Node.ELEMENT_NODE && styleOf(node).display === "none" ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
      }
    });
    const range = document.createRange();
    examined++;
    for (let node = element; node; node = walker.nextNode()) {
      if (examined > 4096) return false;
      if (node.nodeType === Node.ELEMENT_NODE) {
        const style = styleOf(node);
        if (node.namespaceURI !== "http://www.w3.org/1999/xhtml" || paintExpands(style) || style.display === "list-item" ||
          node.localName === "dialog" || node.hasAttribute("popover")) return false;
        for (const pseudo of ["::before", "::after"]) {
          const generated = getComputedStyle(node, pseudo).content;
          if (generated !== "none" && generated !== "normal") return false;
        }
        for (const pseudo of ["::first-letter", "::first-line"]) {
          if (paintExpands(getComputedStyle(node, pseudo))) return false;
        }
        for (const rect of node.getClientRects()) if (!within(rect)) return false;
      } else {
        range.selectNodeContents(node);
        for (const rect of range.getClientRects()) if (!within(rect)) return false;
      }
    }
    return true;
  };
  for (const element of document.querySelectorAll("*")) {
    if (element.localName === "iframe" || element.localName === "frame" || element.shadowRoot) ok = false;
    let secret = false;
    for (const attr of element.attributes) {
      const key = attr.name.replace(/[A-Z]/g, c => c.toLowerCase());
      // Match Go EqualFold; length excludes the final newline accepted by $.
      if (key === "type" && attr.value.length === 8 && /^password$/iu.test(attr.value)) secret = true;
      if (key === "name" || key === "id" || key === "property" || key === "autocomplete") {
        if (names.has(normalized(attr.value))) secret = true;
        if (key === "autocomplete" && attr.value.split(/\s+/).some(v => names.has(normalized(v)))) secret = true;
      }
      if (key.startsWith("data-") && (names.has(normalized(key.slice(5))) || names.has(normalized(attr.value)))) secret = true;
    }
    if (!secret) continue;
    // display:none suppresses the entire subtree, including positioned children.
    // Zero-sized/contents/offscreen/visibility-hidden wrappers do not prove that.
    if (displayHidden(element)) continue;
    const rect = element.getBoundingClientRect(), style = styleOf(element);
    if (!finiteRect(rect) || rect.width === 0 || rect.height === 0 || style.display === "contents" || style.visibility !== "visible" ||
      !clipsCredentialInk(element, style) || !subtreeContained(element, rect)) { ok = false; continue; }
    if (rect.right <= 0 || rect.bottom <= 0 || rect.x >= innerWidth || rect.y >= innerHeight) continue;
    if (rects.length >= 256) { ok = false; break; }
    // A small outward margin covers antialiasing at ordinary field borders.
    const x = Math.max(0,rect.x-2), y = Math.max(0,rect.y-2);
    rects.push({X:x,Y:y,Width:Math.min(innerWidth,rect.right+2)-x,Height:Math.min(innerHeight,rect.bottom+2)-y});
  }
  return {identity:state.identity,revision:state.revision,ok,rects};
}`
