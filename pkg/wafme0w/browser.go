package wafme0w

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Lu1sDV/wafme0w/internal/browserruntime"
	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"
)

const browserHeaderBytes = 64 << 10
const browserHeaderFields = 256

// browserSession owns one process's protocol state, not a reusable browser pool.
// Only the event consumer mutates network state; readers hold mu.
type browserSession struct {
	ctx            context.Context
	cancel         context.CancelFunc
	browser        *rod.Browser
	config         Config
	policy         *targetTransport
	report         *BrowserReport
	mu             sync.Mutex
	target         proto.TargetTargetID
	session        proto.TargetSessionID
	frame          proto.PageFrameID
	loader         proto.NetworkLoaderID
	generation     uint64
	loaded         bool
	lastNetwork    time.Time
	active         map[string]bool
	documents      map[proto.NetworkRequestID]*browserDocument
	frames         map[proto.PageFrameID]browserIdentity
	pages          map[proto.TargetSessionID]*rod.Page
	mainStarts     int
	documentOrigin string
	failure        error
	ready          chan error
}

type browserDocument struct {
	extraIndex      int
	extras          []browserHeaders
	hasResponse     bool
	fromCache       bool
	expectsExtra    bool
	headersComplete bool
}

type browserHeaders struct {
	fields   []Header
	status   int
	complete bool
}

func captureBrowser(parent context.Context, target, id string, occurrence uint64, config Config) (capture browserCapture) {
	selected := *config.Browser
	capture.report = BrowserReport{
		ID: id, Occurrence: occurrence, Mode: selected.Mode, State: "failed", URL: target,
		StartedAt: time.Now().UTC(), Width: browserWidth, Height: browserHeight,
		DOM: BrowserAsset{State: "not_acquired"}, Screenshot: BrowserAsset{State: "not_selected"},
		Limits: BrowserLimits{Timeout: selected.Timeout, Settle: selected.Settle, Requests: browserMaxRequests,
			Redirects: min(3, config.MaxRedirects), DOMBytes: browserMaxDOM, ImageBytes: browserMaxImage},
		Limitations: []string{
			"Local Chromium has no OS-enforced network destination or renderer resource isolation. CDP admission covers intercepted HTTP(S) requests, not exact outbound attempts; DNS, speculative/browser-internal traffic and unsupported channel/target races may bypass it.",
			"Only scoped GET/HEAD resources are admitted. Downloads, unsolicited targets, workers and WebSocket URLs are blocked using available CDP controls; WebRTC/WebTransport and other non-Fetch channels have no complete pre-transmission CDP guarantee.",
			"Readiness describes the initial viewport, not future timers, off-screen lazy content or an unrestricted site appearance. Event streams are denied rather than counted as idle work.",
			"DOM, response metadata and pixels are correlated but not atomic. Credential geometry is checked around the screenshot; arbitrary rendered text and pixels are not guaranteed secret-free.",
		},
	}
	if selected.Mode == "screenshot" {
		capture.report.Screenshot.State = "not_acquired"
	}
	defer func() { capture.report.FinishedAt = time.Now().UTC() }()
	ctx, cancel := context.WithTimeout(parent, selected.Timeout)
	defer cancel()
	u, err := httputil.ParseURI(target)
	if err != nil {
		capture.report.State, capture.report.Reason, capture.report.Error = "skipped", "invalid_target", "invalid browser target"
		return
	}
	origin := normalizedOrigin(u)
	policy := &targetTransport{policy: &outboundPolicy{config: config}, origin: origin}
	if config.RedirectPolicy == "canonical-host" {
		policy.alias = wwwAliasOrigin(origin)
	}
	if !policy.allowed(origin) {
		capture.report.State, capture.report.Reason = "skipped", "target_scope"
		return
	}
	capture.report.URL = u.String()
	runtime, err := browserruntime.Start(ctx, browserruntime.Options{BrowserPath: selected.Path})
	if err != nil {
		capture.report.Reason, capture.report.Error = "launch_failed", browserError(err)
		if parent.Err() != nil {
			capture.report.State, capture.report.Reason = "cancelled", "cancelled"
		} else if ctx.Err() != nil {
			capture.report.Reason = "deadline_exceeded"
		}
		return
	}
	// Raw CDP contains document/header/image data: environment-enabled Rod logging
	// and monitoring must not create a second, unsanitized export path.
	quiet := log.New(io.Discard, "", 0)
	browser := rod.New().ControlURL("").Client(cdp.New().Logger(quiet).Start(runtime)).NoDefaultDevice().Context(ctx).
		Monitor("").Trace(false).SlowMotion(0).Logger(quiet)
	s := &browserSession{ctx: ctx, cancel: cancel, browser: browser, config: config, policy: policy,
		report: &capture.report, active: make(map[string]bool), documents: make(map[proto.NetworkRequestID]*browserDocument),
		frames: make(map[proto.PageFrameID]browserIdentity), pages: make(map[proto.TargetSessionID]*rod.Page),
		ready: make(chan error, 1), lastNetwork: time.Now()}
	var eventsDone chan struct{}
	var acquiredIdentity browserIdentity
	defer func() {
		cancel()
		closeErr := runtime.Close()
		if eventsDone != nil {
			<-eventsDone
		}
		if acquiredIdentity.token != "" && !s.sameDocument(acquiredIdentity) {
			capture.dom, capture.image, capture.secrets, capture.geometryOK = "", nil, nil, false
			capture.report.DOM = BrowserAsset{State: "failed"}
			if selected.Mode == "screenshot" {
				capture.report.Screenshot = BrowserAsset{State: "failed"}
			}
			capture.report.Reason = "document_changed"
			err = errors.New("document changed before capture ownership ended")
		}
		if s.failure != nil {
			err = s.failure
		}
		if err != nil {
			if capture.report.Reason == "" {
				capture.report.Reason = "capture_failed"
			}
			capture.report.Error = browserError(err)
			capture.report.State = "failed"
			if capture.report.Status != 0 || capture.report.DOM.State == "acquired" || capture.report.Screenshot.State == "acquired" {
				capture.report.State = "partial"
			}
		}
		if parent.Err() != nil {
			capture.report.State, capture.report.Reason = "cancelled", "cancelled"
			capture.report.Error = browserError(parent.Err())
		} else if errors.Is(err, context.DeadlineExceeded) {
			capture.report.Reason = "deadline_exceeded"
		}
		if closeErr != nil {
			capture.report.Limitations = append(capture.report.Limitations, "Owned Chromium process/profile cleanup failed.")
			capture.report.Error = browserError(errors.Join(err, closeErr))
			if capture.report.State == "complete" {
				capture.report.State = "partial"
			}
			if capture.report.Reason == "" {
				capture.report.Reason = "cleanup_failed"
			}
		}
		if capture.report.DOM.State == "not_acquired" {
			capture.report.DOM.State = "failed"
		}
		if capture.report.Screenshot.State == "not_acquired" {
			capture.report.Screenshot.State = "failed"
		}
	}()
	if err = browser.Connect(); err != nil {
		return
	}
	version, versionErr := (proto.BrowserGetVersion{}).Call(browser)
	if versionErr != nil {
		err = versionErr
		return
	}
	capture.report.Version = browserBounded(version.Product, 256)
	if err = (proto.BrowserSetDownloadBehavior{Behavior: proto.BrowserSetDownloadBehaviorBehaviorDeny}).Call(browser); err != nil {
		return
	}
	created, createErr := (proto.TargetCreateTarget{URL: "about:blank"}).Call(browser)
	if createErr != nil {
		err = createErr
		return
	}
	s.target = created.TargetID
	events := browser.Event()
	eventsDone = make(chan struct{})
	go func() {
		defer close(eventsDone)
		for message := range events {
			if ctx.Err() != nil {
				return
			}
			if eventErr := s.event(message); eventErr != nil {
				s.stop("control_failed", eventErr)
				return
			}
		}
		if ctx.Err() == nil {
			s.stop("browser_disconnected", errors.New("Chromium control channel closed"))
		}
	}()
	_, err = (proto.TargetAttachToTarget{TargetID: s.target, Flatten: true}).Call(browser)
	if err != nil {
		return
	}
	select {
	case err = <-s.ready:
	case <-ctx.Done():
		err = ctx.Err()
	}
	if err != nil {
		return
	}
	// The root is controlled before global auto-attachment can discover it again.
	if err = (proto.TargetSetAutoAttach{AutoAttach: true, WaitForDebuggerOnStart: true, Flatten: true}).Call(browser); err != nil {
		return
	}
	s.mu.Lock()
	root := s.session
	s.mu.Unlock()
	page := s.page(root)
	navigated, navigateErr := (proto.PageNavigate{URL: u.String()}).Call(page)
	if navigateErr != nil {
		err = navigateErr
		return
	}
	if navigated.ErrorText != "" {
		err = fmt.Errorf("main document navigation failed: %s", browserBounded(navigated.ErrorText, 256))
		return
	}
	var identity browserIdentity
	identity, err = s.waitReady()
	if err != nil {
		return
	}
	acquiredIdentity = identity
	if err = s.acquire(&capture, identity); err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	capture.report.State = "complete"
	if document := s.documents[proto.NetworkRequestID(capture.report.RequestID)]; document == nil || !document.headersComplete ||
		capture.report.RequestID == "" || capture.report.FrameID == "" || capture.report.LoaderID == "" || capture.report.Protocol == "" || capture.report.Version == "" {
		capture.report.State, capture.report.Reason = "partial", "metadata_incomplete"
		s.limitLocked("Main-document response metadata is incomplete: required CDP identity/extra-info/raw headers were missing, ambiguous or over the 64 KiB/256-field limit.")
	}
	if capture.report.DOM.Truncated {
		capture.report.State, capture.report.Reason = "partial", "dom_limit"
	}
	return
}

func browserError(err error) string {
	if err == nil {
		return ""
	}
	return browserBounded(err.Error(), 512)
}

func browserBounded(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= limit {
		return value
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (s *browserSession) stop(reason string, err error) {
	s.mu.Lock()
	if s.failure == nil {
		s.failure = err
		s.report.Reason = reason
	}
	s.mu.Unlock()
	s.cancel()
}

func (s *browserSession) limitLocked(message string) {
	if len(s.report.Limitations) < 24 && !slices.Contains(s.report.Limitations, message) {
		s.report.Limitations = append(s.report.Limitations, message)
	}
}

func (s *browserSession) page(session proto.TargetSessionID) *rod.Page {
	s.mu.Lock()
	defer s.mu.Unlock()
	if page := s.pages[session]; page != nil {
		return page
	}
	page := s.browser.PageFromSession(session)
	s.pages[session] = page
	return page
}

func (s *browserSession) setup(session proto.TargetSessionID, root bool) error {
	page := s.page(session)
	if err := (proto.NetworkEnable{}).Call(page); err != nil {
		return err
	}
	if err := (proto.NetworkSetBlockedURLs{Urls: []string{"ws://*", "wss://*"}}).Call(page); err != nil {
		return err
	}
	if err := (proto.NetworkSetBypassServiceWorker{Bypass: true}).Call(page); err != nil {
		return err
	}
	if err := (proto.FetchEnable{Patterns: []*proto.FetchRequestPattern{{URLPattern: "*", RequestStage: proto.FetchRequestStageRequest}}, HandleAuthRequests: true}).Call(page); err != nil {
		return err
	}
	if err := (proto.PageEnable{}).Call(page); err != nil {
		return err
	}
	if err := (proto.PageSetLifecycleEventsEnabled{Enabled: true}).Call(page); err != nil {
		return err
	}
	if _, err := (proto.PageAddScriptToEvaluateOnNewDocument{Source: browserReadinessInit, WorldName: browserWorld}).Call(page); err != nil {
		return err
	}
	if err := (proto.PageSetInterceptFileChooserDialog{Enabled: true}).Call(page); err != nil {
		return err
	}
	if err := (proto.TargetSetAutoAttach{AutoAttach: true, WaitForDebuggerOnStart: true, Flatten: true}).Call(page); err != nil {
		return err
	}
	if root {
		if err := (proto.EmulationSetDeviceMetricsOverride{Width: browserWidth, Height: browserHeight, DeviceScaleFactor: 1, Mobile: false}).Call(page); err != nil {
			return err
		}
	}
	tree, err := (proto.PageGetFrameTree{}).Call(page)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if root {
		s.frame = tree.FrameTree.Frame.ID
	} else {
		frame := tree.FrameTree.Frame
		if len(s.frames) >= browserMaxRequests && s.frames[frame.ID].frame == "" {
			s.mu.Unlock()
			return errors.New("frame observation limit exceeded")
		}
		s.frames[frame.ID] = browserIdentity{session: session, frame: frame.ID, loader: frame.LoaderID}
	}
	s.mu.Unlock()
	return (proto.RuntimeRunIfWaitingForDebugger{}).Call(page)
}

func (s *browserSession) event(message *rod.Message) error {
	switch message.Method {
	case "Target.attachedToTarget":
		var event proto.TargetAttachedToTarget
		message.Load(&event)
		if event.TargetInfo == nil {
			return errors.New("attached target has no identity")
		}
		s.mu.Lock()
		root := event.TargetInfo.TargetID == s.target
		duplicate := root && s.session != ""
		if root && !duplicate {
			s.session = event.SessionID
		}
		s.mu.Unlock()
		if duplicate {
			return nil
		}
		if root {
			err := s.setup(event.SessionID, true)
			s.ready <- err
			return err
		}
		if event.TargetInfo.Type == "iframe" {
			return s.setup(event.SessionID, false)
		}
		// Workers and unsolicited pages remain paused until destroyed. Their
		// initiating script/document fetch may already have been intercepted in
		// the parent; this is not an OS-level connection boundary.
		s.mu.Lock()
		s.limitLocked("Workers and unsolicited/unsupported targets were not resumed; their content is excluded from this restricted render.")
		s.mu.Unlock()
		closed, err := (proto.TargetCloseTarget{TargetID: event.TargetInfo.TargetID}).Call(s.browser)
		if err != nil {
			return err
		}
		if !closed.Success {
			return errors.New("could not close unsupported browser target")
		}
	case "Fetch.requestPaused":
		var event proto.FetchRequestPaused
		message.Load(&event)
		return s.admit(message.SessionID, &event)
	case "Fetch.authRequired":
		var event proto.FetchAuthRequired
		message.Load(&event)
		return (proto.FetchContinueWithAuth{RequestID: event.RequestID, AuthChallengeResponse: &proto.FetchAuthChallengeResponse{Response: proto.FetchAuthChallengeResponseResponseCancelAuth}}).Call(s.page(message.SessionID))
	case "Network.requestWillBeSent":
		var event proto.NetworkRequestWillBeSent
		message.Load(&event)
		s.mu.Lock()
		defer s.mu.Unlock()
		if message.SessionID != s.session || event.FrameID != s.frame || event.Type != proto.NetworkResourceTypeDocument {
			return nil
		}
		if event.Request == nil {
			return errors.New("main document request has no URL")
		}
		if len(s.documents) >= browserMaxRequests && s.documents[event.RequestID] == nil {
			return errors.New("main document provenance limit exceeded")
		}
		document := s.documents[event.RequestID]
		if document == nil {
			document = &browserDocument{}
			s.documents[event.RequestID] = document
		}
		if event.RedirectResponse != nil && event.RedirectHasExtraInfo {
			document.extraIndex++
		}
		document.hasResponse, document.headersComplete = false, false
		if s.loader != event.LoaderID {
			s.loader = event.LoaderID
			s.generation++
			s.loaded = false
			clear(s.frames)
			s.report.Readiness = BrowserReadiness{}
			s.lastNetwork = time.Now()
		}
		s.report.RequestID, s.report.LoaderID, s.report.FrameID = string(event.RequestID), string(event.LoaderID), string(event.FrameID)
		s.report.FinalURL = browserBounded(event.Request.URL, 8192)
		s.report.Status, s.report.Headers = 0, nil
		s.report.ConnectionID, s.report.Protocol = 0, ""
		s.report.FromCache, s.report.FromServiceWorker = false, false
	case "Page.frameNavigated":
		var event proto.PageFrameNavigated
		message.Load(&event)
		s.mu.Lock()
		defer s.mu.Unlock()
		if event.Frame != nil && !(message.SessionID == s.session && event.Frame.ParentID == "") {
			if len(s.frames) >= browserMaxRequests && s.frames[event.Frame.ID].frame == "" {
				return errors.New("frame observation limit exceeded")
			}
			s.frames[event.Frame.ID] = browserIdentity{session: message.SessionID, frame: event.Frame.ID, loader: event.Frame.LoaderID}
		}
		if event.Frame == nil || message.SessionID != s.session || event.Frame.ParentID != "" {
			return nil
		}
		if s.mainStarts > 0 {
			u, err := httputil.ParseURI(event.Frame.URL)
			if err != nil || !s.policy.allowed(normalizedOrigin(u)) {
				return errors.New("main document committed outside supported HTTP(S) scope")
			}
		}
		if event.Frame.LoaderID != s.loader {
			s.loader = event.Frame.LoaderID
			s.generation++
			s.loaded = false
			s.report.Readiness = BrowserReadiness{}
		}
		s.frame = event.Frame.ID
		if event.Frame.UnreachableURL != "" {
			return errors.New("Chromium committed an error document")
		}
	case "Page.frameDetached":
		var event proto.PageFrameDetached
		message.Load(&event)
		s.mu.Lock()
		if event.Reason != "swap" || s.frames[event.FrameID].session == message.SessionID {
			delete(s.frames, event.FrameID)
		}
		s.lastNetwork = time.Now()
		s.mu.Unlock()
	case "Target.detachedFromTarget":
		var event proto.TargetDetachedFromTarget
		message.Load(&event)
		s.mu.Lock()
		for frame, identity := range s.frames {
			if identity.session == event.SessionID {
				delete(s.frames, frame)
			}
		}
		for key := range s.active {
			if strings.HasPrefix(key, string(event.SessionID)+":") {
				delete(s.active, key)
				s.lastNetwork = time.Now()
			}
		}
		s.mu.Unlock()
	case "Page.navigatedWithinDocument":
		var event proto.PageNavigatedWithinDocument
		message.Load(&event)
		s.mu.Lock()
		if message.SessionID == s.session && event.FrameID == s.frame {
			s.generation++
			s.lastNetwork = time.Now()
			s.report.FinalURL = browserBounded(event.URL, 8192)
			s.report.Readiness = BrowserReadiness{}
		}
		s.mu.Unlock()
	case "Page.lifecycleEvent":
		var event proto.PageLifecycleEvent
		message.Load(&event)
		s.mu.Lock()
		if message.SessionID == s.session && event.FrameID == s.frame && event.LoaderID == s.loader && event.Name == "load" {
			s.loaded = true
		}
		s.mu.Unlock()
	case "Network.responseReceived":
		var event proto.NetworkResponseReceived
		message.Load(&event)
		s.mu.Lock()
		defer s.mu.Unlock()
		if event.Response == nil {
			return nil
		}
		if event.Response.Status >= 400 {
			s.limitLocked("One or more browser resources returned an HTTP error.")
		}
		if event.Response.MIMEType == "text/event-stream" {
			delete(s.active, string(message.SessionID)+":"+string(event.RequestID))
			s.lastNetwork = time.Now()
			s.limitLocked("Fetch-delivered event streams are excluded from finite network-idle accounting and terminated with the capture.")
		}
		if message.SessionID != s.session || event.FrameID != s.frame || event.Type != proto.NetworkResourceTypeDocument || event.LoaderID != s.loader {
			return nil
		}
		document := s.documents[event.RequestID]
		if document == nil {
			return errors.New("main document response has no correlated request")
		}
		document.hasResponse, document.expectsExtra = true, event.HasExtraInfo
		r := event.Response
		s.report.Status, s.report.FinalURL = r.Status, browserBounded(r.URL, 8192)
		s.report.ConnectionID, s.report.Protocol = r.ConnectionID, browserBounded(r.Protocol, 64)
		s.report.FromCache, s.report.FromServiceWorker = document.fromCache || r.FromDiskCache || r.FromPrefetchCache, r.FromServiceWorker
		fallback := browserReadHeaders(r.HeadersText, r.Headers)
		s.report.Headers = fallback.fields
		document.headersComplete = r.HeadersText != "" && fallback.complete
		s.applyHeaders(document)
	case "Network.responseReceivedExtraInfo":
		var event proto.NetworkResponseReceivedExtraInfo
		message.Load(&event)
		s.mu.Lock()
		defer s.mu.Unlock()
		if message.SessionID != s.session {
			return nil
		}
		document := s.documents[event.RequestID]
		if document == nil {
			return nil
		}
		if len(document.extras) >= browserMaxRequests {
			return errors.New("main document header event limit exceeded")
		}
		headers := browserReadHeaders(event.HeadersText, event.Headers)
		headers.status = event.StatusCode
		document.extras = append(document.extras, headers)
		if string(event.RequestID) == s.report.RequestID {
			s.applyHeaders(document)
		}
	case "Network.requestServedFromCache":
		var event proto.NetworkRequestServedFromCache
		message.Load(&event)
		s.mu.Lock()
		if message.SessionID == s.session {
			if document := s.documents[event.RequestID]; document != nil {
				document.fromCache = true
				if string(event.RequestID) == s.report.RequestID {
					s.report.FromCache = true
				}
			}
		}
		s.mu.Unlock()
	case "Network.loadingFinished":
		var event proto.NetworkLoadingFinished
		message.Load(&event)
		s.finished(message.SessionID, event.RequestID, false)
	case "Network.loadingFailed":
		var event proto.NetworkLoadingFailed
		message.Load(&event)
		s.finished(message.SessionID, event.RequestID, true)
	case "Network.webSocketWillSendHandshakeRequest", "Network.webTransportCreated":
		return errors.New("unsupported network channel observed; local CDP cannot guarantee pre-transmission containment")
	case "Page.javascriptDialogOpening":
		return (proto.PageHandleJavaScriptDialog{Accept: false}).Call(s.page(message.SessionID))
	}
	return nil
}

func (s *browserSession) admit(session proto.TargetSessionID, event *proto.FetchRequestPaused) error {
	page := s.page(session)
	s.mu.Lock()
	allowed := false
	reason := "Unsupported URL, method, context or channel was denied by browser request interception."
	main := session == s.session && event.FrameID == s.frame && event.ResourceType == proto.NetworkResourceTypeDocument
	if event.Request != nil {
		u, err := httputil.ParseURI(event.Request.URL)
		if err == nil && (event.Request.Method == "GET" || event.Request.Method == "HEAD") && event.ResourceType != proto.NetworkResourceTypeWebSocket && event.ResourceType != proto.NetworkResourceTypeEventSource {
			origin := normalizedOrigin(u)
			if main && s.policy.allowed(origin) {
				s.documentOrigin = origin
			}
			if main {
				allowed = s.policy.allowed(origin)
				if s.mainStarts > 0 && (s.config.RedirectPolicy == "none" || s.mainStarts > s.report.Limits.Redirects) {
					allowed = false
					reason = "Main-document redirect/navigation budget was exhausted."
				}
			} else {
				allowed = s.policy.policy.allowed(origin) && (origin == s.policy.origin || origin == s.policy.alias || origin == s.documentOrigin || slices.Contains(s.config.Browser.ResourceOrigins, origin))
			}
		}
	}
	if s.report.AdmittedRequests >= browserMaxRequests {
		allowed = false
		reason = "The 40-start logical HTTP request budget was exhausted."
	}
	if event.NetworkID == "" {
		allowed = false
		reason = "A request without correlatable Network identity was denied."
	}
	if allowed {
		s.report.AdmittedRequests++
		s.lastNetwork = time.Now()
		s.active[string(session)+":"+string(event.NetworkID)] = true
		if main {
			s.mainStarts++
			if len(s.report.RedirectChain) < 4 {
				s.report.RedirectChain = append(s.report.RedirectChain, browserBounded(event.Request.URL, 8192))
			}
		}
	} else {
		s.report.DeniedRequests++
		s.limitLocked(reason)
	}
	s.mu.Unlock()
	if !allowed {
		err := (proto.FetchFailRequest{RequestID: event.RequestID, ErrorReason: proto.NetworkErrorReasonBlockedByClient}).Call(page)
		if err != nil {
			return err
		}
		if main {
			return errors.New("main-document navigation denied by browser policy")
		}
		return nil
	}
	return (proto.FetchContinueRequest{RequestID: event.RequestID}).Call(page)
}

func (s *browserSession) finished(session proto.TargetSessionID, request proto.NetworkRequestID, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := string(session) + ":" + string(request)
	if s.active[key] {
		delete(s.active, key)
		s.lastNetwork = time.Now()
	}
	if failed {
		s.limitLocked("One or more browser resources failed or were denied; this is a restricted render.")
	}
}

func (s *browserSession) applyHeaders(document *browserDocument) {
	if document.hasResponse && document.expectsExtra && document.extraIndex < len(document.extras) {
		headers := document.extras[document.extraIndex]
		s.report.Headers = headers.fields
		if headers.status != 0 {
			s.report.Status = headers.status
		}
		document.headersComplete = headers.complete
	}
}

// CDP raw header text is authoritative when present. The CDP header map uses
// newline-separated values for repeated fields, not comma-separated cookies.
func browserReadHeaders(raw string, fields proto.NetworkHeaders) browserHeaders {
	result := browserHeaders{complete: true}
	bytesUsed := 0
	add := func(name, value string) bool {
		if !httpmeta.ValidHeaderName(name) || !httpmeta.ValidHeaderValue(value) {
			result.complete = false
			return false
		}
		if len(result.fields) >= browserHeaderFields || len(name)+len(value)+4 > browserHeaderBytes-bytesUsed {
			result.complete = false
			return false
		}
		bytesUsed += len(name) + len(value) + 4
		result.fields = append(result.fields, Header{Name: name, Value: value})
		return true
	}
	if raw != "" {
		if len(raw) > browserHeaderBytes {
			result.complete = false
			raw = raw[:browserHeaderBytes]
		}
		_, rest, ok := strings.Cut(raw, "\n")
		if !ok {
			result.complete = false
			return result
		}
		for rest != "" {
			line, next, terminated := strings.Cut(rest, "\n")
			rest = next
			line = strings.TrimSuffix(line, "\r")
			if line == "" {
				break
			}
			if !terminated {
				result.complete = false
				break
			}
			name, value, ok := strings.Cut(line, ":")
			if !ok || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				result.complete = false
				continue
			}
			if !add(name, strings.Trim(value, " \t")) {
				break
			}
		}
		return result
	}
	if len(fields) == 0 {
		result.complete = false
		return result
	}
	// Avoid allocating a key list proportional to an untrusted header map.
	if len(fields) > browserHeaderFields {
		result.complete = false
		return result
	}
	keys := make([]string, 0, len(fields))
	for name := range fields {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	for _, name := range keys {
		value, ok := fields[name].Val().(string)
		if !ok {
			result.complete = false
			continue
		}
		for {
			part, rest, more := strings.Cut(value, "\n")
			if !add(name, part) {
				return result
			}
			if !more {
				break
			}
			value = rest
		}
	}
	return result
}

func (s *browserSession) acquire(capture *browserCapture, identity browserIdentity) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	var document browserDOM
	if err := s.evaluate(identity, browserDOMScript, &document); err != nil {
		return err
	}
	if !s.sameDocument(identity) || document.Identity != identity.token {
		return errors.New("document changed during DOM acquisition")
	}
	if !utf8.ValidString(document.HTML) || len(document.HTML) > browserMaxDOM {
		return errors.New("browser returned invalid or oversized DOM")
	}
	capture.dom = document.HTML
	capture.report.DOM = BrowserAsset{State: "acquired", Bytes: len(capture.dom), Truncated: document.Truncated}
	if s.config.Browser.Mode != "screenshot" {
		return nil
	}
	var before, after browserGeometry
	fields, err := json.Marshal(browserCredentialFields)
	if err != nil {
		return err
	}
	geometryScript := "(" + browserGeometryScript + ")(" + string(fields) + ")"
	geometryErr := s.evaluate(identity, geometryScript, &before)
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if !s.sameDocument(identity) {
		return errors.New("document changed before screenshot acquisition")
	}
	// Inspect the encoded size before allocating decoded image storage.
	raw, err := s.browser.Call(s.ctx, string(identity.session), "Page.captureScreenshot",
		proto.PageCaptureScreenshot{Format: proto.PageCaptureScreenshotFormatPng, FromSurface: true,
			CaptureBeyondViewport: false})
	if err != nil {
		return err
	}
	var screenshot struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(raw, &screenshot); err != nil {
		return err
	}
	if len(screenshot.Data) > base64.StdEncoding.EncodedLen(browserMaxImage) {
		return errors.New("viewport PNG exceeded 2 MiB")
	}
	image, err := base64.StdEncoding.DecodeString(screenshot.Data)
	if err != nil || len(image) > browserMaxImage {
		return errors.New("Chromium returned invalid or oversized PNG data")
	}
	decoded, err := png.DecodeConfig(bytes.NewReader(image))
	if err != nil || decoded.Width != browserWidth || decoded.Height != browserHeight {
		return errors.New("Chromium returned an invalid viewport PNG")
	}
	capture.image = image
	capture.report.Screenshot = BrowserAsset{State: "acquired", Bytes: len(image)}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	// Inspect native shadow/frame structure after acquisition: if inspection is
	// unavailable, retain the acquired image but never export it without geometry.
	// Input controls' user-agent internals are not author shadow DOM.
	shadowOK := false
	if geometryErr == nil {
		depth := -1
		tree, treeErr := (proto.DOMGetDocument{Depth: &depth, Pierce: true}).Call(s.page(identity.session))
		if treeErr == nil {
			shadowOK = browserGeometryTreeOK(tree.Root)
		}
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	afterErr := s.evaluate(identity, geometryScript, &after)
	if !s.sameDocument(identity) || (afterErr == nil && after.Identity != identity.token) {
		return errors.New("document changed during screenshot acquisition")
	}
	capture.geometryOK = geometryErr == nil && afterErr == nil && shadowOK && before.OK && after.OK &&
		before.Identity == identity.token && before.Revision == after.Revision && slices.Equal(before.Rects, after.Rects)
	if capture.geometryOK {
		capture.secrets = before.Rects
	} else {
		s.mu.Lock()
		s.limitLocked("Screenshot credential geometry is uncertain (frame/shadow content, document/layout changes or failed inspection); image export is unavailable.")
		s.mu.Unlock()
	}
	return nil
}

func browserGeometryTreeOK(root *proto.DOMNode) bool {
	if root == nil {
		return false
	}
	if root.ContentDocument != nil || root.FrameID != "" && (root.LocalName == "iframe" || root.LocalName == "frame") {
		return false
	}
	for _, shadow := range root.ShadowRoots {
		if shadow.ShadowRootType != proto.DOMShadowRootTypeUserAgent {
			return false
		}
	}
	for _, child := range root.Children {
		if !browserGeometryTreeOK(child) {
			return false
		}
	}
	return true
}
