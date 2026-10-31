package wafmeow

import (
	"bufio"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	httputil "github.com/Lu1sDV/wafmeow/v3/pkg/utils/http"
)

const ResultSchemaVersion = 1

var programVersion = func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}
	version := info.Main.Version
	if version == "" || version == "(devel)" {
		version = "devel"
	}
	var revision string
	var dirty bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if revision != "" {
		version += "+" + revision
	}
	if dirty {
		version += ".dirty"
	}
	return version
}()

// releaseVersion is set only by the release build's Go -ldflags -X option.
// Local builds and go install retain their original module/VCS-derived version.
var releaseVersion string

// Version reports the selected immutable release tag for packaged binaries.
// For development and module installs it preserves Go module/VCS identity.
func Version() string {
	if releaseVersion != "" {
		return releaseVersion
	}
	return programVersion
}

type ScanSettings struct {
	Concurrency                int           `json:"concurrency"`
	ProbeConcurrency           int           `json:"probe_concurrency"`
	FastMode                   bool          `json:"fast_mode"`
	BaselineOnly               bool          `json:"baseline_only"`
	Passive                    bool          `json:"passive"`
	ExcludeGeneric             bool          `json:"exclude_generic"`
	MaxBodyBytes               int64         `json:"max_body_bytes"`
	MaxResponseHeaderBytes     int64         `json:"max_response_header_bytes"`
	MaxTargetEvidenceBytes     int64         `json:"max_target_evidence_bytes"`
	RequestTimeout             time.Duration `json:"request_timeout"`
	TargetTimeout              time.Duration `json:"target_timeout"`
	MaxRequests                int           `json:"max_requests"`
	MaxConnections             int           `json:"max_connections"`
	RequestsPerSecond          float64       `json:"requests_per_second"`
	PerOriginRequestsPerSecond float64       `json:"per_origin_requests_per_second"`
	MaxRedirects               int           `json:"max_redirects"`
	RedirectPolicy             string        `json:"redirect_policy"`
	AllowedOrigins             []string      `json:"allowed_origins,omitempty"`
}

type ResultProvenance struct {
	ProgramVersion  string            `json:"program_version"`
	CatalogueSHA256 string            `json:"catalogue_sha256"`
	ScanMode        string            `json:"scan_mode"` // "deep", "fast", "baseline", or "passive"
	Settings        ScanSettings      `json:"settings"`
	Import          *ImportProvenance `json:"import,omitempty"`
}

type Result struct {
	SchemaVersion int               `json:"schema_version"`
	Target        string            `json:"target"`
	Origin        string            `json:"origin"`
	Provenance    ResultProvenance  `json:"provenance"`
	Evidence      []EvidenceSummary `json:"evidence"`
	Outcome       Outcome           `json:"outcome"`
	Generic       GenericDetection  `json:"generic"`
	Browser       *BrowserReport    `json:"browser,omitempty"`
}

func makeResult(engine *Engine, target, origin string, evidence []Evidence, config Config) Result {
	mode := "deep"
	if config.Passive {
		mode = "passive"
	} else if config.BaselineOnly {
		mode = "baseline"
	} else if config.FastMode {
		mode = "fast"
	}
	result := Result{
		SchemaVersion: ResultSchemaVersion, Target: target, Origin: origin, Outcome: engine.Classify(evidence),
		Evidence: make([]EvidenceSummary, len(evidence)),
		Provenance: ResultProvenance{
			ProgramVersion: Version(), CatalogueSHA256: engine.Digest(), ScanMode: mode,
			Settings: ScanSettings{
				Concurrency: config.Concurrency, ProbeConcurrency: config.ProbeConcurrency,
				FastMode: config.FastMode, BaselineOnly: config.BaselineOnly,
				Passive: config.Passive, ExcludeGeneric: config.ExcludeGeneric, MaxBodyBytes: config.MaxBodyBytes,
				MaxResponseHeaderBytes: config.MaxResponseHeaderBytes, MaxTargetEvidenceBytes: config.MaxTargetEvidenceBytes,
				RequestTimeout: config.RequestTimeout, TargetTimeout: config.TargetTimeout,
				MaxRequests: config.MaxRequests, MaxConnections: config.MaxConnections,
				RequestsPerSecond: config.RequestsPerSecond, PerOriginRequestsPerSecond: config.PerOriginRequestsPerSecond,
				MaxRedirects: config.MaxRedirects, RedirectPolicy: config.RedirectPolicy,
				AllowedOrigins: slices.Clone(config.AllowedOrigins),
			},
		},
	}
	for i, observation := range evidence {
		result.Evidence[i] = EvidenceSummary{
			Index: i, Role: observation.Role, RequestURL: observation.RequestURL,
			EffectiveURL: observation.EffectiveURL, RedirectChain: slices.Clone(observation.RedirectChain),
			StatusCode: observation.StatusCode, BodyTruncated: observation.BodyTruncated, ErrorCode: observation.ErrorCode,
		}
		if observation.Availability != nil {
			availability := *observation.Availability
			result.Evidence[i].Availability = &availability
		}
		if observation.ErrorCode == "redirect_scope" {
			base, err := url.Parse(observation.EffectiveURL)
			if err == nil {
				for _, header := range observation.Headers {
					if strings.EqualFold(header.Name, "Location") {
						if destination, err := base.Parse(header.Value); err == nil {
							result.Evidence[i].BlockedRedirectURL = destination.String()
						}
						break
					}
				}
			}
		}
	}
	if !config.ExcludeGeneric {
		result.Generic = GenericDetect(evidence)
	}
	return result
}

// Run streams one result per nonblank input line to emit, serially in completion
// order. Target failures are results; configuration, input, context, and sink
// failures are returned. HTTP workers pass only body-free results to a bounded
// browser stage with one fresh Chromium capture at a time and two export workers.
// Without browser observation, both work queues are unbuffered. Input lines are
// bounded by bufio.MaxScanTokenSize. Run never closes inputs or retains results.
//
// A blocking reader requires Config.CancelInput (or independent caller wakeup).
// Cancellation, including private sink-failure cancellation, invokes that callback.
// No input scanner goroutine is abandoned. Emit must also return for shutdown.
func Run(ctx context.Context, engine *Engine, inputs io.Reader, config Config, emit func(Result) error) error {
	return run(ctx, engine, inputs, config, emit, captureBrowser)
}

func run(ctx context.Context, engine *Engine, inputs io.Reader, config Config, emit func(Result) error,
	capture func(context.Context, string, string, uint64, Config) browserCapture) error {
	if ctx == nil || engine == nil || inputs == nil || emit == nil {
		return errors.New("context, engine, inputs, and result callback are required")
	}
	config = config.normalized()
	if err := config.validate(); err != nil {
		return err
	}
	if config.Passive {
		return errors.New("passive configuration requires RunCaptured")
	}
	var inputWake sync.Once
	wakeInput := func() {
		inputWake.Do(func() {
			if config.CancelInput != nil {
				config.CancelInput()
			}
		})
	}
	if err := ctx.Err(); err != nil {
		wakeInput()
		return err
	}
	workCtx, cancel := context.WithCancel(ctx)
	inputWoken := make(chan struct{})
	stopWake := context.AfterFunc(workCtx, func() {
		wakeInput()
		close(inputWoken)
	})
	defer func() {
		if !stopWake() {
			<-inputWoken
		}
		cancel()
	}()
	policy := newOutboundPolicy(config)
	if policy.ownedTransport != nil {
		defer policy.ownedTransport.CloseIdleConnections()
	}
	type targetWork struct {
		target     string
		occurrence uint64
	}
	targets := make(chan targetWork)
	results := make(chan Result)
	var browserJobs chan browserWork
	var browserDone chan struct{}
	if config.Browser != nil && config.Browser.Mode != "off" {
		browserJobs = make(chan browserWork, min(config.Concurrency, 20))
		browserDone = make(chan struct{})
		go func() {
			defer close(browserDone)
			runBrowserStage(workCtx, browserJobs, results, config, policy, capture)
		}()
	}
	sinkErrors := make(chan error, 1)
	go func() {
		var sinkErr error
		for result := range results {
			if sinkErr == nil && workCtx.Err() == nil {
				if err := emit(result); err != nil {
					sinkErr = fmt.Errorf("emit result: %w", err)
					cancel()
				}
			}
		}
		sinkErrors <- sinkErr
	}()
	var workers sync.WaitGroup
	workers.Add(config.Concurrency)
	for range config.Concurrency {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case work, ok := <-targets:
					if !ok || workCtx.Err() != nil {
						return
					}
					result := classifyTarget(workCtx, engine, work.target, config, policy)
					if browserJobs != nil {
						work := browserWork{result: result, occurrence: work.occurrence, queuedAt: time.Now().UTC()}
						select {
						case browserJobs <- work:
						case <-workCtx.Done():
							return
						}
					} else {
						select {
						case results <- result:
						case <-workCtx.Done():
							return
						}
					}
				}
			}
		}()
	}
	scanner := bufio.NewScanner(inputs)
	var occurrence uint64
	for workCtx.Err() == nil && scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target == "" {
			continue
		}
		occurrence++
		select {
		case <-workCtx.Done():
		case targets <- targetWork{target: target, occurrence: occurrence}:
		}
	}
	close(targets)
	var inputErr error
	if err := scanner.Err(); err != nil {
		inputErr = fmt.Errorf("read targets: %w", err)
		wakeInput()
	}
	workers.Wait()
	if browserJobs != nil {
		close(browserJobs)
		<-browserDone
	}
	close(results)
	return errors.Join(inputErr, <-sinkErrors, ctx.Err())
}

func classifyTarget(ctx context.Context, engine *Engine, target string, config Config, policy *outboundPolicy) Result {
	u, err := httputil.ParseURI(target)
	if err != nil {
		result := makeResult(engine, target, "", nil, config)
		result.Outcome = Outcome{State: Failed, Diagnostics: []Diagnostic{{Code: "invalid_target", Evidence: -1, Message: err.Error()}}}
		return result
	}
	origin := normalizedOrigin(u)
	if !policy.allowed(origin) {
		result := makeResult(engine, target, origin, nil, config)
		result.Outcome = Outcome{State: Failed, Diagnostics: []Diagnostic{{Code: "target_scope", Evidence: -1, Message: "starting URL is outside permitted origins"}}}
		return result
	}
	targetCtx, cancel := context.WithTimeout(ctx, config.TargetTimeout)
	// Browser acquisition gets its own deadline after HTTP resources are released.
	evidence := sendRequests(targetCtx, u.String(), policy.client(origin), config)
	cancel()
	return makeResult(engine, target, origin, evidence, config)
}

type browserWork struct {
	result     Result
	occurrence uint64
	queuedAt   time.Time
}

type browserExportWork struct {
	result  Result
	capture browserCapture
}

func runBrowserStage(ctx context.Context, jobs <-chan browserWork, results chan<- Result, config Config, policy *outboundPolicy,
	acquire func(context.Context, string, string, uint64, Config) browserCapture) {
	// ponytail: two exports allow a slow artifact sink to overlap the next fresh
	// capture without retaining raw assets proportional to target concurrency.
	const exportWorkers = 2
	permits := make(chan struct{}, exportWorkers)
	captures := make(chan browserExportWork)
	var exporters sync.WaitGroup
	for range exportWorkers {
		exporters.Add(1)
		go func() {
			defer exporters.Done()
			for work := range captures {
				if ctx.Err() != nil {
					<-permits
					continue
				}
				work.result.Browser = exportBrowserCapture(ctx, &work.capture, *config.Browser)
				// Only sanitized, body-free metadata may wait on result emission.
				work.capture = browserCapture{}
				select {
				case results <- work.result:
				case <-ctx.Done():
				}
				<-permits
			}
		}()
	}
	defer func() {
		close(captures)
		exporters.Wait()
	}()
	runID := rand.Text()
	for {
		var work browserWork
		select {
		case <-ctx.Done():
			return
		case next, ok := <-jobs:
			if !ok {
				return
			}
			work = next
		}
		select {
		case permits <- struct{}{}:
		case <-ctx.Done():
			return
		}
		if ctx.Err() != nil {
			<-permits
			return
		}
		id := fmt.Sprintf("%s-%d", runID, work.occurrence)
		var capture browserCapture
		if work.result.Origin == "" || !policy.allowed(work.result.Origin) {
			capture.report = BrowserReport{
				ID: id, Occurrence: work.occurrence, Mode: config.Browser.Mode,
				State: "skipped", Reason: "target_scope", URL: work.result.Target,
				DOM: BrowserAsset{State: "skipped"}, Screenshot: BrowserAsset{State: "skipped"},
			}
		} else {
			capture = acquire(ctx, work.result.Target, id, work.occurrence, config)
		}
		capture.report.QueuedAt = work.queuedAt
		select {
		case captures <- browserExportWork{result: work.result, capture: capture}:
		case <-ctx.Done():
			<-permits
			return
		}
	}
}
