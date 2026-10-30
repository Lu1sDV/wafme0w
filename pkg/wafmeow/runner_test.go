package wafmeow

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

type trackedReader struct {
	io.Reader
	closed bool
}

func (r *trackedReader) Close() error { r.closed = true; return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func emptyEngine(t *testing.T) *Engine {
	t.Helper()
	engine, err := Compile([]WAF{})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestRunRejectsInvalidConfigurationBeforeReading(t *testing.T) {
	engine := emptyEngine(t)
	for _, config := range []Config{{}, {Concurrency: -1, MaxBodyBytes: 1}, {Concurrency: 1, MaxBodyBytes: -1}} {
		readErr := errors.New("input must not be read")
		err := Run(context.Background(), engine, failingReader{readErr}, config, func(Result) error { t.Fatal("unexpected result"); return nil })
		if err == nil || errors.Is(err, readErr) {
			t.Fatalf("configuration reached input: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, engine, strings.NewReader("invalid://target"), DefaultConfig(), func(Result) error { t.Fatal("unexpected result"); return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancelled context: %v", err)
	}
	if err := Run(nil, engine, strings.NewReader(""), DefaultConfig(), func(Result) error { return nil }); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := Run(context.Background(), nil, strings.NewReader(""), DefaultConfig(), func(Result) error { return nil }); err == nil {
		t.Fatal("nil engine accepted")
	}
}

func TestBrowserWrapperRejectedBeforeHTTPOrInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chromium")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Browser = &BrowserConfig{Mode: "navigate", Path: path}
	readErr := errors.New("input reached")
	err := Run(context.Background(), emptyEngine(t), failingReader{readErr}, config, func(Result) error {
		t.Fatal("invalid browser executable emitted a result")
		return nil
	})
	if err == nil || errors.Is(err, readErr) {
		t.Fatalf("browser wrapper passed configuration validation: %v", err)
	}
}

func TestBrowserTimeoutDefaultsToThirtySeconds(t *testing.T) {
	config := DefaultConfig()
	config.Browser = &BrowserConfig{Mode: "navigate"}
	if got := config.normalized().Browser.Timeout; got != 30*time.Second {
		t.Fatalf("browser timeout default = %s, want 30s", got)
	}
}

func TestRunDrainsCompletedTargetsOnBoundedInputFailure(t *testing.T) {
	sentinel := errors.New("target reader failed")
	for _, remainder := range []io.Reader{failingReader{sentinel}, strings.NewReader(strings.Repeat("x", bufio.MaxScanTokenSize+1))} {
		input := &trackedReader{Reader: io.MultiReader(strings.NewReader(" \n invalid://target \n\t\n"), remainder)}
		config := DefaultConfig()
		config.Concurrency = 2
		var results []Result
		err := Run(context.Background(), emptyEngine(t), input, config, func(result Result) error { results = append(results, result); return nil })
		if err == nil {
			t.Fatal("input failure was discarded")
		}
		if _, failed := remainder.(failingReader); failed && !errors.Is(err, sentinel) {
			t.Fatalf("reader error lost: %v", err)
		}
		if len(results) != 1 || results[0].Target != "invalid://target" || results[0].Outcome.State != Failed || len(results[0].Outcome.Diagnostics) == 0 {
			t.Fatalf("completed failure lost: %+v", results)
		}
		if input.closed {
			t.Fatal("caller reader was closed")
		}
	}
}

func TestSinkFailureCancelsActiveWorkers(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		close(cancelled)
		return nil, request.Context().Err()
	})}
	sentinel := errors.New("sink unavailable")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	config := DefaultConfig()
	config.Concurrency = 2
	config.Client = client
	calls := 0
	err := Run(ctx, emptyEngine(t), strings.NewReader("http://fixture.invalid\ninvalid://ready\n"), config, func(Result) error {
		calls++
		select {
		case <-started:
		case <-ctx.Done():
			return ctx.Err()
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) || calls != 1 {
		t.Fatalf("sink failure lost or callback repeated: calls=%d err=%v", calls, err)
	}
	select {
	case <-cancelled:
	default:
		t.Fatal("Run returned before active worker stopped")
	}
}

func TestRunCancellationStopsActiveRequests(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		close(started)
		<-request.Context().Done()
		close(stopped)
		return nil, request.Context().Err()
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engine := emptyEngine(t)
	config := DefaultConfig()
	config.Concurrency = 1
	config.Client = client
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, engine, strings.NewReader("http://fixture.invalid"), config, func(Result) error { return nil })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Run did not stop")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("active request leaked")
	}
}

type signalSecondRead struct {
	io.Reader
	reads   int
	blocked chan struct{}
}

func (r *signalSecondRead) Read(buffer []byte) (int, error) {
	r.reads++
	if r.reads == 2 {
		close(r.blocked)
	}
	return r.Reader.Read(buffer)
}

func TestSinkFailureWakesBlockedOwnedInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	input := &signalSecondRead{Reader: reader, blocked: make(chan struct{})}
	sentinel := errors.New("publication failed")
	config := DefaultConfig()
	wakeups := 0
	config.CancelInput = func() {
		wakeups++
		reader.CloseWithError(sentinel)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	engine := emptyEngine(t)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, engine, input, config, func(Result) error {
			<-input.blocked
			return sentinel
		})
	}()
	if _, err := io.WriteString(writer, "invalid://fixture\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, sentinel) || errors.Is(err, context.DeadlineExceeded) || wakeups != 1 {
			t.Fatalf("sink failure did not wake input exactly once: %v, wakeups=%d", err, wakeups)
		}
	case <-ctx.Done():
		t.Fatal("sink failure abandoned the blocked input")
	}
}

func TestSuccessfulRunDoesNotCancelInput(t *testing.T) {
	config := DefaultConfig()
	config.CancelInput = func() { t.Error("normal EOF cancelled caller input") }
	if err := Run(context.Background(), emptyEngine(t), strings.NewReader("invalid://fixture\n"), config, func(Result) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestRunProvenanceIncludesEffectiveAcquisitionSettings(t *testing.T) {
	for _, configured := range []bool{false, true} {
		config := DefaultConfig()
		wantHeaders, wantEvidence := config.MaxResponseHeaderBytes, config.MaxTargetEvidenceBytes
		wantProbes := 1
		if configured {
			config.MaxResponseHeaderBytes, config.MaxTargetEvidenceBytes = 3072, 8192
			config.ProbeConcurrency, wantProbes = 3, 3
			wantHeaders, wantEvidence = 3072, 8192
		} else {
			config.MaxResponseHeaderBytes, config.MaxTargetEvidenceBytes = 0, 0
			config.ProbeConcurrency = 0
		}
		var settings ScanSettings
		err := Run(context.Background(), emptyEngine(t), strings.NewReader("invalid://fixture"), config, func(result Result) error {
			settings = result.Provenance.Settings
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if settings.MaxResponseHeaderBytes != wantHeaders || settings.MaxTargetEvidenceBytes != wantEvidence || settings.ProbeConcurrency != wantProbes {
			t.Fatalf("configured=%t: effective evidence limits missing from provenance: %+v", configured, settings)
		}
	}
}

type oneTargetPerRead struct {
	remaining int
	reads     int
}

func (input *oneTargetPerRead) Read(buffer []byte) (int, error) {
	if input.remaining == 0 {
		return 0, io.EOF
	}
	input.remaining--
	input.reads++
	return copy(buffer, "invalid://fixture\n"), nil
}

func TestRunBackpressureBoundsRetainedResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.Concurrency = 2
		const total = 100
		input := &oneTargetPerRead{remaining: total}
		started, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		engine := emptyEngine(t)
		calls := 0
		go func() {
			done <- Run(context.Background(), engine, input, config, func(Result) error {
				calls++
				if calls == 1 {
					close(started)
					<-release
				}
				return nil
			})
		}()
		<-started
		synctest.Wait()
		// Two workers may hold results, one is inside emit, and the scanner
		// may have read one target while waiting for worker admission.
		if got, want := input.reads, config.Concurrency+2; got != want {
			t.Errorf("blocked sink admitted %d targets, want %d", got, want)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if calls != total {
			t.Fatalf("emitted %d results, want %d", calls, total)
		}
	})
}

func TestRunEmitsInCompletionOrder(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	config := DefaultConfig()
	config.Concurrency, config.BaselineOnly = 2, true
	config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() == "slow.invalid" {
			close(started)
			select {
			case <-release:
			case <-request.Context().Done():
				return nil, request.Context().Err()
			}
		} else {
			<-started
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	var targets []string
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := Run(ctx, emptyEngine(t), strings.NewReader("http://slow.invalid\nhttp://fast.invalid"), config, func(result Result) error {
		targets = append(targets, result.Target)
		if len(targets) == 1 {
			close(release)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0] != "http://fast.invalid" || targets[1] != "http://slow.invalid" {
		t.Fatalf("results were not emitted in completion order: %v", targets)
	}
}

func browserStageConfig(t *testing.T) Config {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("browser capture requires Linux")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.BaselineOnly = true
	config.Browser = &BrowserConfig{Mode: "navigate", Path: executable}
	return config
}

func savedBrowserCapture(t *testing.T, target, id string, occurrence uint64, config Config) browserCapture {
	t.Helper()
	dom := fmt.Sprintf("<!doctype html><h1>browser-marker-%d</h1><input name=password value=browser-secret>", occurrence)
	return browserCapture{
		report: BrowserReport{ID: id, Occurrence: occurrence, Mode: config.Browser.Mode, State: "complete",
			StartedAt: time.Now().UTC(), FinishedAt: time.Now().UTC(),
			URL: target + "?token=browser-query-secret", DOM: BrowserAsset{State: "acquired", Bytes: len(dom)},
			Screenshot: BrowserAsset{State: "not_selected"}, Headers: []Header{{Name: "Authorization", Value: "browser-header-secret"}}},
		dom: dom, domSnapshot: browserDOMSnapshotFixture(t, dom),
	}
}

func TestRunBrowserStageFreesHTTPWorkersAndBoundsQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := browserStageConfig(t)
		config.Concurrency = 1
		var requests, captures, activeCaptures, exports atomic.Int32
		config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("http-only marker")), Request: request}, nil
		})}
		input := &captureRecordsReader{records: make([]string, 30)}
		for i := range input.records {
			input.records[i] = fmt.Sprintf("http://fixture.invalid/%d\n", i)
		}
		release := make(chan struct{})
		var results []Result
		releaseExports := make(chan struct{})
		config.Browser.SaveText = func(ctx context.Context, artifact BrowserArtifact) (string, error) {
			exports.Add(1)
			select {
			case <-releaseExports:
				return "owned-" + artifact.CaptureID, nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		engine := emptyEngine(t)
		done := make(chan error, 1)
		go func() {
			done <- run(context.Background(), engine, input, config, func(result Result) error {
				results = append(results, result)
				return nil
			}, func(ctx context.Context, target, id string, occurrence uint64, config Config) browserCapture {
				if activeCaptures.Add(1) != 1 {
					t.Error("Chromium captures overlapped")
				}
				defer activeCaptures.Add(-1)
				captures.Add(1)
				if occurrence == 1 {
					<-release
				}
				return savedBrowserCapture(t, target, id, occurrence, config)
			})
		}()
		synctest.Wait()
		// One browser capture, one queued HTTP result, one HTTP worker waiting
		// to queue its result, and one scanner-held target: all fixed bounds.
		if requests.Load() != 3 || captures.Load() != 1 || input.readRecords != 4 || len(results) != 0 {
			t.Errorf("browser blocked HTTP workers or admitted an unbounded queue: HTTP=%d captures=%d read=%d results=%d",
				requests.Load(), captures.Load(), input.readRecords, len(results))
		}
		time.Sleep(time.Second) // Advances only fake time while the first capture is blocked.
		close(release)
		synctest.Wait()
		if captures.Load() != 2 || exports.Load() != 2 || requests.Load() != 5 || input.readRecords != 6 || len(results) != 0 {
			t.Errorf("blocked exports retained unbounded captures or HTTP results: captures=%d exports=%d HTTP=%d read=%d results=%d",
				captures.Load(), exports.Load(), requests.Load(), input.readRecords, len(results))
		}
		close(releaseExports)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if len(results) != len(input.records) || captures.Load() != int32(len(input.records)) || activeCaptures.Load() != 0 {
			t.Fatalf("browser pipeline lost work or returned before joining: results=%d captures=%d active=%d", len(results), captures.Load(), activeCaptures.Load())
		}
		for _, result := range results {
			if report := result.Browser; report.Occurrence == 2 && !report.QueuedAt.Before(report.StartedAt) {
				t.Errorf("QueuedAt was recorded after waiting for Chromium: %+v", report)
			}
		}
	})
}

func TestRunBrowserStageAssociatesOccurrencesAndOverlapsSanitizedExports(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := browserStageConfig(t)
		config.Concurrency = 3
		firstBrowser := make(chan struct{})
		var firstOnce sync.Once
		config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path == "/slow" {
				select {
				case <-firstBrowser:
				case <-request.Context().Done():
					return nil, request.Context().Err()
				}
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("http-only marker private-http-body")), Request: request}, nil
		})}
		secondExport := make(chan struct{})
		var exports atomic.Int32
		var savedMu sync.Mutex
		saved := make(map[uint64]string)
		config.Browser.SaveText = func(ctx context.Context, artifact BrowserArtifact) (string, error) {
			content, err := io.ReadAll(artifact.Content)
			if err != nil {
				return "", err
			}
			if strings.Contains(string(content), "browser-secret") || !strings.Contains(string(content), fmt.Sprintf("browser-marker-%d", artifact.Occurrence)) {
				t.Errorf("artifact was unsanitized or associated with another occurrence: %q", content)
			}
			if exports.Add(1) == 1 {
				select {
				case <-secondExport:
				case <-ctx.Done():
					return "", ctx.Err()
				}
			} else {
				firstOnce.Do(func() { close(secondExport) })
			}
			reference := "owned-" + artifact.CaptureID
			savedMu.Lock()
			saved[artifact.Occurrence] = reference
			savedMu.Unlock()
			return reference, nil
		}
		engine, err := Compile([]WAF{
			{Name: "HTTP fixture", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "http-only marker"}}}}},
			{Name: "Browser must not classify", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "browser-marker"}}}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		targets := []string{"http://fixture.invalid/slow", "http://fixture.invalid/duplicate", "http://fixture.invalid/duplicate", "http://fixture.invalid/last"}
		var captureOrder []uint64
		var results []Result
		err = run(context.Background(), engine, strings.NewReader(strings.Join(targets, "\n")), config, func(result Result) error {
			results = append(results, result)
			return nil
		}, func(ctx context.Context, target, id string, occurrence uint64, config Config) browserCapture {
			captureOrder = append(captureOrder, occurrence)
			if len(captureOrder) == 1 {
				close(firstBrowser)
			}
			return savedBrowserCapture(t, target, id, occurrence, config)
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(results) != len(targets) || exports.Load() != int32(len(targets)) || len(captureOrder) != len(targets) || captureOrder[0] == 1 {
			t.Fatalf("did not exercise HTTP reordering and overlapping exports: results=%d exports=%d capture order=%v", len(results), exports.Load(), captureOrder)
		}
		ids := make(map[string]bool)
		occurrences := make(map[uint64]bool)
		for _, result := range results {
			report := result.Browser
			if report == nil || report.Occurrence == 0 || report.Occurrence > uint64(len(targets)) {
				t.Fatalf("missing browser identity: %+v", report)
			}
			if result.Target != targets[report.Occurrence-1] || occurrences[report.Occurrence] || ids[report.ID] {
				t.Fatalf("browser identity drifted from the HTTP occurrence: target=%q report=%+v", result.Target, report)
			}
			occurrences[report.Occurrence], ids[report.ID] = true, true
			if report.DOM.SaveState != "saved" || report.DOM.Saved != saved[report.Occurrence] || report.QueuedAt.IsZero() {
				t.Fatalf("artifact did not follow its occurrence: %+v", report)
			}
			if len(result.Outcome.Matches) != 1 || result.Outcome.Matches[0].Product != "HTTP fixture" {
				t.Fatalf("browser assets contaminated HTTP classification: %+v", result.Outcome)
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"browser-secret", "browser-query-secret", "browser-header-secret", "private-http-body", "browser-marker"} {
				if strings.Contains(string(encoded), secret) {
					t.Errorf("queued result retained private acquired content %q", secret)
				}
			}
		}
	})
}

func TestRunBrowserStageSerializesResultCallbacks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := browserStageConfig(t)
		config.Concurrency = 2
		config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		})}
		var exports, calls, active atomic.Int32
		config.Browser.SaveText = func(_ context.Context, artifact BrowserArtifact) (string, error) {
			exports.Add(1)
			return "owned-" + artifact.CaptureID, nil
		}
		started, release := make(chan struct{}), make(chan struct{})
		releaseCallbacks := sync.OnceFunc(func() { close(release) })
		defer releaseCallbacks()
		engine := emptyEngine(t)
		done := make(chan error, 1)
		go func() {
			done <- run(context.Background(), engine, strings.NewReader("http://fixture.invalid/first\nhttp://fixture.invalid/second\n"), config, func(Result) error {
				active.Add(1)
				defer active.Add(-1)
				if calls.Add(1) == 1 {
					close(started)
					<-release
				}
				return nil
			}, func(_ context.Context, target, id string, occurrence uint64, config Config) browserCapture {
				return savedBrowserCapture(t, target, id, occurrence, config)
			})
		}()
		<-started
		synctest.Wait()
		if exports.Load() != 2 || calls.Load() != 1 {
			t.Errorf("ready browser results overlapped a blocked callback: exports=%d callbacks=%d", exports.Load(), calls.Load())
		}
		releaseCallbacks()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 || active.Load() != 0 {
			t.Fatalf("result callbacks were lost or not joined: calls=%d active=%d", calls.Load(), active.Load())
		}
	})
}

func TestRunBrowserStageCancellationAndSinkFailureJoinAllOwners(t *testing.T) {
	for _, sinkFailure := range []bool{false, true} {
		t.Run(fmt.Sprintf("sink-failure=%t", sinkFailure), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader, writer := io.Pipe()
				defer reader.Close()
				defer writer.Close()
				input := &signalSecondRead{Reader: reader, blocked: make(chan struct{})}
				config := browserStageConfig(t)
				config.Concurrency = 2
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				sentinel := errors.New("browser result sink failed")
				firstBrowser, browserActive, browserStopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
				exportActive, exportCancelled, exportStopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
				releaseExport := make(chan struct{})
				finishExport := sync.OnceFunc(func() { close(releaseExport) })
				defer finishExport()
				config.Browser.SaveText = func(ctx context.Context, artifact BrowserArtifact) (string, error) {
					if artifact.Occurrence == 2 {
						close(exportActive)
						<-ctx.Done()
						close(exportCancelled)
						<-releaseExport
						close(exportStopped)
						return "", ctx.Err()
					}
					return "owned-" + artifact.CaptureID, nil
				}
				httpActive, httpStopped := make(chan struct{}), make(chan struct{})
				config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
					switch request.URL.Path {
					case "/export-active":
						select {
						case <-firstBrowser:
						case <-request.Context().Done():
							return nil, request.Context().Err()
						}
					case "/browser-active":
						select {
						case <-exportActive:
						case <-request.Context().Done():
							return nil, request.Context().Err()
						}
					case "/http-active":
						close(httpActive)
						<-request.Context().Done()
						close(httpStopped)
						return nil, request.Context().Err()
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
				})}
				wakeups := 0
				config.CancelInput = func() {
					wakeups++
					_ = reader.Close()
				}
				calls := 0
				engine := emptyEngine(t)
				done := make(chan error, 1)
				go func() {
					done <- run(ctx, engine, input, config, func(Result) error {
						calls++
						<-browserActive
						<-exportActive
						<-httpActive
						<-input.blocked
						if sinkFailure {
							return sentinel
						}
						cancel()
						return nil
					}, func(ctx context.Context, target, id string, occurrence uint64, config Config) browserCapture {
						if strings.HasSuffix(target, "/first") {
							close(firstBrowser)
						} else if strings.HasSuffix(target, "/browser-active") {
							close(browserActive)
							<-ctx.Done()
							close(browserStopped)
						}
						return savedBrowserCapture(t, target, id, occurrence, config)
					})
				}()
				if _, err := io.WriteString(writer, "http://fixture.invalid/first\nhttp://fixture.invalid/export-active\nhttp://fixture.invalid/browser-active\nhttp://fixture.invalid/http-active\n"); err != nil {
					t.Fatal(err)
				}
				<-exportCancelled
				synctest.Wait()
				var err error
				returned := false
				select {
				case err = <-done:
					returned = true
					t.Errorf("Run returned before its cancelled artifact callback finished: %v", err)
				default:
				}
				finishExport()
				if !returned {
					err = <-done
				}
				want := error(context.Canceled)
				if sinkFailure {
					want = sentinel
				}
				if !errors.Is(err, want) || calls != 1 || wakeups != 1 {
					t.Fatalf("shutdown changed first failure or emitted again: err=%v calls=%d wakeups=%d", err, calls, wakeups)
				}
				for name, stopped := range map[string]<-chan struct{}{"HTTP": httpStopped, "browser": browserStopped, "export": exportStopped} {
					select {
					case <-stopped:
					default:
						t.Errorf("%s owner was not joined", name)
					}
				}
			})
		})
	}
}

func TestRunBrowserStageDrainsCompletedWorkAfterInputFailure(t *testing.T) {
	config := browserStageConfig(t)
	config.Client = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
	})}
	sentinel := errors.New("target input failed")
	input := &trackedReader{Reader: io.MultiReader(strings.NewReader("http://fixture.invalid/first\nhttp://fixture.invalid/second\n"), failingReader{sentinel})}
	var results []Result
	err := run(context.Background(), emptyEngine(t), input, config, func(result Result) error {
		results = append(results, result)
		return nil
	}, func(ctx context.Context, target, id string, occurrence uint64, config Config) browserCapture {
		return savedBrowserCapture(t, target, id, occurrence, config)
	})
	if !errors.Is(err, sentinel) || len(results) != 2 || input.closed {
		t.Fatalf("input failure discarded browser work or closed caller input: err=%v results=%d closed=%v", err, len(results), input.closed)
	}
	for _, result := range results {
		if result.Browser == nil || result.Browser.State != "complete" {
			t.Fatalf("completed browser capture was not drained: %+v", result.Browser)
		}
	}
}
