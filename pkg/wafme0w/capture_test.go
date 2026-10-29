package wafme0w

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestRunCapturedRejectsLiveBrowserBeforeReading(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inputErr := errors.New("capture input must remain unread")
	for _, mode := range []string{"navigate", "screenshot"} {
		config := DefaultConfig()
		config.Browser = &BrowserConfig{Mode: mode, Path: executable}
		err := RunCaptured(context.Background(), emptyEngine(t), failingReader{inputErr}, config, func(Result) error {
			t.Fatal("live browser configuration emitted an offline result")
			return nil
		})
		if err == nil || errors.Is(err, inputErr) {
			t.Fatalf("%s browser mode reached offline input: %v", mode, err)
		}
	}
}

func TestRunCapturedClassifiesWithoutAcquisition(t *testing.T) {
	engine, err := Compile([]WAF{{Name: "Capture marker", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "saved marker"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	capture := Capture{Target: "saved-origin", Evidence: []Evidence{{Role: "Normal", StatusCode: 200, Reason: "OK\tcaptured", Body: []byte("saved marker: private body"), Headers: []Header{{Name: "X-Private", Value: "private header\tvalue"}}}}}
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(capture); err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("captured evidence attempted a network request")
		return nil, errors.New("network forbidden")
	})}
	var results []Result
	if err := RunCaptured(context.Background(), engine, &input, config, func(result Result) error {
		results = append(results, result)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Target != capture.Target || results[0].Outcome.State != Complete {
		t.Fatalf("capture not classified: %+v", results)
	}
	if results[0].Origin != "" {
		t.Fatalf("opaque capture label acquired an invented origin: %q", results[0].Origin)
	}
	matches := results[0].Outcome.Matches
	if len(matches) != 1 || matches[0].Product != "Capture marker" || len(matches[0].Fingerprints) != 1 || matches[0].Fingerprints[0].Evidence != 0 {
		t.Fatalf("missing captured match evidence: %+v", matches)
	}
	encoded, err := json.Marshal(results[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{base64.StdEncoding.EncodeToString(capture.Evidence[0].Body), "private body", "private header", "X-Private"} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("result retained response content %q", secret)
		}
	}
}

func TestRunCapturedRejectsInvalidRecordsBeforeEmission(t *testing.T) {
	engine := emptyEngine(t)
	config := DefaultConfig()
	config.MaxBodyBytes = 2
	for name, record := range map[string]string{
		"unknown field":          `{"target":"saved","evidence":[],"unexpected":true}`,
		"extra object":           `{"target":"saved","evidence":[]} {}`,
		"missing array":          `{"target":"saved"}`,
		"invalid header":         `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"headers":[{"name":"X Invalid","value":"v"}]}]}`,
		"oversized decoded body": `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"body":"YWJj"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := RunCaptured(context.Background(), engine, strings.NewReader(record), config, func(Result) error {
				t.Fatal("invalid record emitted a result")
				return nil
			})
			if err == nil {
				t.Fatal("invalid record accepted")
			}
		})
	}
}

type capturePipe struct {
	*io.PipeReader
	started chan struct{}
}

func (reader capturePipe) Read(buffer []byte) (int, error) {
	select {
	case <-reader.started:
	default:
		close(reader.started)
	}
	return reader.PipeReader.Read(buffer)
}

func TestRunCapturedCancellationUnblocksOwnedInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	started := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	config := DefaultConfig()
	config.CancelInput = func() { _ = reader.Close() }
	engine := emptyEngine(t)
	done := make(chan error, 1)
	go func() {
		done <- RunCaptured(ctx, engine, capturePipe{reader, started}, config, func(Result) error { return nil })
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("capture reader did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("capture reader was abandoned")
	}
}

func TestRunCapturedSinkFailureStopsStream(t *testing.T) {
	input := strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n{\"target\":\"second\",\"evidence\":[]}\n")
	sentinel := errors.New("sink failed")
	config := DefaultConfig()
	woke := false
	config.CancelInput = func() { woke = true }
	calls := 0
	err := RunCaptured(context.Background(), emptyEngine(t), input, config, func(Result) error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) || calls != 1 || !woke {
		t.Fatalf("sink shutdown failed: calls=%d woke=%v err=%v", calls, woke, err)
	}
}

func TestRunCapturedRejectsHTTPControlBytes(t *testing.T) {
	engine := emptyEngine(t)
	for _, field := range []string{"header", "reason"} {
		for _, control := range []byte{0x01, 0x0b, 0x1f, 0x7f} {
			t.Run(field+"/"+string([]byte{control}), func(t *testing.T) {
				observation := Evidence{Role: "Normal", StatusCode: 200}
				value := "before" + string([]byte{control}) + "after"
				if field == "header" {
					observation.Headers = []Header{{Name: "X-Test", Value: value}}
				} else {
					observation.Reason = value
				}
				var input bytes.Buffer
				if err := json.NewEncoder(&input).Encode(Capture{Target: "saved", Evidence: []Evidence{observation}}); err != nil {
					t.Fatal(err)
				}
				err := RunCaptured(context.Background(), engine, &input, DefaultConfig(), func(Result) error {
					t.Error("invalid HTTP value emitted a result")
					return nil
				})
				if err == nil {
					t.Fatal("invalid HTTP control byte accepted")
				}
			})
		}
	}
}

func TestRunCapturedInputFailurePreservesEarlierResults(t *testing.T) {
	sentinel := errors.New("capture input failed")
	for _, tail := range []io.Reader{failingReader{sentinel}, strings.NewReader("{invalid}\n")} {
		input := &trackedReader{Reader: io.MultiReader(strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n"), tail)}
		var targets []string
		err := RunCaptured(context.Background(), emptyEngine(t), input, DefaultConfig(), func(result Result) error {
			targets = append(targets, result.Target)
			return nil
		})
		if err == nil || len(targets) != 1 || targets[0] != "first" {
			t.Fatalf("earlier capture lost on later input failure: targets=%v err=%v", targets, err)
		}
		if _, failed := tail.(failingReader); failed && !errors.Is(err, sentinel) {
			t.Fatalf("capture input error lost: %v", err)
		}
		if input.closed {
			t.Fatal("caller-owned capture reader was closed")
		}
	}
}

// Each Read ends at a record boundary, while still supporting scanner buffers
// smaller than a record. Repeated strings may share storage in large-byte tests.
type captureRecordsReader struct {
	records     []string
	index       int
	offset      int
	readRecords int
}

func (input *captureRecordsReader) Read(buffer []byte) (int, error) {
	if input.index == len(input.records) {
		return 0, io.EOF
	}
	record := input.records[input.index]
	n := copy(buffer, record[input.offset:])
	input.offset += n
	if input.offset == len(record) {
		input.index++
		input.readRecords++
		input.offset = 0
	}
	return n, nil
}

func TestRunCapturedOrdersSlowEarlierResultsBeforeInvalidRecord(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		engine, err := Compile([]WAF{{Name: "Saved marker", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "marker"}}}}}})
		if err != nil {
			t.Fatal(err)
		}
		config := DefaultConfig()
		config.Passive = true
		first, release, invalid := make(chan struct{}), make(chan struct{}), make(chan struct{})
		input := &captureRecordsReader{records: []string{
			"\n",
			"{\"target\":\"first\",\"evidence\":[{\"role\":\"Normal\",\"status_code\":200,\"body\":\"bWFya2Vy\"}]}\n",
			"{\"target\":\"second\",\"evidence\":[]}\n",
			"{\"target\":\"invalid\",\"evidence\":[],\"unexpected\":true}\n",
			"{\"target\":\"must-not-emit\",\"evidence\":[]}\n",
		}}
		var results []Result
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 2, nil, func(ctx context.Context, record []byte, line int) (Result, error) {
				if line == 2 {
					close(first)
					<-release
				}
				result, err := classifyCapture(ctx, engine, record, line, config)
				if line == 4 {
					close(invalid)
				}
				return result, err
			}, func(result Result) error {
				results = append(results, result)
				return nil
			})
		}()
		<-first
		<-invalid
		synctest.Wait()
		if len(results) != 0 {
			t.Errorf("later work escaped input order: %+v", results)
		}
		close(release)
		err = <-done
		if err == nil || !strings.Contains(err.Error(), "decode capture line 4:") {
			t.Fatalf("invalid record lost its physical line: %v", err)
		}
		if len(results) != 2 || results[0].Target != "first" || results[1].Target != "second" {
			t.Fatalf("valid prefix was not emitted exactly in order: %+v", results)
		}
		if len(results[0].Outcome.Matches) != 1 || results[0].Outcome.Matches[0].Product != "Saved marker" {
			t.Fatalf("scanner buffer reuse changed earlier classification: %+v", results[0].Outcome)
		}
	})
}

func TestRunCapturedChoosesEarliestInvalidRecord(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		engine, config := emptyEngine(t), DefaultConfig()
		release, laterInvalid := make(chan struct{}), make(chan struct{})
		input := strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n{\"target\":\"\",\"evidence\":[]}\n{invalid}\n")
		var targets []string
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 2, nil, func(ctx context.Context, record []byte, line int) (Result, error) {
				if line == 2 {
					<-release
				}
				result, err := classifyCapture(ctx, engine, record, line, config)
				if line == 3 {
					close(laterInvalid)
				}
				return result, err
			}, func(result Result) error {
				targets = append(targets, result.Target)
				return nil
			})
		}()
		<-laterInvalid
		synctest.Wait()
		close(release)
		err := <-done
		if err == nil || !strings.Contains(err.Error(), "capture line 2:") || strings.Contains(err.Error(), "line 3") {
			t.Fatalf("completion order selected the wrong invalid record: %v", err)
		}
		if len(targets) != 1 || targets[0] != "first" {
			t.Fatalf("wrong valid prefix: %v", targets)
		}
	})
}

func TestRunCapturedWorkerLimitFollowsConcurrencyAndEffectiveCPUs(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	for _, concurrency := range []int{1, 5} {
		t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				engine, config := emptyEngine(t), DefaultConfig()
				input := &captureRecordsReader{}
				for i := range 20 {
					input.records = append(input.records, fmt.Sprintf("{\"target\":\"saved-%02d\",\"evidence\":[]}\n", i))
				}
				release := make(chan struct{})
				var active, peak atomic.Int32
				calls := 0
				done := make(chan error, 1)
				go func() {
					done <- runCapturePipeline(context.Background(), input, concurrency, nil, func(ctx context.Context, record []byte, line int) (Result, error) {
						current := active.Add(1)
						for observed := peak.Load(); current > observed; observed = peak.Load() {
							if peak.CompareAndSwap(observed, current) {
								break
							}
						}
						defer active.Add(-1)
						<-release
						return classifyCapture(ctx, engine, record, line, config)
					}, func(result Result) error {
						if want := fmt.Sprintf("saved-%02d", calls); result.Target != want {
							t.Errorf("target = %q, want %q", result.Target, want)
						}
						calls++
						return nil
					})
				}()
				synctest.Wait()
				if got, want := active.Load(), int32(min(concurrency, 2)); got != want {
					t.Errorf("active classifiers = %d, want %d", got, want)
				}
				close(release)
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if peak.Load() != int32(min(concurrency, 2)) || active.Load() != 0 || calls != len(input.records) {
					t.Fatalf("workers were not bounded and joined: peak=%d active=%d calls=%d", peak.Load(), active.Load(), calls)
				}
			})
		})
	}
}

func TestRunCapturedSlowFirstRecordBoundsReorderAdmission(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		engine, config := emptyEngine(t), DefaultConfig()
		input := &captureRecordsReader{records: make([]string, 100)}
		for i := range input.records {
			input.records[i] = fmt.Sprintf("{\"target\":\"saved-%03d\",\"evidence\":[]}\n", i)
		}
		release := make(chan struct{})
		var processed atomic.Int32
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 2, nil, func(ctx context.Context, record []byte, line int) (Result, error) {
				processed.Add(1)
				if line == 1 {
					<-release
				}
				return classifyCapture(ctx, engine, record, line, config)
			}, func(result Result) error {
				if want := fmt.Sprintf("saved-%03d", calls); result.Target != want {
					t.Errorf("target = %q, want %q", result.Target, want)
				}
				calls++
				return nil
			})
		}()
		synctest.Wait()
		if input.readRecords != 4 || processed.Load() != 4 || calls != 0 {
			t.Errorf("slow first item did not backpressure admission: read=%d processed=%d emitted=%d", input.readRecords, processed.Load(), calls)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if calls != len(input.records) {
			t.Fatalf("emitted %d records, want %d", calls, len(input.records))
		}
	})
}

func TestRunCapturedRawByteAdmissionBoundsLargeRecords(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		engine, config := emptyEngine(t), DefaultConfig()
		const recordBytes = 9 << 20
		prefix, suffix := "{\"target\":\"saved\",\"evidence\":[", "]}\n"
		record := prefix + strings.Repeat(" ", recordBytes-len(prefix)-len(suffix)) + suffix
		input := &captureRecordsReader{records: make([]string, 8)}
		for i := range input.records {
			input.records[i] = record
		}
		release := make(chan struct{})
		var admitted atomic.Int32
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 4, nil, func(ctx context.Context, raw []byte, line int) (Result, error) {
				admitted.Add(1)
				if line == 1 {
					<-release
				}
				return classifyCapture(ctx, engine, raw, line, config)
			}, func(Result) error {
				calls++
				return nil
			})
		}()
		synctest.Wait()
		want := maxCaptureInFlightBytes / (recordBytes - 1)
		if int(admitted.Load()) != want || input.readRecords != want+1 || calls != 0 {
			t.Errorf("raw bytes were not bounded independently of record slots: admitted=%d read=%d emitted=%d", admitted.Load(), input.readRecords, calls)
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if calls != len(input.records) {
			t.Fatalf("lost large records: %d", calls)
		}
	})
}

func TestRunCapturedSinkFailureWakesBlockedInputAndKeepsFirstError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		input := &signalSecondRead{Reader: reader, blocked: make(chan struct{})}
		sentinel := errors.New("capture publication failed")
		config := DefaultConfig()
		config.Concurrency = 1
		wakeups := 0
		config.CancelInput = func() {
			wakeups++
			_ = reader.CloseWithError(errors.New("secondary reader wake error"))
		}
		engine := emptyEngine(t)
		done := make(chan error, 1)
		calls := 0
		go func() {
			done <- RunCaptured(context.Background(), engine, input, config, func(Result) error {
				calls++
				<-input.blocked
				return sentinel
			})
		}()
		if _, err := io.WriteString(writer, "{\"target\":\"saved\",\"evidence\":[]}\n"); err != nil {
			t.Fatal(err)
		}
		if err := <-done; !errors.Is(err, sentinel) || strings.Contains(err.Error(), "secondary reader") || calls != 1 || wakeups != 1 {
			t.Fatalf("sink failure was replaced or shutdown leaked: err=%v calls=%d wakeups=%d", err, calls, wakeups)
		}
	})
}

func TestRunCapturedInvalidLaterRecordWakesBlockedInputBeforeEarlierFinishes(t *testing.T) {
	previous := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		reader, writer := io.Pipe()
		defer reader.Close()
		defer writer.Close()
		input := &signalSecondRead{Reader: reader, blocked: make(chan struct{})}
		engine, config := emptyEngine(t), DefaultConfig()
		release, woken := make(chan struct{}), make(chan struct{})
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 2, func() {
				_ = reader.Close()
				close(woken)
			}, func(ctx context.Context, record []byte, line int) (Result, error) {
				if line == 1 {
					<-release
				} else {
					<-input.blocked
				}
				return classifyCapture(ctx, engine, record, line, config)
			}, func(result Result) error {
				if result.Target != "first" {
					t.Errorf("unexpected target %q", result.Target)
				}
				calls++
				return nil
			})
		}()
		if _, err := io.WriteString(writer, "{\"target\":\"first\",\"evidence\":[]}\n{invalid}\n"); err != nil {
			t.Fatal(err)
		}
		<-woken
		synctest.Wait()
		if calls != 0 {
			t.Errorf("earlier unfinished record emitted: %d", calls)
		}
		close(release)
		if err := <-done; err == nil || !strings.Contains(err.Error(), "decode capture line 2:") || calls != 1 {
			t.Fatalf("invalid record did not preserve earlier result: err=%v calls=%d", err, calls)
		}
	})
}

func TestRunCapturedCancellationJoinsWorkersAndByteWaiter(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	synctest.Test(t, func(t *testing.T) {
		const recordBytes = 9 << 20
		record := "{\"target\":\"saved\",\"evidence\":[" + strings.Repeat(" ", recordBytes) + "]}\n"
		input := &captureRecordsReader{records: []string{record, record, record, record, record}}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var active, stopped atomic.Int32
		var wakeups atomic.Int32
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(ctx, input, 4, func() { wakeups.Add(1) }, func(ctx context.Context, _ []byte, _ int) (Result, error) {
				active.Add(1)
				defer active.Add(-1)
				defer stopped.Add(1)
				<-ctx.Done()
				return Result{}, ctx.Err()
			}, func(Result) error {
				t.Error("cancelled work emitted a result")
				return nil
			})
		}()
		synctest.Wait()
		if active.Load() != 3 || input.readRecords != 4 {
			t.Errorf("did not reach bounded byte wait: active=%d read=%d", active.Load(), input.readRecords)
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) || active.Load() != 0 || stopped.Load() != 3 || wakeups.Load() != 1 {
			t.Fatalf("cancelled pipeline was not joined: err=%v active=%d stopped=%d wakeups=%d", err, active.Load(), stopped.Load(), wakeups.Load())
		}
	})
}

func TestRunCapturedReadFailureDrainsSlowEarlierRecord(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sentinel := errors.New("capture source failed")
		input := &trackedReader{Reader: io.MultiReader(strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n"), failingReader{sentinel})}
		engine, config := emptyEngine(t), DefaultConfig()
		release := make(chan struct{})
		calls := 0
		done := make(chan error, 1)
		go func() {
			done <- runCapturePipeline(context.Background(), input, 1, nil, func(ctx context.Context, record []byte, line int) (Result, error) {
				<-release
				return classifyCapture(ctx, engine, record, line, config)
			}, func(Result) error {
				calls++
				return nil
			})
		}()
		synctest.Wait()
		if calls != 0 {
			t.Errorf("slow capture emitted early")
		}
		close(release)
		if err := <-done; !errors.Is(err, sentinel) || calls != 1 || input.closed {
			t.Fatalf("read failure lost valid prefix or reader ownership: err=%v calls=%d closed=%v", err, calls, input.closed)
		}
	})
}

func TestRunCapturedSuccessfulEOFLeavesReaderOwned(t *testing.T) {
	input := &trackedReader{Reader: strings.NewReader("\n{\"target\":\"saved\",\"evidence\":[]}\n")}
	config := DefaultConfig()
	config.CancelInput = func() { t.Error("normal capture EOF cancelled caller input") }
	if err := RunCaptured(context.Background(), emptyEngine(t), input, config, func(Result) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if input.closed {
		t.Fatal("caller-owned reader closed at EOF")
	}
}

func TestRunCapturedOversizedRecordReportsExactLineAfterValidPrefix(t *testing.T) {
	input := io.MultiReader(strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n\n"), strings.NewReader(strings.Repeat("x", maxCaptureRecordBytes+1)))
	calls := 0
	err := RunCaptured(context.Background(), emptyEngine(t), input, DefaultConfig(), func(result Result) error {
		if result.Target != "first" {
			t.Errorf("unexpected emitted target %q", result.Target)
		}
		calls++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "capture line 3 exceeds") || calls != 1 {
		t.Fatalf("oversized record lost line or valid prefix: err=%v calls=%d", err, calls)
	}
}

func TestRunCapturedSinkFailurePrecedesLaterInputFailure(t *testing.T) {
	inputErr, sinkErr := errors.New("later input error"), errors.New("earlier result sink error")
	input := io.MultiReader(strings.NewReader("{\"target\":\"first\",\"evidence\":[]}\n"), failingReader{inputErr})
	calls := 0
	err := RunCaptured(context.Background(), emptyEngine(t), input, DefaultConfig(), func(Result) error {
		calls++
		return sinkErr
	})
	if !errors.Is(err, sinkErr) || errors.Is(err, inputErr) || calls != 1 {
		t.Fatalf("later input failure replaced earlier callback failure: err=%v calls=%d", err, calls)
	}
}

func TestRunCapturedPrecancelledInputWakesWithoutReading(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inputErr := errors.New("input must not be read")
	config := DefaultConfig()
	wakeups := 0
	config.CancelInput = func() { wakeups++ }
	err := RunCaptured(ctx, emptyEngine(t), failingReader{inputErr}, config, func(Result) error {
		t.Error("pre-cancelled stream emitted a result")
		return nil
	})
	if !errors.Is(err, context.Canceled) || errors.Is(err, inputErr) || wakeups != 1 {
		t.Fatalf("pre-cancelled stream acquired input or lost cancellation: err=%v wakeups=%d", err, wakeups)
	}
}
