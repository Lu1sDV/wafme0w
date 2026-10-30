package wafmeow

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"

	"github.com/Lu1sDV/wafmeow/v2/internal/httpmeta"
	httputil "github.com/Lu1sDV/wafmeow/v2/pkg/utils/http"
)

const (
	maxCaptureRecordBytes   = 16 << 20
	maxCaptureInFlightBytes = 32 << 20
)

// Capture is a saved observation set. Body uses the standard JSON base64
// encoding for []byte. Target is an identifying label, not a URL to request.
type Capture struct {
	Target   string     `json:"target"`
	Evidence []Evidence `json:"evidence"`
}

// RunCaptured decodes, validates and classifies JSONL without network requests.
// Workers are capped by both Config.Concurrency and the effective CPU count.
// Admission bounds pending records and their raw bytes, including results waiting
// for earlier records. Callbacks remain serial and in input order; every valid
// record preceding the first invalid record is emitted before that error.
// The reader remains caller-owned. A blocked Read requires CancelInput or an
// independent caller wakeup. All workers and input reads finish before return.
func RunCaptured(ctx context.Context, engine *Engine, inputs io.Reader, config Config, emit func(Result) error) error {
	if ctx == nil || engine == nil || inputs == nil || emit == nil {
		return errors.New("context, engine, inputs, and result callback are required")
	}
	config.Passive = true
	config = config.normalized()
	if err := config.validate(); err != nil {
		return err
	}
	return runCapturePipeline(ctx, inputs, config.Concurrency, config.CancelInput, func(ctx context.Context, record []byte, line int) (Result, error) {
		return classifyCapture(ctx, engine, record, line, config)
	}, emit)
}

type decodedCapture struct {
	capture        Capture
	importMetadata *ImportProvenance
	diagnostics    []Diagnostic
}

type captureDecoder func([]byte, Config, int, int) (decodedCapture, error)

// runCaptured keeps import decoding, classification, and emission synchronous:
// the callback must return before the next record is decoded.
func runCaptured(ctx context.Context, engine *Engine, inputs io.Reader, config Config, decode captureDecoder, emit func(Result) error) (err error) {
	if ctx == nil || engine == nil || inputs == nil || emit == nil {
		return errors.New("context, engine, inputs, and result callback are required")
	}
	config.Passive = true
	config = config.normalized()
	if err := config.validate(); err != nil {
		return err
	}
	if config.CancelInput != nil {
		wake := sync.OnceFunc(config.CancelInput)
		finished := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(finished)
			wake()
		})
		defer func() {
			if err != nil {
				wake()
			}
			if !stop() {
				<-finished
			}
		}()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(inputs)
	scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), maxCaptureRecordBytes+1)
	line, occurrence := 0, 0
	for ctx.Err() == nil && scanner.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return err
		}
		record := bytes.TrimSpace(scanner.Bytes())
		if len(record) == 0 {
			continue
		}
		if len(record) > maxCaptureRecordBytes {
			return fmt.Errorf("capture line %d exceeds %d bytes", line, maxCaptureRecordBytes)
		}
		occurrence++
		decoded, err := decode(record, config, line, occurrence)
		if err != nil {
			return fmt.Errorf("decode capture line %d: %w", line, err)
		}
		result := makeCapturedResult(engine, decoded, config)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := emit(result); err != nil {
			return fmt.Errorf("emit result: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return errors.Join(fmt.Errorf("read captures after line %d: %w", line, err), ctx.Err())
	}
	return ctx.Err()
}

type captureWork struct {
	index  int
	line   int
	record []byte
}

type captureResult struct {
	index  int
	bytes  int
	result Result
	err    error
}

// captureByteBudget has one admitting reader and one releasing emitter. The
// scanner has its own single, bounded buffer in addition to this raw-byte budget.
type captureByteBudget struct {
	mu       sync.Mutex
	used     int
	released chan struct{}
}

func (budget *captureByteBudget) take(ctx context.Context, size int) bool {
	for ctx.Err() == nil {
		budget.mu.Lock()
		if size <= maxCaptureInFlightBytes-budget.used {
			budget.used += size
			budget.mu.Unlock()
			return true
		}
		budget.mu.Unlock()
		select {
		case <-ctx.Done():
			return false
		case <-budget.released:
		}
	}
	return false
}

func (budget *captureByteBudget) release(size int) {
	budget.mu.Lock()
	budget.used -= size
	budget.mu.Unlock()
	select {
	case budget.released <- struct{}{}:
	default:
	}
}

func runCapturePipeline(ctx context.Context, inputs io.Reader, concurrency int, cancelInput func(),
	classify func(context.Context, []byte, int) (Result, error), emit func(Result) error) (err error) {
	workers := min(concurrency, runtime.GOMAXPROCS(0))
	wakeInput := sync.OnceFunc(func() {
		if cancelInput != nil {
			cancelInput()
		}
	})
	if err := ctx.Err(); err != nil {
		wakeInput()
		return err
	}
	workCtx, cancelWork := context.WithCancel(ctx)
	scanCtx, stopScanning := context.WithCancel(workCtx)
	inputWoken := make(chan struct{})
	stopWake := context.AfterFunc(scanCtx, func() {
		defer close(inputWoken)
		wakeInput()
	})
	defer func() {
		// A cancelled pipeline can finish before AfterFunc dispatches its wake.
		// Do not stop that callback before fulfilling the once-only error wakeup.
		if err != nil {
			wakeInput()
		}
		if !stopWake() {
			<-inputWoken
		}
		stopScanning()
		cancelWork()
	}()

	// Slots are retained through emission, not merely through classification:
	// a slow early record cannot grow an unbounded reorder buffer.
	slots := make(chan struct{}, 2*workers)
	budget := captureByteBudget{released: make(chan struct{}, 1)}
	jobs := make(chan captureWork)
	completed := make(chan captureResult)
	var pipeline sync.WaitGroup
	pipeline.Add(1)
	go func() {
		defer pipeline.Done()
		defer close(jobs)
		scanner := bufio.NewScanner(inputs)
		scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), maxCaptureRecordBytes+1)
		line, index := 0, 0
		for scanCtx.Err() == nil {
			select {
			case slots <- struct{}{}:
			case <-scanCtx.Done():
				return
			}
			if scanCtx.Err() != nil {
				return
			}
			if !scanner.Scan() {
				if err := scanner.Err(); err != nil && scanCtx.Err() == nil {
					readErr := fmt.Errorf("read captures after line %d: %w", line, err)
					if errors.Is(err, bufio.ErrTooLong) {
						readErr = fmt.Errorf("capture line %d exceeds %d bytes: %w", line+1, maxCaptureRecordBytes, err)
					}
					select {
					case completed <- captureResult{index: index, err: readErr}:
					case <-scanCtx.Done():
					}
				} else {
					<-slots
				}
				return
			}
			line++
			record := bytes.TrimSpace(scanner.Bytes())
			if len(record) == 0 {
				<-slots
				continue
			}
			if !budget.take(scanCtx, len(record)) {
				return
			}
			// Scanner owns its storage and may reuse it on the next Scan.
			work := captureWork{index: index, line: line, record: bytes.Clone(record)}
			select {
			case jobs <- work:
				index++
			case <-scanCtx.Done():
				budget.release(len(record))
				return
			}
		}
	}()
	for range workers {
		pipeline.Add(1)
		go func() {
			defer pipeline.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case work, ok := <-jobs:
					if !ok || workCtx.Err() != nil {
						return
					}
					result, err := classify(workCtx, work.record, work.line)
					completion := captureResult{index: work.index, bytes: len(work.record), result: result, err: err}
					work.record = nil
					select {
					case completed <- completion:
					case <-workCtx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		pipeline.Wait()
		close(completed)
	}()

	pending := make(map[int]captureResult, cap(slots))
	next := 0
	var streamErr error
	for completion := range completed {
		if streamErr != nil || workCtx.Err() != nil {
			continue
		}
		if completion.err != nil {
			// Stop a potentially blocked reader immediately, but let earlier
			// admitted records finish before selecting the input-order error.
			stopScanning()
		}
		pending[completion.index] = completion
		for {
			current, ok := pending[next]
			if !ok {
				break
			}
			delete(pending, next)
			if current.err != nil {
				streamErr = current.err
			} else if err := emit(current.result); err != nil {
				streamErr = fmt.Errorf("emit result: %w", err)
			}
			budget.release(current.bytes)
			<-slots
			next++
			if streamErr != nil {
				cancelWork()
				break
			}
			if workCtx.Err() != nil {
				break
			}
		}
	}
	return errors.Join(streamErr, ctx.Err())
}

func classifyCapture(ctx context.Context, engine *Engine, record []byte, line int, config Config) (Result, error) {
	if len(record) > maxCaptureRecordBytes {
		return Result{}, fmt.Errorf("capture line %d exceeds %d bytes", line, maxCaptureRecordBytes)
	}
	capture, err := decodeNativeCapture(ctx, record)
	if err != nil {
		return Result{}, fmt.Errorf("decode capture line %d: %w", line, err)
	}
	capture.Target = strings.TrimSpace(capture.Target)
	if err := validateCapture(capture, config.MaxBodyBytes); err != nil {
		return Result{}, fmt.Errorf("capture line %d: %w", line, err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return makeCapturedResult(engine, decodedCapture{capture: capture}, config), nil
}

func makeCapturedResult(engine *Engine, decoded decodedCapture, config Config) Result {
	capture := decoded.capture
	var origin string
	// A label may be a URL, but a bare label must never acquire a host.
	if strings.Contains(capture.Target, "://") {
		if u, err := httputil.ParseURI(capture.Target); err == nil {
			origin = normalizedOrigin(u)
		}
	}
	result := makeResult(engine, capture.Target, origin, capture.Evidence, config)
	result.Provenance.Import = decoded.importMetadata
	result.Outcome.Diagnostics = append(result.Outcome.Diagnostics, decoded.diagnostics...)
	return result
}

func validateCapture(capture Capture, maxBodyBytes int64) error {
	if capture.Target == "" || len(capture.Target) >= bufio.MaxScanTokenSize {
		return errors.New("target label must be nonempty and shorter than 64 KiB")
	}
	if capture.Evidence == nil || len(capture.Evidence) > maxCaptureObservations {
		return errors.New("evidence must be an array of at most 64 observations")
	}
	for i, observation := range capture.Evidence {
		if err := validateEvidenceAvailability(observation); err != nil {
			return fmt.Errorf("evidence %d: %w", i, err)
		}
		if observation.Role == "" || len(observation.Role) > 128 {
			return fmt.Errorf("evidence %d: role must contain 1 to 128 bytes", i)
		}
		if observation.StatusCode != 0 && (observation.StatusCode < 100 || observation.StatusCode > 999) {
			return fmt.Errorf("evidence %d: status must be zero or a three-digit HTTP status", i)
		}
		if !httpmeta.ValidHeaderValue(observation.Reason) {
			return fmt.Errorf("evidence %d: invalid status reason", i)
		}
		if int64(len(observation.Body)) > maxBodyBytes {
			return fmt.Errorf("evidence %d: decoded body exceeds %d bytes", i, maxBodyBytes)
		}
		if len(observation.Headers) > maxCaptureHeaders {
			return fmt.Errorf("evidence %d: more than 4096 header values", i)
		}
		if len(observation.RedirectChain) > maxCaptureRedirects {
			return fmt.Errorf("evidence %d: more than 4096 redirect destinations", i)
		}
		for _, header := range observation.Headers {
			if !httpmeta.ValidHeaderName(header.Name) || !httpmeta.ValidHeaderValue(header.Value) {
				return fmt.Errorf("evidence %d: invalid HTTP header", i)
			}
		}
	}
	return nil
}
