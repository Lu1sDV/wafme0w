package wafme0w

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
	httputil "github.com/Lu1sDV/wafme0w/pkg/utils/http"
)

const maxCaptureRecordBytes = 16 << 20

// Capture is a saved observation set. Body uses the standard JSON base64
// encoding for []byte. Target is an identifying label, not a URL to request.
type Capture struct {
	Target   string     `json:"target"`
	Evidence []Evidence `json:"evidence"`
}

// RunCaptured classifies bounded JSONL records without making network requests.
// It emits serially in input order and retains no capture after its callback.
// Invalid records stop the stream; earlier results may already have been emitted.
// The reader remains caller-owned. CancelInput may unblock its Read on failure
// or context cancellation, just as for Run.
func RunCaptured(ctx context.Context, engine *Engine, inputs io.Reader, config Config, emit func(Result) error) (err error) {
	if ctx == nil || engine == nil || inputs == nil || emit == nil {
		return errors.New("context, engine, inputs, and result callback are required")
	}
	config.Passive = true
	config = config.normalized()
	if err := config.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
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
	scanner := bufio.NewScanner(inputs)
	scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), maxCaptureRecordBytes+1)
	line := 0
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
		decoder := json.NewDecoder(bytes.NewReader(record))
		decoder.DisallowUnknownFields()
		var capture Capture
		if err := decoder.Decode(&capture); err != nil {
			return fmt.Errorf("decode capture line %d: %w", line, err)
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			return fmt.Errorf("capture line %d must contain exactly one JSON object", line)
		}
		capture.Target = strings.TrimSpace(capture.Target)
		if err := validateCapture(capture, config.MaxBodyBytes); err != nil {
			return fmt.Errorf("capture line %d: %w", line, err)
		}
		var origin string
		// A label may be a URL, but a bare label must never acquire a host.
		if strings.Contains(capture.Target, "://") {
			if u, err := httputil.ParseURI(capture.Target); err == nil {
				origin = normalizedOrigin(u)
			}
		}
		result := makeResult(engine, capture.Target, origin, capture.Evidence, config)
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

func validateCapture(capture Capture, maxBodyBytes int64) error {
	if capture.Target == "" || len(capture.Target) >= bufio.MaxScanTokenSize {
		return errors.New("target label must be nonempty and shorter than 64 KiB")
	}
	if capture.Evidence == nil || len(capture.Evidence) > 64 {
		return errors.New("evidence must be an array of at most 64 observations")
	}
	for i, observation := range capture.Evidence {
		if observation.Role == "" || len(observation.Role) > 128 {
			return fmt.Errorf("evidence %d: role must contain 1 to 128 bytes", i)
		}
		if observation.StatusCode != 0 && (observation.StatusCode < 100 || observation.StatusCode > 999) {
			return fmt.Errorf("evidence %d: status must be zero or a three-digit HTTP status", i)
		}
		if strings.ContainsAny(observation.Reason, "\x00\r\n") {
			return fmt.Errorf("evidence %d: invalid status reason", i)
		}
		if int64(len(observation.Body)) > maxBodyBytes {
			return fmt.Errorf("evidence %d: decoded body exceeds %d bytes", i, maxBodyBytes)
		}
		if len(observation.Headers) > 4096 {
			return fmt.Errorf("evidence %d: more than 4096 header values", i)
		}
		for _, header := range observation.Headers {
			if !httpmeta.ValidHeaderName(header.Name) || strings.ContainsAny(header.Value, "\x00\r\n") {
				return fmt.Errorf("evidence %d: invalid HTTP header", i)
			}
		}
	}
	return nil
}
