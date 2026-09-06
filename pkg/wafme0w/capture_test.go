package wafme0w

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunCapturedClassifiesWithoutAcquisition(t *testing.T) {
	engine, err := Compile([]WAF{{Name: "Capture marker", Schemas: []Scheme{{FingerPrints: []FingerPrint{{Type: "Content", Pattern: "saved marker"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	capture := Capture{Target: "saved-origin", Evidence: []Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("saved marker: private body"), Headers: []Header{{Name: "X-Private", Value: "private header"}}}}}
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
