package wafme0w

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
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
