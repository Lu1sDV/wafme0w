//go:build linux

package browserruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

// Options selects an existing native Chromium executable, never a downloader or wrapper.
type Options struct{ BrowserPath string }

// Runtime owns a local Chromium process group and private CDP pipes.
// This is lifecycle ownership, not a network or renderer resource sandbox.
type Runtime struct {
	*Pipe
	command       *exec.Cmd
	cancel        context.CancelFunc
	killed        chan struct{}
	input, output *os.File
	directory     string
	once          sync.Once
	closeErr      error
	logs          cappedLog
}

type cappedLog struct {
	mu   sync.Mutex
	data []byte
}

func (l *cappedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := min(len(p), (64<<10)-len(l.data))
	l.data = append(l.data, p[:n]...)
	return len(p), nil
}

func (l *cappedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return string(l.data)
}

func Start(ctx context.Context, options Options) (*Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 {
		return nil, errors.New("browser capture requires a non-root user with Chromium sandbox support")
	}
	if err := ValidateExecutable(options.BrowserPath); err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "wafme0w-browser-")
	if err != nil {
		return nil, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	r := &Runtime{directory: directory, cancel: cancel, killed: make(chan struct{})}
	started := false
	defer func() {
		if !started {
			cancel()
			if r.input != nil {
				_ = r.input.Close()
			}
			if r.output != nil {
				_ = r.output.Close()
			}
			_ = os.RemoveAll(directory)
		}
	}()
	childInput, input, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.input = input
	defer childInput.Close()
	output, childOutput, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	r.output = output
	defer childOutput.Close()
	r.Pipe = newPipe(output, input)
	command := exec.Command(options.BrowserPath,
		"--headless", "--remote-debugging-pipe", "--user-data-dir="+filepath.Join(directory, "profile"),
		"--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--disable-sync",
		"--disable-extensions", "--disable-component-update", "--disable-default-apps",
		"--disable-breakpad", "--disable-crash-reporter", "--no-proxy-server", "--no-startup-window",
	)
	command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + directory, "TMPDIR=" + directory, "LANG=C.UTF-8"}
	command.ExtraFiles = []*os.File{childInput, childOutput}
	command.Stderr = &r.logs
	command.Stdout = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("launch local browser: %w", err)
	}
	r.command = command
	// Do not reap the group leader until cancellation has signalled the group:
	// retaining its PID prevents a recycled process ID from being signalled.
	context.AfterFunc(childCtx, func() {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = input.Close()
		_ = output.Close()
		close(r.killed)
	})
	started = true
	return r, nil
}

// Close stops this capture's process group before reaping its leader and removing
// the profile. Ordinary profile removal is not secure erasure or RAM-only storage.
func (r *Runtime) Close() error {
	r.once.Do(func() {
		r.cancel()
		<-r.killed
		waitErr := r.command.Wait()
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			waitErr = nil
		} // deliberate shutdown can terminate Chromium by signal
		r.closeErr = errors.Join(waitErr, os.RemoveAll(r.directory))
	})
	return r.closeErr
}

// Diagnostic is bounded native launch output; sanitize before any user-facing export.
func (r *Runtime) Diagnostic() string { return r.logs.String() }
