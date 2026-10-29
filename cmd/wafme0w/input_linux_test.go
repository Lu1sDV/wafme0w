package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Lu1sDV/wafme0w/v2/pkg/wafme0w"
	"golang.org/x/sys/unix"
)

// Watching the open avoids sleeps and proves that a writer is not required to
// get past startup's open syscall before cancellation can close the reader.
func watchNamedInputOpen(t *testing.T, path string) func() {
	t.Helper()
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	watcher := os.NewFile(uintptr(fd), "named-input-open")
	t.Cleanup(func() { _ = watcher.Close() })
	if _, err := unix.InotifyAddWatch(fd, path, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := watcher.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var event [unix.SizeofInotifyEvent]byte
		if n, err := watcher.Read(event[:]); err != nil || n != len(event) {
			t.Fatalf("CLI did not open named input without blocking: bytes=%d err=%v", n, err)
		}
	}
}

func TestCLICancellationUnblocksNamedInputs(t *testing.T) {
	for _, test := range []struct {
		source    string
		inherited bool
	}{
		{source: "input"}, {source: "evidence"}, {source: "fingerprints"},
		{source: "input", inherited: true}, {source: "evidence", inherited: true},
	} {
		for _, connected := range []bool{false, true} {
			name := test.source + "/no-writer"
			if connected {
				name = test.source + "/connected-writer-no-data"
			}
			if test.inherited {
				name = "inherited-stdin/" + name
			}
			t.Run(name, func(t *testing.T) {
				directory, temporary := t.TempDir(), t.TempDir()
				path := filepath.Join(directory, "input.fifo")
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				var writer *os.File
				if connected {
					var err error
					writer, err = os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK, 0)
					if err != nil {
						t.Fatal(err)
					}
					defer writer.Close()
				}
				var reader *os.File
				var readerFD int
				if test.inherited {
					var err error
					readerFD, err = unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					reader = os.NewFile(uintptr(readerFD), path)
					defer reader.Close()
				}
				opened := watchNamedInputOpen(t, path)
				output := filepath.Join(directory, "report.json")
				if err := os.WriteFile(output, []byte("previous report"), 0600); err != nil {
					t.Fatal(err)
				}
				args := []string{"--silent", "--no-colors", "--output", output}
				if test.source == "fingerprints" {
					args = append(args, "--fingerprints", path, "--target=invalid://unused")
				} else {
					selected := path
					if test.inherited {
						selected = "-"
					}
					args = append(args, "--"+test.source, selected, "--fingerprints", fixtureCatalogue(t))
				}
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable, args...)
				cmd.Env = append(os.Environ(), "WAFME0W_CLI_TEST_PROCESS=1", "TMPDIR="+temporary)
				if reader != nil {
					cmd.Stdin = reader
				}
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					cancel()
					if cmd.ProcessState == nil {
						_ = cmd.Wait()
					}
				}()
				opened()
				if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatal(err)
				}
				err = cmd.Wait()
				var exitErr *exec.ExitError
				if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 130 {
					t.Fatalf("named input shutdown hung or failed: err=%v context=%v stderr=%q", err, ctx.Err(), stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("cancellation published output: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				if data, err := os.ReadFile(output); err != nil || string(data) != "previous report" {
					t.Fatalf("cancellation replaced report: %q err=%v", data, err)
				}
				if entries, err := os.ReadDir(temporary); err != nil || len(entries) != 0 {
					t.Fatalf("cancellation leaked temporary resources: entries=%v err=%v", entries, err)
				}
				if reader != nil {
					flags, err := unix.FcntlInt(uintptr(readerFD), unix.F_GETFL, 0)
					if err != nil || flags&unix.O_NONBLOCK == 0 {
						t.Fatalf("inherited nonblocking stdin flag changed: flags=%#x err=%v", flags, err)
					}
					if err := reader.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if writer != nil {
					if err := writer.Close(); err != nil {
						t.Fatal(err)
					}
				}
				fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err == nil {
					_ = unix.Close(fd)
					t.Fatal("named input retained a reader after process exit")
				}
				if !errors.Is(err, unix.ENXIO) {
					t.Fatalf("named input was damaged: %v", err)
				}
			})
		}
	}
}

func TestCLINamedInputsWaitForProducerAndEOF(t *testing.T) {
	capture := captureLines(t, wafme0w.Capture{
		Target: "saved named input", Evidence: []wafme0w.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("saved-marker")}},
	})
	for _, test := range []struct {
		name, source, data, want string
		code                     int
		symlink                  bool
		inherited                bool
	}{
		{name: "targets", source: "input", data: "invalid://named-target\n", want: "invalid://named-target"},
		{name: "empty targets", source: "input"},
		{name: "evidence", source: "evidence", data: capture, want: "saved named input"},
		{name: "empty evidence", source: "evidence"},
		{name: "catalogue", source: "fingerprints", data: `[{"name":"Named catalogue","schemas":[{"fingerprints":[{"type":"Status","pattern":"403"}]}]}]`, want: "Named catalogue"},
		{name: "empty catalogue array", source: "fingerprints", data: "[]"},
		{name: "empty catalogue stream rejected", source: "fingerprints", code: 1},
		{name: "symlink to FIFO", source: "input", data: "invalid://symlink-target\n", want: "invalid://symlink-target", symlink: true},
		{name: "inherited stdin targets", source: "input", data: "invalid://stdin-target\n", want: "invalid://stdin-target", inherited: true},
		{name: "inherited stdin empty targets", source: "input", inherited: true},
		{name: "inherited stdin evidence", source: "evidence", data: capture, want: "saved named input", inherited: true},
		{name: "inherited stdin empty evidence", source: "evidence", inherited: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "input.fifo")
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			var reader *os.File
			var readerFD int
			if test.inherited {
				var err error
				readerFD, err = unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				reader = os.NewFile(uintptr(readerFD), path)
				defer reader.Close()
			}
			opened := watchNamedInputOpen(t, path)
			selected := path
			if test.symlink {
				selected = filepath.Join(directory, "selected")
				if err := os.Symlink(path, selected); err != nil {
					t.Fatal(err)
				}
			}
			if test.inherited {
				selected = "-"
			}
			args := []string{"--silent", "--no-colors", "--" + test.source, selected}
			if test.source == "fingerprints" {
				args = append(args, "--list")
			} else {
				args = append(args, "--jsonl", "--fingerprints", fixtureCatalogue(t))
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, args...)
			cmd.Env = append(os.Environ(), "WAFME0W_CLI_TEST_PROCESS=1")
			cmd.Stdin = strings.NewReader("invalid://must-not-be-selected\n")
			if reader != nil {
				cmd.Stdin = reader
			}
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				if cmd.ProcessState == nil {
					_ = cmd.Wait()
				}
			}()
			opened()
			writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := io.WriteString(writer, test.data)
			if err := errors.Join(writeErr, writer.Close()); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			code := 0
			if err != nil {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatal(err)
				}
				code = exitErr.ExitCode()
			}
			if ctx.Err() != nil || code != test.code {
				t.Fatalf("producer EOF was not consumed: code=%d context=%v stderr=%q", code, ctx.Err(), stderr.String())
			}
			if reader != nil {
				flags, err := unix.FcntlInt(uintptr(readerFD), unix.F_GETFL, 0)
				if err != nil || flags&unix.O_NONBLOCK == 0 {
					t.Fatalf("producer EOF changed inherited nonblocking flag: flags=%#x err=%v", flags, err)
				}
			}
			if test.code != 0 {
				if stdout.Len() != 0 || !strings.Contains(stderr.String(), "decode catalogue") {
					t.Fatalf("empty catalogue bypassed validation: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
				return
			}
			if stderr.Len() != 0 || !strings.Contains(stdout.String(), test.want) || strings.Contains(stdout.String(), "must-not-be-selected") {
				t.Fatalf("named input lost data or precedence: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if test.want == "" && stdout.Len() != 0 {
				t.Fatalf("empty named stream invented data: %q", stdout.String())
			}
			if test.source != "fingerprints" && test.want != "" {
				results := decodeResultLines(t, stdout.String())
				if len(results) != 1 || results[0].Target != test.want {
					t.Fatalf("named input results = %+v", results)
				}
				if test.source == "evidence" && (results[0].Outcome.State != wafme0w.Complete || len(results[0].Outcome.Matches) != 1) {
					t.Fatalf("named evidence lost complete-body semantics: %+v", results[0])
				}
			}
		})
	}
}

func TestCLIRejectsUnsupportedNamedInputTypes(t *testing.T) {
	for _, source := range []string{"input", "evidence", "fingerprints"} {
		for _, path := range []string{t.TempDir(), "/dev/zero"} {
			t.Run(source+"/"+filepath.Base(path), func(t *testing.T) {
				args := []string{"--silent", "--no-colors", "--" + source, path}
				if source == "fingerprints" {
					args = append(args, "--list")
				} else {
					args = append(args, "--jsonl")
				}
				code, stdout, stderr := runCLI(t, nil, args...)
				if code != 1 || stdout != "" || !strings.Contains(stderr, "input must be a regular file or a Linux named pipe") {
					t.Fatalf("unsupported input was read: code=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}

func TestCLIInheritedPipeEOFAndFlags(t *testing.T) {
	capture := captureLines(t, wafme0w.Capture{
		Target: "saved inherited pipe", Evidence: []wafme0w.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("saved-marker")}},
	})
	for _, test := range []struct{ name, source, data, want string }{
		{name: "targets", source: "input", data: "invalid://inherited-target\n", want: "invalid://inherited-target"},
		{name: "empty targets", source: "input"},
		{name: "evidence", source: "evidence", data: capture, want: "saved inherited pipe"},
		{name: "empty evidence", source: "evidence"},
	} {
		for _, nonblocking := range []bool{false, true} {
			for _, restricted := range []bool{false, true} {
				name := test.name + "/blocking"
				if nonblocking {
					name = test.name + "/nonblocking"
				}
				if restricted {
					name += "/dup-fallback"
				} else {
					name += "/reopened"
				}
				t.Run(name, func(t *testing.T) {
					if restricted && os.Geteuid() == 0 {
						t.Skip("root can reopen pipes despite their permission bits")
					}
					flags := unix.O_CLOEXEC
					if nonblocking {
						flags |= unix.O_NONBLOCK
					}
					var fds [2]int
					if err := unix.Pipe2(fds[:], flags); err != nil {
						t.Fatal(err)
					}
					reader := os.NewFile(uintptr(fds[0]), "inherited-input")
					writer := os.NewFile(uintptr(fds[1]), "inherited-producer")
					defer reader.Close()
					defer writer.Close()
					if restricted {
						if err := reader.Chmod(0); err != nil {
							t.Fatal(err)
						}
					}
					before, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, writeErr := io.WriteString(writer, test.data)
					if err := errors.Join(writeErr, writer.Close()); err != nil {
						t.Fatal(err)
					}
					code, stdout, stderr := runCLI(t, reader, "--"+test.source+"=-", "--jsonl", "--silent", "--no-colors", "--fingerprints", fixtureCatalogue(t))
					if code != 0 || stderr != "" {
						t.Fatalf("closed producer was not consumed: code=%d stdout=%q stderr=%q", code, stdout, stderr)
					}
					if test.want == "" {
						if stdout != "" {
							t.Fatalf("empty inherited pipe invented data: %q", stdout)
						}
					} else {
						results := decodeResultLines(t, stdout)
						if len(results) != 1 || results[0].Target != test.want {
							t.Fatalf("inherited pipe lost buffered data: %+v", results)
						}
						if test.source == "evidence" && (results[0].Outcome.State != wafme0w.Complete || len(results[0].Outcome.Matches) != 1) {
							t.Fatalf("inherited evidence lost complete-body semantics: %+v", results[0])
						}
					}
					after, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
					if err != nil || after != before {
						t.Fatalf("inherited stdin flags were not restored: before=%#x after=%#x err=%v", before, after, err)
					}
					if _, err := reader.Stat(); err != nil {
						t.Fatalf("caller-owned inherited stdin was closed: %v", err)
					}
				})
			}
		}
	}
}
