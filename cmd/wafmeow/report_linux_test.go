package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
	"golang.org/x/sys/unix"
)

func TestCLIRealBrokenPipeRemovesHumanReportSpool(t *testing.T) {
	directory := t.TempDir()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, executable, "--target=invalid://fixture", "--no-colors")
	cmd.Env = append(os.Environ(), "WAFME0W_CLI_TEST_PROCESS=1", "TMPDIR="+directory)
	cmd.Stdout = writer
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("broken pipe bypassed normal failure cleanup: err=%v context=%v stderr=%q", err, ctx.Err(), stderr.String())
	}
	if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
		t.Fatalf("broken pipe leaked report spool: entries=%v err=%v", entries, err)
	}
}

func TestCLICancellationUnblocksInheritedReportPipe(t *testing.T) {
	catalogue := fixtureCatalogue(t)
	for _, restricted := range []bool{false, true} {
		name := "reopened pipe"
		if restricted {
			name = "inherited-only pipe"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			writerFD := writer.Fd()
			// Keep a 32 KiB replay write blocked even after bufio reads a prefix.
			if _, err := unix.FcntlInt(writerFD, unix.F_SETPIPE_SZ, 4096); err != nil {
				t.Fatal(err)
			}
			if restricted {
				if err := writer.Chmod(0); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			if err := reader.SetReadDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			target := "saved-report-pipe/" + strings.Repeat("full-path/", 5000)
			input := captureLines(t, wafmeow.Capture{Target: target, Evidence: []wafmeow.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}})
			output := filepath.Join(t.TempDir(), "report.json")
			cmd := exec.CommandContext(ctx, executable, "--evidence=-", "--fingerprints", catalogue, "--output", output, "--no-colors")
			cmd.Env = append(os.Environ(), "WAFME0W_CLI_TEST_PROCESS=1", "TMPDIR="+directory)
			cmd.Stdin = strings.NewReader(input)
			cmd.Stdout, cmd.Stderr = io.Discard, writer
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := bufio.NewReader(reader)
			for {
				line, err := lines.ReadString('\n')
				if err != nil {
					cancel()
					_ = cmd.Wait()
					t.Fatalf("final table heading: %v", err)
				}
				if strings.HasPrefix(line, "--------|") {
					break
				}
			}
			if _, err := lines.ReadByte(); err != nil {
				cancel()
				_ = cmd.Wait()
				t.Fatalf("first replay chunk: %v", err)
			}
			if err := cmd.Process.Signal(os.Interrupt); err != nil {
				cancel()
				_ = cmd.Wait()
				t.Fatal(err)
			}
			err = cmd.Wait()
			var exitErr *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 130 {
				t.Fatalf("blocked report pipe cancellation: err=%v context=%v", err, ctx.Err())
			}
			if data, err := os.ReadFile(output); err != nil || !bytes.Contains(data, []byte("saved-report-pipe/")) {
				t.Fatalf("already-published report was lost: bytes=%d err=%v", len(data), err)
			}
			if entries, err := os.ReadDir(directory); err != nil || len(entries) != 0 {
				t.Fatalf("cancellation leaked report spool: entries=%v err=%v", entries, err)
			}
			flags, err := unix.FcntlInt(writerFD, unix.F_GETFL, 0)
			if err != nil || flags&unix.O_NONBLOCK != 0 {
				t.Fatalf("inherited pipe flags were not restored: flags=%#x err=%v", flags, err)
			}
		})
	}
}

func TestCancellableOutputPreservesInheritedNonblockingFlags(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	fd := writer.Fd()
	if err := unix.SetNonblock(int(fd), true); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output, release, err := cancellableOutput(ctx, writer)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := release(); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("closed duplicate")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("owned output remained writable after cancellation: %v", err)
	}
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("inherited nonblocking flag changed: flags=%#x err=%v", flags, err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatalf("caller-owned source was closed: %v", err)
	}
	var data [1]byte
	if _, err := io.ReadFull(reader, data[:]); err != nil || data[0] != 'x' {
		t.Fatalf("caller-owned pipe was damaged: data=%q err=%v", data, err)
	}
}
