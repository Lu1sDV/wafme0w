package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
)

func TestCLINoAnimationKeepsStaticHumanOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runContext(context.Background(), []string{"--target-file=-", "--no-animation", "--no-colors"}, strings.NewReader(""), true, &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "wafmeow") || !strings.Contains(stderr.String(), "SUMMARY") {
		t.Fatalf("static opt-out: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if strings.ContainsAny(stdout.String()+stderr.String(), "\x1b\r") {
		t.Fatal("plain static output contains terminal controls")
	}
	var help bytes.Buffer
	if err := writeHelpWidth(&help, 80); err != nil || !strings.Contains(help.String(), "--no-animation") {
		t.Fatalf("animation opt-out is missing from help: %v", err)
	}
}

func animationEnvironment(t *testing.T) {
	t.Helper()
	previous, set := os.LookupEnv("NO_COLOR")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if set {
			_ = os.Setenv("NO_COLOR", previous)
		} else {
			_ = os.Unsetenv("NO_COLOR")
		}
	})
	t.Setenv("TERM", "xterm-256color")
}

func animationTerminal() bannerTerminal {
	return bannerTerminal{interactive: true, ansi: true, columns: 80, rows: 24}
}

type logoTestWriter struct {
	mu     sync.Mutex
	writes []string
	failAt int
	short  bool
	err    error
}

func (writer *logoTestWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.writes = append(writer.writes, string(data))
	if len(writer.writes) == writer.failAt {
		if writer.short {
			return len(data) / 2, nil
		}
		return 0, writer.err
	}
	return len(data), nil
}

func (writer *logoTestWriter) snapshot() (string, int) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	return strings.Join(writer.writes, ""), len(writer.writes)
}

type logoTestSize struct {
	mu            sync.Mutex
	columns, rows int
}

func (size *logoTestSize) get() (int, int) {
	size.mu.Lock()
	defer size.mu.Unlock()
	return size.columns, size.rows
}

func (size *logoTestSize) set(columns, rows int) {
	size.mu.Lock()
	defer size.mu.Unlock()
	size.columns, size.rows = columns, rows
}

func TestLogoFramesHaveBoundedGeometry(t *testing.T) {
	for frame, rows := range logoFrames {
		for row, text := range rows {
			if len(text) > logoColumns {
				t.Errorf("frame %d row %d exceeds %d columns: %q", frame, row, logoColumns, text)
			}
			for _, character := range []byte(text) {
				if character < 32 || character > 126 {
					t.Errorf("frame %d row %d is not printable ASCII", frame, row)
				}
			}
		}
		plain := logoFrame(frame, false, aurora.New(aurora.WithColors(false)))
		if strings.Count(plain, "\n") != logoRows || strings.ContainsAny(plain, "\x1b\r") || !strings.HasSuffix(plain, "\n") {
			t.Errorf("frame %d changed geometry or cursor state: %q", frame, plain)
		}
	}
}

func TestLogoAnimationGates(t *testing.T) {
	animationEnvironment(t)
	for _, test := range []struct {
		name      string
		configure func(*options, *bannerTerminal)
		empty     bool
	}{
		{"opt out", func(opts *options, _ *bannerTerminal) { opts.NoAnimation = true }, false},
		{"no colors", func(opts *options, _ *bannerTerminal) { opts.NoColors = true }, false},
		{"JSONL", func(opts *options, _ *bannerTerminal) { opts.JSONL = true }, true},
		{"silent", func(opts *options, _ *bannerTerminal) { opts.Silent = true }, true},
		{"list", func(opts *options, _ *bannerTerminal) { opts.ListWAFS = true }, true},
		{"version", func(opts *options, _ *bannerTerminal) { opts.Version = true }, true},
		{"redirected stdout", func(_ *options, terminal *bannerTerminal) { terminal.interactive = false }, false},
		{"dumb or unknown terminal", func(_ *options, terminal *bannerTerminal) { terminal.ansi = false }, false},
		{"narrow terminal", func(_ *options, terminal *bannerTerminal) { terminal.columns = logoColumns }, false},
		{"short terminal", func(_ *options, terminal *bannerTerminal) { terminal.rows = logoRows }, false},
		{"unknown width", func(_ *options, terminal *bannerTerminal) { terminal.columns = 0 }, false},
		{"unknown height", func(_ *options, terminal *bannerTerminal) { terminal.rows = 0 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			opts, terminal := newOptions(wafmeow.DefaultConfig()), animationTerminal()
			test.configure(&opts, &terminal)
			var output bytes.Buffer
			animation, err := startScanBanner(context.Background(), &output, opts, aurora.New(aurora.WithColors(false)), terminal, func() { t.Error("static banner aborted acquisition") })
			if animation != nil {
				_ = animation.stop()
				t.Fatal("ineligible output started an animation")
			}
			if err != nil || (output.Len() == 0) != test.empty || strings.ContainsAny(output.String(), "\x1b\r") {
				t.Fatalf("gate failed: err=%v output=%q", err, output.String())
			}
		})
	}
	t.Run("NO_COLOR even empty", func(t *testing.T) {
		t.Setenv("NO_COLOR", "")
		var output bytes.Buffer
		animation, err := startScanBanner(context.Background(), &output, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(true)), animationTerminal(), func() { t.Error("static banner aborted") })
		if animation != nil {
			_ = animation.stop()
			t.Fatal("NO_COLOR started animation")
		}
		if err != nil || strings.ContainsAny(output.String(), "\x1b\r") {
			t.Fatalf("NO_COLOR output: %v %q", err, output.String())
		}
	})
	if terminal := inspectBannerTerminal(&bytes.Buffer{}); terminal.interactive {
		t.Fatal("non-file writer detected as a terminal")
	}
}

func TestLogoAnimationStopsImmediatelyAndNeverRedrawsAfterResult(t *testing.T) {
	animationEnvironment(t)
	synctest.Test(t, func(t *testing.T) {
		writer := &logoTestWriter{}
		animation, err := startScanBanner(context.Background(), writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), animationTerminal(), func() { t.Error("animation aborted") })
		if err != nil || animation == nil {
			t.Fatalf("start: animation=%v err=%v", animation, err)
		}
		if _, writes := writer.snapshot(); writes != 1 {
			t.Fatalf("first frame was not synchronous: %d writes", writes)
		}
		time.Sleep(logoInterval)
		synctest.Wait()
		before := time.Now()
		if err := animation.stop(); err != nil {
			t.Fatal(err)
		}
		if !time.Now().Equal(before) {
			t.Fatal("first result waited for an animation timer")
		}
		_, _ = io.WriteString(writer, "RESULT starts here\n")
		snapshot, writes := writer.snapshot()
		time.Sleep(time.Second)
		synctest.Wait()
		if err := animation.stop(); err != nil {
			t.Fatal(err)
		}
		if got, count := writer.snapshot(); got != snapshot || count != writes {
			t.Fatalf("redraw after result or repeated stop: %q", got)
		}
		if strings.Contains(snapshot, "\x1b[?25") || strings.Contains(snapshot, "\x1b[?1049") {
			t.Fatal("animation changed cursor visibility or alternate screen")
		}
	})
}

func TestLogoAnimationFinishesWithin540ms(t *testing.T) {
	animationEnvironment(t)
	synctest.Test(t, func(t *testing.T) {
		writer := &logoTestWriter{}
		animation, err := startScanBanner(context.Background(), writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), animationTerminal(), func() { t.Error("animation aborted") })
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(540 * time.Millisecond)
		synctest.Wait()
		select {
		case <-animation.done:
		default:
			t.Fatal("animation outlived its bounded startup interval")
		}
		text, writes := writer.snapshot()
		if writes != len(logoFrames) || !strings.HasSuffix(text, logoFrame(len(logoFrames)-1, true, aurora.New(aurora.WithColors(false)))) {
			t.Fatalf("animation did not settle on its final frame: writes=%d text=%q", writes, text)
		}
		if err := animation.stop(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLogoAnimationCancellationAndResizeLeaveNoRedraw(t *testing.T) {
	animationEnvironment(t)
	for _, mode := range []string{"cancel", "resize narrower", "resize wider", "unknown dimensions"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				terminal := animationTerminal()
				size := &logoTestSize{columns: terminal.columns, rows: terminal.rows}
				terminal.size = size.get
				writer := &logoTestWriter{}
				animation, err := startScanBanner(ctx, writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), terminal, func() { t.Error("context or resize is not a sink failure") })
				if err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				switch mode {
				case "cancel":
					cancel()
				case "resize narrower":
					size.set(20, terminal.rows)
				case "resize wider":
					size.set(120, terminal.rows)
				case "unknown dimensions":
					size.set(0, 0)
				}
				time.Sleep(logoInterval)
				synctest.Wait()
				if err := animation.stop(); err != nil {
					t.Fatal(err)
				}
				if text, writes := writer.snapshot(); writes != 1 || strings.Contains(text, "\x1b[") {
					t.Fatalf("invalid cursor restoration after %s: writes=%d text=%q", mode, writes, text)
				}
			})
		})
	}
}

func TestLogoAnimationWriterFailures(t *testing.T) {
	animationEnvironment(t)
	for _, stage := range []string{"first", "timer", "settle"} {
		for _, short := range []bool{false, true} {
			t.Run(stage+map[bool]string{true: " short", false: " error"}[short], func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					failure := errors.New("owned logo writer failure")
					writer := &logoTestWriter{failAt: 2, short: short, err: failure}
					if stage == "first" {
						writer.failAt = 1
					}
					if short {
						failure = io.ErrShortWrite
					}
					aborted := 0
					animation, err := startScanBanner(context.Background(), writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), animationTerminal(), func() { aborted++ })
					if stage == "first" {
						if animation != nil || !errors.Is(err, failure) || aborted != 0 {
							t.Fatalf("first-frame failure: animation=%v err=%v aborted=%d", animation, err, aborted)
						}
						return
					}
					if err != nil {
						t.Fatal(err)
					}
					if stage == "timer" {
						time.Sleep(logoInterval)
						synctest.Wait()
					}
					if err := animation.stop(); !errors.Is(err, failure) || aborted != 1 {
						t.Fatalf("later failure: err=%v aborted=%d", err, aborted)
					}
					_, writes := writer.snapshot()
					time.Sleep(time.Second)
					synctest.Wait()
					if _, got := writer.snapshot(); got != writes {
						t.Fatal("failed animator kept writing")
					}
				})
			})
		}
	}
}

func TestCLIBannerStopsBeforeSharedConsoleResultsAndDiagnostics(t *testing.T) {
	animationEnvironment(t)
	catalogue := fixtureCatalogue(t)
	input := captureLines(t, wafmeow.Capture{Target: "saved", Evidence: []wafmeow.Evidence{{Role: "Normal", StatusCode: 200, Body: []byte("ordinary")}}})
	for _, batch := range []string{"1", "4"} {
		t.Run("journal batch "+batch, func(t *testing.T) {
			journal := filepath.Join(t.TempDir(), "journal.jsonl")
			synctest.Test(t, func(t *testing.T) {
				writer := &logoTestWriter{}
				started := time.Now()
				code := runContextWithTerminal(context.Background(), []string{"--evidence=-", "--fingerprints", catalogue, "--debug", "--diagnostics-journal", journal, "--journal-batch-size", batch}, strings.NewReader(input), true, writer, writer, animationTerminal())
				text, _ := writer.snapshot()
				if code != 0 || time.Since(started) >= logoInterval {
					t.Fatalf("result waited for animation: exit=%d elapsed=%v output=%q", code, time.Since(started), text)
				}
				first := strings.Index(text, "DEBUG")
				if first < 0 || !strings.Contains(text[:first], "\x1b[9A") || strings.Contains(text[first:], "\x1b[9A") || !strings.Contains(text, "SUMMARY") {
					t.Fatalf("shared terminal redraw interleaved with diagnostics/results: %q", text)
				}
				data, err := os.ReadFile(journal)
				if err != nil || !strings.Contains(string(data), `"type":"result"`) {
					t.Fatalf("journal lost result: %q %v", data, err)
				}
			})
		})
	}
}

func TestCLIBannerEarlyEndAndModeExclusions(t *testing.T) {
	animationEnvironment(t)
	catalogue := fixtureCatalogue(t)
	for _, test := range []struct {
		name     string
		args     []string
		input    string
		code     int
		animated bool
	}{
		{"empty input", []string{"--evidence=-"}, "", 0, true},
		{"malformed input", []string{"--evidence=-"}, "{bad}\n", 1, true},
		{"help", []string{"--help"}, "", 0, false},
		{"version", []string{"--version"}, "", 0, false},
		{"list", []string{"--list"}, "", 0, false},
		{"JSONL", []string{"--evidence=-", "--jsonl"}, "", 0, false},
		{"silent", []string{"--evidence=-", "--jsonl", "--silent"}, "", 0, false},
		{"atomic open failure", []string{"--evidence=-", "--output", filepath.Join(t.TempDir(), "missing", "out.json")}, "", 1, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				writer := &logoTestWriter{}
				args := append(append([]string{}, test.args...), "--fingerprints", catalogue)
				started := time.Now()
				code := runContextWithTerminal(context.Background(), args, strings.NewReader(test.input), true, writer, writer, animationTerminal())
				text, _ := writer.snapshot()
				if code != test.code || time.Since(started) >= logoInterval || strings.Contains(text, "\x1b[9A") != test.animated {
					t.Fatalf("early end/exclusion: code=%d elapsed=%v text=%q", code, time.Since(started), text)
				}
				for _, marker := range []string{"PARTIAL SUMMARY", "SUMMARY", "ERROR render", "ERROR open"} {
					if at := strings.Index(text, marker); at >= 0 && strings.Contains(text[at:], "\x1b[9A") {
						t.Fatalf("redraw after %s: %q", marker, text)
					}
				}
			})
		})
	}
}

type logoInputReader struct {
	reads  int
	closed bool
}

func (reader *logoInputReader) Read([]byte) (int, error) { reader.reads++; return 0, io.EOF }
func (reader *logoInputReader) Close() error             { reader.closed = true; return nil }

func TestCLIBannerFirstFrameFailurePreventsInputAcquisition(t *testing.T) {
	animationEnvironment(t)
	for _, short := range []bool{false, true} {
		writer := &logoTestWriter{failAt: 1, short: short, err: errors.New("owned first frame failure")}
		input := &logoInputReader{}
		var stderr bytes.Buffer
		code := runContextWithTerminal(context.Background(), []string{"--target-file=-"}, input, true, writer, &stderr, animationTerminal())
		if code != 1 || input.reads != 0 || !input.closed || !strings.Contains(stderr.String(), "render startup logo") {
			t.Fatalf("initial sink failure acquired input: exit=%d reads=%d closed=%t stderr=%q", code, input.reads, input.closed, stderr.String())
		}
	}
}

func TestCLIBannerLaterFailureCancelsOpenInputAndPreservesReport(t *testing.T) {
	animationEnvironment(t)
	catalogue := fixtureCatalogue(t)
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{true: "short", false: "error"}[short], func(t *testing.T) {
			directory := t.TempDir()
			report := filepath.Join(directory, "report.json")
			journal := filepath.Join(directory, "journal.jsonl")
			if err := os.WriteFile(report, []byte("previous report"), 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				input, producer := io.Pipe()
				defer producer.Close()
				writer := &logoTestWriter{failAt: 2, short: short, err: errors.New("owned redraw failure")}
				var stderr bytes.Buffer
				code := runContextWithTerminal(context.Background(), []string{"--evidence=-", "--fingerprints", catalogue, "--output", report, "--diagnostics-journal", journal}, input, true, writer, &stderr, animationTerminal())
				if code != 1 || strings.Count(stderr.String(), "render startup logo:") != 1 {
					t.Fatalf("late sink failure: code=%d stderr=%q", code, stderr.String())
				}
				if _, err := producer.Write([]byte("next")); !errors.Is(err, io.ErrClosedPipe) {
					t.Fatalf("open producer not woken: %v", err)
				}
				data, err := os.ReadFile(report)
				if err != nil || string(data) != "previous report" {
					t.Fatalf("failed animation replaced report: %q %v", data, err)
				}
				data, err = os.ReadFile(journal)
				if err != nil || !strings.Contains(string(data), "run_error") || !strings.Contains(string(data), "render startup logo") {
					t.Fatalf("missing failure journal: %q %v", data, err)
				}
			})
		})
	}
}

func TestCLIBannerCancellationWhileInputWaits(t *testing.T) {
	animationEnvironment(t)
	catalogue := fixtureCatalogue(t)
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		input, producer := io.Pipe()
		defer producer.Close()
		writer := &logoTestWriter{}
		done := make(chan int, 1)
		go func() {
			done <- runContextWithTerminal(ctx, []string{"--evidence=-", "--fingerprints", catalogue}, input, true, writer, writer, animationTerminal())
		}()
		synctest.Wait()
		time.Sleep(logoInterval)
		synctest.Wait()
		cancel()
		synctest.Wait()
		if code := <-done; code != 130 {
			t.Fatalf("cancellation exit=%d", code)
		}
		text, writes := writer.snapshot()
		time.Sleep(time.Second)
		synctest.Wait()
		if after, count := writer.snapshot(); count != writes || text != after {
			t.Fatal("cancelled CLI kept animating")
		}
		if _, err := producer.Write([]byte("next")); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("cancelled input not closed: %v", err)
		}
	})
}

func TestLogoFinalFrameFailureOccursAfterJournalDurability(t *testing.T) {
	animationEnvironment(t)
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	synctest.Test(t, func(t *testing.T) {
		journal, err := openJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		defer journal.close()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		failure := errors.New("owned final frame failure")
		writer := &logoTestWriter{failAt: 2, err: failure}
		animation, err := startScanBanner(ctx, writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), animationTerminal(), cancel)
		if err != nil {
			t.Fatal(err)
		}
		sink := newJournalSink(journal, 4, func(wafmeow.Result) error { return animation.stop() }, cancel)
		// The runner requests a stop at its first emit before handing the
		// result to the journal. Give the timer owner time to acknowledge it;
		// this must not attempt a fallible final frame before durable output.
		animation.requestStop()
		synctest.Wait()
		_, writes := writer.snapshot()
		writeErr := sink.write(ctx, wafmeow.Result{Target: "saved-before-final-frame"})
		closeErr := sink.close()
		if writes != 1 {
			t.Errorf("final frame written before durable result: %d writes", writes)
		}
		if writeErr != nil || !errors.Is(closeErr, failure) {
			t.Errorf("journal handoff: write=%v close=%v", writeErr, closeErr)
		}
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "saved-before-final-frame") {
			t.Fatalf("cosmetic sink failure lost journal result: %q %v", data, err)
		}
	})
}

func TestLogoAnimationResizeBackDoesNotReenableRedraw(t *testing.T) {
	animationEnvironment(t)
	synctest.Test(t, func(t *testing.T) {
		terminal := animationTerminal()
		size := &logoTestSize{columns: terminal.columns, rows: terminal.rows}
		terminal.size = size.get
		writer := &logoTestWriter{}
		animation, err := startScanBanner(context.Background(), writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), terminal, func() { t.Error("resize aborted acquisition") })
		if err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		size.set(20, terminal.rows)
		time.Sleep(logoInterval)
		synctest.Wait()
		size.set(terminal.columns, terminal.rows)
		if err := animation.stop(); err != nil {
			t.Fatal(err)
		}
		if text, writes := writer.snapshot(); writes != 1 || strings.Contains(text, "\x1b[9A") {
			t.Fatalf("resize-back reused invalidated cursor position: writes=%d text=%q", writes, text)
		}
	})
}

func TestLogoConcurrentStopSettlesOnce(t *testing.T) {
	animationEnvironment(t)
	synctest.Test(t, func(t *testing.T) {
		writer := &logoTestWriter{failAt: 2, err: errors.New("owned shared settle failure")}
		aborted := 0
		animation, err := startScanBanner(context.Background(), writer, newOptions(wafmeow.DefaultConfig()), aurora.New(aurora.WithColors(false)), animationTerminal(), func() { aborted++ })
		if err != nil {
			t.Fatal(err)
		}
		var group sync.WaitGroup
		failures := make(chan error, 8)
		for range 8 {
			group.Go(func() { failures <- animation.stop() })
		}
		group.Wait()
		for range 8 {
			if err := <-failures; !errors.Is(err, writer.err) {
				t.Errorf("stop lost sink failure: %v", err)
			}
		}
		if _, writes := writer.snapshot(); writes != 2 || aborted != 1 {
			t.Fatalf("concurrent stop repeated final output: writes=%d aborts=%d", writes, aborted)
		}
	})
}
