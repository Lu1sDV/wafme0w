package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Deliberately invalid schemes keep these input-selection tests independent of
// DNS, outbound requests, and the availability of a local HTTP listener.
func TestCLIContractRepeatableTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want []string
		code int
	}{
		{"long", []string{"--target=invalid://one", "--target", "invalid://two"}, []string{"invalid://one", "invalid://two"}, 0},
		{"mixed spellings", []string{"-tinvalid://one", "--target=invalid://two", "-t", "invalid://three"}, []string{"invalid://one", "invalid://two", "invalid://three"}, 0},
		{"duplicates retained", []string{"--target=invalid://one", "--target=invalid://one"}, []string{"invalid://one", "invalid://one"}, 0},
		{"literal commas and escapes", []string{"--target=invalid://one/a,b?value=%0A&flag=--input"}, []string{"invalid://one/a,b?value=%0A&flag=--input"}, 0},
		{"strict publishes all results", []string{"--target=invalid://one", "--target=invalid://two", "--strict"}, []string{"invalid://one", "invalid://two"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--jsonl", "--silent", "--no-colors", "--concurrency=1", "--fingerprints", fixtureCatalogue(t)}, tc.args...)
			code, stdout, stderr := runCLI(t, nil, args...)
			if code != tc.code || stderr != "" {
				t.Fatalf("direct targets: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			assertCLIContractTargets(t, stdout, tc.want)
		})
	}
}

func TestCLIContractRejectsNonSingleLineTargets(t *testing.T) {
	for _, value := range []string{"", " ", "\t", "invalid://one\ninvalid://two", "invalid://one\rinvalid://two", "invalid://one\r\n", "\ninvalid://one"} {
		for _, position := range []string{"first", "last"} {
			t.Run(position+"/"+strings.ReplaceAll(strings.ReplaceAll(value, "\n", "\\n"), "\r", "\\r"), func(t *testing.T) {
				args := []string{"--target", value, "--target=invalid://valid"}
				if position == "last" {
					args = []string{"--target=invalid://valid", "--target", value}
				}
				assertCLIContractRejectedBeforePublication(t, args, "target")
			})
		}
	}
}

func TestCLIContractTargetFileSpellings(t *testing.T) {
	for _, flag := range []string{"--target-file", "--input", "-I"} {
		for _, source := range []string{"file", "explicit stdin"} {
			t.Run(flag+"/"+source, func(t *testing.T) {
				content := "invalid://one\r\n\n  \ninvalid://two\n"
				path := "-"
				var stdin io.Reader = strings.NewReader(content)
				if source == "file" {
					path = filepath.Join(t.TempDir(), "targets with spaces.txt")
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
					stdin = strings.NewReader("invalid://ignored-stdin\n")
				}
				var stdout, stderr bytes.Buffer
				// Explicit '-' must work even when terminal detection says there
				// is no pipe. File selection must not consume supplied stdin.
				code := runContext(context.Background(), []string{flag, path, "--jsonl", "--silent", "--no-colors", "--concurrency=1", "--fingerprints", fixtureCatalogue(t)}, stdin, false, &stdout, &stderr)
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("target source: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
				assertCLIContractTargets(t, stdout.String(), []string{"invalid://one", "invalid://two"})
			})
		}
	}
}

func TestCLIContractRejectsRepeatedSources(t *testing.T) {
	for _, args := range [][]string{
		{"--target-file=-", "--target-file=-"},
		{"--input=-", "--input=-"},
		{"-I-", "-I-"},
		{"--input=-", "-I-"},
		{"-I-", "--input=-"},
		{"--target-file=-", "--input=-"},
		{"--input=-", "--target-file=-"},
		{"--target-file=-", "-I-"},
		{"-I-", "--target-file=-"},
		{"--evidence=-", "--evidence=-"},
		{"--input=", "--input=-"},
		{"--evidence=", "--evidence=-"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			assertCLIContractRejectedBeforePublication(t, args, "")
		})
	}
}

func TestCLIContractExclusiveSources(t *testing.T) {
	for _, args := range [][]string{
		{"--target=invalid://one", "--target-file=-"},
		{"--target-file=-", "--target=invalid://one"},
		{"--target=invalid://one", "--input=-"},
		{"--target=invalid://one", "-I-"},
		{"--target=invalid://one", "--evidence=-"},
		{"--target-file=-", "--evidence=-"},
		{"--input=-", "--evidence=-"},
		{"-I-", "--evidence=-"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			assertCLIContractRejectedBeforePublication(t, args, "exclusive")
		})
	}
}

func TestCLIContractInformationalCommandsRejectSources(t *testing.T) {
	for _, mode := range []string{"--list", "--version"} {
		for _, source := range []string{"--target=invalid://one", "--target-file=-", "--input=-", "-I-", "--evidence=-"} {
			t.Run(mode+"/"+source, func(t *testing.T) {
				code, stdout, stderr := runCLI(t, strings.NewReader(""), mode, source, "--no-colors")
				if code != 1 || stdout != "" || !strings.Contains(stderr, "cannot be combined") {
					t.Fatalf("informational command ignored source: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
				}
			})
		}
	}
}

func TestCLIContractExplicitInputPrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(path, []byte("invalid://from-file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		want []string
	}{
		{"implicit stdin", nil, []string{"invalid://from-stdin"}},
		{"direct targets", []string{"--target=invalid://one", "--target=invalid://two"}, []string{"invalid://one", "invalid://two"}},
		{"canonical file", []string{"--target-file", path}, []string{"invalid://from-file"}},
		{"legacy file", []string{"--input", path}, []string{"invalid://from-file"}},
		{"short file", []string{"-I", path}, []string{"invalid://from-file"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"--jsonl", "--silent", "--no-colors", "--concurrency=1", "--fingerprints", fixtureCatalogue(t)}, tc.args...)
			code, stdout, stderr := runCLI(t, strings.NewReader("invalid://from-stdin\n"), args...)
			if code != 0 || stderr != "" {
				t.Fatalf("source precedence: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			assertCLIContractTargets(t, stdout, tc.want)
		})
	}
}

func TestCLIContractPositionalsAndDelimiter(t *testing.T) {
	for _, args := range [][]string{
		{"invalid://positional"},
		{"--target=invalid://selected", "--", "invalid://positional"},
		{"--", "--target=invalid://positional"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			assertCLIContractRejectedBeforePublication(t, args, "positional")
		})
	}
	code, stdout, stderr := runCLI(t, nil, "--jsonl", "--silent", "--no-colors", "--target=invalid://selected", "--")
	if code != 0 || stderr != "" {
		t.Fatalf("empty delimiter tail changed selection: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	assertCLIContractTargets(t, stdout, []string{"invalid://selected"})
}

func TestCLIContractTargetFileCollisionChecks(t *testing.T) {
	for _, sourceFlag := range []string{"--target-file", "--input", "-I"} {
		for _, sinkFlag := range []string{"--output", "--diagnostics-journal"} {
			for _, stdinSource := range []bool{false, true} {
				name := sourceFlag + "/" + sinkFlag + "/file"
				if stdinSource {
					name = sourceFlag + "/" + sinkFlag + "/stdin"
				}
				t.Run(name, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "targets.jsonl")
					const content = "invalid://preserve-this-input\n"
					if err := os.WriteFile(path, []byte(content), 0600); err != nil {
						t.Fatal(err)
					}
					inputPath := path
					var stdin io.Reader
					if stdinSource {
						file, err := os.Open(path)
						if err != nil {
							t.Fatal(err)
						}
						defer file.Close()
						stdin, inputPath = file, "-"
					}
					code, stdout, stderr := runCLI(t, stdin, sourceFlag, inputPath, sinkFlag, path, "--jsonl", "--silent", "--no-colors", "--fingerprints", fixtureCatalogue(t))
					if code != 1 || stdout != "" || !strings.Contains(stderr, "same file") {
						t.Fatalf("collision accepted or misdiagnosed: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
					}
					if data, err := os.ReadFile(path); err != nil || string(data) != content {
						t.Fatalf("collision changed input: %q %v", data, err)
					}
				})
			}
		}
	}
}

type cliContractStartedReader struct {
	*io.PipeReader
	started chan struct{}
	once    sync.Once
}

func (reader *cliContractStartedReader) Read(data []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	return reader.PipeReader.Read(data)
}

func TestCLIContractTargetStdinCancellation(t *testing.T) {
	for _, flag := range []string{"--target-file", "--input", "-I"} {
		t.Run(flag, func(t *testing.T) {
			input, writer := io.Pipe()
			reader := &cliContractStartedReader{PipeReader: input, started: make(chan struct{})}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer reader.Close()
			defer writer.Close()
			output := filepath.Join(t.TempDir(), "report.json")
			const previous = "previous report"
			if err := os.WriteFile(output, []byte(previous), 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{flag, "-", "--output", output, "--silent", "--no-colors", "--fingerprints", fixtureCatalogue(t)}
			var stdout, stderr bytes.Buffer
			done := make(chan int, 1)
			go func() { done <- runContext(ctx, args, reader, false, &stdout, &stderr) }()
			select {
			case <-reader.started:
			case code := <-done:
				t.Fatalf("explicit stdin was not selected: exit=%d stderr=%q", code, stderr.String())
			case <-time.After(5 * time.Second):
				cancel()
				_ = reader.Close()
				<-done
				t.Fatal("explicit stdin never reached its reader")
			}
			cancel()
			select {
			case code := <-done:
				if code != 130 || stdout.Len() != 0 {
					t.Fatalf("stdin cancellation: exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
				}
			case <-time.After(5 * time.Second):
				_ = reader.Close()
				<-done
				t.Fatal("cancellation did not unblock explicit stdin")
			}
			if data, err := os.ReadFile(output); err != nil || string(data) != previous {
				t.Fatalf("cancellation replaced prior report: %q %v", data, err)
			}
		})
	}
}

func assertCLIContractTargets(t *testing.T, stdout string, want []string) {
	t.Helper()
	var got []string
	for _, result := range decodeResultLines(t, stdout) {
		got = append(got, result.Target)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target selection changed: got=%q want=%q", got, want)
	}
}

func assertCLIContractRejectedBeforePublication(t *testing.T, args []string, diagnostic string) {
	t.Helper()
	dir := t.TempDir()
	report, journal := filepath.Join(dir, "report.json"), filepath.Join(dir, "journal.jsonl")
	const previous = "previous report"
	if err := os.WriteFile(report, []byte(previous), 0600); err != nil {
		t.Fatal(err)
	}
	args = append(append([]string{}, args...), "--jsonl", "--silent", "--no-colors", "--output", report, "--diagnostics-journal", journal, "--fingerprints", fixtureCatalogue(t))
	code, stdout, stderr := runCLI(t, strings.NewReader(""), args...)
	if code != 1 || stdout != "" || stderr == "" || !strings.Contains(stderr, diagnostic) {
		t.Fatalf("invalid configuration accepted or misdiagnosed: exit=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if data, err := os.ReadFile(report); err != nil || string(data) != previous {
		t.Fatalf("invalid configuration replaced prior report: %q %v", data, err)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatalf("invalid configuration opened a journal: %v", err)
	}
}
