package browserruntime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestValidateExecutableRejectsFIFOWithoutBlocking(t *testing.T) {
	const childPath = "WAFME0W_TEST_EXECUTABLE_FIFO"
	if path := os.Getenv(childPath); path != "" {
		if err := ValidateExecutable(path); err == nil || !strings.Contains(err.Error(), "native") {
			t.Fatalf("FIFO executable validation: %v", err)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "browser")
	if err := syscall.Mkfifo(path, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Use an owned subprocess so a blocking open cannot strand the test runner.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestValidateExecutableRejectsFIFOWithoutBlocking$")
	cmd.Env = append(os.Environ(), childPath+"="+path)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FIFO executable validation blocked: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("FIFO executable validation: %v\n%s", err, output)
	}
}

func TestValidateExecutableRequiresNativeRegularExecutable(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name    string
		content string
		mode    os.FileMode
		wantErr bool
	}{
		{"native", "\x7fELFfixture", 0700, false},
		{"not-executable", "\x7fELFfixture", 0600, true},
		{"wrapper", "#!/bin/sh\nexit 0\n", 0700, true},
		{"truncated", "\x7fEL", 0700, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name)
			if err := os.WriteFile(path, []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			if err := ValidateExecutable(path); (err != nil) != tc.wantErr {
				t.Fatalf("ValidateExecutable() = %v, want error %v", err, tc.wantErr)
			}
		})
	}
	if err := ValidateExecutable(root); err == nil {
		t.Fatal("directory accepted as a browser executable")
	}
	alias := filepath.Join(root, "native-link")
	if err := os.Symlink(filepath.Join(root, "native"), alias); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecutable(alias); err != nil {
		t.Fatalf("native executable symlink rejected: %v", err)
	}
}

func TestExecutableFIFODescriptorsCannotBlock(t *testing.T) {
	const childPath = "WAFME0W_TEST_EXECUTABLE_DESCRIPTOR_FIFO"
	const childPhase = "WAFME0W_TEST_EXECUTABLE_DESCRIPTOR_PHASE"
	if path := os.Getenv(childPath); path != "" {
		var file *os.File
		var err error
		if os.Getenv(childPhase) == "open" {
			file, err = openExecutable(path)
		} else {
			file, err = os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if os.Getenv(childPhase) == "validate" {
			if err := validateOpenedExecutable(file); err == nil || !strings.Contains(err.Error(), "native") {
				t.Fatalf("opened FIFO executable validation: %v", err)
			}
		}
		return
	}
	for _, phase := range []string{"open", "validate"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "browser")
			if err := syscall.Mkfifo(path, 0700); err != nil {
				t.Fatal(err)
			}
			if phase == "validate" {
				// A held writer with no data makes any attempted read wait. This
				// models the descriptor obtained after a regular-path replacement
				// without relying on a probabilistic filesystem race.
				writer, err := os.OpenFile(path, os.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestExecutableFIFODescriptorsCannotBlock$")
			cmd.Env = append(os.Environ(), childPath+"="+path, childPhase+"="+phase)
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("FIFO descriptor %s blocked: %v", phase, ctx.Err())
			}
			if err != nil {
				t.Fatalf("FIFO descriptor %s: %v\n%s", phase, err, output)
			}
		})
	}
}
