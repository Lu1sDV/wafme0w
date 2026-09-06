package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestFailedPublicationPreservesDestination(t *testing.T) {
	for _, exists := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "results.json")
		if exists {
			if err := os.WriteFile(path, []byte("previous report"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		sentinel := errors.New("sink failed")
		err := Write(path, func(writer io.Writer) error {
			if _, err := io.WriteString(writer, "partial report"); err != nil {
				return err
			}
			_, err := io.Copy(io.MultiWriter(writer, failingWriter{sentinel}), strings.NewReader("unfinished report"))
			return err
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("writer error lost: %v", err)
		}
		data, err := os.ReadFile(path)
		if exists {
			if err != nil || string(data) != "previous report" {
				t.Fatalf("failed write replaced report: %q %v", data, err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed write published output: %q %v", data, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		want := 0
		if exists {
			want = 1
		}
		if len(entries) != want {
			t.Fatalf("temporary output leaked: %v", entries)
		}
	}
}

func TestSuccessfulPublicationReplacesOldContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "results.txt")
	if err := os.WriteFile(path, []byte("stale report"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, func(writer io.Writer) error { _, err := io.WriteString(writer, "new report"); return err }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "new report" {
		t.Fatalf("report was not published: %q %v", data, err)
	}
}

func TestRenameFailureCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "destination")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, func(writer io.Writer) error { _, err := io.WriteString(writer, "report"); return err }); err == nil {
		t.Fatal("directory was replaced by a report")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].IsDir() {
		t.Fatalf("failed rename left output: %v", entries)
	}
}
