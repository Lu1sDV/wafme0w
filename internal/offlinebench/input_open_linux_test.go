package offlinebench

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLoadCorpusRejectsFIFOWithoutWaitingForWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	bodies := t.TempDir()
	done := make(chan error, 1)
	go func() {
		_, err := LoadCorpusContext(ctx, path, bodies)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("FIFO was not rejected as nonregular input: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("corpus loader waited for a FIFO writer")
	}
}
