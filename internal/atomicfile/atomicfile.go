// Package atomicfile publishes a file only after its writer succeeds.
package atomicfile

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Write writes beside path, then atomically replaces path. Failed callbacks,
// flushes, syncs, closes, and renames leave the previous destination untouched.
func Write(path string, write func(io.Writer) error) (err error) {
	if write == nil {
		return errors.New("nil file writer")
	}
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	defer os.Remove(file.Name())
	buffer := bufio.NewWriter(file)
	if err = write(buffer); err == nil {
		err = buffer.Flush()
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	return nil
}
