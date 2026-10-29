//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import (
	"context"
	"io"
	"os"
)

// Inherited synchronous Windows pipe writes cannot use Unix pollable duplicates.
func cancellableOutput(_ context.Context, source *os.File) (io.Writer, func() error, error) {
	return source, func() error { return nil }, nil
}
