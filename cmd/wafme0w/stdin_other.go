//go:build !linux

package main

import (
	"io"
	"os"
)

func cancellableStdin() (io.ReadCloser, error) { return os.Stdin, nil }
