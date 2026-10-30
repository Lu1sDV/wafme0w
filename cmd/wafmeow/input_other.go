//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

import (
	"errors"
	"io"
	"os"
)

func openInputFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil && info.Mode().IsRegular() {
		return file, nil
	}
	if err == nil {
		err = errors.New("named input requires a regular file on this platform; use stdin for streams")
	}
	return nil, errors.Join(err, file.Close())
}
