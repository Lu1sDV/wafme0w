//go:build !linux

package offlinebench

import (
	"errors"
	"os"
)

func openInputFile(path string) (*os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("input must be a regular file")
	}
	return os.Open(path)
}
