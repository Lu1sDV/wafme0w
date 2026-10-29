//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

func openInputFile(path string) (io.ReadCloser, error) {
	// Set nonblocking mode in open itself: a path can become a FIFO at any time.
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err == nil {
		switch {
		case info.Mode().IsRegular():
			return file, nil
		case info.Mode()&os.ModeNamedPipe != 0 && runtime.GOOS == "linux":
			return &namedPipeInput{File: file}, nil
		case info.Mode()&os.ModeNamedPipe != 0:
			err = errors.New("named input pipes are supported only on Linux; use a regular file or stdin")
		default:
			err = errors.New("input must be a regular file or a Linux named pipe")
		}
	}
	return nil, errors.Join(err, file.Close())
}

type namedPipeInput struct {
	*os.File
	ready bool
}

func (input *namedPipeInput) Read(data []byte) (int, error) {
	if !input.ready && len(data) != 0 {
		raw, err := input.File.SyscallConn()
		if err != nil {
			return 0, err
		}
		var pollErr error
		err = raw.Read(func(fd uintptr) bool {
			events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			_, pollErr = unix.Poll(events, 0)
			if pollErr == unix.EINTR {
				return false
			}
			// A FIFO with no writer initially reads EOF. Wait in Go's poller
			// until data or a writer's close, rather than accepting that EOF.
			return pollErr != nil || events[0].Revents != 0
		})
		if err != nil || pollErr != nil {
			return 0, errors.Join(err, pollErr)
		}
		input.ready = true
	}
	return input.File.Read(data)
}
