package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// cancellableStdin makes inherited pipes pollable so Close can wake a Read.
func cancellableStdin() (io.ReadCloser, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		return os.Stdin, err
	}
	// A nonblocking inherited FIFO may not have a writer yet. Open atomically
	// nonblocking, then use the same data/EOF readiness gate as named inputs.
	if file, err := os.OpenFile("/dev/stdin", os.O_RDONLY|unix.O_NONBLOCK, 0); err == nil {
		return &namedPipeInput{File: file}, nil
	}
	// An inherited descriptor remains readable after a UID/permission change,
	// even when reopening its inode is forbidden. Dup preserves that access.
	// Its shared nonblocking flag is restored after the pollable reader closes.
	raw, err := os.Stdin.SyscallConn()
	if err != nil {
		return nil, err
	}
	var sourceFD int
	// Unlike Fd, Control does not change the source's nonblocking mode.
	if err := raw.Control(func(fd uintptr) { sourceFD = int(fd) }); err != nil {
		return nil, err
	}
	flags, err := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	fd, err := unix.FcntlInt(uintptr(sourceFD), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return &inheritedStdin{
		namedPipeInput: namedPipeInput{File: os.NewFile(uintptr(fd), os.Stdin.Name())},
		sourceFD:       sourceFD, nonblocking: flags&unix.O_NONBLOCK != 0,
	}, nil
}

type inheritedStdin struct {
	namedPipeInput
	sourceFD    int
	nonblocking bool
}

func (input *inheritedStdin) Close() error {
	err := input.File.Close()
	return errors.Join(err, unix.SetNonblock(input.sourceFD, input.nonblocking))
}
