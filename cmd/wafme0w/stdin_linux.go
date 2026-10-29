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
	if file, err := os.Open("/dev/stdin"); err == nil {
		return file, nil
	}
	// An inherited descriptor remains readable after a UID/permission change,
	// even when reopening its inode is forbidden. Dup preserves that access.
	// Its shared nonblocking flag is restored after the pollable reader closes.
	sourceFD := int(os.Stdin.Fd())
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
		File:     os.NewFile(uintptr(fd), os.Stdin.Name()),
		sourceFD: sourceFD, nonblocking: flags&unix.O_NONBLOCK != 0,
	}, nil
}

type inheritedStdin struct {
	*os.File
	sourceFD    int
	nonblocking bool
}

func (input *inheritedStdin) Close() error {
	err := input.File.Close()
	return errors.Join(err, unix.SetNonblock(input.sourceFD, input.nonblocking))
}
