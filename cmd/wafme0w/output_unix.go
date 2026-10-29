//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// cancellableOutput owns only pipe duplicates, never the inherited descriptor.
func cancellableOutput(ctx context.Context, source *os.File) (io.Writer, func() error, error) {
	info, err := source.Stat()
	if err != nil {
		return nil, nil, err
	}
	if info.Mode()&os.ModeNamedPipe == 0 {
		return source, func() error { return nil }, nil
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nil, err
	}
	var sourceFD int
	// Unlike Fd, Control preserves an inherited nonblocking flag.
	if err := raw.Control(func(fd uintptr) { sourceFD = int(fd) }); err != nil {
		return nil, nil, err
	}
	var file *os.File
	restore := func() error { return nil }
	if runtime.GOOS == "linux" {
		// Reopening gives this process independent file-status flags.
		file, _ = os.OpenFile(fmt.Sprintf("/dev/fd/%d", sourceFD), os.O_WRONLY|unix.O_NONBLOCK, 0)
	}
	if file == nil {
		flags, err := unix.FcntlInt(uintptr(sourceFD), unix.F_GETFL, 0)
		if err != nil {
			return nil, nil, err
		}
		fd, err := unix.FcntlInt(uintptr(sourceFD), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			return nil, nil, err
		}
		if err := unix.SetNonblock(fd, true); err != nil {
			_ = unix.Close(fd)
			return nil, nil, err
		}
		file = os.NewFile(uintptr(fd), source.Name())
		// As with stdin's fallback, shared flags require exclusive CLI use.
		restore = func() error { return unix.SetNonblock(sourceFD, flags&unix.O_NONBLOCK != 0) }
	}
	closed := make(chan struct{})
	var closeErr error
	stop := context.AfterFunc(ctx, func() {
		closeErr = file.Close()
		close(closed)
	})
	release := func() error {
		if stop() {
			closeErr = file.Close()
		} else {
			<-closed
		}
		return errors.Join(closeErr, restore())
	}
	// Hide Fd: terminal detection must not turn a pollable pipe blocking again.
	return struct{ io.Writer }{file}, release, nil
}
