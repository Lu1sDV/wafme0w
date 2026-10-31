//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

func isTerminal(file *os.File) bool {
	_, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	return err == nil
}

func terminalColumns(file *os.File) int {
	columns, _ := terminalSize(file)
	return columns
}

func terminalSize(file *os.File) (columns, rows int) {
	size, err := unix.IoctlGetWinsize(int(file.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		return 0, 0
	}
	return int(size.Col), int(size.Row)
}
