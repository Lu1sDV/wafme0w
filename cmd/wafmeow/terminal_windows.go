package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func isTerminal(file *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil && mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
}
