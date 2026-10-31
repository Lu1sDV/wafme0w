package main

import (
	"os"

	"golang.org/x/sys/windows"
)

func isTerminal(file *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(file.Fd()), &mode) == nil && mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0
}

func terminalColumns(file *os.File) int {
	columns, _ := terminalSize(file)
	return columns
}

func terminalSize(file *os.File) (columns, rows int) {
	var info windows.ConsoleScreenBufferInfo
	if err := windows.GetConsoleScreenBufferInfo(windows.Handle(file.Fd()), &info); err != nil {
		return 0, 0
	}
	return int(info.Window.Right-info.Window.Left) + 1, int(info.Window.Bottom-info.Window.Top) + 1
}
