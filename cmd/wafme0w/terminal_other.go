//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package main

import "os"

func isTerminal(*os.File) bool { return false }
