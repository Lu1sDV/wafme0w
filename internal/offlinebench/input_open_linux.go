package offlinebench

import (
	"os"

	"golang.org/x/sys/unix"
)

// Nonblocking open lets descriptor validation reject FIFOs without waiting for
// a writer, even if a regular path was replaced immediately before opening.
func openInputFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}
