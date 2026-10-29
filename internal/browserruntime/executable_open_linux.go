package browserruntime

import (
	"os"

	"golang.org/x/sys/unix"
)

func openExecutable(path string) (*os.File, error) {
	// A regular path can be replaced after preflight. Avoid a blocking open if
	// it becomes a FIFO; the caller checks the descriptor before reading it.
	return os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
}
