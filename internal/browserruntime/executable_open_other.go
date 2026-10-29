//go:build !linux

package browserruntime

import "os"

func openExecutable(path string) (*os.File, error) {
	return os.Open(path)
}
