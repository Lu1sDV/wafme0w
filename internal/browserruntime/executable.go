package browserruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ValidateExecutable rejects wrappers and setid executables before input acquisition.
// The current local runtime supports native Linux Chromium only.
func ValidateExecutable(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("browser path must be absolute")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open browser executable: %w", err)
	}
	var magic [4]byte
	_, readErr := io.ReadFull(file, magic[:])
	info, statErr := file.Stat()
	closeErr := file.Close()
	if err := errors.Join(readErr, statErr, closeErr); err != nil {
		return err
	}
	if !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("browser path must name a native non-setid Chromium executable, not a shell wrapper")
	}
	return nil
}
