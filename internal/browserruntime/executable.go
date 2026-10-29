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
	// Opening a FIFO or device can block before its mode can be checked. Reject
	// non-regular paths first, then validate the opened file again below.
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect browser executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("browser path must name a native regular Chromium executable")
	}
	file, err := openExecutable(path)
	if err != nil {
		return fmt.Errorf("open browser executable: %w", err)
	}
	return errors.Join(validateOpenedExecutable(file), file.Close())
}

func validateOpenedExecutable(file *os.File) error {
	const invalid = "browser path must name a native non-setid Chromium executable, not a shell wrapper"
	info, err := file.Stat()
	if err != nil {
		return err
	}
	// The path may have changed after the initial stat. Inspect the descriptor
	// before reading so a substituted FIFO/device cannot wait for header bytes.
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New(invalid)
	}
	var magic [4]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return err
	}
	if !bytes.Equal(magic[:], []byte{0x7f, 'E', 'L', 'F'}) {
		return errors.New(invalid)
	}
	return nil
}
