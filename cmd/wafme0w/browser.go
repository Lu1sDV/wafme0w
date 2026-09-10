package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/Lu1sDV/wafme0w/internal/atomicfile"
	"github.com/Lu1sDV/wafme0w/internal/browserruntime"
	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func validateBrowserOptions(opts options) error {
	switch opts.Browser {
	case "off":
		if opts.SaveScreenshots != "" || len(opts.BrowserOrigins) != 0 {
			return errors.New("browser saving and resource origins require --browser=navigate or --browser=screenshot")
		}
		return nil
	case "navigate", "screenshot":
	default:
		return fmt.Errorf("unknown browser mode %q", opts.Browser)
	}
	if opts.EvidenceFile != "" {
		return errors.New("--evidence cannot be combined with browser acquisition")
	}
	if opts.BrowserTimeout <= 0 || opts.BrowserSettle <= 0 || opts.BrowserSettle >= opts.BrowserTimeout {
		return errors.New("browser timeout and settle must be positive, with settle smaller than timeout")
	}
	if opts.SaveScreenshots != "" && opts.Browser != "screenshot" {
		return errors.New("--save-screenshots requires --browser=screenshot")
	}
	if opts.SaveScreenshots != "" {
		if _, err := inspectArtifactRoot(opts.SaveScreenshots); err != nil {
			return err
		}
	}
	return nil
}

func configureBrowser(opts options) (*wafme0w.BrowserConfig, error) {
	if opts.Browser == "off" {
		return nil, nil
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("local browser capture currently supports Linux only")
	}
	path, err := resolveBrowserPath(opts.BrowserPath)
	if err != nil {
		return nil, err
	}
	return &wafme0w.BrowserConfig{Mode: opts.Browser, Path: path, Timeout: opts.BrowserTimeout,
		Settle: opts.BrowserSettle, ResourceOrigins: opts.BrowserOrigins}, nil
}

func resolveBrowserPath(path string) (string, error) {
	if path != "" {
		return nativeBrowserPath(path)
	}
	// Prefer native package binaries, not distribution wrappers that inherit flags.
	candidates := []string{
		"/usr/lib64/chromium-browser/chromium-browser",
		"/usr/lib/chromium/chromium", "/usr/lib/chromium-browser/chromium-browser",
		"/opt/google/chrome/chrome", "/opt/google/chrome-beta/chrome",
	}
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if candidate, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, candidate)
		}
	}
	for _, candidate := range candidates {
		if resolved, err := nativeBrowserPath(candidate); err == nil {
			return resolved, nil
		}
	}
	return "", errors.New("no installed native Chromium executable found; set --browser-path (shell wrappers and downloads are not used)")
}

func nativeBrowserPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("resolve browser executable: %w", err)
	}
	if err := browserruntime.ValidateExecutable(absolute); err != nil {
		return "", err
	}
	return absolute, nil
}

// Inspect every existing component without creating anything during validation.
func inspectArtifactRoot(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect artifact directory: %w", err)
		}
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return "", fmt.Errorf("artifact path component %q must be a directory, not a symlink", current)
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return absolute, nil
}

type browserArtifactDirectory struct {
	path string
	file *os.File
}

type browserArtifacts struct {
	imageRoot   string
	mu          sync.Mutex
	directories map[string]*browserArtifactDirectory
}

func newBrowserArtifacts(imageRoot string) *browserArtifacts {
	return &browserArtifacts{imageRoot: imageRoot, directories: make(map[string]*browserArtifactDirectory)}
}

func (artifacts *browserArtifacts) saveScreenshot(ctx context.Context, artifact wafme0w.BrowserArtifact) (string, error) {
	if artifact.MIME != "image/png" {
		return "", errors.New("unexpected screenshot artifact MIME type")
	}
	return artifacts.save(ctx, artifacts.imageRoot, ".png", artifact.Content)
}

func (artifacts *browserArtifacts) directory(root string) (*browserArtifactDirectory, error) {
	artifacts.mu.Lock()
	defer artifacts.mu.Unlock()
	absolute, err := inspectArtifactRoot(root)
	if err != nil {
		return nil, err
	}
	if directory := artifacts.directories[absolute]; directory != nil {
		return directory, nil
	}
	// The local runtime is Linux-only. Pin publication to open directory handles,
	// so renaming/replacing a parent cannot redirect atomicfile's temporary files.
	if runtime.GOOS != "linux" {
		return nil, errors.New("private browser artifact publication requires Linux")
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, err
	}
	if _, err := inspectArtifactRoot(absolute); err != nil {
		return nil, err
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return nil, err
	}
	parent, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	opened, err := parent.Stat()
	if err == nil && !os.SameFile(info, opened) {
		err = errors.New("artifact directory changed while opening")
	}
	var generated string
	if err == nil {
		generated, err = os.MkdirTemp(fmt.Sprintf("/proc/self/fd/%d", parent.Fd()), "wafme0w-")
	}
	var created os.FileInfo
	if err == nil {
		created, err = os.Lstat(generated)
		if err == nil && (!created.IsDir() || created.Mode().Perm()&0077 != 0) {
			err = errors.New("generated artifact directory is not private")
		}
	}
	var file *os.File
	if err == nil {
		file, err = os.Open(generated)
		if err == nil {
			var opened os.FileInfo
			opened, err = file.Stat()
			if err == nil && !os.SameFile(created, opened) {
				err = errors.New("generated artifact directory changed while opening")
			}
		}
	}
	err = errors.Join(err, parent.Close())
	if err != nil {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		return nil, err
	}
	directory := &browserArtifactDirectory{path: filepath.Join(absolute, filepath.Base(generated)), file: file}
	artifacts.directories[absolute] = directory
	return directory, nil
}

func (artifacts *browserArtifacts) save(ctx context.Context, root, extension string, content io.Reader) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if root == "" || content == nil {
		return "", errors.New("browser artifact destination and content are required")
	}
	directory, err := artifacts.directory(root)
	if err != nil {
		return "", fmt.Errorf("prepare browser artifact directory: %w", err)
	}
	name := rand.Text() + extension
	path := filepath.Join(directory.path, name)
	anchored := fmt.Sprintf("/proc/self/fd/%d/%s", directory.file.Fd(), name)
	err = atomicfile.Write(anchored, func(writer io.Writer) error {
		_, err := io.Copy(writer, browserArtifactReader{ctx: ctx, reader: content})
		return errors.Join(err, ctx.Err())
	})
	if err == nil {
		// Never report a stale path if the caller's directory was replaced/moved.
		var reported, retained os.FileInfo
		reported, err = os.Stat(directory.path)
		if err == nil {
			retained, err = directory.file.Stat()
		}
		if err == nil && !os.SameFile(reported, retained) {
			err = errors.New("browser artifact directory moved during publication")
		}
	}
	if err != nil {
		return "", fmt.Errorf("save browser artifact: %w", err)
	}
	return path, nil
}

type browserArtifactReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader browserArtifactReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func (artifacts *browserArtifacts) close() error {
	var err error
	for _, directory := range artifacts.directories {
		err = errors.Join(err, directory.file.Close())
	}
	return err
}
