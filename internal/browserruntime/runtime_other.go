//go:build !linux

package browserruntime

import (
	"context"
	"errors"
)

type Options struct{ BrowserPath string }
type Runtime struct{ *Pipe }

func Start(context.Context, Options) (*Runtime, error) {
	return nil, errors.New("local browser capture currently supports Linux only")
}
func (*Runtime) Close() error       { return nil }
func (*Runtime) Diagnostic() string { return "local browser capture is unsupported on this OS" }
