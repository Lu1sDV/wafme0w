package wafme0w

import (
	"context"
	"io"
	"time"
)

// BrowserConfig selects a fresh local Chromium process per input occurrence.
// It is opt-in and does not provide OS-level network or renderer resource isolation.
// Chromium's sandbox and certificate validation remain enabled. Path names an
// existing native executable; browser discovery belongs to the caller.
type BrowserConfig struct {
	Mode            string
	Path            string
	Timeout         time.Duration
	Settle          time.Duration
	ResourceOrigins []string
	// Sinks receive sanitized bounded content after Chromium has stopped. They
	// must honor cancellation, return, and not retain Content. They may overlap.
	SaveText       func(context.Context, BrowserArtifact) (string, error)
	SaveScreenshot func(context.Context, BrowserArtifact) (string, error)
}

// BrowserArtifact is valid only for the duration of its sink callback.
type BrowserArtifact struct {
	CaptureID  string
	Occurrence uint64
	MIME       string
	SHA256     string
	Content    io.Reader
}

type BrowserAsset struct {
	State string `json:"state"`
	Bytes int    `json:"bytes,omitempty"`
	// AcquiredSHA256 identifies raw acquired bytes; SHA256 identifies a sanitized artifact.
	AcquiredSHA256 string `json:"acquired_sha256,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Saved          string `json:"saved,omitempty"`
	SaveState      string `json:"save_state,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
}

type BrowserLimits struct {
	Timeout    time.Duration `json:"timeout"`
	Settle     time.Duration `json:"settle"`
	Requests   int           `json:"requests"`
	Redirects  int           `json:"redirects"`
	DOMBytes   int           `json:"dom_bytes"`
	ImageBytes int           `json:"image_bytes"`
}

type BrowserReadiness struct {
	Loaded             bool `json:"loaded"`
	DOMQuiet           bool `json:"dom_quiet"`
	NetworkQuiet       bool `json:"network_quiet"`
	VisibleImagesReady bool `json:"visible_images_ready"`
	FontsReady         bool `json:"fonts_ready"`
}

// BrowserReport is separate from classifier evidence and contains no raw DOM or image.
// Metadata is sanitized before result emission. A complete restricted render is
// not proof of an unrestricted appearance, WAF enforcement, or WAF absence.
type BrowserReport struct {
	ID                string           `json:"id"`
	Occurrence        uint64           `json:"occurrence"`
	Mode              string           `json:"mode"`
	State             string           `json:"state"`
	Reason            string           `json:"reason,omitempty"`
	Error             string           `json:"error,omitempty"`
	QueuedAt          time.Time        `json:"queued_at"`
	StartedAt         time.Time        `json:"started_at,omitempty"`
	FinishedAt        time.Time        `json:"finished_at,omitempty"`
	URL               string           `json:"url"`
	FinalURL          string           `json:"final_url,omitempty"`
	Status            int              `json:"status,omitempty"`
	Headers           []Header         `json:"headers,omitempty"`
	RequestID         string           `json:"request_id,omitempty"`
	LoaderID          string           `json:"loader_id,omitempty"`
	FrameID           string           `json:"frame_id,omitempty"`
	ConnectionID      float64          `json:"connection_id,omitempty"`
	Protocol          string           `json:"protocol,omitempty"`
	Version           string           `json:"version,omitempty"`
	RedirectChain     []string         `json:"redirect_chain,omitempty"`
	FromCache         bool             `json:"from_cache,omitempty"`
	FromServiceWorker bool             `json:"from_service_worker,omitempty"`
	Width             int              `json:"width"`
	Height            int              `json:"height"`
	AdmittedRequests  int              `json:"admitted_requests"`
	DeniedRequests    int              `json:"denied_requests"`
	Limits            BrowserLimits    `json:"limits"`
	Readiness         BrowserReadiness `json:"readiness"`
	DOM               BrowserAsset     `json:"dom"`
	Screenshot        BrowserAsset     `json:"screenshot"`
	Limitations       []string         `json:"limitations"`
}

// Failed reports optional capture/export failure, never deterministic scan truth.
func (r *BrowserReport) Failed() bool {
	return r != nil && (r.State == "failed" || r.State == "partial" || r.State == "cancelled" || r.DOM.SaveState == "failed" || r.Screenshot.SaveState == "failed")
}

const (
	browserMaxRequests = 40
	browserMaxDOM      = 1 << 20
	browserMaxImage    = 2 << 20
	browserWidth       = 1440
	browserHeight      = 900
)

type browserRect struct{ X, Y, Width, Height float64 }

type browserCapture struct {
	report     BrowserReport
	dom        string
	image      []byte
	secrets    []browserRect
	geometryOK bool
}
