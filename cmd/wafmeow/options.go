package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
	"github.com/jessevdk/go-flags"
)

// Groups are embedded so the execution path uses the same option values that
// generate help. Only the input-source aliases need normalization after parsing.
type options struct {
	InputOptions   `group:"Input"`
	ModeOptions    `group:"Detection"`
	HTTPOptions    `group:"HTTP requests"`
	LimitOptions   `group:"Limits"`
	OutputOptions  `group:"Output"`
	BrowserOptions `group:"Browser"`
	InfoOptions    `group:"Information"`

	Target       string
	InputFile    string
	EvidenceFile string
}

type InputOptions struct {
	Targets               []string `short:"t" long:"target" value-name:"URL" unquote:"false" description:"One target URL per occurrence; repeat for more; bare hosts use HTTPS"`
	TargetFiles           []string `short:"I" long:"target-file" value-name:"FILE" unquote:"false" description:"Read target URLs, one per line; - reads stdin; ./- is a filename"`
	InputFiles            []string `long:"input" value-name:"FILE" unquote:"false" description:"Equivalent to --target-file; choose one spelling, once"`
	EvidenceFiles         []string `long:"evidence" value-name:"FILE" unquote:"false" description:"Read saved response JSONL offline, with no requests; - reads stdin"`
	EvidenceFormat        string   `long:"evidence-format" value-name:"FORMAT" unquote:"false" description:"Saved response format: native or httpx; requires --evidence"`
	HTTPXResponseEncoding string   `long:"httpx-response-encoding" value-name:"ENCODING" unquote:"false" description:"httpx raw_header/body encoding: text or base64; requires httpx evidence"`
	FingerPrintFile       string   `long:"fingerprints" value-name:"FILE" unquote:"false" description:"Replace the bundled fingerprint catalogue with this JSON file"`
}

type ModeOptions struct {
	FastMode       bool `long:"fast" description:"Use the reduced three-request set (active); full mode uses up to eight before redirects"`
	BaselineOnly   bool `long:"baseline" description:"Send only the normal request, plus allowed redirects; no active probes"`
	ExcludeGeneric bool `long:"no-generic" description:"Skip generic anomaly checks; keep named WAF fingerprint matching"`
}

type HTTPOptions struct {
	Headers          []string      `short:"H" long:"header" value-name:"HEADER" unquote:"false" description:"Name: value; repeatable; CSV-quote the whole field if its value contains commas"`
	RequestTimeout   time.Duration `long:"request-timeout" value-name:"DURATION" description:"HTTP deadline per request, e.g. 5s; live acquisition only"`
	TargetTimeout    time.Duration `long:"target-timeout" value-name:"DURATION" description:"HTTP deadline per target, e.g. 30s; independent of browser"`
	MaxRedirects     int           `long:"max-redirects" value-name:"N" description:"Redirects per HTTP request; 0 follows none"`
	RedirectPolicy   string        `long:"redirect-policy" value-name:"POLICY" unquote:"false" description:"canonical-host (www/non-www), same-origin, none or allowlist"`
	AllowedOrigins   []string      `long:"allow-origin" value-name:"ORIGIN" unquote:"false" description:"Allowed exact HTTP(S) origin, including starting URLs; repeatable"`
	ProbeConcurrency int           `long:"probe-concurrency" value-name:"N" description:"Full-mode active probes in parallel after the normal request (1..8)"`
}

type LimitOptions struct {
	Concurrency            int     `short:"c" long:"concurrency" value-name:"N" description:"Concurrent target workers (1..65536); offline workers also capped by CPU count"`
	MaxConnections         int     `long:"max-connections" value-name:"N" description:"Global in-flight HTTP connections; 0 follows the larger of target and probe concurrency (default 0)"`
	Rate                   float64 `long:"rate" value-name:"RPS" description:"Global HTTP requests per second; 0 disables pacing (default 0)"`
	PerOriginRate          float64 `long:"per-origin-rate" value-name:"RPS" description:"HTTP requests per second per origin; 0 disables pacing (default 0)"`
	MaxRequests            int     `long:"max-requests" value-name:"N" description:"HTTP requests per target, including redirects; live acquisition only"`
	MaxBodyBytes           int64   `long:"max-body-bytes" value-name:"BYTES" description:"Maximum decoded response bytes; also validates saved response bodies"`
	MaxResponseHeaderBytes int64   `long:"max-response-header-bytes" value-name:"BYTES" description:"HTTP response header limit; 0 uses 65536; live acquisition only"`
	MaxTargetEvidenceBytes int64   `long:"max-target-evidence-bytes" value-name:"BYTES" description:"Retained HTTP evidence per target; 0 uses 16777216; excludes browser"`
}

type OutputOptions struct {
	JSONL            bool   `long:"jsonl" description:"Stream result JSONL to stdout; human summary goes to stderr"`
	OutputFile       string `short:"O" long:"output" value-name:"FILE" unquote:"false" description:"Atomic report: .json/.jsonl/.csv select format, otherwise TXT; - is a literal file"`
	Strict           bool   `long:"strict" description:"Exit 2 for incomplete, failed or diagnosed results after report publication"`
	Silent           bool   `long:"silent" description:"Suppress human scan output; requires --output or --jsonl (except --list/--version)"`
	NoColors         bool   `long:"no-colors" description:"Disable ANSI color; also honors NO_COLOR and redirected output"`
	SuppressWarnings bool   `long:"no-warning" description:"Suppress human warnings; retain result state and journal records"`
	Debug            bool   `long:"debug" description:"Write body-free request/evidence diagnostics to stderr after each target"`
	JournalFile      string `long:"diagnostics-journal" value-name:"FILE" unquote:"false" description:"Append and sync body-free result/diagnostic JSONL independently of the report"`
	JournalBatchSize int    `long:"journal-batch-size" value-name:"N" description:"Results per durable sync (1..256); requires --diagnostics-journal; flush within 25ms"`
}

type BrowserOptions struct {
	Browser         string        `long:"browser" value-name:"MODE" unquote:"false" description:"off, navigate or screenshot; installed Linux Chromium; no hard network/resource isolation"`
	BrowserPath     string        `long:"browser-path" value-name:"FILE" unquote:"false" description:"Native Chromium executable; requires browser mode; never downloaded"`
	BrowserTimeout  time.Duration `long:"browser-timeout" value-name:"DURATION" description:"Browser deadline, separate from HTTP; requires browser mode"`
	BrowserSettle   time.Duration `long:"browser-settle" value-name:"DURATION" description:"Browser quiet interval, shorter than its deadline; requires browser mode"`
	BrowserOrigins  []string      `long:"browser-allow-origin" value-name:"ORIGIN" unquote:"false" description:"Extra resource origin, intersected with --allow-origin; repeatable; requires browser mode"`
	SaveScreenshots string        `long:"save-screenshots" value-name:"DIR" unquote:"false" description:"Save sanitized PNGs under a private run directory; requires --browser=screenshot"`
}

type InfoOptions struct {
	ListWAFS bool `long:"list" description:"List the detectable WAF products and exit"`
	Version  bool `long:"version" description:"Print the program version and exit"`
}

func newOptions(config wafmeow.Config) options {
	return options{
		InputOptions: InputOptions{EvidenceFormat: "native", HTTPXResponseEncoding: "text"},
		HTTPOptions: HTTPOptions{
			RequestTimeout: config.RequestTimeout, TargetTimeout: config.TargetTimeout,
			MaxRedirects: config.MaxRedirects, RedirectPolicy: config.RedirectPolicy, ProbeConcurrency: 1,
		},
		LimitOptions: LimitOptions{
			Concurrency: config.Concurrency, MaxBodyBytes: config.MaxBodyBytes,
			MaxResponseHeaderBytes: config.MaxResponseHeaderBytes, MaxTargetEvidenceBytes: config.MaxTargetEvidenceBytes,
			MaxRequests: config.MaxRequests, Rate: config.RequestsPerSecond, PerOriginRate: config.PerOriginRequestsPerSecond,
		},
		OutputOptions:  OutputOptions{JournalBatchSize: 1},
		BrowserOptions: BrowserOptions{Browser: "off", BrowserTimeout: 30 * time.Second, BrowserSettle: 2 * time.Second},
	}
}

func (opts *options) normalizeInputs() error {
	for _, target := range opts.Targets {
		if strings.TrimSpace(target) == "" || strings.ContainsAny(target, "\r\n") {
			return errors.New("--target requires one nonblank URL per occurrence; repeat --target or use --target-file for multiple targets")
		}
	}
	if len(opts.TargetFiles)+len(opts.InputFiles) > 1 {
		return errors.New("specify --target-file (or --input / -I) only once; concatenate multiple lists on stdin")
	}
	if len(opts.EvidenceFiles) > 1 {
		return errors.New("specify --evidence only once")
	}
	for _, source := range []struct {
		name   string
		values []string
		dest   *string
	}{
		{"target-file", opts.TargetFiles, &opts.InputFile},
		{"input", opts.InputFiles, &opts.InputFile},
		{"evidence", opts.EvidenceFiles, &opts.EvidenceFile},
	} {
		if len(source.values) == 1 {
			if source.values[0] == "" {
				return fmt.Errorf("--%s requires a nonempty value", source.name)
			}
			*source.dest = source.values[0]
		}
	}
	opts.Target = strings.Join(opts.Targets, "\n")
	return nil
}

func validateOptionDependencies(opts options, parser *flags.Parser) error {
	switch opts.Browser {
	case "off", "navigate", "screenshot":
	default:
		return fmt.Errorf("unknown browser mode %q; choose off, navigate or screenshot", opts.Browser)
	}
	if parser.FindOptionByLongName("evidence-format").IsSet() && opts.EvidenceFile == "" {
		return errors.New("--evidence-format requires --evidence")
	}
	if parser.FindOptionByLongName("httpx-response-encoding").IsSet() && (opts.EvidenceFile == "" || opts.EvidenceFormat != "httpx") {
		return errors.New("--httpx-response-encoding requires --evidence-format=httpx and --evidence")
	}
	// Informational commands must not discover, open or start Chromium.
	if opts.ListWAFS || opts.Version {
		return nil
	}
	if opts.Browser == "off" {
		for _, name := range []string{"browser-timeout", "browser-settle"} {
			if parser.FindOptionByLongName(name).IsSet() {
				return fmt.Errorf("--%s requires --browser=navigate or --browser=screenshot", name)
			}
		}
	}
	if parser.FindOptionByLongName("journal-batch-size").IsSet() && opts.JournalFile == "" {
		return errors.New("--journal-batch-size requires --diagnostics-journal")
	}
	if opts.ProbeConcurrency > 1 && (opts.FastMode || opts.BaselineOnly) {
		return errors.New("--probe-concurrency above 1 applies only to full mode; omit --fast and --baseline")
	}
	return nil
}
