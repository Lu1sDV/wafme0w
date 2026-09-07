package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Lu1sDV/wafme0w/internal/atomicfile"
	"github.com/Lu1sDV/wafme0w/internal/httpmeta"
	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
	"github.com/jessevdk/go-flags"
)

//go:embed resources/waf-fingerprints.json
var embeddedFingerPrints []byte

type options struct {
	Target           string        `short:"t" long:"target" description:"HTTP(S) target URL (active unless --baseline)"`
	InputFile        string        `short:"I" long:"input" description:"File with one target URL per line"`
	EvidenceFile     string        `long:"evidence" description:"Classify saved capture JSONL with zero network access; - reads stdin"`
	OutputFile       string        `short:"O" long:"output" description:"Atomic report file: JSON, JSONL, CSV or TXT by extension"`
	JournalFile      string        `long:"diagnostics-journal" description:"Append and sync body-free result/diagnostic JSONL independently of the report"`
	Debug            bool          `long:"debug" description:"Print body-free per-request evidence and error details to stderr after each target"`
	Headers          []string      `short:"H" long:"header" description:"Comma-separated Name: value headers; override defaults, repeatable; CSV-quote fields containing commas"`
	FingerPrintFile  string        `long:"fingerprints" description:"File containing the JSON-formatted fingerprints"`
	Concurrency      int           `short:"c" long:"concurrency" description:"Number of concurrent target workers"`
	MaxBodyBytes     int64         `long:"max-body-bytes" description:"Maximum decoded bytes retained per response"`
	RequestTimeout   time.Duration `long:"request-timeout" description:"Per-request timeout, e.g. 5s"`
	TargetTimeout    time.Duration `long:"target-timeout" description:"Total per-target timeout, e.g. 30s"`
	MaxRequests      int           `long:"max-requests" description:"Per-target outbound request budget, including redirects"`
	MaxConnections   int           `long:"max-connections" description:"Global maximum in-flight outbound requests"`
	Rate             float64       `long:"rate" description:"Global outbound requests per second; 0 disables pacing"`
	PerOriginRate    float64       `long:"per-origin-rate" description:"Outbound requests per second per origin; 0 disables pacing"`
	MaxRedirects     int           `long:"max-redirects" description:"Maximum redirects per request; 0 follows none"`
	RedirectPolicy   string        `long:"redirect-policy" description:"Redirect policy: canonical-host (www/non-www), same-origin, none or allowlist"`
	AllowedOrigins   []string      `long:"allow-origin" description:"Allowed exact HTTP(S) origin; repeat for multiple origins"`
	FastMode         bool          `long:"fast" description:"Use the reduced ACTIVE request set; not passive"`
	BaselineOnly     bool          `long:"baseline" description:"Send only the normal request; no active probe requests"`
	ExcludeGeneric   bool          `long:"no-generic" description:"Exclude generic anomaly checks"`
	JSONL            bool          `long:"jsonl" description:"Stream only result JSONL to stdout; human summary goes to stderr"`
	Strict           bool          `long:"strict" description:"Exit 2 for failed, incomplete or diagnosed targets after report publication"`
	Version          bool          `long:"version" description:"Print the program version and exit"`
	ListWAFS         bool          `long:"list" description:"List all detectable WAFs"`
	Silent           bool          `long:"silent" description:"Suppress human scan output; requires --output or --jsonl"`
	NoColors         bool          `long:"no-colors" description:"Disable ANSI color (also honors NO_COLOR and redirected output)"`
	SuppressWarnings bool          `long:"no-warning" description:"Suppress human diagnostics, not result state or journal records"`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runContext(ctx, args, os.Stdin, hasStdin(), os.Stdout, os.Stderr)
}

func runContext(ctx context.Context, args []string, stdin io.Reader, piped bool, stdout, stderr io.Writer) int {
	config := wafme0w.DefaultConfig()
	opts := options{
		Concurrency: config.Concurrency, MaxBodyBytes: config.MaxBodyBytes,
		RequestTimeout: config.RequestTimeout, TargetTimeout: config.TargetTimeout,
		MaxRequests: config.MaxRequests, MaxConnections: config.MaxConnections,
		Rate: config.RequestsPerSecond, PerOriginRate: config.PerOriginRequestsPerSecond,
		MaxRedirects: config.MaxRedirects, RedirectPolicy: config.RedirectPolicy,
	}
	parser := flags.NewParser(&opts, flags.HelpFlag)
	positional, err := parser.ParseArgs(args)
	if err != nil {
		if flagErr, ok := err.(*flags.Error); ok && flagErr.Type == flags.ErrHelp {
			parser.WriteHelp(stdout)
			return 0
		}
		fmt.Fprintln(stderr, terminalText(err.Error()))
		return 1
	}
	console := colorizer(stdout, opts.NoColors)
	diagnostics := colorizer(stderr, opts.NoColors)
	fail := func(err error) int {
		fmt.Fprintf(stderr, "%s %s\n", diagnostics.Bold(diagnostics.Red("ERROR")), terminalText(err.Error()))
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return 130
		}
		return 1
	}
	if len(positional) != 0 {
		return fail(fmt.Errorf("unexpected positional arguments: %q", positional))
	}
	for _, name := range []string{"target", "input", "evidence", "output", "diagnostics-journal", "fingerprints"} {
		option := parser.FindOptionByLongName(name)
		if option.IsSet() && option.Value().(string) == "" {
			return fail(fmt.Errorf("--%s requires a nonempty value", name))
		}
	}
	if len(args) == 0 && !piped {
		parser.WriteHelp(stdout)
		return 0
	}
	if err := validateOptions(opts); err != nil {
		return fail(err)
	}
	config.Headers, err = parseHeaders(opts.Headers)
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if opts.Version {
		if _, err := fmt.Fprintf(stdout, "wafme0w %s\n", terminalText(wafme0w.Version())); err != nil {
			return fail(err)
		}
		return 0
	}
	engine, err := loadEngine(opts.FingerPrintFile)
	if err != nil {
		return fail(err)
	}
	if opts.ListWAFS {
		if !opts.Silent {
			if err := printBanner(stdout, console); err != nil {
				return fail(err)
			}
		}
		if err := printProducts(stdout, engine.Products(), console); err != nil {
			return fail(err)
		}
		return 0
	}
	if err := checkFileCollisions(opts, stdin, piped, stdout, stderr); err != nil {
		return fail(err)
	}
	input, closeInput, err := resolveInput(opts, stdin, piped)
	if err != nil {
		return fail(err)
	}
	defer closeInput()
	stopInput := context.AfterFunc(ctx, closeInput)
	defer stopInput()
	config.CancelInput = closeInput
	config.Concurrency, config.MaxBodyBytes = opts.Concurrency, opts.MaxBodyBytes
	config.FastMode, config.BaselineOnly, config.ExcludeGeneric = opts.FastMode, opts.BaselineOnly, opts.ExcludeGeneric
	config.RequestTimeout, config.TargetTimeout = opts.RequestTimeout, opts.TargetTimeout
	config.MaxRequests, config.MaxConnections = opts.MaxRequests, opts.MaxConnections
	config.RequestsPerSecond, config.PerOriginRequestsPerSecond = opts.Rate, opts.PerOriginRate
	config.MaxRedirects, config.RedirectPolicy, config.AllowedOrigins = opts.MaxRedirects, opts.RedirectPolicy, opts.AllowedOrigins

	journal, err := openJournal(opts.JournalFile)
	if err != nil {
		return fail(err)
	}
	finish := func(runErr error) int {
		if runErr != nil {
			closeInput()
			runErr = errors.Join(runErr, journal.diagnostic("run_error", runErr.Error()))
		}
		runErr = errors.Join(runErr, journal.close())
		if runErr != nil {
			return fail(runErr)
		}
		return 0
	}
	if !opts.Silent && !opts.JSONL {
		if err := printBanner(stdout, console); err != nil {
			return finish(err)
		}
	}
	var counts resultCounts
	execute := func(writer io.Writer) error {
		var output, stream *wafme0w.ResultWriter
		if writer != nil {
			format := strings.ToLower(filepath.Ext(opts.OutputFile))
			if format != ".json" && format != ".jsonl" && format != ".csv" {
				format = "txt"
			}
			var err error
			output, err = wafme0w.NewResultWriter(writer, format)
			if err != nil {
				return err
			}
		}
		if opts.JSONL {
			var err error
			stream, err = wafme0w.NewResultWriter(stdout, "jsonl")
			if err != nil {
				return err
			}
		}
		runner := wafme0w.Run
		if opts.EvidenceFile != "" {
			runner = wafme0w.RunCaptured
		}
		err := runner(ctx, engine, input, config, func(result wafme0w.Result) error {
			// Persist recovery evidence before touching fallible final-report sinks.
			if err := journal.result(result); err != nil {
				return err
			}
			if opts.Debug {
				if err := printDebug(stderr, result); err != nil {
					return err
				}
			}
			counts.add(result)
			if output != nil {
				if err := output.Write(result); err != nil {
					return err
				}
			}
			if stream != nil {
				if err := stream.Write(result); err != nil {
					return err
				}
			} else if !opts.Silent {
				return printResult(stdout, stderr, result, opts.SuppressWarnings, console)
			}
			return nil
		})
		if err == nil && output != nil {
			err = output.Close()
		}
		if err == nil && stream != nil {
			err = stream.Close()
		}
		return errors.Join(err, ctx.Err())
	}
	if opts.OutputFile != "" {
		err = atomicfile.Write(opts.OutputFile, execute)
	} else {
		err = execute(nil)
	}
	if err != nil {
		if !opts.Silent {
			err = errors.Join(err, printSummary(stderr, counts, false, diagnostics))
		}
		return finish(err)
	}
	if !opts.Silent {
		if err := printSummary(stderr, counts, true, diagnostics); err != nil {
			return finish(err)
		}
	}
	if code := finish(nil); code != 0 {
		return code
	}
	if opts.Strict && counts.StrictFailure {
		return 2
	}
	return 0
}

func validateOptions(opts options) error {
	if opts.Concurrency <= 0 || opts.MaxBodyBytes <= 0 || opts.MaxRequests <= 0 || opts.MaxConnections <= 0 {
		return errors.New("concurrency, decoded body limit, request budget and connection limit must be positive")
	}
	if opts.RequestTimeout <= 0 || opts.TargetTimeout <= 0 {
		return errors.New("request and target timeouts must be positive")
	}
	if opts.MaxRedirects < 0 {
		return errors.New("maximum redirects must not be negative")
	}
	for _, rate := range []float64{opts.Rate, opts.PerOriginRate} {
		if math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0 {
			return errors.New("request rates must be finite and nonnegative")
		}
	}
	switch opts.RedirectPolicy {
	case "canonical-host", "same-origin", "none":
	case "allowlist":
		if len(opts.AllowedOrigins) == 0 {
			return errors.New("allowlist redirect policy requires --allow-origin")
		}
	default:
		return fmt.Errorf("unknown redirect policy %q", opts.RedirectPolicy)
	}
	if opts.Target != "" && strings.TrimSpace(opts.Target) == "" {
		return errors.New("--target must not be blank")
	}
	if opts.Target != "" && opts.InputFile != "" {
		return errors.New("--target and --input are mutually exclusive")
	}
	if opts.EvidenceFile != "" && (opts.Target != "" || opts.InputFile != "" || opts.FastMode || opts.BaselineOnly || len(opts.Headers) != 0) {
		return errors.New("--evidence is exclusive with --target, --input, --fast, --baseline and --header")
	}
	if opts.FastMode && opts.BaselineOnly {
		return errors.New("--fast is active and cannot be combined with --baseline")
	}
	if opts.ListWAFS || opts.Version {
		if opts.ListWAFS && opts.Version || opts.JSONL || opts.Target != "" || opts.InputFile != "" || opts.EvidenceFile != "" || opts.OutputFile != "" || opts.JournalFile != "" || opts.FastMode || opts.BaselineOnly {
			return errors.New("--list and --version cannot be combined with scanning or output options")
		}
	}
	if opts.Silent && opts.OutputFile == "" && !opts.JSONL && !opts.ListWAFS && !opts.Version {
		return errors.New("silent mode requires --output or --jsonl")
	}
	return nil
}

func parseHeaders(values []string) ([]wafme0w.Header, error) {
	var headers []wafme0w.Header
	for _, value := range values {
		if value == "" || strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("--header requires a nonempty, single-line header list")
		}
		reader := csv.NewReader(strings.NewReader(value))
		reader.TrimLeadingSpace = true
		fields, err := reader.Read()
		if err != nil {
			return nil, errors.New("--header requires CSV-quoted fields when values contain commas or quotes")
		}
		for _, field := range fields {
			name, content, ok := strings.Cut(field, ":")
			name, content = strings.Trim(name, " \t"), strings.Trim(content, " \t")
			if !ok || !httpmeta.ValidHeaderName(name) || !httpmeta.ValidHeaderValue(content) {
				return nil, errors.New("--header requires valid Name: value entries")
			}
			headers = append(headers, wafme0w.Header{Name: name, Value: content})
		}
	}
	return headers, nil
}

func loadEngine(path string) (*wafme0w.Engine, error) {
	var reader io.Reader = bytes.NewReader(embeddedFingerPrints)
	var file *os.File
	if path != "" {
		var err error
		file, err = os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open fingerprints: %w", err)
		}
		reader = file
	}
	catalogue, err := wafme0w.ReadCatalogue(reader)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	if err != nil {
		return nil, err
	}
	return wafme0w.Compile(catalogue)
}

func resolveInput(opts options, stdin io.Reader, piped bool) (io.Reader, func(), error) {
	path := opts.InputFile
	if opts.EvidenceFile != "" && opts.EvidenceFile != "-" {
		path = opts.EvidenceFile
	}
	var input io.Reader
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("open input: %w", err)
		}
		input = file
	} else if opts.EvidenceFile == "-" {
		if stdin == nil {
			return nil, nil, errors.New("--evidence - requires stdin")
		}
		input = stdin
	} else if strings.TrimSpace(opts.Target) != "" {
		input = strings.NewReader(opts.Target)
	} else if piped && stdin != nil {
		input = stdin
	} else {
		return nil, nil, errors.New("no targets provided")
	}
	var once sync.Once
	closeInput := func() {
		once.Do(func() {
			if closer, ok := input.(io.Closer); ok {
				_ = closer.Close()
			}
		})
	}
	return input, closeInput, nil
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	return err == nil && (stat.Mode()&os.ModeCharDevice == 0 || stat.Mode()&os.ModeNamedPipe != 0)
}
