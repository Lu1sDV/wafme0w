package main

import (
	"bytes"
	_ "embed"
	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
	"github.com/jessevdk/go-flags"
	"github.com/logrusorgru/aurora/v4"
	"os"
	"strings"
)

//go:embed resources/waf-fingerprints.json
var embeddedFingerPrints []byte

func main() {
	opts := wafme0w.NewOptions()

	args := os.Args

	_, err := flags.ParseArgs(opts, args)
	if err != nil {
		os.Exit(0)
	}

	if hasStdin() {
		opts.StdIn = true
		opts.Inputs = os.Stdin
	}

	if !opts.StdIn && len(args) < 2 {
		args = []string{"--help"}
	}

	au := aurora.New(aurora.WithColors(!opts.NoColors))
	if !opts.Silent {
		wafme0w.PrintBanner()
	}

	if opts.Silent && opts.OutputFile == "" {
		wafme0w.PrintError("You must provide a valid output file when Silent mode is enabled", au)
		os.Exit(1)
	}

	//check if target input has been provided
	if opts.InputFile == "" && opts.Target == "" && !opts.StdIn && !opts.ListWAFS {
		wafme0w.PrintError("No targets provided", au)
		os.Exit(1)
	}

	//parse inputs if provided by command line arguments
	if !opts.StdIn {
		if opts.Target != "" {
			opts.Inputs = strings.NewReader(opts.Target)
		}
		if opts.InputFile != "" {
			//input file shadows target option
			file, err := os.Open(opts.InputFile)
			if err != nil {
				errText := "error reading input file: " + err.Error()
				wafme0w.PrintError(errText, au)
			}
			opts.Inputs = file
		}
	}
	fingerPrints, err := readFingerPrints(opts.FingerPrintFile)
	if err != nil {
		errText := "Error reading fingerprints: " + err.Error()
		wafme0w.PrintError(errText, au)
	}
	opts.FingerPrints = bytes.NewReader(fingerPrints)

	runner := wafme0w.NewRunner(opts)
	runner.Aurora = au

	if opts.ListWAFS {
		wafs, err := runner.GetAllWAFs()
		if err != nil {
			wafme0w.PrintError("Error displaying firewalls", au)
			os.Exit(1)
		}
		wafme0w.PrintAllWafs(wafs, au)
		os.Exit(0)
	}

	_, err = runner.Scan()
	if err != nil {
		errorString := "Scan error: " + err.Error()
		wafme0w.PrintError(errorString, au)
		os.Exit(1)
	}
}

func hasStdin() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	isPipedFromChrDev := (stat.Mode() & os.ModeCharDevice) == 0
	isPipedFromFIFO := (stat.Mode() & os.ModeNamedPipe) != 0

	return isPipedFromChrDev || isPipedFromFIFO
}

func readFingerPrints(fingerPrintsFile string) ([]byte, error) {
	if fingerPrintsFile == "" {
		return embeddedFingerPrints, nil
	}

	dat, err := os.ReadFile(fingerPrintsFile)
	if err != nil {
		return nil, err
	}
	return dat, nil
}
