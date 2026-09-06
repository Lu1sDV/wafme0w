package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Lu1sDV/wafme0w/internal/offlinebench"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("offlinebench", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	worker := flags.String("worker", "", "internal worker mode")
	corpusPath := flags.String("corpus", "tools/offlinebench/testdata/corpus.json", "offline corpus manifest")
	bodiesDir := flags.String("bodies", "tools/offlinebench/testdata/bodies", "content-addressed body directory")
	catalogue := flags.String("catalogue", "cmd/wafme0w/resources/waf-fingerprints.json", "wafme0w fingerprint catalogue")
	coverageContract := flags.String("coverage-contract", "tools/offlinebench/testdata/coverage-contract.json", "reviewed fixture and full-catalogue rule identity inventory")
	python := flags.String("wafw00f-python", os.Getenv("WAFW00F_PYTHON"), "Python executable in a wafw00f virtual environment")
	adapter := flags.String("wafw00f-adapter", "tools/offlinebench/wafw00f_adapter.py", "wafw00f replay adapter")
	outputDir := flags.String("output", "offlinebench-results", "new-run destination (must be absent or empty; never overwrites a generation)")
	verifyRun := flags.String("verify-run", "", "verify a complete generation and its artifact hashes, then print its report (no workers)")
	iterations := flags.Int("iterations", 100, "warm classification iterations per case and block")
	blocks := flags.Int("blocks", 4, "alternating process blocks")
	minimumCoverage := flags.Float64("min-coverage", 1, "minimum processing rate for cases expected complete (raw completion is reported separately)")
	minimumAccuracy := flags.Float64("min-accuracy", 1, "minimum exact accuracy across expected-complete labelled cases")
	timeout := flags.Duration("timeout", 5*time.Minute, "whole-run timeout")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if *verifyRun != "" {
		exclusive := true
		flags.Visit(func(value *flag.Flag) {
			if value.Name != "verify-run" {
				exclusive = false
			}
		})
		if !exclusive {
			fmt.Fprintln(os.Stderr, "-verify-run cannot be combined with other flags")
			return 2
		}
		if _, err := offlinebench.VerifyArtifacts(*verifyRun); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		report, err := os.ReadFile(filepath.Join(*verifyRun, "report.txt"))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if _, err := os.Stdout.Write(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if *worker != "" {
		if *worker != "wafme0w" {
			fmt.Fprintf(os.Stderr, "unsupported worker %q\n", *worker)
			return 2
		}
		if err := offlinebench.RunWafme0wWorker(os.Stdin, os.Stdout, *catalogue); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	}
	if *python == "" {
		fmt.Fprintln(os.Stderr, "-wafw00f-python or WAFW00F_PYTHON is required")
		return 2
	}

	var err error
	for _, path := range []*string{corpusPath, bodiesDir, catalogue, coverageContract, python, adapter, outputDir} {
		*path, err = filepath.Abs(*path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	bubblewrap, err := exec.LookPath("bwrap")
	if err != nil {
		fmt.Fprintln(os.Stderr, "bubblewrap is required for network-denied workers")
		return 1
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	corpus, err := offlinebench.LoadCorpus(*corpusPath, *bodiesDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	_, summary, manifest, err := offlinebench.Execute(ctx, corpus, *corpusPath, offlinebench.Config{
		Executable:       executable,
		Bubblewrap:       bubblewrap,
		Catalogue:        *catalogue,
		CoverageContract: *coverageContract,
		Wafw00fPython:    *python,
		Wafw00fAdapter:   *adapter,
		OutputDir:        *outputDir,
		Iterations:       *iterations,
		Blocks:           *blocks,
		MinimumCoverage:  *minimumCoverage,
		MinimumAccuracy:  *minimumAccuracy,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if manifest.Complete {
			fmt.Fprintf(os.Stderr, "Complete generation published despite evaluation gate failure: %s (inspect with -verify-run)\n", *outputDir)
		}
		return 1
	}
	for _, tool := range []string{"wafme0w", "wafw00f"} {
		metrics := summary.Metrics[tool]
		fmt.Printf("%s raw-completion=%.2f%% expected-complete=%.2f%% state-conformance=%.2f%% product-conformance=%.2f%% exact=%d/%d median=%dns\n", tool, 100*metrics.RawCompletionRate, 100*metrics.ExpectedCompleteCoverage, 100*metrics.StateConformance, 100*metrics.ProductConformance, metrics.ExactCases, metrics.ExpectedLabelledCases, metrics.MedianCaseNS)
	}
	fmt.Printf("observed cross-detector disagreements=%d/%d (independent of expected conformance)\n", len(summary.Comparison.Disagreements), summary.Comparison.OutcomeCases)
	fmt.Printf("wafw00f/wafme0w median latency ratio=%.3fx\n", summary.Comparison.Wafw00fOverWafme0wRatio)
	fmt.Printf("native reviewed schemas=%d/%d; fully reviewed products=%d/%d; full-native profile products=%d\n", summary.Catalogue.TestedSchemas, summary.Catalogue.TotalSchemas, summary.Catalogue.TestedProducts, summary.Catalogue.TotalProducts, summary.FullNative.CatalogueSize)
	fmt.Printf("complete generation: %s (verify before consuming: offlinebench -verify-run %q)\n", *outputDir, *outputDir)
	return 0
}
