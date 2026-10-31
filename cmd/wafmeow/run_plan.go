package main

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
)

// The default plan fits one line. Only customized safety controls need extra
// lines. Never print targets, header values, origin values, or local paths.
func runPlanText(opts options, config wafmeow.Config) string {
	if opts.Silent {
		return ""
	}
	var plan strings.Builder
	var details []string
	defaults := wafmeow.DefaultConfig()
	if opts.EvidenceFile != "" {
		if opts.EvidenceFormat == "httpx" {
			plan.WriteString("RUN PLAN  offline httpx | serial import | no network\n")
		} else {
			fmt.Fprintf(&plan, "RUN PLAN  offline %s | %d workers | no network\n",
				terminalText(opts.EvidenceFormat), min(config.Concurrency, runtime.GOMAXPROCS(0)))
		}
		if config.MaxBodyBytes != defaults.MaxBodyBytes {
			details = append(details, fmt.Sprintf("body limit %dB", config.MaxBodyBytes))
		}
	} else {
		connections := config.MaxConnections
		if connections == 0 {
			connections = max(config.Concurrency, config.ProbeConcurrency)
		}
		mode := "deep (7 probes)"
		parallelism := fmt.Sprintf("%d at a time", min(config.ProbeConcurrency, connections, 7))
		if config.BaselineOnly {
			mode, parallelism = "baseline (normal only)", ""
		} else if config.FastMode {
			mode = "fast (3 requests)"
			parallelism = fmt.Sprintf("%d at a time", min(3, connections))
		}
		if parallelism == "" {
			fmt.Fprintf(&plan, "RUN PLAN  %s | %d workers | %s/req | %s/target\n",
				mode, config.Concurrency, config.RequestTimeout, config.TargetTimeout)
		} else {
			fmt.Fprintf(&plan, "RUN PLAN  %s | %d workers | %s | %s/req | %s/target\n",
				mode, config.Concurrency, parallelism, config.RequestTimeout, config.TargetTimeout)
		}
		if config.MaxConnections != 0 || connections != config.Concurrency {
			details = append(details, fmt.Sprintf("%d in flight", connections))
		}
		if config.MaxRequests != defaults.MaxRequests {
			details = append(details, fmt.Sprintf("%d attempts/target", config.MaxRequests))
		}
		if config.MaxRedirects != defaults.MaxRedirects || config.RedirectPolicy != defaults.RedirectPolicy {
			if config.RedirectPolicy == "none" {
				details = append(details, "redirects off")
			} else {
				details = append(details, fmt.Sprintf("%d redirects (%s)", config.MaxRedirects, terminalText(config.RedirectPolicy)))
			}
		}
		if len(config.AllowedOrigins) != 0 {
			details = append(details, "origin allowlist on")
		}
		if config.RequestsPerSecond != 0 {
			details = append(details, planRate(config.RequestsPerSecond)+" global")
		}
		if config.PerOriginRequestsPerSecond != 0 {
			details = append(details, planRate(config.PerOriginRequestsPerSecond)+" per origin")
		}
		if !config.BaselineOnly {
			for _, header := range config.Headers {
				if strings.EqualFold(header.Name, "User-Agent") {
					details = append(details, "custom User-Agent overrides every probe")
					break
				}
			}
		}
		if config.Browser != nil && config.Browser.Mode != "off" {
			details = append(details, fmt.Sprintf("browser %s (%s)", terminalText(config.Browser.Mode), config.Browser.Timeout))
		}
	}
	if opts.JSONL {
		details = append(details, "JSONL")
	}
	if opts.OutputFile != "" {
		format := "TXT"
		switch extension := strings.ToLower(filepath.Ext(opts.OutputFile)); extension {
		case ".json", ".jsonl", ".csv":
			format = strings.ToUpper(extension[1:])
		}
		details = append(details, format+" report")
	}
	if opts.JournalFile != "" {
		details = append(details, "journal")
	}
	if opts.Strict {
		details = append(details, "strict")
	}
	// Bound optional detail lines to avoid accidental 80-column wrapping.
	const limit = 76
	const prefix = "  settings  "
	line := prefix
	for _, detail := range details {
		separator := ""
		if line != prefix {
			separator = " | "
		}
		if line != prefix && len(line)+len(separator)+len(detail) >= limit {
			plan.WriteString(line)
			plan.WriteByte('\n')
			line, separator = prefix, ""
		}
		line += separator + detail
	}
	if line != prefix {
		plan.WriteString(line)
		plan.WriteByte('\n')
	}
	return plan.String()
}

// Keep run-plan content on stderr, including human scans.
func printRunPlan(writer io.Writer, opts options, config wafmeow.Config) error {
	return writeRunPlan(writer, runPlanText(opts, config))
}

func writeRunPlan(writer io.Writer, plan string) error {
	if plan == "" {
		return nil
	}
	n, err := io.WriteString(writer, plan)
	if err == nil && n != len(plan) {
		return io.ErrShortWrite
	}
	return err
}

func planRate(rate float64) string {
	if rate == 0 {
		return "unlimited"
	}
	return strconv.FormatFloat(rate, 'g', -1, 64) + " requests/s"
}
