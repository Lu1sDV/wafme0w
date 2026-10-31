package main

import (
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
)

// printRunPlan describes a validated CLI configuration before acquisition. It
// deliberately omits targets, origin values, headers, and local paths. The
// caller supplies stderr and owns cancellation and the returned output error.
func printRunPlan(writer io.Writer, opts options, config wafmeow.Config) error {
	if opts.Silent {
		return nil
	}
	var plan strings.Builder
	if opts.EvidenceFile != "" {
		fmt.Fprintf(&plan, "RUN PLAN  offline %s | no network requests\n", terminalText(opts.EvidenceFormat))
		if opts.EvidenceFormat == "httpx" {
			plan.WriteString("  1 classification worker (httpx import is serial)\n")
		} else {
			cpuCap := runtime.GOMAXPROCS(0)
			fmt.Fprintf(&plan, "  classification workers: %d (requested %d; CPU cap %d)\n", min(config.Concurrency, cpuCap), config.Concurrency, cpuCap)
		}
		fmt.Fprintf(&plan, "  saved-response limit: %d bytes/body\n", config.MaxBodyBytes)
		plan.WriteString("  live HTTP timeouts, rate, redirects and connection controls: inactive\n")
	} else {
		// CLI parsing already supplies nonzero timeout, request and probe defaults.
		// A zero connection limit is normalized by Run itself.
		connections := config.MaxConnections
		if connections == 0 {
			connections = max(config.Concurrency, config.ProbeConcurrency)
		}
		mode, requests := "deep", "normal request, then up to 7 probes"
		scheduling := fmt.Sprintf("probe concurrency: %d after normal", min(config.ProbeConcurrency, connections, 7))
		if config.BaselineOnly {
			mode, requests, scheduling = "baseline", "normal request only", "1 request/target"
		} else if config.FastMode {
			mode, requests = "fast", "normal, no-user-agent and combined probe"
			scheduling = fmt.Sprintf("per-target parallel request limit: %d", min(3, connections))
		}
		fmt.Fprintf(&plan, "RUN PLAN  %s | %s (before redirects/retries)\n", mode, requests)
		if !config.BaselineOnly {
			for _, header := range config.Headers {
				if strings.EqualFold(header.Name, "User-Agent") {
					plan.WriteString("  custom User-Agent overrides every probe, including no-user-agent\n")
					break
				}
			}
		}
		fmt.Fprintf(&plan, "  target workers: %d | %s | global in-flight request limit: %d\n", config.Concurrency, scheduling, connections)
		redirects := config.MaxRedirects
		if config.RedirectPolicy == "none" {
			redirects = 0
		}
		originScope := "off"
		if len(config.AllowedOrigins) != 0 {
			originScope = "on"
		}
		fmt.Fprintf(&plan, "  HTTP limits: %d attempts/target | %d redirects/request (%s) | origin allowlist: %s\n", config.MaxRequests, redirects, terminalText(config.RedirectPolicy), originScope)
		fmt.Fprintf(&plan, "  rate: %s global | %s per origin\n", planRate(config.RequestsPerSecond), planRate(config.PerOriginRequestsPerSecond))
		fmt.Fprintf(&plan, "  deadlines: %s/request | %s/target; include local rate/connection waits\n", config.RequestTimeout, config.TargetTimeout)
		if config.Browser != nil && config.Browser.Mode != "off" {
			fmt.Fprintf(&plan, "  browser: %s | %s deadline, separate from HTTP\n", terminalText(config.Browser.Mode), config.Browser.Timeout)
		}
	}
	outputs := []string{"human stdout"}
	if opts.JSONL {
		outputs[0] = "JSONL stdout"
	}
	if opts.OutputFile != "" {
		format := "TXT"
		switch extension := strings.ToLower(filepath.Ext(opts.OutputFile)); extension {
		case ".json", ".jsonl", ".csv":
			format = strings.ToUpper(extension[1:])
		}
		outputs = append(outputs, "atomic "+format+" report")
	}
	if opts.JournalFile != "" {
		outputs = append(outputs, "durable JSONL journal")
	}
	strict := "off"
	if opts.Strict {
		strict = "on (exit 2 for incomplete/failed/diagnosed results)"
	}
	fmt.Fprintf(&plan, "  output: %s | strict %s\n", strings.Join(outputs, "; "), strict)
	n, err := io.WriteString(writer, plan.String())
	if err == nil && n != plan.Len() {
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
