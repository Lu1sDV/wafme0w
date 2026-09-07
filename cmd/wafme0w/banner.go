package main

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
	"github.com/logrusorgru/aurora/v4"
)

func colorizer(writer io.Writer, disabled bool) *aurora.Aurora {
	_, noColor := os.LookupEnv("NO_COLOR")
	file, ok := writer.(*os.File)
	colors := ok && !disabled && !noColor && os.Getenv("TERM") != "dumb" && isTerminal(file)
	return aurora.New(aurora.WithColors(colors), aurora.WithHyperlinks(false))
}

func printBanner(writer io.Writer, au *aurora.Aurora) error {
	_, err := fmt.Fprintf(writer, "%s  %s  %s\n  HTTP evidence fingerprinting | active, baseline or saved capture\n\n",
		au.Cyan("/\\_/\\"), au.Bold("wafme0w"), terminalText(wafme0w.Version()))
	return err
}

// Escape controls and invisible formatting before strings enter a terminal.
// Escape untrusted text before applying trusted ANSI styling.
func terminalText(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&out, "\\x%02x", value[i])
		} else if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			quoted := strconv.QuoteRuneToASCII(r)
			out.WriteString(quoted[1 : len(quoted)-1])
		} else {
			out.WriteString(value[i : i+size])
		}
		i += size
	}
	return out.String()
}

func printProducts(writer io.Writer, products []string, au *aurora.Aurora) error {
	sort.Strings(products)
	for _, product := range products {
		if _, err := fmt.Fprintf(writer, "  %s %s\n", au.Cyan("-"), terminalText(product)); err != nil {
			return err
		}
	}
	return nil
}

func printResult(stdout, stderr io.Writer, result wafme0w.Result, suppressWarnings bool, au *aurora.Aurora) error {
	partial := result.Outcome.State != wafme0w.Complete || len(result.Outcome.Diagnostics) != 0
	label := au.Bold(au.Yellow("INCONCLUSIVE"))
	switch {
	case len(result.Outcome.Matches) != 0:
		label = au.Bold(au.Green("FOUND"))
	case result.Outcome.State == wafme0w.Failed:
		label = au.Bold(au.Red("ERROR"))
	case !partial:
		label = au.Bold("NO MATCH")
	}
	var group strings.Builder
	fmt.Fprintf(&group, "%s  %s | ", label, terminalText(result.Target))
	for i, match := range result.Outcome.Matches {
		if i != 0 {
			group.WriteString(", ")
		}
		fmt.Fprint(&group, au.Bold(au.White(terminalText(match.Product))))
	}
	if len(result.Outcome.Matches) == 0 {
		switch {
		case !partial:
			group.WriteString("No known WAF fingerprint matched")
		case result.Outcome.State == wafme0w.Failed:
			group.WriteString("Target evaluation failed")
		default:
			description := "No HTTP response received"
			for _, observation := range result.Evidence {
				if observation.StatusCode >= 100 {
					description = "HTTP response received; fingerprint evidence incomplete"
					break
				}
			}
			for _, diagnostic := range result.Outcome.Diagnostics {
				if diagnostic.Code == "redirect_scope" {
					description = "Redirect blocked by scope; fingerprint evidence incomplete"
					break
				}
			}
			group.WriteString(description)
		}
	} else if partial {
		group.WriteString(" | partial scan")
	}
	if result.Generic.Reason != "" || result.Generic.Mode != "" {
		group.WriteString(" | generic anomaly")
	}
	group.WriteByte('\n')
	if _, err := io.WriteString(stdout, group.String()); err != nil {
		return err
	}
	if !suppressWarnings && len(result.Outcome.Diagnostics) != 0 {
		seen := make(map[string]bool)
		group.Reset()
		fmt.Fprintf(&group, "WARN  %s | ", terminalText(result.Target))
		first := true
		for _, diagnostic := range result.Outcome.Diagnostics {
			key := diagnostic.Code + "\x00" + diagnostic.Message
			if seen[key] {
				continue
			}
			seen[key] = true
			if !first {
				group.WriteString("; ")
			}
			first = false
			if diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
				if role := result.Evidence[diagnostic.Evidence].Role; role != "" {
					fmt.Fprintf(&group, "[%s] ", terminalText(role))
				}
			}
			description := diagnostic.Message
			if description == "" || description == diagnostic.Code {
				description = strings.ReplaceAll(diagnostic.Code, "_", " ")
			}
			if diagnostic.Code == "redirect_scope" {
				description = "redirect outside allowed scope"
				if diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
					if status := result.Evidence[diagnostic.Evidence].StatusCode; status >= 300 && status < 400 {
						description = fmt.Sprintf("Got Redirect %d", status)
					}
				}
			}
			group.WriteString(terminalText(description))
			if diagnostic.Code == "redirect_scope" && diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
				if destination := result.Evidence[diagnostic.Evidence].BlockedRedirectURL; destination != "" {
					fmt.Fprintf(&group, ": %s", au.Italic(au.White(terminalText(destination))))
				}
			}
		}
		group.WriteByte('\n')
		if _, err := io.WriteString(stderr, group.String()); err != nil {
			return err
		}
	}
	_, err := io.WriteString(stdout, "\n")
	return err
}

// Debug output uses the same recorded evidence as JSON reports, not new requests.
func printDebug(writer io.Writer, result wafme0w.Result) error {
	var group strings.Builder
	for i, observation := range result.Evidence {
		fmt.Fprintf(&group, "DEBUG  %s | evidence=%d role=%s status=%d request=%s effective=%s truncated=%t code=%s\n",
			terminalText(result.Target), i, terminalText(observation.Role), observation.StatusCode,
			terminalText(observation.RequestURL), terminalText(observation.EffectiveURL),
			observation.BodyTruncated, terminalText(observation.ErrorCode))
		for hop, destination := range observation.RedirectChain {
			fmt.Fprintf(&group, "DEBUG  %s | evidence=%d redirect=%d destination=%s\n",
				terminalText(result.Target), i, hop+1, terminalText(destination))
		}
		if observation.BlockedRedirectURL != "" {
			fmt.Fprintf(&group, "DEBUG  %s | evidence=%d blocked_redirect=%s\n",
				terminalText(result.Target), i, terminalText(observation.BlockedRedirectURL))
		}
	}
	for _, diagnostic := range result.Outcome.Diagnostics {
		fmt.Fprintf(&group, "DEBUG  %s | evidence=%d code=%s detail=%s\n",
			terminalText(result.Target), diagnostic.Evidence, terminalText(diagnostic.Code), terminalText(diagnostic.Message))
	}
	_, err := io.WriteString(writer, group.String())
	return err
}

type resultCounts struct {
	Total, Complete, Matched, Unnamed, Incomplete, Failed, Generic, Diagnostics int
	StrictFailure                                                               bool
}

func (counts *resultCounts) add(result wafme0w.Result) {
	counts.Total++
	switch result.Outcome.State {
	case wafme0w.Complete:
		counts.Complete++
		if len(result.Outcome.Matches) == 0 {
			counts.Unnamed++
		}
	case wafme0w.Incomplete:
		counts.Incomplete++
	case wafme0w.Failed:
		counts.Failed++
	}
	if len(result.Outcome.Matches) != 0 {
		counts.Matched++
	}
	if result.Generic.Mode != "" || result.Generic.Reason != "" {
		counts.Generic++
	}
	counts.Diagnostics += len(result.Outcome.Diagnostics)
	counts.StrictFailure = counts.StrictFailure || result.Outcome.State != wafme0w.Complete || len(result.Outcome.Diagnostics) != 0
}

func printSummary(writer io.Writer, counts resultCounts, finished bool, au *aurora.Aurora) error {
	label := au.Bold("SUMMARY")
	if !finished {
		label = au.Bold(au.Yellow("PARTIAL SUMMARY"))
	}
	_, err := fmt.Fprintf(writer, "%s  %d targets\n  complete %d | matched %d | unnamed %d | incomplete %d | failed %d\n  generic %d | diagnostics %d\n",
		label, counts.Total, counts.Complete, counts.Matched, counts.Unnamed, counts.Incomplete, counts.Failed, counts.Generic, counts.Diagnostics)
	return err
}
