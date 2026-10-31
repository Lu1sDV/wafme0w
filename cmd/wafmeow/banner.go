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

	"github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
	"github.com/logrusorgru/aurora/v4"
	"github.com/rivo/uniseg"
)

func colorizer(writer io.Writer, disabled bool) *aurora.Aurora {
	_, noColor := os.LookupEnv("NO_COLOR")
	file, ok := writer.(*os.File)
	colors := ok && !disabled && !noColor && os.Getenv("TERM") != "dumb" && isTerminal(file)
	return aurora.New(aurora.WithColors(colors), aurora.WithHyperlinks(false))
}

func printBanner(writer io.Writer, au *aurora.Aurora) error {
	_, err := fmt.Fprintf(writer, "%s  %s  %s\n  HTTP evidence fingerprinting | fast, deep, baseline or saved capture\n\n",
		au.Cyan("/\\_/\\"), au.Bold("wafmeow"), terminalText(wafmeow.Version()))
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

// HTTP classification and browser capture are independent reporting axes.
func humanOutcome(result wafmeow.Result) string {
	switch {
	case result.Outcome.State == wafmeow.Failed:
		return "ERROR"
	case len(result.Outcome.Matches) != 0:
		return "WAF MATCH"
	case result.Outcome.State != wafmeow.Complete:
		return "INCOMPLETE"
	case result.Generic.Mode != "" || result.Generic.Reason != "" || len(result.Outcome.Diagnostics) != 0 || channelsNeedReview(result):
		return "REVIEW"
	}
	return "NO WAF MATCH"
}

func hasExplicitAvailability(result wafmeow.Result) bool {
	for _, observation := range result.Evidence {
		if observation.Availability != nil {
			return true
		}
	}
	return false
}

func channelsNeedReview(result wafmeow.Result) bool {
	for _, observation := range result.Evidence {
		if availability := observation.Availability; availability != nil {
			if availability.Status != wafmeow.ChannelComplete || availability.Headers != wafmeow.ChannelComplete ||
				availability.Reason != wafmeow.ChannelComplete || availability.Body != wafmeow.ChannelComplete {
				return true
			}
		}
	}
	return false
}

func channelSummary(result wafmeow.Result) string {
	var summary strings.Builder
	for i, observation := range result.Evidence {
		availability := observation.Availability
		if availability == nil {
			continue
		}
		if summary.Len() != 0 {
			summary.WriteString(" / ")
		}
		headers := string(availability.Headers)
		if availability.Headers == wafmeow.ChannelIncomplete {
			headers = "partial"
		}
		fmt.Fprintf(&summary, "#%d status %s; headers %s; reason %s; body %s", i+1,
			terminalText(string(availability.Status)), terminalText(headers),
			terminalText(string(availability.Reason)), terminalText(string(availability.Body)))
	}
	return summary.String()
}

// Match references use positions in Result.Evidence, not EvidenceSummary.Index.
func supportingEvidence(match wafmeow.Match, evidenceCount int) []int {
	indices := make([]int, 0, len(match.Fingerprints))
	for _, fingerprint := range match.Fingerprints {
		if fingerprint.Evidence >= 0 && fingerprint.Evidence < evidenceCount {
			indices = append(indices, fingerprint.Evidence)
		}
	}
	sort.Ints(indices)
	unique := indices[:0]
	for _, index := range indices {
		if len(unique) == 0 || unique[len(unique)-1] != index {
			unique = append(unique, index)
		}
	}
	return unique
}

func printResult(stdout, stderr io.Writer, result wafmeow.Result, suppressWarnings bool, au, diagnostics *aurora.Aurora) error {
	outcome := humanOutcome(result)
	label := au.Yellow("[ " + outcome + " ]")
	switch outcome {
	case "ERROR", "WAF MATCH":
		label = au.Red("[ " + outcome + " ]")
	case "NO WAF MATCH":
		label = au.Green("[ " + outcome + " ]")
	}
	var group strings.Builder
	fmt.Fprintf(&group, "%s  %s\n", au.Bold(label), terminalText(result.Target))
	for _, match := range result.Outcome.Matches {
		fmt.Fprintf(&group, "   product  %s\n", au.Bold(au.Red(terminalText(match.Product))))
		indices := supportingEvidence(match, len(result.Evidence))
		group.WriteString("   matched on  ")
		if len(indices) == 0 {
			group.WriteString("supporting observation unavailable")
		}
		for i, index := range indices {
			if i != 0 {
				group.WriteString("; ")
			}
			observation := result.Evidence[index]
			fmt.Fprintf(&group, "#%d %s HTTP ", index+1, probeTag(observation.Role, au))
			if observation.StatusCode >= 100 && observation.StatusCode <= 999 {
				fmt.Fprint(&group, observation.StatusCode)
			} else {
				group.WriteByte('?')
			}
			if observation.RequestURL != "" {
				fmt.Fprintf(&group, " %s", terminalText(observation.RequestURL))
			}
			if observation.EffectiveURL != "" && observation.EffectiveURL != observation.RequestURL {
				fmt.Fprintf(&group, " -> %s", terminalText(observation.EffectiveURL))
			}
		}
		group.WriteByte('\n')
	}
	if len(result.Outcome.Matches) == 0 {
		switch outcome {
		case "ERROR":
			group.WriteString("   result   Target evaluation failed\n")
		case "INCOMPLETE":
			if hasExplicitAvailability(result) {
				group.WriteString("   result   No known WAF fingerprint matched; classification incomplete\n")
				break
			}
			description := "No HTTP response received"
			for _, observation := range result.Evidence {
				if observation.StatusCode >= 100 && observation.StatusCode <= 999 {
					description = "HTTP response received"
					break
				}
			}
			fmt.Fprintf(&group, "   result   %s; fingerprint evidence incomplete\n", description)
		default:
			group.WriteString("   result   No known WAF fingerprint matched\n")
		}
	}
	if result.Generic.Mode != "" || result.Generic.Reason != "" {
		description := result.Generic.Reason
		if description == "" {
			description = result.Generic.Mode.String()
		}
		fmt.Fprintf(&group, "   review   Unusual response: %s\n", terminalText(description))
	} else if outcome == "REVIEW" {
		if hasExplicitAvailability(result) {
			group.WriteString("   review   HTTP channels or diagnostics need review\n")
		} else {
			group.WriteString("   review   HTTP diagnostics need review\n")
		}
	}
	group.WriteString("   HTTP  ")
	if len(result.Evidence) == 0 {
		group.WriteString("unavailable")
	}
	for i, observation := range result.Evidence {
		if i != 0 {
			group.WriteString(" / ")
		}
		fmt.Fprintf(&group, "#%d ", i+1)
		if observation.StatusCode >= 100 && observation.StatusCode <= 999 {
			fmt.Fprint(&group, observation.StatusCode)
		} else {
			group.WriteByte('?')
		}
		if observation.BodyTruncated {
			group.WriteString(" (body truncated)")
		}
	}
	evidenceState := au.Colorize(terminalText(string(result.Outcome.State)), 0)
	switch result.Outcome.State {
	case wafmeow.Incomplete:
		evidenceState = au.Yellow(evidenceState)
	case wafmeow.Failed:
		evidenceState = au.Red(evidenceState)
	}
	stateLabel := "evidence"
	if hasExplicitAvailability(result) {
		stateLabel = "classification"
	}
	fmt.Fprintf(&group, " | %s %s\n", stateLabel, evidenceState)
	if channels := channelSummary(result); channels != "" {
		fmt.Fprintf(&group, "   channels  %s\n", channels)
	}
	if browser := result.Browser; browser != nil {
		fmt.Fprintf(&group, "   browser  %s (%s), text %s, image %s (separate from HTTP)\n",
			terminalText(browser.State), terminalText(browser.Mode), terminalText(browser.DOM.State), terminalText(browser.Screenshot.State))
		if browser.DOM.SaveState != "" {
			fmt.Fprintf(&group, "            text save %s\n", terminalText(browser.DOM.SaveState))
		}
		if browser.Screenshot.SaveState != "" {
			fmt.Fprintf(&group, "            image save %s\n", terminalText(browser.Screenshot.SaveState))
		}
		if browser.DOM.Saved != "" {
			fmt.Fprintf(&group, "            text saved %s\n", terminalText(browser.DOM.Saved))
		}
		if browser.Screenshot.Saved != "" {
			fmt.Fprintf(&group, "            image saved %s\n", terminalText(browser.Screenshot.Saved))
		}
	}
	group.WriteByte('\n')
	if _, err := io.WriteString(stdout, group.String()); err != nil {
		return err
	}
	if suppressWarnings {
		return nil
	}
	return printResultDiagnostics(stderr, result, diagnostics)
}

// probeTag colors a probe role. Roles are presentation labels, not machine
// data; one stable color per role keeps a repeated probe list scannable.
func probeTag(role string, au *aurora.Aurora) aurora.Value {
	tag := "[" + terminalText(role) + "]"
	switch role {
	case "Normal":
		return au.Cyan(tag)
	case "Saved":
		return au.BrightCyan(tag)
	case "NoUserAgent":
		return au.BrightBlack(tag)
	case "NonExistent":
		return au.Blue(tag)
	case "XssAttack":
		return au.BrightMagenta(tag)
	case "XxeAttack":
		return au.Magenta(tag)
	case "LfiAttack":
		return au.BrightYellow(tag)
	case "CentralAttack":
		return au.Yellow(tag)
	// Removed probe roles can still appear in saved captures recorded before
	// the probe consolidation, so their colours stay stable.
	case "SqliAttack":
		return au.BrightRed(tag)
	case "RceAttack":
		return au.Red(tag)
	case "JndiAttack":
		return au.BrightRed(tag)
	}
	return au.Bold(tag)
}

// diagnosticText renders one recorded diagnostic explanation.
func diagnosticText(result wafmeow.Result, diagnostic wafmeow.Diagnostic) string {
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
	var text strings.Builder
	text.WriteString(terminalText(description))
	if diagnostic.Code == "redirect_scope" && diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
		if destination := result.Evidence[diagnostic.Evidence].BlockedRedirectURL; destination != "" {
			fmt.Fprintf(&text, ": %s", terminalText(destination))
		}
	}
	if guidance := certificateGuidance(diagnostic.Message); guidance != "" {
		fmt.Fprintf(&text, " (%s)", guidance)
	}
	return text.String()
}

// Diagnostics go to stderr and follow stderr's own TTY status: the caller builds
// the colorizer from this writer, so a redirected log stays free of escapes.
func printResultDiagnostics(writer io.Writer, result wafmeow.Result, au *aurora.Aurora) error {
	var group strings.Builder
	if len(result.Outcome.Diagnostics) != 0 {
		type row struct {
			tag   aurora.Value
			width int
			text  string
		}
		rows := make([]row, 0, len(result.Outcome.Diagnostics))
		seen := make(map[wafmeow.Diagnostic]bool, len(result.Outcome.Diagnostics))
		width := 2 // Retain the empty tag column for diagnostics without a role.
		for _, diagnostic := range result.Outcome.Diagnostics {
			if seen[diagnostic] {
				continue
			}
			seen[diagnostic] = true
			tag := au.Colorize("", 0)
			if diagnostic.Evidence >= 0 && diagnostic.Evidence < len(result.Evidence) {
				if role := result.Evidence[diagnostic.Evidence].Role; role != "" {
					tag = probeTag(role, au)
				}
			}
			// Measure the escaped tag in terminal cells, excluding ANSI styling.
			tagWidth := uniseg.StringWidth(tag.Reset().String())
			rows = append(rows, row{tag: tag, width: tagWidth, text: diagnosticText(result, diagnostic)})
			width = max(width, tagWidth)
		}
		fmt.Fprintf(&group, "%s  %s | %d diagnostics\n", au.Bold(au.Yellow("WARN")), terminalText(result.Target), len(rows))
		for _, row := range rows {
			fmt.Fprintf(&group, "  %s%s %s\n", row.tag, strings.Repeat(" ", width-row.width), row.text)
		}
	}
	if browser := result.Browser; browser != nil {
		if browser.Reason != "" || browser.Error != "" {
			fmt.Fprintf(&group, "%s  %s | browser %s: %s\n", au.Bold(au.Yellow("WARN")), terminalText(result.Target), terminalText(browser.Reason), terminalText(browser.Error))
		}
		for _, limitation := range browser.Limitations {
			fmt.Fprintf(&group, "%s  %s | browser limitation: %s\n", au.Bold(au.Yellow("WARN")), terminalText(result.Target), terminalText(limitation))
		}
	}
	if group.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(writer, group.String())
	return err
}

// Results retain cause text, not error values; only recognized x509 causes get
// specific guidance. A TLS failure does not imply other observations are absent.
func certificateGuidance(message string) string {
	cause := strings.ToLower(message)
	if !strings.Contains(cause, "x509:") {
		return ""
	}
	switch {
	case strings.Contains(cause, "certificate signed by unknown authority"):
		return "Check the certificate chain and trust store; if a private CA is expected, on Linux set SSL_CERT_FILE to an approved CA bundle"
	case strings.Contains(cause, "certificate has expired"), strings.Contains(cause, "not yet valid"):
		return "Correct the certificate validity dates and check the system clock"
	case strings.Contains(cause, "certificate is valid for"), strings.Contains(cause, "not valid for any names"), strings.Contains(cause, "doesn't contain any ip sans"):
		return "Correct the target hostname or the certificate subject alternative names"
	default:
		return ""
	}
}

// Debug output uses the same recorded evidence as JSON reports, not new requests.
func printDebug(writer io.Writer, result wafmeow.Result) error {
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
	WAFMatch, NoWAFMatch, Review, OutcomeIncomplete, OutcomeError               int
	Browser, BrowserFailed                                                      int
	StrictFailure                                                               bool
	ExplicitAvailability                                                        bool
}

func (counts *resultCounts) add(result wafmeow.Result) {
	counts.Total++
	counts.ExplicitAvailability = counts.ExplicitAvailability || hasExplicitAvailability(result)
	switch humanOutcome(result) {
	case "WAF MATCH":
		counts.WAFMatch++
	case "NO WAF MATCH":
		counts.NoWAFMatch++
	case "REVIEW":
		counts.Review++
	case "INCOMPLETE":
		counts.OutcomeIncomplete++
	case "ERROR":
		counts.OutcomeError++
	}
	switch result.Outcome.State {
	case wafmeow.Complete:
		counts.Complete++
		if len(result.Outcome.Matches) == 0 {
			counts.Unnamed++
		}
	case wafmeow.Incomplete:
		counts.Incomplete++
	case wafmeow.Failed:
		counts.Failed++
	}
	if len(result.Outcome.Matches) != 0 {
		counts.Matched++
	}
	if result.Generic.Mode != "" || result.Generic.Reason != "" {
		counts.Generic++
	}
	counts.Diagnostics += len(result.Outcome.Diagnostics)
	if result.Browser != nil {
		counts.Browser++
		if result.Browser.Failed() {
			counts.BrowserFailed++
			counts.StrictFailure = true
		}
	}
	counts.StrictFailure = counts.StrictFailure || result.Outcome.State != wafmeow.Complete || len(result.Outcome.Diagnostics) != 0
}

func printSummary(writer io.Writer, counts resultCounts, finished bool, au *aurora.Aurora) error {
	label := au.Bold("SUMMARY")
	if !finished {
		label = au.Bold(au.Yellow("PARTIAL SUMMARY"))
	}
	stateLabel := "HTTP evidence"
	if counts.ExplicitAvailability {
		stateLabel = "HTTP classification"
	}
	_, err := fmt.Fprintf(writer, "%s  %d targets\n  HTTP OUTCOME | TARGETS\n  WAF MATCH    | %d\n  NO WAF MATCH | %d\n  REVIEW       | %d\n  INCOMPLETE   | %d\n  ERROR        | %d\n  %s: complete %d | incomplete %d | failed %d\n  unusual responses %d | HTTP diagnostics %d\n",
		label, counts.Total, counts.WAFMatch, counts.NoWAFMatch, counts.Review, counts.OutcomeIncomplete, counts.OutcomeError,
		stateLabel, counts.Complete, counts.Incomplete, counts.Failed, counts.Generic, counts.Diagnostics)
	if err == nil && counts.Browser != 0 {
		_, err = fmt.Fprintf(writer, "  browser %d | browser/artifact failures %d (separate from HTTP state)\n", counts.Browser, counts.BrowserFailed)
	}
	if err == nil {
		_, err = io.WriteString(writer, "  No WAF match is not proof of WAF absence; matched-on observations show supporting evidence, not causation.\n")
	}
	return err
}
