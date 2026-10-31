package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
	"github.com/jessevdk/go-flags"
)

// A standalone help flag remains useful even after an invalid option. Attached
// values and everything after -- retain their literal argument meaning.
func requestsHelp(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func writeHelp(writer io.Writer) error {
	width := terminalColumns(os.Stdout)
	if width == 0 {
		width = terminalColumns(os.Stdin)
	}
	if width == 0 {
		width = 80
	}
	return writeHelpWidth(writer, width)
}

func writeHelpWidth(writer io.Writer, width int) error {
	width = max(40, min(width, 100))
	var help bytes.Buffer
	help.WriteString(`wafmeow - WAF fingerprints from targets or saved responses

Usage:
  wafmeow --target URL [--target URL ...] [OPTIONS]
  wafmeow --target-file FILE|- [OPTIONS]
  wafmeow --evidence FILE|- [OPTIONS]

Examples:
  Scan one authorized URL:
    wafmeow --target URL --fast
  Scan a list and stream results:
    wafmeow --target-file targets.txt --fast --jsonl
  Classify saved response captures without requests:
    wafmeow --evidence captures.jsonl --jsonl

`)
	helpParagraph(&help, width, "", "Choose one input source. With no explicit source, piped stdin supplies target URLs, one per line. Use --target for direct URLs; positional URLs are not accepted.")
	help.WriteByte('\n')
	helpParagraph(&help, width, "", "For live targets, choose one live mode (default: --deep). --fast selects 3 requests; --deep selects 8; --baseline fingerprints the normal response only. Fast and deep already include the normal request. Redirects, retries, failures and budgets affect actual request counts.")
	help.WriteByte('\n')
	// Render the same metadata used for parsing, with fresh defaults rather than
	// values supplied before --help. A separate description line keeps long
	// option names from squeezing the entire reference into a narrow column.
	defaults := newOptions(wafmeow.DefaultConfig())
	parser := flags.NewParser(&defaults, flags.None)
	var writeGroup func(*flags.Group)
	writeGroup = func(group *flags.Group) {
		if group.Hidden {
			return
		}
		if len(group.Options()) > 0 {
			fmt.Fprintf(&help, "%s:\n", group.ShortDescription)
		}
		for _, option := range group.Options() {
			if option.Hidden {
				continue
			}
			help.WriteString("  ")
			if option.ShortName != 0 {
				fmt.Fprintf(&help, "-%c, ", option.ShortName)
			}
			fmt.Fprintf(&help, "--%s", option.LongName)
			if option.ValueName != "" {
				fmt.Fprintf(&help, "=%s", option.ValueName)
			}
			help.WriteByte('\n')
			description := option.Description
			if value := helpDefault(option); value != "" {
				description += " (default: " + value + ")"
			}
			helpParagraph(&help, width, "    ", description)
		}
		if len(group.Options()) > 0 {
			help.WriteByte('\n')
		}
		for _, child := range group.Groups() {
			writeGroup(child)
		}
	}
	for _, group := range parser.Groups() {
		writeGroup(group)
	}
	help.WriteString("Help:\n  -h, --help\n    Show this help, including after an invalid option.\n\n")
	help.WriteString("Automation contracts:\n")
	for _, paragraph := range []string{
		"Use --jsonl for structured stdout; --output writes a named file independently. Its extension selects JSON/JSONL/CSV, otherwise TXT. --output - is a literal filename, not stdout.",
		"--evidence reads response captures, not result reports written by --output. Choose native captures or --evidence-format=httpx exports. Live request controls do not enable offline acquisition.",
		"--strict checks evidence quality. Matches alone do not fail. Empty input succeeds and publishes an empty report, even with --strict. Nonzero exit does not mean no output was published.",
		"Rate and connection waits consume request and target deadlines. When lowering --rate, also review --concurrency and both timeouts. HTTP and browser deadlines are separate.",
	} {
		helpParagraph(&help, width, "  ", paragraph)
		help.WriteByte('\n')
	}
	help.WriteString("Exit codes:\n")
	for _, exit := range []string{
		"0    Completed; inspect result states, or use --strict.",
		"1    Configuration, input or output failure.",
		"2    Strict found incomplete, failed or diagnosed results; reports are published first.",
		"130  Cancelled by SIGINT or SIGTERM.",
	} {
		helpParagraph(&help, width, "  ", exit)
	}
	help.WriteString("\nDocumentation and support:\n  https://github.com/Lu1sDV/wafmeow/blob/main/docs/usage.md\n  https://github.com/Lu1sDV/wafmeow/issues\n")
	_, err := help.WriteTo(writer)
	return err
}

func helpDefault(option *flags.Option) string {
	if option.DefaultMask != "" {
		if option.DefaultMask == "-" {
			return ""
		}
		return option.DefaultMask
	}
	switch value := option.Value().(type) {
	case bool, []string:
		return ""
	case string:
		return value
	default:
		return fmt.Sprint(value)
	}
}

// Help strings are trusted ASCII. Leave indivisible words (such as flags and
// URLs) intact so copying them never introduces a hyphen or altered spelling.
func helpParagraph(writer *bytes.Buffer, width int, indent, text string) {
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line) > len(indent) && len(line)+1+len(word) > width {
			writer.WriteString(line + "\n")
			line = indent
		}
		if len(line) > len(indent) {
			line += " "
		}
		line += word
	}
	writer.WriteString(line + "\n")
}
