package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Lu1sDV/wafmeow/v3/pkg/wafmeow"
)

// Only formatted, body-free rows live on disk; replay never retains the scan.
type humanReportSpool struct {
	file                 *os.File
	size                 int64
	explicitAvailability bool
}

func openHumanReport(opts options) (*humanReportSpool, error) {
	if opts.Silent || opts.JSONL {
		return nil, nil
	}
	file, err := os.CreateTemp("", "wafmeow-results-*")
	if err != nil {
		return nil, fmt.Errorf("create human report spool: %w", err)
	}
	return &humanReportSpool{file: file}, nil
}

func (report *humanReportSpool) add(result wafmeow.Result) error {
	if report == nil {
		return nil
	}
	var products strings.Builder
	for i, match := range result.Outcome.Matches {
		if i != 0 {
			products.WriteString("; ")
		}
		products.WriteString(terminalText(match.Product))
		products.WriteString(" (observations ")
		support := supportingEvidence(match, len(result.Evidence))
		if len(support) == 0 {
			products.WriteString("unavailable")
		}
		for j, index := range support {
			if j != 0 {
				products.WriteByte(',')
			}
			fmt.Fprintf(&products, "#%d", index+1)
		}
		products.WriteByte(')')
	}
	if products.Len() == 0 {
		products.WriteByte('-')
	}
	state := terminalText(string(result.Outcome.State))
	if hasExplicitAvailability(result) {
		report.explicitAvailability = true
		state = "classification " + state + "; " + channelSummary(result)
	}
	row := fmt.Sprintf("%s | %s | %s | %s\n", humanOutcome(result), products.String(), state, terminalText(result.Target))
	n, err := io.WriteString(report.file, row)
	if err == nil && n != len(row) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write human report spool: %w", err)
	}
	// A failed partial write must never appear as a completed table row.
	report.size += int64(n)
	return nil
}

func (report *humanReportSpool) replay(ctx context.Context, writer io.Writer, finished bool) error {
	if report == nil {
		return nil
	}
	writer = reportReplayWriter{ctx: ctx, writer: writer}
	label := "URL / RESULT / EVIDENCE"
	if !finished {
		label = "PARTIAL URL / RESULT / EVIDENCE (completed rows only)"
	}
	stateLabel := "HTTP EVIDENCE"
	if report.explicitAvailability {
		label = "URL / RESULT / CLASSIFICATION / CHANNELS"
		if !finished {
			label = "PARTIAL " + label + " (completed rows only)"
		}
		stateLabel = "HTTP CLASSIFICATION / CHANNELS"
	}
	if _, err := fmt.Fprintf(writer, "\n%s\nOUTCOME | PRODUCTS (SUPPORTING OBSERVATIONS) | %s | FULL URL\n--------|-----------------------------------|---------------|---------\n", label, stateLabel); err != nil {
		return fmt.Errorf("write human report table: %w", err)
	}
	// Fixed separators avoid tabwriter's whole-table buffering on large scans.
	if _, err := io.Copy(writer, io.NewSectionReader(report.file, 0, report.size)); err != nil {
		return fmt.Errorf("replay human report spool: %w", err)
	}
	return ctx.Err()
}

type reportReplayWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (writer reportReplayWriter) Write(data []byte) (int, error) {
	if err := writer.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := writer.writer.Write(data)
	return n, errors.Join(err, writer.ctx.Err())
}

func (report *humanReportSpool) close() error {
	if report == nil || report.file == nil {
		return nil
	}
	file := report.file
	report.file = nil
	if err := errors.Join(file.Close(), os.Remove(file.Name())); err != nil {
		return fmt.Errorf("close human report spool: %w", err)
	}
	return nil
}
