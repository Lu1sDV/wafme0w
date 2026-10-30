package wafmeow

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestCapturedSerializedRecordLineEndings(t *testing.T) {
	engine, config := emptyEngine(t), DefaultConfig()
	for _, format := range []string{"native", "httpx"} {
		t.Run(format, func(t *testing.T) {
			prefix, suffix, padding := `{"target":"saved","evidence":[`, `]}`, " "
			if format == "httpx" {
				prefix, suffix, padding = `{"url":"https://example.test/","ignored":"`, `"}`, "x"
			}
			for _, boundary := range []struct {
				name     string
				extra    int
				trailing string
			}{
				{name: "exact-limit"},
				{name: "one-byte-over", extra: 1},
				{name: "whitespace-over", trailing: " "},
				{name: "unicode-whitespace-over", extra: -1, trailing: "\u00a0"},
			} {
				record := prefix + strings.Repeat(padding, maxCaptureRecordBytes-len(prefix)-len(suffix)+boundary.extra) + suffix + boundary.trailing
				for _, ending := range []struct{ name, text string }{{"EOF", ""}, {"LF", "\n"}, {"CRLF", "\r\n"}} {
					t.Run(fmt.Sprintf("%s/%s", boundary.name, ending.name), func(t *testing.T) {
						calls := 0
						emit := func(Result) error { calls++; return nil }
						input := strings.NewReader(record + ending.text)
						var err error
						if format == "native" {
							err = RunCaptured(context.Background(), engine, input, config, emit)
						} else {
							err = RunHTTPXCaptured(context.Background(), engine, input, config, HTTPXImportOptions{}, emit)
						}
						if len(record) == maxCaptureRecordBytes && (err != nil || calls != 1) {
							t.Fatalf("exact-limit record rejected: calls=%d err=%v", calls, err)
						}
						if len(record) > maxCaptureRecordBytes && (err == nil || calls != 0) {
							t.Fatalf("oversized record accepted: calls=%d err=%v", calls, err)
						}
					})
				}
			}
		})
	}
}

func TestRunCapturedPreservesSurroundingWhitespace(t *testing.T) {
	for _, whitespace := range []struct{ name, text string }{
		{"ASCII", " \t"}, {"NBSP", "\u00a0"}, {"ideographic-space", "\u3000"},
	} {
		t.Run(whitespace.name, func(t *testing.T) {
			record := whitespace.text + `{"target":"saved","evidence":[]}` + whitespace.text + "\r\n"
			calls := 0
			err := RunCaptured(context.Background(), emptyEngine(t), strings.NewReader(record), DefaultConfig(), func(result Result) error {
				calls++
				if result.Target != "saved" {
					t.Errorf("capture target changed: %q", result.Target)
				}
				return nil
			})
			if err != nil || calls != 1 {
				t.Fatalf("surrounding whitespace rejected: calls=%d err=%v", calls, err)
			}
		})
	}
}
