package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jessevdk/go-flags"
)

// Guidance never reparses an argument or turns an unknown spelling into an
// alias. Keep the parser error available to callers and escape the combined
// message at the same terminal boundary as other CLI errors.
func withArgumentGuidance(parser *flags.Parser, err error) error {
	var flagErr *flags.Error
	if !errors.As(err, &flagErr) || flagErr.Type != flags.ErrUnknownFlag {
		return err
	}
	name, ok := strings.CutPrefix(flagErr.Message, "unknown flag `")
	if ok {
		name, ok = strings.CutSuffix(name, "'")
	}
	if ok {
		switch name {
		case "o":
			return fmt.Errorf("%w; use --output FILE or -O FILE; short flags are case-sensitive", err)
		case "i":
			return fmt.Errorf("%w; use --target-file FILE or -I FILE; short flags are case-sensitive", err)
		}
		// Suggest only an unambiguous nearby long option. Single-character
		// flags have different meanings across tools; do not guess at them.
		if len(name) >= 3 {
			var candidates []string
			var visit func(*flags.Group)
			visit = func(group *flags.Group) {
				for _, option := range group.Options() {
					if !option.Hidden && option.LongName != "" && nearbyFlagName(name, option.LongName) {
						candidates = append(candidates, "--"+option.LongName)
					}
				}
				for _, child := range group.Groups() {
					visit(child)
				}
			}
			visit(parser.Group)
			if len(candidates) == 1 {
				return fmt.Errorf("%w; did you mean %s? Use --help for usage", err, candidates[0])
			}
		}
	}
	return fmt.Errorf("%w; use --help for available options", err)
}

// Flag names are ASCII. Accept a case difference, one insertion/deletion or
// substitution, or one adjacent transposition as a suggestion candidate.
func nearbyFlagName(left, right string) bool {
	left, right = strings.ToLower(left), strings.ToLower(right)
	if left == right {
		return true
	}
	if len(left) == len(right) {
		first, second := -1, -1
		for i := 0; i < len(left); i++ {
			if left[i] == right[i] {
				continue
			}
			if first == -1 {
				first = i
			} else if second == -1 {
				second = i
			} else {
				return false
			}
		}
		return second == -1 || second == first+1 && left[first] == right[second] && left[second] == right[first]
	}
	if len(left) > len(right) {
		left, right = right, left
	}
	if len(right)-len(left) != 1 {
		return false
	}
	for i := 0; i < len(left); i++ {
		if left[i] != right[i] {
			return left[i:] == right[i+1:]
		}
	}
	return true
}

const headerCSVRecovery = `--header requires CSV-quoted fields when values contain commas or quotes; quote the whole Name: value entry and double embedded quotes. POSIX shell examples: -H '"Accept: text/html, application/json"' or -H '"If-None-Match: ""abc"""'`

// Native captures reject a result report at its schema_version field. Add a
// CLI-only explanation after that existing rejection; do not sniff or rewrite
// input, change the decoder, or discard valid records already emitted.
func withCaptureInputGuidance(opts options, err error) error {
	if err == nil || opts.EvidenceFile == "" || opts.EvidenceFormat != "native" {
		return err
	}
	message := err.Error()
	if strings.Contains(message, "decode capture line ") && strings.Contains(message, `json: unknown field "schema_version"`) {
		return fmt.Errorf("%w; --jsonl and --output create result reports, not response captures; --evidence needs native capture JSONL or an httpx response export with --evidence-format=httpx", err)
	}
	return err
}
