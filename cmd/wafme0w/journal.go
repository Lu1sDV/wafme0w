package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

type journalRecord struct {
	Type       string              `json:"type"`
	Result     *wafme0w.Result     `json:"result,omitempty"`
	Diagnostic *wafme0w.Diagnostic `json:"diagnostic,omitempty"`
}

// A journal is deliberately independent of the atomic final report. Each
// complete record reaches Sync before any report or console sink sees it.
// It is evidence for recovery, never a list of work to resume automatically.
type diagnosticsJournal struct {
	file    *os.File
	encoder *json.Encoder
	err     error
}

func openJournal(path string) (*diagnosticsJournal, error) {
	if path == "" {
		return nil, nil
	}
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("diagnostics journal must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect diagnostics journal: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open diagnostics journal: %w", err)
	}
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = errors.New("diagnostics journal must be a regular file")
	}
	if err == nil && info.Size() != 0 {
		var last [1]byte
		_, err = file.ReadAt(last[:], info.Size()-1)
		if err == nil && last[0] != '\n' {
			err = errors.New("diagnostics journal has an incomplete last record; preserve it and choose a new journal")
		}
	}
	if err != nil {
		return nil, fmt.Errorf("inspect diagnostics journal: %w", errors.Join(err, file.Close()))
	}
	return &diagnosticsJournal{file: file, encoder: json.NewEncoder(file)}, nil
}

func (journal *diagnosticsJournal) write(record journalRecord) error {
	if journal == nil {
		return nil
	}
	if journal.err != nil {
		return journal.err
	}
	if err := journal.encoder.Encode(record); err != nil {
		journal.err = fmt.Errorf("append diagnostics journal: %w", err)
	} else if err := journal.file.Sync(); err != nil {
		journal.err = fmt.Errorf("sync diagnostics journal: %w", err)
	}
	return journal.err
}

func (journal *diagnosticsJournal) result(result wafme0w.Result) error {
	if journal == nil {
		return nil
	}
	return journal.write(journalRecord{Type: "result", Result: &result})
}

func (journal *diagnosticsJournal) diagnostic(code, message string) error {
	if journal == nil {
		return nil
	}
	return journal.write(journalRecord{Type: "diagnostic", Diagnostic: &wafme0w.Diagnostic{Code: code, Evidence: -1, Message: message}})
}

func (journal *diagnosticsJournal) close() error {
	if journal == nil {
		return nil
	}
	if err := errors.Join(journal.file.Sync(), journal.file.Close()); err != nil {
		return fmt.Errorf("close diagnostics journal: %w", err)
	}
	return nil
}

type pathIdentity struct {
	label  string
	path   string
	info   os.FileInfo
	writes bool
}

func identifyPath(label, path string, writes bool) (pathIdentity, error) {
	identity := pathIdentity{label: label, writes: writes}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return identity, err
	}
	identity.path = absolute
	identity.info, err = os.Stat(absolute)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return identity, err
	}
	identity.path, err = resolvePath(absolute, 0)
	return identity, err
}

// EvalSymlinks alone cannot identify aliases whose destination does not exist
// yet. Follow dangling links too, before opening an append-only journal.
func resolvePath(path string, links int) (string, error) {
	if links >= 40 {
		return "", errors.New("too many symbolic links in output path")
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	}
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(path), target)
		}
		return resolvePath(target, links+1)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	resolved, err := resolvePath(parent, links)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(path)), nil
}

func checkFileCollisions(opts options, stdin io.Reader, piped bool, stdout, stderr io.Writer) error {
	var identities []pathIdentity
	for _, item := range []struct {
		label, path string
		writes      bool
	}{
		{"target input", opts.InputFile, false},
		{"evidence input", opts.EvidenceFile, false},
		{"fingerprints", opts.FingerPrintFile, false},
		{"output", opts.OutputFile, true},
		{"diagnostics journal", opts.JournalFile, true},
	} {
		if item.path == "" || item.label == "evidence input" && item.path == "-" {
			continue
		}
		identity, err := identifyPath(item.label, item.path, item.writes)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", item.label, err)
		}
		identities = append(identities, identity)
	}
	usesStdin := opts.EvidenceFile == "-" || opts.EvidenceFile == "" && opts.InputFile == "" && opts.Target == "" && piped
	for _, stream := range []struct {
		label        string
		value        any
		used, writes bool
	}{
		{"stdin", stdin, usesStdin, false},
		{"stdout", stdout, opts.JSONL || !opts.Silent, true},
		{"stderr", stderr, true, true},
	} {
		if file, ok := stream.value.(*os.File); ok && stream.used {
			info, err := file.Stat()
			if err != nil {
				return fmt.Errorf("inspect %s: %w", stream.label, err)
			}
			if info.Mode().IsRegular() {
				identities = append(identities, pathIdentity{label: stream.label, info: info, writes: stream.writes})
			}
		}
	}
	for i, left := range identities {
		for _, right := range identities[i+1:] {
			if !left.writes && !right.writes {
				continue
			}
			// stdout and stderr may intentionally share one redirected log.
			if left.label == "stdout" && right.label == "stderr" {
				continue
			}
			samePath := left.path != "" && left.path == right.path
			sameFile := left.info != nil && right.info != nil && os.SameFile(left.info, right.info)
			if samePath || sameFile {
				return fmt.Errorf("%s and %s must not refer to the same file", left.label, right.label)
			}
		}
	}
	return nil
}
