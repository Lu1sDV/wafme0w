package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

func TestBrowserArtifactsPrivateSeparateAndAtomic(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("local browser artifact publication requires Linux")
	}
	root := filepath.Join(t.TempDir(), "saved")
	artifacts := newBrowserArtifacts(root)
	t.Cleanup(func() {
		if err := artifacts.close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("artifact configuration wrote storage: %v", err)
	}
	paths := make(map[string]bool)
	for _, content := range []string{"bounded sanitized image", "second bounded image"} {
		artifact := wafme0w.BrowserArtifact{CaptureID: "../../unsafe", MIME: "image/png", Content: strings.NewReader(content)}
		path, err := artifacts.saveScreenshot(context.Background(), artifact)
		if err != nil {
			t.Fatal(err)
		}
		if paths[path] || filepath.Ext(path) != ".png" || filepath.Dir(filepath.Dir(path)) != root || strings.Contains(path, "unsafe") {
			t.Fatalf("unsafe, duplicate or misrouted artifact path: %q", path)
		}
		paths[path] = true
		data, err := os.ReadFile(path)
		if err != nil || string(data) != content {
			t.Fatalf("artifact bytes: %q, %v", data, err)
		}
		for _, private := range []string{path, filepath.Dir(path)} {
			info, err := os.Stat(private)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatalf("artifact is not private: %s, %v", private, err)
			}
		}
	}
	sentinel := errors.New("source failed")
	path, err := artifacts.saveScreenshot(context.Background(), wafme0w.BrowserArtifact{MIME: "image/png", Content: failingArtifactReader{sentinel}})
	if path != "" || !errors.Is(err, sentinel) {
		t.Fatalf("failed content published: %q, %v", path, err)
	}
	for directory := range artifacts.directories {
		entries, err := os.ReadDir(artifacts.directories[directory].path)
		if err != nil || len(entries) != len(paths) {
			t.Fatalf("failed publication left a partial or temporary file: %v, %v", entries, err)
		}
	}
}

type failingArtifactReader struct{ err error }

func (reader failingArtifactReader) Read([]byte) (int, error) { return 0, reader.err }

func TestBrowserArtifactsRejectAliasesAndCancellation(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{alias, filepath.Join(alias, "missing")} {
		if _, err := inspectArtifactRoot(path); err == nil {
			t.Fatalf("symlink artifact root accepted: %q", path)
		}
	}
	for _, opts := range []options{
		{SaveScreenshots: real, JournalFile: alias},
		{Browser: "navigate", BrowserPath: alias, OutputFile: real},
	} {
		if err := checkFileCollisions(opts, nil, false, io.Discard, io.Discard); err == nil {
			t.Fatalf("artifact/browser alias accepted: %+v", opts)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := filepath.Join(base, "cancelled")
	artifacts := newBrowserArtifacts(root)
	path, err := artifacts.saveScreenshot(ctx, wafme0w.BrowserArtifact{MIME: "image/png", Content: strings.NewReader("png")})
	if path != "" || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled publication: %q, %v", path, err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled artifact created storage: %v", err)
	}
}

func TestBrowserSelectionIndependentInformationalCommands(t *testing.T) {
	for _, flag := range []string{"--help", "--version", "--list"} {
		var stdout, stderr bytes.Buffer
		code := runContext(context.Background(), []string{flag, "--browser=screenshot", "--browser-path=/missing/native-browser"}, nil, false, &stdout, &stderr)
		if code != 0 || stdout.Len() == 0 {
			t.Fatalf("%s required browser: exit=%d stderr=%s", flag, code, &stderr)
		}
	}
	root := filepath.Join(t.TempDir(), "uncreated")
	var stdout, stderr bytes.Buffer
	code := runContext(context.Background(), []string{"--browser=screenshot", "--browser-path=/missing/native-browser", "--save-screenshots=" + root, "--target=invalid://target"}, nil, false, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("missing executable did not fail before scan: exit=%d stdout=%s", code, &stdout)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("early validation created artifacts: %v", err)
	}
}

func TestBrowserHelpOmitsDOMArtifactsAndDefaultsToThirtySeconds(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runContext(context.Background(), []string{"--help"}, nil, false, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit=%d stderr=%s", code, &stderr)
	}
	help := stdout.String()
	if strings.Contains(help, "--artifacts") || !strings.Contains(help, "--browser-timeout=") || !strings.Contains(help, "(default: 30s)") {
		t.Fatalf("unexpected browser help:\n%s", help)
	}
}

func TestBrowserRejectsExecutableWrappers(t *testing.T) {
	wrapper := filepath.Join(t.TempDir(), "chromium")
	if err := os.WriteFile(wrapper, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBrowserPath(wrapper); err == nil {
		t.Fatal("shell wrapper accepted as native Chromium")
	}
}

func TestBrowserFailureDoesNotChangeHTTPCounts(t *testing.T) {
	var counts resultCounts
	counts.add(wafme0w.Result{Outcome: wafme0w.Outcome{State: wafme0w.Complete}, Browser: &wafme0w.BrowserReport{State: "complete", DOM: wafme0w.BrowserAsset{SaveState: "failed"}}})
	if counts.Complete != 1 || counts.Unnamed != 1 || counts.Failed != 0 || counts.Diagnostics != 0 || counts.BrowserFailed != 1 || !counts.StrictFailure {
		t.Fatalf("browser saving failure changed HTTP truth or lost strictness: %+v", counts)
	}
}
