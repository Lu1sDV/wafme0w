package wafmeow_test

import (
	"context"
	"io"
	"strings"
	"testing"

	waf "github.com/Lu1sDV/wafmeow/v2/pkg/wafmeow"
)

// Compile the documented runner signatures from an external consumer package.
var (
	_ func(context.Context, *waf.Engine, io.Reader, waf.Config, func(waf.Result) error) error                         = waf.Run
	_ func(context.Context, *waf.Engine, io.Reader, waf.Config, func(waf.Result) error) error                         = waf.RunCaptured
	_ func(context.Context, *waf.Engine, io.Reader, waf.Config, waf.HTTPXImportOptions, func(waf.Result) error) error = waf.RunHTTPXCaptured
)

func TestExternalV2CaptureContracts(t *testing.T) {
	engine, err := waf.Compile([]waf.WAF{{Name: "body fixture", Schemas: []waf.Scheme{{FingerPrints: []waf.FingerPrint{{Type: "Content", Pattern: "marker"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	var result waf.Result
	emit := func(r waf.Result) error { result = r; return nil }
	err = waf.RunHTTPXCaptured(context.Background(), engine, strings.NewReader(`{"url":"https://example.test/","status_code":200,"body":"marker"}`), waf.DefaultConfig(), waf.HTTPXImportOptions{}, emit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome.State != waf.Incomplete || len(result.Outcome.Matches) != 0 || result.Evidence[0].Availability.Body != waf.ChannelUnknown {
		t.Fatalf("imported body became complete: %+v", result)
	}
	err = waf.RunCaptured(context.Background(), engine, strings.NewReader(`{"target":"native","evidence":[{"role":"Normal","status_code":200,"body":"bWFya2Vy"}]}`), waf.DefaultConfig(), emit)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome.State != waf.Complete || len(result.Outcome.Matches) != 1 || result.Outcome.Matches[0].Product != "body fixture" || result.Evidence[0].Availability != nil {
		t.Fatalf("legacy native contract changed: %+v", result)
	}
}
