package wafme0w

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestRunCapturedChecksCollectionLimitsBeforeDecodingExcessElement(t *testing.T) {
	// The first disallowed element has a valid JSON type that cannot decode into
	// the destination. A count error proves that it was rejected before decoding,
	// without constructing a large input or relying on allocator measurements.
	for name, test := range map[string]struct {
		record string
		want   string
	}{
		"observations": {
			`{"target":"saved","evidence":[` + strings.Repeat(`{"role":"Normal"},`, 64) + `false]}`,
			"at most 64 observations",
		},
		"headers": {
			`{"target":"saved","evidence":[{"role":"Normal","headers":[` + strings.Repeat(`{"name":"X-Test","value":"fixture"},`, 4096) + `false]}]}`,
			"more than 4096 header values",
		},
		"redirects": {
			`{"target":"saved","evidence":[{"role":"Normal","redirect_chain":[` + strings.Repeat(`"https://fixture.test/",`, 4096) + `false]}]}`,
			"more than 4096 redirect destinations",
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := RunCaptured(context.Background(), emptyEngine(t), strings.NewReader(test.record), DefaultConfig(), func(Result) error {
				t.Error("over-limit collection emitted a result")
				return nil
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("excess element was decoded before the count limit: %v", err)
			}
		})
	}
}

func TestNativeCaptureBoundedDecodePreservesJSONContracts(t *testing.T) {
	for name, record := range map[string]string{
		"empty":                    `{"target":"saved","evidence":[]}`,
		"legacy null availability": `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"availability":null}]}`,
		"explicit availability":    `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"availability":{"status":"complete","headers":"complete","reason":"complete","body":"unknown"}}]}`,
		"null collections":         `{"target":"saved","evidence":[{"role":"Normal","headers":null,"redirect_chain":null}]}`,
		"case folded fields":       `{"TARGET":"saved","EVIDENCE":[{"ROLE":"Normal","HEADERS":[{"NAME":"X-Test","VALUE":"fixture"}],"REDIRECT_CHAIN":["fixture"]}]}`,
		"repeated evidence":        `{"target":"saved","evidence":[{"role":"Normal","status_code":200,"headers":[{"name":"X-Test","value":"fixture"}]}],"evidence":[{"reason":"OK"}]}`,
		"repeated headers":         `{"target":"saved","evidence":[{"role":"Normal","headers":[{"name":"X-Test","value":"fixture"}],"headers":[{"value":"replacement"}]}]}`,
		"null observation":         `{"target":"saved","evidence":[null]}`,
		"unknown capture field":    `{"target":"saved","evidence":[],"unexpected":true}`,
		"unknown evidence field":   `{"target":"saved","evidence":[{"role":"Normal","unexpected":true}]}`,
		"unknown header field":     `{"target":"saved","evidence":[{"role":"Normal","headers":[{"name":"X-Test","value":"fixture","unexpected":true}]}]}`,
		"repeated availability":    `{"target":"saved","evidence":[{"role":"Normal","availability":null,"availability":null}]}`,
		"repeated channel":         `{"target":"saved","evidence":[{"role":"Normal","availability":{"status":"complete","status":"unavailable"}}]}`,
		"invalid header array":     `{"target":"saved","evidence":[{"role":"Normal","headers":{}}]}`,
		"invalid observation":      `{"target":"saved","evidence":[false]}`,
	} {
		t.Run(name, func(t *testing.T) {
			var want Capture
			decoder := json.NewDecoder(bytes.NewReader([]byte(record)))
			decoder.DisallowUnknownFields()
			wantErr := decoder.Decode(&want)
			got, err := decodeNativeCapture(context.Background(), []byte(record))
			if (err == nil) != (wantErr == nil) || err == nil && !reflect.DeepEqual(got, want) {
				t.Fatalf("native JSON contract changed: got=%+v err=%v; want=%+v err=%v", got, err, want, wantErr)
			}
		})
	}
}

func TestNativeCaptureBoundedDecodeHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := decodeNativeCapture(ctx, []byte(`{"target":"saved","evidence":[]}`))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled native decoding lost cancellation: %v", err)
	}
}

func TestRunCapturedAcceptsCollectionLimitBoundaries(t *testing.T) {
	for name, record := range map[string]string{
		"observations": `{"target":"saved","evidence":[` + strings.Repeat(`{"role":"Normal"},`, 63) + `{"role":"Normal"}]}`,
		"headers":      `{"target":"saved","evidence":[{"role":"Normal","headers":[` + strings.Repeat(`{"name":"X-Test","value":"fixture"},`, 4095) + `{"name":"X-Test","value":"fixture"}]}]}`,
		"redirects":    `{"target":"saved","evidence":[{"role":"Normal","redirect_chain":[` + strings.Repeat(`"https://fixture.test/",`, 4095) + `"https://fixture.test/"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			err := RunCaptured(context.Background(), emptyEngine(t), strings.NewReader(record), DefaultConfig(), func(Result) error {
				calls++
				return nil
			})
			if err != nil || calls != 1 {
				t.Fatalf("valid collection boundary rejected: err=%v calls=%d", err, calls)
			}
		})
	}
}
