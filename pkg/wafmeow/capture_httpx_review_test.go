package wafmeow

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestHTTPXOfflineAttributionPreservesProducerURLs(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Status", Pattern: "200"})
	config := DefaultConfig()
	config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("offline identity caused network acquisition")
		return nil, context.Canceled
	})}
	for _, identity := range []string{
		"https://example.test/#section", "https://example.test/#",
		"https://例え.test/path", "https://user:secret@example.test/path",
	} {
		for _, field := range []string{"url", "final_url"} {
			t.Run(field+"/"+identity, func(t *testing.T) {
				record := map[string]any{"url": "https://example.test/", "status_code": 200}
				record[field] = identity
				result := httpxResults(t, engine, makeHTTPXRecord(t, record), config, HTTPXImportOptions{})[0]
				got := result.Target
				if field == "url" && result.Evidence[0].RequestURL != identity {
					t.Fatalf("requested attribution changed: %+v", result.Evidence)
				}
				if field == "final_url" {
					got = result.Evidence[0].EffectiveURL
				}
				if got != identity || len(result.Outcome.Matches) != 1 || result.Evidence[0].Availability.Body != ChannelUnavailable {
					t.Fatalf("offline identity lost or invented evidence: %+v", result)
				}
			})
		}
	}
}

func TestHTTPXDumpRecoversOmittedStatus(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Status", Pattern: "403"})
	for _, encoding := range []HTTPXResponseEncoding{HTTPXText, HTTPXBase64} {
		for _, state := range []string{"absent", "null", "zero", "conflict", "malformed"} {
			t.Run(string(encoding)+"/"+state, func(t *testing.T) {
				raw := "HTTP/1.1 403 Forbidden\r\nServer: fixture\r\n\r\n"
				if state == "malformed" {
					raw += "not a header block\r\n\r\n"
				}
				if encoding == HTTPXBase64 {
					raw = base64.StdEncoding.EncodeToString([]byte(raw))
				}
				record := map[string]any{"url": "https://example.test/", "raw_header": raw}
				switch state {
				case "null":
					record["status_code"] = nil
				case "zero":
					record["status_code"] = 0
				case "conflict":
					record["status_code"] = 200
				}
				result := httpxResults(t, engine, makeHTTPXRecord(t, record), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: encoding})[0]
				want := 403
				if state == "conflict" || state == "malformed" {
					want = 0
				}
				if result.Evidence[0].StatusCode != want || (len(result.Outcome.Matches) == 1) != (want == 403) {
					t.Fatalf("dump status not independently interpreted: %+v", result)
				}
			})
		}
	}
}

func TestHTTPXHeaderDumpRejectsTrailingMaterial(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "^cloudflare$"})
	for _, encoding := range []HTTPXResponseEncoding{HTTPXText, HTTPXBase64} {
		for _, tail := range []string{"HTTP/1.1 403 Forbidden\r\nServer: origin\r\n\r\n", "not a header\r\n\r\n"} {
			t.Run(string(encoding)+"/"+tail, func(t *testing.T) {
				raw := "HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n" + tail
				if encoding == HTTPXBase64 {
					raw = base64.StdEncoding.EncodeToString([]byte(raw))
				}
				result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw}), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: encoding})[0]
				hasDiagnostic := false
				for _, diagnostic := range result.Outcome.Diagnostics {
					hasDiagnostic = hasDiagnostic || diagnostic.Code == "import_httpx_headers"
				}
				if len(result.Outcome.Matches) != 0 || result.Evidence[0].StatusCode != 200 || result.Evidence[0].Availability.Headers != ChannelUnavailable || !hasDiagnostic {
					t.Fatalf("trailing header material admitted: %+v", result)
				}
			})
		}
	}
}

func TestHTTPXBase64PaddingTerminatesEntireField(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "^cloudflare$"})
	for _, padding := range []int{483, 484, 485} {
		first := "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", padding)
		tail := "\r\nServer: cloudflare\r\n\r\n"
		for _, valid := range []bool{false, true} {
			t.Run(fmt.Sprintf("header/pad-%d/single-%t", padding, valid), func(t *testing.T) {
				raw := base64.StdEncoding.EncodeToString([]byte(first)) + base64.StdEncoding.EncodeToString([]byte(tail))
				if valid {
					raw = base64.StdEncoding.EncodeToString([]byte(first + tail))
				}
				// Without padding at the join, the encodings are a valid single value.
				wantMatch := valid || len(first)%3 == 0
				result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "raw_header": raw}), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: HTTPXBase64})[0]
				if (len(result.Outcome.Matches) == 1) != wantMatch || (!wantMatch && result.Evidence[0].Availability.Headers != ChannelUnavailable) || result.Evidence[0].StatusCode != 200 {
					t.Fatalf("base64 header framing lost: %+v", result)
				}
			})
		}
	}
	for _, prefix := range []int{254, 255, 256} {
		body := strings.Repeat("AAAA", prefix) + "YQ==YQ=="
		result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 200, "body": body}), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: HTTPXBase64})[0]
		if result.Evidence[0].Availability.Body != ChannelUnavailable || result.Evidence[0].StatusCode != 200 {
			t.Fatalf("concatenated body accepted at prefix %d: %+v", prefix, result.Evidence)
		}
	}
}
