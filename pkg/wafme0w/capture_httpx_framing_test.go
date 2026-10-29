package wafme0w

import (
	"encoding/base64"
	"testing"
)

func TestHTTPXHeaderDumpEmptyChunkTerminator(t *testing.T) {
	engine := httpxEngine(t, FingerPrint{Type: "Header", HeaderKey: "Server", HeaderValue: "^cloudflare$"})
	for _, encoding := range []HTTPXResponseEncoding{HTTPXText, HTTPXBase64} {
		for _, tc := range []struct {
			name, transfer, tail string
			match                bool
		}{
			{"producer empty chunk", "Transfer-Encoding: chunked\r\n", "0\r\n\r\n", true},
			{"no transfer encoding", "", "0\r\n\r\n", false},
			{"different transfer", "Transfer-Encoding: gzip\r\n", "0\r\n\r\n", false},
			{"nonempty chunk", "Transfer-Encoding: chunked\r\n", "1\r\na\r\n0\r\n\r\n", false},
			{"trailer injection", "Transfer-Encoding: chunked\r\n", "0\r\nServer: origin\r\n\r\n", false},
			{"second response", "Transfer-Encoding: chunked\r\n", "0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", false},
		} {
			t.Run(string(encoding)+"/"+tc.name, func(t *testing.T) {
				raw := "HTTP/1.1 304 Not Modified\r\n" + tc.transfer + "Server: cloudflare\r\n\r\n" + tc.tail
				if encoding == HTTPXBase64 {
					raw = base64.StdEncoding.EncodeToString([]byte(raw))
				}
				result := httpxResults(t, engine, makeHTTPXRecord(t, map[string]any{"url": "https://example.test/", "status_code": 304, "raw_header": raw}), DefaultConfig(), HTTPXImportOptions{ResponseEncoding: encoding})[0]
				if (len(result.Outcome.Matches) == 1) != tc.match || result.Evidence[0].StatusCode != 304 {
					t.Fatalf("producer framing changed header or independent status: %+v", result)
				}
			})
		}
	}
}
