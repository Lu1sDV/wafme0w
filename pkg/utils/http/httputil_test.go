package httputil

import "testing"

func TestParseURIPreservesComponents(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"HTTP://Example.COM:8080/Case%2fKept?Token=Ab%2B&n=One", "http://Example.COM:8080/Case%2fKept?Token=Ab%2B&n=One"},
		{"localhost:8080/Case?next=https://Other.invalid/Path", "https://localhost:8080/Case?next=https://Other.invalid/Path"},
		{"[::1]:8443/Case", "https://[::1]:8443/Case"},
		{"127.0.0.1/Case", "https://127.0.0.1/Case"},
		{"example.invalid./", "https://example.invalid./"},
	} {
		t.Run(test.input, func(t *testing.T) {
			parsed, err := ParseURI(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.String() != test.want {
				t.Fatalf("URL = %q, want %q", parsed.String(), test.want)
			}
		})
	}
}

func TestParseURIRejectsAmbiguousOrUnsupportedURLs(t *testing.T) {
	for _, input := range []string{
		"", " example.invalid", "example.invalid ", "!", "ftp://localhost", "file:///tmp/local", "//example.invalid",
		"http:::/not.valid/a//a", "http:///path", "http://user:pass@example.invalid", "http://example.invalid/#", "http://example.invalid/#part",
		"http://example.invalid:", "http://example.invalid:0", "http://example.invalid:65536", "http://example.invalid:bad",
		"http://[::1", "http://::1", "http://[127.0.0.1]", "http://[fe80::1%25eth0]", "http://[::1]suffix",
		"http://999.1.1.1", "http://127.000.0.1", "http://12345", "http://-bad.invalid", "http://bad-.invalid",
		"http://bad..invalid", "http://under_score.invalid", "http://éxample.invalid", "http://example.invalid/a%ZZ", "http://example.invalid/?q=%ZZ",
	} {
		t.Run(input, func(t *testing.T) {
			if parsed, err := ParseURI(input); err == nil {
				t.Fatalf("accepted invalid URL %q as %s", input, parsed)
			}
		})
	}
}

func TestParseURIPreservesOpaqueQuerySeparators(t *testing.T) {
	const target = "https://fixture.invalid/Case?section=A;B&key=One+Two"
	parsed, err := ParseURI(target)
	if err != nil || parsed.String() != target {
		t.Fatalf("valid opaque query was changed: parsed=%v err=%v", parsed, err)
	}
}
