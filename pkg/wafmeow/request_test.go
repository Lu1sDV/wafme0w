package wafmeow

import (
	"strings"
	"testing"
)

func TestCentralProbeCarriesSQLiXSSPolyglot(t *testing.T) {
	options := newTypeOptions("http://fixture.invalid/base")
	if len(options) != 8 {
		t.Fatalf("probe count = %d, want 8 with standalone JndiAttack", len(options))
	}
	var central, jndi requestOpts
	for _, option := range options {
		if option.Type == "RceAttack" || option.Type == "SqliAttack" {
			t.Fatalf("removed probe %s is still present", option.Type)
		}
		switch option.Type {
		case "CentralAttack":
			central = option
		case "JndiAttack":
			jndi = option
		}
	}
	const xss = `"><script>alert("XSS")</script>`
	if got := central.Params["d"]; got != xss {
		t.Fatalf("central XSS = %q, want %q", got, xss)
	}
	if got := central.Params["l2"]; got != `..\..\..\..\etc\passwd` {
		t.Fatalf("central backslash traversal = %q", got)
	}
	if got := central.Params["c"]; got != ";wafme0w-canary" {
		t.Fatalf("central command canary = %q", got)
	}
	if _, ok := central.Params["j"]; ok {
		t.Fatal("JNDI payload is still embedded in CentralAttack")
	}
	if got := jndi.Params["p"]; got != `${jndi:ldap://127.0.0.1:1/a}` {
		t.Fatalf("standalone JNDI canary = %q", got)
	}
	if got := central.Params["r"]; got != "\r\nX-Wafme0w: canary" {
		t.Fatalf("central CRLF canary = %q", got)
	}
	if got := central.Params["h"]; got != "() { :;};" {
		t.Fatalf("central Shellshock canary = %q", got)
	}
	payload := central.Params["v"]
	for _, fragment := range []string{"'", "OR 1=1", "UNION SELECT", "information_schema", "SLEEP(5)", "-- -", xss} {
		if !strings.Contains(payload, fragment) {
			t.Fatalf("central polyglot lost %q: %q", fragment, payload)
		}
	}
}
