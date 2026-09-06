package httpmeta

import (
	"strings"
	"testing"
)

func TestValidHeaderNameTokenBytes(t *testing.T) {
	const token = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if ValidHeaderName("") {
		t.Fatal("empty field name is not a token")
	}
	for value := range 256 {
		c := byte(value)
		name := "X-" + string([]byte{c}) + "-Field"
		if got, want := ValidHeaderName(name), strings.IndexByte(token, c) >= 0; got != want {
			t.Fatalf("field name containing byte %#02x: valid=%t, want %t", c, got, want)
		}
	}
}
