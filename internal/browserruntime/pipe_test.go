package browserruntime

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestPipeFramingBounds(t *testing.T) {
	var wire bytes.Buffer
	pipe := newPipe(strings.NewReader("{\"id\":1}\x00{\"id\":2}\x00"), &wire)
	for _, want := range []string{`{"id":1}`, `{"id":2}`} {
		got, err := pipe.Read()
		if err != nil || string(got) != want {
			t.Fatalf("message = %q, %v; want %s", got, err, want)
		}
		if err := pipe.Send(got); err != nil {
			t.Fatal(err)
		}
	}
	if wire.String() != "{\"id\":1}\x00{\"id\":2}\x00" {
		t.Fatalf("wire = %q", wire.String())
	}
	for name, input := range map[string]string{
		"invalid JSON": "{oops}\x00",
		"truncated":    "{\"id\":1}",
		"oversized":    strings.Repeat(" ", maxMessageBytes+1) + "\x00",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newPipe(strings.NewReader(input), io.Discard).Read(); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}
