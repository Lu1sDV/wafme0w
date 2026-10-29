package offlinebench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	maxCorpusArrayEntries = 4096
	maxCaseResponses      = 64
	maxCorpusObjectFields = 64
	maxCorpusDepth        = 16
	maxCorpusValues       = 65536
)

// Admit structure before decoding either Corpus or its fixture RawMessages.
// Byte limits alone do not bound the expansion of arrays of tiny objects into
// Go structs. The global value budget also bounds many individually legal arrays.
func admitCorpusJSON(ctx context.Context, data []byte) error {
	decoder := json.NewDecoder(contextReader{ctx, bytes.NewReader(data)})
	decoder.UseNumber()
	admission := corpusAdmission{ctx: ctx, decoder: decoder, remaining: maxCorpusValues}
	if err := admission.value("", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("trailing JSON value")
	}
	return ctx.Err()
}

type corpusAdmission struct {
	ctx       context.Context
	decoder   *json.Decoder
	remaining int
}

func (admission *corpusAdmission) value(field string, depth int) error {
	if err := admission.ctx.Err(); err != nil {
		return err
	}
	if depth > maxCorpusDepth {
		return fmt.Errorf("nesting exceeds %d levels", maxCorpusDepth)
	}
	if admission.remaining == 0 {
		return fmt.Errorf("exceeds %d JSON values", maxCorpusValues)
	}
	admission.remaining--
	token, err := admission.decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		for fields := 0; admission.decoder.More(); fields++ {
			if fields == maxCorpusObjectFields {
				return fmt.Errorf("object exceeds %d fields", maxCorpusObjectFields)
			}
			key, err := admission.decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("object field must be a string")
			}
			if err := admission.value(name, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		limit := maxCorpusArrayEntries
		// Match encoding/json's case-insensitive field-name interpretation.
		switch {
		case strings.EqualFold(field, "responses"):
			limit = maxCaseResponses
		case strings.EqualFold(field, "headers"):
			limit = maxHeaders
		}
		for entries := 0; admission.decoder.More(); entries++ {
			if entries == limit {
				return fmt.Errorf("%q array exceeds %d entries", field, limit)
			}
			if err := admission.value("", depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = admission.decoder.Token() // Consume and validate the closing delimiter.
	return err
}
