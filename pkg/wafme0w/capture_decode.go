package wafme0w

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	maxCaptureObservations = 64
	maxCaptureHeaders      = 4096
	maxCaptureRedirects    = 4096
)

// The raw-record budget does not bound the expansion of small JSON array
// elements into Go structs. Decode native capture collections one element at a
// time and check their limits before decoding or allocating the next element.
// Keep these limits on the importer, not the public Evidence JSON API.
func decodeNativeCapture(ctx context.Context, record []byte) (Capture, error) {
	type captureJSON Capture
	var capture captureJSON
	fields := struct {
		*captureJSON
		Evidence captureArrayJSON[Evidence] `json:"evidence"`
	}{
		captureJSON: &capture,
		Evidence: captureArrayJSON[Evidence]{
			ctx: ctx, limit: maxCaptureObservations,
			limitError: "evidence must be an array of at most 64 observations",
			decode: func(decoder *json.Decoder, evidence *Evidence) error {
				bounded := captureEvidenceJSON{ctx: ctx, evidence: *evidence}
				if err := decoder.Decode(&bounded); err != nil {
					return err
				}
				*evidence = bounded.evidence
				return nil
			},
		},
	}
	decoder := newCaptureJSONDecoder(ctx, record)
	if err := decoder.Decode(&fields); err != nil {
		return Capture{}, err
	}
	// Only inspect the next token. Decoding an arbitrary trailing value into an
	// interface could itself expand a rejected array or object without a bound.
	if _, err := decoder.Token(); err != io.EOF {
		if err := ctx.Err(); err != nil {
			return Capture{}, err
		}
		return Capture{}, errors.New("must contain exactly one JSON object")
	}
	capture.Evidence = fields.Evidence.values
	return Capture(capture), ctx.Err()
}

type captureEvidenceJSON struct {
	ctx      context.Context
	evidence Evidence
}

func (bounded *captureEvidenceJSON) UnmarshalJSON(data []byte) error {
	// Mirror Evidence.UnmarshalJSON's availability handling while replacing only
	// the two collections with bounded decoders. Embedded scalar/body fields keep
	// encoding/json's existing types, field matching, and strict unknown checks.
	type evidenceJSON Evidence
	decoded := evidenceJSON(bounded.evidence)
	fields := struct {
		*evidenceJSON
		Headers       captureArrayJSON[Header] `json:"headers"`
		RedirectChain captureArrayJSON[string] `json:"redirect_chain"`
		Availability  availabilityJSON         `json:"availability"`
	}{
		evidenceJSON: &decoded,
		Headers: captureArrayJSON[Header]{
			ctx: bounded.ctx, values: decoded.Headers, limit: maxCaptureHeaders,
			limitError: "more than 4096 header values",
		},
		RedirectChain: captureArrayJSON[string]{
			ctx: bounded.ctx, values: decoded.RedirectChain, limit: maxCaptureRedirects,
			limitError: "more than 4096 redirect destinations",
		},
	}
	if err := newCaptureJSONDecoder(bounded.ctx, data).Decode(&fields); err != nil {
		return err
	}
	decoded.Headers = fields.Headers.values
	decoded.RedirectChain = fields.RedirectChain.values
	if fields.Availability.seen {
		decoded.Availability = fields.Availability.value
	}
	bounded.evidence = Evidence(decoded)
	return nil
}

type captureArrayJSON[T any] struct {
	ctx        context.Context
	values     []T
	limit      int
	limitError string
	decode     func(*json.Decoder, *T) error
}

func (array *captureArrayJSON[T]) UnmarshalJSON(data []byte) error {
	decoder := newCaptureJSONDecoder(array.ctx, data)
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		array.values = nil
		return nil
	}
	if token != json.Delim('[') {
		return errors.New("expected a JSON array")
	}
	values := array.values[:0]
	if values == nil {
		values = []T{}
	}
	for decoder.More() {
		if err := array.ctx.Err(); err != nil {
			return err
		}
		if len(values) == array.limit {
			return errors.New(array.limitError)
		}
		index := len(values)
		// Retain encoding/json's slice-element reuse for repeated fields.
		if index < cap(values) {
			values = values[:index+1]
		} else {
			var value T
			values = append(values, value)
		}
		if array.decode != nil {
			err = array.decode(decoder, &values[index])
		} else {
			err = decoder.Decode(&values[index])
		}
		if err != nil {
			return fmt.Errorf("element %d: %w", index, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if len(values) == 0 {
		values = []T{}
	}
	array.values = values
	return array.ctx.Err()
}

type captureContextReader struct {
	ctx    context.Context
	reader *bytes.Reader
}

func (reader captureContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

func newCaptureJSONDecoder(ctx context.Context, data []byte) *json.Decoder {
	decoder := json.NewDecoder(captureContextReader{ctx: ctx, reader: bytes.NewReader(data)})
	decoder.DisallowUnknownFields()
	return decoder
}
