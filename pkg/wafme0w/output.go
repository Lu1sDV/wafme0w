package wafme0w

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ResultWriter serializes all results, including complete no-matches and failures.
// Call Close to finish JSON framing; Close never closes the caller's writer.
// Write and Close are serial operations. The first write error is retained.
type ResultWriter struct {
	writer io.Writer
	format string
	csv    *csv.Writer
	json   *json.Encoder
	wrote  bool
	closed bool
	err    error
}

// NewResultWriter accepts json, jsonl, csv, or txt (case-insensitive, optional
// leading dot). File extension selection and publication belong to the caller.
func NewResultWriter(writer io.Writer, format string) (*ResultWriter, error) {
	if writer == nil {
		return nil, errors.New("output writer is required")
	}
	out := &ResultWriter{writer: writer, format: strings.ToLower(strings.TrimPrefix(format, "."))}
	switch out.format {
	case "json":
		out.json = json.NewEncoder(writer)
		_, out.err = io.WriteString(writer, "[")
	case "jsonl":
		out.json = json.NewEncoder(writer)
	case "csv":
		out.csv = csv.NewWriter(writer)
		out.err = out.csv.Write([]string{"target", "state", "matches", "generic", "incomplete_products", "diagnostics", "schema_version", "origin", "provenance", "evidence"})
		out.csv.Flush()
		out.err = errors.Join(out.err, out.csv.Error())
	case "txt":
	default:
		return nil, fmt.Errorf("unsupported output format %q", format)
	}
	if out.err != nil {
		return nil, out.err
	}
	return out, nil
}

func (out *ResultWriter) Write(result Result) error {
	if out.err != nil {
		return out.err
	}
	if out.closed {
		return errors.New("result writer is closed")
	}
	if out.format == "jsonl" {
		out.err = out.json.Encode(result)
		return out.err
	}
	if out.format == "json" {
		if out.wrote {
			_, out.err = io.WriteString(out.writer, ",")
		}
		if out.err == nil {
			out.err = out.json.Encode(result)
		}
		out.wrote = true
		return out.err
	}
	row := []string{result.Target, string(result.Outcome.State)}
	for _, value := range []any{
		result.Outcome.Matches, result.Generic, result.Outcome.IncompleteProducts,
		result.Outcome.Diagnostics, result.SchemaVersion, result.Origin,
		result.Provenance, result.Evidence,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			out.err = err
			return err
		}
		row = append(row, string(encoded))
	}
	if out.format == "csv" {
		out.err = out.csv.Write(row)
		out.csv.Flush()
		out.err = errors.Join(out.err, out.csv.Error())
	} else {
		_, out.err = fmt.Fprintf(out.writer, "%s\tstate=%s\tmatches=%s\tgeneric=%s\tincomplete_products=%s\tdiagnostics=%s\tschema_version=%s\torigin=%s\tprovenance=%s\tevidence=%s\n",
			strconv.QuoteToGraphic(row[0]), strconv.QuoteToGraphic(row[1]), row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9])
	}
	return out.err
}

func (out *ResultWriter) Close() error {
	if out.closed || out.err != nil {
		return out.err
	}
	out.closed = true
	if out.format == "json" {
		_, out.err = io.WriteString(out.writer, "]\n")
	}
	return out.err
}
