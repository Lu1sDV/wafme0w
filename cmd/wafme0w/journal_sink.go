package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

const (
	maxJournalBatchSize  = 256
	maxJournalBatchBytes = 1 << 20
	journalFlushInterval = 25 * time.Millisecond
)

// One owner appends, syncs and emits; callers close only after the runner joins
// its serial callbacks. The unbuffered handoff cannot accumulate a second batch.
type journalSink struct {
	journal *diagnosticsJournal
	emit    func(wafme0w.Result) error
	input   chan wafme0w.Result
	done    chan struct{}
	err     error // Read only after done closes.
}

func newJournalSink(journal *diagnosticsJournal, size int, emit func(wafme0w.Result) error, abort func()) *journalSink {
	sink := &journalSink{journal: journal, emit: emit}
	if journal == nil || size == 1 {
		return sink
	}
	sink.input = make(chan wafme0w.Result)
	sink.done = make(chan struct{})
	go func() {
		defer close(sink.done)
		if err := sink.consume(size); err != nil {
			sink.err = err
			abort()
		}
	}()
	return sink
}

func (sink *journalSink) write(ctx context.Context, result wafme0w.Result) error {
	if sink.input == nil {
		if err := sink.journal.result(result); err != nil {
			return err
		}
		return sink.emit(result)
	}
	select {
	case <-sink.done:
		return sink.err
	case <-ctx.Done():
		return ctx.Err()
	case sink.input <- result:
		return nil
	}
}

func (sink *journalSink) close() error {
	if sink.input == nil {
		return nil
	}
	close(sink.input)
	<-sink.done
	return sink.err
}

func (sink *journalSink) consume(size int) error {
	pending := make([]wafme0w.Result, 0, size)
	pendingBytes := 0
	timer := time.NewTimer(journalFlushInterval)
	timer.Stop()
	defer timer.Stop()
	var tick <-chan time.Time
	flush := func() error {
		if err := sink.journal.sync(); err != nil {
			return err
		}
		for _, result := range pending {
			if err := sink.emit(result); err != nil {
				return err
			}
		}
		clear(pending)
		pending = pending[:0]
		pendingBytes = 0
		timer.Stop()
		tick = nil
		return nil
	}
	for {
		// A ready flush wins over accepting another record from a busy stream.
		select {
		case <-tick:
			if err := flush(); err != nil {
				return err
			}
		default:
		}
		select {
		case <-tick:
			if err := flush(); err != nil {
				return err
			}
		case result, ok := <-sink.input:
			if !ok {
				if len(pending) != 0 {
					return flush()
				}
				return nil
			}
			encoded, err := json.Marshal(journalRecord{Type: "result", Result: &result})
			if err != nil {
				return fmt.Errorf("encode diagnostics journal: %w", err)
			}
			encoded = append(encoded, '\n')
			// Pending Results are charged by their encoded size. Only the
			// current record is encoded in memory; there is no encoded queue.
			if len(pending) != 0 && pendingBytes+len(encoded) > maxJournalBatchBytes {
				if err := flush(); err != nil {
					// This handoff was already accepted. Preserve its recovery
					// record even if a previous result's dependent sink failed.
					tailErr := sink.journal.append(encoded)
					if tailErr == nil {
						tailErr = sink.journal.sync()
					}
					return errors.Join(err, tailErr)
				}
			}
			if err := sink.journal.append(encoded); err != nil {
				return err
			}
			if len(encoded) >= maxJournalBatchBytes {
				if err := sink.journal.sync(); err != nil {
					return err
				}
				if err := sink.emit(result); err != nil {
					return err
				}
				continue
			}
			if len(pending) == 0 {
				timer.Reset(journalFlushInterval)
				tick = timer.C
			}
			pending = append(pending, result)
			pendingBytes += len(encoded)
			if len(pending) >= size || pendingBytes >= maxJournalBatchBytes {
				if err := flush(); err != nil {
					return err
				}
			}
		}
	}
}
