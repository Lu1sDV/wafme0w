package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/Lu1sDV/wafme0w/internal/atomicfile"
	"github.com/Lu1sDV/wafme0w/pkg/wafme0w"
)

type durableJournalFile struct {
	bytes.Buffer
	durable           []byte
	syncs             int
	syncErr           error
	writeErr          error
	shortWrite        bool
	unsyncedBytes     int
	peakUnsyncedBytes int
}

func (file *durableJournalFile) Write(data []byte) (int, error) {
	if file.writeErr != nil {
		return 0, file.writeErr
	}
	if file.shortWrite {
		data = data[:len(data)/2]
	}
	n, err := file.Buffer.Write(data)
	file.unsyncedBytes += n
	file.peakUnsyncedBytes = max(file.peakUnsyncedBytes, file.unsyncedBytes)
	return n, err
}

func (file *durableJournalFile) Sync() error {
	file.syncs++
	if file.syncErr != nil {
		return file.syncErr
	}
	file.durable = append(file.durable[:0], file.Bytes()...)
	file.unsyncedBytes = 0
	return nil
}

func (*durableJournalFile) Close() error { return nil }

func testJournal(file *durableJournalFile) *diagnosticsJournal {
	return &diagnosticsJournal{file: file, encoder: json.NewEncoder(file)}
}

func journalRecords(t *testing.T, data []byte) []journalRecord {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var records []journalRecord
	for {
		var record journalRecord
		if err := decoder.Decode(&record); err == io.EOF {
			return records
		} else if err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
}

func durableResult(file *durableJournalFile, target string) error {
	decoder := json.NewDecoder(bytes.NewReader(file.durable))
	for {
		var record journalRecord
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf("result %q reached a dependent sink before durable sync: %w", target, err)
		}
		if record.Result != nil && record.Result.Target == target {
			return nil
		}
	}
}

func TestJournalSinkDurabilityBatchCountAndEOF(t *testing.T) {
	for _, size := range []int{1, 3} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				file := &durableJournalFile{}
				var emitted []string
				sink := newJournalSink(testJournal(file), size, func(result wafme0w.Result) error {
					if err := durableResult(file, result.Target); err != nil {
						return err
					}
					emitted = append(emitted, result.Target)
					return nil
				}, func() {})
				var want []string
				for i := range 5 {
					target := fmt.Sprintf("saved-%d", i)
					want = append(want, target)
					if err := sink.write(context.Background(), wafme0w.Result{Target: target}); err != nil {
						t.Fatal(err)
					}
					synctest.Wait()
					if got, want := len(emitted), ((i+1)/size)*size; got != want {
						t.Fatalf("emitted %d results before full batch, want %d", got, want)
					}
				}
				if err := sink.close(); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(emitted, want) || file.syncs != (len(want)+size-1)/size {
					t.Fatalf("tail lost or durability changed: emitted=%v syncs=%d", emitted, file.syncs)
				}
			})
		})
	}
}

func TestJournalSinkPartialBatchTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		file := &durableJournalFile{}
		emitted := make(chan struct{}, 1)
		sink := newJournalSink(testJournal(file), 4, func(result wafme0w.Result) error {
			if err := durableResult(file, result.Target); err != nil {
				return err
			}
			emitted <- struct{}{}
			return nil
		}, func() {})
		if err := sink.write(context.Background(), wafme0w.Result{Target: "live"}); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		time.Sleep(journalFlushInterval - time.Nanosecond)
		synctest.Wait()
		if len(emitted) != 0 {
			t.Fatal("partial batch flushed before its timer")
		}
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		select {
		case <-emitted:
		default:
			t.Fatal("live partial batch was not flushed")
		}
		if file.syncs != 1 {
			t.Fatalf("live partial batch syncs = %d, want 1", file.syncs)
		}
		if err := sink.close(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestJournalSinkBoundsPendingBytesAndFlushesOversizedRecord(t *testing.T) {
	for _, oversized := range []bool{false, true} {
		t.Run(fmt.Sprint(oversized), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				file := &durableJournalFile{}
				emitted := 0
				sink := newJournalSink(testJournal(file), maxJournalBatchSize, func(result wafme0w.Result) error {
					emitted++
					return durableResult(file, result.Target)
				}, func() {})
				length, count := maxJournalBatchBytes/2, 2
				if oversized {
					length, count = maxJournalBatchBytes+1, 1
				}
				for i := range count {
					if err := sink.write(context.Background(), wafme0w.Result{Target: strings.Repeat("x", length) + fmt.Sprint(i)}); err != nil {
						t.Fatal(err)
					}
				}
				synctest.Wait()
				if emitted != 1 || file.syncs != 1 {
					t.Fatalf("byte limit did not flush promptly: emitted=%d syncs=%d", emitted, file.syncs)
				}
				if !oversized && file.peakUnsyncedBytes > maxJournalBatchBytes {
					t.Fatalf("encoded batch exceeded byte bound: %d", file.peakUnsyncedBytes)
				}
				if err := sink.close(); err != nil {
					t.Fatal(err)
				}
				if emitted != count {
					t.Fatalf("byte-bound flush lost tail: emitted=%d want=%d", emitted, count)
				}
			})
		})
	}
}

func TestJournalSinkFailurePreservesDurableAcceptedTail(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		t.Run(fmt.Sprint(overflow), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				file := &durableJournalFile{}
				journal := testJournal(file)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				failure := errors.New("dependent report failed")
				emitted, size, count, length := 0, 3, 3, 1
				if overflow {
					size, count, length = maxJournalBatchSize, 2, maxJournalBatchBytes/2
				}
				sink := newJournalSink(journal, size, func(result wafme0w.Result) error {
					emitted++
					if err := durableResult(file, result.Target); err != nil {
						return err
					}
					return failure
				}, cancel)
				for i := range count {
					if err := sink.write(ctx, wafme0w.Result{Target: strings.Repeat("x", length) + fmt.Sprint(i)}); err != nil {
						t.Fatal(err)
					}
				}
				<-ctx.Done()
				if err := sink.close(); !errors.Is(err, failure) {
					t.Fatalf("original failure lost: %v", err)
				}
				if emitted != 1 || len(journalRecords(t, file.durable)) != count {
					t.Fatalf("accepted tail lost after sink failure: emitted=%d records=%d", emitted, len(journalRecords(t, file.durable)))
				}
				if err := journal.diagnostic("run_error", failure.Error()); err != nil {
					t.Fatal(err)
				}
				records := journalRecords(t, file.durable)
				if len(records) != count+1 || records[count].Diagnostic == nil || records[count].Diagnostic.Message != failure.Error() {
					t.Fatalf("diagnostic did not follow drained results: %+v", records)
				}
			})
		})
	}
}

func TestJournalSinkSyncFailureCancelsBeforeAnyDependentSink(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		failure := errors.New("disk sync failed")
		file := &durableJournalFile{syncErr: failure}
		journal := testJournal(file)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		emitted := 0
		sink := newJournalSink(journal, 4, func(wafme0w.Result) error { emitted++; return nil }, cancel)
		if err := sink.write(ctx, wafme0w.Result{Target: "live"}); err != nil {
			t.Fatal(err)
		}
		<-ctx.Done() // The partial-batch timer must fail and cancel without EOF.
		if err := sink.close(); !errors.Is(err, failure) || emitted != 0 || len(file.durable) != 0 {
			t.Fatalf("sync failure exposed result or lost cause: err=%v emitted=%d", err, emitted)
		}
		if err := journal.diagnostic("run_error", "later"); !errors.Is(err, failure) {
			t.Fatalf("later diagnostic replaced first journal failure: %v", err)
		}
	})
}

func TestJournalSinkAppendFailuresRemainOriginal(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				failure := errors.New("disk append failed")
				file := &durableJournalFile{writeErr: failure}
				if short {
					file.writeErr, file.shortWrite, failure = nil, true, io.ErrShortWrite
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				emitted := 0
				sink := newJournalSink(testJournal(file), 4, func(wafme0w.Result) error { emitted++; return nil }, cancel)
				if err := sink.write(ctx, wafme0w.Result{Target: "saved"}); err != nil {
					t.Fatal(err)
				}
				<-ctx.Done()
				if err := sink.close(); !errors.Is(err, failure) || emitted != 0 {
					t.Fatalf("append failure lost: err=%v emitted=%d", err, emitted)
				}
			})
		})
	}
}

func TestJournalSinkCancellationDrainsAcceptedTail(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		file := &durableJournalFile{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var emitted []string
		sink := newJournalSink(testJournal(file), 4, func(result wafme0w.Result) error {
			emitted = append(emitted, result.Target)
			return durableResult(file, result.Target)
		}, cancel)
		for _, target := range []string{"first", "second"} {
			if err := sink.write(ctx, wafme0w.Result{Target: target}); err != nil {
				t.Fatal(err)
			}
		}
		cancel()
		if err := sink.close(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(emitted, []string{"first", "second"}) || file.syncs != 1 {
			t.Fatalf("cancellation discarded accepted results: emitted=%v syncs=%d", emitted, file.syncs)
		}
	})
}

func TestJournalSinkBackpressureBoundsAcceptedResults(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		file := &durableJournalFile{}
		started, release := make(chan struct{}), make(chan struct{})
		emitted := 0
		sink := newJournalSink(testJournal(file), 3, func(result wafme0w.Result) error {
			emitted++
			if emitted == 1 {
				close(started)
				<-release
			}
			return durableResult(file, result.Target)
		}, func() {})
		accepted := make(chan struct{}, 10)
		done := make(chan error, 1)
		go func() {
			for i := range 10 {
				if err := sink.write(context.Background(), wafme0w.Result{Target: fmt.Sprint(i)}); err != nil {
					done <- err
					return
				}
				accepted <- struct{}{}
			}
			done <- sink.close()
		}()
		<-started
		synctest.Wait()
		got := len(accepted)
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if got != 3 || emitted != 10 {
			t.Fatalf("unbounded admission or lost output: accepted while blocked=%d emitted=%d", got, emitted)
		}
	})
}

type failingReportWriter struct {
	writer  io.Writer
	failure error
}

func (writer failingReportWriter) Write(data []byte) (int, error) {
	if bytes.Equal(data, []byte("[")) {
		return writer.writer.Write(data)
	}
	return 0, writer.failure
}

func TestJournalSinkReportFailureKeepsAtomicReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("previous report"), 0600); err != nil {
		t.Fatal(err)
	}
	synctest.Test(t, func(t *testing.T) {
		file := &durableJournalFile{}
		failure := errors.New("report device failed")
		err := atomicfile.Write(path, func(writer io.Writer) error {
			report, err := wafme0w.NewResultWriter(failingReportWriter{writer: writer, failure: failure}, "json")
			if err != nil {
				return err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := newJournalSink(testJournal(file), 3, func(result wafme0w.Result) error {
				if err := durableResult(file, result.Target); err != nil {
					return err
				}
				return report.Write(result)
			}, cancel)
			var writeErr error
			for i := range 3 {
				if writeErr = sink.write(ctx, wafme0w.Result{Target: fmt.Sprint(i)}); writeErr != nil {
					break
				}
			}
			return errors.Join(sink.close(), writeErr, report.Close())
		})
		if !errors.Is(err, failure) {
			t.Fatalf("report write error lost: %v", err)
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "previous report" {
			t.Fatalf("failed batched report replaced previous report: %q %v", data, err)
		}
		if len(journalRecords(t, file.durable)) != 3 {
			t.Fatal("report failure preceded durable recovery batch")
		}
	})
}
