package wafme0w

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestExcessiveConcurrencyRejectedBeforeInput(t *testing.T) {
	for _, concurrency := range []int{65537, 1 << 30, int(^uint(0) >> 1)} {
		config := DefaultConfig()
		config.Concurrency = concurrency
		// A cancelled context makes the pre-fix implementation return before
		// allocating workers. Configuration errors must take precedence.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := Run(ctx, emptyEngine(t), failingReader{errors.New("must not read")}, config, func(Result) error {
			t.Fatal("invalid configuration emitted a result")
			return nil
		})
		if err == nil || !strings.Contains(err.Error(), "concurrency") {
			t.Fatalf("concurrency %d was not rejected before execution: %v", concurrency, err)
		}
	}
}

func TestSupportedConcurrencyBoundsValidateWithoutStartingWorkers(t *testing.T) {
	for _, concurrency := range []int{1, 20, 65536} {
		config := DefaultConfig()
		config.Concurrency = concurrency
		if err := config.normalized().validate(); err != nil {
			t.Fatalf("supported concurrency %d rejected: %v", concurrency, err)
		}
	}
}
