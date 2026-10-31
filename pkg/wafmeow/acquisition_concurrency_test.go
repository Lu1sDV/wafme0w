package wafmeow

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestPacedOriginWaitersDoNotReserveConnectionSlots(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.MaxConnections, config.PerOriginRequestsPerSecond = 2, 10
		policy := newOutboundPolicy(config)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := policy.acquire(ctx, "http://one.invalid"); err != nil {
			t.Fatal(err)
		}
		<-policy.slots
		start := time.Now()
		done := make(chan error, 2)
		for range 2 {
			go func() {
				err := policy.acquire(ctx, "http://one.invalid")
				if err == nil {
					<-policy.slots
				}
				done <- err
			}()
		}
		synctest.Wait()
		waitingSlots := len(policy.slots)
		err := policy.acquire(ctx, "http://two.invalid")
		delay := time.Since(start)
		if err == nil {
			<-policy.slots
		}
		cancel()
		for range 2 {
			<-done
		}
		if err != nil || waitingSlots != 0 || delay != 0 || len(policy.slots) != 0 {
			t.Fatalf("paced origin blocked another origin: slots=%d delay=%v err=%v remaining=%d", waitingSlots, delay, err, len(policy.slots))
		}
	})
}

func TestRetryPacingSharesOriginAdmissions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.PerOriginRequestsPerSecond = 10
		policy := newOutboundPolicy(config)
		ctx := context.Background()
		const origin = "http://one.invalid"
		if err := policy.acquire(ctx, origin); err != nil {
			t.Fatal(err)
		}
		<-policy.slots
		start := time.Now()
		if err := policy.waitRate(ctx, origin); err != nil {
			t.Fatal(err)
		}
		if delay := time.Since(start); delay != 100*time.Millisecond {
			t.Fatalf("retry admission did not share origin pacing: delay=%v", delay)
		}
	})
}

func TestPacingUsesDispatchAfterConnectionWait(t *testing.T) {
	for _, perOrigin := range []bool{false, true} {
		name := "global"
		if perOrigin {
			name = "per-origin"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config := DefaultConfig()
				config.MaxConnections = 1
				if perOrigin {
					config.PerOriginRequestsPerSecond = 10
				} else {
					config.RequestsPerSecond = 10
				}
				dispatched := make(chan time.Time, 3)
				config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					dispatched <- time.Now()
					return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
				})}
				policy := newOutboundPolicy(config)
				client := policy.client("http://fixture.invalid")
				first, err := client.Get("http://fixture.invalid")
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 2)
				for range 2 {
					go func() {
						response, err := client.Get("http://fixture.invalid")
						if err == nil {
							err = response.Body.Close()
						}
						done <- err
					}()
				}
				synctest.Wait()
				time.Sleep(500 * time.Millisecond)
				if err := first.Body.Close(); err != nil {
					t.Fatal(err)
				}
				for range 2 {
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				}
				initial, second, third := <-dispatched, <-dispatched, <-dispatched
				if second.Sub(initial) != 500*time.Millisecond || third.Sub(second) != 100*time.Millisecond {
					t.Fatalf("stale pacing admission burst after body release: dispatch offsets=%v,%v", second.Sub(initial), third.Sub(initial))
				}
				if len(policy.slots) != 0 {
					t.Fatal("closed bodies retained connection slots")
				}
			})
		})
	}
}

func TestConnectionSemaphoreCancellationDoesNotLeakAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.MaxConnections = 1
		policy := newOutboundPolicy(config)
		if err := policy.acquire(context.Background(), "http://fixture.invalid"); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- policy.acquire(ctx, "http://fixture.invalid") }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("semaphore waiter ignored cancellation: %v", err)
		}
		if len(policy.slots) != 1 {
			t.Fatal("cancelled waiter released another request's body slot")
		}
		<-policy.slots
		if err := policy.acquire(ctx, "http://fixture.invalid"); !errors.Is(err, context.Canceled) || len(policy.slots) != 0 {
			t.Fatalf("cancelled context consumed a free slot: err=%v slots=%d", err, len(policy.slots))
		}
		if err := policy.acquire(context.Background(), "http://other.invalid"); err != nil {
			t.Fatal(err)
		}
		<-policy.slots
	})
}

func TestFastProbesLaunchWithoutFixedDelays(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.FastMode = true
		arrived := make(chan time.Time, 3)
		release := make(chan struct{})
		config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			arrived <- time.Now()
			<-release
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		})}
		policy := newOutboundPolicy(config)
		done := make(chan []Evidence, 1)
		go func() {
			done <- sendRequests(context.Background(), "http://fixture.invalid", policy.client("http://fixture.invalid"), config)
		}()
		first, second, third := <-arrived, <-arrived, <-arrived
		close(release)
		evidence := <-done
		if !first.Equal(second) || !second.Equal(third) {
			t.Fatalf("fast launch retained fixed delays: %v, %v", second.Sub(first), third.Sub(first))
		}
		var roles []string
		for _, observation := range evidence {
			roles = append(roles, observation.Role)
			if observation.StatusCode != 204 || observation.ErrorCode != "" {
				t.Fatalf("fast probe failed: %+v", observation)
			}
		}
		if !reflect.DeepEqual(roles, []string{"Normal", "NoUserAgent", "CentralAttack"}) {
			t.Fatalf("fast probe identities changed: %v", roles)
		}
	})
}

type baselineCompletionBody struct {
	io.Reader
	closed *atomic.Bool
}

func (b *baselineCompletionBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestDeepProbeConcurrencyIsBoundedAndKeepsEvidenceOrder(t *testing.T) {
	for _, workers := range []int{1, 2, 7} {
		t.Run(strconv.Itoa(workers), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				config := DefaultConfig()
				config.ProbeConcurrency = workers
				var requests atomic.Int32
				var baselineClosed atomic.Bool
				release := make(chan struct{})
				config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if requests.Add(1) == 1 {
						return &http.Response{StatusCode: 200, Body: &baselineCompletionBody{Reader: strings.NewReader(req.URL.String()), closed: &baselineClosed}}, nil
					}
					if !baselineClosed.Load() {
						t.Error("active probe started before baseline body closed")
					}
					<-release
					return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(req.URL.String()))}, nil
				})}
				policy := newOutboundPolicy(config)
				done := make(chan []Evidence, 1)
				go func() {
					done <- sendRequests(context.Background(), "http://fixture.invalid/target", policy.client("http://fixture.invalid"), config)
				}()
				synctest.Wait()
				started := requests.Load()
				close(release)
				evidence := <-done
				if started != int32(workers+1) || requests.Load() != 8 || len(evidence) != 8 {
					t.Fatalf("probe fan-out not bounded: blocked=%d workers=%d requests=%d evidence=%d", started, workers, requests.Load(), len(evidence))
				}
				roles := []string{"Normal", "NoUserAgent", "NonExistent", "XssAttack", "XxeAttack", "LfiAttack", "CentralAttack", "JndiAttack"}
				for i, observation := range evidence {
					if observation.Role != roles[i] || observation.StatusCode != 200 || observation.ErrorCode != "" || string(observation.Body) != observation.RequestURL {
						t.Fatalf("evidence index %d no longer identifies its probe: %+v", i, observation)
					}
				}
			})
		})
	}
}

func TestDeepProbeFanoutStopsWithoutBaselineMetadata(t *testing.T) {
	for _, budgetFailure := range []bool{false, true} {
		config := DefaultConfig()
		config.ProbeConcurrency = 8
		var requests atomic.Int32
		if budgetFailure {
			config.MaxTargetEvidenceBytes = 1
		}
		config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			if !budgetFailure {
				return nil, errors.New("baseline unavailable")
			}
			return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
		})}
		evidence := acquireHTTPFixture(t, "http://fixture.invalid", config)
		if requests.Load() != 1 || len(evidence) != 1 || evidence[0].Role != "Normal" || evidence[0].StatusCode != 0 || evidence[0].ErrorCode == "" {
			t.Fatalf("active fan-out continued without baseline metadata: requests=%d evidence=%+v", requests.Load(), evidence)
		}
	}
}

func TestDeepProbeFanoutHonorsSharedRequestBudget(t *testing.T) {
	for _, budget := range []int{1, 2, 8, 9, 10} {
		config := DefaultConfig()
		config.ProbeConcurrency, config.MaxRequests = 8, budget
		var requests atomic.Int32
		config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
		})}
		evidence := acquireHTTPFixture(t, "http://fixture.invalid", config)
		usable, exhausted := 0, 0
		for _, observation := range evidence {
			if observation.StatusCode == 204 && observation.ErrorCode == "" {
				usable++
			} else if observation.ErrorCode == "request_budget" {
				exhausted++
			}
		}
		want := min(8, budget)
		if requests.Load() != int32(want) || len(evidence) != 8 || usable != want || exhausted != 8-want {
			t.Fatalf("fan-out exceeded budget %d: requests=%d usable=%d exhausted=%d evidence=%+v", budget, requests.Load(), usable, exhausted, evidence)
		}
	}
}

func TestDeepProbeFanoutCountsRedirectsAgainstSharedRequestBudget(t *testing.T) {
	for _, budget := range []int{2, 3, 10, 15} {
		config := DefaultConfig()
		config.ProbeConcurrency, config.MaxRequests = 8, budget
		var requests atomic.Int32
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if requests.Add(1) == 1 || req.URL.Path == "/done" {
				return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
			}
			return &http.Response{StatusCode: 302, Header: http.Header{"Location": {"/done"}}, Body: http.NoBody}, nil
		})}
		evidence := acquireHTTPFixture(t, "http://fixture.invalid", config)
		if requests.Load() != int32(budget) || len(evidence) != 8 || evidence[0].StatusCode != 204 {
			t.Fatalf("fan-out redirects escaped wire budget %d: requests=%d evidence=%+v", budget, requests.Load(), evidence)
		}
		for _, observation := range evidence {
			if observation.ErrorCode != "" && observation.ErrorCode != "request_budget" {
				t.Fatalf("unexpected fan-out redirect failure: %+v", observation)
			}
		}
	}
}

func TestDeepProbeFanoutPreservesUsableBaselineWithBodyFailure(t *testing.T) {
	config := DefaultConfig()
	config.ProbeConcurrency = 8
	var requests atomic.Int32
	config.Client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if requests.Add(1) == 1 {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(failingReader{errors.New("baseline body unavailable")})}, nil
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
	})}
	evidence := acquireHTTPFixture(t, "http://fixture.invalid", config)
	if requests.Load() != 8 || len(evidence) != 8 || evidence[0].StatusCode != 200 || evidence[0].ErrorCode != "body_read" {
		t.Fatalf("usable baseline metadata was discarded: requests=%d evidence=%+v", requests.Load(), evidence)
	}
}

func TestDeepProbeFanoutCancellationJoinsConnectionWaiters(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		config := DefaultConfig()
		config.ProbeConcurrency, config.MaxConnections = 2, 1
		var requests atomic.Int32
		config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if requests.Add(1) == 1 {
				return &http.Response{StatusCode: 204, Body: http.NoBody}, nil
			}
			<-req.Context().Done()
			return nil, req.Context().Err()
		})}
		policy := newOutboundPolicy(config)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := make(chan []Evidence, 1)
		go func() {
			done <- sendRequests(ctx, "http://fixture.invalid", policy.client("http://fixture.invalid"), config)
		}()
		synctest.Wait()
		started := requests.Load()
		cancel()
		evidence := <-done
		if started != 2 || requests.Load() != 2 || len(evidence) != 8 || len(policy.slots) != 0 {
			t.Fatalf("cancelled fan-out leaked/admitted requests: started=%d requests=%d slots=%d evidence=%+v", started, requests.Load(), len(policy.slots), evidence)
		}
		for _, observation := range evidence[1:] {
			if observation.ErrorCode != "cancelled" || observation.TransportError == "" {
				t.Fatalf("cancelled/unsent probe lost its diagnostic: %+v", observation)
			}
		}
	})
}

func TestDeepProbeFanoutRetainedEvidenceBudgetBoundary(t *testing.T) {
	config := DefaultConfig()
	config.ProbeConcurrency = 8
	config.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		// Fix total metadata bytes even when NonExistent gets a longer random path.
		headers := http.Header{"X-Padding": {strings.Repeat("x", 2048-2*len(req.URL.String()))}}
		return &http.Response{StatusCode: 200, ContentLength: 1, Header: headers, Body: io.NopCloser(strings.NewReader("x"))}, nil
	})}
	original := acquireHTTPFixture(t, "http://fixture.invalid/target", config)
	exact := retainedHTTPFixtureBytes(original)
	for _, observation := range original {
		exact -= int64(cap(observation.Body) - len(observation.Body))
	}
	for _, limit := range []int64{exact, exact - 1} {
		config.MaxTargetEvidenceBytes = limit
		evidence := acquireHTTPFixture(t, "http://fixture.invalid/target", config)
		if len(evidence) != 8 || retainedHTTPFixtureBytes(evidence) > limit {
			t.Fatalf("fan-out escaped shared evidence budget %d: %+v", limit, evidence)
		}
		diagnosed := false
		for _, observation := range evidence {
			diagnosed = diagnosed || observation.ErrorCode == "evidence_budget"
			if limit == exact && (observation.StatusCode != 200 || observation.ErrorCode != "" || observation.BodyTruncated || string(observation.Body) != "x") {
				t.Fatalf("exact aggregate evidence budget rejected: %+v", observation)
			}
		}
		if limit < exact && !diagnosed {
			t.Fatalf("fan-out evidence overflow was not diagnosed: %+v", evidence)
		}
	}
}

func TestZeroMaxConnectionsFollowsTargetConcurrency(t *testing.T) {
	for _, test := range []struct{ concurrency, cap, want int }{
		{1, 0, 1}, {37, 0, 37}, {37, 3, 3}, {1, 20, 20},
	} {
		config := DefaultConfig()
		config.Concurrency, config.MaxConnections, config.ProbeConcurrency = test.concurrency, test.cap, 0
		config = config.normalized()
		if config.MaxConnections != test.want || config.ProbeConcurrency != 1 {
			t.Fatalf("normalization ignored explicit/derived limits: %+v", config)
		}
		if err := config.validate(); err != nil {
			t.Fatal(err)
		}
	}
}
