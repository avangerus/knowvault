package ingestion

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeaseHeartbeatRunsBeyondOneObjectLeaseAndDrains(t *testing.T) {
	parent := context.Background()
	var beats atomic.Int32
	thirdBeat := make(chan struct{})
	objectCtx, stop := startContinuousHeartbeat(parent, 5*time.Millisecond,
		func(context.Context) error {
			if beats.Add(1) == 3 {
				close(thirdBeat)
			}
			return nil
		})

	// This models an extractor that runs for longer than its initial lease. The
	// callback is deliberately real scheduling, not a production queue bypass;
	// Handle supplies Handler.heartbeat as this callback.
	select {
	case <-thirdBeat:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not extend a long-running object")
	}
	if err := stop(); err != nil {
		t.Fatalf("stop returned heartbeat error: %v", err)
	}
	if got := beats.Load(); got < 3 {
		t.Fatalf("heartbeat count = %d, want at least 3 during long object", got)
	}
	if objectCtx.Err() == nil {
		t.Fatal("object context was not canceled while draining heartbeat")
	}
	completed := beats.Load()
	time.Sleep(20 * time.Millisecond)
	if got := beats.Load(); got != completed {
		t.Fatalf("heartbeat continued after stop: before=%d after=%d", completed, got)
	}
}

func TestLeaseHeartbeatFailureCancelsObjectAndReturnsError(t *testing.T) {
	want := errors.New("lease lost")
	var beats atomic.Int32
	objectCtx, stop := startContinuousHeartbeat(context.Background(), 5*time.Millisecond,
		func(context.Context) error {
			if beats.Add(1) == 2 {
				return want
			}
			return nil
		})

	select {
	case <-objectCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("heartbeat failure did not cancel object context")
	}
	if err := stop(); !errors.Is(err, want) {
		t.Fatalf("stop error = %v, want %v", err, want)
	}
	completed := beats.Load()
	time.Sleep(20 * time.Millisecond)
	if got := beats.Load(); got != completed {
		t.Fatalf("heartbeat continued after failure: before=%d after=%d", completed, got)
	}
}

func TestLeaseHeartbeatPreservesInFlightFailureRacingStop(t *testing.T) {
	want := errors.New("database connection lost")
	started := make(chan struct{})
	release := make(chan struct{})
	objectCtx, stop := startContinuousHeartbeat(context.Background(), 5*time.Millisecond,
		func(context.Context) error {
			close(started)
			<-release
			return want
		})
	<-started
	stopDone := make(chan error, 1)
	go func() { stopDone <- stop() }()
	close(release)
	select {
	case <-objectCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("in-flight heartbeat did not cancel object context")
	}
	select {
	case err := <-stopDone:
		if !errors.Is(err, want) {
			t.Fatalf("stop error = %v, want in-flight failure %v", err, want)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not drain in-flight heartbeat")
	}
}

func TestLeaseHeartbeatStopDrainsBlockingBeat(t *testing.T) {
	entered := make(chan struct{})
	returned := make(chan struct{})
	var once atomic.Bool
	objectCtx, stop := startContinuousHeartbeat(context.Background(), 5*time.Millisecond,
		func(ctx context.Context) error {
			if once.CompareAndSwap(false, true) {
				close(entered)
			}
			<-ctx.Done()
			close(returned)
			return ctx.Err()
		})
	<-entered
	stopDone := make(chan error, 1)
	go func() { stopDone <- stop() }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("stop did not drain a blocking heartbeat callback")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("stop returned error for cancellation drain: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stop did not return after heartbeat callback drained")
	}
	if objectCtx.Err() == nil {
		t.Fatal("object context was not canceled")
	}
}

func TestLeaseHeartbeatIntervalIsBounded(t *testing.T) {
	if got := leaseHeartbeatInterval(3600); got != 30*time.Second {
		t.Fatalf("large extension interval = %s, want 30s cap", got)
	}
	if got := leaseHeartbeatInterval(1); got != time.Second/3 {
		t.Fatalf("short extension interval = %s, want extension/3", got)
	}
	if got := leaseHeartbeatInterval(60); got != 20*time.Second {
		t.Fatalf("normal extension interval = %s, want extension/3", got)
	}
}
