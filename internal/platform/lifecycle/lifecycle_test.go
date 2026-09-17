package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWaitReturnsAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Wait(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("cancelled lifecycle returned error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("lifecycle did not stop after cancellation")
	}
}

func TestWaitRejectsNilContext(t *testing.T) {
	t.Parallel()

	if err := Wait(nil); !errors.Is(err, ErrNilContext) {
		t.Fatalf("expected ErrNilContext, got %v", err)
	}
}

func TestSignalContextHonorsParentCancellation(t *testing.T) {
	t.Parallel()

	parent, cancelParent := context.WithCancel(context.Background())
	ctx, stop := SignalContext(parent)
	defer stop()
	cancelParent()

	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("signal context ignored parent cancellation")
	}
}
