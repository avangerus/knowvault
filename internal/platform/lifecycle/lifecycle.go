// Package lifecycle centralizes process shutdown without owning business work.
package lifecycle

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// ErrNilContext rejects an unbounded lifecycle with no cancellation authority.
var ErrNilContext = errors.New("lifecycle context is nil")

// SignalContext is cancelled by the parent, SIGINT, or SIGTERM.
func SignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
}

// Wait blocks until shutdown is requested. Context cancellation is a clean stop.
func Wait(ctx context.Context) error {
	if ctx == nil {
		return ErrNilContext
	}
	<-ctx.Done()
	return nil
}
