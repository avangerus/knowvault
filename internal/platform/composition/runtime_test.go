package composition

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingRuntimeRunner struct {
	started chan struct{}
	calls   atomic.Int32
	once    sync.Once
}

func newBlockingRuntimeRunner() *blockingRuntimeRunner {
	return &blockingRuntimeRunner{started: make(chan struct{})}
}

func (runner *blockingRuntimeRunner) ListenAndServe(ctx context.Context) error {
	runner.calls.Add(1)
	runner.once.Do(func() { close(runner.started) })
	<-ctx.Done()
	return nil
}

type failingRuntimeRunner struct {
	calls atomic.Int32
	err   error
}

type immediateRuntimeRunner struct {
	calls atomic.Int32
}

func (runner *immediateRuntimeRunner) ListenAndServe(context.Context) error {
	runner.calls.Add(1)
	return nil
}

type drainObservingRunner struct {
	started  chan struct{}
	returned atomic.Bool
}

func (runner *drainObservingRunner) ListenAndServe(ctx context.Context) error {
	close(runner.started)
	<-ctx.Done()
	runner.returned.Store(true)
	return nil
}

func (runner *failingRuntimeRunner) ListenAndServe(context.Context) error {
	runner.calls.Add(1)
	return runner.err
}

func TestRuntimeDoesNotEnterListenerBeforeRun(t *testing.T) {
	runner := newBlockingRuntimeRunner()
	runtime := newRuntime(runner, nil)
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("listener calls before Run = %d", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("listener calls after ready Close = %d", got)
	}
	if err := runtime.Run(context.Background()); CodeOf(err) != CodeRuntimeStateInvalid {
		t.Fatalf("Run after Close code = %q", CodeOf(err))
	}
}

func TestRuntimeClosedStateNeverEntersListener(t *testing.T) {
	runner := &immediateRuntimeRunner{}
	runtime := newRuntime(runner, nil)
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := runtime.Run(context.Background()); CodeOf(err) != CodeRuntimeStateInvalid {
		t.Fatalf("Run after Close code = %q", CodeOf(err))
	}
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("listener calls after Close = %d", got)
	}
}

func TestRuntimeConcurrentCloseCancelsRunAndCleansExactlyOnce(t *testing.T) {
	runner := newBlockingRuntimeRunner()
	var cleanups [4]atomic.Int32
	steps := make([]cleanupFunc, len(cleanups))
	for index := range cleanups {
		index := index
		steps[index] = func() error {
			cleanups[index].Add(1)
			return nil
		}
	}
	runtime := newRuntime(runner, steps)
	copyOfRuntime := *runtime
	runResult := make(chan error, 1)
	go func() { runResult <- copyOfRuntime.Run(context.Background()) }()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not enter runner")
	}
	if err := runtime.Run(context.Background()); CodeOf(err) != CodeRuntimeStateInvalid {
		t.Fatalf("concurrent Run code = %q", CodeOf(err))
	}

	const closers = 12
	results := make(chan error, closers)
	for index := 0; index < closers; index++ {
		go func() { results <- runtime.Close() }()
	}
	for index := 0; index < closers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("Close %d: %v", index, err)
		}
	}
	if err := <-runResult; err != nil {
		t.Fatalf("Run: %v", err)
	}
	for index := range cleanups {
		if got := cleanups[index].Load(); got != 1 {
			t.Fatalf("cleanup %d calls = %d", index, got)
		}
	}
	if got := runner.calls.Load(); got != 1 {
		t.Fatalf("runner calls = %d", got)
	}
	if err := copyOfRuntime.Close(); err != nil {
		t.Fatalf("idempotent Close: %v", err)
	}
}

func TestRuntimeOnlyOneOfConcurrentRunsConsumesRunner(t *testing.T) {
	runner := newBlockingRuntimeRunner()
	runtime := newRuntime(runner, nil)

	const contenders = 32
	start := make(chan struct{})
	results := make(chan error, contenders)
	for index := 0; index < contenders; index++ {
		go func() {
			<-start
			results <- runtime.Run(context.Background())
		}()
	}
	close(start)
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("no concurrent Run entered runner")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	invalid := 0
	succeeded := 0
	for index := 0; index < contenders; index++ {
		err := <-results
		if err == nil {
			succeeded++
			continue
		}
		switch CodeOf(err) {
		case CodeRuntimeStateInvalid:
			invalid++
		default:
			t.Fatalf("Run %d code = %q", index, CodeOf(err))
		}
	}
	if invalid != contenders-1 {
		t.Fatalf("invalid Run results = %d, want %d", invalid, contenders-1)
	}
	if succeeded != 1 {
		t.Fatalf("successful Run results = %d, want 1", succeeded)
	}
	if got := runner.calls.Load(); got != 1 {
		t.Fatalf("runner calls = %d", got)
	}
}

func TestRuntimeCleanupStartsOnlyAfterRunnerReturns(t *testing.T) {
	runner := &drainObservingRunner{started: make(chan struct{})}
	var cleaned atomic.Bool
	runtime := newRuntime(runner, []cleanupFunc{func() error {
		if !runner.returned.Load() {
			t.Error("cleanup started before runner returned")
		}
		cleaned.Store(true)
		return nil
	}})
	runResult := make(chan error, 1)
	go func() { runResult <- runtime.Run(context.Background()) }()
	select {
	case <-runner.started:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not enter runner")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-runResult; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !cleaned.Load() {
		t.Fatal("cleanup did not run")
	}
}

func TestRuntimeRunnerFailureStillCleansBeforeReturn(t *testing.T) {
	runner := &failingRuntimeRunner{err: errors.New("private listener detail")}
	var cleaned atomic.Bool
	runtime := newRuntime(runner, []cleanupFunc{func() error { cleaned.Store(true); return nil }})
	err := runtime.Run(context.Background())
	if CodeOf(err) != CodeRuntimeRunFailed {
		t.Fatalf("Run code = %q", CodeOf(err))
	}
	if !cleaned.Load() {
		t.Fatal("Run returned before cleanup")
	}
	if got := err.Error(); got != string(CodeRuntimeRunFailed) {
		t.Fatalf("unsafe error = %q", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close after failed Run: %v", err)
	}
}

func TestRuntimeCancelledContextDoesNotConsumeReadyState(t *testing.T) {
	runner := newBlockingRuntimeRunner()
	runtime := newRuntime(runner, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Run(ctx); CodeOf(err) != CodeRuntimeStateInvalid {
		t.Fatalf("cancelled Run code = %q", CodeOf(err))
	}
	if got := runner.calls.Load(); got != 0 {
		t.Fatalf("cancelled Run listener calls = %d", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestCleanupStackRollsBackEveryAcquiredPrefixInReverse(t *testing.T) {
	const acquisitions = 8
	for failAt := 0; failAt <= acquisitions; failAt++ {
		t.Run(fmt.Sprintf("failure_%d", failAt), func(t *testing.T) {
			var stack cleanupStack
			var order []int
			for index := 0; index < failAt; index++ {
				index := index
				stack.push(func() error { order = append(order, index); return nil })
			}
			if err := stack.rollback(); err != nil {
				t.Fatalf("rollback: %v", err)
			}
			if len(order) != failAt {
				t.Fatalf("cleanup count = %d, want %d", len(order), failAt)
			}
			for position, got := range order {
				want := failAt - 1 - position
				if got != want {
					t.Fatalf("cleanup[%d] = %d, want %d", position, got, want)
				}
			}
			if err := stack.rollback(); err != nil {
				t.Fatalf("second rollback: %v", err)
			}
		})
	}
}

func TestCleanupContinuesAfterFailureAndReturnsContentFreeCode(t *testing.T) {
	var order []int
	steps := []cleanupFunc{
		func() error { order = append(order, 0); return nil },
		func() error { order = append(order, 1); return errors.New("secret cleanup detail") },
		func() error { order = append(order, 2); return nil },
	}
	err := closeReverse(steps)
	if CodeOf(err) != CodeRuntimeCleanupFailed {
		t.Fatalf("cleanup code = %q", CodeOf(err))
	}
	if fmt.Sprint(order) != "[2 1 0]" {
		t.Fatalf("cleanup order = %v", order)
	}
	if got := err.Error(); got != string(CodeRuntimeCleanupFailed) {
		t.Fatalf("unsafe cleanup error = %q", got)
	}
}

func TestRuntimeFormattingIsRedacted(t *testing.T) {
	runtime := newRuntime(&failingRuntimeRunner{err: errors.New("sensitive")}, nil)
	if got := fmt.Sprint(runtime); got != "composition.Runtime{[REDACTED]}" {
		t.Fatalf("String = %q", got)
	}
	if got := fmt.Sprintf("%#v", runtime); got != "composition.Runtime{[REDACTED]}" {
		t.Fatalf("GoString = %q", got)
	}
	if got := fmt.Sprintf("%#v", runtime.state); got != "composition.runtimeState{[REDACTED]}" {
		t.Fatalf("state GoString = %q", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
