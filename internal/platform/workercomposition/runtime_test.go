package workercomposition

import (
	"context"
	"sync"
	"testing"
)

type testRunner struct {
	started chan struct{}
	result  error
}

func (runner *testRunner) Execute(ctx context.Context) error {
	close(runner.started)
	<-ctx.Done()
	return runner.result
}

func TestRuntimeRunsOnceAndCleansInReverseOrder(t *testing.T) {
	runner := &testRunner{started: make(chan struct{})}
	var mu sync.Mutex
	var order []int
	add := func(value int) cleanupFunc {
		return func() error {
			mu.Lock()
			order = append(order, value)
			mu.Unlock()
			return nil
		}
	}
	runtime := &Runtime{state: &runtimeState{
		phase: runtimeReady, runner: runner, cleanup: []cleanupFunc{add(1), add(2)}, done: make(chan struct{}),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runtime.Run(ctx) }()
	<-runner.started
	cancel()
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := runtime.Run(context.Background()); CodeOf(err) != CodeRuntimeState {
		t.Fatalf("second run err=%v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != 2 || order[1] != 1 {
		t.Fatalf("cleanup order=%v", order)
	}
}
