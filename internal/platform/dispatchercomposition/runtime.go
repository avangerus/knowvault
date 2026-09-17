package dispatchercomposition

import (
	"context"
	"sync"

	"knowvault.local/verified-workspace/internal/sandboxdispatch"
)

// Runtime is an opaque, copy-safe one-shot dispatcher handle. It owns no public
// resource accessors; only Run/Close can consume its lifecycle.
type Runtime struct{ state *runtimeState }

// runtimeState carries the production role-separated v2 broker. It holds no
// container-creation capability — the package imports no runtime and no
// process-spawn surface.
type runtimeState struct {
	once   sync.Once
	closed chan struct{}
	broker *sandboxdispatch.DispatcherV2
}

func (Runtime) String() string   { return "dispatchercomposition.Runtime{[REDACTED]}" }
func (Runtime) GoString() string { return "dispatchercomposition.Runtime{[REDACTED]}" }

// NewProduction builds the production DispatcherV2 for one process. V2 owns
// four role-separated listeners and acquires the kernel observer plus the
// supervisor implementation internally; neither capability can be replaced
// through configuration or a request.
func NewProduction(config Config) (*Runtime, error) {
	if !config.matchesManifestTuple() {
		return nil, dispatcherError(CodeConfigInvalid)
	}
	broker, err := sandboxdispatch.NewV2(config.v2Config())
	if err != nil {
		return nil, dispatcherError(CodeStartupFailed)
	}
	return &Runtime{state: &runtimeState{
		closed: make(chan struct{}),
		broker: broker,
	}}, nil
}

// Run serves the broker until the context is done.
func (runtime *Runtime) Run(ctx context.Context) error {
	select {
	case <-runtime.state.closed:
		return dispatcherError(CodeRuntimeFailed)
	default:
	}
	if err := runtime.state.broker.ListenAndServe(ctx); err != nil {
		return dispatcherError(CodeRuntimeFailed)
	}
	return nil
}

// Close stops the runtime exactly once.
func (runtime *Runtime) Close() error {
	runtime.state.once.Do(func() {
		close(runtime.state.closed)
		runtime.state.broker.Close()
	})
	return nil
}
