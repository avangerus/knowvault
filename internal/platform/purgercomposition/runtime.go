package purgercomposition

import (
	"context"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/secretmount"
	"knowvault.local/verified-workspace/internal/platform/trustbundle"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

const (
	purgerPrincipalID = "knowvault_purger"
	purgerPollID      = "purger.poll"
	reclaimLimit      = 100
)

type Runtime struct{ state *runtimeState }

type runtimePhase uint8

const (
	runtimeReady runtimePhase = iota + 1
	runtimeRunning
	runtimeClosing
	runtimeClosed
)

type runtimeState struct {
	mu          sync.Mutex
	runner      *purge.Runner
	cleanup     []func() error
	phase       runtimePhase
	runCancel   context.CancelFunc
	done        chan struct{}
	closeResult error
}

func (Runtime) String() string   { return "purgercomposition.Runtime{[REDACTED]}" }
func (Runtime) GoString() string { return "purgercomposition.Runtime{[REDACTED]}" }

// NewProduction acquires the exact mounted trust, tenant secret and purger
// database role before the queue loop can run. It is intentionally separate
// from the ingestion worker composition, whose role has no purge authority.
func NewProduction(ctx context.Context, config Config, info buildinfo.Info) (*Runtime, error) {
	_ = info
	if ctx == nil || ctx.Err() != nil {
		return nil, purgerError(CodeConfigInvalid)
	}
	if !validConfig(config) {
		return nil, purgerError(CodeConfigInvalid)
	}
	var cleanup []func() error
	fail := func() (*Runtime, error) {
		_ = closeReverse(cleanup)
		return nil, purgerError(CodeStartupFailed)
	}
	bundle, err := trustbundle.LoadMounted()
	if err != nil {
		return fail()
	}
	secrets, err := secretmount.LoadMountedForTenant(config.OrganizationID(), config.ProviderID())
	if err != nil {
		return fail()
	}
	cleanup = append(cleanup, secrets.Close)
	databaseURL, err := secrets.DatabaseURL()
	if err != nil {
		return fail()
	}
	roots, err := bundle.DatabaseRoots()
	if err != nil {
		return fail()
	}
	databaseConfig := database.DefaultConfig()
	databaseConfig.ApplicationRole = purgerPrincipalID
	databaseConfig.URL = databaseURL
	store, err := database.OpenProduction(ctx, databaseConfig, roots)
	databaseURL = ""
	databaseConfig.URL = ""
	if err != nil {
		return fail()
	}
	cleanup = append(cleanup, func() error { store.Close(); return nil })
	queue, err := purge.NewQueue(store)
	if err != nil {
		return fail()
	}
	sourceQueue, err := purge.NewSourceQueue(store)
	if err != nil {
		return fail()
	}
	purger, err := purge.NewPurger(store, time.Now, ids.New)
	if err != nil {
		return fail()
	}
	access := database.AccessContext{
		OrganizationID: string(config.OrganizationID()),
		PrincipalID:    purgerPrincipalID,
		RequestID:      purgerPollID,
	}
	runner, err := purge.NewRunnerWithSource(purger, queue, sourceQueue, access, purge.RunnerConfig{
		WorkerID: config.PurgerID(), LeaseSeconds: config.LeaseSeconds(),
		PollInterval: time.Duration(config.PollSeconds()) * time.Second, ReclaimLimit: reclaimLimit,
	})
	if err != nil {
		return fail()
	}
	return &Runtime{state: &runtimeState{
		runner: runner, cleanup: cleanup, phase: runtimeReady, done: make(chan struct{}),
	}}, nil
}

func validConfig(config Config) bool {
	return validOpaqueID(string(config.OrganizationID())) && validOpaqueID(string(config.ProviderID())) &&
		validOpaqueID(config.PurgerID()) && config.LeaseSeconds() >= minimumLeaseSeconds &&
		config.LeaseSeconds() <= maximumLeaseSeconds && config.PollSeconds() >= minimumPollSeconds &&
		config.PollSeconds() <= maximumPollSeconds && config.PollSeconds() < config.LeaseSeconds()
}

// Run executes the runner and releases all mounted capabilities when it stops.
// Context cancellation is a clean stop; operational errors are returned as a
// content-free purger error for the process supervisor.
func (runtime *Runtime) Run(ctx context.Context) error {
	if runtime == nil || runtime.state == nil || ctx == nil || ctx.Err() != nil {
		return purgerError(CodeRuntimeFailed)
	}
	state := runtime.state
	state.mu.Lock()
	if state.phase != runtimeReady || state.runner == nil {
		state.mu.Unlock()
		return purgerError(CodeRuntimeFailed)
	}
	runContext, cancel := context.WithCancel(ctx)
	state.phase = runtimeRunning
	state.runCancel = cancel
	runner := state.runner
	state.mu.Unlock()
	runErr := runner.Run(runContext)
	cancel()
	state.mu.Lock()
	if state.phase == runtimeRunning {
		state.phase = runtimeClosing
	}
	cleanup := state.cleanup
	state.cleanup = nil
	state.mu.Unlock()
	cleanupErr := closeReverse(cleanup)
	state.mu.Lock()
	state.closeResult = cleanupErr
	state.phase = runtimeClosed
	state.runCancel = nil
	close(state.done)
	state.mu.Unlock()
	if runErr != nil {
		return purgerError(CodeRuntimeFailed)
	}
	if cleanupErr != nil {
		return purgerError(CodeCleanupFailed)
	}
	return nil
}

// Close cancels an active runner, waits for cleanup, and is idempotent.
func (runtime *Runtime) Close() error {
	if runtime == nil || runtime.state == nil {
		return purgerError(CodeRuntimeFailed)
	}
	state := runtime.state
	state.mu.Lock()
	switch state.phase {
	case runtimeReady:
		state.phase = runtimeClosing
		cleanup := state.cleanup
		state.cleanup = nil
		state.mu.Unlock()
		cleanupErr := closeReverse(cleanup)
		state.mu.Lock()
		state.closeResult = cleanupErr
		state.phase = runtimeClosed
		close(state.done)
		state.mu.Unlock()
		if cleanupErr != nil {
			return purgerError(CodeCleanupFailed)
		}
		return nil
	case runtimeRunning:
		state.phase = runtimeClosing
		cancel := state.runCancel
		done := state.done
		state.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		<-done
		return runtime.closeResult()
	case runtimeClosing:
		done := state.done
		state.mu.Unlock()
		<-done
		return runtime.closeResult()
	case runtimeClosed:
		result := state.closeResult
		state.mu.Unlock()
		return result
	default:
		state.mu.Unlock()
		return purgerError(CodeRuntimeFailed)
	}
}

func (runtime *Runtime) closeResult() error {
	state := runtime.state
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.closeResult
}

func closeReverse(steps []func() error) error {
	failed := false
	for index := len(steps) - 1; index >= 0; index-- {
		if steps[index] != nil && steps[index]() != nil {
			failed = true
		}
	}
	if failed {
		return purgerError(CodeCleanupFailed)
	}
	return nil
}
