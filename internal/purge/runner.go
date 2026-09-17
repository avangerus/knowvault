package purge

// The runner is the small production loop around the migration-owned purge
// queues. It deliberately owns no retention state or SQL selectors: reclaim,
// lease fencing and source/conversation cleanup stay in Queue and Purger. One
// tick handles at most one request per queue so a slow or poisoned target
// cannot starve the lease/restart boundary of other work.

import (
	"context"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
)

type RunnerErrorCode string

const (
	RunnerCodeInvalid RunnerErrorCode = "PURGE_RUNNER_INVALID"
	RunnerCodeStopped RunnerErrorCode = "PURGE_RUNNER_STOPPED"
	RunnerCodeFailed  RunnerErrorCode = "PURGE_RUNNER_FAILED"
)

type RunnerError struct {
	code  RunnerErrorCode
	cause error
}

func (e *RunnerError) Error() string { return string(e.code) }
func (e *RunnerError) Unwrap() error { return e.cause }

func RunnerCodeOf(err error) RunnerErrorCode {
	var runnerError *RunnerError
	if errors.As(err, &runnerError) && runnerError != nil {
		return runnerError.code
	}
	return RunnerCodeFailed
}

// RunnerConfig is a bounded, tenant-local poll profile.  A runner is created
// for one mounted purger identity and one organization access context.
type RunnerConfig struct {
	WorkerID     string
	LeaseSeconds int
	PollInterval time.Duration
	ReclaimLimit int
}

func (config RunnerConfig) validate() error {
	if !queueOpaqueID.MatchString(config.WorkerID) ||
		config.LeaseSeconds < 1 || config.LeaseSeconds > 3600 ||
		config.PollInterval < time.Second || config.PollInterval > 5*time.Minute ||
		config.ReclaimLimit < 1 || config.ReclaimLimit > 1000 ||
		time.Duration(config.LeaseSeconds)*time.Second <= config.PollInterval {
		return &RunnerError{code: RunnerCodeInvalid}
	}
	return nil
}

// RunOutcome contains only operational counters.  It is safe for metrics and
// logs because it contains no tenant content, source identifiers or SQL.
type RunOutcome struct {
	Reclaimed       int
	Processed       bool
	SourceReclaimed int
	SourceProcessed bool
}

// Runner is bound to the real conversation queue, optional source-version
// queue, Purger and authenticated access context. Both queues retain separate
// state machines and lease fences; the runner only composes their bounded
// ticks and owns no retention authority.
type Runner struct {
	purger      *Purger
	queue       *Queue
	sourceQueue *SourceQueue
	access      database.AccessContext
	config      RunnerConfig
}

func NewRunner(purger *Purger, queue *Queue, access database.AccessContext, config RunnerConfig) (*Runner, error) {
	return newRunner(purger, queue, nil, access, config)
}

// NewRunnerWithSource composes the accepted conversation queue with the
// source-version retention queue. One tick can process at most one request
// from each queue; no second scheduler or listener is introduced.
func NewRunnerWithSource(purger *Purger, queue *Queue, sourceQueue *SourceQueue,
	access database.AccessContext, config RunnerConfig) (*Runner, error) {
	return newRunner(purger, queue, sourceQueue, access, config)
}

func newRunner(purger *Purger, queue *Queue, sourceQueue *SourceQueue,
	access database.AccessContext, config RunnerConfig) (*Runner, error) {
	if purger == nil || queue == nil || access.Validate() != nil || config.validate() != nil {
		return nil, &RunnerError{code: RunnerCodeInvalid}
	}
	return &Runner{purger: purger, queue: queue, sourceQueue: sourceQueue, access: access, config: config}, nil
}

// RunOnce reclaims expired leases and then processes at most one request.  A
// cancellation before or during the database call is returned as a clean stop
// so a supervisor can distinguish shutdown from a failed worker.
func (runner *Runner) RunOnce(ctx context.Context) (RunOutcome, error) {
	if runner == nil || ctx == nil {
		return RunOutcome{}, &RunnerError{code: RunnerCodeInvalid}
	}
	if err := ctx.Err(); err != nil {
		return RunOutcome{}, &RunnerError{code: RunnerCodeStopped, cause: err}
	}
	if runner.purger == nil || runner.queue == nil {
		return RunOutcome{}, &RunnerError{code: RunnerCodeInvalid}
	}
	reclaimed, err := runner.queue.Reclaim(ctx, runner.access, runner.config.ReclaimLimit)
	if err != nil {
		if ctx.Err() != nil {
			return RunOutcome{Reclaimed: reclaimed}, &RunnerError{code: RunnerCodeStopped, cause: ctx.Err()}
		}
		return RunOutcome{Reclaimed: reclaimed}, &RunnerError{code: RunnerCodeFailed, cause: err}
	}
	processed, err := runner.purger.ProcessNextConversationPurge(ctx, runner.access, runner.queue,
		runner.config.WorkerID, runner.config.LeaseSeconds)
	if err != nil {
		if ctx.Err() != nil {
			return RunOutcome{Reclaimed: reclaimed, Processed: processed}, &RunnerError{code: RunnerCodeStopped, cause: ctx.Err()}
		}
		return RunOutcome{Reclaimed: reclaimed, Processed: processed}, &RunnerError{code: RunnerCodeFailed, cause: err}
	}
	outcome := RunOutcome{Reclaimed: reclaimed, Processed: processed}
	if runner.sourceQueue == nil {
		return outcome, nil
	}
	sourceReclaimed, err := runner.sourceQueue.Reclaim(ctx, runner.access, runner.config.ReclaimLimit)
	outcome.SourceReclaimed = sourceReclaimed
	if err != nil {
		if ctx.Err() != nil {
			return outcome, &RunnerError{code: RunnerCodeStopped, cause: ctx.Err()}
		}
		return outcome, &RunnerError{code: RunnerCodeFailed, cause: err}
	}
	sourceProcessed, err := runner.purger.ProcessNextSourceVersionPurge(ctx, runner.access, runner.sourceQueue,
		runner.config.WorkerID, runner.config.LeaseSeconds)
	outcome.SourceProcessed = sourceProcessed
	if err != nil {
		if ctx.Err() != nil {
			return outcome, &RunnerError{code: RunnerCodeStopped, cause: ctx.Err()}
		}
		return outcome, &RunnerError{code: RunnerCodeFailed, cause: err}
	}
	return outcome, nil
}

// Run starts the bounded poll loop.  A failed tick is returned to the process
// supervisor, which can restart the runner while the durable queue reclaims
// any lease left by the failed process.  Context cancellation is a clean stop.
func (runner *Runner) Run(ctx context.Context) error {
	if runner == nil || runner.config.validate() != nil || ctx == nil {
		return &RunnerError{code: RunnerCodeInvalid}
	}
	if _, err := runner.RunOnce(ctx); err != nil {
		if RunnerCodeOf(err) == RunnerCodeStopped && ctx.Err() != nil {
			return nil
		}
		return err
	}
	ticker := time.NewTicker(runner.config.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := runner.RunOnce(ctx); err != nil {
				if RunnerCodeOf(err) == RunnerCodeStopped && ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}
