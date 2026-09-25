package composition

import (
	"context"
	"log/slog"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

// questionReconcileInterval is how often a running server re-checks for
// Question Runs whose owner process died. It is independent of the question
// package's own heartbeat/grace policy: the sweep only ever finishes a run
// that has already missed the grace window, so a shorter interval just makes
// the user-visible convergence faster without risking a live run.
const questionReconcileInterval = 10 * time.Second

// questionReconcilePrincipal is the fixed, non-human marker for the startup
// and periodic reconciliation access context. It never becomes an audit actor
// (the events are ActorSystem) and it grants nothing: the database gates the
// tenant-wide scan to the application role, not to this value.
const questionReconcilePrincipal = "svc_question_reconciler"

// reconcileQuestionRuns runs one orphan sweep. Failures are logged and
// swallowed: a transient database problem must not take a healthy server down,
// and the next tick retries.
func reconcileQuestionRuns(ctx context.Context, questions *question.Service, organizationID string) {
	if questions == nil || organizationID == "" || ctx == nil || ctx.Err() != nil {
		return
	}
	requestID, err := newStartupRequestID()
	if err != nil {
		return
	}
	access := database.AccessContext{
		OrganizationID: organizationID, PrincipalID: questionReconcilePrincipal, RequestID: requestID,
	}
	if _, err := questions.ReconcileInterruptedRuns(ctx, access); err != nil {
		slog.Warn("question run reconciliation failed", "error_code", question.CodeOf(err))
	}
}

// startQuestionReconcileLoop keeps the periodic orphan sweep running for the
// lifetime of the composed runtime. It is started during preflight and pushed
// onto the runtime's own cleanup stack, so it is cancelled and awaited exactly
// where every other acquired capability is retired — no reconciliation can
// outlive the runtime. It is deliberately not a listener wrapper: ARC-014/F1
// allow exactly one production ListenAndServe call, in (*Runtime).Run.
func startQuestionReconcileLoop(questions *question.Service, organizationID string) func() error {
	if questions == nil || organizationID == "" {
		return nil
	}
	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(questionReconcileInterval)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				reconcileQuestionRuns(loopCtx, questions, organizationID)
			}
		}
	}()
	return func() error {
		cancel()
		<-done
		return nil
	}
}
