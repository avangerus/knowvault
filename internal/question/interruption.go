package question

import (
	"context"
	"database/sql"
	"log/slog"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// 000121 liveness policy. A run proves it is still being answered by keeping
// owner_heartbeat_at fresh; the grace window is several missed heartbeats, so
// a slow model call, a scheduled pause or a loaded machine is never mistaken
// for a dead process, while a crashed one is finished promptly.
const (
	questionRunHeartbeatInterval  = 5 * time.Second
	questionRunHeartbeatTimeout   = 5 * time.Second
	questionRunOrphanGraceSeconds = 30
	questionRunReconcileLimit     = 250

	// questionInterruptedFailureCode is the closed, content-free code every
	// run finished by the reconciler carries, and the audit error code of the
	// matching question.failed event.
	questionInterruptedFailureCode = "QUESTION_INTERRUPTED"
)

// startRunHeartbeat refreshes the run's owner heartbeat in the background for
// as long as this process is answering it, and returns the stop function
// Create defers. The heartbeat is fenced by owner_id and only touches a
// QUEUED/RUNNING row, so it can never resurrect or mutate a terminal run, and
// a late tick after completion is a no-op. It is a no-op for a Service built
// without a run owner (the protected-independent unit fixtures).
func (service *Service) startRunHeartbeat(ctx context.Context, access database.AccessContext, runID, workspaceID string) func() {
	if service == nil || service.db == nil || service.runOwner == "" || !validOpaque(runID) || !validOpaque(workspaceID) {
		return func() {}
	}
	heartbeatCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(questionRunHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-heartbeatCtx.Done():
				return
			case <-ticker.C:
				service.refreshRunHeartbeat(heartbeatCtx, access, runID, workspaceID)
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// refreshRunHeartbeat writes one liveness proof. The request may already be
// unwinding, so the write gets its own bounded context rather than borrowing
// the cancel that is stopping this very heartbeat.
func (service *Service) refreshRunHeartbeat(ctx context.Context, access database.AccessContext, runID, workspaceID string) {
	if ctx.Err() != nil {
		return
	}
	beatCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), questionRunHeartbeatTimeout)
	defer cancel()
	err := service.db.Write(beatCtx, access, func(txCtx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(txCtx, `
			UPDATE public.question_run
			   SET owner_heartbeat_at = clock_timestamp()
			 WHERE organization_id = $1 AND id = $2 AND workspace_id = $3
			   AND owner_id = $4 AND result_status IN ('QUEUED', 'RUNNING')
		`, access.OrganizationID, runID, workspaceID, service.runOwner)
		return execErr
	})
	if err != nil {
		slog.Warn("question run heartbeat failed", "error_code", CodeOf(err))
	}
}

// ReconcileInterruptedRuns finishes every RUNNING run in the caller's tenant
// whose recorded owner process is gone: it stopped refreshing its heartbeat
// longer ago than the grace window. The transition is a compare-and-set inside
// the database (`app.question_run_interrupt_orphan`), so a run that completed,
// or whose live owner refreshed its heartbeat after discovery, is left
// untouched — this covers several replicas and one slow model call. Every
// finished run is recorded exactly like any other terminal outcome: the run
// becomes INTERRUPTED with completed_at and failure_code set, and the same
// transaction appends its question.failed audit event. It returns how many
// runs were finished.
//
// The tenant-wide scan is a SECURITY DEFINER gate because this runs before any
// user request exists; access only supplies the organization and request
// identity, and the database re-checks that the caller is the application
// role.
func (service *Service) ReconcileInterruptedRuns(ctx context.Context, access database.AccessContext) (int, error) {
	if service == nil || service.db == nil || service.audit == nil || service.newID == nil || service.now == nil ||
		ctx == nil || access.Validate() != nil {
		return 0, &Error{code: CodeInvalid}
	}
	reconciled := 0
	err := service.db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		rows, err := tx.Query(txCtx, `
			SELECT run_id, owner_id
			  FROM app.question_run_orphan_candidates($1, $2)
		`, questionRunOrphanGraceSeconds, questionRunReconcileLimit)
		if err != nil {
			return err
		}
		type orphan struct{ runID, ownerID string }
		// The candidate cursor is drained and closed before any compare-and-set:
		// pgx permits only one active statement per transaction, and the
		// set stays bounded by the gate's own limit.
		candidates := make([]orphan, 0, questionRunReconcileLimit)
		for rows.Next() {
			var item orphan
			if err := rows.Scan(&item.runID, &item.ownerID); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()

		for _, candidate := range candidates {
			var finishedWorkspace sql.NullString
			if err := tx.QueryRow(txCtx, `SELECT app.question_run_interrupt_orphan($1, $2, $3)`,
				candidate.runID, candidate.ownerID, questionRunOrphanGraceSeconds).Scan(&finishedWorkspace); err != nil {
				return err
			}
			if !finishedWorkspace.Valid || finishedWorkspace.String == "" {
				// Lost the race to a completed run or a refreshed heartbeat.
				continue
			}
			eventID, err := service.newID("aud")
			if err != nil {
				return err
			}
			workspaceID := finishedWorkspace.String
			completedAt := service.now().UTC()
			code := questionInterruptedFailureCode
			qrunID := candidate.runID
			if _, err := service.audit.AppendInTransaction(txCtx, access, tx, audit.EventInput{
				EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorSystem,
				Action: audit.ActionQuestionFailed, ResourceType: audit.ResourceQuestionRun,
				ResourceID: candidate.runID, RequestID: access.RequestID, Outcome: audit.OutcomeFailed,
				ErrorCode: &code, ReferencedEvidenceIDs: []string{},
				Metadata: audit.Metadata{QuestionRunID: &qrunID}, OccurredAt: completedAt,
			}); err != nil {
				return err
			}
			reconciled++
		}
		return nil
	})
	if err != nil {
		return 0, &Error{code: CodeUnavailable, cause: err}
	}
	return reconciled, nil
}
