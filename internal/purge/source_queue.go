package purge

// This file owns the typed adapter for the migration-owned source-version
// purge request queue.  The database remains the state-machine authority:
// callers receive only opaque request fields and lease-fenced transitions, not
// a table handle or caller-provided SQL.

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// SourceRequest is the server-generated work item returned by Claim.
type SourceRequest struct {
	ID            string
	SourceVersion string
	ReasonCode    string
	LeaseEpoch    int64
	AttemptNumber int
	MaxAttempts   int
}

// SourceRequestSpec describes a source-version purge request.  A source purge
// is organization-wide and therefore intentionally has no workspace selector.
type SourceRequestSpec struct {
	RequestID      string
	SourceVersion  string
	ReasonCode     string
	IdempotencyKey string
	Priority       int
	MaxAttempts    int
	AvailableAfter int
}

func (spec SourceRequestSpec) validate() error {
	if !queueReferenceID.MatchString(spec.RequestID) ||
		!queueReferenceID.MatchString(spec.SourceVersion) ||
		!queueReasonCode.MatchString(spec.ReasonCode) ||
		!queueOpaqueID.MatchString(spec.IdempotencyKey) ||
		spec.Priority < 0 || spec.Priority > 1000 ||
		spec.MaxAttempts < 1 || spec.MaxAttempts > 100 ||
		spec.AvailableAfter < 0 || spec.AvailableAfter > 2592000 {
		return &QueueError{code: QueueCodeInvalid}
	}
	return nil
}

// SourceQueue is bound to a store opened as knowvault_purger.  Role checks and
// tenant fencing remain in the SECURITY DEFINER functions.
type SourceQueue struct{ db *database.Store }

func NewSourceQueue(db *database.Store) (*SourceQueue, error) {
	if db == nil {
		return nil, &QueueError{code: QueueCodeInvalid}
	}
	return &SourceQueue{db: db}, nil
}

// Enqueue is idempotent on (organization, idempotency key).  Only the trusted
// purger role can call the underlying function because a source-version purge
// affects every workspace observing the version.
func (q *SourceQueue) Enqueue(ctx context.Context, access database.AccessContext, spec SourceRequestSpec) (string, error) {
	if q == nil || q.db == nil {
		return "", &QueueError{code: QueueCodeInvalid}
	}
	if err := spec.validate(); err != nil {
		return "", err
	}
	var requestID string
	if err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.source_version_purge_request_enqueue(
			$1,$2,$3,$4,$5,$6,$7)`,
			spec.RequestID, spec.SourceVersion, spec.ReasonCode, spec.IdempotencyKey,
			spec.Priority, spec.MaxAttempts, spec.AvailableAfter).Scan(&requestID)
	}); err != nil {
		return "", &QueueError{code: QueueCodePersistence, cause: err}
	}
	return requestID, nil
}

// Claim leases one pending source-version request.  The boolean is false when
// no work is due for the tenant.
func (q *SourceQueue) Claim(ctx context.Context, access database.AccessContext, workerID string, leaseSeconds int) (SourceRequest, bool, error) {
	if q == nil || q.db == nil || !queueOpaqueID.MatchString(workerID) || leaseSeconds < 1 || leaseSeconds > 3600 {
		return SourceRequest{}, false, &QueueError{code: QueueCodeInvalid}
	}
	var request SourceRequest
	found := false
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		row := tx.QueryRow(ctx, `SELECT request_id, source_version_id, reason_code,
			lease_epoch, attempt_number, max_attempts
			FROM app.source_version_purge_request_claim($1,$2)`, workerID, leaseSeconds)
		if scanErr := row.Scan(&request.ID, &request.SourceVersion, &request.ReasonCode,
			&request.LeaseEpoch, &request.AttemptNumber, &request.MaxAttempts); scanErr != nil {
			if database.IsNotFound(scanErr) {
				return nil
			}
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return SourceRequest{}, false, &QueueError{code: QueueCodePersistence, cause: err}
	}
	return request, found, nil
}

func (q *SourceQueue) Heartbeat(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64, extendSeconds int) error {
	if q == nil || q.db == nil || !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) || extendSeconds < 1 || extendSeconds > 3600 {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.source_version_purge_request_heartbeat($1,$2,$3,$4)`, requestID, workerID, leaseEpoch, extendSeconds)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *SourceQueue) Complete(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64) error {
	if q == nil || q.db == nil || !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.source_version_purge_request_complete($1,$2,$3)`, requestID, workerID, leaseEpoch)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *SourceQueue) Fail(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64, code string, retryAfterSeconds int) error {
	if q == nil || q.db == nil || !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) ||
		!queueReasonCode.MatchString(code) || retryAfterSeconds < 0 || retryAfterSeconds > 2592000 {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.source_version_purge_request_fail($1,$2,$3,$4,$5)`,
			requestID, workerID, leaseEpoch, code, retryAfterSeconds)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *SourceQueue) Reclaim(ctx context.Context, access database.AccessContext, limit int) (int, error) {
	if q == nil || q.db == nil || limit < 1 || limit > 1000 {
		return 0, &QueueError{code: QueueCodeInvalid}
	}
	var reclaimed int
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.source_version_purge_request_reclaim($1)`, limit).Scan(&reclaimed)
	})
	if err != nil {
		return 0, &QueueError{code: QueueCodePersistence, cause: err}
	}
	return reclaimed, nil
}

func (q *SourceQueue) mapLeaseError(err error) error {
	if err == nil {
		return nil
	}
	if database.SQLStateCode(err) == "55000" {
		return &QueueError{code: QueueCodeLeaseLost, cause: err}
	}
	return &QueueError{code: QueueCodePersistence, cause: err}
}
