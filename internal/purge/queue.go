package purge

// This file owns the typed adapter for the migration-owned conversation purge
// request queue.  The database remains the state-machine authority: callers
// receive only opaque request fields and lease-fenced operations, never a raw
// table handle or caller-provided SQL.

import (
	"context"
	"errors"
	"regexp"

	"knowvault.local/verified-workspace/internal/platform/database"
)

var (
	queueReferenceID = regexp.MustCompile(`^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	queueOpaqueID    = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
	queueReasonCode  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
)

// QueueErrorCode is content-free and safe for logs and metrics.
type QueueErrorCode string

const (
	QueueCodeInvalid     QueueErrorCode = "PURGE_QUEUE_INVALID"
	QueueCodeLeaseLost   QueueErrorCode = "PURGE_QUEUE_LEASE_LOST"
	QueueCodePersistence QueueErrorCode = "PURGE_QUEUE_PERSISTENCE_FAILED"
)

type QueueError struct {
	code  QueueErrorCode
	cause error
}

func (e *QueueError) Error() string { return string(e.code) }
func (e *QueueError) Unwrap() error { return e.cause }

func QueueCodeOf(err error) QueueErrorCode {
	var queueError *QueueError
	if errors.As(err, &queueError) {
		return queueError.code
	}
	return QueueCodePersistence
}

// Request is the server-generated, opaque work item returned by Claim.
type Request struct {
	ID                string
	WorkspaceID       string
	WorkspaceRevision int64
	ConversationID    string
	ReasonCode        string
	LeaseEpoch        int64
	AttemptNumber     int
	MaxAttempts       int
}

// RequestSpec describes a request to enqueue.  It contains no content or SQL.
type RequestSpec struct {
	RequestID      string
	WorkspaceID    string
	ConversationID string
	ReasonCode     string
	IdempotencyKey string
	Priority       int
	MaxAttempts    int
	AvailableAfter int
}

func (spec RequestSpec) validate() error {
	if !queueReferenceID.MatchString(spec.RequestID) ||
		!queueOpaqueID.MatchString(spec.WorkspaceID) ||
		!queueOpaqueID.MatchString(spec.ConversationID) ||
		!queueReasonCode.MatchString(spec.ReasonCode) ||
		!queueOpaqueID.MatchString(spec.IdempotencyKey) ||
		spec.Priority < 0 || spec.Priority > 1000 ||
		spec.MaxAttempts < 1 || spec.MaxAttempts > 100 ||
		spec.AvailableAfter < 0 || spec.AvailableAfter > 2592000 {
		return &QueueError{code: QueueCodeInvalid}
	}
	return nil
}

// Queue is bound to a store opened with either knowvault_app (enqueue) or
// knowvault_purger (claim/lease transitions).  Database role checks remain in
// the SECURITY DEFINER functions and are not duplicated as authority here.
type Queue struct{ db *database.Store }

func NewQueue(db *database.Store) (*Queue, error) {
	if db == nil {
		return nil, &QueueError{code: QueueCodeInvalid}
	}
	return &Queue{db: db}, nil
}

// Enqueue is idempotent on (organization, IdempotencyKey).  A collision with
// a different target is rejected by the database function.
func (q *Queue) Enqueue(ctx context.Context, access database.AccessContext, spec RequestSpec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	var requestID string
	if err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.conversation_purge_request_enqueue(
			$1,$2,$3,$4,$5,$6,$7,$8)`,
			spec.RequestID, spec.WorkspaceID, spec.ConversationID, spec.ReasonCode,
			spec.IdempotencyKey, spec.Priority, spec.MaxAttempts, spec.AvailableAfter).Scan(&requestID)
	}); err != nil {
		return "", &QueueError{code: QueueCodePersistence, cause: err}
	}
	return requestID, nil
}

// Claim leases one pending request.  The boolean is false when no work is due.
func (q *Queue) Claim(ctx context.Context, access database.AccessContext, workerID string, leaseSeconds int) (Request, bool, error) {
	if !queueOpaqueID.MatchString(workerID) || leaseSeconds < 1 || leaseSeconds > 3600 {
		return Request{}, false, &QueueError{code: QueueCodeInvalid}
	}
	var request Request
	found := false
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		row := tx.QueryRow(ctx, `SELECT request_id, workspace_id, workspace_revision,
			conversation_id, reason_code, lease_epoch, attempt_number, max_attempts
			FROM app.conversation_purge_request_claim($1,$2)`, workerID, leaseSeconds)
		if scanErr := row.Scan(&request.ID, &request.WorkspaceID, &request.WorkspaceRevision,
			&request.ConversationID, &request.ReasonCode, &request.LeaseEpoch,
			&request.AttemptNumber, &request.MaxAttempts); scanErr != nil {
			if database.IsNotFound(scanErr) {
				return nil
			}
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return Request{}, false, &QueueError{code: QueueCodePersistence, cause: err}
	}
	return request, found, nil
}

func (q *Queue) Heartbeat(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64, extendSeconds int) error {
	if !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) || extendSeconds < 1 || extendSeconds > 3600 {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.conversation_purge_request_heartbeat($1,$2,$3,$4)`, requestID, workerID, leaseEpoch, extendSeconds)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *Queue) Complete(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64) error {
	if !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.conversation_purge_request_complete($1,$2,$3)`, requestID, workerID, leaseEpoch)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *Queue) Fail(ctx context.Context, access database.AccessContext, requestID, workerID string, leaseEpoch int64, code string, retryAfterSeconds int) error {
	if !queueReferenceID.MatchString(requestID) || !queueOpaqueID.MatchString(workerID) ||
		!queueReasonCode.MatchString(code) || retryAfterSeconds < 0 || retryAfterSeconds > 2592000 {
		return &QueueError{code: QueueCodeInvalid}
	}
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `SELECT app.conversation_purge_request_fail($1,$2,$3,$4,$5)`,
			requestID, workerID, leaseEpoch, code, retryAfterSeconds)
		return err
	})
	return q.mapLeaseError(err)
}

func (q *Queue) Reclaim(ctx context.Context, access database.AccessContext, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, &QueueError{code: QueueCodeInvalid}
	}
	var reclaimed int
	err := q.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.conversation_purge_request_reclaim($1)`, limit).Scan(&reclaimed)
	})
	if err != nil {
		return 0, &QueueError{code: QueueCodePersistence, cause: err}
	}
	return reclaimed, nil
}

func (q *Queue) mapLeaseError(err error) error {
	if err == nil {
		return nil
	}
	if database.SQLStateCode(err) == "55000" {
		return &QueueError{code: QueueCodeLeaseLost, cause: err}
	}
	return &QueueError{code: QueueCodePersistence, cause: err}
}
