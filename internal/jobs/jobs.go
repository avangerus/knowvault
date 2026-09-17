// Package jobs is the typed semantic owner of the durable ingestion job
// substrate. It exposes exactly the lease-fenced state-machine operations —
// enqueue, claim, heartbeat, complete, fail, reclaim — and nothing else. It
// never hands out a generic "run SQL against the job table" capability: every
// method routes through the SECURITY DEFINER database functions that own the
// transitions, and the runtime/worker roles have no direct DML on the tables.
//
// The database is the authority. This layer adds a closed, typed surface,
// client-side input validation (defence in depth against the same rules the
// database enforces), and content-free error codes safe for logs and metrics.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// Type is the closed inventory of durable ingestion operations. Handlers for
// each type are composed in later slices; the substrate owns the taxonomy.
type Type string

const (
	TypeSourceScopeSync Type = "SOURCE_SCOPE_SYNC"
	// TypePostgreSQLQuerySync reads one immutable DBA-managed projection from
	// an external PostgreSQL connection and publishes it through the same
	// lease-fenced catalog/evidence path as folder sync.
	TypePostgreSQLQuerySync Type = "POSTGRESQL_QUERY_SYNC"
	TypeSourceObjectExtract Type = "SOURCE_OBJECT_EXTRACTION"
	TypeOutboxDelivery      Type = "OUTBOX_DELIVERY"
	TypeSourceVersionPurge  Type = "SOURCE_VERSION_PURGE"
	TypeKEKRewrap           Type = "KEK_REWRAP"
	TypeDigestRecompute     Type = "DIGEST_RECOMPUTE"
)

func (t Type) valid() bool {
	switch t {
	case TypeSourceScopeSync, TypePostgreSQLQuerySync, TypeSourceObjectExtract, TypeOutboxDelivery, TypeSourceVersionPurge, TypeKEKRewrap, TypeDigestRecompute:
		return true
	default:
		return false
	}
}

// ErrorCode is content-free and safe for structured logs, metrics and API
// mapping. It never carries payload, source or model content.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "JOB_INVALID"
	CodeLeaseLost   ErrorCode = "JOB_LEASE_LOST"
	CodePersistence ErrorCode = "JOB_PERSISTENCE_FAILED"
)

// Error preserves a safe code and hides the underlying database error.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps any error to a safe code. A lease-fencing rejection surfaces as
// CodeLeaseLost so a caller can distinguish "someone else owns this now" from a
// transport failure.
func CodeOf(err error) ErrorCode {
	var jobError *Error
	if errors.As(err, &jobError) {
		return jobError.code
	}
	return CodePersistence
}

// leaseLostSQLState is the state raised by the database when a heartbeat,
// completion or failure presents a lease this worker no longer holds.
const leaseLostSQLState = "55000"

var (
	referenceIDPattern   = regexp.MustCompile(`^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	opaqueIDPattern      = regexp.MustCompile(`^[^\x00-\x1f]{1,256}$`)
	errorCodePattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	sha256Pattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	referencePayloadKeys = map[string]bool{
		"source_scope_id": true, "source_object_id": true, "source_version_id": true,
		"extraction_id": true, "index_generation_id": true, "workspace_id": true, "artifact_id": true,
	}
	hashPayloadKeys      = map[string]bool{"content_hash": true, "text_hash": true}
	fencePayloadKeys     = map[string]bool{"retention_fence": true, "generation_fence": true}
	validPayloadOperator = map[string]bool{"UPSERT": true, "DELETE": true, "PURGE": true, "ACTIVATE": true}
)

// Payload is a bounded closed reference/hash object. It never carries text,
// paths, principals or secrets; Validate enforces the same closed inventory the
// database CHECK enforces.
type Payload map[string]any

// Validate rejects any key outside the closed inventory or any value with the
// wrong shape, before the payload is sent to the database.
func (p Payload) Validate() error {
	for key, value := range p {
		switch {
		case referencePayloadKeys[key]:
			text, ok := value.(string)
			if !ok || !referenceIDPattern.MatchString(text) {
				return &Error{code: CodeInvalid}
			}
		case hashPayloadKeys[key]:
			text, ok := value.(string)
			if !ok || !sha256Pattern.MatchString(text) {
				return &Error{code: CodeInvalid}
			}
		case fencePayloadKeys[key]:
			fence, ok := value.(int64)
			if !ok || fence < 0 {
				return &Error{code: CodeInvalid}
			}
		case key == "operation":
			text, ok := value.(string)
			if !ok || !validPayloadOperator[text] {
				return &Error{code: CodeInvalid}
			}
		default:
			return &Error{code: CodeInvalid}
		}
	}
	return nil
}

func (p Payload) marshal() ([]byte, error) {
	if p == nil {
		return []byte("{}"), nil
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(map[string]any(p))
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	if len(encoded) > 16384 {
		return nil, &Error{code: CodeInvalid}
	}
	return encoded, nil
}

// Spec describes a unit of durable work to enqueue.
type Spec struct {
	JobID          string
	Type           Type
	Payload        Payload
	IdempotencyKey string
	Priority       int
	MaxAttempts    int
	AvailableAfter int // seconds
}

func (s Spec) validate() error {
	if !referenceIDPattern.MatchString(s.JobID) ||
		!s.Type.valid() ||
		!opaqueIDPattern.MatchString(s.IdempotencyKey) ||
		s.Priority < 0 || s.Priority > 1000 ||
		s.MaxAttempts < 1 || s.MaxAttempts > 100 ||
		s.AvailableAfter < 0 || s.AvailableAfter > 2592000 {
		return &Error{code: CodeInvalid}
	}
	return nil
}

// ClaimedJob is a leased unit of work. LeaseEpoch is the fencing token every
// subsequent heartbeat/complete/fail must present.
type ClaimedJob struct {
	ID            string
	Type          Type
	Payload       Payload
	LeaseEpoch    int64
	AttemptNumber int
	MaxAttempts   int
}

// Queue is the durable job owner bound to one runtime pool. A Web/API runtime
// pool can only Enqueue (the database rejects the rest); a worker pool can drive
// the whole state machine.
type Queue struct {
	store *database.Store
}

// New binds the owner to a runtime store. It fails closed on a nil store.
func New(store *database.Store) (*Queue, error) {
	if store == nil {
		return nil, &Error{code: CodeInvalid}
	}
	return &Queue{store: store}, nil
}

// Enqueue registers durable work. It is idempotent on the idempotency key: a
// repeat returns the original job id and never creates a second unit of work.
func (q *Queue) Enqueue(ctx context.Context, access database.AccessContext, spec Spec) (string, error) {
	var jobID string
	writeErr := q.store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var err error
		jobID, err = q.EnqueueInTransaction(ctx, access, tx, spec)
		return err
	})
	if writeErr != nil {
		return "", &Error{code: CodePersistence, cause: writeErr}
	}
	return jobID, nil
}

// EnqueueInTransaction registers durable work inside the caller's write
// transaction, so job placement and the caller's own state change commit
// atomically (AUD-005: no job can exist without the audit record that made it
// visible). The idempotency semantics match Enqueue.
func (q *Queue) EnqueueInTransaction(ctx context.Context, access database.AccessContext, tx database.Transaction, spec Spec) (string, error) {
	if err := spec.validate(); err != nil {
		return "", err
	}
	payload, err := spec.Payload.marshal()
	if err != nil {
		return "", err
	}
	var jobID string
	if err := tx.QueryRow(ctx, `SELECT app.enqueue_job($1, $2, $3::jsonb, $4, $5, $6, $7)`,
		spec.JobID, string(spec.Type), string(payload), spec.IdempotencyKey,
		spec.Priority, spec.MaxAttempts, spec.AvailableAfter).Scan(&jobID); err != nil {
		return "", &Error{code: CodePersistence, cause: err}
	}
	return jobID, nil
}

// Claim leases the next runnable job for this tenant. The bool is false when
// nothing is runnable.
func (q *Queue) Claim(ctx context.Context, access database.AccessContext, workerID string, leaseSeconds int) (ClaimedJob, bool, error) {
	if !opaqueIDPattern.MatchString(workerID) || leaseSeconds < 1 || leaseSeconds > 3600 {
		return ClaimedJob{}, false, &Error{code: CodeInvalid}
	}
	var claimed ClaimedJob
	var payloadRaw []byte
	var jobType string
	found := false
	writeErr := q.store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		row := tx.QueryRow(ctx, `SELECT job_id, job_type, payload_json, lease_epoch, attempt_number, max_attempts
			FROM app.claim_next_job($1, $2)`, workerID, leaseSeconds)
		if scanErr := row.Scan(&claimed.ID, &jobType, &payloadRaw, &claimed.LeaseEpoch, &claimed.AttemptNumber, &claimed.MaxAttempts); scanErr != nil {
			if database.IsNotFound(scanErr) {
				return nil
			}
			return scanErr
		}
		found = true
		return nil
	})
	if writeErr != nil {
		return ClaimedJob{}, false, &Error{code: CodePersistence, cause: writeErr}
	}
	if !found {
		return ClaimedJob{}, false, nil
	}
	claimed.Type = Type(jobType)
	if len(payloadRaw) > 0 {
		decoded := Payload{}
		if err := json.Unmarshal(payloadRaw, &decoded); err != nil {
			return ClaimedJob{}, false, &Error{code: CodePersistence, cause: err}
		}
		claimed.Payload = decoded
	}
	return claimed, true, nil
}

// Heartbeat extends a held lease. It returns CodeLeaseLost if this worker no
// longer owns the lease at the given epoch.
func (q *Queue) Heartbeat(ctx context.Context, access database.AccessContext, jobID, workerID string, leaseEpoch int64, extendSeconds int) error {
	if !referenceIDPattern.MatchString(jobID) || !opaqueIDPattern.MatchString(workerID) || extendSeconds < 1 || extendSeconds > 3600 {
		return &Error{code: CodeInvalid}
	}
	return q.leaseCall(ctx, access, `SELECT app.heartbeat_job($1, $2, $3, $4)`, jobID, workerID, leaseEpoch, extendSeconds)
}

// Complete acknowledges success. It runs inside the worker's result
// transaction, so derived writes and follow-on enqueues commit atomically with
// the acknowledgement. It returns CodeLeaseLost if the lease is no longer held.
func (q *Queue) Complete(ctx context.Context, access database.AccessContext, jobID, workerID string, leaseEpoch int64) error {
	if !referenceIDPattern.MatchString(jobID) || !opaqueIDPattern.MatchString(workerID) {
		return &Error{code: CodeInvalid}
	}
	return q.leaseCall(ctx, access, `SELECT app.complete_job($1, $2, $3)`, jobID, workerID, leaseEpoch)
}

// Fail records a failure. Within the retry budget the job is re-queued after the
// backoff; once the budget is exhausted it is dead-lettered.
func (q *Queue) Fail(ctx context.Context, access database.AccessContext, jobID, workerID string, leaseEpoch int64, code ErrorCode, retryAfterSeconds int) error {
	if !referenceIDPattern.MatchString(jobID) || !opaqueIDPattern.MatchString(workerID) ||
		!errorCodePattern.MatchString(string(code)) || retryAfterSeconds < 0 || retryAfterSeconds > 2592000 {
		return &Error{code: CodeInvalid}
	}
	var resulting string
	writeErr := q.store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.fail_job($1, $2, $3, $4, $5)`,
			jobID, workerID, leaseEpoch, string(code), retryAfterSeconds).Scan(&resulting)
	})
	return q.mapLeaseError(writeErr)
}

// Reclaim closes leases whose worker was lost and re-queues or dead-letters the
// affected jobs. It returns how many jobs it reclaimed.
func (q *Queue) Reclaim(ctx context.Context, access database.AccessContext, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, &Error{code: CodeInvalid}
	}
	var reclaimed int
	writeErr := q.store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.reclaim_expired_jobs($1)`, limit).Scan(&reclaimed)
	})
	if writeErr != nil {
		return 0, &Error{code: CodePersistence, cause: writeErr}
	}
	return reclaimed, nil
}

func (q *Queue) leaseCall(ctx context.Context, access database.AccessContext, sql string, arguments ...any) error {
	writeErr := q.store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(ctx, sql, arguments...)
		return execErr
	})
	return q.mapLeaseError(writeErr)
}

func (q *Queue) mapLeaseError(writeErr error) error {
	if writeErr == nil {
		return nil
	}
	var pgErr interface{ SQLState() string }
	if errors.As(writeErr, &pgErr) && pgErr.SQLState() == leaseLostSQLState {
		return &Error{code: CodeLeaseLost, cause: writeErr}
	}
	return &Error{code: CodePersistence, cause: writeErr}
}
