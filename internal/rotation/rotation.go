// Package rotation is the privileged control-plane owner of deployment secret
// rotation (ADR-0070). It orchestrates the fenced two-phase state machine in
// migration 000019: a worker-only begin that registers the previous/active
// pair and places the first re-wrap job, and a completion that reaches COMPLETE
// only at zero remaining wrappers/projections. Every terminal outcome leaves
// one content-free key.rotation audit event; a refusal or failed precondition
// is audited with its closed error code in a separate transaction, so the
// audit stream never loses an attempt (AUD-005).
//
// The package holds no ambient authority: it runs as the trusted
// knowvault_worker role, the only role granted EXECUTE on the rotation
// functions, and it names the exact tenant and key pair. Neither the web/API
// runtime nor the sync worker can reach these functions.
package rotation

import (
	"context"
	"errors"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// The two closeable rotation domains (ADR-0070 §1.2). They are the exact
// strings the database and the audit projection accept.
const (
	DomainKEK    = "KEK"
	DomainDigest = "DIGEST"
)

// rotationBatchSize is the bounded per-job candidate batch. A full batch
// re-enqueues the next pass; a short batch means every candidate was covered,
// so the same transaction may close the rotation.
const rotationBatchSize = 1000

// maxSafeInt64 mirrors the audit/database bound for key versions: JSON
// round-trippable without precision loss.
const maxSafeInt64 = int64(9007199254740991)

// ErrorCode is content-free and safe for logs and metrics.
type ErrorCode string

const (
	CodeInvalid     ErrorCode = "ROTATION_INVALID"
	CodeDenied      ErrorCode = "ROTATION_DENIED"
	CodeFailed      ErrorCode = "ROTATION_FAILED"
	CodePersistence ErrorCode = "ROTATION_PERSISTENCE_FAILED"
)

// Error preserves a safe code and hides the underlying database error.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// CodeOf maps any error to a safe code.
func CodeOf(err error) ErrorCode {
	var rotationError *Error
	if errors.As(err, &rotationError) {
		return rotationError.code
	}
	return CodePersistence
}

// refusalSQLStates are the fail-closed SQL states of the rotation functions:
// a denied role/tenant context, or an invalid/refused key pair. Everything else
// (zero-wrappers, unknown pair, no rotation in progress) is a failed
// precondition, not a refusal (audit contract, ADR-0070).
func refusalSQLState(state string) bool {
	return state == "42501" || state == "22023"
}

// rotationState is the projection of app.rotation_state for one domain.
type rotationState struct {
	phase           string
	previousRef     string
	previousVersion int64
	activeRef       string
	activeVersion   int64
	watermark       int64
}

// Coordinator drives begin and complete for one rotation domain over the
// worker-role store. It is constructed only by composition or by tests acting
// as composition.
type Coordinator struct {
	db    *database.Store
	queue *jobs.Queue
	audit *audit.Store
	now   func() time.Time
	newID func(string) (string, error)
}

// NewCoordinator wires a rotation coordinator over a store opened as the
// knowvault_worker role.
func NewCoordinator(db *database.Store, queue *jobs.Queue, now func() time.Time, newID func(string) (string, error)) (*Coordinator, error) {
	if db == nil || queue == nil || now == nil || newID == nil {
		return nil, &Error{code: CodeInvalid}
	}
	auditStore, err := audit.NewStore(db)
	if err != nil {
		return nil, &Error{code: CodePersistence, cause: err}
	}
	return &Coordinator{db: db, queue: queue, audit: auditStore, now: now, newID: newID}, nil
}

// Begin registers the previous/active pair of a domain, places the first
// re-wrap job in the same transaction and audits the begin on SUCCESS. A
// repeat of the same pair is idempotent; a begin under a different in-flight
// pair is refused. The active pair of the mounted keys must already be live in
// the secret manifest before begin is called, so writes seal under the active
// pair from the first moment of the window (ADR-0070 §1.3).
func (c *Coordinator) Begin(ctx context.Context, access database.AccessContext, domain, previousRef string, previousVersion int64, activeRef string, activeVersion int64) error {
	if c == nil || c.db == nil || c.queue == nil || c.audit == nil || access.Validate() != nil {
		return &Error{code: CodeInvalid}
	}
	if !validDomain(domain) || !validReference(previousRef) || !validReference(activeRef) ||
		!validVersion(previousVersion) || !validVersion(activeVersion) ||
		previousRef == activeRef && previousVersion == activeVersion {
		return &Error{code: CodeInvalid}
	}

	jobType := jobs.TypeKEKRewrap
	if domain == DomainDigest {
		jobType = jobs.TypeDigestRecompute
	}
	eventID, err := c.newID("audit")
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	jobID, err := c.newID("job")
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}

	err = c.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.rotation_begin($1, $2, $3, $4, $5)`,
			domain, previousRef, previousVersion, activeRef, activeVersion); err != nil {
			return err
		}
		// The re-wrap pass starts from this transaction: job placement and the
		// registered pair commit atomically, so a rotation can never be begun
		// without a driver and a job can never outlive the pair it serves.
		if _, err := c.queue.EnqueueInTransaction(ctx, access, tx, jobs.Spec{
			JobID: jobID, Type: jobType, Payload: jobs.Payload{},
			IdempotencyKey: "rotation:begin:" + domain, Priority: 0, MaxAttempts: 5,
		}); err != nil {
			return err
		}
		return c.appendRotationAudit(ctx, access, tx, audit.ActionKeyRotationBegin, eventID,
			domain, activeRef, activeVersion)
	})
	if err != nil {
		c.appendRefusalAudit(ctx, access, audit.ActionKeyRotationBegin, domain, err)
		return &Error{code: refusalCode(err), cause: err}
	}
	return nil
}

// Complete closes a rotation window: for KEK the zero-wrappers precondition is
// enforced by the database, for DIGEST the zero-remaining precondition, and
// the audit event is written in the same transaction. A repeat of the same
// active pair/previous version is idempotent. A failed precondition (wrappers
// still under the previous pair, an unknown pair, no rotation in progress) is
// audited FAILED and returned as CodeFailed.
func (c *Coordinator) Complete(ctx context.Context, access database.AccessContext, domain string) error {
	if c == nil || c.db == nil || c.audit == nil || access.Validate() != nil || !validDomain(domain) {
		return &Error{code: CodeInvalid}
	}
	eventID, err := c.newID("audit")
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}

	err = c.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		state, err := readRotationState(ctx, tx, domain)
		if err != nil {
			return err
		}
		if state.phase == "COMPLETE" {
			return nil // a closed rotation is already complete; no second event
		}
		if domain == DomainKEK {
			if _, err := tx.Exec(ctx, `SELECT app.kek_rotation_complete($1, $2)`,
				state.activeRef, state.activeVersion); err != nil {
				return err
			}
		} else {
			if _, err := tx.Exec(ctx, `SELECT app.digest_rotation_complete($1)`,
				state.previousVersion); err != nil {
				return err
			}
		}
		return c.appendRotationAudit(ctx, access, tx, audit.ActionKeyRotationComplete, eventID,
			domain, state.activeRef, state.activeVersion)
	})
	if err != nil {
		c.appendRefusalAudit(ctx, access, audit.ActionKeyRotationComplete, domain, err)
		return &Error{code: refusalCode(err), cause: err}
	}
	return nil
}

// appendRotationAudit appends the SUCCESS begin event in the caller's
// transaction (the begin/complete success contract, ADR-0070).
func (c *Coordinator) appendRotationAudit(ctx context.Context, access database.AccessContext, tx database.Transaction,
	action audit.Action, eventID, domain, activeRef string, activeVersion int64) error {
	return appendRotationSuccessAudit(ctx, c.audit, access, tx, action, eventID, domain, activeRef, activeVersion, c.now())
}

// appendRotationSuccessAudit appends the SUCCESS begin/complete event in the
// caller's transaction: a SYSTEM actor, the active key reference as the
// resource id, and the exact domain/reference/version triple in metadata (audit
// contract, ADR-0070). The complete event is written by whoever closes the
// window — the handler closing a drained rotation in the same transaction, or
// the coordinator on a manual complete — so a closed rotation is never without
// its event.
func appendRotationSuccessAudit(ctx context.Context, store *audit.Store, access database.AccessContext, tx database.Transaction,
	action audit.Action, eventID, domain, activeRef string, activeVersion int64, occurredAt time.Time) error {
	domainValue := domain
	referenceValue := activeRef
	versionValue := activeVersion
	_, err := store.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID:      eventID,
		ActorType:    audit.ActorSystem,
		Action:       action,
		ResourceType: audit.ResourceCryptoKey,
		ResourceID:   activeRef,
		RequestID:    access.RequestID,
		Outcome:      audit.OutcomeSuccess,
		OccurredAt:   occurredAt,
		Metadata: audit.Metadata{
			RotationDomain: &domainValue,
			KeyReference:   &referenceValue,
			KeyVersion:     &versionValue,
		},
	})
	return err
}

// appendRefusalAudit records a denied or failed begin/complete in its own
// transaction, so the attempt is never lost even when the main transaction
// rolled back. The event names exactly the domain and nothing else: a refusal
// has no proven pair to name (audit contract, ADR-0070).
func (c *Coordinator) appendRefusalAudit(ctx context.Context, access database.AccessContext,
	action audit.Action, domain string, cause error) {
	outcome := audit.OutcomeFailed
	errorCode := audit.ErrorRotationFailed
	if refusalSQLState(sqlStateOf(cause)) {
		outcome = audit.OutcomeDenied
		errorCode = audit.ErrorRotationDenied
	}
	eventID, err := c.newID("audit")
	if err != nil {
		return
	}
	domainValue := domain
	_ = c.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := c.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
			EventID:      eventID,
			ActorType:    audit.ActorSystem,
			Action:       action,
			ResourceType: audit.ResourceCryptoKey,
			ResourceID:   "crypto-key-rotation",
			RequestID:    access.RequestID,
			Outcome:      outcome,
			ErrorCode:    &errorCode,
			OccurredAt:   c.now(),
			Metadata:     audit.Metadata{RotationDomain: &domainValue},
		})
		return err
	})
}

// refusalCode maps a failed operation to the coordinator-facing code: a
// refusal is CodeDenied, everything else CodeFailed.
func refusalCode(err error) ErrorCode {
	if refusalSQLState(sqlStateOf(err)) {
		return CodeDenied
	}
	return CodeFailed
}

// sqlStateOf extracts the PostgreSQL SQLSTATE from a wrapped error, or "".
func sqlStateOf(err error) string {
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		return state.SQLState()
	}
	return ""
}

// readRotationState reads one domain's rotation state inside the caller's
// transaction. An absent state is an error: no rotation in progress.
func readRotationState(ctx context.Context, tx database.Transaction, domain string) (rotationState, error) {
	var state rotationState
	err := tx.QueryRow(ctx, `SELECT phase,
			COALESCE(previous_reference, ''), COALESCE(previous_version, 0),
			COALESCE(active_reference, ''), COALESCE(active_version, 0), watermark
		FROM app.rotation_state($1)`, domain).Scan(
		&state.phase, &state.previousRef, &state.previousVersion,
		&state.activeRef, &state.activeVersion, &state.watermark)
	return state, err
}

func validDomain(domain string) bool {
	return domain == DomainKEK || domain == DomainDigest
}

func validReference(reference string) bool {
	return reference != "" && len(reference) <= 1024 && strings.TrimSpace(reference) == reference
}

func validVersion(version int64) bool {
	return version >= 1 && version <= maxSafeInt64
}
