package repository

// ADR-0087 §2: CONNECTOR_ADMIN-gated source connection trust verification
// (source_connection_trust_projection DRAFT -> VERIFIED, migration 000057).
//
// This is deliberately NOT one of the four ADR-0053 WORKSPACE_* authority
// operations authority_commands.go composes: it is organization/connection
// scoped, not workspace scoped, it carries a mandatory attestation instead of
// an optimistic workspace-revision precondition, and it opens its own
// SECURITY DEFINER door (app.source_connection_trust_verify) rather than
// reusing the four-operation canonical envelope. It shares this package only
// because VerifyConnectionTrust needs the same reviewed database/audit/clock
// dependencies the Store already holds.
//
// Two independent authorization layers guard the one critical invariant here
// (POKA_YOKE.md s1): the application policy gate below
// (policy.OperationSourceVerifyTrust, already restricted to CONNECTOR_ADMIN in
// internal/policy/decision.go) runs first, and the SECURITY DEFINER function
// re-checks the same CONNECTOR_ADMIN membership independently before it ever
// touches source_connection_trust_projection. Neither layer trusts the other,
// and the runtime application role still holds no UPDATE grant on that
// projection: only the definer function does.

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// The content-free error surface of the connection trust verification
// command. It is deliberately distinct from both the plain workspace codes
// and the codes the four ADR-0053 operations reserve to their own namespace.
const (
	CodeConnectionTrustRequestInvalid      ErrorCode = "WORKSPACE_CONNECTION_TRUST_REQUEST_INVALID"
	CodeConnectionTrustIdempotencyConflict ErrorCode = "WORKSPACE_CONNECTION_TRUST_IDEMPOTENCY_CONFLICT"
	CodeConnectionTrustDenied              ErrorCode = "WORKSPACE_CONNECTION_TRUST_DENIED"
	CodeConnectionTrustNotFound            ErrorCode = "WORKSPACE_CONNECTION_TRUST_NOT_FOUND"
	CodeConnectionTrustPreconditionFailed  ErrorCode = "WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED"
	CodeConnectionTrustPersistence         ErrorCode = "WORKSPACE_CONNECTION_TRUST_PERSISTENCE_FAILED"
)

// The audit event's content-free error-code vocabulary for this command. Kept
// distinct from audit.ErrorAuthorityDenied/NotFound/PreconditionFailed, which
// authority.go's validAuthorityProjection reserves to the four ADR-0053
// WORKSPACE_* operations and ResourceWorkspaceAuthorityCommand.
const (
	auditErrorConnectionTrustDenied             = "SOURCE_CONNECTION_TRUST_DENIED"
	auditErrorConnectionTrustNotFound           = "SOURCE_CONNECTION_TRUST_NOT_FOUND"
	auditErrorConnectionTrustPreconditionFailed = "SOURCE_CONNECTION_TRUST_PRECONDITION_FAILED"
)

const connectionTrustVerifyRequestSchema = "source-connection-trust-verify-request-v1"
const connectionTrustVerifyDocumentSchema = "source-connection-trust-verify-v1"

// connectionTrustVerifyRequestDocument is the canonical envelope whose RFC
// 8785 JCS bytes bind the actor-scoped idempotency receipt to this exact
// request (architecture/contracts/source-connection-trust-verify-request.schema.json,
// docs/CANONICALIZATION.md s6.2). Named (rather than an inline anonymous
// struct literal) so trust_verify_contract_test.go can marshal one instance
// and assert its field set exactly matches the schema, with no duplicated
// shape to drift out of sync.
type connectionTrustVerifyRequestDocument struct {
	SchemaVersion             string `json:"schema_version"`
	Operation                 string `json:"operation"`
	ConnectionID              string `json:"connection_id"`
	AttestedConnectorIdentity string `json:"attested_connector_identity"`
	AttestedBy                string `json:"attested_by"`
	AttestedAt                string `json:"attested_at"`
}

// VerifyConnectionTrustRequest is the ADR-0087 §2 attestation envelope. The
// organization is always the trusted AccessContext, never a client-supplied
// value: this command has no cross-tenant optimistic precondition to guard, so
// unlike the four ADR-0053 operations it carries no separate OrganizationID
// field to exact-match.
type VerifyConnectionTrustRequest struct {
	IdempotencyKey            string
	ConnectionID              string
	AttestedConnectorIdentity string
	AttestedBy                string
	AttestedAt                string // RFC 3339, e.g. "2026-09-06T12:00:00Z"
}

// VerifyConnectionTrustResult carries only the immutable, content-free
// identifiers of a completed or replayed command
// (architecture/contracts/source-connection-trust-verify-result.schema.json).
// The json tags exist so trust_verify_contract_test.go can marshal one
// instance and assert its field set exactly matches the schema; both REST
// (workspaceapi.go) and MCP (mcp_adapter.go) build their own response map
// with these same two keys rather than marshaling this struct directly.
type VerifyConnectionTrustResult struct {
	ResultID   string `json:"result_id"`
	ResultHash string `json:"result_hash"`
}

func (request VerifyConnectionTrustRequest) valid() bool {
	if !authorityRequestID(request.ConnectionID) {
		return false
	}
	if !validAttestationText(request.AttestedConnectorIdentity, 512) || !validAttestationText(request.AttestedBy, 256) {
		return false
	}
	parsed, err := time.Parse(time.RFC3339, request.AttestedAt)
	return err == nil && !parsed.IsZero()
}

// validAttestationText admits a bounded, control-character-free string. The
// attestation fields are operator-supplied metadata, never SQL, a locator or
// source content, but they are still validated defensively before they ever
// reach a canonical document or a database row.
func validAttestationText(value string, max int) bool {
	if value == "" || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// connectionTrustVerifyDocument is the canonical attestation document whose
// RFC 8785 JCS hash becomes the command's content-free audit trace
// (TrustVerificationHash). It is never itself placed in an audit event.
type connectionTrustVerifyDocument struct {
	SchemaVersion             string `json:"schema_version"`
	VerificationID            string `json:"verification_id"`
	OrganizationID            string `json:"organization_id"`
	ConnectionID              string `json:"connection_id"`
	AttestedConnectorIdentity string `json:"attested_connector_identity"`
	AttestedBy                string `json:"attested_by"`
	AttestedAt                string `json:"attested_at"`
	VerifiedBy                string `json:"verified_by"`
	VerifiedAt                string `json:"verified_at"`
}

// VerifyConnectionTrust executes the ADR-0087 §2 command: it reserves an
// actor-scoped idempotency receipt, applies the application policy gate
// (layer 1), and — only if that allows — calls the SECURITY DEFINER function
// that re-checks CONNECTOR_ADMIN independently (layer 2) and performs the
// monotonic DRAFT -> VERIFIED transition. A denied gate and a hidden/missing
// connection are deliberately mapped to the same content-free outcome by the
// transport layer (workspaceapi/mcp_adapter), exactly as the four ADR-0053
// confirmation actions collapse CodeAuthorityDenied/CodeAuthorityNotFound: no
// surface may expose whether the caller lacks the role or the connection does
// not exist.
func (store *Store) VerifyConnectionTrust(ctx context.Context, access database.AccessContext, request VerifyConnectionTrustRequest) (VerifyConnectionTrustResult, error) {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil || access.Validate() != nil {
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustRequestInvalid}
	}
	if !request.valid() {
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustRequestInvalid}
	}
	_, requestHash, err := authorityCanonicalHash(connectionTrustVerifyRequestDocument{
		SchemaVersion: connectionTrustVerifyRequestSchema, Operation: "VERIFY_TRUST",
		ConnectionID: request.ConnectionID, AttestedConnectorIdentity: request.AttestedConnectorIdentity,
		AttestedBy: request.AttestedBy, AttestedAt: request.AttestedAt,
	})
	if err != nil {
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	attestedAt, parseErr := time.Parse(time.RFC3339, request.AttestedAt)
	if parseErr != nil {
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustRequestInvalid}
	}

	var result VerifyConnectionTrustResult
	var terminalCode ErrorCode
	err = store.database.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		created, status, existingResultID, existingResultHash, reserveErr := reserveConnectionTrustVerification(
			txCtx, tx, access.OrganizationID, access.PrincipalID, keyHash, request.ConnectionID, requestHash,
			request.AttestedConnectorIdentity, request.AttestedBy, attestedAt.UTC())
		if reserveErr != nil {
			return reserveErr
		}
		if !created {
			switch status {
			case "SUCCESS":
				result = VerifyConnectionTrustResult{ResultID: existingResultID, ResultHash: existingResultHash}
				return nil
			case "DENIED":
				terminalCode = CodeConnectionTrustDenied
				return nil
			case "NOT_FOUND":
				terminalCode = CodeConnectionTrustNotFound
				return nil
			case "PRECONDITION_FAILED":
				terminalCode = CodeConnectionTrustPreconditionFailed
				return nil
			default:
				return &Error{code: CodeConnectionTrustIdempotencyConflict}
			}
		}

		allowed, gateErr := store.connectionTrustActorGate(txCtx, tx, access)
		if gateErr != nil {
			return gateErr
		}
		if !allowed {
			terminalCode = CodeConnectionTrustDenied
			return store.terminalizeConnectionTrustVerification(txCtx, tx, access, keyHash,
				"DENIED", audit.OutcomeDenied, auditErrorConnectionTrustDenied)
		}

		// The SECURITY DEFINER call below can fail with any of its own closed
		// ERRCODEs (wrong role, separation of duty, hidden connection, wrong
		// lifecycle state) as an ordinary business decision, not an
		// infrastructure fault -- but a failed statement still aborts the
		// whole PostgreSQL transaction unless it runs inside its own
		// SAVEPOINT. Without this, terminalizeConnectionTrustVerification's
		// own INSERT/UPDATE below would themselves fail with "current
		// transaction is aborted", turning a correctly classified DENIED/
		// NOT_FOUND/PRECONDITION_FAILED outcome into an unclassified
		// persistence failure instead.
		if _, spErr := tx.Exec(txCtx, `SAVEPOINT source_connection_trust_verify_attempt`); spErr != nil {
			return spErr
		}
		var trustRecordID string
		sqlErr := tx.QueryRow(txCtx, `SELECT app.source_connection_trust_verify($1, $2, $3, $4)`,
			request.ConnectionID, request.AttestedConnectorIdentity, request.AttestedBy, attestedAt.UTC()).Scan(&trustRecordID)
		if sqlErr != nil {
			status, code, auditCode := classifyConnectionTrustVerifySQLError(sqlErr)
			if status == "" {
				return sqlErr
			}
			if _, rollbackErr := tx.Exec(txCtx, `ROLLBACK TO SAVEPOINT source_connection_trust_verify_attempt`); rollbackErr != nil {
				return rollbackErr
			}
			terminalCode = code
			return store.terminalizeConnectionTrustVerification(txCtx, tx, access, keyHash, status, audit.OutcomeDenied, auditCode)
		}
		if _, relErr := tx.Exec(txCtx, `RELEASE SAVEPOINT source_connection_trust_verify_attempt`); relErr != nil {
			return relErr
		}

		verificationID, idErr := store.generatedID("wctv_")
		if idErr != nil {
			return &Error{code: CodeConnectionTrustPersistence, cause: idErr}
		}
		verifiedAt := store.now().UTC()
		_, canonicalHash, hashErr := authorityCanonicalHash(connectionTrustVerifyDocument{
			SchemaVersion: connectionTrustVerifyDocumentSchema, VerificationID: verificationID,
			OrganizationID: access.OrganizationID, ConnectionID: request.ConnectionID,
			AttestedConnectorIdentity: request.AttestedConnectorIdentity, AttestedBy: request.AttestedBy,
			AttestedAt: attestedAt.UTC().Format(time.RFC3339), VerifiedBy: access.PrincipalID,
			VerifiedAt: verifiedAt.Format(time.RFC3339),
		})
		if hashErr != nil {
			return &Error{code: CodeConnectionTrustPersistence, cause: hashErr}
		}
		if err := store.completeConnectionTrustVerificationSuccess(txCtx, tx, access, keyHash,
			verificationID, canonicalHash, request.ConnectionID, verifiedAt); err != nil {
			return err
		}
		result = VerifyConnectionTrustResult{ResultID: verificationID, ResultHash: canonicalHash}
		return nil
	})
	if err != nil {
		if isCommandResultError(err) {
			return VerifyConnectionTrustResult{}, err
		}
		return VerifyConnectionTrustResult{}, &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	if terminalCode != "" {
		return VerifyConnectionTrustResult{}, &Error{code: terminalCode}
	}
	return result, nil
}

// connectionTrustActorGate resolves the current actor exactly the way
// internal/source/registration.Service.actorGate does and asks the pure
// organization policy for source.verify_trust. A false result never
// distinguishes "no such actor" from "insufficient role" — the caller must
// collapse it with a hidden/missing connection into one content-free outcome.
func (store *Store) connectionTrustActorGate(ctx context.Context, tx database.Transaction, access database.AccessContext) (bool, error) {
	var organizationStatus, principalStatus string
	var sessionRevision int64
	err := tx.QueryRow(ctx, `
		SELECT organization.status, principal.status, principal.session_revision
		FROM public.organization AS organization
		JOIN public.principal AS principal
		  ON principal.organization_id = organization.id
		WHERE organization.id = $1 AND principal.id = $2`, access.OrganizationID, access.PrincipalID).
		Scan(&organizationStatus, &principalStatus, &sessionRevision)
	if err != nil {
		if database.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	rows, err := tx.Query(ctx, `
		SELECT role FROM public.organization_role_assignment
		WHERE organization_id = $1 AND principal_id = $2 AND revoked_at IS NULL
		ORDER BY role`, access.OrganizationID, access.PrincipalID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	roles := []policy.OrganizationRole{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return false, err
		}
		roles = append(roles, policy.OrganizationRole(role))
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	decision := policy.EvaluateOrganization(policy.OrganizationRequest{
		Operation: policy.OperationSourceVerifyTrust,
		Subject: policy.Subject{
			OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID,
			Status: policy.PrincipalStatus(principalStatus), SessionRevision: sessionRevision,
			OrganizationRoles: roles,
		},
		Organization: policy.Organization{ID: access.OrganizationID, Status: policy.OrganizationStatus(organizationStatus)},
	})
	return decision.Allowed, nil
}

// classifyConnectionTrustVerifySQLError maps the SECURITY DEFINER function's
// closed ERRCODE vocabulary onto a terminal receipt status, repository error
// code and audit error code. Any other SQLSTATE (or none) is an
// infrastructure failure: the caller rolls the whole transaction back rather
// than writing a false terminal receipt.
func classifyConnectionTrustVerifySQLError(err error) (status string, code ErrorCode, auditCode string) {
	switch database.SQLStateCode(err) {
	case "42501":
		return "DENIED", CodeConnectionTrustDenied, auditErrorConnectionTrustDenied
	case "P0002":
		return "NOT_FOUND", CodeConnectionTrustNotFound, auditErrorConnectionTrustNotFound
	case "55000":
		return "PRECONDITION_FAILED", CodeConnectionTrustPreconditionFailed, auditErrorConnectionTrustPreconditionFailed
	case "23514":
		// migration 000059's own defense-in-depth attestation-completeness
		// check (B2): the Go request validator above already rejects an
		// empty/incomplete attestation before this call, so a legitimate
		// caller never reaches this branch; it exists so a direct database
		// session as the runtime role cannot bypass the requirement either.
		return "PRECONDITION_FAILED", CodeConnectionTrustPreconditionFailed, auditErrorConnectionTrustPreconditionFailed
	default:
		return "", "", ""
	}
}

// reserveConnectionTrustVerification inserts the actor-scoped PENDING receipt
// or, on a replay, loads and locks the existing row. A stored row whose
// canonical fields do not exactly match this request is a key reused across a
// different command: the caller maps that to CodeConnectionTrustIdempotencyConflict.
func reserveConnectionTrustVerification(ctx context.Context, tx database.Transaction, organizationID, actorID, keyHash,
	connectionID, requestHash, attestedConnectorIdentity, attestedBy string, attestedAt time.Time) (created bool, status, resultID, resultHash string, err error) {
	tag, execErr := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_verification (
			organization_id, actor_principal_id, idempotency_key_hash,
			connection_id, operation, canonical_request_hash,
			attested_connector_identity, attested_by, attested_at
		) VALUES ($1,$2,$3,$4,'VERIFY_TRUST',$5,$6,$7,$8)
		ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING
	`, organizationID, actorID, keyHash, connectionID, requestHash, attestedConnectorIdentity, attestedBy, attestedAt)
	if execErr != nil {
		return false, "", "", "", execErr
	}
	if tag.RowsAffected() == 1 {
		return true, "PENDING", "", "", nil
	}
	var storedRequestHash, storedConnectionID, storedIdentity, storedBy, storedStatus string
	var storedAttestedAt time.Time
	var storedResultID, storedResultHash *string
	if scanErr := tx.QueryRow(ctx, `
		SELECT canonical_request_hash, connection_id, attested_connector_identity, attested_by, attested_at,
		       status, verification_id, canonical_hash
		  FROM public.source_connection_trust_verification
		 WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		 FOR UPDATE
	`, organizationID, actorID, keyHash).Scan(&storedRequestHash, &storedConnectionID, &storedIdentity, &storedBy,
		&storedAttestedAt, &storedStatus, &storedResultID, &storedResultHash); scanErr != nil {
		return false, "", "", "", scanErr
	}
	if storedRequestHash != requestHash || storedConnectionID != connectionID || storedIdentity != attestedConnectorIdentity ||
		storedBy != attestedBy || !storedAttestedAt.Equal(attestedAt) {
		return false, "", "", "", nil
	}
	if storedResultID != nil {
		resultID = *storedResultID
	}
	if storedResultHash != nil {
		resultHash = *storedResultHash
	}
	return false, storedStatus, resultID, resultHash, nil
}

// terminalizeConnectionTrustVerification appends the one content-free audit
// event for a non-success terminal (DENIED/NOT_FOUND/PRECONDITION_FAILED) and
// seals the receipt to that same terminal, atomically with the audit append.
func (store *Store) terminalizeConnectionTrustVerification(ctx context.Context, tx database.Transaction, access database.AccessContext,
	keyHash, status string, outcome audit.Outcome, errorCode string) error {
	eventID, err := store.generatedID("aud_")
	if err != nil {
		return &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	actorID := access.PrincipalID
	code := errorCode
	if _, err := store.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: audit.ActionSourceConnectionTrustVerified, ResourceType: audit.ResourceSourceConnection,
		ResourceID: keyHash, RequestID: access.RequestID, Outcome: outcome, ErrorCode: &code,
		OccurredAt: store.now().UTC(),
	}); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.source_connection_trust_verification
		   SET status = $5, audit_event_id = $4, terminal_at = transaction_timestamp()
		 WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3 AND status = 'PENDING'
	`, access.OrganizationID, access.PrincipalID, keyHash, eventID, status)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	return nil
}

// completeConnectionTrustVerificationSuccess seals the receipt SUCCESS with
// its generated verification id and canonical hash, atomically with the one
// content-free success audit event. The event carries source_connection_id
// (review remark, review-opus-s2-4-5.md) so the audit trail alone identifies
// which connection was verified, without requiring a join back to the
// actor-scoped receipt table.
func (store *Store) completeConnectionTrustVerificationSuccess(ctx context.Context, tx database.Transaction, access database.AccessContext,
	keyHash, verificationID, canonicalHash, connectionID string, verifiedAt time.Time) error {
	eventID, err := store.generatedID("aud_")
	if err != nil {
		return &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	actorID := access.PrincipalID
	trustVerificationID := verificationID
	trustVerificationHash := canonicalHash
	sourceConnectionID := connectionID
	if _, err := store.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID: eventID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: audit.ActionSourceConnectionTrustVerified, ResourceType: audit.ResourceSourceConnection,
		ResourceID: verificationID, RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
		Metadata: audit.Metadata{
			TrustVerificationID: &trustVerificationID, TrustVerificationHash: &trustVerificationHash,
			SourceConnectionID: &sourceConnectionID,
		},
		OccurredAt: store.now().UTC(),
	}); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.source_connection_trust_verification
		   SET status = 'SUCCESS', audit_event_id = $4, verification_id = $5, canonical_hash = $6,
		       verified_by = $2, verified_at = $7, terminal_at = transaction_timestamp()
		 WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3 AND status = 'PENDING'
	`, access.OrganizationID, access.PrincipalID, keyHash, eventID, verificationID, canonicalHash, verifiedAt)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodeConnectionTrustPersistence, cause: err}
	}
	return nil
}
