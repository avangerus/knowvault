package repository

// The authority-family idempotency receipt (ADR-0053/0054). This is a separate
// receipt family from workspace_command_receipt: an authority command never
// creates a WorkspaceRevision. The namespace is
// (organization_id, actor_principal_id, idempotency_key_hash), where
// organization_id is ALWAYS the trusted AccessContext.OrganizationID. The raw
// Idempotency-Key never enters the canonical request bytes and is never stored;
// only its SHA-256 participates in the namespace.

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
)

type authorityReservation struct {
	created   bool
	commandID string
	status    receiptStatus
	// resultID/resultHash are set only when replaying a stored SUCCESS.
	resultID   string
	resultHash string
}

// authorityReceiptInsert is the closed per-operation receipt projection. Every
// field of every other operation is deliberately SQL NULL, exactly as the
// migration's projection_exact CHECK requires; the nullable columns carry `any`
// so an unset value is a genuine NULL rather than a zero.
type authorityReceiptInsert struct {
	organizationID   string
	actorPrincipalID string
	keyHash          string
	commandID        string
	operation        authorityOperation
	canonicalBytes   []byte
	canonicalHash    string

	requestOrganizationID         string
	requestWorkspaceID            string
	requestExpectedPolicyRevision string

	expectedWorkspaceRevision          any
	expectedWorkspaceConfigurationHash any
	targetPrincipalID                  any
	ttlSeconds                         any

	grantID       any
	grantRevision any
	grantHash     any

	workspaceRevision          any
	workspaceConfigurationHash any
	workspaceSourceID          any
	sourceScopeID              any
	sourceScopeRevision        any
	scopeConfigHash            any
	accessMode                 any

	confirmationActorGrantID       any
	confirmationActorGrantRevision any
	confirmationActorGrantHash     any
	warningVersion                 any
	warningContractHash            any
	acknowledgementCode            any

	confirmationID   any
	confirmationHash any
}

// reserveAuthorityCommand inserts the PENDING receipt or, on an existing key,
// resolves whether the retry is an exact replay or an idempotency conflict. It
// never selects a tenant from the request body: organization_id is the trusted
// AccessContext value on both the insert and the lookup.
func reserveAuthorityCommand(ctx context.Context, transaction database.Transaction, insert authorityReceiptInsert) (authorityReservation, error) {
	tag, err := transaction.Exec(ctx, `
		INSERT INTO public.workspace_managed_authority_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
			canonical_request_bytes, canonical_request_hash,
			request_organization_id, request_workspace_id, request_expected_policy_revision,
			request_expected_workspace_revision, request_expected_workspace_configuration_hash,
			request_target_principal_id, request_ttl_seconds,
			request_grant_id, request_grant_revision, request_grant_hash,
			request_workspace_revision, request_workspace_configuration_hash,
			request_workspace_source_id, request_source_scope_id, request_source_scope_revision,
			request_scope_config_hash, request_access_mode,
			request_confirmation_actor_grant_id, request_confirmation_actor_grant_revision,
			request_confirmation_actor_grant_hash, request_warning_version,
			request_warning_contract_hash, request_acknowledgement_code,
			request_confirmation_id, request_confirmation_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
		          $23,$24,$25,$26,$27,$28,$29,$30,$31,$32)
		ON CONFLICT (organization_id, actor_principal_id, idempotency_key_hash) DO NOTHING
	`,
		insert.organizationID, insert.actorPrincipalID, insert.keyHash, insert.commandID, string(insert.operation),
		insert.canonicalBytes, insert.canonicalHash,
		insert.requestOrganizationID, insert.requestWorkspaceID, insert.requestExpectedPolicyRevision,
		insert.expectedWorkspaceRevision, insert.expectedWorkspaceConfigurationHash,
		insert.targetPrincipalID, insert.ttlSeconds,
		insert.grantID, insert.grantRevision, insert.grantHash,
		insert.workspaceRevision, insert.workspaceConfigurationHash,
		insert.workspaceSourceID, insert.sourceScopeID, insert.sourceScopeRevision,
		insert.scopeConfigHash, insert.accessMode,
		insert.confirmationActorGrantID, insert.confirmationActorGrantRevision,
		insert.confirmationActorGrantHash, insert.warningVersion,
		insert.warningContractHash, insert.acknowledgementCode,
		insert.confirmationID, insert.confirmationHash,
	)
	if err != nil {
		return authorityReservation{}, err
	}
	if tag.RowsAffected() == 1 {
		return authorityReservation{created: true, commandID: insert.commandID, status: receiptPending}, nil
	}

	var storedOperation, storedRequestHash, storedCommandID string
	var status receiptStatus
	var resultID, resultHash *string
	if err := transaction.QueryRow(ctx, `
		SELECT operation, canonical_request_hash, command_id, status,
		       result_authority_id, result_authority_hash
		FROM public.workspace_managed_authority_command_receipt
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		FOR UPDATE
	`, insert.organizationID, insert.actorPrincipalID, insert.keyHash).Scan(
		&storedOperation, &storedRequestHash, &storedCommandID, &status, &resultID, &resultHash); err != nil {
		return authorityReservation{}, err
	}
	// A reused key that hash-differs, or names a different operation, is an
	// idempotency conflict: it creates nothing.
	if storedOperation != string(insert.operation) || storedRequestHash != insert.canonicalHash {
		return authorityReservation{}, &Error{code: CodeAuthorityIdempotencyConflict}
	}
	// A PENDING row can never be observed after commit: the deferred no-pending
	// gate forbids it. Seeing one here is an integrity failure, not a replay.
	if status == receiptPending {
		return authorityReservation{}, &Error{code: CodeAuthorityPersistence}
	}
	reservation := authorityReservation{created: false, commandID: storedCommandID, status: status}
	if status == receiptSuccess {
		if resultID == nil || resultHash == nil {
			return authorityReservation{}, &Error{code: CodeAuthorityPersistence}
		}
		reservation.resultID, reservation.resultHash = *resultID, *resultHash
	}
	return reservation, nil
}

// loadAuthorityResultBytes reads the immutable canonical bytes of the authority
// row a SUCCESS receipt bound, so a replay can return the exact stored result
// without re-deriving it.
func loadAuthorityResultBytes(ctx context.Context, transaction database.Transaction, organizationID, commandID string, operation authorityOperation) ([]byte, error) {
	var relation string
	switch operation {
	case operationConfirmationGrantIssue:
		relation = "public.workspace_source_confirmation_actor_grant"
	case operationConfirmationGrantRevoke:
		relation = "public.workspace_source_confirmation_actor_grant_revocation"
	case operationManagedConfirm:
		relation = "public.workspace_managed_grant_confirmation"
	case operationManagedConfirmRevoke:
		relation = "public.workspace_managed_grant_revocation"
	default:
		return nil, &Error{code: CodeAuthorityPersistence}
	}
	var canonical []byte
	err := transaction.QueryRow(ctx,
		"SELECT canonical_bytes FROM "+relation+" WHERE organization_id = $1 AND command_id = $2",
		organizationID, commandID).Scan(&canonical)
	if err != nil {
		if database.IsNotFound(err) {
			return nil, &Error{code: CodeAuthorityPersistence}
		}
		return nil, err
	}
	return canonical, nil
}

// terminalizeAuthorityCommand transitions the PENDING receipt to its one
// terminal state and binds its audit event. On SUCCESS it also binds the exact
// result ID and hash; on any failure both stay NULL. The deferred gates prove,
// at commit, that a SUCCESS binds exactly one authority row and every terminal
// binds exactly one audit event.
func terminalizeAuthorityCommand(ctx context.Context, transaction database.Transaction, organizationID, actorPrincipalID, keyHash string, status receiptStatus, resultID, resultHash, auditEventID string) error {
	var resultIDValue, resultHashValue any
	if status == receiptSuccess {
		if resultID == "" || resultHash == "" {
			return &Error{code: CodeAuthorityPersistence}
		}
		resultIDValue, resultHashValue = resultID, resultHash
	} else if status != receiptDenied && status != receiptNotFound && status != receiptPreconditionFailed {
		return &Error{code: CodeAuthorityPersistence}
	}
	tag, err := transaction.Exec(ctx, `
		UPDATE public.workspace_managed_authority_command_receipt
		SET status = $4, result_authority_id = $5, result_authority_hash = $6,
		    audit_event_id = $7, terminal_at = transaction_timestamp()
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3 AND status = 'PENDING'
	`, organizationID, actorPrincipalID, keyHash, string(status), resultIDValue, resultHashValue, auditEventID)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodeAuthorityPersistence, cause: err}
	}
	return nil
}

// authorityTransactionEpoch reads the one PostgreSQL transaction-second the
// command may use for every server-owned timestamp it derives, so a client
// clock can neither backdate a grant nor stretch its own TTL. It computes the
// value inline rather than through app.authority_transaction_epoch(): that
// SECURITY DEFINER helper is reserved to the trigger gates and is deliberately
// not granted to the runtime role, but it is by definition equal to
// extract(epoch FROM date_trunc('second', transaction_timestamp())), which the
// gates re-derive and compare against every stored authority timestamp.
func authorityTransactionEpoch(ctx context.Context, transaction database.Transaction) (int64, error) {
	var epoch int64
	if err := transaction.QueryRow(ctx, `SELECT extract(epoch FROM date_trunc('second', transaction_timestamp()))::bigint`).Scan(&epoch); err != nil {
		return 0, err
	}
	return epoch, nil
}

func receiptStatusForTerminal(terminal authorityTerminal) receiptStatus {
	switch terminal {
	case terminalSuccess:
		return receiptSuccess
	case terminalDenied:
		return receiptDenied
	case terminalNotFound:
		return receiptNotFound
	default:
		return receiptPreconditionFailed
	}
}
