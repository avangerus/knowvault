package postgres_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
)

// End-to-end coverage of all four ADR-0053 operations at head, each executed as
// the runtime role through its whole command transaction: reserve PENDING,
// insert the authority row, append the audit event, terminalize, commit.
//
// workspace_managed_authority_command_test.go proves the grant-issue path and
// the boundary's structural gates. This file proves the remaining three
// operations, every terminal failure outcome, and — for each operation — that a
// SUCCESS audit event whose metadata is well-formed but names a different row
// than the one persisted is rejected.

const (
	authorityOpsOrganization = "org_authority_ops"
	authorityOpsOwner        = "usr_authority_ops_owner"
	authorityOpsWorkspace    = "ws_authority_ops"

	operationGrantRevoke   = "WORKSPACE_CONFIRMATION_GRANT_REVOKE"
	operationConfirm       = "WORKSPACE_MANAGED_CONFIRM"
	operationConfirmRevoke = "WORKSPACE_MANAGED_CONFIRM_REVOKE"

	authorityReasonGrantRevoked  = "AUTHORITY_REVOKED"
	authorityReasonAccessRevoked = "ACCESS_REVOKED"
	authorityAccessMode          = "WORKSPACE_MANAGED"
)

// authorityOpsFixture is a real tenant complete enough for every operation: a
// workspace-managed source snapshot, its scope chain, a policy registry
// revision, and the warning contract migration 000010 seeds.
type authorityOpsFixture struct {
	organizationID string
	ownerID        string
	workspaceID    string

	policyID     string
	policyNumber int64

	workspaceRevision int64
	workspaceConfHash string

	workspaceSourceID   string
	sourceScopeID       string
	sourceScopeRevision int64
	scopeConfigHash     string
}

func setupAuthorityOpsFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool) authorityOpsFixture {
	t.Helper()
	return setupAuthorityOpsTenant(t, ctx, admin, authorityOpsOrganization, authorityOpsOwner, authorityOpsWorkspace)
}

// setupAuthorityOpsTenant builds the same fixture for an arbitrary tenant, so a
// test can hold two of them at once and observe cross-tenant contention.
func setupAuthorityOpsTenant(
	t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, ownerID, workspaceID string,
) authorityOpsFixture {
	t.Helper()
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	insertSourceScopeDraftChain(t, ctx, admin, organizationID, ownerID,
		organizationID, "workspace_managed")
	insertWorkspaceSourceSnapshot(t, ctx, admin, organizationID, ownerID,
		workspaceID, "workspace_managed")

	clock := fetchAuthorityClock(t, ctx, admin)
	policyID := "policy-" + organizationID + "-0001"
	insertPolicyRegistryRow(t, ctx, admin, organizationID, 1, policyID,
		authoritySha256(0x70), ownerID, clock.grantedAt)

	var revision int64
	var confHash string
	if err := admin.QueryRow(ctx, `
		SELECT workspace.current_revision, wr.configuration_hash
		FROM public.workspace AS workspace
		JOIN public.workspace_revision AS wr
		  ON wr.organization_id = workspace.organization_id
		 AND wr.workspace_id = workspace.id
		 AND wr.revision = workspace.current_revision
		WHERE workspace.organization_id = $1 AND workspace.id = $2
	`, organizationID, workspaceID).Scan(&revision, &confHash); err != nil {
		t.Fatalf("load current workspace revision: %v", err)
	}

	return authorityOpsFixture{
		organizationID:      organizationID,
		ownerID:             ownerID,
		workspaceID:         workspaceID,
		policyID:            policyID,
		policyNumber:        1,
		workspaceRevision:   revision,
		workspaceConfHash:   confHash,
		workspaceSourceID:   testWorkspaceBindingID,
		sourceScopeID:       confirmationScopeID,
		sourceScopeRevision: 1,
		scopeConfigHash:     confirmationScopeHash,
	}
}

// authorityOp is one command of any of the four operations. Every operation
// shares the same receipt lifecycle, so they share one runner; what differs is
// the request projection, the result document and the audit metadata, which the
// three builders below supply.
type authorityOp struct {
	operation string
	commandID string
	keyHash   string
	actor     string
	// status is the terminal receipt status. Anything but SUCCESS inserts no
	// authority row.
	status string

	// The created row.
	resultID string
	// Parent identity, for the two revocations.
	parentID       string
	parentRevision int64
	parentHash     string

	auditEventID string
	// forgeAuditMetadata substitutes a well-formed SUCCESS metadata set that
	// names something other than the row actually persisted.
	forgeAuditMetadata func(audit.Metadata) audit.Metadata

	// Derived inside the command transaction from the one transaction-second.
	at string
}

func (op authorityOp) reasonCode() string {
	if op.operation == operationGrantRevoke {
		return authorityReasonGrantRevoked
	}
	return authorityReasonAccessRevoked
}

func (fixture authorityOpsFixture) request(op authorityOp) map[string]any {
	request := map[string]any{
		"organization_id":          fixture.organizationID,
		"workspace_id":             fixture.workspaceID,
		"expected_policy_revision": fixture.policyID,
	}
	switch op.operation {
	case operationGrantRevoke:
		request["grant_id"] = op.parentID
		request["grant_revision"] = op.parentRevision
		request["grant_hash"] = op.parentHash
	case operationConfirm:
		request["workspace_revision"] = fixture.workspaceRevision
		request["workspace_configuration_hash"] = fixture.workspaceConfHash
		request["workspace_source_id"] = fixture.workspaceSourceID
		request["source_scope_id"] = fixture.sourceScopeID
		request["source_scope_revision"] = fixture.sourceScopeRevision
		request["scope_config_hash"] = fixture.scopeConfigHash
		request["access_mode"] = authorityAccessMode
		request["confirmation_actor_grant_id"] = op.parentID
		request["confirmation_actor_grant_revision"] = op.parentRevision
		request["confirmation_actor_grant_hash"] = op.parentHash
		request["warning_version"] = confirmationWarningVer
		request["warning_contract_hash"] = confirmationWarnHash
		request["acknowledgement_code"] = confirmationAckCode
	case operationConfirmRevoke:
		request["confirmation_id"] = op.parentID
		request["confirmation_hash"] = op.parentHash
	}
	return map[string]any{
		"schema_version": authorityCommandRequestSchema,
		"operation":      op.operation,
		"request":        request,
	}
}

// document is the canonical result contract of the operation. The hash stored
// beside it is SHA-256 of exactly these bytes, which is what PostgreSQL proves.
func (fixture authorityOpsFixture) document(op authorityOp) map[string]any {
	switch op.operation {
	case operationGrantRevoke:
		return map[string]any{
			"schema_version":  "workspace-source-confirmation-grant-revocation-v1",
			"revocation_id":   op.resultID,
			"organization_id": fixture.organizationID,
			"grant_id":        op.parentID,
			"grant_revision":  op.parentRevision,
			"grant_hash":      op.parentHash,
			"revoked_by":      op.actor,
			"revoked_at":      op.at,
			"reason_code":     op.reasonCode(),
			"policy_revision": fixture.policyID,
		}
	case operationConfirm:
		return map[string]any{
			"schema_version":                    "workspace-managed-confirmation-v1",
			"confirmation_id":                   op.resultID,
			"organization_id":                   fixture.organizationID,
			"workspace_id":                      fixture.workspaceID,
			"workspace_revision":                fixture.workspaceRevision,
			"workspace_configuration_hash":      fixture.workspaceConfHash,
			"workspace_source_id":               fixture.workspaceSourceID,
			"source_scope_id":                   fixture.sourceScopeID,
			"source_scope_revision":             fixture.sourceScopeRevision,
			"scope_config_hash":                 fixture.scopeConfigHash,
			"access_mode":                       authorityAccessMode,
			"confirmation_actor_grant_id":       op.parentID,
			"confirmation_actor_grant_revision": op.parentRevision,
			"confirmation_actor_grant_hash":     op.parentHash,
			"warning_version":                   confirmationWarningVer,
			"warning_contract_hash":             confirmationWarnHash,
			"acknowledgement_code":              confirmationAckCode,
			"confirmed_by":                      op.actor,
			"confirmed_at":                      op.at,
			"policy_revision":                   fixture.policyID,
		}
	default:
		return map[string]any{
			"schema_version":    "workspace-managed-confirmation-revocation-v1",
			"revocation_id":     op.resultID,
			"organization_id":   fixture.organizationID,
			"confirmation_id":   op.parentID,
			"confirmation_hash": op.parentHash,
			"revoked_by":        op.actor,
			"revoked_at":        op.at,
			"reason_code":       op.reasonCode(),
			"policy_revision":   fixture.policyID,
		}
	}
}

func (fixture authorityOpsFixture) reserve(t *testing.T, ctx context.Context, tx pgx.Tx, op authorityOp) error {
	t.Helper()
	bytes, hash := authorityCanonicalBytes(t, fixture.request(op))

	var grantID, grantHash, confirmationID, confirmationHash any
	var grantRevision any
	var workspaceRevision, sourceScopeRevision, actorGrantRevision any
	var confHash, sourceID, scopeID, scopeHash, accessMode any
	var actorGrantID, actorGrantHash, warningVersion, warningHash, ackCode any

	switch op.operation {
	case operationGrantRevoke:
		grantID, grantRevision, grantHash = op.parentID, op.parentRevision, op.parentHash
	case operationConfirm:
		workspaceRevision, confHash = fixture.workspaceRevision, fixture.workspaceConfHash
		sourceID, scopeID = fixture.workspaceSourceID, fixture.sourceScopeID
		sourceScopeRevision, scopeHash = fixture.sourceScopeRevision, fixture.scopeConfigHash
		accessMode = authorityAccessMode
		actorGrantID, actorGrantRevision, actorGrantHash = op.parentID, op.parentRevision, op.parentHash
		warningVersion, warningHash, ackCode = confirmationWarningVer, confirmationWarnHash, confirmationAckCode
	case operationConfirmRevoke:
		confirmationID, confirmationHash = op.parentID, op.parentHash
	}

	_, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_managed_authority_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
			canonical_request_bytes, canonical_request_hash,
			request_organization_id, request_workspace_id, request_expected_policy_revision,
			request_grant_id, request_grant_revision, request_grant_hash,
			request_workspace_revision, request_workspace_configuration_hash,
			request_workspace_source_id, request_source_scope_id, request_source_scope_revision,
			request_scope_config_hash, request_access_mode,
			request_confirmation_actor_grant_id, request_confirmation_actor_grant_revision,
			request_confirmation_actor_grant_hash, request_warning_version,
			request_warning_contract_hash, request_acknowledgement_code,
			request_confirmation_id, request_confirmation_hash
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
		          $21,$22,$23,$24,$25,$26,$27,$28)
	`, fixture.organizationID, op.actor, op.keyHash, op.commandID, op.operation,
		bytes, hash, fixture.organizationID, fixture.workspaceID, fixture.policyID,
		grantID, grantRevision, grantHash,
		workspaceRevision, confHash, sourceID, scopeID, sourceScopeRevision, scopeHash, accessMode,
		actorGrantID, actorGrantRevision, actorGrantHash, warningVersion, warningHash, ackCode,
		confirmationID, confirmationHash)
	return err
}

func (fixture authorityOpsFixture) insertResult(t *testing.T, ctx context.Context, tx pgx.Tx, op authorityOp) error {
	t.Helper()
	bytes, hash := authorityCanonicalBytes(t, fixture.document(op))

	switch op.operation {
	case operationGrantRevoke:
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_source_confirmation_actor_grant_revocation (
				organization_id, revocation_id, confirmation_actor_grant_revocation_hash,
				grant_id, grant_revision, grant_hash, revoked_by, revoked_at, reason_code,
				policy_revision_number, policy_revision, command_id, canonical_bytes
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		`, fixture.organizationID, op.resultID, hash, op.parentID, op.parentRevision, op.parentHash,
			op.actor, op.at, op.reasonCode(), fixture.policyNumber, fixture.policyID, op.commandID, bytes)
		return err
	case operationConfirm:
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_grant_confirmation (
				organization_id, confirmation_id, confirmation_hash, workspace_id,
				workspace_revision, workspace_configuration_hash, workspace_source_id,
				source_scope_id, source_scope_revision, scope_config_hash, access_mode,
				confirmation_actor_grant_id, confirmation_actor_grant_revision,
				confirmation_actor_grant_hash, warning_version, warning_contract_hash,
				acknowledgement_code, confirmed_by, confirmed_at,
				policy_revision_number, policy_revision, command_id, canonical_bytes
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
		`, fixture.organizationID, op.resultID, hash, fixture.workspaceID,
			fixture.workspaceRevision, fixture.workspaceConfHash, fixture.workspaceSourceID,
			fixture.sourceScopeID, fixture.sourceScopeRevision, fixture.scopeConfigHash, authorityAccessMode,
			op.parentID, op.parentRevision, op.parentHash, confirmationWarningVer, confirmationWarnHash,
			confirmationAckCode, op.actor, op.at, fixture.policyNumber, fixture.policyID, op.commandID, bytes)
		return err
	default:
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_grant_revocation (
				organization_id, revocation_id, workspace_managed_confirmation_revocation_hash,
				confirmation_id, confirmation_hash, revoked_by, revoked_at, reason_code,
				policy_revision_number, policy_revision, command_id, canonical_bytes
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		`, fixture.organizationID, op.resultID, hash, op.parentID, op.parentHash,
			op.actor, op.at, op.reasonCode(), fixture.policyNumber, fixture.policyID, op.commandID, bytes)
		return err
	}
}

func (fixture authorityOpsFixture) auditAction(op authorityOp) audit.Action {
	switch op.operation {
	case operationGrantRevoke:
		return audit.ActionWorkspaceSourceConfirmationGrantRevoked
	case operationConfirm:
		return audit.ActionWorkspaceSourceConfirmed
	default:
		return audit.ActionWorkspaceSourceConfirmationRevoked
	}
}

// successMetadata is the trusted projection of the row this command persisted.
func (fixture authorityOpsFixture) successMetadata(t *testing.T, op authorityOp) audit.Metadata {
	t.Helper()
	_, hash := authorityCanonicalBytes(t, fixture.document(op))
	operation := op.operation
	policy := fixture.policyID
	reason := op.reasonCode()

	switch op.operation {
	case operationConfirm:
		revision := op.parentRevision
		scopeRevision := fixture.sourceScopeRevision
		workspaceRevision := fixture.workspaceRevision
		return audit.Metadata{
			AuthorityOperation:             &operation,
			AuthorityResultID:              &op.resultID,
			AuthorityResultHash:            &hash,
			WorkspaceRevision:              &workspaceRevision,
			WorkspaceConfigurationHash:     &fixture.workspaceConfHash,
			WorkspaceSourceID:              &fixture.workspaceSourceID,
			SourceScopeID:                  &fixture.sourceScopeID,
			SourceScopeRevision:            &scopeRevision,
			ScopeConfigHash:                &fixture.scopeConfigHash,
			AccessMode:                     ptrString(authorityAccessMode),
			ConfirmationActorGrantID:       &op.parentID,
			ConfirmationActorGrantRevision: &revision,
			ConfirmationActorGrantHash:     &op.parentHash,
			WarningVersion:                 ptrString(confirmationWarningVer),
			WarningContractHash:            ptrString(confirmationWarnHash),
			AcknowledgementCode:            ptrString(confirmationAckCode),
			PolicyRevision:                 &policy,
		}
	default:
		return audit.Metadata{
			AuthorityOperation:      &operation,
			AuthorityParentID:       &op.parentID,
			AuthorityParentHash:     &op.parentHash,
			AuthorityRevocationID:   &op.resultID,
			AuthorityRevocationHash: &hash,
			AuthorityReasonCode:     &reason,
			PolicyRevision:          &policy,
		}
	}
}

func ptrString(value string) *string { return &value }

func (fixture authorityOpsFixture) appendAudit(t *testing.T, ctx context.Context, tx pgx.Tx, op authorityOp) error {
	t.Helper()

	var headSequence int64
	var headHash string
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT last_sequence FROM public.audit_chain_head WHERE organization_id = $1), 0),
		       COALESCE((SELECT last_event_hash FROM public.audit_chain_head WHERE organization_id = $1),
		                'sha256:' || repeat('0',64))
	`, fixture.organizationID).Scan(&headSequence, &headHash); err != nil {
		return err
	}

	workspace := fixture.workspaceID
	auditWorkspace := &workspace
	outcome := audit.Outcome(audit.OutcomeSuccess)
	var errorCode *string
	metadata := fixture.successMetadata(t, op)

	if op.status != "SUCCESS" {
		operation := op.operation
		metadata = audit.Metadata{AuthorityOperation: &operation}
		switch op.status {
		case "DENIED":
			outcome = audit.OutcomeDenied
			errorCode = ptrString(audit.ErrorAuthorityDenied)
		case "NOT_FOUND":
			outcome = audit.OutcomeDenied
			errorCode = ptrString(audit.ErrorAuthorityNotFound)
			// A NOT_FOUND event may never name a workspace: that would tell the
			// caller the workspace exists.
			auditWorkspace = nil
		case "PRECONDITION_FAILED":
			outcome = audit.OutcomeFailed
			errorCode = ptrString(audit.ErrorAuthorityPreconditionFailed)
		}
	}
	if op.forgeAuditMetadata != nil {
		metadata = op.forgeAuditMetadata(metadata)
	}

	actor := op.actor
	event, err := audit.Build(fixture.organizationID, audit.EventInput{
		EventID: op.auditEventID, WorkspaceID: auditWorkspace,
		ActorType: audit.ActorHuman, ActorPrincipalID: &actor,
		Action:       fixture.auditAction(op),
		ResourceType: audit.ResourceWorkspaceAuthorityCommand,
		ResourceID:   op.commandID, RequestID: "req_test",
		Outcome: outcome, ErrorCode: errorCode, Metadata: metadata,
		OccurredAt: time.Now().UTC(),
	}, headSequence, headHash)
	if err != nil {
		return err
	}
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO public.audit_event (
		id,schema_version,organization_id,sequence,workspace_id,actor_type,actor_principal_id,
		action,resource_type,resource_id,request_id,outcome,error_code,referenced_evidence_ids_json,
		metadata_json,canonical_bytes,previous_event_hash,event_hash,occurred_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'[]'::jsonb,$14,$15,$16,$17,$18)`,
		event.EventID, event.SchemaVersion, fixture.organizationID, event.Sequence, event.WorkspaceID,
		string(event.ActorType), actor, string(event.Action), string(event.ResourceType), event.ResourceID,
		event.RequestID, string(event.Outcome), event.ErrorCode, metadataJSON, event.CanonicalBytes,
		event.PreviousEventHash, event.EventHash, event.OccurredAt)
	return err
}

func (fixture authorityOpsFixture) terminalize(t *testing.T, ctx context.Context, tx pgx.Tx, op authorityOp) error {
	t.Helper()
	var resultID, resultHash any
	if op.status == "SUCCESS" {
		_, hash := authorityCanonicalBytes(t, fixture.document(op))
		resultID, resultHash = op.resultID, hash
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.workspace_managed_authority_command_receipt
		SET status = $4, result_authority_id = $5, result_authority_hash = $6,
		    audit_event_id = $7, terminal_at = transaction_timestamp()
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		  AND status = 'PENDING'
	`, fixture.organizationID, op.actor, op.keyHash, op.status, resultID, resultHash, op.auditEventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errNoReceiptTerminalized
	}
	return nil
}

// run executes the whole command transaction as the runtime role.
func (fixture authorityOpsFixture) run(
	t *testing.T, ctx context.Context, app *pgxpool.Pool, op authorityOp,
) error {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, op.actor)
	op.at, _ = authorityTransactionSecond(t, ctx, tx)
	if err := fixture.reserve(t, ctx, tx, op); err != nil {
		return err
	}
	if op.status == "SUCCESS" {
		if err := fixture.insertResult(t, ctx, tx, op); err != nil {
			return err
		}
	}
	if err := fixture.appendAudit(t, ctx, tx, op); err != nil {
		return err
	}
	if err := fixture.terminalize(t, ctx, tx, op); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// issueOpsGrant runs a real grant-issue command so the other three operations
// have a genuine, receipt-bound parent grant to act on rather than a row
// smuggled past the boundary by an admin insert.
func issueOpsGrant(
	t *testing.T, ctx context.Context, app *pgxpool.Pool, admin *pgxpool.Pool,
	fixture authorityOpsFixture, sequence int,
) (string, int64, string) {
	t.Helper()
	command := authorityCommandFixture{
		organizationID:    fixture.organizationID,
		ownerID:           fixture.ownerID,
		workspaceID:       fixture.workspaceID,
		policyID:          fixture.policyID,
		policyNumber:      fixture.policyNumber,
		workspaceRevision: fixture.workspaceRevision,
		workspaceConfHash: fixture.workspaceConfHash,
	}
	issue := command.baseGrantIssue(sequence)
	if err := command.runGrantIssueCommand(t, ctx, app, issue); err != nil {
		t.Fatalf("issue the parent grant: %v", err)
	}

	var grantHash string
	var grantRevision int64
	if err := admin.QueryRow(ctx, `
		SELECT grant_hash, revision FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id = $1 AND grant_id = $2
	`, fixture.organizationID, issue.grantID).Scan(&grantHash, &grantRevision); err != nil {
		t.Fatalf("read the issued grant: %v", err)
	}
	return issue.grantID, grantRevision, grantHash
}

func (fixture authorityOpsFixture) baseOp(operation string, sequence int) authorityOp {
	return authorityOp{
		operation: operation,
		commandID: authorityID("command", sequence),
		// The idempotency namespace is (tenant, actor, key hash) and these
		// commands share both tenant and actor with the grant-issue fixture, so
		// the two suites must seed from disjoint byte ranges. '0'+sequence stays
		// clear of the lowercase seeds used there.
		keyHash:      authoritySha256(byte('0' + sequence)),
		actor:        fixture.ownerID,
		status:       "SUCCESS",
		resultID:     authorityID("result", sequence),
		auditEventID: authorityID("audit", sequence),
	}
}

func countAuthorityRows(t *testing.T, ctx context.Context, admin *pgxpool.Pool, relation string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.`+relation).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", relation, err)
	}
	return count
}

// TestAuthorityAllFourOperationsCommitEndToEnd walks the whole lifecycle as the
// runtime role: issue a grant, confirm with it, revoke the confirmation, revoke
// the grant. Each step is a separate command with its own receipt and audit
// event, and each proves that every gate on its path — receipt freshness,
// canonical hash, relational projection, server-owned timestamp, deferred
// result and audit binding — accepts the honest command.
func TestAuthorityAllFourOperationsCommitEndToEnd(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	confirm := fixture.baseOp(operationConfirm, 2)
	confirm.parentID, confirm.parentRevision, confirm.parentHash = grantID, grantRevision, grantHash
	if err := fixture.run(t, ctx, app, confirm); err != nil {
		t.Fatalf("managed confirm command must commit as the runtime role: %v", err)
	}

	var confirmationHash string
	if err := admin.QueryRow(ctx, `
		SELECT confirmation_hash FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1 AND confirmation_id = $2
	`, fixture.organizationID, confirm.resultID).Scan(&confirmationHash); err != nil {
		t.Fatalf("read the committed confirmation: %v", err)
	}

	confirmRevoke := fixture.baseOp(operationConfirmRevoke, 3)
	confirmRevoke.parentID, confirmRevoke.parentHash = confirm.resultID, confirmationHash
	if err := fixture.run(t, ctx, app, confirmRevoke); err != nil {
		t.Fatalf("managed confirm revoke command must commit as the runtime role: %v", err)
	}

	grantRevoke := fixture.baseOp(operationGrantRevoke, 4)
	grantRevoke.parentID, grantRevoke.parentRevision, grantRevoke.parentHash = grantID, grantRevision, grantHash
	if err := fixture.run(t, ctx, app, grantRevoke); err != nil {
		t.Fatalf("grant revoke command must commit as the runtime role: %v", err)
	}

	for relation, want := range map[string]int64{
		"workspace_source_confirmation_actor_grant":            1,
		"workspace_managed_grant_confirmation":                 1,
		"workspace_managed_grant_revocation":                   1,
		"workspace_source_confirmation_actor_grant_revocation": 1,
	} {
		if got := countAuthorityRows(t, ctx, admin, relation); got != want {
			t.Fatalf("%s holds %d rows, want %d", relation, got, want)
		}
	}

	// Every one of the four receipts is terminal, SUCCESS, names its own audit
	// event, and that audit event carries the command's own resource ID.
	var bound int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.workspace_managed_authority_command_receipt AS receipt
		JOIN public.audit_event AS event
		  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
		WHERE receipt.organization_id = $1 AND receipt.status = 'SUCCESS'
		  AND receipt.terminal_at IS NOT NULL
		  AND event.resource_id = receipt.command_id
		  AND event.resource_type = 'WORKSPACE_AUTHORITY_COMMAND'
		  AND event.outcome = 'SUCCESS' AND event.error_code IS NULL
		  AND event.metadata_json ->> 'authority_operation' = receipt.operation
	`, fixture.organizationID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != 4 {
		t.Fatalf("%d of the four commands are exactly receipt-to-audit bound", bound)
	}
}

// TestAuthorityFailureOutcomesCommitWithoutAuthorityRows proves each terminal
// failure of each operation: the receipt terminalizes, exactly one audit event
// records it with the mapped outcome and error code, and no authority row is
// created. This is the half of the contract that cannot be proved by the
// success path — a boundary that only ever succeeds hides nothing.
func TestAuthorityFailureOutcomesCommitWithoutAuthorityRows(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	before := map[string]int64{
		"workspace_source_confirmation_actor_grant":            countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"),
		"workspace_managed_grant_confirmation":                 countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"),
		"workspace_managed_grant_revocation":                   countAuthorityRows(t, ctx, admin, "workspace_managed_grant_revocation"),
		"workspace_source_confirmation_actor_grant_revocation": countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant_revocation"),
	}

	statuses := map[string]struct {
		outcome   string
		errorCode string
	}{
		"DENIED":              {"DENIED", "WORKSPACE_AUTHORITY_DENIED"},
		"NOT_FOUND":           {"DENIED", "WORKSPACE_AUTHORITY_NOT_FOUND"},
		"PRECONDITION_FAILED": {"FAILED", "WORKSPACE_AUTHORITY_PRECONDITION_FAILED"},
	}

	sequence := 10
	for _, operation := range []string{operationGrantRevoke, operationConfirm, operationConfirmRevoke} {
		for status, want := range statuses {
			sequence++
			t.Run(operation+" "+status, func(t *testing.T) {
				op := fixture.baseOp(operation, sequence)
				op.status = status
				op.parentID, op.parentRevision, op.parentHash = grantID, grantRevision, grantHash
				if err := fixture.run(t, ctx, app, op); err != nil {
					t.Fatalf("%s must terminalize %s: %v", operation, status, err)
				}

				var outcome, errorCode string
				var resultID, resultHash *string
				if err := admin.QueryRow(ctx, `
					SELECT event.outcome, event.error_code, receipt.result_authority_id,
					       receipt.result_authority_hash
					FROM public.workspace_managed_authority_command_receipt AS receipt
					JOIN public.audit_event AS event
					  ON event.organization_id = receipt.organization_id
					 AND event.id = receipt.audit_event_id
					WHERE receipt.organization_id = $1 AND receipt.command_id = $2
				`, fixture.organizationID, op.commandID).Scan(&outcome, &errorCode, &resultID, &resultHash); err != nil {
					t.Fatalf("read the terminal receipt and its audit event: %v", err)
				}
				if outcome != want.outcome || errorCode != want.errorCode {
					t.Fatalf("%s terminalized as %s/%s, want %s/%s",
						status, outcome, errorCode, want.outcome, want.errorCode)
				}
				// A failure binds no authority row in either direction.
				if resultID != nil || resultHash != nil {
					t.Fatalf("a %s receipt names a result authority row", status)
				}
			})
		}
	}

	for relation, want := range before {
		if got := countAuthorityRows(t, ctx, admin, relation); got != want {
			t.Fatalf("%s changed from %d to %d rows across nine failed commands", relation, want, got)
		}
	}
}

// TestAuthoritySuccessAuditMustNameThePersistedRowForEveryOperation is the P0
// proof carried across the remaining operations: metadata that is structurally
// perfect but names a different row, hash, parent or policy than the one
// actually persisted must roll the whole command back. Shape and key-set checks
// alone would accept every forgery below.
func TestAuthoritySuccessAuditMustNameThePersistedRowForEveryOperation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	// Each group's prerequisites are set up immediately before it, because they
	// are mutually exclusive: a confirm forgery needs the tuple to have no live
	// confirmation (000010's derived-live guard would otherwise reject it before
	// it reached the binding under test), while a confirm-revoke forgery needs a
	// live confirmation to name as its parent. Forged commands roll back
	// entirely, so they never disturb the next group's state.
	var confirmationHash string
	seedConfirmationParent := func(t *testing.T) string {
		t.Helper()
		confirm := fixture.baseOp(operationConfirm, 2)
		confirm.parentID, confirm.parentRevision, confirm.parentHash = grantID, grantRevision, grantHash
		if err := fixture.run(t, ctx, app, confirm); err != nil {
			t.Fatalf("seed a real confirmation: %v", err)
		}
		if err := admin.QueryRow(ctx, `
			SELECT confirmation_hash FROM public.workspace_managed_grant_confirmation
			WHERE organization_id = $1 AND confirmation_id = $2
		`, fixture.organizationID, confirm.resultID).Scan(&confirmationHash); err != nil {
			t.Fatal(err)
		}
		return confirm.resultID
	}
	var confirmationID string

	// Each forgery substitutes exactly one value IN PLACE, leaving the key set
	// exactly what the operation's SUCCESS contract requires. That is the whole
	// point: a forgery that adds or drops a key is caught by the key-set check
	// long before the value binding is consulted, and would prove nothing about
	// it. So the field substituted differs per operation — a revocation carries
	// authority_revocation_*, a confirmation carries authority_result_* and its
	// grant tuple, and neither carries the other's keys.
	forgeries := map[string]func(operation string, m audit.Metadata) audit.Metadata{
		"a substituted result ID": func(operation string, m audit.Metadata) audit.Metadata {
			forged := ptrString(authorityID("result", 99))
			if operation == operationConfirm {
				m.AuthorityResultID = forged
			} else {
				m.AuthorityRevocationID = forged
			}
			return m
		},
		"a substituted result hash": func(operation string, m audit.Metadata) audit.Metadata {
			forged := ptrString(authoritySha256('z'))
			if operation == operationConfirm {
				m.AuthorityResultHash = forged
			} else {
				m.AuthorityRevocationHash = forged
			}
			return m
		},
		"a substituted parent hash": func(operation string, m audit.Metadata) audit.Metadata {
			forged := ptrString(authoritySha256('y'))
			if operation == operationConfirm {
				m.ConfirmationActorGrantHash = forged
			} else {
				m.AuthorityParentHash = forged
			}
			return m
		},
		"a substituted policy revision": func(operation string, m audit.Metadata) audit.Metadata {
			m.PolicyRevision = ptrString("policy-" + authorityOpsOrganization + "-0009")
			return m
		},
	}
	// The confirmation projects seventeen fields, and every one of them is part
	// of the binding. These forgeries reach the ones no revocation has.
	confirmOnlyForgeries := map[string]func(audit.Metadata) audit.Metadata{
		"a substituted workspace configuration hash": func(m audit.Metadata) audit.Metadata {
			m.WorkspaceConfigurationHash = ptrString(authoritySha256('x'))
			return m
		},
		"a substituted workspace source": func(m audit.Metadata) audit.Metadata {
			m.WorkspaceSourceID = ptrString("binding_01ARZ3NDEKTSV4RRFFQ69G5FBW")
			return m
		},
		"a substituted actor grant ID": func(m audit.Metadata) audit.Metadata {
			m.ConfirmationActorGrantID = ptrString(authorityID("grant", 98))
			return m
		},
		"a substituted scope config hash": func(m audit.Metadata) audit.Metadata {
			m.ScopeConfigHash = ptrString(authoritySha256('v'))
			return m
		},
	}

	sequence := 30
	// Confirm before confirm-revoke: the parent the latter needs is the very
	// thing that would block the former.
	for _, operation := range []string{operationGrantRevoke, operationConfirm, operationConfirmRevoke} {
		if operation == operationConfirmRevoke {
			confirmationID = seedConfirmationParent(t)
		}
		applicable := map[string]func(string, audit.Metadata) audit.Metadata{}
		for name, forge := range forgeries {
			applicable[name] = forge
		}
		if operation == operationConfirm {
			for name, forge := range confirmOnlyForgeries {
				applicable[name] = func(_ string, m audit.Metadata) audit.Metadata { return forge(m) }
			}
		}

		for name, forge := range applicable {
			sequence++
			t.Run(operation+" with "+name, func(t *testing.T) {
				op := fixture.baseOp(operation, sequence)
				op.forgeAuditMetadata = func(m audit.Metadata) audit.Metadata { return forge(operation, m) }
				switch operation {
				case operationConfirmRevoke:
					op.parentID, op.parentHash = confirmationID, confirmationHash
				default:
					op.parentID, op.parentRevision, op.parentHash = grantID, grantRevision, grantHash
				}

				before := countAuthorityRows(t, ctx, admin, authorityRelationOf(operation))
				err := fixture.run(t, ctx, app, op)
				if err == nil {
					t.Fatal("a SUCCESS audit event naming a row other than the persisted one was accepted")
				}
				// The rejection must come from the value binding in the
				// database. Accepting any error would let a forgery that is
				// caught earlier — by the Go key-set check, say — masquerade as
				// proof of a control it never reached.
				if !strings.Contains(err.Error(), "audit metadata does not match the created") {
					t.Fatalf("the forgery was rejected by something other than the persisted-row binding: %v", err)
				}
				if after := countAuthorityRows(t, ctx, admin, authorityRelationOf(operation)); after != before {
					t.Fatalf("the forged command left %d rows behind", after-before)
				}
				var receipts int64
				if err := admin.QueryRow(ctx, `
					SELECT count(*) FROM public.workspace_managed_authority_command_receipt
					WHERE organization_id = $1 AND command_id = $2
				`, fixture.organizationID, op.commandID).Scan(&receipts); err != nil {
					t.Fatal(err)
				}
				if receipts != 0 {
					t.Fatal("the forged command left its receipt behind")
				}
			})
		}
	}
}

// TestAuthorityForeignRequestTenantIsOnlyEverNotFound proves the exact width of
// the one exemption that lets a receipt's canonical request name an
// organization other than the trusted tenant. ADR-0053 makes every cross-tenant
// reference NOT_FOUND and never DENIED, so NOT_FOUND — and the PENDING it is
// reserved as — is where that request must be storable, and every other status
// asserts a tenant-bound fact its own hash-bound request may not disclaim.
func TestAuthorityForeignRequestTenantIsOnlyEverNotFound(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	// The command is honest about its own tenant; only the request body names a
	// foreign organization, exactly as a cross-tenant attempt would.
	foreign := fixture
	foreign.organizationID = "org_authority_ops_foreign"

	reserveForeign := func(t *testing.T, tx pgx.Tx, op authorityOp) error {
		t.Helper()
		bytes, hash := authorityCanonicalBytes(t, foreign.request(op))
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_authority_command_receipt (
				organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
				canonical_request_bytes, canonical_request_hash,
				request_organization_id, request_workspace_id, request_expected_policy_revision,
				request_grant_id, request_grant_revision, request_grant_hash
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		`, fixture.organizationID, op.actor, op.keyHash, op.commandID, operationGrantRevoke,
			bytes, hash, foreign.organizationID, foreign.workspaceID, foreign.policyID,
			op.parentID, op.parentRevision, op.parentHash)
		return err
	}

	sequence := 70
	for _, status := range []string{"NOT_FOUND", "DENIED", "PRECONDITION_FAILED"} {
		sequence++
		t.Run(status, func(t *testing.T) {
			op := fixture.baseOp(operationGrantRevoke, sequence)
			op.status = status
			op.parentID, op.parentRevision, op.parentHash = grantID, grantRevision, grantHash

			tx, err := app.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, op.actor)

			// Reserving PENDING with a foreign request is always allowed: the
			// tenant of the reference is not known until it is evaluated.
			if err := reserveForeign(t, tx, op); err != nil {
				t.Fatalf("a PENDING reservation must accept a foreign request organization: %v", err)
			}

			if err := fixture.appendAudit(t, ctx, tx, op); err != nil {
				t.Fatal(err)
			}
			err = fixture.terminalize(t, ctx, tx, op)
			if err == nil {
				err = tx.Commit(ctx)
			}
			if status == "NOT_FOUND" {
				if err != nil {
					t.Fatalf("a cross-tenant reference must be able to terminate NOT_FOUND: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a %s receipt kept a request naming a foreign organization", status)
			}
			if !strings.Contains(err.Error(), "workspace_managed_authority_command_receipt_request_tenant") {
				t.Fatalf("the %s receipt was refused for the wrong reason: %v", status, err)
			}
		})
	}
}

func authorityRelationOf(operation string) string {
	switch operation {
	case operationGrantRevoke:
		return "workspace_source_confirmation_actor_grant_revocation"
	case operationConfirm:
		return "workspace_managed_grant_confirmation"
	default:
		return "workspace_managed_grant_revocation"
	}
}
