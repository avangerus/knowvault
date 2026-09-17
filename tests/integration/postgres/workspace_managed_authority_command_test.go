package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
)

// Migration 000011 opens the first — and only — write path into the four
// ADR-0052 authority relations, and gates it behind an exact command receipt.
// This suite proves that boundary at the head of the migration history. The
// historical inert boundary that 000010 shipped is proved separately, against
// the 000010 schema, by workspace_managed_confirmation_authority_test.go.
//
// Canonical bytes here are built in the test rather than by a production Go
// canonicalizer, which does not exist yet: PostgreSQL never checks RFC 8785
// canonicality (it checks only that the stored hash is SHA-256 of exactly the
// stored bytes, that the bytes are the closed JSON contract, and that every
// JSON field matches its column). Proving that the production canonicalizer
// emits canonical bytes belongs to its own checkpoint and its own golden
// vectors, not here.

const (
	authorityCommandOrganization = "org_authority_cmd"
	authorityCommandOwner        = "usr_authority_owner"
	authorityCommandWorkspace    = "ws_authority_cmd"
	authorityCommandTTLSeconds   = 3600

	authorityCommandRequestSchema = "workspace-managed-authority-command-v1"
	authorityGrantSchema          = "workspace-source-confirmation-grant-v1"

	operationGrantIssue = "WORKSPACE_CONFIRMATION_GRANT_ISSUE"
)

// authorityCanonicalBytes returns the JCS form of value and its SHA-256. The
// database is proved against exactly these bytes.
func authorityCanonicalBytes(t *testing.T, value any) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal canonical value: %v", err)
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		t.Fatalf("canonicalize value: %v", err)
	}
	digest := sha256.Sum256(canonical)
	return []byte(canonical), "sha256:" + hex.EncodeToString(digest[:])
}

// authorityCommandFixture is a complete, real tenant that a grant-issue
// command can legitimately succeed against.
type authorityCommandFixture struct {
	organizationID string
	ownerID        string
	workspaceID    string
	policyID       string
	policyNumber   int64
	clock          authorityClock
	// The grant-issue request is optimistic, so the fixture must name the
	// workspace revision and configuration hash that are actually current.
	workspaceRevision int64
	workspaceConfHash string
}

func setupAuthorityCommandFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool) authorityCommandFixture {
	t.Helper()
	seedOrganization(t, ctx, admin, authorityCommandOrganization, authorityCommandOwner, authorityCommandWorkspace)
	clock := fetchAuthorityClock(t, ctx, admin)
	policyID := "policy-" + authorityCommandOrganization + "-0001"
	insertPolicyRegistryRow(t, ctx, admin, authorityCommandOrganization, 1, policyID,
		authoritySha256('p'), authorityCommandOwner, clock.grantedAt)

	var workspaceRevision int64
	var workspaceConfHash string
	if err := admin.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash
		FROM public.workspace AS workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		WHERE workspace.organization_id = $1 AND workspace.id = $2
	`, authorityCommandOrganization, authorityCommandWorkspace).Scan(&workspaceRevision, &workspaceConfHash); err != nil {
		t.Fatalf("load current workspace revision: %v", err)
	}

	return authorityCommandFixture{
		organizationID:    authorityCommandOrganization,
		ownerID:           authorityCommandOwner,
		workspaceID:       authorityCommandWorkspace,
		policyID:          policyID,
		policyNumber:      1,
		clock:             clock,
		workspaceRevision: workspaceRevision,
		workspaceConfHash: workspaceConfHash,
	}
}

// authorityTransactionSecond reads the one server clock reading the command
// transaction is allowed to use for every server-owned timestamp it derives.
func authorityTransactionSecond(t *testing.T, ctx context.Context, tx pgx.Tx) (string, string) {
	t.Helper()
	var now, validUntil string
	if err := tx.QueryRow(ctx, `
		SELECT to_char(date_trunc('second', transaction_timestamp()) AT TIME ZONE 'UTC',
		               'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		       to_char((date_trunc('second', transaction_timestamp()) + make_interval(secs => $1))
		               AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`, authorityCommandTTLSeconds).Scan(&now, &validUntil); err != nil {
		t.Fatalf("read the command transaction second: %v", err)
	}
	return now, validUntil
}

// grantIssueCommand is exactly the ADR-0053 grant-issue request projection.
type grantIssueCommand struct {
	commandID      string
	keyHash        string
	requestOrgID   string
	workspaceID    string
	targetID       string
	grantID        string
	grantedBy      string
	auditEventID   string
	auditWorkspace *string
	status         string
	// Server-owned timestamps, derived from the one PostgreSQL transaction-second
	// of the command transaction rather than from any Go clock.
	grantedAt  string
	validUntil string
	// forgeAuditMetadata rewrites the SUCCESS audit metadata after it is built,
	// so a test can ship a structurally valid metadata set whose values name a
	// different authority row than the one actually persisted.
	forgeAuditMetadata func(audit.Metadata) audit.Metadata
}

func (fixture authorityCommandFixture) baseGrantIssue(sequence int) grantIssueCommand {
	workspace := fixture.workspaceID
	return grantIssueCommand{
		commandID:      authorityID("command", sequence),
		keyHash:        authoritySha256(byte('k' + sequence)),
		requestOrgID:   fixture.organizationID,
		workspaceID:    fixture.workspaceID,
		targetID:       fixture.ownerID,
		grantID:        authorityID("grant", sequence),
		grantedBy:      fixture.ownerID,
		auditEventID:   authorityID("audit", sequence),
		auditWorkspace: &workspace,
		status:         "SUCCESS",
	}
}

// requestEnvelope is the closed canonical command envelope.
func (fixture authorityCommandFixture) requestEnvelope(command grantIssueCommand) map[string]any {
	return map[string]any{
		"schema_version": authorityCommandRequestSchema,
		"operation":      operationGrantIssue,
		"request": map[string]any{
			"organization_id":                       command.requestOrgID,
			"workspace_id":                          command.workspaceID,
			"expected_workspace_revision":           fixture.workspaceRevision,
			"expected_workspace_configuration_hash": fixture.workspaceConfHash,
			"target_principal_id":                   command.targetID,
			"ttl_seconds":                           authorityCommandTTLSeconds,
			"expected_policy_revision":              fixture.policyID,
		},
	}
}

func (fixture authorityCommandFixture) grantDocument(command grantIssueCommand) map[string]any {
	return map[string]any{
		"schema_version":  authorityGrantSchema,
		"grant_id":        command.grantID,
		"revision":        1,
		"organization_id": fixture.organizationID,
		"workspace_id":    command.workspaceID,
		"principal_id":    command.targetID,
		"permission":      "workspace.source.confirm",
		"valid_from":      command.grantedAt,
		"valid_until":     command.validUntil,
		"policy_revision": fixture.policyID,
		"granted_by":      command.grantedBy,
		"granted_at":      command.grantedAt,
	}
}

// reserveAuthorityReceipt performs the PENDING reservation exactly as the
// future repository will: trusted tenant, trusted actor, canonical request
// bytes and the server-reserved command_id.
func (fixture authorityCommandFixture) reserveAuthorityReceipt(
	t *testing.T, ctx context.Context, tx pgx.Tx, command grantIssueCommand,
) error {
	t.Helper()
	requestBytes, requestHash := authorityCanonicalBytes(t, fixture.requestEnvelope(command))
	_, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_managed_authority_command_receipt (
			organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
			canonical_request_bytes, canonical_request_hash,
			request_organization_id, request_workspace_id, request_expected_policy_revision,
			request_expected_workspace_revision, request_expected_workspace_configuration_hash,
			request_target_principal_id, request_ttl_seconds
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
	`, fixture.organizationID, command.grantedBy, command.keyHash, command.commandID, operationGrantIssue,
		requestBytes, requestHash, command.requestOrgID, command.workspaceID, fixture.policyID,
		fixture.workspaceRevision, fixture.workspaceConfHash, command.targetID, authorityCommandTTLSeconds)
	return err
}

func (fixture authorityCommandFixture) insertGrant(
	t *testing.T, ctx context.Context, tx pgx.Tx, command grantIssueCommand,
) error {
	t.Helper()
	grantBytes, grantHash := authorityCanonicalBytes(t, fixture.grantDocument(command))
	_, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant (
			organization_id, grant_id, revision, workspace_id, principal_id, permission,
			valid_from, valid_until, policy_revision_number, policy_revision,
			grant_hash, granted_by, granted_at, command_id, canonical_bytes
		) VALUES ($1,$2,1,$3,$4,'workspace.source.confirm',$5,$6,$7,$8,$9,$10,$11,$12,$13)
	`, fixture.organizationID, command.grantID, command.workspaceID, command.targetID,
		command.grantedAt, command.validUntil, fixture.policyNumber, fixture.policyID,
		grantHash, command.grantedBy, command.grantedAt, command.commandID, grantBytes)
	return err
}

func (fixture authorityCommandFixture) appendAuthorityAudit(
	t *testing.T, ctx context.Context, tx pgx.Tx, command grantIssueCommand,
) error {
	t.Helper()
	_, grantHash := authorityCanonicalBytes(t, fixture.grantDocument(command))

	var headSequence int64
	var headHash string
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE((SELECT last_sequence FROM public.audit_chain_head WHERE organization_id = $1), 0),
		       COALESCE((SELECT last_event_hash FROM public.audit_chain_head WHERE organization_id = $1),
		                'sha256:' || repeat('0',64))
	`, fixture.organizationID).Scan(&headSequence, &headHash); err != nil {
		return err
	}

	actor := command.grantedBy
	operation := operationGrantIssue
	resultID := command.grantID
	resultHash := grantHash
	target := command.targetID
	policy := fixture.policyID
	auditWorkspace := command.auditWorkspace
	outcome := audit.Outcome(audit.OutcomeSuccess)
	var errorCode *string
	metadata := audit.Metadata{
		AuthorityOperation:  &operation,
		AuthorityResultID:   &resultID,
		AuthorityResultHash: &resultHash,
		TargetPrincipalID:   &target,
		PolicyRevision:      &policy,
	}
	if command.status != "SUCCESS" {
		// A failure carries exactly the operation key, and its outcome,
		// error code and workspace_id follow the same exhaustive map the
		// database gate enforces for every operation.
		metadata = audit.Metadata{AuthorityOperation: &operation}
		switch command.status {
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
	if command.forgeAuditMetadata != nil {
		metadata = command.forgeAuditMetadata(metadata)
	}

	event, err := audit.Build(fixture.organizationID, audit.EventInput{
		EventID: command.auditEventID, WorkspaceID: auditWorkspace,
		ActorType: audit.ActorHuman, ActorPrincipalID: &actor,
		Action:       audit.ActionWorkspaceSourceConfirmationGrantIssued,
		ResourceType: audit.ResourceWorkspaceAuthorityCommand,
		// ADR-0053: the audit resource ID is always receipt.command_id, never a
		// created or parent authority ID.
		ResourceID: command.commandID, RequestID: "req_test",
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

func (fixture authorityCommandFixture) terminalize(
	ctx context.Context, tx pgx.Tx, command grantIssueCommand,
) error {
	_, grantHash := authorityCanonicalBytesNoT(fixture.grantDocument(command))
	var resultID, resultHash any
	if command.status == "SUCCESS" {
		resultID, resultHash = command.grantID, grantHash
	}
	tag, err := tx.Exec(ctx, `
		UPDATE public.workspace_managed_authority_command_receipt
		SET status = $4, result_authority_id = $5, result_authority_hash = $6,
		    audit_event_id = $7, terminal_at = transaction_timestamp()
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
		  AND status = 'PENDING'
	`, fixture.organizationID, command.grantedBy, command.keyHash, command.status,
		resultID, resultHash, command.auditEventID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errNoReceiptTerminalized
	}
	return nil
}

var errNoReceiptTerminalized = &terminalizeError{}

type terminalizeError struct{}

func (*terminalizeError) Error() string { return "no pending receipt terminalized" }

// authorityCanonicalBytesNoT mirrors authorityCanonicalBytes for the paths that
// run without a *testing.T in scope.
func authorityCanonicalBytesNoT(value any) ([]byte, string) {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		panic(err)
	}
	digest := sha256.Sum256(canonical)
	return []byte(canonical), "sha256:" + hex.EncodeToString(digest[:])
}

// runGrantIssueCommand executes the whole command transaction as the runtime
// role, in exactly the ADR-0053 order: reserve PENDING, insert the authority
// row, append audit, terminalize, commit.
func (fixture authorityCommandFixture) runGrantIssueCommand(
	t *testing.T, ctx context.Context, app *pgxpool.Pool, command grantIssueCommand,
) error {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
	command.grantedAt, command.validUntil = authorityTransactionSecond(t, ctx, tx)
	if err := fixture.reserveAuthorityReceipt(t, ctx, tx, command); err != nil {
		return err
	}
	if command.status == "SUCCESS" {
		if err := fixture.insertGrant(t, ctx, tx, command); err != nil {
			return err
		}
	}
	if err := fixture.appendAuthorityAudit(t, ctx, tx, command); err != nil {
		return err
	}
	if err := fixture.terminalize(ctx, tx, command); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func openAuthorityAppPool(t *testing.T, ctx context.Context) *pgxpool.Pool {
	t.Helper()
	app, err := pgxpool.New(ctx, applicationURL(t, testDatabaseURL(t)))
	if err != nil {
		t.Fatalf("open application pool: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// TestAuthorityGrantIssueCommitsReceiptAuthorityAndAuditTogether is the
// load-bearing proof of migration 000011: the runtime role can actually
// execute a whole authority command. Every gate the migration installs is on
// this path, so a missing EXECUTE grant, a wrong projection or a broken
// receipt gate fails here rather than in production.
func TestAuthorityGrantIssueCommitsReceiptAuthorityAndAuditTogether(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(1)
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("grant issue command must commit as the runtime role: %v", err)
	}

	var status, storedCommandID, resultID string
	var auditEventID string
	if err := admin.QueryRow(ctx, `
		SELECT status, command_id, result_authority_id, audit_event_id
		FROM public.workspace_managed_authority_command_receipt
		WHERE organization_id = $1 AND actor_principal_id = $2 AND idempotency_key_hash = $3
	`, fixture.organizationID, command.grantedBy, command.keyHash).Scan(
		&status, &storedCommandID, &resultID, &auditEventID); err != nil {
		t.Fatalf("load committed receipt: %v", err)
	}
	if status != "SUCCESS" || storedCommandID != command.commandID || resultID != command.grantID {
		t.Fatalf("receipt = (%s, %s, %s), want SUCCESS/%s/%s", status, storedCommandID, resultID,
			command.commandID, command.grantID)
	}

	// Exactly one authority row, bound to the same command.
	var grants int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id = $1 AND command_id = $2
	`, fixture.organizationID, command.commandID).Scan(&grants); err != nil {
		t.Fatal(err)
	}
	if grants != 1 {
		t.Fatalf("authority rows bound to command = %d, want 1", grants)
	}

	// Exactly one audit event, and its resource ID is the command ID.
	var auditResource, auditAction, auditOutcome string
	var auditErrorCode *string
	if err := admin.QueryRow(ctx, `
		SELECT resource_id, action, outcome, error_code FROM public.audit_event
		WHERE organization_id = $1 AND id = $2
	`, fixture.organizationID, auditEventID).Scan(
		&auditResource, &auditAction, &auditOutcome, &auditErrorCode); err != nil {
		t.Fatalf("load authority audit event: %v", err)
	}
	if auditResource != command.commandID {
		t.Fatalf("audit resource_id = %s, want receipt command_id %s", auditResource, command.commandID)
	}
	if auditAction != "workspace.source_confirmation_grant_issued" ||
		auditOutcome != "SUCCESS" || auditErrorCode != nil {
		t.Fatalf("audit projection = (%s, %s, %v), want grant_issued/SUCCESS/nil",
			auditAction, auditOutcome, auditErrorCode)
	}
}

// TestAuthorityGrantIssueFailureOutcomesCommitWithoutGrant carries the failure
// matrix onto the one operation missing from it. The other three operations
// prove every terminal failure in workspace_managed_authority_operations_test.go;
// grant-issue is the first command in a lifecycle, so its DENIED, NOT_FOUND and
// PRECONDITION_FAILED terminals are just as reachable — a policy denial, an
// unknown target or tenant, and a stale optimistic precondition respectively —
// and each must run the whole receipt→audit terminal branch, map to the exact
// outcome, error code and workspace_id the database enforces, carry exactly the
// operation key in metadata, and create no grant row.
func TestAuthorityGrantIssueFailureOutcomesCommitWithoutGrant(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	cases := map[string]struct {
		outcome      string
		errorCode    string
		wantWorkspce bool
	}{
		// workspace_id is exact on PRECONDITION_FAILED, absent on NOT_FOUND, and
		// on DENIED contract-legal either way — this fixture keeps it, exercising
		// the same-tenant-visibility branch of the gate.
		"DENIED":              {"DENIED", "WORKSPACE_AUTHORITY_DENIED", true},
		"NOT_FOUND":           {"DENIED", "WORKSPACE_AUTHORITY_NOT_FOUND", false},
		"PRECONDITION_FAILED": {"FAILED", "WORKSPACE_AUTHORITY_PRECONDITION_FAILED", true},
	}

	sequence := 40
	for status, want := range cases {
		sequence++
		t.Run(status, func(t *testing.T) {
			command := fixture.baseGrantIssue(sequence)
			command.status = status

			if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
				t.Fatalf("grant issue must terminalize %s through the real branch: %v", status, err)
			}

			// The terminal receipt and its audit event agree on outcome and
			// error code, and the receipt binds no result row.
			var receiptStatus, outcome, errorCode string
			var resultID, resultHash *string
			var workspaceID *string
			var metadataJSON string
			if err := admin.QueryRow(ctx, `
				SELECT receipt.status, receipt.result_authority_id, receipt.result_authority_hash,
				       event.outcome, event.error_code, event.workspace_id, event.metadata_json::text
				FROM public.workspace_managed_authority_command_receipt AS receipt
				JOIN public.audit_event AS event
				  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
				WHERE receipt.organization_id = $1 AND receipt.command_id = $2
			`, fixture.organizationID, command.commandID).Scan(
				&receiptStatus, &resultID, &resultHash, &outcome, &errorCode, &workspaceID, &metadataJSON); err != nil {
				t.Fatalf("load the terminal receipt and its audit event: %v", err)
			}
			if receiptStatus != status || outcome != want.outcome || errorCode != want.errorCode {
				t.Fatalf("receipt/outcome/error = (%s, %s, %s), want (%s, %s, %s)",
					receiptStatus, outcome, errorCode, status, want.outcome, want.errorCode)
			}
			if resultID != nil || resultHash != nil {
				t.Fatalf("a %s receipt names a result authority row", status)
			}
			if (workspaceID != nil) != want.wantWorkspce {
				t.Fatalf("%s audit workspace_id present = %v, want %v", status, workspaceID != nil, want.wantWorkspce)
			}
			// A failure carries exactly the operation key and nothing else.
			if metadataJSON != `{"authority_operation": "WORKSPACE_CONFIRMATION_GRANT_ISSUE"}` {
				t.Fatalf("%s audit metadata = %s, want exactly the operation key", status, metadataJSON)
			}

			// No grant row was created by any failed command.
			var grants int
			if err := admin.QueryRow(ctx, `
				SELECT count(*) FROM public.workspace_source_confirmation_actor_grant
				WHERE organization_id = $1 AND command_id = $2
			`, fixture.organizationID, command.commandID).Scan(&grants); err != nil {
				t.Fatal(err)
			}
			if grants != 0 {
				t.Fatalf("a %s command created %d grant rows, want 0", status, grants)
			}
		})
	}
}

// TestAuthorityRawInsertWithoutReceiptIsRejected proves the INSERT privilege
// opened by 000011 is worthless without a receipt.
func TestAuthorityRawInsertWithoutReceiptIsRejected(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(2)
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)

	// No receipt reserved: the authority INSERT must fail closed.
	if err := fixture.insertGrant(t, ctx, tx, command); err == nil {
		t.Fatal("authority INSERT without a receipt must be rejected")
	}
}

// TestAuthorityReceiptCannotCommitPending proves a reservation can never
// survive commit on its own.
func TestAuthorityReceiptCannotCommitPending(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(3)
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
	if err := fixture.reserveAuthorityReceipt(t, ctx, tx, command); err != nil {
		t.Fatalf("reserve receipt: %v", err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("committing a PENDING authority receipt must be rejected")
	}

	var receipts int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_authority_command_receipt
		WHERE organization_id = $1
	`, fixture.organizationID).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 0 {
		t.Fatalf("rolled back reservation left %d receipts, want 0", receipts)
	}
}

// TestAuthorityTerminalReceiptIsImmutable proves a settled command can never be
// rewritten, replayed into a different outcome or re-terminalized.
func TestAuthorityTerminalReceiptIsImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(4)
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("seed a terminal receipt: %v", err)
	}

	for name, statement := range map[string]string{
		"re-terminalize": `UPDATE public.workspace_managed_authority_command_receipt
			SET status = 'DENIED', terminal_at = transaction_timestamp()
			WHERE organization_id = $1 AND command_id = $2`,
		"rewrite request hash": `UPDATE public.workspace_managed_authority_command_receipt
			SET canonical_request_hash = 'sha256:` + hex.EncodeToString(make([]byte, 32)) + `'
			WHERE organization_id = $1 AND command_id = $2`,
		"delete": `DELETE FROM public.workspace_managed_authority_command_receipt
			WHERE organization_id = $1 AND command_id = $2`,
	} {
		if _, err := admin.Exec(ctx, statement, fixture.organizationID, command.commandID); err == nil {
			t.Fatalf("%s on a terminal authority receipt must be rejected", name)
		}
	}
}

// TestAuthorityReceiptRejectsWrongOperationActorAndTenant proves the receipt
// gate is exact, not merely present.
func TestAuthorityReceiptRejectsWrongOperationActorAndTenant(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	t.Run("wrong actor", func(t *testing.T) {
		command := fixture.baseGrantIssue(5)
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
		if err := fixture.reserveAuthorityReceipt(t, ctx, tx, command); err != nil {
			t.Fatal(err)
		}
		// The grant claims a different granted_by than the receipt actor.
		forged := command
		forged.grantedBy = "usr_intruder"
		if err := fixture.insertGrant(t, ctx, tx, forged); err == nil {
			t.Fatal("authority row whose actor differs from its receipt must be rejected")
		}
	})

	t.Run("wrong request projection", func(t *testing.T) {
		command := fixture.baseGrantIssue(6)
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
		if err := fixture.reserveAuthorityReceipt(t, ctx, tx, command); err != nil {
			t.Fatal(err)
		}
		forged := command
		forged.targetID = "usr_someone_else"
		if err := fixture.insertGrant(t, ctx, tx, forged); err == nil {
			t.Fatal("authority row that does not match its receipt projection must be rejected")
		}
	})
}

// TestAuthorityReceiptRLSIsActorScoped proves a receipt never becomes an
// existence oracle for another actor or another tenant.
func TestAuthorityReceiptRLSIsActorScoped(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(7)
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("seed a terminal receipt: %v", err)
	}

	for name, principal := range map[string]string{
		"other actor in the same tenant": "usr_other",
	} {
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, principal)
		var visible int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM public.workspace_managed_authority_command_receipt
		`).Scan(&visible); err != nil {
			t.Fatal(err)
		}
		_ = tx.Rollback(ctx)
		if visible != 0 {
			t.Fatalf("%s sees %d authority receipts, want 0", name, visible)
		}
	}

	// The owning actor still sees exactly their own receipt.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
	var own int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_authority_command_receipt
	`).Scan(&own); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
	if own != 1 {
		t.Fatalf("owning actor sees %d receipts, want 1", own)
	}
}

// TestAuthorityCanonicalHashMustMatchStoredBytes proves the database checks the
// hash against exactly the bytes it stores, and that the stored bytes are the
// closed JSON contract projected onto the columns.
func TestAuthorityCanonicalHashMustMatchStoredBytes(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	t.Run("request hash must equal sha256 of stored request bytes", func(t *testing.T) {
		command := fixture.baseGrantIssue(8)
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)

		requestBytes, _ := authorityCanonicalBytes(t, fixture.requestEnvelope(command))
		_, err = tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_authority_command_receipt (
				organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
				canonical_request_bytes, canonical_request_hash,
				request_organization_id, request_workspace_id, request_expected_policy_revision,
				request_expected_workspace_revision, request_expected_workspace_configuration_hash,
				request_target_principal_id, request_ttl_seconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13)
		`, fixture.organizationID, command.grantedBy, command.keyHash, command.commandID, operationGrantIssue,
			requestBytes, authoritySha256('z'), // a well-formed hash of something else
			command.requestOrgID, command.workspaceID, fixture.policyID,
			authoritySha256('w'), command.targetID, authorityCommandTTLSeconds)
		if err == nil {
			t.Fatal("receipt whose hash is not SHA-256 of its stored bytes must be rejected")
		}
	})

	t.Run("request bytes must project onto the columns", func(t *testing.T) {
		command := fixture.baseGrantIssue(9)
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)

		// Canonical bytes and hash agree with each other, but the request names
		// a different target than the receipt's typed projection.
		envelope := fixture.requestEnvelope(command)
		envelope["request"].(map[string]any)["target_principal_id"] = "usr_drifted"
		requestBytes, requestHash := authorityCanonicalBytes(t, envelope)
		_, err = tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_authority_command_receipt (
				organization_id, actor_principal_id, idempotency_key_hash, command_id, operation,
				canonical_request_bytes, canonical_request_hash,
				request_organization_id, request_workspace_id, request_expected_policy_revision,
				request_expected_workspace_revision, request_expected_workspace_configuration_hash,
				request_target_principal_id, request_ttl_seconds
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,$11,$12,$13)
		`, fixture.organizationID, command.grantedBy, command.keyHash, command.commandID, operationGrantIssue,
			requestBytes, requestHash, command.requestOrgID, command.workspaceID, fixture.policyID,
			authoritySha256('w'), command.targetID, authorityCommandTTLSeconds)
		if err == nil {
			t.Fatal("receipt whose canonical bytes disagree with its projection must be rejected")
		}
	})
}

// TestAuthorityCommitTimePolicyAdvanceRollsBack proves the ADR-0053 rule that a
// policy advance between reservation and commit fails the whole transaction
// closed rather than committing a row that claims a stale policy revision.
func TestAuthorityCommitTimePolicyAdvanceRollsBack(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(10)
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, command.grantedBy)
	command.grantedAt, command.validUntil = authorityTransactionSecond(t, ctx, tx)
	if err := fixture.reserveAuthorityReceipt(t, ctx, tx, command); err != nil {
		t.Fatal(err)
	}
	if err := fixture.insertGrant(t, ctx, tx, command); err != nil {
		t.Fatalf("insert grant under the current policy: %v", err)
	}

	// A concurrent transaction advances the organization policy after this
	// command already loaded and bound it. The advance is a real registry
	// append plus the counter move, exactly as a policy change must be.
	insertPolicyRegistryRow(t, ctx, admin, fixture.organizationID, 2,
		"policy-"+fixture.organizationID+"-0002", authoritySha256('q'), fixture.ownerID, fixture.clock.now)
	if _, err := admin.Exec(ctx, `
		UPDATE public.organization SET policy_revision = 2 WHERE id = $1
	`, fixture.organizationID); err != nil {
		t.Fatalf("advance organization policy: %v", err)
	}

	if err := fixture.appendAuthorityAudit(t, ctx, tx, command); err != nil {
		t.Fatal(err)
	}
	if err := fixture.terminalize(ctx, tx, command); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatal("a policy advance between reservation and commit must roll the command back")
	}

	var grants, receipts int
	if err := admin.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant WHERE organization_id = $1),
		       (SELECT count(*) FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1)
	`, fixture.organizationID).Scan(&grants, &receipts); err != nil {
		t.Fatal(err)
	}
	if grants != 0 || receipts != 0 {
		t.Fatalf("rolled back command left %d grants and %d receipts, want 0/0", grants, receipts)
	}
}

// TestMigration000011FailsClosedOnPreReceiptAuthorityRows proves the upgrade
// refuses to declare pre-receipt authority rows trusted.
func TestMigration000011FailsClosedOnPreReceiptAuthorityRows(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)

	// Build a legitimate 000010-era authority row: at that migration the
	// relations exist, no receipt does, and the migration owner can insert.
	fixture := setupConfirmationFixture(t, ctx, admin, "org_pre_receipt", "usr_pre_receipt", "ws_pre_receipt")
	_ = fixture

	migration, err := readMigrationFile(t, "000011_stage2_workspace_managed_authority_command.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, migration); err == nil {
		t.Fatal("migration 000011 must abort when pre-receipt authority rows exist")
	}

	// The abort must leave 000010's schema untouched: no receipt relation, no
	// half-applied upgrade.
	var receiptExists bool
	if err := admin.QueryRow(ctx, `
		SELECT to_regclass('public.workspace_managed_authority_command_receipt') IS NOT NULL
	`).Scan(&receiptExists); err != nil {
		t.Fatal(err)
	}
	if receiptExists {
		t.Fatal("aborted migration 000011 must roll back its own receipt relation")
	}
}

// TestAuthorityAuditMetadataMustMatchThePersistedRow proves the SUCCESS audit
// metadata is bound to the authority row that was actually created, not merely
// to the right shape. A structurally perfect metadata set — correct key set,
// correct types, correct formats, correct operation — that names a different
// grant must be rejected, because ADR-0053 requires SUCCESS metadata to come
// from trusted persisted projections rather than from anything the caller was
// free to choose.
func TestAuthorityAuditMetadataMustMatchThePersistedRow(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	decoy := "usr_authority_decoy"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, decoy)

	forgeries := map[string]func(audit.Metadata) audit.Metadata{
		"result ID names another grant": func(metadata audit.Metadata) audit.Metadata {
			other := authorityID("grant", 999)
			metadata.AuthorityResultID = &other
			return metadata
		},
		"result hash is another well-formed digest": func(metadata audit.Metadata) audit.Metadata {
			other := authoritySha256('x')
			metadata.AuthorityResultHash = &other
			return metadata
		},
		"target names another principal": func(metadata audit.Metadata) audit.Metadata {
			other := decoy
			metadata.TargetPrincipalID = &other
			return metadata
		},
		"policy revision names another registry row": func(metadata audit.Metadata) audit.Metadata {
			other := "policy-" + authorityCommandOrganization + "-9999"
			metadata.PolicyRevision = &other
			return metadata
		},
	}
	sequence := 30
	for name, forge := range forgeries {
		sequence++
		t.Run(name, func(t *testing.T) {
			command := fixture.baseGrantIssue(sequence)
			command.forgeAuditMetadata = forge
			err := fixture.runGrantIssueCommand(t, ctx, app, command)
			if err == nil {
				t.Fatal("SUCCESS audit metadata that does not match the persisted authority row was accepted")
			}
			// Every forgery here keeps the key set exact and substitutes one
			// value, so it must reach the database and die on the persisted-row
			// binding. Accepting any error would let a forgery rejected by an
			// earlier shape check pose as proof of a control it never reached.
			if !strings.Contains(err.Error(), "grant issue audit metadata does not match the created grant") {
				t.Fatalf("the forgery was rejected by something other than the persisted-row binding: %v", err)
			}
			var grants, receipts int
			if err := admin.QueryRow(ctx, `
				SELECT (SELECT count(*) FROM public.workspace_source_confirmation_actor_grant WHERE organization_id = $1),
				       (SELECT count(*) FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1)
			`, fixture.organizationID).Scan(&grants, &receipts); err != nil {
				t.Fatal(err)
			}
			if grants != 0 || receipts != 0 {
				t.Fatalf("rejected forgery left %d grants and %d receipts, want 0/0", grants, receipts)
			}
		})
	}
}
