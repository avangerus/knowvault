package postgres_test

// End-to-end coverage of the ADR-0087 §2 connection trust verification
// command (migration 000057) against real PostgreSQL 18.4: a real FOLDER
// connection is registered through the production registration surface (not
// raw SQL), then Store.VerifyConnectionTrust drives the whole command
// transaction — the CONNECTOR_ADMIN application policy gate, the SECURITY
// DEFINER door, the monotonic DRAFT->VERIFIED transition, the actor-scoped
// idempotency receipt and the one content-free audit event — with the
// production runtime role, exactly as the workspace-managed authority runtime
// suite proves the four ADR-0053 operations.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const trustVerifyConnectorAdminID = "usr_reg_connector_admin"

func seedConnectorAdmin(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, connectorAdminID, assignedBy string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, connectorAdminID, organizationID); err != nil {
		t.Fatalf("seed connector-admin principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_'||$2, $1, $2, 'CONNECTOR_ADMIN', 1, $3)`, organizationID, connectorAdminID, assignedBy); err != nil {
		t.Fatalf("seed connector-admin role: %v", err)
	}
}

func newTrustVerifyStore(t *testing.T, appStore *database.Store) *workspacerepository.Store {
	t.Helper()
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	store, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("workspace repository: %v", err)
	}
	return store
}

func registerTrustVerifyConnection(t *testing.T, ctx context.Context, service *registration.Service) string {
	t.Helper()
	result, err := service.Register(ctx, regOwnerAccess("req_trust_verify_register"), regRequest())
	if err != nil {
		t.Fatalf("register connection: %v", err)
	}
	if result.ConnectionID == "" {
		t.Fatalf("register connection returned no connection id: %#v", result)
	}
	return result.ConnectionID
}

func trustProjectionStatus(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, connectionID string) string {
	t.Helper()
	var status string
	if err := admin.QueryRow(ctx, `
		SELECT projection.status
		  FROM public.source_connection_trust_record AS record
		  JOIN public.source_connection_trust_projection AS projection
		    ON projection.organization_id = record.organization_id AND projection.trust_record_id = record.id
		 WHERE record.organization_id = $1 AND record.connection_id = $2`,
		organizationID, connectionID).Scan(&status); err != nil {
		t.Fatalf("read trust projection status: %v", err)
	}
	return status
}

func TestSourceConnectionTrustVerifySucceedsForConnectorAdmin(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	seedConnectorAdmin(t, ctx, admin, regOrg, trustVerifyConnectorAdminID, regOwner)
	connectionID := registerTrustVerifyConnection(t, ctx, service)
	store := newTrustVerifyStore(t, appStore)

	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "DRAFT" {
		t.Fatalf("trust projection before verification = %q, want DRAFT", got)
	}

	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: trustVerifyConnectorAdminID, RequestID: "req_trust_verify"}
	result, err := store.VerifyConnectionTrust(ctx, access, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("trust-verify-success"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("verify connection trust: %v", err)
	}
	if result.ResultID == "" || result.ResultHash == "" {
		t.Fatalf("verify connection trust result = %#v", result)
	}
	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "VERIFIED" {
		t.Fatalf("trust projection after verification = %q, want VERIFIED", got)
	}

	var outcome, errorCode, action string
	var boundToResult bool
	if err := admin.QueryRow(ctx, `
		SELECT outcome, coalesce(error_code, ''), action, resource_id = $2
		  FROM public.audit_event
		 WHERE organization_id = $1 AND action = 'source.connection_trust_verified' AND outcome = 'SUCCESS'`,
		regOrg, result.ResultID).Scan(&outcome, &errorCode, &action, &boundToResult); err != nil {
		t.Fatalf("read audit event: %v", err)
	}
	if outcome != "SUCCESS" || errorCode != "" || !boundToResult {
		t.Fatalf("audit event not bound to result: outcome=%s errorCode=%s boundToResult=%v", outcome, errorCode, boundToResult)
	}
}

func TestSourceConnectionTrustVerifyDeniedForNonConnectorAdmin(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	connectionID := registerTrustVerifyConnection(t, ctx, service)
	store := newTrustVerifyStore(t, appStore)

	// regOwner holds organization OWNER, not CONNECTOR_ADMIN: source.verify_trust
	// denies it exactly as internal/policy/decision.go restricts the operation.
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_trust_verify_denied"}
	_, err := store.VerifyConnectionTrust(ctx, access, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("trust-verify-denied"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeConnectionTrustDenied {
		t.Fatalf("verify connection trust error = %v, want CodeConnectionTrustDenied", err)
	}
	// Fail-closed: a denied attempt leaves the DRAFT projection untouched.
	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "DRAFT" {
		t.Fatalf("trust projection after denied verification = %q, want DRAFT", got)
	}
	var outcome, errorCode string
	if err := admin.QueryRow(ctx, `
		SELECT outcome, coalesce(error_code, '')
		  FROM public.audit_event
		 WHERE organization_id = $1 AND action = 'source.connection_trust_verified' AND outcome = 'DENIED'`,
		regOrg).Scan(&outcome, &errorCode); err != nil {
		t.Fatalf("read denied audit event: %v", err)
	}
	if outcome != "DENIED" || errorCode == "" {
		t.Fatalf("denied audit event malformed: outcome=%s errorCode=%s", outcome, errorCode)
	}
}

func TestSourceConnectionTrustVerifyIsIdempotentByKey(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	seedConnectorAdmin(t, ctx, admin, regOrg, trustVerifyConnectorAdminID, regOwner)
	connectionID := registerTrustVerifyConnection(t, ctx, service)
	store := newTrustVerifyStore(t, appStore)

	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: trustVerifyConnectorAdminID, RequestID: "req_trust_verify_replay"}
	request := workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("trust-verify-replay"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	first, err := store.VerifyConnectionTrust(ctx, access, request)
	if err != nil {
		t.Fatalf("first verify: %v", err)
	}
	second, err := store.VerifyConnectionTrust(ctx, access, request)
	if err != nil {
		t.Fatalf("replay verify: %v", err)
	}
	if first.ResultID != second.ResultID || first.ResultHash != second.ResultHash {
		t.Fatalf("replay returned a different result: %#v vs %#v", first, second)
	}
	var events int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_event
		 WHERE organization_id = $1 AND action = 'source.connection_trust_verified' AND outcome = 'SUCCESS'`,
		regOrg).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("replay appended %d success audit events, want 1", events)
	}
}

// TestSourceConnectionTrustVerifyRejectsIncompleteAttestationInSQL is the
// real-PostgreSQL proof for ADR-0087 §2 review blocker B2
// (review-opus-s2-4-5.md): migration 000059 replaces
// app.source_connection_trust_verify(text) with a version that requires the
// attestation fields itself, so an empty attestation is rejected by the
// database even when the Go request validator (VerifyConnectionTrustRequest
// .valid()) is bypassed entirely — this test calls the SECURITY DEFINER
// function directly as the runtime application role, never through
// Store.VerifyConnectionTrust.
func TestSourceConnectionTrustVerifyRejectsIncompleteAttestationInSQL(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)
	seedConnectorAdmin(t, ctx, admin, regOrg, trustVerifyConnectorAdminID, regOwner)
	connectionID := registerTrustVerifyConnection(t, ctx, service)
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	for _, testCase := range []struct {
		name                      string
		attestedConnectorIdentity string
		attestedBy                string
	}{
		{name: "empty attested_connector_identity", attestedConnectorIdentity: "", attestedBy: "security-team"},
		{name: "blank attested_connector_identity", attestedConnectorIdentity: "   ", attestedBy: "security-team"},
		{name: "empty attested_by", attestedConnectorIdentity: "folder-connector-1", attestedBy: ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tx, err := app.Begin(ctx)
			if err != nil {
				t.Fatalf("begin app tx: %v", err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, regOrg, trustVerifyConnectorAdminID)

			var result string
			execErr := tx.QueryRow(ctx, `SELECT app.source_connection_trust_verify($1, $2, $3, now())`,
				connectionID, testCase.attestedConnectorIdentity, testCase.attestedBy).Scan(&result)
			if execErr == nil {
				t.Fatalf("SQL accepted an incomplete attestation (%s), want rejection", testCase.name)
			}
			if database.SQLStateCode(execErr) != "23514" {
				t.Fatalf("errcode = %q, want 23514 (check_violation): %v", database.SQLStateCode(execErr), execErr)
			}
		})
	}

	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "DRAFT" {
		t.Fatalf("trust projection after rejected attempts = %q, want DRAFT", got)
	}
}

func TestSourceConnectionTrustVerifyRuntimeRoleHasNoUpdateGrant(t *testing.T) {
	// The product surface's only door onto source_connection_trust_projection
	// is the SECURITY DEFINER function app.source_connection_trust_verify
	// (migration 000057): the runtime application role must still hold no
	// direct UPDATE grant on the table, exactly as migration 000006/000014
	// declared and this checkpoint deliberately does not widen.
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedRegistrationTenant(t, ctx, admin)
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatalf("begin app tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, regOrg, regOwner)

	_, execErr := tx.Exec(ctx, `
		UPDATE public.source_connection_trust_projection SET status = 'VERIFIED' WHERE organization_id = $1`, regOrg)
	if execErr == nil {
		t.Fatal("runtime application role updated source_connection_trust_projection directly, want permission denied")
	}
	if database.SQLStateCode(execErr) != "42501" {
		t.Fatalf("update error = %v (sqlstate %q), want insufficient_privilege (42501)", execErr, database.SQLStateCode(execErr))
	}
}
