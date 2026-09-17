package postgres_test

// TestSourceConnectionTrustVerifyDeniesSameConfirmerAsVerifier is the
// real-PostgreSQL proof for ADR-0087 §2 review blocker B3
// (review-opus-s2-4-5.md): "A principal cannot be both the CONNECTOR_ADMIN
// verifier and the confirming workspace owner/manager for the same scope;
// that separation is enforced at authorization time, not left to operational
// discipline." Migration 000059 adds this check inside
// app.source_connection_trust_verify itself.

import (
	"context"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestSourceConnectionTrustVerifyDeniesSameConfirmerAsVerifier(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	connectionID := "conn_" + fixture.organizationID

	// The fixture's owner confirms the WORKSPACE_MANAGED binding for this
	// connection's scope.
	grant := issueRuntimeGrant(t, ctx, store, fixture, "sod-issue")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_sod_confirm"),
		confirmRuntimeRequest(fixture, grant, "sod-confirm")); err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	// The same owner also becomes CONNECTOR_ADMIN for this organization
	// (seedConnectorAdmin can't be reused here: it inserts a fresh principal,
	// and this principal -- the confirmer -- already exists from the fixture).
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_sod_owner_admin', $1, $2, 'CONNECTOR_ADMIN', 1, $2)`, fixture.organizationID, fixture.ownerID); err != nil {
		t.Fatalf("grant CONNECTOR_ADMIN to the confirming owner: %v", err)
	}

	if got := trustProjectionStatus(t, ctx, admin, fixture.organizationID, connectionID); got != "DRAFT" {
		t.Fatalf("trust projection before verification = %q, want DRAFT", got)
	}

	sameConfirmerAccess := database.AccessContext{OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_sod_verify_same"}
	_, err := store.VerifyConnectionTrust(ctx, sameConfirmerAccess, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("sod-verify-same-principal"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeConnectionTrustDenied {
		t.Fatalf("same-principal verify-trust code = %v, want CodeConnectionTrustDenied", err)
	}
	if got := trustProjectionStatus(t, ctx, admin, fixture.organizationID, connectionID); got != "DRAFT" {
		t.Fatalf("trust projection after same-principal denial = %q, want DRAFT (fail-closed)", got)
	}

	// A different CONNECTOR_ADMIN principal, who never confirmed this scope,
	// succeeds — proving the denial above was the separation-of-duty check
	// and not some unrelated fixture defect.
	secondAdmin := "usr_authority_ops_second_admin"
	seedConnectorAdmin(t, ctx, admin, fixture.organizationID, secondAdmin, fixture.ownerID)

	differentVerifierAccess := database.AccessContext{OrganizationID: fixture.organizationID, PrincipalID: secondAdmin, RequestID: "req_sod_verify_different"}
	result, err := store.VerifyConnectionTrust(ctx, differentVerifierAccess, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("sod-verify-different-principal"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("different-principal verify-trust: %v", err)
	}
	if result.ResultID == "" || result.ResultHash == "" {
		t.Fatalf("different-principal verify-trust result = %#v", result)
	}
	if got := trustProjectionStatus(t, ctx, admin, fixture.organizationID, connectionID); got != "VERIFIED" {
		t.Fatalf("trust projection after different-principal verification = %q, want VERIFIED", got)
	}
}
