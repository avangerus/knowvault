package postgres_test

// Card D-1 acceptance proof against real PostgreSQL: a half-finished
// PostgreSQL connection is a workspace-scoped draft that the workspace that
// started it can list and discard, a foreign workspace cannot see, and an
// unchanged already-verified trust material can be re-attested without the
// WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED refusal a genuinely changed
// certificate still receives.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// seedDraftWorkspace adds one active workspace of regOrg owned by ownerID with
// that owner as its only member, built through the production canonical
// snapshot serializer so the workspace-repository read path accepts it. The
// registration tenant seed does not create a workspace by itself; the card's
// draft tests only need a real workspace and membership, not a source scope.
func seedDraftWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, workspaceID, ownerID string) {
	t.Helper()
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: regOrg, ID: workspaceID, Revision: 1, Name: workspaceID,
		Status: workspace.StatusActive, OwnerPrincipalID: ownerID,
		Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("normalize workspace %s: %v", workspaceID, err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("workspace %s hash: %v", workspaceID, err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("workspace %s canonical bytes: %v", workspaceID, err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
			VALUES ($1, $2, $1, 'ACTIVE', $3, 1)`, []any{workspaceID, regOrg, ownerID}},
		{`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
			VALUES ($1, $2, 1, $3, $4)`, []any{regOrg, workspaceID, configurationHash, ownerID}},
		{`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
			VALUES ($1, $2, 1, $3, $4)`, []any{regOrg, workspaceID, configurationHash, canonicalBytes}},
		{`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
			VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)`, []any{"wsm_" + workspaceID, regOrg, workspaceID, ownerID}},
	} {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed workspace %s step: %v", workspaceID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace %s: %v", workspaceID, err)
	}
}

func TestSourceConnectionDraftListingIsWorkspaceScoped(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	seedDraftWorkspace(t, ctx, admin, regWorkspace, regOwner)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_draft_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Operations database", DatabaseIdentity: "ops-demo", LineageID: "ops-primary",
			CredentialReference: testCredentialRef, WorkspaceID: regWorkspace,
		})
	if err != nil {
		t.Fatalf("bootstrap draft connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	store := newTrustVerifyStore(t, appStore)

	drafts, err := store.ListSourceConnectionDrafts(ctx, regOwnerAccess("req_draft_list"), regWorkspace)
	if err != nil {
		t.Fatalf("list own draft: %v", err)
	}
	if len(drafts) != 1 || drafts[0].ConnectionID != bootstrap.ConnectionID ||
		drafts[0].State != workspacerepository.SourceConnectionDraftAwaitingTrust ||
		drafts[0].TrustStatus != "DRAFT" || drafts[0].ConnectionName != "Operations database" {
		t.Fatalf("own workspace draft = %#v", drafts)
	}

	// A member of another workspace in the same organization lists their own
	// workspace and sees an empty list, never this draft.
	seedDraftWorkspace(t, ctx, admin, "ws_registration_other", regViewer)
	foreignAccess := database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_draft_foreign"}
	foreign, err := store.ListSourceConnectionDrafts(ctx, foreignAccess, "ws_registration_other")
	if err != nil {
		t.Fatalf("list foreign workspace drafts: %v", err)
	}
	if len(foreign) != 0 {
		t.Fatalf("foreign workspace saw %d draft(s): %#v", len(foreign), foreign)
	}

	// A caller who is not a member of the draft's workspace gets the one
	// content-free not-found, exactly like every other source metadata read.
	if _, err := store.ListSourceConnectionDrafts(ctx, foreignAccess, regWorkspace); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("non-member list error = %v, want CodeNotFound", err)
	}
}

func TestSourceConnectionDraftDiscardRemovesOnlyWorkspacePointer(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	seedDraftWorkspace(t, ctx, admin, regWorkspace, regOwner)

	bootstrap, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_discard_bootstrap"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Operations database", DatabaseIdentity: "ops-demo", LineageID: "ops-primary",
			CredentialReference: testCredentialRef, WorkspaceID: regWorkspace,
		})
	if err != nil {
		t.Fatalf("bootstrap draft connection: %v (code=%s)", err, registration.CodeOf(err))
	}
	store := newTrustVerifyStore(t, appStore)

	if err := store.DiscardSourceConnectionDraft(ctx, regOwnerAccess("req_draft_discard"), regWorkspace, bootstrap.ConnectionID); err != nil {
		t.Fatalf("discard own draft: %v", err)
	}
	drafts, err := store.ListSourceConnectionDrafts(ctx, regOwnerAccess("req_draft_list_after"), regWorkspace)
	if err != nil {
		t.Fatalf("list after discard: %v", err)
	}
	if len(drafts) != 0 {
		t.Fatalf("discarded draft still listed: %#v", drafts)
	}
	// Only the workspace pointer is gone: the immutable connection lineage is
	// untouched, so a replay can link it again.
	var connections int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1 AND id=$2`,
		regOrg, bootstrap.ConnectionID).Scan(&connections); err != nil {
		t.Fatal(err)
	}
	if connections != 1 {
		t.Fatalf("discard removed the connection lineage: count=%d", connections)
	}
	if _, err := service.BootstrapPostgreSQLConnection(ctx, regOwnerAccess("req_draft_relink"),
		registration.PostgreSQLConnectionBootstrapRequest{
			Name: "Operations database", DatabaseIdentity: "ops-demo", LineageID: "ops-primary",
			CredentialReference: testCredentialRef, WorkspaceID: regWorkspace,
		}); err != nil {
		t.Fatalf("re-bootstrap after discard: %v", err)
	}
	drafts, err = store.ListSourceConnectionDrafts(ctx, regOwnerAccess("req_draft_list_relinked"), regWorkspace)
	if err != nil || len(drafts) != 1 {
		t.Fatalf("re-bootstrap did not re-link the draft: drafts=%#v err=%v", drafts, err)
	}
}

func TestSourceConnectionTrustReentrySucceedsAndChangedCertificateIsRefused(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	appStore, _, service := seedRegistrationTenant(t, ctx, admin)
	seedConnectorAdmin(t, ctx, admin, regOrg, trustVerifyConnectorAdminID, regOwner)
	connectionID := registerTrustVerifyConnection(t, ctx, service)
	store := newTrustVerifyStore(t, appStore)
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: trustVerifyConnectorAdminID, RequestID: "req_trust_reentry"}

	verify := func(key, identity string) (workspacerepository.VerifyConnectionTrustResult, error) {
		return store.VerifyConnectionTrust(ctx, access, workspacerepository.VerifyConnectionTrustRequest{
			IdempotencyKey: authorityIdempotencyKey(key), ConnectionID: connectionID,
			AttestedConnectorIdentity: identity, AttestedBy: "security-team",
			AttestedAt: time.Now().UTC().Format(time.RFC3339),
		})
	}

	first, err := verify("trust-reentry-first", "folder-connector-1")
	if err != nil {
		t.Fatalf("first verification: %v", err)
	}
	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "VERIFIED" {
		t.Fatalf("trust projection after first verification = %q, want VERIFIED", got)
	}

	// Re-entering the wizard with the same trust material (the same attested
	// connector identity, a fresh idempotency key) continues from the current
	// state instead of failing the DRAFT -> VERIFIED precondition.
	second, err := verify("trust-reentry-second", "folder-connector-1")
	if err != nil {
		t.Fatalf("unchanged re-verification refused: %v (code=%s)", err, workspacerepository.CodeOf(err))
	}
	if second.ResultID == "" || second.ResultHash == "" {
		t.Fatalf("unchanged re-verification result = %#v", second)
	}
	if second.ResultID == first.ResultID {
		t.Fatalf("re-verification replayed the first result id %q instead of recording the re-attestation", second.ResultID)
	}

	// A different CONNECTOR_ADMIN re-attesting the same trust material must
	// also continue, not be refused because another administrator recorded the
	// original verification.
	const secondConnectorAdminID = "usr_reg_connector_admin_two"
	seedConnectorAdmin(t, ctx, admin, regOrg, secondConnectorAdminID, regOwner)
	secondAccess := database.AccessContext{OrganizationID: regOrg, PrincipalID: secondConnectorAdminID, RequestID: "req_trust_reentry_two"}
	third, err := store.VerifyConnectionTrust(ctx, secondAccess, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("trust-reentry-other-admin"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("unchanged re-verification by another CONNECTOR_ADMIN refused: %v (code=%s)", err, workspacerepository.CodeOf(err))
	}
	if third.ResultID == "" {
		t.Fatalf("other admin unchanged re-verification result = %#v", third)
	}

	// A genuinely changed certificate (a different connector identity for an
	// already-verified connection) still fails closed with the unchanged
	// precondition code.
	if _, err := verify("trust-reentry-changed", "different-connector"); workspacerepository.CodeOf(err) != workspacerepository.CodeConnectionTrustPreconditionFailed {
		t.Fatalf("changed certificate error = %v, want CodeConnectionTrustPreconditionFailed", err)
	}
	if got := trustProjectionStatus(t, ctx, admin, regOrg, connectionID); got != "VERIFIED" {
		t.Fatalf("changed certificate altered the trust projection = %q", got)
	}
}
