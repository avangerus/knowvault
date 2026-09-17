package postgres_test

// Explicit-source reconfirmation lifecycle (ADR-0052/0053/0054, manifest task
// explicit-source-reconfirmation-r53): after a workspace revision advances and
// an existing WORKSPACE_MANAGED confirmation becomes derived-stale, the
// operator must be able to re-confirm the now-current revision through the
// production repository authority-command runtime (IssueConfirmationGrant /
// ConfirmManagedSource / RevokeManagedConfirmation with idempotency keys) — no
// raw INSERT forgery — and the stale original must remain revocable under the
// current policy while the re-confirmed row stays derived-live. Replaying the
// re-confirm with the same idempotency key returns the stored AuthorityResult
// with no duplicate confirmation or receipt row (idempotent-replay), and a
// foreign-tenant re-confirm attempt resolves to WORKSPACE_AUTHORITY_NOT_FOUND
// only (real-postgresql-revision-rbac / RLS fail-closed).
//
// Every confirmation/revocation/grant in this test is produced by the closed
// four-operation runtime, so the receipts, deferred derived-live guards and the
// tenant fence on migration 000011 are all exercised end to end. The one
// non-authority mutation is the workspace revision advance itself: adding a
// workspace revision (and carrying the WORKSPACE_MANAGED source projection onto
// it) is a workspace source-plane operation, not an authority command, so it is
// seeded directly through the same canonical-snapshot serializer the workspace
// source-plane tests use.

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	reconfirmationOrganization = "org_reconfirm"
	reconfirmationOwner        = "usr_reconfirm_owner"
	reconfirmationWorkspace    = "ws_reconfirm"

	reconfirmationForeignOrganization = "org_reconfirm_foreign"
	reconfirmationForeignOwner        = "usr_reconfirm_foreign_owner"
	reconfirmationForeignWorkspace    = "ws_reconfirm_foreign"
)

// scopedCount rows of one table within one organization.
func scopedAuthorityCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, relation, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.`+relation+` WHERE organization_id = $1`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count %s in %s: %v", relation, organizationID, err)
	}
	return count
}

func scopedReceiptCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count receipts in %s: %v", organizationID, err)
	}
	return count
}

func scopedAuthorityAuditCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id = $1 AND resource_type = 'WORKSPACE_AUTHORITY_COMMAND'`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count authority audit events in %s: %v", organizationID, err)
	}
	return count
}

// advanceManagedWorkspaceRevision advances the fixture workspace to the next
// revision, carrying every WORKSPACE_MANAGED source projection of the current
// revision onto the fresh revision and storing its canonical snapshot exactly
// as the source-plane serializer would. This is the source-plane event that
// makes a confirmation naming the previous revision derived-stale; it returns
// the new revision and its configuration hash for a re-confirm command to name.
func advanceManagedWorkspaceRevision(
	t *testing.T, ctx context.Context, admin *pgxpool.Pool, fixture authorityOpsFixture,
) (int64, string) {
	t.Helper()
	newRevision := fixture.workspaceRevision + 1

	// Active members at the current revision (the fixtures carry the owner).
	type memberRow struct{ principalID, role string }
	var members []memberRow
	memberRows, err := admin.Query(ctx, `SELECT principal_id, role FROM public.workspace_member
		WHERE organization_id = $1 AND workspace_id = $2 AND removed_at IS NULL
		ORDER BY principal_id`, fixture.organizationID, fixture.workspaceID)
	if err != nil {
		t.Fatalf("read workspace members: %v", err)
	}
	for memberRows.Next() {
		var row memberRow
		if err := memberRows.Scan(&row.principalID, &row.role); err != nil {
			memberRows.Close()
			t.Fatalf("scan member: %v", err)
		}
		members = append(members, row)
	}
	memberRows.Close()
	if err := memberRows.Err(); err != nil {
		t.Fatalf("iterate members: %v", err)
	}

	// The source projection currently active at the fixture revision.
	type bindingRow struct {
		sourceScopeID          string
		sourceScopeRevision    int64
		scopeConfigHash        string
		enabled                bool
	}
	var bindings []bindingRow
	bindingQuery, err := admin.Query(ctx, `SELECT source_scope_id, source_scope_revision, scope_config_hash, enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $3
		ORDER BY source_scope_id`, fixture.organizationID, fixture.workspaceID, fixture.workspaceRevision)
	if err != nil {
		t.Fatalf("read current revision bindings: %v", err)
	}
	for bindingQuery.Next() {
		var row bindingRow
		if err := bindingQuery.Scan(&row.sourceScopeID, &row.sourceScopeRevision, &row.scopeConfigHash, &row.enabled); err != nil {
			bindingQuery.Close()
			t.Fatalf("scan binding: %v", err)
		}
		bindings = append(bindings, row)
	}
	bindingQuery.Close()
	if err := bindingQuery.Err(); err != nil {
		t.Fatalf("iterate bindings: %v", err)
	}

	memberList := make([]workspace.Member, 0, len(members))
	for _, member := range members {
		memberList = append(memberList, workspace.Member{PrincipalID: member.principalID, Role: workspace.Role(member.role)})
	}
	bindingList := make([]workspace.SourceBinding, 0, len(bindings))
	for _, binding := range bindings {
		bindingList = append(bindingList, workspace.SourceBinding{
			SourceScopeID: binding.sourceScopeID, SourceScopeRevision: binding.sourceScopeRevision,
			ScopeConfigHash: binding.scopeConfigHash, Enabled: binding.enabled,
		})
	}

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: fixture.organizationID, ID: fixture.workspaceID, Revision: newRevision,
		Name: fixture.workspaceID, Status: workspace.StatusActive, OwnerPrincipalID: fixture.ownerID,
		Members: memberList, SourceBindings: bindingList,
	})
	if err != nil {
		t.Fatalf("normalize advanced workspace snapshot: %v", err)
	}
	newHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("advanced workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("advanced workspace canonical snapshot: %v", err)
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin revision advance: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)`, fixture.organizationID, fixture.workspaceID, newRevision, newHash, fixture.ownerID); err != nil {
		t.Fatalf("insert advanced workspace revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, $3, $4, $5)`, fixture.organizationID, fixture.workspaceID, newRevision, newHash, canonicalBytes); err != nil {
		t.Fatalf("insert advanced workspace snapshot: %v", err)
	}
	// Carry the source projection onto the fresh revision exactly as the
	// source-plane does; the exact-set guard compares these rows to the
	// canonical bindings above.
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision_source (
			organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
			workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled
		)
		SELECT $1, $2, $3, $4, workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $5`,
		fixture.organizationID, fixture.workspaceID, newRevision, newHash, fixture.workspaceRevision); err != nil {
		t.Fatalf("carry source projection onto advanced revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision = $3
		WHERE organization_id = $1 AND id = $2`, fixture.organizationID, fixture.workspaceID, newRevision); err != nil {
		t.Fatalf("advance workspace current revision: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace revision advance: %v", err)
	}
	return newRevision, newHash
}

func loadConfirmationHash(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, confirmationID string) string {
	t.Helper()
	var hash string
	if err := admin.QueryRow(ctx, `SELECT confirmation_hash FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1 AND confirmation_id = $2`, organizationID, confirmationID).Scan(&hash); err != nil {
		t.Fatalf("load confirmation hash: %v", err)
	}
	return hash
}

// TestExplicitSourceReconfirmationStaleReconfirmRevokeReplay walks the whole
// operator-visible lifecycle against real PostgreSQL: initial grant+confirm at
// the current revision, a workspace revision advance that stales it, a re-confirm
// naming the current revision (exactly one new live confirmation), an idempotent
// replay of that re-confirm (no new row, no new receipt), a revocation of the
// stale original under the current policy (the re-confirmed row stays live), and
// a foreign-tenant re-confirm that resolves to WORKSPACE_AUTHORITY_NOT_FOUND only.
func TestExplicitSourceReconfirmationStaleReconfirmRevokeReplay(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsTenant(t, ctx, admin, reconfirmationOrganization, reconfirmationOwner, reconfirmationWorkspace)
	store := newAuthorityRuntime(t, ctx)

	// 1. Issue a grant and confirm the current revision: a live confirmation.
	grant := issueRuntimeGrant(t, ctx, store, fixture, "reconf-issue")
	original, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_reconf_original_confirm"),
		confirmRuntimeRequest(fixture, grant, "reconf-original-confirm"))
	if err != nil {
		t.Fatalf("initial confirm at current revision: %v", err)
	}
	if !derivedLive(ctx, admin, fixture.organizationID, original.ResultID) {
		t.Fatal("initial confirmation is not derived-live while its revision is current")
	}
	if got := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID); got != 1 {
		t.Fatalf("initial confirm produced %d confirmations, want 1", got)
	}

	// 2. A workspace revision advances (source-plane event). The original
	//    confirmation, still naming the old revision, becomes derived-stale.
	newRevision, newHash := advanceManagedWorkspaceRevision(t, ctx, admin, fixture)
	if derivedLive(ctx, admin, fixture.organizationID, original.ResultID) {
		t.Fatal("original confirmation is still derived-live after its workspace revision advanced")
	}

	// 3. The operator re-confirms the now-current revision. Exactly one new
	//    live confirmation commits (the stale original is not a live blocker).
	reconfirmRequest := confirmRuntimeRequest(fixture, grant, "reconf-new-confirm")
	reconfirmRequest.WorkspaceRevision = newRevision
	reconfirmRequest.WorkspaceConfigurationHash = newHash
	reconfirmed, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_reconf_reconfirm"),
		reconfirmRequest)
	if err != nil {
		t.Fatalf("re-confirm naming the current revision: %v", err)
	}
	if reconfirmed.ResultID == original.ResultID {
		t.Fatalf("re-confirm returned the stale original confirmation id")
	}
	if !derivedLive(ctx, admin, fixture.organizationID, reconfirmed.ResultID) {
		t.Fatal("re-confirmed row is not derived-live at the current revision")
	}
	if got := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID); got != 2 {
		t.Fatalf("re-confirm produced %d confirmations, want exactly 2 (stale original + re-confirmed)", got)
	}

	// 4. Replaying the re-confirm with the same idempotency key returns the
	//    stored AuthorityResult and creates no additional confirmation, receipt
	//    or audit event (idempotent-replay).
	confirmationsBefore := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID)
	receiptsBefore := scopedReceiptCount(t, ctx, admin, fixture.organizationID)
	auditsBefore := scopedAuthorityAuditCount(t, ctx, admin, fixture.organizationID)
	replayed, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_reconf_reconfirm_replay"),
		reconfirmRequest)
	if err != nil {
		t.Fatalf("replay of the re-confirm: %v", err)
	}
	if replayed.ResultID != reconfirmed.ResultID || replayed.ResultHash != reconfirmed.ResultHash {
		t.Fatalf("replay changed the re-confirm result: %s/%s vs %s/%s",
			replayed.ResultID, replayed.ResultHash, reconfirmed.ResultID, reconfirmed.ResultHash)
	}
	if got := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID); got != confirmationsBefore {
		t.Fatalf("idempotent replay added %d confirmation rows", got-confirmationsBefore)
	}
	if got := scopedReceiptCount(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
		t.Fatalf("idempotent replay added %d receipts", got-receiptsBefore)
	}
	if got := scopedAuthorityAuditCount(t, ctx, admin, fixture.organizationID); got != auditsBefore {
		t.Fatalf("idempotent replay added %d authority audit events", got-auditsBefore)
	}

	// 5. The now-stale original confirmation is still revocable under the
	//    current policy, and the re-confirmed row stays derived-live.
	originalHash := loadConfirmationHash(t, ctx, admin, fixture.organizationID, original.ResultID)
	if _, err := store.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_reconf_revoke_stale"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("reconf-revoke-stale"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ConfirmationID: original.ResultID, ConfirmationHash: originalHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke the stale original confirmation under the current policy: %v", err)
	}
	if !derivedLive(ctx, admin, fixture.organizationID, reconfirmed.ResultID) {
		t.Fatal("the re-confirmed row lost derived-liveness after the stale original was revoked")
	}
	if got := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_revocation", fixture.organizationID); got != 1 {
		t.Fatalf("stale-original revocation produced %d revocation rows, want 1", got)
	}

	// 6. A foreign-tenant attempt to re-confirm the current revision resolves to
	//    WORKSPACE_AUTHORITY_NOT_FOUND only: no confirmation row is created and
	//    no SUCCESS receipt is recorded for the trusted tenant (RLS fail-closed).
	foreign := setupAuthorityOpsTenant(t, ctx, admin, reconfirmationForeignOrganization, reconfirmationForeignOwner, reconfirmationForeignWorkspace)
	foreignConfirmationsBefore := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID)
	foreignAccess := database.AccessContext{
		OrganizationID: foreign.organizationID, PrincipalID: foreign.ownerID, RequestID: "req_foreign_reconfirm",
	}
	_, foreignErr := store.ConfirmManagedSource(ctx, foreignAccess, workspacerepository.ConfirmRequest{
		IdempotencyKey: authorityIdempotencyKey("reconf-foreign"), OrganizationID: fixture.organizationID,
		WorkspaceID: fixture.workspaceID, WorkspaceRevision: newRevision,
		WorkspaceConfigurationHash: newHash, WorkspaceSourceID: fixture.workspaceSourceID,
		SourceScopeID: fixture.sourceScopeID, SourceScopeRevision: fixture.sourceScopeRevision,
		ScopeConfigHash: fixture.scopeConfigHash, AccessMode: authorityAccessMode,
		ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1,
		ConfirmationActorGrantHash: grant.ResultHash, WarningVersion: confirmationWarningVer,
		WarningContractHash: confirmationWarnHash, AcknowledgementCode: confirmationAckCode,
		ExpectedPolicyRevision: fixture.policyID,
	})
	if workspacerepository.CodeOf(foreignErr) != workspacerepository.CodeAuthorityNotFound {
		t.Fatalf("foreign-tenant re-confirm code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", workspacerepository.CodeOf(foreignErr))
	}
	if got := scopedAuthorityCount(t, ctx, admin, "workspace_managed_grant_confirmation", fixture.organizationID); got != foreignConfirmationsBefore {
		t.Fatalf("foreign-tenant re-confirm created %d confirmation rows in the trusted tenant", got-foreignConfirmationsBefore)
	}
}
