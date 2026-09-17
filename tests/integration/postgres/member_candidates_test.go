package postgres_test

// P10a real-PostgreSQL proof. The repository MemberCandidates read resolves the
// caller's OperationWorkspaceManage (OWNER/MANAGER of an ACTIVE workspace)
// authorization and returns only current ACTIVE USER principals of the caller's
// own organization, with principal_id/display_name/already_member, deterministic
// order and a truthful truncated boundary. Denied callers, revoked/archived
// workspaces and inactive/foreign/service/group principals never leak.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestWorkspaceMemberCandidatesNameAndIDSearch(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	mustAddPrincipal(t, ctx, admin, "usr_bob", "org_alpha", "USER", "Bob Builder", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_carol", "org_alpha", "USER", "Carol Architect", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_name"}

	byName, err := store.MemberCandidates(ctx, owner, "ws_alpha", "Bob")
	if err != nil {
		t.Fatalf("name search: %v", err)
	}
	if len(byName.Candidates) != 1 || byName.Candidates[0].PrincipalID != "usr_bob" ||
		byName.Candidates[0].DisplayName != "Bob Builder" || byName.Candidates[0].AlreadyMember || byName.Truncated {
		t.Fatalf("name candidates=%#v truncated=%v", byName.Candidates, byName.Truncated)
	}

	// Searching by id returns only the exact literal owner (already a member).
	byID, err := store.MemberCandidates(ctx, owner, "ws_alpha", "usr_alice")
	if err != nil {
		t.Fatalf("id search: %v", err)
	}
	if len(byID.Candidates) != 1 || byID.Candidates[0].PrincipalID != "usr_alice" || !byID.Candidates[0].AlreadyMember {
		t.Fatalf("id candidates=%#v", byID.Candidates)
	}
}

func TestWorkspaceMemberCandidatesCrossTenantInactiveAndServiceExclusion(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")

	mustAddPrincipal(t, ctx, admin, "usr_bob", "org_alpha", "USER", "Bob Alpha", "ACTIVE")
	// The same display text in another tenant must never be returned.
	mustAddPrincipal(t, ctx, admin, "usr_zara", "org_beta", "USER", "Bob Zeta", "ACTIVE")
	// Inactive / service / group principals with a matching name must never
	// be returned even inside the caller's own organization.
	mustAddPrincipal(t, ctx, admin, "usr_disabled", "org_alpha", "USER", "Bob Disabled", "DISABLED")
	mustAddPrincipal(t, ctx, admin, "usr_deprov", "org_alpha", "USER", "Bob Gone", "DEPROVISIONED")
	mustAddPrincipal(t, ctx, admin, "usr_svc", "org_alpha", "SERVICE", "Bob Service", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_grp", "org_alpha", "GROUP", "Bob Team", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_excl"}
	result, err := store.MemberCandidates(ctx, owner, "ws_alpha", "Bob")
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].PrincipalID != "usr_bob" {
		t.Fatalf("candidates=%#v, want only usr_bob", result.Candidates)
	}
}

func TestWorkspaceMemberCandidatesRoleDenialAndArchived(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	mustAddPrincipal(t, ctx, admin, "usr_bob", "org_alpha", "USER", "Bob Builder", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_carol", "org_alpha", "USER", "Carol Member", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_role"}
	initial, err := store.Get(ctx, owner, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}

	// bob becomes a MANAGER (allowed to manage members), carol stays MEMBER.
	withBob, err := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("p10a-manager"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial), PrincipalID: "usr_bob", Role: workspace.RoleManager,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("p10a-member"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, withBob), PrincipalID: "usr_carol", Role: workspace.RoleMember,
	}); err != nil {
		t.Fatal(err)
	}

	manager := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_p10a_manager"}
	if result, err := store.MemberCandidates(ctx, manager, "ws_alpha", "Bob"); err != nil || len(result.Candidates) == 0 {
		t.Fatalf("manager search candidates=%#v err=%v", result.Candidates, err)
	}

	member := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_p10a_member"}
	if _, err := store.MemberCandidates(ctx, member, "ws_alpha", "Bob"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("member search code=%q err=%v", workspacerepository.CodeOf(err), err)
	}

	// The owner (a manager-capable caller) may not search an archived
	// workspace: the same content-free refusal as absence.
	archived, err := store.Archive(ctx, owner, workspacerepository.ArchiveRequest{
		IdempotencyKey: workspaceIdempotencyKey("p10a-archive"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, mustCurrent(t, store, ctx, owner, "ws_alpha")),
	})
	if err != nil || archived.Status != workspace.StatusArchived {
		t.Fatalf("archive status=%v err=%v", archived.Status, err)
	}
	if _, err := store.MemberCandidates(ctx, owner, "ws_alpha", "Bob"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("archived search code=%q err=%v", workspacerepository.CodeOf(err), err)
	}
}

// TestWorkspaceMemberCandidatesDenySurfaceBeyondMemberAndArchive proves on a
// real PostgreSQL database that OperationWorkspaceManage denial is content-free
// (CodeNotFound) not only for a plain workspace MEMBER and an archived
// workspace but also for a workspace VIEWER, a workspace AUDITOR, a caller
// whose MANAGER grant was revoked, a caller from a foreign (other-organization)
// tenant targeting a workspace that is not its own, and an inactive-actor
// caller — while preserving the OWNER/MANAGER positive paths.
func TestWorkspaceMemberCandidatesDenySurfaceBeyondMemberAndArchive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// A separate tenant owner lets us prove a foreign caller cannot observe ws_alpha.
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")
	mustAddPrincipal(t, ctx, admin, "usr_bob", "org_alpha", "USER", "Bob Builder", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_mem", "org_alpha", "USER", "Mina Member", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_view", "org_alpha", "USER", "Vera Viewer", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_aud", "org_alpha", "USER", "Avery Auditor", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_mgr", "org_alpha", "USER", "Max Manager", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_ghost", "org_alpha", "USER", "Gus Ghost", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_denysurf"}
	current, err := store.Get(ctx, owner, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	add := func(principalID string, role workspace.Role, label string) {
		next, addErr := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
			IdempotencyKey:            workspaceIdempotencyKey("p10a-" + label),
			WorkspaceID:               "ws_alpha",
			ExpectedConfigurationHash: mustWorkspaceHash(t, current),
			PrincipalID:               principalID,
			Role:                      role,
		})
		if addErr != nil {
			t.Fatalf("add %s: %v", label, addErr)
		}
		current = next
	}
	add("usr_mem", workspace.RoleMember, "member")
	add("usr_view", workspace.RoleViewer, "viewer")
	add("usr_aud", workspace.RoleAuditor, "auditor")
	add("usr_mgr", workspace.RoleManager, "manager")
	add("usr_ghost", workspace.RoleManager, "ghost")

	deny := func(access database.AccessContext, label string) {
		_, lookupErr := store.MemberCandidates(ctx, access, "ws_alpha", "Bob")
		if workspacerepository.CodeOf(lookupErr) != workspacerepository.CodeNotFound {
			t.Fatalf("%s denial code=%q err=%v", label, workspacerepository.CodeOf(lookupErr), lookupErr)
		}
	}
	deny(database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_mem", RequestID: "req_p10a_member"}, "member")
	deny(database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_view", RequestID: "req_p10a_viewer"}, "viewer")
	deny(database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_aud", RequestID: "req_p10a_auditor"}, "auditor")

	// usr_mgr is an effective MANAGER while active: prove the positive path
	// before revoking the grant to keep the revoke assertion meaningful.
	manager := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_mgr", RequestID: "req_p10a_manager"}
	if result, mgrErr := store.MemberCandidates(ctx, manager, "ws_alpha", "Bob"); mgrErr != nil || len(result.Candidates) == 0 {
		t.Fatalf("manager before revoke candidates=%#v err=%v", result.Candidates, mgrErr)
	}
	if _, err := store.RemoveMember(ctx, owner, workspacerepository.RemoveMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("p10a-revoke"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, current),
		PrincipalID:               "usr_mgr",
	}); err != nil {
		t.Fatalf("revoke manager grant: %v", err)
	}
	deny(manager, "revoked-former-manager")

	// A caller from org_beta targeting ws_alpha must not observe a workspace it
	// has no grant to: the target is absent from its tenant, so CodeNotFound.
	foreign := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_eve", RequestID: "req_p10a_foreign"}
	deny(foreign, "foreign-workspace")

	// Deactivate a still-granted MANAGER: an inactive actor loses manage
	// authority even while its membership row remains, and the read is
	// content-free. Seed deactivation is the same admin-level fixture step
	// mustAddPrincipal uses for principal status.
	if _, deactivateErr := admin.Exec(ctx, `UPDATE public.principal SET status = 'DISABLED', session_revision = session_revision + 1 WHERE id = 'usr_ghost'`); deactivateErr != nil {
		t.Fatalf("deactivate ghost: %v", deactivateErr)
	}
	inactive := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_ghost", RequestID: "req_p10a_inactive"}
	deny(inactive, "inactive-actor")

	// The OWNER still retains the manage path after every denial setup above.
	ownerDeny := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_owner_recheck"}
	if result, ownerErr := store.MemberCandidates(ctx, ownerDeny, "ws_alpha", "Bob"); ownerErr != nil || len(result.Candidates) != 1 || result.Candidates[0].PrincipalID != "usr_bob" {
		t.Fatalf("owner recheck candidates=%#v err=%v", result.Candidates, ownerErr)
	}
}

func TestWorkspaceMemberCandidatesLiteralPercentAndUnderscore(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// Only dave's literal display name contains "%_"; david's does not, so a
	// query of "%_" must match dave alone and never act as a wildcard.
	mustAddPrincipal(t, ctx, admin, "usr_dave", "org_alpha", "USER", "Dave 50%_Special", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_david", "org_alpha", "USER", "Dave 50XSpecial", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_literal"}
	result, err := store.MemberCandidates(ctx, owner, "ws_alpha", "50%_")
	if err != nil {
		t.Fatalf("literal search: %v", err)
	}
	if len(result.Candidates) != 1 || result.Candidates[0].PrincipalID != "usr_dave" {
		t.Fatalf("literal candidates=%#v, want only usr_dave", result.Candidates)
	}
}

func TestWorkspaceMemberCandidatesLimitAndTruncation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	for index := 0; index < 30; index++ {
		id := "usr_limit_" + pad2(index)
		mustAddPrincipal(t, ctx, admin, id, "org_alpha", "USER", "Limit Worker "+pad2(index), "ACTIVE")
	}

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_p10a_limit"}
	result, err := store.MemberCandidates(ctx, owner, "ws_alpha", "Limit Worker")
	if err != nil {
		t.Fatalf("limit search: %v", err)
	}
	if len(result.Candidates) != 20 || !result.Truncated {
		t.Fatalf("candidates=%d truncated=%v, want 20 and truncated", len(result.Candidates), result.Truncated)
	}
	for index := 1; index < len(result.Candidates); index++ {
		if result.Candidates[index-1].PrincipalID >= result.Candidates[index].PrincipalID {
			t.Fatalf("candidates not strictly ordered by id: %q before %q",
				result.Candidates[index-1].PrincipalID, result.Candidates[index].PrincipalID)
		}
	}
}

func mustCurrent(t *testing.T, store *workspacerepository.Store, ctx context.Context, access database.AccessContext, workspaceID string) workspace.Snapshot {
	t.Helper()
	snapshot, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("get %s: %v", workspaceID, err)
	}
	return snapshot
}

func mustAddPrincipal(t *testing.T, ctx context.Context, admin *pgxpool.Pool, id, organizationID, principalType, displayName, status string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, $3, $4, $5)
	`, id, organizationID, principalType, displayName, status); err != nil {
		t.Fatalf("seed principal %s: %v", id, err)
	}
}

func pad2(value int) string {
	return fmt.Sprintf("%02d", value)
}
