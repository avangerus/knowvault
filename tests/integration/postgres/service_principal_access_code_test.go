package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestServiceAccessCodeIssueAuthenticateRevoke proves the V1-C agent access
// code lifecycle on real PostgreSQL: an OWNER issues a code scoped to one
// workspace it owns, the raw code authenticates as a SERVICE principal that
// can read only the granted workspace, a code scoped to a workspace the
// caller does not own is refused before anything is created, and revoke
// immediately makes the same raw code unauthenticatable.
func TestServiceAccessCodeIssueAuthenticateRevoke(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// ws_other is owned by bob, not alice: Issue must refuse a request naming
	// it alongside ws_alpha, before creating a principal or credential.
	seedSecondWorkspaceOwnedByAnotherPrincipal(t, ctx, admin, "org_alpha", "usr_bob", "ws_other")

	databaseStore, auditStore, workspaceStore := newServiceAccessCodeStores(t, ctx)
	accessCodes, err := serviceprincipal.New(databaseStore, auditStore, workspaceStore)
	if err != nil {
		t.Fatal(err)
	}
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_issue"}

	// Partial authority (owner of ws_alpha only) must deny the whole request.
	if _, err := accessCodes.Issue(ctx, alice, serviceprincipal.IssueRequest{
		Name: "agent-1", WorkspaceIDs: []string{"ws_alpha", "ws_other"}, TTLSeconds: 3600,
		IdempotencyKey: workspaceIdempotencyKey("access-code-partial-authority"),
	}); serviceprincipal.CodeOf(err) != serviceprincipal.CodeDenied {
		t.Fatalf("partial-authority issue code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}

	issueKey := workspaceIdempotencyKey("access-code-issue-1")
	result, err := accessCodes.Issue(ctx, alice, serviceprincipal.IssueRequest{
		Name: "agent-1", WorkspaceIDs: []string{"ws_alpha"}, TTLSeconds: 3600, IdempotencyKey: issueKey,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if result.Code == "" || result.PrincipalID == "" || result.CredentialID == "" {
		t.Fatalf("incomplete issue result: %#v", result)
	}
	if !serviceprincipal.ValidCodeShape(result.Code) {
		t.Fatalf("issued code has the wrong shape: %q", result.Code)
	}

	serviceAccess, err := accessCodes.Authenticate(ctx, "org_alpha", result.Code, "req_mcp")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if serviceAccess.PrincipalID != result.PrincipalID || serviceAccess.EffectiveActorKind() != database.ActorKindService {
		t.Fatalf("unexpected resolved access: %#v", serviceAccess)
	}
	if snapshot, err := workspaceStore.Get(ctx, serviceAccess, "ws_alpha"); err != nil {
		t.Fatalf("granted workspace read: %v", err)
	} else if snapshot.ID != "ws_alpha" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
	// The same principal must not reach a workspace it was never scoped to.
	if _, err := workspaceStore.Get(ctx, serviceAccess, "ws_other"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("ungranted workspace code=%q err=%v", workspacerepository.CodeOf(err), err)
	}

	list, err := accessCodes.List(ctx, alice, "ws_alpha")
	if err != nil || len(list) != 1 || list[0].CredentialID != result.CredentialID || list[0].RevokedAt != nil {
		t.Fatalf("list=%#v err=%v", list, err)
	}

	// FIX-1 #2: a retry with the exact same idempotency key and body must
	// never mint a second principal/credential. The raw code can never be
	// replayed (it is never persisted), so the retry gets a typed
	// already-issued outcome instead.
	if _, err := accessCodes.Issue(ctx, alice, serviceprincipal.IssueRequest{
		Name: "agent-1", WorkspaceIDs: []string{"ws_alpha"}, TTLSeconds: 3600, IdempotencyKey: issueKey,
	}); serviceprincipal.CodeOf(err) != serviceprincipal.CodeAlreadyIssued {
		t.Fatalf("replayed issue code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}
	if list, err := accessCodes.List(ctx, alice, "ws_alpha"); err != nil || len(list) != 1 {
		t.Fatalf("list after replay=%#v err=%v", list, err)
	}
	// The same key with a different body is a conflict, not a replay.
	if _, err := accessCodes.Issue(ctx, alice, serviceprincipal.IssueRequest{
		Name: "agent-2", WorkspaceIDs: []string{"ws_alpha"}, TTLSeconds: 3600, IdempotencyKey: issueKey,
	}); serviceprincipal.CodeOf(err) != serviceprincipal.CodeIdempotencyConflict {
		t.Fatalf("conflicting issue code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}

	// An unknown/garbage bearer value must never authenticate.
	if _, err := accessCodes.Authenticate(ctx, "org_alpha", serviceprincipal.CodePrefix+"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "req_bad"); serviceprincipal.CodeOf(err) != serviceprincipal.CodeDenied {
		t.Fatalf("garbage code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}

	if err := accessCodes.Revoke(ctx, alice, result.CredentialID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := accessCodes.Authenticate(ctx, "org_alpha", result.Code, "req_after_revoke"); serviceprincipal.CodeOf(err) != serviceprincipal.CodeDenied {
		t.Fatalf("post-revoke authenticate code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}
	if _, err := workspaceStore.Get(ctx, database.AccessContext{OrganizationID: "org_alpha", PrincipalID: result.PrincipalID, RequestID: "req_post_revoke_member"}, "ws_alpha"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("post-revoke membership code=%q err=%v", workspacerepository.CodeOf(err), err)
	}
	if err := accessCodes.Revoke(ctx, alice, result.CredentialID); serviceprincipal.CodeOf(err) != serviceprincipal.CodeNotFound {
		t.Fatalf("double revoke code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}
}

func newServiceAccessCodeStores(t *testing.T, ctx context.Context) (*database.Store, *audit.Store, *workspacerepository.Store) {
	t.Helper()
	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	return databaseStore, auditStore, workspaceStore
}

// seedSecondWorkspaceOwnedByAnotherPrincipal adds one more USER principal and
// one more ACTIVE workspace (with that principal as its sole OWNER) to an
// already-seeded organization, mirroring seedOrganization's own direct-SQL
// transaction so the workspace-active-owner-membership trigger is satisfied
// exactly once at commit.
func seedSecondWorkspaceOwnedByAnotherPrincipal(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive,
		OwnerPrincipalID: ownerID, Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("seed second workspace snapshot: %v", err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("seed second workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("seed second workspace canonical snapshot: %v", err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql:  "INSERT INTO public.principal (id, organization_id, type, display_name, status) VALUES ($1, $2, 'USER', $1, 'ACTIVE')",
			args: []any{ownerID, organizationID},
		},
		{
			sql:  "INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id) VALUES ($1, $2, $1, 'ACTIVE', $3)",
			args: []any{workspaceID, organizationID, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, canonicalBytes},
		},
		{
			sql:  "INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)",
			args: []any{"wsm_" + workspaceID, organizationID, workspaceID, ownerID},
		},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed second workspace %s: %v", workspaceID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit second workspace %s: %v", workspaceID, err)
	}
}

// seedSecondWorkspaceSameOwner adds one more ACTIVE workspace, owned by an
// already-seeded principal, to an already-seeded organization. Unlike
// seedSecondWorkspaceOwnedByAnotherPrincipal it never inserts a principal row
// (the owner already exists), so it is safe to call for a workspace the same
// human owns alongside their first one.
func seedSecondWorkspaceSameOwner(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive,
		OwnerPrincipalID: ownerID, Members: []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatalf("seed same-owner workspace snapshot: %v", err)
	}
	configurationHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("seed same-owner workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("seed same-owner workspace canonical snapshot: %v", err)
	}
	statements := []struct {
		sql  string
		args []any
	}{
		{
			sql:  "INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id) VALUES ($1, $2, $1, 'ACTIVE', $3)",
			args: []any{workspaceID, organizationID, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, ownerID},
		},
		{
			sql:  "INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes) VALUES ($1, $2, 1, $3, $4)",
			args: []any{organizationID, workspaceID, configurationHash, canonicalBytes},
		},
		{
			sql:  "INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by) VALUES ($1, $2, $3, $4, 'OWNER', 1, $4)",
			args: []any{"wsm_" + workspaceID, organizationID, workspaceID, ownerID},
		},
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed same-owner workspace %s: %v", workspaceID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit same-owner workspace %s: %v", workspaceID, err)
	}
}

// failAddMemberFor wraps a real WorkspaceAuthority and fails AddMember for one
// named workspace, forwarding everything else (Get, RemoveMember, and
// AddMember for any other workspace) to the real store. It lets the test
// inject a deterministic mid-loop failure on real PostgreSQL without any
// change to internal/serviceprincipal itself.
type failAddMemberFor struct {
	serviceprincipal.WorkspaceAuthority
	workspaceID string
}

func (wrapped failAddMemberFor) AddMember(ctx context.Context, access database.AccessContext, request workspacerepository.AddMemberRequest) (workspace.Snapshot, error) {
	if request.WorkspaceID == wrapped.workspaceID {
		return workspace.Snapshot{}, errors.New("injected: add member failure")
	}
	return wrapped.WorkspaceAuthority.AddMember(ctx, access, request)
}

// TestServiceAccessCodeIssuePartialFailureLeavesNoActiveAccess proves FIX-1
// #2's atomicity half: when the second of two requested workspaces fails its
// AddMember, Issue must leave no authenticatable credential (not even scoped
// only to the first workspace) and must remove the membership the first
// workspace's AddMember already granted.
func TestServiceAccessCodeIssuePartialFailureLeavesNoActiveAccess(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedSecondWorkspaceSameOwner(t, ctx, admin, "org_alpha", "usr_alice", "ws_gamma")

	databaseStore, auditStore, workspaceStore := newServiceAccessCodeStores(t, ctx)
	failingWorkspaces := failAddMemberFor{WorkspaceAuthority: workspaceStore, workspaceID: "ws_gamma"}
	accessCodes, err := serviceprincipal.New(databaseStore, auditStore, failingWorkspaces)
	if err != nil {
		t.Fatal(err)
	}
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_issue_partial"}

	_, err = accessCodes.Issue(ctx, alice, serviceprincipal.IssueRequest{
		Name: "agent-partial", WorkspaceIDs: []string{"ws_alpha", "ws_gamma"}, TTLSeconds: 3600,
		IdempotencyKey: workspaceIdempotencyKey("access-code-partial-failure"),
	})
	if serviceprincipal.CodeOf(err) != serviceprincipal.CodeUnavailable {
		t.Fatalf("partial-failure issue code=%q err=%v", serviceprincipal.CodeOf(err), err)
	}

	// No credential for this OWNER's workspace shows any trace of an active
	// grant: List on ws_alpha (the workspace whose AddMember succeeded before
	// the injected failure on ws_gamma) must show nothing live.
	list, listErr := accessCodes.List(ctx, alice, "ws_alpha")
	if listErr != nil {
		t.Fatalf("list after partial failure: %v", listErr)
	}
	for _, credential := range list {
		if credential.RevokedAt == nil {
			t.Fatalf("credential %q from a failed Issue is not revoked: %#v", credential.CredentialID, credential)
		}
	}

	// The membership ws_alpha's AddMember granted before the failure must have
	// been unwound: no SERVICE principal this Issue call could have created
	// remains a member of ws_alpha. We cannot name the principal id directly
	// (Issue returned no result), so assert on the workspace's own member
	// count instead: only alice (OWNER) remains.
	ownerAccess := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_check_members"}
	snapshot, getErr := workspaceStore.Get(ctx, ownerAccess, "ws_alpha")
	if getErr != nil {
		t.Fatalf("get ws_alpha after partial failure: %v", getErr)
	}
	if len(snapshot.Members) != 1 || snapshot.Members[0].PrincipalID != "usr_alice" {
		t.Fatalf("ws_alpha retains a stray member after unwind: %#v", snapshot.Members)
	}
}
