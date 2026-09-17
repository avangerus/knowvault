package postgres_test

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestWorkspaceSnapshotProjectsCurrentSameOrganizationMemberDisplayNames
// proves the member snapshot joins current principal metadata in one
// repository read, keeps idempotent mutation responses populated, and does
// not let a principal rename change the immutable workspace configuration
// hash.
func TestWorkspaceSnapshotProjectsCurrentSameOrganizationMemberDisplayNames(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")
	mustAddPrincipal(t, ctx, admin, "usr_bob", "org_alpha", "USER", "Bob Builder", "ACTIVE")
	mustAddPrincipal(t, ctx, admin, "usr_zara", "org_beta", "USER", "Zara Beta", "ACTIVE")

	store := newWorkspaceSourceRepository(t, ctx)
	owner := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_member_display_name"}
	initial, err := store.Get(ctx, owner, "ws_alpha")
	if err != nil {
		t.Fatalf("get initial snapshot: %v", err)
	}
	if len(initial.Members) != 1 || initial.Members[0].DisplayName != "usr_alice" {
		t.Fatalf("initial members=%#v, want only same-organization owner display name", initial.Members)
	}

	added, err := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("member-display-name"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		PrincipalID:               "usr_bob",
		Role:                      workspace.RoleMember,
	})
	if err != nil {
		t.Fatalf("add member: %v", err)
	}
	if member := memberByPrincipal(added, "usr_bob"); member == nil || member.DisplayName != "Bob Builder" {
		t.Fatalf("added members=%#v, want Bob Builder projection", added.Members)
	}

	replayed, err := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("member-display-name"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		PrincipalID:               "usr_bob",
		Role:                      workspace.RoleMember,
	})
	if err != nil {
		t.Fatalf("replay add member: %v", err)
	}
	if member := memberByPrincipal(replayed, "usr_bob"); member == nil || member.DisplayName != "Bob Builder" {
		t.Fatalf("replayed members=%#v, want Bob Builder projection", replayed.Members)
	}

	if _, err := admin.Exec(ctx, `
		UPDATE public.principal
		SET display_name = 'Bobby Builder'
		WHERE organization_id = 'org_alpha' AND id = 'usr_bob'
	`); err != nil {
		t.Fatalf("rename principal: %v", err)
	}
	renamed, err := store.Get(ctx, owner, "ws_alpha")
	if err != nil {
		t.Fatalf("get renamed snapshot: %v", err)
	}
	if member := memberByPrincipal(renamed, "usr_bob"); member == nil || member.DisplayName != "Bobby Builder" {
		t.Fatalf("renamed members=%#v, want current display name", renamed.Members)
	}
	if mustWorkspaceHash(t, renamed) != mustWorkspaceHash(t, added) {
		t.Fatal("principal display-name change changed workspace configuration hash")
	}

	removed, err := store.RemoveMember(ctx, owner, workspacerepository.RemoveMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("member-display-name-remove"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, renamed),
		PrincipalID:               "usr_bob",
	})
	if err != nil {
		t.Fatalf("remove member: %v", err)
	}
	if memberByPrincipal(removed, "usr_bob") != nil {
		t.Fatalf("removed members=%#v, want Bob absent", removed.Members)
	}

	replayedAfterRemoval, err := store.AddMember(ctx, owner, workspacerepository.AddMemberRequest{
		IdempotencyKey:            workspaceIdempotencyKey("member-display-name"),
		WorkspaceID:               "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		PrincipalID:               "usr_bob",
		Role:                      workspace.RoleMember,
	})
	if err != nil {
		t.Fatalf("replay add member after removal: %v", err)
	}
	if member := memberByPrincipal(replayedAfterRemoval, "usr_bob"); member == nil || member.DisplayName != "Bobby Builder" {
		t.Fatalf("historical replay members=%#v, want current Bobby Builder projection", replayedAfterRemoval.Members)
	}
}

func memberByPrincipal(snapshot workspace.Snapshot, principalID string) *workspace.Member {
	for index := range snapshot.Members {
		if snapshot.Members[index].PrincipalID == principalID {
			return &snapshot.Members[index]
		}
	}
	return nil
}
