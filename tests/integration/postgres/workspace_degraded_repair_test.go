package postgres_test

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestWorkspaceGetAndUpdateRepairAStaleConfigurationHash proves the 12.09 acc2
// guard's repair path against real PostgreSQL: a member's read of a workspace
// whose live metadata no longer hashes to its stored revision hash must not
// hard-fail with WORKSPACE_PERSISTENCE_FAILED, and an ordinary mutation must be
// able to persist a corrected configuration hash on the same condition.
//
// The negative controls stay intact: a non-member read is still the documented
// not-found denial with no content, and the degraded Get journals exactly one
// content-free policy.decision FAILED event carrying the closed reason code.
func TestWorkspaceGetAndUpdateRepairAStaleConfigurationHash(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// A principal of the same organization without any workspace membership.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_mallory', 'org_alpha', 'USER', 'Mallory', 'ACTIVE')`); err != nil {
		t.Fatalf("seed non-member principal: %v", err)
	}
	// Advance the live metadata without moving the revision pointer: the live
	// snapshot then hashes to something other than revision one's stored hash.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace SET name = 'Diverged'
		WHERE organization_id = 'org_alpha' AND id = 'ws_alpha'`); err != nil {
		t.Fatalf("diverge live workspace metadata: %v", err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open bounded application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}

	member := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_degraded_repair"}
	read, err := workspaceStore.Get(ctx, member, "ws_alpha")
	if err != nil {
		t.Fatalf("member Get hard-failed on a stale configuration hash: %v", err)
	}
	if !read.Degraded || read.DegradedReason != workspacerepository.SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("member Get marker=%v reason=%q, want the typed degraded indication", read.Degraded, read.DegradedReason)
	}
	if read.Name != "Diverged" {
		t.Fatalf("member Get returned name %q, want the readable live metadata", read.Name)
	}

	var journalled int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND action = 'policy.decision'
		  AND outcome = 'FAILED'
		  AND error_code = $1
		  AND resource_id = 'ws_alpha'`,
		workspacerepository.SummaryDegradedReasonConfigurationHashStale,
	).Scan(&journalled); err != nil {
		t.Fatalf("read degraded repair journal entry: %v", err)
	}
	if journalled != 1 {
		t.Fatalf("degraded Get journalled %d events, want exactly one content-free event", journalled)
	}

	nonMember := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_mallory", RequestID: "req_degraded_non_member"}
	if _, deniedErr := workspaceStore.Get(ctx, nonMember, "ws_alpha"); workspacerepository.CodeOf(deniedErr) != workspacerepository.CodeNotFound {
		t.Fatalf("non-member Get code = %v, want the documented not-found denial", workspacerepository.CodeOf(deniedErr))
	}

	// The caller's observable precondition is the recomputed hash of the live
	// snapshot, exactly the value a GET ETag exposes.
	expectedHash := mustWorkspaceHash(t, read)
	repaired, err := workspaceStore.Update(ctx, member, workspacerepository.UpdateRequest{
		IdempotencyKey: workspaceIdempotencyKey("repair-stale-workspace"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: expectedHash, Name: "Repaired", Description: "repair path", RetentionPolicyID: "",
	})
	if err != nil {
		t.Fatalf("repair Update hard-failed on the stale configuration hash: %v", err)
	}
	if repaired.Degraded || repaired.DegradedReason != "" {
		t.Fatalf("repaired snapshot still carries a degraded marker: %+v", repaired)
	}
	repairedHash := mustWorkspaceHash(t, repaired)
	var persistedHash string
	if err := admin.QueryRow(ctx, `
		SELECT configuration_hash
		FROM public.workspace_revision
		WHERE organization_id = 'org_alpha' AND workspace_id = 'ws_alpha' AND revision = $1`,
		repaired.Revision,
	).Scan(&persistedHash); err != nil {
		t.Fatalf("read persisted revision hash: %v", err)
	}
	if persistedHash != repairedHash {
		t.Fatalf("persisted hash %q, want the configuration hash of the repaired snapshot %q", persistedHash, repairedHash)
	}

	var success int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND action = 'workspace.updated'
		  AND outcome = 'SUCCESS'
		  AND resource_id = 'ws_alpha'`).Scan(&success); err != nil {
		t.Fatalf("read repair success journal entry: %v", err)
	}
	if success != 1 {
		t.Fatalf("repair journalled %d workspace.updated success events, want exactly one", success)
	}

	after, err := workspaceStore.Get(ctx, member, "ws_alpha")
	if err != nil {
		t.Fatalf("Get after repair failed: %v", err)
	}
	if after.Degraded || after.DegradedReason != "" {
		t.Fatalf("workspace still degraded after the repair mutation: %+v", after)
	}
	if after.Revision != repaired.Revision {
		t.Fatalf("post-repair revision %d, want %d", after.Revision, repaired.Revision)
	}
}
