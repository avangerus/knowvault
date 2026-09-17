package postgres_test

import (
	"context"
	"encoding/json"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestR3a1Acc2DegradedRepairIsAudited proves the 12.09 acc2 stale-hash repair
// path is real and audited, not a silent recompute:
//
//  1. a member's read of a workspace whose live metadata diverges from its
//     stored revision hash stays readable with the typed degraded marker and
//     never fails with WORKSPACE_PERSISTENCE_FAILED;
//  2. a member mutation against the same divergent workspace persists a new
//     revision whose stored configuration hash equals the live snapshot hash;
//  3. that repair appends exactly one content-free policy.decision SUCCESS
//     event carrying the organization, workspace and principal ids plus the
//     closed reason code, and no source/model content; the read-path degraded
//     journal keeps its existing one-event behavior;
//  4. a non-member read and a non-member mutation stay denied with no content.
func TestR3a1Acc2DegradedRepairIsAudited(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// A principal of the same organization without any workspace membership.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_outsider', 'org_alpha', 'USER', 'Outsider', 'ACTIVE')`); err != nil {
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

	// Acceptance 1: the member read is readable and typed-degraded, never a
	// persistence failure.
	member := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_r3a1_acc2_repair_read"}
	read, err := workspaceStore.Get(ctx, member, "ws_alpha")
	if err != nil {
		if workspacerepository.CodeOf(err) == workspacerepository.CodePersistence {
			t.Fatalf("member read hard-failed with WORKSPACE_PERSISTENCE_FAILED on a stale configuration hash: %v", err)
		}
		t.Fatalf("member read failed: %v", err)
	}
	if !read.Degraded || read.DegradedReason != workspacerepository.SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("member read marker=%v reason=%q, want the typed degraded indication", read.Degraded, read.DegradedReason)
	}
	if read.Name != "Diverged" {
		t.Fatalf("member read returned name %q, want the readable live metadata", read.Name)
	}
	// The read-path degraded journal keeps its existing one-event behavior.
	var degradedReads int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND workspace_id = 'ws_alpha'
		  AND action = 'policy.decision'
		  AND outcome = 'FAILED'
		  AND error_code = $1`,
		workspacerepository.SummaryDegradedReasonConfigurationHashStale,
	).Scan(&degradedReads); err != nil {
		t.Fatalf("count degraded read journal entries: %v", err)
	}
	if degradedReads != 1 {
		t.Fatalf("degraded read journalled %d policy.decision FAILED events, want exactly one", degradedReads)
	}

	// Acceptance 4: a non-member read of the same workspace stays denied with
	// no content before any repair is attempted.
	outsider := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_outsider", RequestID: "req_r3a1_acc2_outsider_read"}
	if _, err := workspaceStore.Get(ctx, outsider, "ws_alpha"); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("non-member read code = %v, want the documented not-found denial", workspacerepository.CodeOf(err))
	}

	// Acceptance 2: the caller's observable precondition is the recomputed hash
	// of the live snapshot, exactly the value a GET ETag exposes.
	expectedHash, err := workspace.ConfigurationHash(read)
	if err != nil {
		t.Fatalf("hash the live snapshot: %v", err)
	}
	repaired, err := workspaceStore.Update(ctx, member, workspacerepository.UpdateRequest{
		IdempotencyKey: workspaceIdempotencyKey("r3a1-acc2-audited-repair"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: expectedHash, Name: "Repaired", Description: "audited repair", RetentionPolicyID: "",
	})
	if err != nil {
		if workspacerepository.CodeOf(err) == workspacerepository.CodePersistence {
			t.Fatalf("repair mutation hard-failed with WORKSPACE_PERSISTENCE_FAILED on the stale configuration hash: %v", err)
		}
		t.Fatalf("repair mutation failed: %v", err)
	}
	if repaired.Revision != read.Revision+1 {
		t.Fatalf("repaired revision %d, want %d", repaired.Revision, read.Revision+1)
	}
	if repaired.Degraded || repaired.DegradedReason != "" {
		t.Fatalf("repaired snapshot still carries a degraded marker: %+v", repaired)
	}
	liveHash, err := workspace.ConfigurationHash(repaired)
	if err != nil {
		t.Fatalf("hash the repaired snapshot: %v", err)
	}
	var persistedHash string
	if err := admin.QueryRow(ctx, `
		SELECT configuration_hash
		FROM public.workspace_revision
		WHERE organization_id = 'org_alpha' AND workspace_id = 'ws_alpha' AND revision = $1`,
		repaired.Revision,
	).Scan(&persistedHash); err != nil {
		t.Fatalf("read persisted revision hash: %v", err)
	}
	if persistedHash != liveHash {
		t.Fatalf("persisted revision hash %q, want the live configuration hash %q", persistedHash, liveHash)
	}

	// Acceptance 4: a non-member mutation of the same workspace stays denied.
	if _, err := workspaceStore.Update(ctx, outsider, workspacerepository.UpdateRequest{
		IdempotencyKey: workspaceIdempotencyKey("r3a1-acc2-outsider-mutation"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: liveHash, Name: "Outsider", Description: "", RetentionPolicyID: "",
	}); workspacerepository.CodeOf(err) != workspacerepository.CodeDenied {
		t.Fatalf("non-member mutation code = %v, want the documented denial", workspacerepository.CodeOf(err))
	}

	// Acceptance 3: exactly one content-free repair event records the repair.
	var repairCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND workspace_id = 'ws_alpha'
		  AND action = 'policy.decision'
		  AND outcome = 'SUCCESS'
		  AND resource_id = 'ws_alpha'`).Scan(&repairCount); err != nil {
		t.Fatalf("count repair audit events: %v", err)
	}
	if repairCount != 1 {
		t.Fatalf("repair journalled %d policy.decision SUCCESS events, want exactly one", repairCount)
	}

	var organizationID, resourceID string
	var workspaceID, actorID, errorCode *string
	var evidenceJSON, metadataJSON []byte
	if err := admin.QueryRow(ctx, `
		SELECT organization_id, workspace_id, actor_principal_id, resource_id, error_code,
		       referenced_evidence_ids_json, metadata_json
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND workspace_id = 'ws_alpha'
		  AND action = 'policy.decision'
		  AND outcome = 'SUCCESS'
		  AND resource_id = 'ws_alpha'
		ORDER BY sequence DESC
		LIMIT 1`).Scan(&organizationID, &workspaceID, &actorID, &resourceID, &errorCode, &evidenceJSON, &metadataJSON); err != nil {
		t.Fatalf("read the repair audit event: %v", err)
	}
	if organizationID != "org_alpha" || resourceID != "ws_alpha" {
		t.Fatalf("repair event ids organization=%q resource=%q, want org_alpha/ws_alpha", organizationID, resourceID)
	}
	if workspaceID == nil || *workspaceID != "ws_alpha" {
		t.Fatalf("repair event workspace_id=%v, want ws_alpha", workspaceID)
	}
	if actorID == nil || *actorID != "usr_alice" {
		t.Fatalf("repair event actor_principal_id=%v, want the repairing member", actorID)
	}
	if errorCode != nil {
		t.Fatalf("repair event carries error code %q on a successful repair", *errorCode)
	}
	var evidence []string
	if err := json.Unmarshal(evidenceJSON, &evidence); err != nil {
		t.Fatalf("decode repair event evidence ids: %v", err)
	}
	if len(evidence) != 0 {
		t.Fatalf("repair event referenced %d evidence ids, want none", len(evidence))
	}
	var metadata map[string]any
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		t.Fatalf("decode repair event metadata: %v", err)
	}
	if len(metadata) != 1 {
		t.Fatalf("repair event metadata carries %d fields, want only the closed reason code: %v", len(metadata), metadata)
	}
	reasonCodes, ok := metadata["reason_codes"].([]any)
	if !ok || len(reasonCodes) != 1 || reasonCodes[0] != workspacerepository.SummaryDegradedReasonConfigurationHashStale {
		t.Fatalf("repair event reason_codes=%v, want the closed stale-hash code", metadata["reason_codes"])
	}

	// The repaired workspace reads clean afterwards: the live snapshot now
	// hashes to its persisted revision hash.
	after, err := workspaceStore.Get(ctx, member, "ws_alpha")
	if err != nil {
		t.Fatalf("read after repair failed: %v", err)
	}
	if after.Degraded || after.DegradedReason != "" {
		t.Fatalf("workspace still degraded after the audited repair: %+v", after)
	}
}
