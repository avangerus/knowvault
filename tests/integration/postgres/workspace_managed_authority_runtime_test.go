package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// End-to-end coverage of the checkpoint-0055 Go runtime: the four ADR-0053
// operations driven through the production repository (not raw SQL) against real
// PostgreSQL 18.4. These prove the whole command transaction — decision phase,
// receipt reservation, canonical result, atomic audit, terminalization, replay,
// idempotency conflict and the tenant fence — behaves exactly as the migration
// gates require, with the runtime role.

func newAuthorityRuntime(t *testing.T, ctx context.Context) *workspacerepository.Store {
	t.Helper()
	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("open application store: %v", err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	store, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	return store
}

func authorityIdempotencyKey(label string) string {
	digest := sha256.Sum256([]byte("authority-runtime-idempotency\x00" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func authorityAccess(fixture authorityOpsFixture, principalID, request string) database.AccessContext {
	return database.AccessContext{OrganizationID: fixture.organizationID, PrincipalID: principalID, RequestID: request}
}

func issueRuntimeGrant(t *testing.T, ctx context.Context, store *workspacerepository.Store, fixture authorityOpsFixture, label string) workspacerepository.AuthorityResult {
	t.Helper()
	result, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_"+label),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if err != nil {
		t.Fatalf("issue grant: %v", err)
	}
	return result
}

func confirmRuntimeRequest(fixture authorityOpsFixture, grant workspacerepository.AuthorityResult, label string) workspacerepository.ConfirmRequest {
	return workspacerepository.ConfirmRequest{
		IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
		WorkspaceID: fixture.workspaceID, WorkspaceRevision: fixture.workspaceRevision,
		WorkspaceConfigurationHash: fixture.workspaceConfHash, WorkspaceSourceID: fixture.workspaceSourceID,
		SourceScopeID: fixture.sourceScopeID, SourceScopeRevision: fixture.sourceScopeRevision,
		ScopeConfigHash: fixture.scopeConfigHash, AccessMode: authorityAccessMode,
		ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1, ConfirmationActorGrantHash: grant.ResultHash,
		WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
		AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: fixture.policyID,
	}
}

func TestAuthorityRuntimeAllFourOperationsEndToEnd(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "e2e-issue")
	if grant.ResultID == "" || grant.ResultHash == "" || grant.Operation != "WORKSPACE_CONFIRMATION_GRANT_ISSUE" {
		t.Fatalf("grant result = %#v", grant)
	}

	confirmation, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_e2e_confirm"),
		confirmRuntimeRequest(fixture, grant, "e2e-confirm"))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}

	if _, err := store.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_e2e_confirm_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("e2e-confirm-revoke"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ConfirmationID: confirmation.ResultID, ConfirmationHash: confirmation.ResultHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke confirmation: %v", err)
	}

	if _, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_e2e_grant_revoke"),
		workspacerepository.RevokeGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("e2e-grant-revoke"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, GrantID: grant.ResultID, GrantRevision: 1, GrantHash: grant.ResultHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke grant: %v", err)
	}

	for relation, want := range map[string]int64{
		"workspace_source_confirmation_actor_grant":            1,
		"workspace_managed_grant_confirmation":                 1,
		"workspace_managed_grant_revocation":                   1,
		"workspace_source_confirmation_actor_grant_revocation": 1,
	} {
		if got := countAuthorityRows(t, ctx, admin, relation); got != want {
			t.Fatalf("%s holds %d rows, want %d", relation, got, want)
		}
	}

	// Every one of the four commands is a terminal SUCCESS receipt bound to its
	// own audit event, whose resource ID is the command ID.
	var bound int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*)
		FROM public.workspace_managed_authority_command_receipt AS receipt
		JOIN public.audit_event AS event
		  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
		WHERE receipt.organization_id = $1 AND receipt.status = 'SUCCESS'
		  AND event.resource_id = receipt.command_id AND event.resource_type = 'WORKSPACE_AUTHORITY_COMMAND'
		  AND event.outcome = 'SUCCESS' AND event.error_code IS NULL
		  AND event.metadata_json ->> 'authority_operation' = receipt.operation
	`, fixture.organizationID).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if bound != 4 {
		t.Fatalf("%d of the four commands are receipt-to-audit bound, want 4", bound)
	}
}

func TestAuthorityRuntimeReplayReturnsStoredResult(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	first := issueRuntimeGrant(t, ctx, store, fixture, "replay")
	second := issueRuntimeGrant(t, ctx, store, fixture, "replay")
	if first.ResultID != second.ResultID || first.ResultHash != second.ResultHash || first.CommandID != second.CommandID {
		t.Fatalf("replay returned a different result: %#v vs %#v", first, second)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 1 {
		t.Fatalf("replay created %d grants, want 1", got)
	}
	// Replay creates no second audit event.
	var events int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = $1 AND resource_type = 'WORKSPACE_AUTHORITY_COMMAND'`, fixture.organizationID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("replay produced %d authority audit events, want 1", events)
	}
}

func TestAuthorityRuntimeIdempotencyConflictCreatesNothing(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	if _, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_conflict_a"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("conflict"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	// Same key, different TTL -> different request hash -> conflict.
	_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_conflict_b"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("conflict"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 7200, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityIdempotencyConflict {
		t.Fatalf("conflict code = %q, want WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 1 {
		t.Fatalf("conflict created a second grant: %d", got)
	}
}

func TestAuthorityRuntimeTenantMismatchIsNotFound(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_cross_tenant"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("cross-tenant"), OrganizationID: "org_somewhere_else",
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
		t.Fatalf("tenant mismatch code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 0 {
		t.Fatalf("cross-tenant reference created %d grants, want 0", got)
	}
	// The NOT_FOUND receipt exists in the trusted tenant, and its audit event
	// names no workspace.
	var workspaceID *string
	if err := admin.QueryRow(ctx, `
		SELECT event.workspace_id
		FROM public.workspace_managed_authority_command_receipt AS receipt
		JOIN public.audit_event AS event
		  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
		WHERE receipt.organization_id = $1 AND receipt.status = 'NOT_FOUND'
	`, fixture.organizationID).Scan(&workspaceID); err != nil {
		t.Fatalf("load NOT_FOUND receipt: %v", err)
	}
	if workspaceID != nil {
		t.Fatal("a NOT_FOUND authority audit event leaked a workspace id")
	}
}

func TestAuthorityRuntimeStalePreconditionFails(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_stale"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("stale"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision + 1,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityPreconditionFailed {
		t.Fatalf("stale revision code = %q, want WORKSPACE_AUTHORITY_PRECONDITION_FAILED", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 0 {
		t.Fatalf("stale precondition created %d grants, want 0", got)
	}
}

func TestAuthorityRuntimeDeniedForNonAdmin(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	// A workspace member with no organization role can see the workspace but may
	// not issue a grant: visible, unauthorized -> DENIED.
	member := "usr_authority_plain_member"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, member)
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1, $2, $3, $4, 'MEMBER', 1, $5)
	`, "wsm_plain_member", fixture.organizationID, fixture.workspaceID, member, fixture.ownerID); err != nil {
		t.Fatalf("seed plain member: %v", err)
	}

	_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, member, "req_denied"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("denied"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityDenied {
		t.Fatalf("non-admin issue code = %q, want WORKSPACE_AUTHORITY_DENIED", workspacerepository.CodeOf(err))
	}
	// A DENIED command still binds one receipt and one audit event, but no grant.
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 0 {
		t.Fatalf("denied command created %d grants, want 0", got)
	}
	var outcome, errorCode string
	if err := admin.QueryRow(ctx, `
		SELECT event.outcome, event.error_code
		FROM public.workspace_managed_authority_command_receipt AS receipt
		JOIN public.audit_event AS event
		  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
		WHERE receipt.organization_id = $1 AND receipt.actor_principal_id = $2
	`, fixture.organizationID, member).Scan(&outcome, &errorCode); err != nil {
		t.Fatalf("load denied receipt: %v", err)
	}
	if outcome != "DENIED" || errorCode != "WORKSPACE_AUTHORITY_DENIED" {
		t.Fatalf("denied audit = (%s, %s), want DENIED/WORKSPACE_AUTHORITY_DENIED", outcome, errorCode)
	}
}

func TestAuthorityRuntimeConcurrentSameKeyCommitsExactlyOneGrant(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	const workers = 6
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	results := make(chan workspacerepository.AuthorityResult, workers)
	errors := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			result, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_race_"+authorityID("w", index)),
				workspacerepository.IssueGrantRequest{
					IdempotencyKey: authorityIdempotencyKey("race"), OrganizationID: fixture.organizationID,
					WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
					ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
					TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
				})
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(results)
	close(errors)

	for err := range errors {
		t.Fatalf("a concurrent issue failed: %v", err)
	}
	var canonical string
	count := 0
	for result := range results {
		count++
		if canonical == "" {
			canonical = result.ResultID
		} else if result.ResultID != canonical {
			t.Fatalf("concurrent issues returned different grants: %s vs %s", canonical, result.ResultID)
		}
	}
	if count != workers {
		t.Fatalf("only %d of %d workers returned a result", count, workers)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 1 {
		t.Fatalf("the idempotency race committed %d grants, want exactly 1", got)
	}
}

func TestAuthorityRuntimeConfirmWarningDriftIsPreconditionFailed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "warn-drift-issue")
	request := confirmRuntimeRequest(fixture, grant, "warn-drift-confirm")
	// A warning contract hash that is a well-formed hash but not the registry
	// head is a stale precondition, not a request-shape error.
	request.WarningContractHash = authoritySha256('x')
	_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_warn_drift"), request)
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityPreconditionFailed {
		t.Fatalf("warning drift code = %q, want WORKSPACE_AUTHORITY_PRECONDITION_FAILED", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"); got != 0 {
		t.Fatalf("warning drift created %d confirmations, want 0", got)
	}
}

func TestAuthorityRuntimeGrantRevokeStaleHashIsPreconditionFailed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "stale-hash-issue")
	// The grant exists at (id, revision) but the supplied hash is stale.
	_, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_stale_hash"),
		workspacerepository.RevokeGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("stale-hash-revoke"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, GrantID: grant.ResultID, GrantRevision: 1, GrantHash: authoritySha256('y'),
			ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityPreconditionFailed {
		t.Fatalf("stale grant hash code = %q, want WORKSPACE_AUTHORITY_PRECONDITION_FAILED", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant_revocation"); got != 0 {
		t.Fatalf("stale grant hash created %d revocations, want 0", got)
	}
}

func TestAuthorityRuntimeMissingGrantRevokeParentIsNotFound(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	_, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_missing_parent"),
		workspacerepository.RevokeGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("missing-parent"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, GrantID: "grant_never_existed", GrantRevision: 1, GrantHash: authoritySha256('z'),
			ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
		t.Fatalf("missing parent code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", workspacerepository.CodeOf(err))
	}
}
