package postgres_test

// Real-PostgreSQL regression coverage for ADR-0087 s1 (independent review
// blocker B1, review-opus-s2-4-5.md): before this fix, mutateSource's
// re-enable path (source_commands.go, the ADD branch of an already-bound
// scope) flipped a disabled WORKSPACE_MANAGED binding back to enabled through
// exactScopeTupleExists alone, with no check that a live, unrevoked
// confirmation still covered the exact scope tuple -- unlike :sync and
// Activate, which both call app.source_scope_activation_confirmed
// (internal/source/registration/service.go:893/1020) before proceeding.
//
// Every command here goes through the production repository runtime
// (workspacerepository.Store), never raw SQL for a source-plane or authority
// mutation. Only WORKSPACE_MANAGED is exercised: the existing
// TestWorkspaceSourceRepositoryReenablesAlreadyActivatedScope in
// workspace_source_repository_test.go already covers the SOURCE_ENFORCED
// re-enable path (no confirmation authority at all) the review separately
// confirmed already worked.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	managedReenableOrganization = "org_managed_reenable"
	managedReenableOwner        = "usr_managed_reenable_owner"
	managedReenableWorkspace    = "ws_managed_reenable"
)

// managedReenableBindingID reads the real stable binding id store.AddSource
// derived and persisted, unlike repositoryWorkspaceSourceID
// (workspace_source_repository_test.go), which hardcodes organization_id
// 'org_alpha'.
func managedReenableBindingID(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID string) string {
	t.Helper()
	var bindingID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
		organizationID, workspaceID, confirmationScopeID).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	return bindingID
}

// seedManagedReenableTenant builds a fresh organization, workspace and
// WORKSPACE_MANAGED source-scope draft chain -- but, unlike
// setupAuthorityOpsFixture (workspace_managed_authority_operations_test.go),
// binds no source_scope to the workspace: this test binds it itself through
// the real store.AddSource so the stable binding id is the production
// lineage hash, not a fixture constant, matching what RemoveSource's own
// validation recomputes.
func seedManagedReenableTenant(t *testing.T, ctx context.Context, admin *pgxpool.Pool) (organizationID, ownerID, workspaceID, policyID string) {
	t.Helper()
	seedOrganization(t, ctx, admin, managedReenableOrganization, managedReenableOwner, managedReenableWorkspace)
	insertSourceScopeDraftChain(t, ctx, admin, managedReenableOrganization, managedReenableOwner, managedReenableOrganization, "workspace_managed")
	clock := fetchAuthorityClock(t, ctx, admin)
	policyID = "policy-" + managedReenableOrganization + "-0001"
	insertPolicyRegistryRow(t, ctx, admin, managedReenableOrganization, 1, policyID, authoritySha256(0x70), managedReenableOwner, clock.grantedAt)
	return managedReenableOrganization, managedReenableOwner, managedReenableWorkspace, policyID
}

// TestWorkspaceSourceRepositoryReenableWorkspaceManagedSucceedsWithLiveConfirmation
// proves the recovery half of B1: a WORKSPACE_MANAGED binding that was
// confirmed while enabled, then disabled without the confirmation ever being
// revoked, re-enables immediately -- exactly the demo1-measured defect
// (register -> confirm -> activate -> disable -> re-enable 404) closes
// without forcing an operator to reconfirm on every disable/enable cycle.
func TestWorkspaceSourceRepositoryReenableWorkspaceManagedSucceedsWithLiveConfirmation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	organizationID, ownerID, workspaceID, policyID := seedManagedReenableTenant(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_live"}

	initial, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("read initial workspace: %v", err)
	}
	added, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-live-add"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("bind managed source: %v", err)
	}
	bindingID := managedReenableBindingID(t, ctx, admin, organizationID, workspaceID)

	// Confirm while enabled: confirmBindingCurrent (authority_facts.go)
	// requires the exact current enabled WORKSPACE_MANAGED binding, so this
	// can only happen now, before the disable below.
	grant, err := store.IssueConfirmationGrant(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_live_issue"},
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("managed-reenable-live-issue"), OrganizationID: organizationID,
			WorkspaceID: workspaceID, ExpectedWorkspaceRevision: added.Revision, ExpectedWorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			TargetPrincipalID: ownerID, TTLSeconds: 3600, ExpectedPolicyRevision: policyID,
		})
	if err != nil {
		t.Fatalf("issue confirmation grant: %v", err)
	}
	if _, err := store.ConfirmManagedSource(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_live_confirm"},
		workspacerepository.ConfirmRequest{
			IdempotencyKey: authorityIdempotencyKey("managed-reenable-live-confirm"), OrganizationID: organizationID,
			WorkspaceID: workspaceID, WorkspaceRevision: added.Revision, WorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			WorkspaceSourceID: bindingID, SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
			AccessMode: authorityAccessMode, ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1,
			ConfirmationActorGrantHash: grant.ResultHash, WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
			AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: policyID,
		}); err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	removed, err := store.RemoveSource(ctx, access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-live-remove"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("disable managed source: %v", err)
	}
	assertSingleRepositoryBinding(t, removed, added.Revision+1, false)

	statuses, err := store.ListSources(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("list sources while disabled: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Enabled || !statuses[0].Confirmed {
		t.Fatalf("source status while disabled = %#v, want disabled and still live-confirmed", statuses)
	}

	reenabled, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-live-allow"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: removed.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, removed),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("re-enable with a live confirmation: %v", err)
	}
	assertSingleRepositoryBinding(t, reenabled, removed.Revision+1, true)
}

// TestWorkspaceSourceRepositoryReenableWorkspaceManagedDeniesWithoutConfirmation
// proves the fail-closed half of B1: a WORKSPACE_MANAGED binding that was
// disabled without ever being confirmed cannot be re-enabled, and the denial
// is content-free (CodeDenied, not a distinguishing error).
func TestWorkspaceSourceRepositoryReenableWorkspaceManagedDeniesWithoutConfirmation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	organizationID, ownerID, workspaceID, _ := seedManagedReenableTenant(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_denied"}

	initial, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("read initial workspace: %v", err)
	}
	added, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-denied-add"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("bind managed source: %v", err)
	}
	bindingID := managedReenableBindingID(t, ctx, admin, organizationID, workspaceID)

	// Disabled without ever being confirmed.
	removed, err := store.RemoveSource(ctx, access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-denied-remove"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("disable managed source: %v", err)
	}

	if _, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-denied-attempt"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: removed.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, removed),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	}); workspacerepository.CodeOf(err) != workspacerepository.CodeDenied {
		t.Fatalf("re-enable without any confirmation code = %v, want CodeDenied", err)
	}

	stillDisabled, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("read workspace after denied re-enable: %v", err)
	}
	assertSingleRepositoryBinding(t, stillDisabled, removed.Revision, false)

	statuses, err := store.ListSources(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("list sources after denied re-enable: %v", err)
	}
	if len(statuses) != 1 || statuses[0].Enabled || statuses[0].Confirmed {
		t.Fatalf("source status after denied re-enable = %#v, want disabled and unconfirmed", statuses)
	}
}

// TestWorkspaceSourceRepositoryReenableWorkspaceManagedDeniesWhenActorGrantRevoked
// proves review-opus-s2-6-7.md blocker B1': managedReenableConfirmationLive
// (source_commands.go) must treat a confirmation whose confirmation-actor
// grant has since been revoked exactly as a revoked confirmation itself --
// the same NOT EXISTS ... workspace_source_confirmation_actor_grant_revocation
// clause app.source_scope_activation_confirmed already carries
// (db/migrations/000018_stage2_scope_activation_confirmed.sql:513-528).
// Before the fix, revoking only the actor grant behind the sole confirmation
// on file for a disabled scope left re-enable wrongly succeeding, because the
// predicate checked confirmation-revocation (workspace_managed_grant_
// revocation) but not grant-revocation.
//
// The success half of the same round trip -- re-enable succeeding with a
// live, unrevoked grant -- is already covered by
// TestWorkspaceSourceRepositoryReenableWorkspaceManagedSucceedsWithLiveConfirmation
// above and is asserted here not to have regressed: this test's own grant
// stays live throughout its own first confirm/disable/re-enable cycle before
// the grant is revoked, so the same fixed predicate is exercised on both its
// true and false branches within one run.
func TestWorkspaceSourceRepositoryReenableWorkspaceManagedDeniesWhenActorGrantRevoked(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	organizationID, ownerID, workspaceID, policyID := seedManagedReenableTenant(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_grantrevoked"}

	initial, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("read initial workspace: %v", err)
	}
	added, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-grantrevoked-add"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("bind managed source: %v", err)
	}
	bindingID := managedReenableBindingID(t, ctx, admin, organizationID, workspaceID)

	grant, err := store.IssueConfirmationGrant(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_grantrevoked_issue"},
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("managed-reenable-grantrevoked-issue"), OrganizationID: organizationID,
			WorkspaceID: workspaceID, ExpectedWorkspaceRevision: added.Revision, ExpectedWorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			TargetPrincipalID: ownerID, TTLSeconds: 3600, ExpectedPolicyRevision: policyID,
		})
	if err != nil {
		t.Fatalf("issue confirmation grant: %v", err)
	}
	if _, err := store.ConfirmManagedSource(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_grantrevoked_confirm"},
		workspacerepository.ConfirmRequest{
			IdempotencyKey: authorityIdempotencyKey("managed-reenable-grantrevoked-confirm"), OrganizationID: organizationID,
			WorkspaceID: workspaceID, WorkspaceRevision: added.Revision, WorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			WorkspaceSourceID: bindingID, SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
			AccessMode: authorityAccessMode, ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1,
			ConfirmationActorGrantHash: grant.ResultHash, WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
			AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: policyID,
		}); err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	removed, err := store.RemoveSource(ctx, access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-grantrevoked-remove"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("disable managed source: %v", err)
	}

	// While disabled, the confirmation's own actor grant is still live and
	// unrevoked: the read side must still report it as confirmed, exactly as
	// TestWorkspaceSourceRepositoryReenableWorkspaceManagedSucceedsWithLiveConfirmation
	// asserts for its own equivalent state.
	beforeRevoke, err := store.ListSources(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("list sources before grant revocation: %v", err)
	}
	if len(beforeRevoke) != 1 || beforeRevoke[0].Enabled || !beforeRevoke[0].Confirmed {
		t.Fatalf("source status before grant revocation = %#v, want disabled and still live-confirmed", beforeRevoke)
	}

	if _, err := store.RevokeConfirmationGrant(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_managed_reenable_grantrevoked_revoke"},
		workspacerepository.RevokeGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("managed-reenable-grantrevoked-revoke"), OrganizationID: organizationID,
			WorkspaceID: workspaceID, GrantID: grant.ResultID, GrantRevision: 1, GrantHash: grant.ResultHash,
			ExpectedPolicyRevision: policyID,
		}); err != nil {
		t.Fatalf("revoke confirmation-actor grant: %v", err)
	}

	// The confirmation-actor grant behind the sole confirmation on file is now
	// revoked. Before the B1' fix, managedReenableConfirmationLive ignored
	// grant revocation entirely and this re-enable wrongly succeeded.
	if _, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("managed-reenable-grantrevoked-attempt"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: removed.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, removed),
		SourceScopeID: confirmationScopeID, SourceScopeRevision: 1, ScopeConfigHash: confirmationScopeHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	}); workspacerepository.CodeOf(err) != workspacerepository.CodeDenied {
		t.Fatalf("re-enable with a revoked actor grant code = %v, want CodeDenied", err)
	}

	stillDisabled, err := store.Get(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("read workspace after denied re-enable: %v", err)
	}
	assertSingleRepositoryBinding(t, stillDisabled, removed.Revision, false)

	afterRevoke, err := store.ListSources(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("list sources after grant revocation: %v", err)
	}
	if len(afterRevoke) != 1 || afterRevoke[0].Enabled || afterRevoke[0].Confirmed {
		t.Fatalf("source status after grant revocation = %#v, want disabled and no longer live-confirmed", afterRevoke)
	}
}
