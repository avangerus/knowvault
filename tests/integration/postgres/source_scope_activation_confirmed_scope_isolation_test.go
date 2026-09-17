package postgres_test

// Real-PostgreSQL regression coverage for the FIN-1 demo-readiness defect
// ("confirmation reset"): app.source_scope_activation_confirmed (migration
// 000018, fixed by 000076) must stay true for a WORKSPACE_MANAGED source
// scope whose own binding tuple has not changed, even though an unrelated
// workspace configuration mutation (here: disabling a *different* source
// bound to the same workspace) advances workspace.current_revision -- and
// must still go false the instant the mutation touches THIS scope's own
// binding (its own enabled flag, revision or config hash).
//
// Before 000076, the predicate additionally required the confirmation's own
// recorded workspace_revision to equal workspace.current_revision and the
// joined workspace_revision_source binding to sit at that same historical
// revision. Because workspace_revision_source is a full copy-forward
// snapshot -- every revision bump carries every existing binding forward as a
// fresh row, changed or not (000008's exact-set guard) -- ANY workspace
// configuration mutation stopped every confirmation in the workspace from
// matching the instant the revision counter advanced, not only the
// confirmation of the source that actually changed. Operator symptom: enable
// or disable one source, or issue an access code, and every other source's
// confirmation is lost at once (Activate/:sync fail-closed, answers stop
// citing evidence). 000076 re-keys the binding join to the workspace's
// CURRENT revision instead of the confirmation's own recorded revision, so an
// untouched scope's confirmation survives revision bumps caused by other
// scopes while a scope whose own tuple changed still requires reconfirmation.
//
// This test calls app.source_scope_activation_confirmed directly (the exact
// function Activate, :sync and the read-side confirmation_state all consult
// -- internal/source/registration/service.go, internal/workspace/repository/
// source_status.go), not a test-local reimplementation, so it fails on the
// pre-000076 predicate and passes only with the fix. Confirmations
// themselves are produced by the production repository authority-command
// runtime (IssueConfirmationGrant / ConfirmManagedSource), never raw INSERT
// forgery; only the disabling mutation goes through the production
// workspace-source command (store.RemoveSource) to produce a real revision
// advance exactly as an operator's "Disable" click would.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	scopeIsolationOrganization = "org_scope_isolation"
	scopeIsolationOwner        = "usr_scope_isolation_owner"
	scopeIsolationWorkspace    = "ws_scope_isolation"

	// Scope A reuses the shared draft-chain convention (suffix == organization
	// ID) that seedManagedReenableTenant and setupAuthorityOpsTenant both use,
	// so its scope ID/hash are the shared confirmationScopeID/confirmationScopeHash
	// constants (workspace_managed_confirmation_authority_test.go).
	scopeIsolationSecondSuffix      = "org_scope_isolation_b"
	scopeIsolationSecondScopeID     = "scope_01ARZ3NDEKTSV4RRFFQ69G5FBV"
	scopeIsolationSecondDiscoveryID = "discovered_01ARZ3NDEKTSV4RRFFQ69G5FBV"
)

// insertSecondConnectionDraftChainInTx is insertSourceDraftChainInTx
// (source_connection_draft_test.go), copied rather than called a second time
// in the same organization: that helper hardcodes its one encrypted_artifact
// row's nonce ('6e' repeated) regardless of suffix, which every existing
// caller gets away with because no existing fixture binds two connections
// into the same organization. Scope isolation needs exactly that, so this
// copy changes only the nonce ('7e') to keep
// encrypted_artifact_organization_id_kek_reference_kek_version_key
// (organization_id, kek_reference, kek_version, nonce) satisfied for a
// second connection in scope A's own organization. No fault branches: this
// test only ever calls it with the one, successful shape.
func insertSecondConnectionDraftChainInTx(ctx context.Context, tx pgx.Tx, organizationID, ownerID, suffix string) error {
	profileID := "cap_" + suffix
	connectionID := "conn_" + suffix
	artifactID := "artifact_trust_" + suffix
	trustRecordID := "trust_" + suffix
	buildID := "folder-build-" + suffix
	credentialReference := testCredentialRef
	executionTarget := "CENTRAL_WORKER"
	var revisionAgentID, trustAgentID any
	activeRevision := any(nil)
	allowedAccessModes := `["WORKSPACE_MANAGED","SOURCE_ENFORCED"]`

	profileHash := "sha256:" + strings.Repeat("a", 64)
	artifactHash := "sha256:" + strings.Repeat("b", 64)
	suiteHash := "sha256:" + strings.Repeat("c", 64)
	trustHash := "sha256:" + strings.Repeat("d", 64)
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (
			id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash,
			stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links,
			deletion_events, local_extraction, contract_suite_hash, verified_at
		) VALUES (
			$1, $2, $3, 'FOLDER', '1.0.0', $4,
			true, true, true, false, true, true, true, true, true, true,
			$5, transaction_timestamp()
		)
	`, profileID, profileHash, buildID, artifactHash, suiteHash); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection (
			organization_id, id, type, name, latest_revision,
			active_revision, status, created_by
		) VALUES ($1, $2, 'FOLDER', $2, 1, $3, 'DRAFT', $4)
	`, organizationID, connectionID, activeRevision, ownerID); err != nil {
		return err
	}
	var resourceID string
	if err := tx.QueryRow(ctx, `
		SELECT app.source_connection_revision_resource_id($1, $2, 1)
	`, organizationID, connectionID).Scan(&resourceID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type,
			resource_id, field_name, ciphertext, size_bytes, nonce,
			wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
			aad_hash, plaintext_hash
		) VALUES (
			$1, $2, 'source_connection_revision', 'trust_profile_artifact_id',
			'SOURCE_TRUST_CONFIG', $3, 'TRUST_CONFIG',
			decode(repeat('ab', 17), 'hex'), 1, decode(repeat('7e', 12), 'hex'),
			decode('77726170706564', 'hex'), $4, 'kms://tenant', 1, $5, $6
		)
	`, organizationID, artifactID, resourceID, artifactHash, suiteHash, trustHash); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_revision (
			organization_id, connection_id, revision, credential_reference,
			connector_build_id, connector_type,
			capability_profile_id, capability_profile_hash,
			connector_agent_id, execution_target, trust_record_id,
			trust_profile_artifact_id, trust_profile_hash,
			connector_version, connector_artifact_hash,
			connector_contract_suite_hash, connector_verified_at,
			allowed_access_modes_json, max_scope_objects, max_scope_bytes,
			max_object_bytes, created_by
		) VALUES (
			$1, $2, 1, $3, $4, 'FOLDER', $5, $6, $7, $8, $9,
			$10, $11, '1.0.0', $12, $13, transaction_timestamp(),
			$15::jsonb,
			1000, 1000000, 100000, $14
		)
	`, organizationID, connectionID, credentialReference, buildID,
		profileID, profileHash, revisionAgentID, executionTarget, trustRecordID,
		artifactID, trustHash, artifactHash, suiteHash, ownerID, allowedAccessModes); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_record (
			organization_id, id, connection_id, connection_revision,
			connector_agent_id, execution_target, trust_profile_artifact_id,
			trust_profile_hash, verified_at, expires_at
		) VALUES (
			$1, $2, $3, 1, $4, $5, $6, $7,
			transaction_timestamp(), transaction_timestamp() + interval '1 day'
		)
	`, organizationID, trustRecordID, connectionID, trustAgentID,
		executionTarget, artifactID, trustHash); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_projection (
			organization_id, trust_record_id, revision, status
		) VALUES ($1, $2, 1, 'DRAFT')
	`, organizationID, trustRecordID)
	return err
}

// insertSecondSourceScopeDraftChain builds a second WORKSPACE_MANAGED source
// scope (its own connection, discovery and scope-revision draft chain) in the
// same organization as insertSourceScopeDraftChain's scope A, at a distinct
// scope ID/discovery ID/connection so both can be bound into the same
// workspace simultaneously. It mirrors insertSourceScopeDraftChainInTx
// (source_scope_draft_test.go) with the "workspace_managed" fault branch,
// parameterized instead of hardcoded, because that helper always names the
// same literal scope ID regardless of suffix.
func insertSecondSourceScopeDraftChain(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID string) string {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertSecondConnectionDraftChainInTx(ctx, tx, organizationID, ownerID, scopeIsolationSecondSuffix); err != nil {
		t.Fatalf("insert second connection draft chain: %v", err)
	}
	connectionID := "conn_" + scopeIsolationSecondSuffix
	scopeID := scopeIsolationSecondScopeID
	discoveryID := scopeIsolationSecondDiscoveryID
	identityArtifactID := "artifact_identity_" + scopeIsolationSecondSuffix
	displayArtifactID := "artifact_display_" + scopeIsolationSecondSuffix
	configArtifactID := "artifact_scope_config_" + scopeIsolationSecondSuffix
	identityDigest := "hmac-sha256:k1:" + strings.Repeat("1", 64)
	identityHash := "sha256:" + strings.Repeat("4", 64)
	displayHash := "sha256:" + strings.Repeat("5", 64)
	configHash := "sha256:" + strings.Repeat("7", 64)

	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1, $2, 1)`, organizationID, scopeID).Scan(&scopeResourceID); err != nil {
		t.Fatalf("derive second scope resource id: %v", err)
	}
	for _, artifact := range []struct {
		id, ownerTable, ownerColumn, resourceType, resourceID, field, hash, nonce string
	}{
		{identityArtifactID, "source_discovered_scope", "identity_artifact_id", "SOURCE_SCOPE_IDENTITY", discoveryID, "EXTERNAL_SCOPE_IDENTITY", identityHash, "41"},
		{displayArtifactID, "source_discovered_scope", "display_metadata_artifact_id", "SOURCE_SCOPE_METADATA", discoveryID, "DISPLAY_METADATA", displayHash, "42"},
		{configArtifactID, "source_scope_revision", "scope_config_artifact_id", "SOURCE_SCOPE_CONFIG", scopeResourceID, "SCOPE_CONFIG", configHash, "43"},
	} {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.encrypted_artifact (
				organization_id, id, owner_table, owner_column, resource_type,
				resource_id, field_name, ciphertext, size_bytes, nonce,
				wrapped_dek, wrapped_dek_hash, kek_reference, kek_version,
				aad_hash, plaintext_hash
			) VALUES (
				$1, $2, $3, $4, $5, $6, $7,
				decode(repeat('ab', 17), 'hex'), 1, decode(repeat($8, 12), 'hex'),
				decode('77726170706564', 'hex'), $9, 'kms://tenant', 1, $10, $11
			)
		`, organizationID, artifact.id, artifact.ownerTable, artifact.ownerColumn,
			artifact.resourceType, artifact.resourceID, artifact.field, artifact.nonce,
			"sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("9", 64), artifact.hash); err != nil {
			t.Fatalf("insert second scope artifact %s: %v", artifact.id, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_discovered_scope (
			organization_id, id, connection_id, connection_revision, source_type,
			identity_digest, identity_digest_key_version,
			identity_artifact_id, identity_plaintext_hash,
			display_metadata_artifact_id, display_metadata_hash
		) VALUES ($1, $2, $3, 1, 'FOLDER', $4, 1, $5, $6, $7, $8)
	`, organizationID, discoveryID, connectionID, identityDigest, identityArtifactID,
		identityHash, displayArtifactID, displayHash); err != nil {
		t.Fatalf("insert second discovered scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope (
			organization_id, id, connection_id, discovered_scope_id,
			source_type, latest_revision, created_by
		) VALUES ($1, $2, $3, $4, 'FOLDER', 1, $5)
	`, organizationID, scopeID, connectionID, discoveryID, ownerID); err != nil {
		t.Fatalf("insert second source scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_revision (
			organization_id, source_scope_id, revision,
			connection_id, connection_revision, discovered_scope_id,
			discovered_identity_digest, discovered_identity_digest_key_version,
			source_type, scope_config_artifact_id, scope_config_hash,
			scope_contract_version, access_mode, sync_interval_seconds,
			content_freshness_sla_seconds, acl_freshness_sla_seconds,
			object_limit, byte_limit, max_object_bytes, created_by
		) VALUES (
			$1, $2, 1, $3, 1, $4, $5, 1, 'FOLDER', $6, $7,
			'1.2', 'WORKSPACE_MANAGED', 300, 600, 300, $8, $9, $10, $11
		)
	`, organizationID, scopeID, connectionID, discoveryID, identityDigest,
		configArtifactID, configHash, int64(500), int64(500000), int64(100000), ownerID); err != nil {
		t.Fatalf("insert second scope revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_activation (
			organization_id, source_scope_id, source_scope_revision, revision, status
		) VALUES ($1, $2, 1, 1, 'DRAFT')
	`, organizationID, scopeID); err != nil {
		t.Fatalf("insert second scope activation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit second source scope draft chain: %v", err)
	}
	return configHash
}

// scopeIsolationBindingID reads the real stable binding id store.AddSource
// derived and persisted for a given source scope, exactly like
// managedReenableBindingID (workspace_managed_source_reenable_test.go) but
// parameterized by scope ID so it works for either scope A or scope B.
func scopeIsolationBindingID(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, sourceScopeID string) string {
	t.Helper()
	var bindingID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
		organizationID, workspaceID, sourceScopeID).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	return bindingID
}

// productActivationConfirmed calls the real product predicate, exactly as
// Activate, :sync and the read-side confirmation_state do -- never a
// test-local reimplementation of the join -- under the same session tenant
// context the application role's transactions run in (setAccessContext,
// rls_test.go).
func productActivationConfirmed(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, sourceScopeID string, sourceScopeRevision int64, scopeConfigHash string) bool {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin activation-confirmed check: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	var confirmed bool
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_activation_confirmed($1, $2, $3)`,
		sourceScopeID, sourceScopeRevision, scopeConfigHash).Scan(&confirmed); err != nil {
		t.Fatalf("call app.source_scope_activation_confirmed: %v", err)
	}
	return confirmed
}

// confirmScope drives the production authority-command runtime to bind and
// confirm one WORKSPACE_MANAGED source scope into the workspace at its
// current revision, returning the workspace snapshot left by the bind
// (AddSource) -- ConfirmManagedSource itself never advances the workspace
// revision, only a source-plane mutation does -- so the caller can chain a
// further AddSource/RemoveSource against the exact revision this call left.
// It mirrors
// TestWorkspaceSourceRepositoryReenableWorkspaceManagedSucceedsWithLiveConfirmation's
// setup exactly, just extracted so it can run twice (once per scope) against
// one shared workspace.
func confirmScope(
	t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store,
	access database.AccessContext, workspaceID, policyID, sourceScopeID, scopeConfigHash, label string,
	expectedRevision int64, expectedHash string,
) workspace.Snapshot {
	t.Helper()
	added, err := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey(label + "-add"), WorkspaceID: workspaceID,
		ExpectedWorkspaceRevision: expectedRevision, ExpectedConfigurationHash: expectedHash,
		SourceScopeID: sourceScopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeConfigHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("bind managed source %s: %v", sourceScopeID, err)
	}
	bindingID := scopeIsolationBindingID(t, ctx, admin, access.OrganizationID, workspaceID, sourceScopeID)

	grant, err := store.IssueConfirmationGrant(ctx, database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: "req_" + label + "_issue"},
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey(label + "-issue"), OrganizationID: access.OrganizationID,
			WorkspaceID: workspaceID, ExpectedWorkspaceRevision: added.Revision, ExpectedWorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			TargetPrincipalID: access.PrincipalID, TTLSeconds: 3600, ExpectedPolicyRevision: policyID,
		})
	if err != nil {
		t.Fatalf("issue confirmation grant for %s: %v", sourceScopeID, err)
	}
	if _, err := store.ConfirmManagedSource(ctx, database.AccessContext{OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, RequestID: "req_" + label + "_confirm"},
		workspacerepository.ConfirmRequest{
			IdempotencyKey: authorityIdempotencyKey(label + "-confirm"), OrganizationID: access.OrganizationID,
			WorkspaceID: workspaceID, WorkspaceRevision: added.Revision, WorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			WorkspaceSourceID: bindingID, SourceScopeID: sourceScopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeConfigHash,
			AccessMode: authorityAccessMode, ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1,
			ConfirmationActorGrantHash: grant.ResultHash, WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
			AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: policyID,
		}); err != nil {
		t.Fatalf("confirm managed source %s: %v", sourceScopeID, err)
	}
	return added
}

// TestSourceScopeActivationConfirmedSurvivesUnrelatedSourceMutation is the
// FIN-1 regression: two WORKSPACE_MANAGED scopes (A, B) share one workspace,
// both confirmed and enabled. Disabling B alone -- a real production mutation
// through store.RemoveSource, exactly "Disable" in the UI -- advances the
// workspace's current_revision. Scope A's own binding tuple never changed, so
// its confirmation must still be live (000076); scope B's own binding tuple
// just changed (enabled -> disabled), so its confirmation must correctly stop
// gating activation (fail-closed for the scope that actually mutated is
// unchanged behaviour, not a regression).
func TestSourceScopeActivationConfirmedSurvivesUnrelatedSourceMutation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, scopeIsolationOrganization, scopeIsolationOwner, scopeIsolationWorkspace)
	insertSourceScopeDraftChain(t, ctx, admin, scopeIsolationOrganization, scopeIsolationOwner, scopeIsolationOrganization, "workspace_managed")
	scopeBHash := insertSecondSourceScopeDraftChain(t, ctx, admin, scopeIsolationOrganization, scopeIsolationOwner)
	clock := fetchAuthorityClock(t, ctx, admin)
	policyID := "policy-" + scopeIsolationOrganization + "-0001"
	insertPolicyRegistryRow(t, ctx, admin, scopeIsolationOrganization, 1, policyID, authoritySha256(0x71), scopeIsolationOwner, clock.grantedAt)

	store := newAuthorityRuntime(t, ctx)
	access := database.AccessContext{OrganizationID: scopeIsolationOrganization, PrincipalID: scopeIsolationOwner, RequestID: "req_scope_isolation"}

	initial, err := store.Get(ctx, access, scopeIsolationWorkspace)
	if err != nil {
		t.Fatalf("read initial workspace: %v", err)
	}

	// Bind and confirm scope A, then scope B, each against the workspace
	// revision left by the previous step. confirmScope returns the snapshot
	// AddSource left (ConfirmManagedSource itself never advances the
	// workspace revision), so afterB is exactly the workspace's current
	// revision once both scopes are bound and confirmed.
	afterA := confirmScope(t, ctx, admin, store, access, scopeIsolationWorkspace, policyID,
		confirmationScopeID, confirmationScopeHash, "scope-isolation-a", initial.Revision, mustWorkspaceHash(t, initial))
	afterB := confirmScope(t, ctx, admin, store, access, scopeIsolationWorkspace, policyID,
		scopeIsolationSecondScopeID, scopeBHash, "scope-isolation-b", afterA.Revision, mustWorkspaceHash(t, afterA))

	// Both scopes are confirmed and enabled: the predicate must be true for
	// both, straight from the production function.
	if !productActivationConfirmed(t, ctx, admin, scopeIsolationOrganization, confirmationScopeID, 1, confirmationScopeHash) {
		t.Fatal("scope A activation-confirmed is false right after its own confirm")
	}
	if !productActivationConfirmed(t, ctx, admin, scopeIsolationOrganization, scopeIsolationSecondScopeID, 1, scopeBHash) {
		t.Fatal("scope B activation-confirmed is false right after its own confirm")
	}

	// Disable scope B only -- a real workspace mutation unrelated to scope A.
	bBindingID := scopeIsolationBindingID(t, ctx, admin, scopeIsolationOrganization, scopeIsolationWorkspace, scopeIsolationSecondScopeID)
	removed, err := store.RemoveSource(ctx, access, workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("scope-isolation-disable-b"), WorkspaceID: scopeIsolationWorkspace,
		ExpectedWorkspaceRevision: afterB.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, afterB),
		WorkspaceSourceID: bBindingID, SourceScopeID: scopeIsolationSecondScopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeBHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("disable scope B: %v", err)
	}
	if removed.Revision != afterB.Revision+1 {
		t.Fatalf("disabling scope B did not advance the workspace revision: got %d, want %d", removed.Revision, afterB.Revision+1)
	}

	// The FIX under test: scope A's own tuple never changed, so its
	// confirmation must still be live even though workspace.current_revision
	// just advanced because of scope B's mutation.
	if !productActivationConfirmed(t, ctx, admin, scopeIsolationOrganization, confirmationScopeID, 1, confirmationScopeHash) {
		t.Fatal("scope A activation-confirmed went false after an UNRELATED mutation (disabling scope B) -- FIN-1 regression: a foreign workspace mutation must not reset another source's confirmation")
	}

	// FAIL-CLOSED PRESERVED: scope B's own binding just changed (enabled ->
	// disabled), so the activation gate must correctly stop treating it as
	// confirmed for activation/sync purposes.
	if productActivationConfirmed(t, ctx, admin, scopeIsolationOrganization, scopeIsolationSecondScopeID, 1, scopeBHash) {
		t.Fatal("scope B activation-confirmed stayed true after its OWN mutation (disable) -- fail-closed for the scope that actually changed must be preserved")
	}
}
