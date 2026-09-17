package postgres_test

// Real-PostgreSQL regression coverage for ADR-0087 §2 review blocker B3'
// (review-opus-s2-6-7.md): the reverse direction of the verifier/confirmer
// separation of duty. Migration 000059's app.source_connection_trust_verify
// already denies verify-after-confirm (source_connection_trust_verify_
// separation_of_duty_test.go); this file proves confirm-after-verify is
// denied the same content-free way (terminalDenied, mapped to
// CodeAuthorityDenied, never a distinguishing precondition code), and that
// the check's per-connection granularity is strictly stricter than a
// per-scope-only rule would be, not a weaker substitute for one.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// insertAdditionalWorkspaceManagedScope inserts a second WORKSPACE_MANAGED
// source-scope DRAFT chain under an EXISTING connection (organizationID's
// "conn_"+organizationID, the connection insertSourceScopeDraftChain already
// created for the fixture's own scope), so a test can hold two distinct
// scopes of one connection at once. It deliberately does not touch
// public.source_connection or its trust record/projection: those already
// exist from the fixture's own chain, and this scope shares them.
func insertAdditionalWorkspaceManagedScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, ownerID, connectionID, scopeID, discoveryID, label string) string {
	t.Helper()
	scopeConfigHash := "sha256:" + strings.Repeat("6", 63) + label[len(label)-1:]
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	identityArtifactID := "artifact_identity_" + label
	displayArtifactID := "artifact_display_" + label
	configArtifactID := "artifact_scope_config_" + label
	identityHash := "sha256:" + strings.Repeat("4", 63) + label[len(label)-1:]
	displayHash := "sha256:" + strings.Repeat("5", 63) + label[len(label)-1:]

	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1, $2, 1)`, organizationID, scopeID).Scan(&scopeResourceID); err != nil {
		t.Fatalf("compute scope revision resource id: %v", err)
	}
	for _, artifact := range []struct {
		id, ownerTable, ownerColumn, resourceType, resourceID, field, hash, nonce string
	}{
		{identityArtifactID, "source_discovered_scope", "identity_artifact_id", "SOURCE_SCOPE_IDENTITY", discoveryID, "EXTERNAL_SCOPE_IDENTITY", identityHash, "41"},
		{displayArtifactID, "source_discovered_scope", "display_metadata_artifact_id", "SOURCE_SCOPE_METADATA", discoveryID, "DISPLAY_METADATA", displayHash, "42"},
		{configArtifactID, "source_scope_revision", "scope_config_artifact_id", "SOURCE_SCOPE_CONFIG", scopeResourceID, "SCOPE_CONFIG", scopeConfigHash, "43"},
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
			t.Fatalf("insert %s artifact: %v", artifact.field, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_discovered_scope (
			organization_id, id, connection_id, connection_revision, source_type,
			identity_digest, identity_digest_key_version,
			identity_artifact_id, identity_plaintext_hash,
			display_metadata_artifact_id, display_metadata_hash
		) VALUES ($1, $2, $3, 1, 'FOLDER', $4, 1, $5, $6, $7, $8)
	`, organizationID, discoveryID, connectionID,
		"hmac-sha256:k1:"+strings.Repeat("2", 63)+label[len(label)-1:], identityArtifactID,
		identityHash, displayArtifactID, displayHash); err != nil {
		t.Fatalf("insert discovered scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope (
			organization_id, id, connection_id, discovered_scope_id,
			source_type, latest_revision, created_by
		) VALUES ($1, $2, $3, $4, 'FOLDER', 1, $5)
	`, organizationID, scopeID, connectionID, discoveryID, ownerID); err != nil {
		t.Fatalf("insert source scope: %v", err)
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
	`, organizationID, scopeID, connectionID, discoveryID,
		"hmac-sha256:k1:"+strings.Repeat("2", 63)+label[len(label)-1:], configArtifactID, scopeConfigHash,
		int64(500), int64(500000), int64(100000), ownerID); err != nil {
		t.Fatalf("insert source scope revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_activation (
			organization_id, source_scope_id, source_scope_revision, revision, status
		) VALUES ($1, $2, 1, 1, 'DRAFT')
	`, organizationID, scopeID); err != nil {
		t.Fatalf("insert source scope activation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit additional scope: %v", err)
	}
	return scopeConfigHash
}

// TestConfirmManagedSourceDeniesVerifierConflict is the reverse direction of
// TestSourceConnectionTrustVerifyDeniesSameConfirmerAsVerifier
// (source_connection_trust_verify_separation_of_duty_test.go): the same
// principal verifies a connection's trust first, then attempts to confirm a
// WORKSPACE_MANAGED binding of that connection's own scope, and the confirm
// is denied exactly as content-free as an unheld actor grant (CodeDenied,
// never a distinguishing precondition code).
func TestConfirmManagedSourceDeniesVerifierConflict(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	connectionID := "conn_" + fixture.organizationID

	// The fixture owner becomes CONNECTOR_ADMIN and verifies the connection's
	// trust before ever confirming anything.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_confirm_conflict_owner', $1, $2, 'CONNECTOR_ADMIN', 1, $2)`, fixture.organizationID, fixture.ownerID); err != nil {
		t.Fatalf("grant CONNECTOR_ADMIN to the owner: %v", err)
	}
	verifyAccess := database.AccessContext{OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_confirm_conflict_verify"}
	if _, err := store.VerifyConnectionTrust(ctx, verifyAccess, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("confirm-conflict-verify"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("verify connection trust: %v", err)
	}

	// The same principal now tries to confirm the WORKSPACE_MANAGED binding
	// of a scope belonging to the connection they just verified.
	grant := issueRuntimeGrant(t, ctx, store, fixture, "confirm-conflict-issue")
	_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_confirm"),
		confirmRuntimeRequest(fixture, grant, "confirm-conflict-confirm"))
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityDenied {
		t.Fatalf("confirm-after-verify by the same principal code = %v, want CodeAuthorityDenied", err)
	}

	// A different, never-verifying principal who holds the same kind of
	// grant succeeds — proving the denial above was the separation-of-duty
	// conflict and not some unrelated fixture defect. A workspace has exactly
	// one active OWNER (workspace_one_active_owner), so this second confirmer
	// joins as MANAGER instead -- confirmDecision's own ws.isOwnerOrManager()
	// treats OWNER and MANAGER identically for this purpose.
	secondOwner := "usr_authority_ops_second_owner"
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, secondOwner, fixture.organizationID); err != nil {
		t.Fatalf("seed second principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1, $2, $3, $4, 'MANAGER', 1, $5)`,
		"wsm_confirm_conflict_"+secondOwner, fixture.organizationID, fixture.workspaceID, secondOwner, fixture.ownerID); err != nil {
		t.Fatalf("seed second workspace manager: %v", err)
	}
	secondGrant, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_second_issue"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("confirm-conflict-second-issue"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: secondOwner,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if err != nil {
		t.Fatalf("issue second grant: %v", err)
	}
	secondRequest := confirmRuntimeRequest(fixture, secondGrant, "confirm-conflict-second-confirm")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, secondOwner, "req_confirm_conflict_second_confirm"), secondRequest); err != nil {
		t.Fatalf("different-principal confirm: %v", err)
	}
}

// TestConfirmManagedSourceDeniesVerifierConflictAcrossDifferentScopesOfSameConnection
// proves the per-connection granularity of the B3' check is strictly
// stricter than a per-SourceScopeID-only rule would be, never a weaker
// substitute for one (review-opus-s2-6-7.md remark on granularity, ADR-0087
// §2's own wording: "verifies a connector's trust" is connection-scoped,
// "confirms that scope's WORKSPACE_MANAGED binding" is scope-scoped). It
// verifies connection trust once, then confirms a DIFFERENT scope of the
// SAME connection than the one exercised by any other test in this file —
// a case a hypothetical rule comparing only "the one scope this
// verification concerned" could never catch, because VerifyConnectionTrust
// carries no scope at all: the whole connection is the only coherent unit
// the conflict can be checked against.
func TestConfirmManagedSourceDeniesVerifierConflictAcrossDifferentScopesOfSameConnection(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	connectionID := "conn_" + fixture.organizationID

	secondScopeID := "scope_01ARZ3NDEKTSV4RRFFQ69G5FBZ"
	secondDiscoveryID := "discovered_01ARZ3NDEKTSV4RRFFQ69G5FBZ"
	secondScopeConfigHash := insertAdditionalWorkspaceManagedScope(t, ctx, admin,
		fixture.organizationID, fixture.ownerID, connectionID, secondScopeID, secondDiscoveryID, "second1")

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_confirm_conflict_cross_owner', $1, $2, 'CONNECTOR_ADMIN', 1, $2)`, fixture.organizationID, fixture.ownerID); err != nil {
		t.Fatalf("grant CONNECTOR_ADMIN to the owner: %v", err)
	}
	verifyAccess := database.AccessContext{OrganizationID: fixture.organizationID, PrincipalID: fixture.ownerID, RequestID: "req_confirm_conflict_cross_verify"}
	if _, err := store.VerifyConnectionTrust(ctx, verifyAccess, workspacerepository.VerifyConnectionTrustRequest{
		IdempotencyKey: authorityIdempotencyKey("confirm-conflict-cross-verify"), ConnectionID: connectionID,
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("verify connection trust: %v", err)
	}

	// Bind the SECOND scope (never referenced by the verify call above --
	// VerifyConnectionTrust names only the connection) into the same
	// workspace, then attempt to confirm it.
	currentWorkspace, err := store.Get(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_cross_get"), fixture.workspaceID)
	if err != nil {
		t.Fatalf("read workspace: %v", err)
	}
	added, err := store.AddSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_cross_add"), workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("confirm-conflict-cross-add"), WorkspaceID: fixture.workspaceID,
		ExpectedWorkspaceRevision: currentWorkspace.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, currentWorkspace),
		SourceScopeID: secondScopeID, SourceScopeRevision: 1, ScopeConfigHash: secondScopeConfigHash,
		AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
	})
	if err != nil {
		t.Fatalf("bind second managed scope: %v", err)
	}
	var secondBindingID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
		fixture.organizationID, fixture.workspaceID, secondScopeID).Scan(&secondBindingID); err != nil {
		t.Fatalf("read second binding id: %v", err)
	}

	// AddSource above advanced the workspace past fixture.workspaceRevision,
	// so the grant issued here must reference the current revision/hash
	// (added.Revision/mustWorkspaceHash(t, added)), not the stale fixture
	// values issueRuntimeGrant would use.
	grant, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_cross_issue"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("confirm-conflict-cross-issue"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: added.Revision, ExpectedWorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			TargetPrincipalID: fixture.ownerID, TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if err != nil {
		t.Fatalf("issue grant for second scope: %v", err)
	}
	_, err = store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_confirm_conflict_cross_confirm"),
		workspacerepository.ConfirmRequest{
			IdempotencyKey: authorityIdempotencyKey("confirm-conflict-cross-confirm"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, WorkspaceRevision: added.Revision, WorkspaceConfigurationHash: mustWorkspaceHash(t, added),
			WorkspaceSourceID: secondBindingID, SourceScopeID: secondScopeID, SourceScopeRevision: 1, ScopeConfigHash: secondScopeConfigHash,
			AccessMode: authorityAccessMode, ConfirmationActorGrantID: grant.ResultID, ConfirmationActorGrantRevision: 1,
			ConfirmationActorGrantHash: grant.ResultHash, WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
			AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityDenied {
		t.Fatalf("confirm of a different scope of the verified connection code = %v, want CodeAuthorityDenied", err)
	}
}
