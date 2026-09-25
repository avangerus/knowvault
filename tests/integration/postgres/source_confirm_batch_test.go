package postgres_test

// Card S3.4b: real-PostgreSQL proof of batch managed-source confirmation. The
// batch is a composite of the unchanged individual WORKSPACE_MANAGED_CONFIRM
// command, so these tests pin the three properties the card requires:
//
//   - every table of a batch gets exactly the same confirmation record as an
//     individual confirmation, and the authority audit carries one success
//     event per table;
//   - a per-table refusal (here the ADR-0087 §2 verifier/confirmer separation
//     of duty) never blocks the others and never confirms anything it should
//     not;
//   - replaying the same request creates nothing twice, a foreign workspace's
//     table is the same content-free not-found, and more than 1000 tables is
//     refused as a whole.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// batchConfirmFixture is one workspace with tables on two connections, so a
// batch can mix a table whose connection was trust-verified by the confirming
// principal with tables that were not.
type batchConfirmFixture struct {
	authorityOpsFixture
	tables []workspacerepository.BatchConfirmTable
}

// insertBatchConnection seeds one additional FOLDER source connection in an
// organization that already has one. It mirrors insertSourceDraftChainInTx
// (which fixes its encrypted-artifact nonce and therefore cannot run twice in
// one organization) with a nonce this fixture owns.
func insertBatchConnection(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, suffix string) string {
	t.Helper()
	connectionID := "conn_" + suffix
	profileID := "cap_batch_" + suffix
	artifactID := "artifact_batch_trust_" + suffix
	trustRecordID := "trust_batch_" + suffix
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (
			id, profile_hash, connector_build_id, connector_type, connector_version,
			connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor,
			webhooks, item_level_acl, acl_refresh, historical_versions, deep_links,
			deletion_events, local_extraction, contract_suite_hash, verified_at
		) VALUES ($1, $2, $3, 'FOLDER', '1.0.0', $4, true, true, true, false,
			true, true, true, true, true, true, $5, transaction_timestamp())`,
		profileID, "sha256:"+strings.Repeat("a", 64), "folder-build-"+suffix,
		"sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)); err != nil {
		t.Fatalf("seed second capability profile: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection (organization_id, id, type, name, latest_revision, active_revision, status, created_by)
		VALUES ($1, $2, 'FOLDER', $2, 1, NULL, 'DRAFT', $3)`, organizationID, connectionID, ownerID); err != nil {
		t.Fatalf("seed second connection: %v", err)
	}
	var resourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_connection_revision_resource_id($1, $2, 1)`,
		organizationID, connectionID).Scan(&resourceID); err != nil {
		t.Fatalf("second connection resource id: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type, resource_id,
			field_name, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
			kek_reference, kek_version, aad_hash, plaintext_hash
		) VALUES ($1, $2, 'source_connection_revision', 'trust_profile_artifact_id',
			'SOURCE_TRUST_CONFIG', $3, 'TRUST_CONFIG',
			decode(repeat('ab', 17), 'hex'), 1, decode(repeat('70', 12), 'hex'),
			decode('77726170706564', 'hex'), $4, 'kms://tenant', 1, $5, $6)`,
		organizationID, artifactID, resourceID, "sha256:"+strings.Repeat("d", 63)+"0",
		"sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64)); err != nil {
		t.Fatalf("seed second trust artifact: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_revision (
			organization_id, connection_id, revision, credential_reference, connector_build_id,
			connector_type, capability_profile_id, capability_profile_hash, connector_agent_id,
			execution_target, trust_record_id, trust_profile_artifact_id, trust_profile_hash,
			connector_version, connector_artifact_hash, connector_contract_suite_hash,
			connector_verified_at, allowed_access_modes_json, max_scope_objects, max_scope_bytes,
			max_object_bytes, created_by
		) VALUES ($1, $2, 1, $3, $4, 'FOLDER', $5, $6, NULL, 'CENTRAL_WORKER', $7, $8, $9,
			'1.0.0', $10, $11, transaction_timestamp(), '["WORKSPACE_MANAGED"]'::jsonb,
			1000, 1000000, 100000, $12)`,
		organizationID, connectionID, testCredentialRef, "folder-build-"+suffix, profileID,
		"sha256:"+strings.Repeat("a", 64), trustRecordID, artifactID, "sha256:"+strings.Repeat("d", 64),
		"sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64), ownerID); err != nil {
		t.Fatalf("seed second connection revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_record (
			organization_id, id, connection_id, connection_revision, connector_agent_id,
			execution_target, trust_profile_artifact_id, trust_profile_hash, verified_at, expires_at
		) VALUES ($1, $2, $3, 1, NULL, 'CENTRAL_WORKER', $4, $5,
			transaction_timestamp(), transaction_timestamp() + interval '1 day')`,
		organizationID, trustRecordID, connectionID, artifactID, "sha256:"+strings.Repeat("d", 64)); err != nil {
		t.Fatalf("seed second trust record: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_connection_trust_projection (organization_id, trust_record_id, revision, status)
		VALUES ($1, $2, 1, 'DRAFT')`, organizationID, trustRecordID); err != nil {
		t.Fatalf("seed second trust projection: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return connectionID
}

// insertBatchScope inserts one additional WORKSPACE_MANAGED scope under an
// existing connection, with artifact nonces derived from ordinal so several
// scopes can coexist in one organization. It is insertAdditionalWorkspaceManagedScope
// with the one fixed value that would collide parameterized.
func insertBatchScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, ownerID, connectionID, scopeID, discoveryID, label string, ordinal int) string {
	t.Helper()
	scopeConfigHash := "sha256:" + strings.Repeat("6", 63) + fmt.Sprintf("%x", ordinal%16)
	identityHash := "sha256:" + strings.Repeat("4", 63) + fmt.Sprintf("%x", ordinal%16)
	displayHash := "sha256:" + strings.Repeat("5", 63) + fmt.Sprintf("%x", ordinal%16)
	identityArtifactID := "artifact_batch_identity_" + label
	displayArtifactID := "artifact_batch_display_" + label
	configArtifactID := "artifact_batch_config_" + label
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1, $2, 1)`,
		organizationID, scopeID).Scan(&scopeResourceID); err != nil {
		t.Fatalf("batch scope resource id: %v", err)
	}
	for artifactIndex, artifact := range []struct {
		id, ownerTable, ownerColumn, resourceType, resourceID, field, hash string
	}{
		{identityArtifactID, "source_discovered_scope", "identity_artifact_id", "SOURCE_SCOPE_IDENTITY", discoveryID, "EXTERNAL_SCOPE_IDENTITY", identityHash},
		{displayArtifactID, "source_discovered_scope", "display_metadata_artifact_id", "SOURCE_SCOPE_METADATA", discoveryID, "DISPLAY_METADATA", displayHash},
		{configArtifactID, "source_scope_revision", "scope_config_artifact_id", "SOURCE_SCOPE_CONFIG", scopeResourceID, "SCOPE_CONFIG", scopeConfigHash},
	} {
		artifactNonce := fmt.Sprintf("%02x", 0x50+ordinal*4+artifactIndex)
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.encrypted_artifact (
				organization_id, id, owner_table, owner_column, resource_type, resource_id,
				field_name, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
				kek_reference, kek_version, aad_hash, plaintext_hash
			) VALUES ($1, $2, $3, $4, $5, $6, $7, decode(repeat('ab', 17), 'hex'), 1,
				decode(repeat($8, 12), 'hex'), decode('77726170706564', 'hex'),
				$9, 'kms://tenant', 1, $10, $11)`,
			organizationID, artifact.id, artifact.ownerTable, artifact.ownerColumn,
			artifact.resourceType, artifact.resourceID, artifact.field, artifactNonce,
			"sha256:"+strings.Repeat("8", 64), "sha256:"+strings.Repeat("9", 64), artifact.hash); err != nil {
			t.Fatalf("insert batch scope artifact %s: %v", artifact.field, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_discovered_scope (
			organization_id, id, connection_id, connection_revision, source_type, identity_digest,
			identity_digest_key_version, identity_artifact_id, identity_plaintext_hash,
			display_metadata_artifact_id, display_metadata_hash
		) VALUES ($1, $2, $3, 1, 'FOLDER', $4, 1, $5, $6, $7, $8)`,
		organizationID, discoveryID, connectionID, "hmac-sha256:k1:"+strings.Repeat("2", 63)+fmt.Sprintf("%x", ordinal%16),
		identityArtifactID, identityHash, displayArtifactID, displayHash); err != nil {
		t.Fatalf("insert batch discovered scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope (organization_id, id, connection_id, discovered_scope_id, source_type, latest_revision, created_by)
		VALUES ($1, $2, $3, $4, 'FOLDER', 1, $5)`,
		organizationID, scopeID, connectionID, discoveryID, ownerID); err != nil {
		t.Fatalf("insert batch source scope: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_revision (
			organization_id, source_scope_id, revision, connection_id, connection_revision,
			discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version,
			source_type, scope_config_artifact_id, scope_config_hash, scope_contract_version,
			access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
			object_limit, byte_limit, max_object_bytes, created_by
		) VALUES ($1, $2, 1, $3, 1, $4, $5, 1, 'FOLDER', $6, $7, '1.2', 'WORKSPACE_MANAGED',
			300, 600, 300, $8, $9, $10, $11)`,
		organizationID, scopeID, connectionID, discoveryID,
		"hmac-sha256:k1:"+strings.Repeat("2", 63)+fmt.Sprintf("%x", ordinal%16), configArtifactID,
		scopeConfigHash, int64(500), int64(500000), int64(100000), ownerID); err != nil {
		t.Fatalf("insert batch scope revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ($1, $2, 1, 1, 'DRAFT')`, organizationID, scopeID); err != nil {
		t.Fatalf("insert batch scope activation: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return scopeConfigHash
}

// boundScope describes one scope bound to the fixture workspace.
type boundScope struct {
	scopeID    string
	bindingID  string
	configHash string
}

// seedBatchConfirmFixture builds the fixture workspace, an independent second
// connection, and count additional scopes bound through the production
// AddSource path. Every binding is carried onto the workspace's current
// revision, so the returned fixture names the exact revision to confirm at.
func seedBatchConfirmFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, count int) (batchConfirmFixture, []boundScope, *workspacerepository.Store) {
	t.Helper()
	base := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)
	secondConnectionID := insertBatchConnection(t, ctx, admin, base.organizationID, base.ownerID, "batch2")

	scopes := []boundScope{{
		scopeID: base.sourceScopeID, bindingID: base.workspaceSourceID, configHash: base.scopeConfigHash,
	}}
	access := authorityAccess(base, base.ownerID, "req_batch_bind")
	snapshot, err := store.Get(ctx, access, base.workspaceID)
	if err != nil {
		t.Fatalf("read workspace before binding: %v", err)
	}
	for index := 0; index < count; index++ {
		label := fmt.Sprintf("b%d", index+1)
		suffix := fmt.Sprintf("01ARZ3NDEKTSV4RRFFQ69G5F%02d", index+1)
		scopeID := "scope_" + suffix
		discoveryID := "discovered_" + suffix
		configHash := insertBatchScope(t, ctx, admin,
			base.organizationID, base.ownerID, secondConnectionID, scopeID, discoveryID, label, index+1)
		added, addErr := store.AddSource(ctx, access, workspacerepository.AddSourceRequest{
			IdempotencyKey:            authorityIdempotencyKey("batch-bind-" + label),
			WorkspaceID:               base.workspaceID,
			ExpectedWorkspaceRevision: snapshot.Revision,
			ExpectedConfigurationHash: mustWorkspaceHash(t, snapshot),
			SourceScopeID:             scopeID, SourceScopeRevision: 1, ScopeConfigHash: configHash,
			AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
		})
		if addErr != nil {
			t.Fatalf("bind scope %s: %v", scopeID, addErr)
		}
		snapshot = added
		var bindingID string
		if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
			WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
			base.organizationID, base.workspaceID, scopeID).Scan(&bindingID); err != nil {
			t.Fatalf("read binding %s: %v", scopeID, err)
		}
		scopes = append(scopes, boundScope{scopeID: scopeID, bindingID: bindingID, configHash: configHash})
	}

	fixture := batchConfirmFixture{authorityOpsFixture: base}
	fixture.workspaceRevision = snapshot.Revision
	fixture.workspaceConfHash = mustWorkspaceHash(t, snapshot)
	for _, scope := range scopes {
		fixture.tables = append(fixture.tables, workspacerepository.BatchConfirmTable{
			WorkspaceSourceID: scope.bindingID, SourceScopeID: scope.scopeID,
			SourceScopeRevision: 1, ScopeConfigHash: scope.configHash,
		})
	}
	return fixture, scopes, store
}

func batchConfirmRequest(fixture batchConfirmFixture, label string, grant workspacerepository.AuthorityResult,
	tables []workspacerepository.BatchConfirmTable) workspacerepository.BatchConfirmRequest {
	return workspacerepository.BatchConfirmRequest{
		IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
		WorkspaceID: fixture.workspaceID, WorkspaceRevision: fixture.workspaceRevision,
		WorkspaceConfigurationHash: fixture.workspaceConfHash,
		ConfirmationActorGrantID:   grant.ResultID, ConfirmationActorGrantRevision: 1,
		ConfirmationActorGrantHash: grant.ResultHash,
		WarningVersion:             confirmationWarningVer, WarningContractHash: confirmationWarnHash,
		AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: fixture.policyID,
		Tables: tables,
	}
}

func countConfirmationsFor(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_grant_confirmation WHERE organization_id=$1`,
		organizationID).Scan(&count); err != nil {
		t.Fatalf("count confirmations: %v", err)
	}
	return count
}

func countConfirmedAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='workspace.source_confirmed' AND outcome='SUCCESS'`,
		organizationID).Scan(&count); err != nil {
		t.Fatalf("count confirmation audit: %v", err)
	}
	return count
}

// TestBatchConfirmThreeTablesMatchesIndividualShape proves the first card
// result: one request confirms three tables, each gets a confirmation record
// identical in shape to the individually confirmed fourth table, and the
// authority audit carries four successful confirmation events.
func TestBatchConfirmThreeTablesMatchesIndividualShape(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture, _, store := seedBatchConfirmFixture(t, ctx, admin, 3)
	grant := issueRuntimeGrant(t, ctx, store, fixture.authorityOpsFixture, "batch-shape-issue")

	// The fourth table is confirmed one at a time, the exact shape the batch
	// must match.
	individual := fixture.tables[3]
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_shape_individual"),
		workspacerepository.ConfirmRequest{
			IdempotencyKey: authorityIdempotencyKey("batch-shape-individual"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, WorkspaceRevision: fixture.workspaceRevision,
			WorkspaceConfigurationHash: fixture.workspaceConfHash,
			WorkspaceSourceID:          individual.WorkspaceSourceID, SourceScopeID: individual.SourceScopeID,
			SourceScopeRevision: individual.SourceScopeRevision, ScopeConfigHash: individual.ScopeConfigHash,
			AccessMode: authorityAccessMode, ConfirmationActorGrantID: grant.ResultID,
			ConfirmationActorGrantRevision: 1, ConfirmationActorGrantHash: grant.ResultHash,
			WarningVersion: confirmationWarningVer, WarningContractHash: confirmationWarnHash,
			AcknowledgementCode: confirmationAckCode, ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("individual confirm: %v", err)
	}

	result, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_shape"),
		batchConfirmRequest(fixture, "batch-shape", grant, fixture.tables[:3]))
	if err != nil {
		t.Fatalf("batch confirm: %v", err)
	}
	if result.ConfirmedCount != 3 || result.RefusedCount != 0 || len(result.Outcomes) != 3 {
		t.Fatalf("batch result = %#v", result)
	}
	for _, outcome := range result.Outcomes {
		if !outcome.Confirmed || outcome.ConfirmationID == "" || outcome.ConfirmationHash == "" {
			t.Fatalf("outcome not confirmed: %#v", outcome)
		}
	}
	if got := countConfirmationsFor(t, ctx, admin, fixture.organizationID); got != 4 {
		t.Fatalf("confirmation rows = %d, want 4 (3 batch + 1 individual)", got)
	}
	if got := countConfirmedAudit(t, ctx, admin, fixture.organizationID); got != 4 {
		t.Fatalf("confirmation audit events = %d, want 4", got)
	}

	// Every batch row must carry the exact same authority shape as the
	// individually created one; only the identity of the table and the
	// server-owned id/hash/timestamp differ.
	var individualShape string
	if err := admin.QueryRow(ctx, `
		SELECT concat_ws('|', workspace_id, workspace_revision, workspace_configuration_hash,
			source_scope_revision, access_mode, confirmation_actor_grant_id, confirmation_actor_grant_revision,
			confirmation_actor_grant_hash, warning_version, warning_contract_hash, acknowledgement_code,
			confirmed_by, policy_revision_number, policy_revision)
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND source_scope_id=$2`, fixture.organizationID, individual.SourceScopeID).Scan(&individualShape); err != nil {
		t.Fatalf("read individual shape: %v", err)
	}
	for _, outcome := range result.Outcomes {
		var shape string
		if err := admin.QueryRow(ctx, `
			SELECT concat_ws('|', workspace_id, workspace_revision, workspace_configuration_hash,
				source_scope_revision, access_mode, confirmation_actor_grant_id, confirmation_actor_grant_revision,
				confirmation_actor_grant_hash, warning_version, warning_contract_hash, acknowledgement_code,
				confirmed_by, policy_revision_number, policy_revision)
			FROM public.workspace_managed_grant_confirmation
			WHERE organization_id=$1 AND source_scope_id=$2`, fixture.organizationID, outcome.SourceScopeID).Scan(&shape); err != nil {
			t.Fatalf("read batch shape: %v", err)
		}
		if shape != individualShape {
			t.Fatalf("batch confirmation shape %q != individual %q", shape, individualShape)
		}
	}
}

// TestBatchConfirmMixedRecordsPerTableRefusalWithoutBlocking proves the second
// card result: the ADR-0087 §2 verifier/confirmer conflict refuses exactly the
// verified connection's table with its closed code, while the other connection's
// table is confirmed in the same request.
func TestBatchConfirmMixedRecordsPerTableRefusalWithoutBlocking(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture, _, store := seedBatchConfirmFixture(t, ctx, admin, 1)

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_batch_sod_owner', $1, $2, 'CONNECTOR_ADMIN', 1, $2)`, fixture.organizationID, fixture.ownerID); err != nil {
		t.Fatalf("grant CONNECTOR_ADMIN: %v", err)
	}
	if _, err := store.VerifyConnectionTrust(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_sod_verify"),
		workspacerepository.VerifyConnectionTrustRequest{
			IdempotencyKey: authorityIdempotencyKey("batch-sod-verify"), ConnectionID: "conn_" + fixture.organizationID,
			AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
			AttestedAt: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
		t.Fatalf("verify connection trust: %v", err)
	}
	grant := issueRuntimeGrant(t, ctx, store, fixture.authorityOpsFixture, "batch-sod-issue")

	result, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_sod"),
		batchConfirmRequest(fixture, "batch-sod", grant, fixture.tables))
	if err != nil {
		t.Fatalf("batch confirm: %v", err)
	}
	if result.ConfirmedCount != 1 || result.RefusedCount != 1 || len(result.Outcomes) != 2 {
		t.Fatalf("mixed batch result = %#v", result)
	}
	verified, other := result.Outcomes[0], result.Outcomes[1]
	if verified.Confirmed || verified.ReasonCode != string(workspacerepository.CodeAuthorityDenied) {
		t.Fatalf("verified connection's table outcome = %#v, want DENIED", verified)
	}
	if !other.Confirmed || other.ReasonCode != "" {
		t.Fatalf("unverified connection's table outcome = %#v, want confirmed", other)
	}
	// Only the confirmable table produced a record: a refusal confirms nothing.
	var rows int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND source_scope_id=$2`, fixture.organizationID, verified.SourceScopeID).Scan(&rows); err != nil {
		t.Fatalf("count refused rows: %v", err)
	}
	if rows != 0 {
		t.Fatalf("refused table produced %d confirmation rows", rows)
	}
	if got := countConfirmationsFor(t, ctx, admin, fixture.organizationID); got != 1 {
		t.Fatalf("confirmation rows = %d, want 1", got)
	}
}

// TestBatchConfirmReplayCreatesNothingTwice proves the replay rule: the same
// request with the same Idempotency-Key returns the same per-table outcomes and
// adds no confirmation row and no audit event.
func TestBatchConfirmReplayCreatesNothingTwice(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture, _, store := seedBatchConfirmFixture(t, ctx, admin, 2)
	grant := issueRuntimeGrant(t, ctx, store, fixture.authorityOpsFixture, "batch-replay-issue")
	request := batchConfirmRequest(fixture, "batch-replay", grant, fixture.tables)

	first, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_replay"), request)
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	rowsAfterFirst := countConfirmationsFor(t, ctx, admin, fixture.organizationID)
	auditAfterFirst := countConfirmedAudit(t, ctx, admin, fixture.organizationID)

	replay, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_replay_again"), request)
	if err != nil {
		t.Fatalf("replay batch: %v", err)
	}
	if len(replay.Outcomes) != len(first.Outcomes) {
		t.Fatalf("replay outcomes = %#v, first = %#v", replay.Outcomes, first.Outcomes)
	}
	for index := range first.Outcomes {
		if replay.Outcomes[index] != first.Outcomes[index] {
			t.Fatalf("replay outcome %d = %#v, want %#v", index, replay.Outcomes[index], first.Outcomes[index])
		}
	}
	if got := countConfirmationsFor(t, ctx, admin, fixture.organizationID); got != rowsAfterFirst {
		t.Fatalf("replay created confirmation rows: %d -> %d", rowsAfterFirst, got)
	}
	if got := countConfirmedAudit(t, ctx, admin, fixture.organizationID); got != auditAfterFirst {
		t.Fatalf("replay appended audit events: %d -> %d", auditAfterFirst, got)
	}
}

// TestBatchConfirmForeignWorkspaceTableIsContentFreeNotFound proves the third
// card result: naming another workspace's table resolves to the same
// content-free not-found an individual confirmation returns, and confirms
// nothing of it. The named table is a real scope bound to a different tenant,
// so the proof is not vacuous.
func TestBatchConfirmForeignWorkspaceTableIsContentFreeNotFound(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture, _, store := seedBatchConfirmFixture(t, ctx, admin, 0)
	grant := issueRuntimeGrant(t, ctx, store, fixture.authorityOpsFixture, "batch-foreign-issue")

	foreign := setupAuthorityOpsTenant(t, ctx, admin, "org_batch_foreign", "usr_batch_foreign_owner", "ws_batch_foreign")
	foreignScopeID := "scope_01ARZ3NDEKTSV4RRFFQ69G5FBZ"
	foreignHash := insertAdditionalWorkspaceManagedScope(t, ctx, admin,
		foreign.organizationID, foreign.ownerID, "conn_"+foreign.organizationID, foreignScopeID,
		"discovered_01ARZ3NDEKTSV4RRFFQ69G5FBZ", "z9")

	tables := append([]workspacerepository.BatchConfirmTable(nil), fixture.tables...)
	tables = append(tables, workspacerepository.BatchConfirmTable{
		WorkspaceSourceID: foreign.workspaceSourceID, SourceScopeID: foreignScopeID,
		SourceScopeRevision: 1, ScopeConfigHash: foreignHash,
	})
	result, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_foreign"),
		batchConfirmRequest(fixture, "batch-foreign", grant, tables))
	if err != nil {
		t.Fatalf("batch confirm: %v", err)
	}
	if len(result.Outcomes) != 2 {
		t.Fatalf("outcomes = %#v", result.Outcomes)
	}
	if !result.Outcomes[0].Confirmed {
		t.Fatalf("own table not confirmed: %#v", result.Outcomes[0])
	}
	if result.Outcomes[1].Confirmed || result.Outcomes[1].ReasonCode != string(workspacerepository.CodeAuthorityNotFound) {
		t.Fatalf("foreign table outcome = %#v, want content-free NOT_FOUND", result.Outcomes[1])
	}
	var foreignRows int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND source_scope_id=$2`, fixture.organizationID, foreignScopeID).Scan(&foreignRows); err != nil {
		t.Fatalf("count foreign rows: %v", err)
	}
	if foreignRows != 0 {
		t.Fatalf("foreign table produced %d confirmation rows", foreignRows)
	}
}

// TestBatchConfirmRefusesMoreThanOneThousandAsAWhole proves the bound: a 1001
// table request is refused before any table is examined, so it confirms nothing.
func TestBatchConfirmRefusesMoreThanOneThousandAsAWhole(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture, _, store := seedBatchConfirmFixture(t, ctx, admin, 1)
	grant := issueRuntimeGrant(t, ctx, store, fixture.authorityOpsFixture, "batch-bound-issue")

	tables := make([]workspacerepository.BatchConfirmTable, 0, workspacerepository.MaxBatchConfirmTables+1)
	for index := 0; index <= workspacerepository.MaxBatchConfirmTables; index++ {
		tables = append(tables, fixture.tables[0])
	}
	_, err := store.ConfirmManagedSourcesBatch(ctx, authorityAccess(fixture.authorityOpsFixture, fixture.ownerID, "req_batch_bound"),
		batchConfirmRequest(fixture, "batch-bound", grant, tables))
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityRequestInvalid {
		t.Fatalf("1001-table batch code = %v, want WORKSPACE_AUTHORITY_REQUEST_INVALID", err)
	}
	if got := countConfirmationsFor(t, ctx, admin, fixture.organizationID); got != 0 {
		t.Fatalf("oversized batch created %d confirmations", got)
	}
	// The bound is enforced before any per-table command runs: no confirmation
	// receipt exists for this organization.
	var receipts int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_authority_command_receipt
		WHERE organization_id=$1 AND operation='WORKSPACE_MANAGED_CONFIRM'`, fixture.organizationID).Scan(&receipts); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 0 {
		t.Fatalf("oversized batch left %d confirmation receipts", receipts)
	}
}
