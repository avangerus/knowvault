package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	testConnectorAgentA = "agent_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	testConnectorAgentB = "agent_01ARZ3NDEKTSV4RRFFQ69G5FAW"
	testCredentialRef   = "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV"
)

func TestSourceConnectionDraftChainIsFailClosedAndTenantReadable(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	insertSourceDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	insertSourceDraftChain(t, ctx, admin, "org_beta", "usr_bob", "beta", "")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	for _, tableName := range sourceTenantTables() {
		var count int
		if err := app.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
			t.Fatalf("unscoped %s query: %v", tableName, err)
		}
		if count != 0 {
			t.Fatalf("unscoped %s returned %d rows", tableName, count)
		}
	}

	tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
	for _, tableName := range sourceTenantTables() {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
			t.Fatalf("scoped %s query: %v", tableName, err)
		}
		if count != 1 {
			t.Fatalf("alpha %s count = %d, want 1", tableName, count)
		}
	}
	var activeRevision *int64
	var connectionStatus, trustStatus string
	if err := tx.QueryRow(ctx, `
		SELECT c.active_revision, c.status, p.status
		FROM public.source_connection AS c
		JOIN public.source_connection_revision AS r
		  ON r.organization_id = c.organization_id
		 AND r.connection_id = c.id AND r.revision = c.latest_revision
		JOIN public.source_connection_trust_projection AS p
		  ON p.organization_id = r.organization_id
		 AND p.trust_record_id = r.trust_record_id
	`).Scan(&activeRevision, &connectionStatus, &trustStatus); err != nil {
		t.Fatal(err)
	}
	if activeRevision != nil || connectionStatus != "DRAFT" || trustStatus != "DRAFT" {
		t.Fatalf("unexpected authority state: active=%v connection=%s trust=%s", activeRevision, connectionStatus, trustStatus)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	for _, tableName := range append([]string{"connector_capability_profile"}, sourceTenantTables()...) {
		for privilege, want := range map[string]bool{
			"SELECT": true, "INSERT": false, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		} {
			var got bool
			if err := admin.QueryRow(ctx, "SELECT has_table_privilege('knowvault_app', $1, $2)", "public."+tableName, privilege).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("knowvault_app %s on %s = %v, want %v", privilege, tableName, got, want)
			}
		}
	}
	for _, tableName := range sourceTenantTables() {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c
			JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s does not FORCE RLS", tableName)
		}
	}
	var canExecute bool
	if err := admin.QueryRow(ctx, `
		SELECT has_function_privilege(
			'knowvault_app', 'app.source_generated_id_is_valid(text,text)', 'EXECUTE')
	`).Scan(&canExecute); err != nil {
		t.Fatal(err)
	}
	if canExecute {
		t.Fatal("runtime role unexpectedly has EXECUTE on source checkpoint helper")
	}
	assertSourceRuntimeWriteRejected(t, ctx, app, "org_alpha", `
		INSERT INTO public.source_connection (
			organization_id, id, type, name, latest_revision, created_by
		) VALUES ('org_alpha', 'conn_runtime', 'FOLDER', 'runtime', 1, 'usr_alice')
	`)
}

func TestSourceConnectionRevisionAndTrustAreImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetPreCatalogDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	for label, statement := range map[string]string{
		"capability": `UPDATE public.connector_capability_profile SET stable_object_ids = false WHERE id = 'cap_alpha'`,
		"revision":   `UPDATE public.source_connection_revision SET max_scope_objects = 2 WHERE organization_id = 'org_alpha'`,
		"trust":      `UPDATE public.source_connection_trust_record SET expires_at = expires_at + interval '1 hour' WHERE organization_id = 'org_alpha'`,
		"projection": `UPDATE public.source_connection_trust_projection SET changed_at = changed_at + interval '1 second' WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := admin.Exec(ctx, statement); err == nil {
			t.Fatalf("%s mutation unexpectedly succeeded", label)
		}
	}
}

func TestSourceConnectionExactTuplesRejectForgery(t *testing.T) {
	for _, fault := range []string{"wrong_profile", "wrong_agent", "wrong_artifact"} {
		fault := fault
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			assertSourceDraftChainRejected(t, ctx, admin, "org_alpha", "usr_alice", fault)
		})
	}
}

func TestSourceConnectionCheckpointRejectsAuthorityAndUnsafeReferences(t *testing.T) {
	for _, fault := range []string{"active_revision", "ready_projection", "uri_credential"} {
		fault := fault
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			admin := resetPreCatalogDatabase(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			assertSourceDraftChainRejected(t, ctx, admin, "org_alpha", "usr_alice", fault)
		})
	}
}

func TestSourceConnectionHardDeleteRequiresTenantDeletionState(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	if _, err := admin.Exec(ctx, `
		DELETE FROM public.source_connection_trust_projection
		WHERE organization_id = 'org_alpha'
	`); err == nil {
		t.Fatal("source trust projection was deleted for an active tenant")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET status = 'DELETING' WHERE id = 'org_alpha'`); err != nil {
		t.Fatalf("mark tenant deleting: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range []string{
		`DELETE FROM public.source_connection_trust_projection WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_connection_trust_record WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_connection_revision WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_connection WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("hard-delete source row: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit source hard-delete: %v", err)
	}
}

func insertSourceDraftChain(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, suffix, fault string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertSourceDraftChainInTx(ctx, tx, organizationID, ownerID, suffix, fault); err != nil {
		t.Fatalf("insert source draft chain: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit source draft chain: %v", err)
	}
}

func assertSourceDraftChainRejected(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, fault string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertSourceDraftChainInTx(ctx, tx, organizationID, ownerID, fault, fault); err != nil {
		return
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatalf("forged source draft chain %q committed", fault)
	}
}

func insertSourceDraftChainInTx(ctx context.Context, tx pgx.Tx, organizationID, ownerID, suffix, fault string) error {
	profileID := "cap_" + suffix
	connectionID := "conn_" + suffix
	artifactID := "artifact_trust_" + suffix
	trustRecordID := "trust_" + suffix
	buildID := "folder-build-" + suffix
	revisionBuildID := buildID
	credentialReference := testCredentialRef
	executionTarget := "CENTRAL_WORKER"
	var revisionAgentID, trustAgentID any
	activeRevision := any(nil)
	projectionStatus := "DRAFT"
	allowedAccessModes := `["WORKSPACE_MANAGED","SOURCE_ENFORCED"]`
	stableObjectIDs := true
	itemLevelACL := true
	aclRefresh := true
	if fault == "wrong_profile" {
		revisionBuildID = "other-build-" + suffix
	}
	if fault == "wrong_agent" {
		executionTarget = "CONNECTOR_AGENT"
		revisionAgentID = testConnectorAgentA
		trustAgentID = testConnectorAgentB
	}
	if fault == "active_revision" {
		activeRevision = int64(1)
	}
	if fault == "ready_projection" {
		projectionStatus = "VERIFIED"
	}
	if fault == "uri_credential" {
		credentialReference = "vault://tenant/source/password"
	}
	if fault == "workspace_only" {
		allowedAccessModes = `["WORKSPACE_MANAGED"]`
	}
	if fault == "missing_source_acl_capability" {
		itemLevelACL = false
	}

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
			$6, true, true, false, $7, $8, true, true, true, true,
			$5, transaction_timestamp()
		)
	`, profileID, profileHash, buildID, artifactHash, suiteHash,
		stableObjectIDs, itemLevelACL, aclRefresh); err != nil {
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
	if fault == "wrong_artifact" {
		resourceID = "sha256:" + strings.Repeat("e", 64)
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
			decode(repeat('ab', 17), 'hex'), 1, decode(repeat('6e', 12), 'hex'),
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
	`, organizationID, connectionID, credentialReference, revisionBuildID,
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
		) VALUES ($1, $2, 1, $3)
	`, organizationID, trustRecordID, projectionStatus)
	return err
}

func assertSourceRuntimeWriteRejected(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, statement string) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, organizationID)
	if _, err := tx.Exec(ctx, statement); err == nil {
		t.Fatalf("runtime role unexpectedly permitted source mutation %q", statement)
	}
}

func sourceTenantTables() []string {
	return []string{
		"source_connection",
		"source_connection_revision",
		"source_connection_trust_record",
		"source_connection_trust_projection",
	}
}
