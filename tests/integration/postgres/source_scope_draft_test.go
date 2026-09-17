package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestSourceScopeDraftChainIsTenantIsolatedAndFailClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	insertSourceScopeDraftChain(t, ctx, admin, "org_beta", "usr_bob", "beta", "")

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	for _, tableName := range sourceScopeTenantTables() {
		var count int
		if err := app.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
			t.Fatalf("unscoped %s: %v", tableName, err)
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
	for _, tableName := range sourceScopeTenantTables() {
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
			t.Fatalf("scoped %s: %v", tableName, err)
		}
		if count != 1 {
			t.Fatalf("alpha %s count = %d, want 1", tableName, count)
		}
	}
	var activeRevision, activatedAt any
	var scopeStatus, activationStatus, discoveryStatus, contractVersion string
	if err := tx.QueryRow(ctx, `
		SELECT s.active_revision, s.status, a.status, a.activated_at,
		       d.status, r.scope_contract_version
		FROM public.source_scope AS s
		JOIN public.source_scope_revision AS r
		  ON r.organization_id = s.organization_id
		 AND r.source_scope_id = s.id AND r.revision = s.latest_revision
		JOIN public.source_scope_activation AS a
		  ON a.organization_id = r.organization_id
		 AND a.source_scope_id = r.source_scope_id
		 AND a.source_scope_revision = r.revision
		JOIN public.source_discovered_scope AS d
		  ON d.organization_id = r.organization_id
		 AND d.id = r.discovered_scope_id
	`).Scan(&activeRevision, &scopeStatus, &activationStatus, &activatedAt,
		&discoveryStatus, &contractVersion); err != nil {
		t.Fatal(err)
	}
	if activeRevision != nil || activatedAt != nil || scopeStatus != "DRAFT" ||
		activationStatus != "DRAFT" || discoveryStatus != "ACTIVE" || contractVersion != "1.2" {
		t.Fatalf("unexpected inert state active=%v activated=%v scope=%s activation=%s discovery=%s contract=%s",
			activeRevision, activatedAt, scopeStatus, activationStatus, discoveryStatus, contractVersion)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	for _, tableName := range sourceScopeTenantTables() {
		for privilege, want := range map[string]bool{
			"SELECT": true, "INSERT": false, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		} {
			var got bool
			if err := admin.QueryRow(ctx,
				"SELECT has_table_privilege('knowvault_app', $1, $2)",
				"public."+tableName, privilege).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("knowvault_app %s on %s = %v, want %v", privilege, tableName, got, want)
			}
		}
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s does not FORCE RLS", tableName)
		}
	}
	for _, signature := range []string{
		"app.source_keyed_digest_matches_version(text,bigint)",
		"app.source_scope_revision_resource_id(text,text,bigint)",
		"app.source_scope_revision_policy_guard()",
	} {
		var canExecute bool
		if err := admin.QueryRow(ctx,
			"SELECT has_function_privilege('knowvault_app', $1, 'EXECUTE')",
			signature).Scan(&canExecute); err != nil {
			t.Fatal(err)
		}
		if canExecute {
			t.Fatalf("runtime role unexpectedly has EXECUTE on %s", signature)
		}
	}
	assertSourceRuntimeWriteRejected(t, ctx, app, "org_alpha", `
		INSERT INTO public.source_scope (
			organization_id, id, connection_id, discovered_scope_id,
			source_type, latest_revision, created_by
		) VALUES (
			'org_alpha', 'scope_runtime', 'conn_alpha', 'discovery_alpha',
			'FOLDER', 1, 'usr_alice'
		)
	`)
}

func TestSourceScopeSchemaContainsNoRawExternalIdentity(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	for _, forbidden := range []string{
		"external_scope_id", "raw_identity", "identity_plaintext", "display_metadata_json", "scope_config_json",
	} {
		var count int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM information_schema.columns
			WHERE table_schema = 'public'
			  AND table_name IN ('source_discovered_scope', 'source_scope', 'source_scope_revision')
			  AND column_name = $1
		`, forbidden).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("source scope schema persists forbidden raw field %q", forbidden)
		}
	}
}

func TestSourceScopeExactTuplesRejectForgery(t *testing.T) {
	for _, fault := range []string{
		"wrong_discovery", "wrong_digest", "wrong_key_version", "wrong_artifact",
		"wrong_connection", "wrong_access_mode", "wrong_object_limit", "wrong_byte_limit",
		"wrong_max_object_bytes", "access_mode_not_allowed",
		"missing_source_acl_capability", "purged_discovery",
	} {
		fault := fault
		t.Run(fault, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			assertSourceScopeDraftChainRejected(t, ctx, admin, "org_alpha", "usr_alice", fault)
		})
	}
}

func TestSourceScopeRowsAreImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetPreCatalogDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	for label, statement := range map[string]string{
		"discovery":  `UPDATE public.source_discovered_scope SET discovered_at = discovered_at + interval '1 second' WHERE organization_id = 'org_alpha'`,
		"scope":      `UPDATE public.source_scope SET status = 'DRAFT' WHERE organization_id = 'org_alpha'`,
		"revision":   `UPDATE public.source_scope_revision SET object_limit = 2 WHERE organization_id = 'org_alpha'`,
		"activation": `UPDATE public.source_scope_activation SET changed_at = changed_at + interval '1 second' WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := admin.Exec(ctx, statement); err == nil {
			t.Fatalf("%s mutation unexpectedly succeeded", label)
		}
	}
}

func TestSourceScopeHardDeleteRequiresExactChildFirstOrder(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	if _, err := admin.Exec(ctx, `DELETE FROM public.source_scope_activation WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("scope activation deleted for active tenant")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET status = 'DELETING' WHERE id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.source_discovered_scope WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("discovery deleted before dependent scope")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.source_scope_revision WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("scope revision deleted before activation")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range []string{
		`DELETE FROM public.source_scope_activation WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_scope_revision WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_scope WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.source_discovered_scope WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("ordered scope hard-delete: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit scope hard-delete: %v", err)
	}
}

func insertSourceScopeDraftChain(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, suffix, fault string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertSourceScopeDraftChainInTx(ctx, tx, organizationID, ownerID, suffix, fault); err != nil {
		t.Fatalf("insert source scope draft chain: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit source scope draft chain: %v", err)
	}
}

func assertSourceScopeDraftChainRejected(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, fault string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := insertSourceScopeDraftChainInTx(ctx, tx, organizationID, ownerID, fault, fault); err != nil {
		return
	}
	if err := tx.Commit(ctx); err == nil {
		t.Fatalf("forged source scope chain %q committed", fault)
	}
}

func insertSourceScopeDraftChainInTx(ctx context.Context, tx pgx.Tx, organizationID, ownerID, suffix, fault string) error {
	connectionFault := ""
	if fault == "access_mode_not_allowed" {
		connectionFault = "workspace_only"
	}
	if fault == "missing_source_acl_capability" {
		connectionFault = "missing_source_acl_capability"
	}
	if err := insertSourceDraftChainInTx(ctx, tx, organizationID, ownerID, suffix, connectionFault); err != nil {
		return err
	}
	connectionID := "conn_" + suffix
	// Discovery and scope IDs are server-generated opaque references. They are
	// intentionally unrelated to provider-native identity or caller labels.
	discoveryID := "discovered_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	scopeID := "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	identityArtifactID := "artifact_identity_" + suffix
	displayArtifactID := "artifact_display_" + suffix
	configArtifactID := "artifact_scope_config_" + suffix
	identityDigest := "hmac-sha256:k1:" + strings.Repeat("1", 64)
	identityKeyVersion := int64(1)
	revisionDiscoveryID := discoveryID
	revisionConnectionID := connectionID
	accessMode := "SOURCE_ENFORCED"
	objectLimit := int64(500)
	byteLimit := int64(500000)
	maxObjectBytes := int64(100000)
	configResourceFault := false

	switch fault {
	case "workspace_managed":
		accessMode = "WORKSPACE_MANAGED"
	case "wrong_discovery":
		revisionDiscoveryID = "discovery_missing"
	case "wrong_digest":
		identityDigest = "hmac-sha256:k1:" + strings.Repeat("2", 64)
	case "wrong_key_version":
		identityKeyVersion = 2
	case "wrong_artifact":
		configResourceFault = true
	case "wrong_connection":
		revisionConnectionID = "conn_missing"
	case "wrong_access_mode":
		accessMode = "NOT_ALLOWED"
	case "wrong_object_limit":
		objectLimit = 1001
	case "wrong_byte_limit":
		byteLimit = 1000001
	case "wrong_max_object_bytes":
		maxObjectBytes = 100001
	}

	identityHash := "sha256:" + strings.Repeat("4", 64)
	displayHash := "sha256:" + strings.Repeat("5", 64)
	configHash := "sha256:" + strings.Repeat("6", 64)
	discoveryResourceID := discoveryID
	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1, $2, 1)`, organizationID, scopeID).Scan(&scopeResourceID); err != nil {
		return err
	}
	if configResourceFault {
		scopeResourceID = "sha256:" + strings.Repeat("7", 64)
	}
	for _, artifact := range []struct {
		id, ownerTable, ownerColumn, resourceType, resourceID, field, hash, nonce string
	}{
		{identityArtifactID, "source_discovered_scope", "identity_artifact_id", "SOURCE_SCOPE_IDENTITY", discoveryResourceID, "EXTERNAL_SCOPE_IDENTITY", identityHash, "31"},
		{displayArtifactID, "source_discovered_scope", "display_metadata_artifact_id", "SOURCE_SCOPE_METADATA", discoveryResourceID, "DISPLAY_METADATA", displayHash, "32"},
		{configArtifactID, "source_scope_revision", "scope_config_artifact_id", "SOURCE_SCOPE_CONFIG", scopeResourceID, "SCOPE_CONFIG", configHash, "33"},
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
			return err
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
		"hmac-sha256:k1:"+strings.Repeat("1", 64), identityArtifactID,
		identityHash, displayArtifactID, displayHash); err != nil {
		return err
	}
	if fault == "purged_discovery" {
		if _, err := tx.Exec(ctx, `
			UPDATE public.encrypted_artifact
			SET ciphertext = NULL, wrapped_dek = NULL, purged_at = transaction_timestamp()
			WHERE organization_id = $1 AND id = $2
		`, organizationID, identityArtifactID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope (
			organization_id, id, connection_id, discovered_scope_id,
			source_type, latest_revision, created_by
		) VALUES ($1, $2, $3, $4, 'FOLDER', 1, $5)
	`, organizationID, scopeID, connectionID, discoveryID, ownerID); err != nil {
		return err
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
			$1, $2, 1, $3, 1, $4, $5, $6, 'FOLDER', $7, $8,
			'1.2', $9, 300, 600, 300, $10, $11, $12, $13
		)
	`, organizationID, scopeID, revisionConnectionID, revisionDiscoveryID,
		identityDigest, identityKeyVersion, configArtifactID, configHash,
		accessMode, objectLimit, byteLimit, maxObjectBytes, ownerID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO public.source_scope_activation (
			organization_id, source_scope_id, source_scope_revision, revision, status
		) VALUES ($1, $2, 1, 1, 'DRAFT')
	`, organizationID, scopeID)
	return err
}

func sourceScopeTenantTables() []string {
	return []string{
		"source_discovered_scope", "source_scope", "source_scope_revision", "source_scope_activation",
	}
}
