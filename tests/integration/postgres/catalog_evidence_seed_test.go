package postgres_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
)

var s1dKEK = []byte("s1d-kek-32-bytes-abcdefghijklmno")

func s1dCodec(t *testing.T, organizationID string) *artifactcrypto.Codec {
	t.Helper()
	provider, err := artifactcrypto.NewMountedProvider(organizationID, s1dKEKRef, 1, s1dKEK)
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	codec, err := artifactcrypto.NewCodec(provider)
	if err != nil {
		t.Fatalf("codec: %v", err)
	}
	return codec
}

func openStore(t *testing.T, ctx context.Context, role, applicationRole string) *database.Store {
	t.Helper()
	parsed, err := url.Parse(testDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	parsed.User = url.UserPassword(role, workerPassword)
	store, err := database.Open(ctx, database.Config{URL: parsed.String(), ApplicationRole: applicationRole, MaxConnections: 8})
	if err != nil {
		t.Fatalf("open store as %s: %v", applicationRole, err)
	}
	t.Cleanup(store.Close)
	return store
}

func workerAccess(t *testing.T, organizationID string) database.AccessContext {
	t.Helper()
	return database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_worker", RequestID: "req_worker"}
}

func writeS1dFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func seedS1dOrg(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// organization.owner_principal_id and principal.organization_id form a
	// deferrable cycle; both must be inserted in one transaction.
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization (id, name, status, region, owner_principal_id)
		VALUES ($1, $1, 'ACTIVE', 'eu', $2)`, organizationID, ownerID); err != nil {
		t.Fatalf("seed organization: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, ownerID, organizationID); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ($1, $2, $3, 'OWNER', 1, $3)`, "ora_"+organizationID, organizationID, ownerID); err != nil {
		t.Fatalf("seed owner role: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit org seed: %v", err)
	}
}

// seedS1dScope seeds a fully activated WORKSPACE_MANAGED FOLDER scope whose
// scope-config and trust-profile artifacts carry real sealed content the worker
// decrypts. The connection trust projection is VERIFIED so activation may begin.
func seedS1dScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool, codec *artifactcrypto.Codec, organizationID, ownerID string) string {
	t.Helper()
	const (
		connectionID   = "conn_s1d"
		capabilityID   = "cap_s1d"
		trustRecordID  = "trust_s1d"
		trustArtifact  = "artifact_trust_s1d"
		discoveryID    = "discovered_01ARZ3NDEKTSV4RRFFQ69G5FAV"
		identityArt    = "artifact_identity_s1d"
		displayArt     = "artifact_display_s1d"
		configArtifact = "artifact_scope_config_s1d"
		buildID        = "folder-build-s1d"
	)
	folderConfigJSON := []byte(`{"root_alias":"docs-root","relative_root":"projects/alpha","path_matcher_version":"scope-glob-v1","recursive":true,"include_globs":["**/*"],"exclude_globs":[],"max_file_bytes":1048576,"ocr_mode":"OFF","follow_symlinks":false,"formats":["TXT","MARKDOWN","SOURCE_CODE","CSV","JSON","XML","HTML","EML","DOCX","PPTX","XLSX","PDF"]}`)
	trustJSON := []byte(`{"schema_version":"source-folder-trust-v1","platform":"POSIX","root_alias":"docs-root","root_identity":"vol-1"}`)

	profileHash := "sha256:" + strings.Repeat("a", 64)
	artifactHash := "sha256:" + strings.Repeat("b", 64)
	suiteHash := "sha256:" + strings.Repeat("c", 64)
	identityDigest := "hmac-sha256:k1:" + strings.Repeat("1", 64)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var connectionResourceID, scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_connection_revision_resource_id($1,$2,1)`, organizationID, connectionID).Scan(&connectionResourceID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1,$2,1)`, organizationID, s1dScopeID).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}

	trustHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceConnectionTrustConfig, organizationID,
		trustArtifact, connectionResourceID, "source_connection_revision", "trust_profile_artifact_id",
		"SOURCE_TRUST_CONFIG", "TRUST_CONFIG", trustJSON)
	configHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeConfig, organizationID,
		configArtifact, scopeResourceID, "source_scope_revision", "scope_config_artifact_id",
		"SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", folderConfigJSON)

	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed step: %v\n%s", err, sql)
		}
	}
	exec(`INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
		connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
		item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ($1,$2,$3,'FOLDER','1.0.0',$4,true,true,true,false,true,true,true,true,true,true,$5,transaction_timestamp())`,
		capabilityID, profileHash, buildID, artifactHash, suiteHash)
	exec(`INSERT INTO public.source_connection (organization_id, id, type, name, latest_revision, active_revision, status, created_by)
		VALUES ($1,$2,'FOLDER',$2,1,NULL,'DRAFT',$3)`, organizationID, connectionID, ownerID)
	exec(`INSERT INTO public.source_connection_revision (organization_id, connection_id, revision, credential_reference,
		connector_build_id, connector_type, capability_profile_id, capability_profile_hash, connector_agent_id, execution_target,
		trust_record_id, trust_profile_artifact_id, trust_profile_hash, connector_version, connector_artifact_hash,
		connector_contract_suite_hash, connector_verified_at, allowed_access_modes_json, max_scope_objects, max_scope_bytes, max_object_bytes, created_by)
		VALUES ($1,$2,1,'cred_01ARZ3NDEKTSV4RRFFQ69G5FAV',$3,'FOLDER',$4,$5,NULL,'CENTRAL_WORKER',$6,$7,$8,'1.0.0',$9,$10,transaction_timestamp(),
		'["WORKSPACE_MANAGED"]'::jsonb,1000,1000000,100000,$11)`,
		organizationID, connectionID, buildID, capabilityID, profileHash, trustRecordID, trustArtifact, trustHash, artifactHash, suiteHash, ownerID)
	exec(`INSERT INTO public.source_connection_trust_record (organization_id, id, connection_id, connection_revision,
		connector_agent_id, execution_target, trust_profile_artifact_id, trust_profile_hash, verified_at, expires_at)
		VALUES ($1,$2,$3,1,NULL,'CENTRAL_WORKER',$4,$5,transaction_timestamp(),transaction_timestamp()+interval '1 day')`,
		organizationID, trustRecordID, connectionID, trustArtifact, trustHash)
	exec(`INSERT INTO public.source_connection_trust_projection (organization_id, trust_record_id, revision, status)
		VALUES ($1,$2,1,'VERIFIED')`, organizationID, trustRecordID)

	// The scope identity and display artifacts carry real sealed content too:
	// every encrypted_artifact row must hold a genuinely wrapped DEK, so
	// KEK rotation (ADR-0070) can re-wrap every row of the window. The plaintexts
	// are inert but shape-correct, and the scope row's plaintext hashes name
	// exactly the sealed artifacts.
	identityJSON := []byte(`{"schema_version":"source-scope-identity-v1","external_id":"discovered-01ARZ3NDEKTSV4RRFFQ69G5FAV"}`)
	displayJSON := []byte(`{"schema_version":"source-scope-display-v1","display_name":"Alpha docs root"}`)
	identityHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeIdentity, organizationID,
		identityArt, discoveryID, "source_discovered_scope", "identity_artifact_id",
		"SOURCE_SCOPE_IDENTITY", "EXTERNAL_SCOPE_IDENTITY", identityJSON)
	displayHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeDisplayMetadata, organizationID,
		displayArt, discoveryID, "source_discovered_scope", "display_metadata_artifact_id",
		"SOURCE_SCOPE_METADATA", "DISPLAY_METADATA", displayJSON)
	exec(`INSERT INTO public.source_discovered_scope (organization_id, id, connection_id, connection_revision, source_type,
		identity_digest, identity_digest_key_version, identity_artifact_id, identity_plaintext_hash, display_metadata_artifact_id, display_metadata_hash)
		VALUES ($1,$2,$3,1,'FOLDER',$4,1,$5,$6,$7,$8)`, organizationID, discoveryID, connectionID, identityDigest, identityArt, identityHash, displayArt, displayHash)
	exec(`INSERT INTO public.source_scope (organization_id, id, connection_id, discovered_scope_id, source_type, latest_revision, created_by)
		VALUES ($1,$2,$3,$4,'FOLDER',1,$5)`, organizationID, s1dScopeID, connectionID, discoveryID, ownerID)
	exec(`INSERT INTO public.source_scope_revision (organization_id, source_scope_id, revision, connection_id, connection_revision,
		discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version, source_type, scope_config_artifact_id, scope_config_hash,
		scope_contract_version, access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
		object_limit, byte_limit, max_object_bytes, created_by)
		VALUES ($1,$2,1,$3,1,$4,$5,1,'FOLDER',$6,$7,'1.2','WORKSPACE_MANAGED',300,600,NULL,1000,1000000,100000,$8)`,
		organizationID, s1dScopeID, connectionID, discoveryID, identityDigest, configArtifact, configHash, ownerID)
	exec(`INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ($1,$2,1,1,'DRAFT')`, organizationID, s1dScopeID)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit seed: %v", err)
	}
	return configHash
}

// seedS1dSecondScope adds a second FOLDER scope on the same connection whose
// globs also match the same file, so an overlapping-scope sync must resolve to
// one shared SourceObject with two ACTIVE memberships. Returns the scope id and
// its revision-1 scope-config hash (the latter feeds the scope's authority seed).
func seedS1dSecondScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool, codec *artifactcrypto.Codec, organizationID, ownerID string) (string, string) {
	t.Helper()
	const (
		connectionID   = "conn_s1d"
		scopeID        = "scope_02ARZ3NDEKTSV4RRFFQ69G5FAV"
		discoveryID    = "discovered_02ARZ3NDEKTSV4RRFFQ69G5FAV"
		identityArt    = "artifact_identity_s1d2"
		displayArt     = "artifact_display_s1d2"
		configArtifact = "artifact_scope_config_s1d2"
	)
	folderConfigJSON := []byte(`{"root_alias":"docs-root","relative_root":"projects/alpha","path_matcher_version":"scope-glob-v1","recursive":true,"include_globs":["**/*"],"exclude_globs":[],"max_file_bytes":1048576,"ocr_mode":"OFF","follow_symlinks":false,"formats":["TXT","MARKDOWN","SOURCE_CODE","CSV","JSON","XML"]}`)
	identityDigest := "hmac-sha256:k1:" + strings.Repeat("2", 64)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1,$2,1)`, organizationID, scopeID).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}
	configHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeConfig, organizationID,
		configArtifact, scopeResourceID, "source_scope_revision", "scope_config_artifact_id",
		"SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", folderConfigJSON)
	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed second scope: %v\n%s", err, sql)
		}
	}
	identityJSON := []byte(`{"schema_version":"source-scope-identity-v1","external_id":"discovered-02ARZ3NDEKTSV4RRFFQ69G5FAV"}`)
	displayJSON := []byte(`{"schema_version":"source-scope-display-v1","display_name":"Alpha docs root (second scope)"}`)
	identityHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeIdentity, organizationID,
		identityArt, discoveryID, "source_discovered_scope", "identity_artifact_id",
		"SOURCE_SCOPE_IDENTITY", "EXTERNAL_SCOPE_IDENTITY", identityJSON)
	displayHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeDisplayMetadata, organizationID,
		displayArt, discoveryID, "source_discovered_scope", "display_metadata_artifact_id",
		"SOURCE_SCOPE_METADATA", "DISPLAY_METADATA", displayJSON)
	exec(`INSERT INTO public.source_discovered_scope (organization_id, id, connection_id, connection_revision, source_type,
		identity_digest, identity_digest_key_version, identity_artifact_id, identity_plaintext_hash, display_metadata_artifact_id, display_metadata_hash)
		VALUES ($1,$2,$3,1,'FOLDER',$4,1,$5,$6,$7,$8)`, organizationID, discoveryID, connectionID, identityDigest, identityArt, identityHash, displayArt, displayHash)
	exec(`INSERT INTO public.source_scope (organization_id, id, connection_id, discovered_scope_id, source_type, latest_revision, created_by)
		VALUES ($1,$2,$3,$4,'FOLDER',1,$5)`, organizationID, scopeID, connectionID, discoveryID, ownerID)
	exec(`INSERT INTO public.source_scope_revision (organization_id, source_scope_id, revision, connection_id, connection_revision,
		discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version, source_type, scope_config_artifact_id, scope_config_hash,
		scope_contract_version, access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
		object_limit, byte_limit, max_object_bytes, created_by)
		VALUES ($1,$2,1,$3,1,$4,$5,1,'FOLDER',$6,$7,'1.2','WORKSPACE_MANAGED',300,600,NULL,1000,1000000,100000,$8)`,
		organizationID, scopeID, connectionID, discoveryID, identityDigest, configArtifact, configHash, ownerID)
	exec(`INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ($1,$2,1,1,'DRAFT')`, organizationID, scopeID)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit second scope: %v", err)
	}
	return scopeID, configHash
}

// seedS1dWorkspaceBinding seeds the full S1d authority chain for the S1d scope
// and returns an authorityOpsFixture pointing at it. The grant and the
// confirmation are minted directly on the exact binding tuple so the worker's
// claim-time liveness re-check (000018 s5) admits the sync; tests that must
// prove the production minting path re-mint through the repository on top.
func seedS1dWorkspaceBinding(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, ownerID, viewerPrincipal, scopeConfigHash string) authorityOpsFixture {
	t.Helper()
	return seedS1dScopeAuthority(t, ctx, admin, organizationID, workspaceID, ownerID, viewerPrincipal,
		s1dScopeID, scopeConfigHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		"grant_s1d_admin", "confirmation_s1d_admin")
}

// seedS1dScopeAuthority mints the full authority chain a worker sync needs at
// claim time (000018 s3/s5): a workspace at its current revision with owner and
// viewer members, the organization policy revision, an enabled WORKSPACE_MANAGED
// binding for the scope at the given revision and config hash, the actor grant,
// and a live derived-live confirmation on the exact binding tuple — workspace
// revision, workspace configuration hash, binding, scope, scope revision, scope
// config hash and access mode — with no revocation present. Every seed that
// drives a worker sync must present such a confirmation or
// source_scope_registered_begin_sync fails closed, so a revision-2 seed calls it
// again with the new config hash (the same grant may feed both confirmations).
// The warning contract at revision 1 is pre-seeded by migration 000010. Returns
// the fixture so production-path tests share the same ids.
func seedS1dScopeAuthority(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, ownerID, viewerPrincipal, scopeID, scopeConfigHash string,
	sourceScopeRevision int64, bindingID, grantID, confirmationID string, canonicalFixture ...bool) authorityOpsFixture {
	t.Helper()
	const policyID = "policy-s1d-01ARZ3NDEKTSV4RRFFQ69G5FAV"
	wsConfigHash := "sha256:" + strings.Repeat("e", 64)
	policyHash := "sha256:" + strings.Repeat("d", 64)
	canonicalBytes := []byte("{}")
	if len(canonicalFixture) > 0 && canonicalFixture[0] {
		snapshot := workspace.Snapshot{OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: workspaceID, Status: workspace.StatusActive, OwnerPrincipalID: ownerID,
			Members:        []workspace.Member{{PrincipalID: ownerID, Role: workspace.RoleOwner}, {PrincipalID: viewerPrincipal, Role: workspace.RoleMember}},
			SourceBindings: []workspace.SourceBinding{{SourceScopeID: scopeID, SourceScopeRevision: sourceScopeRevision, ScopeConfigHash: scopeConfigHash, Enabled: true}}}
		var err error
		canonicalBytes, err = workspace.CanonicalSnapshot(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		wsConfigHash, err = workspace.ConfigurationHash(snapshot)
		if err != nil {
			t.Fatal(err)
		}
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed scope authority: %v\n%s", err, sql)
		}
	}
	exec(`INSERT INTO public.organization_policy_revision
		(organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ($1, 1, $2, $3, '2019-01-01T00:00:00Z', $4)`, organizationID, policyID, policyHash, ownerID)
	exec(`INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, viewerPrincipal, organizationID)
	exec(`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
		VALUES ($1, $2, $1, 'ACTIVE', $3, 1)`, workspaceID, organizationID, ownerID)
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, 1, $3, $4)`, organizationID, workspaceID, wsConfigHash, ownerID)
	// The snapshot is the inert '{}' fixture, intentionally: the exact-set
	// guard (000008) compares canonical bindings against the projection rows,
	// and every comparison over '{}' evaluates NULL, so the guard stays
	// silent. These seeds verify the authority/liveness tuples, not the
	// canonical document itself — the registration seed builds the real
	// canonical snapshot through the production serializer.
	exec(`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, 1, $3, $4)`, organizationID, workspaceID, wsConfigHash, canonicalBytes)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_owner_s1d', $1, $2, $3, 'OWNER', 1, $3)`, organizationID, workspaceID, ownerID)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_viewer_s1d', $1, $2, $3, 'MEMBER', 1, $4)`, organizationID, workspaceID, viewerPrincipal, ownerID)
	exec(`INSERT INTO public.workspace_source (organization_id, id, workspace_id, source_scope_id, added_by)
		VALUES ($1, $2, $3, $4, $5)`, organizationID, bindingID, workspaceID, scopeID, ownerID)
	exec(`INSERT INTO public.workspace_revision_source
		(organization_id, workspace_id, workspace_revision, workspace_configuration_hash, workspace_source_id,
		 source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
		VALUES ($1, $2, 1, $3, $4, $5, $6, $7, 'WORKSPACE_MANAGED', true)`,
		organizationID, workspaceID, wsConfigHash, bindingID, scopeID, sourceScopeRevision, scopeConfigHash)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit scope authority seed: %v", err)
	}
	// The grant and the confirmation must be minted through the production
	// repository: authority rows carry canonical result bytes plus a command
	// receipt written in the same transaction (000011 §4.1), so a raw INSERT
	// cannot produce a live confirmation. grantID/confirmationID name the
	// idempotency keys of the minting commands.
	fixture := authorityOpsFixture{
		organizationID: organizationID, ownerID: ownerID, workspaceID: workspaceID,
		policyID: policyID, policyNumber: 1, workspaceRevision: 1, workspaceConfHash: wsConfigHash,
		workspaceSourceID: bindingID, sourceScopeID: scopeID, sourceScopeRevision: sourceScopeRevision,
		scopeConfigHash: scopeConfigHash,
	}
	store := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, store, fixture, grantID)
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_seed_confirm_"+confirmationID),
		confirmRuntimeRequest(fixture, grant, confirmationID)); err != nil {
		t.Fatalf("seed confirm managed source: %v", err)
	}
	return fixture
}

// seedS1dScopeBinding adds a further live confirmation for a scope that already
// has its workspace core (seedS1dScopeAuthority): a workspace_source row for a
// second overlapping scope at revision 1, or a later revision of an existing
// binding via the cutover model of 000016/000018 — the activation liveness
// check joins the workspace at its CURRENT revision, so a scope cutover moves
// the workspace to a fresh revision carrying the new scope-revision projection
// while the binding itself is reused (a scope binds at most one workspace_source,
// 000008 §2). The scope-config hash is read back from source_scope_revision, so
// the confirmation is always on the exact tuple the sync target resolves to.
// Used by the overlapping-scope and cutover seeds, whose sync target is a
// different scope or a higher revision and therefore needs its own confirmation
// at claim time (000018 s5).
func seedS1dScopeBinding(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, workspaceID, ownerID, scopeID string,
	sourceScopeRevision int64, bindingID, grantID, confirmationID string) {
	t.Helper()
	var scopeConfigHash string
	if err := admin.QueryRow(ctx, `SELECT scope_config_hash FROM public.source_scope_revision
		WHERE organization_id=$1 AND source_scope_id=$2 AND revision=$3`,
		organizationID, scopeID, sourceScopeRevision).Scan(&scopeConfigHash); err != nil {
		t.Fatalf("read scope config hash for authority seed: %v", err)
	}
	wsRevision := int64(1)
	wsConfHash := "sha256:" + strings.Repeat("e", 64)
	var workspaceSourceID string
	err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
		organizationID, workspaceID, scopeID).Scan(&workspaceSourceID)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		workspaceSourceID = bindingID
	case err != nil:
		t.Fatal(err)
	default:
		// Later revision of an existing binding: cutover to a fresh workspace
		// revision (activation_confirmed requires current_revision to match the
		// confirmation's workspace revision).
		wsRevision = sourceScopeRevision
		wsConfHash = "sha256:" + strings.Repeat("f", 64)
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed scope binding: %v\n%s", err, sql)
		}
	}
	if workspaceSourceID == bindingID {
		exec(`INSERT INTO public.workspace_source (organization_id, id, workspace_id, source_scope_id, added_by)
			VALUES ($1, $2, $3, $4, $5)`, organizationID, bindingID, workspaceID, scopeID, ownerID)
	}
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		organizationID, workspaceID, wsRevision, wsConfHash, ownerID)
	// Cutover revisions reuse the same inert '{}' fixture: the exact-set guard
	// compares canonical bindings against projection rows, and over '{}' every
	// comparison evaluates NULL, so the guard stays silent. The cutover seeds
	// prove the binding reuse and the claim-time liveness tuple, not the
	// canonical document of the carried revision.
	exec(`INSERT INTO public.workspace_revision_snapshot
		(organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, $3, $4, decode('7b7d','hex')) ON CONFLICT DO NOTHING`,
		organizationID, workspaceID, wsRevision, wsConfHash)
	exec(`INSERT INTO public.workspace_revision_source
		(organization_id, workspace_id, workspace_revision, workspace_configuration_hash, workspace_source_id,
		 source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'WORKSPACE_MANAGED', true)`,
		organizationID, workspaceID, wsRevision, wsConfHash, workspaceSourceID, scopeID, sourceScopeRevision, scopeConfigHash)
	exec(`UPDATE public.workspace SET current_revision=$3 WHERE organization_id=$1 AND id=$2`,
		organizationID, workspaceID, wsRevision)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit scope binding seed: %v", err)
	}
	// The grant and the confirmation are minted through the production
	// repository (000011 §4.1): authority rows require canonical result bytes
	// plus a command receipt written in the same transaction, so a raw INSERT
	// cannot produce a live confirmation. grantID/confirmationID name the
	// idempotency keys of the minting commands.
	fixture := authorityOpsFixture{
		organizationID: organizationID, ownerID: ownerID, workspaceID: workspaceID,
		policyID: "policy-s1d-01ARZ3NDEKTSV4RRFFQ69G5FAV", policyNumber: 1,
		workspaceRevision: wsRevision, workspaceConfHash: wsConfHash,
		workspaceSourceID: workspaceSourceID, sourceScopeID: scopeID, sourceScopeRevision: sourceScopeRevision,
		scopeConfigHash: scopeConfigHash,
	}
	store := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, store, fixture, grantID)
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_seed_confirm_"+confirmationID),
		confirmRuntimeRequest(fixture, grant, confirmationID)); err != nil {
		t.Fatalf("seed confirm managed source: %v", err)
	}
}

func sealArtifactTx(t *testing.T, ctx context.Context, tx pgx.Tx,
	codec *artifactcrypto.Codec, field artifactcrypto.OwnerField, organizationID, artifactID, resourceID,
	ownerTable, ownerColumn, resourceType, fieldName string, plaintext []byte) string {
	t.Helper()
	owner, err := artifactcrypto.NewOwnerIdentity(field, organizationID, resourceID)
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	envelope, err := codec.Seal(owner, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.encrypted_artifact
		(organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
		 ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		organizationID, artifactID, ownerTable, ownerColumn, resourceType, resourceID, fieldName,
		envelope.Ciphertext(), envelope.SizeBytes(), envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(),
		envelope.KEKReference(), envelope.KEKVersion(), envelope.AADHash(), envelope.PlaintextHash()); err != nil {
		t.Fatalf("insert sealed artifact: %v", err)
	}
	return envelope.PlaintextHash()
}
