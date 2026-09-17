package postgres_test

// R3a-1 KV-A04 (Outcome 4): named-ref code sources proved against real
// PostgreSQL through the production ingestion publication path, the production
// evidence.Viewer inventory/whole-object read and the production workspaceapi
// MCP surfaces knowvault_grep / knowvault_read / knowvault_list_objects.
//
// The existing unit mutation tests pin the ref-scoped grep and the code-source
// mirror age over hand-made fakes (internal/platform/workspaceapi/mcp_grep_ref_test.go
// and mcp_workspace_list_test.go). This suite is the real-store proof: it seeds
// a registered GIT source scope, publishes two immutable versions of the SAME
// repository-relative path at two named refs through the production ingestion
// pipeline, and shows that
//
//  1. a ref-scoped grep for a needle present only at ref A carries the canon
//     file:lines locator (path plus 1-based line/column span) and its address
//     version names ref A exactly;
//  2. the same needle is never reported for ref B when the file differs at the
//     two refs (the canon negative control);
//  3. a ref-scoped read resolves the ref-A bytes and not the ref-B bytes (and
//     an address naming ref B resolves ref-B bytes, so the ref is not ignored);
//  4. the object inventory exposes both immutable versions as GIT_FILE objects
//     with their external_version_key and the code-source mirror age.
//
// No production semantics, route, contract, migration or dependency change; the
// test is additive and leaves every existing test byte-identical.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/observation"
)

const (
	kvA04GitConnectionID  = "conn_kva04git"
	kvA04GitCapabilityID  = "cap_kva04git"
	kvA04GitTrustRecordID = "trust_kva04git"
	kvA04GitTrustArtifact = "artifact_trust_kva04git"
	kvA04GitDiscoveryID   = "disc_01ARZ3NDEKTSV4RRFFQ69G5FZA"
	kvA04GitIdentityArt   = "artifact_identity_kva04git"
	kvA04GitDisplayArt    = "artifact_display_kva04git"
	kvA04GitConfigArt     = "artifact_scope_config_kva04git"
	kvA04GitScopeID       = "scope_01ARZ3NDEKTSV4RRFFQ69G5FZB"
	kvA04GitBuildID       = "git-build-kva04"
	kvA04GitPath          = "src/app.txt"
)

// kvA04GitResolver is the deployment-owned ObservationAdapterResolver stand-in
// for this real-store proof: it hands the ingestion pipeline the GIT observation
// adapter currently selected for the next sync (ref A first, ref B second). The
// pipeline, object/version identity, artifacts, retention and workspace binding
// are the production ones; only the connector transport is a controlled fixture.
type kvA04GitResolver struct {
	mu      sync.Mutex
	adapter observation.Adapter
}

func (resolver *kvA04GitResolver) selectAdapter(adapter observation.Adapter) {
	resolver.mu.Lock()
	resolver.adapter = adapter
	resolver.mu.Unlock()
}

func (resolver *kvA04GitResolver) Resolve(_ context.Context, _ database.AccessContext, target ingestion.ObservationAdapterTarget) (ingestion.ObservationAdapterBinding, error) {
	if target.SourceType != "GIT" {
		return ingestion.ObservationAdapterBinding{}, errors.New("kva04: unexpected source type")
	}
	resolver.mu.Lock()
	adapter := resolver.adapter
	resolver.mu.Unlock()
	if adapter == nil {
		return ingestion.ObservationAdapterBinding{}, errors.New("kva04: no ref selected to observe")
	}
	return ingestion.ObservationAdapterBinding{Adapter: adapter, Formats: map[string]bool{"TXT": true}}, nil
}

// kvA04GitAdapter is one immutable git tree observation: exactly one
// repository-relative path at one named ref.
type kvA04GitAdapter struct {
	object observation.Object
}

func (adapter kvA04GitAdapter) Kind() observation.Kind { return observation.KindGit }

func (adapter kvA04GitAdapter) Observe(ctx context.Context, request observation.Request) (observation.Page, error) {
	if err := ctx.Err(); err != nil {
		return observation.Page{}, err
	}
	object := adapter.object
	object.ObservedAt = time.Now().UTC()
	page := observation.Page{OrganizationID: request.OrganizationID, Kind: observation.KindGit,
		CoverageComplete: true, Objects: []observation.Object{object}}
	if err := page.Validate(request); err != nil {
		return observation.Page{}, err
	}
	return page, nil
}

// kvA04GitObject builds one git code-source observation whose immutable version
// identity is the production "native:commit:<sha>;blob:<blob>" shape, so the
// named ref a caller supplies is the commit token the ref matching resolves.
func kvA04GitObject(path string, content []byte, versionKey string) observation.Object {
	digest := sha256.Sum256(content)
	return observation.Object{
		Kind: observation.KindGit, ExternalID: path, VersionKey: versionKey, ObjectType: "GIT_FILE",
		ContentHash: "sha256:" + hex.EncodeToString(digest[:]),
		ObservedAt:  time.Now().UTC(), PayloadKind: observation.PayloadBytes,
		Document: &observation.DocumentPayload{MediaType: "text/plain", MediaFamily: "TEXT", Bytes: content},
	}
}

// seedKVA04GitScope seeds one fully activated WORKSPACE_MANAGED GIT scope whose
// sealed scope-config and trust-profile artifacts carry real content. It is the
// GIT twin of seedS1dScope: the same connection/capability/trust/scope lineage,
// with the GIT connector type and contract version.
func seedKVA04GitScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool, codec *artifactcrypto.Codec, organizationID, ownerID string) string {
	t.Helper()
	gitConfigJSON := []byte(`{"provider":"GITHUB","repository_id":"acme/knowledge","branch_name":"main","include_globs":["**/*"],"exclude_globs":[],"text_media_types":["text/plain"],"max_blob_bytes":1048576}`)
	trustJSON := []byte(`{"schema_version":"source-git-trust-v1","provider":"GITHUB","endpoint":"https://api.github.com"}`)
	profileHash := "sha256:" + strings.Repeat("a", 64)
	artifactHash := "sha256:" + strings.Repeat("b", 64)
	suiteHash := "sha256:" + strings.Repeat("c", 64)
	identityDigest := "hmac-sha256:k1:" + strings.Repeat("3", 64)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var connectionResourceID, scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_connection_revision_resource_id($1,$2,1)`, organizationID, kvA04GitConnectionID).Scan(&connectionResourceID); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1,$2,1)`, organizationID, kvA04GitScopeID).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}
	trustHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceConnectionTrustConfig, organizationID,
		kvA04GitTrustArtifact, connectionResourceID, "source_connection_revision", "trust_profile_artifact_id",
		"SOURCE_TRUST_CONFIG", "TRUST_CONFIG", trustJSON)
	configHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeConfig, organizationID,
		kvA04GitConfigArt, scopeResourceID, "source_scope_revision", "scope_config_artifact_id",
		"SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", gitConfigJSON)

	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed kva04 git scope: %v\n%s", err, sql)
		}
	}
	exec(`INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
		connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
		item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ($1,$2,$3,'GIT','1.0.0',$4,true,true,true,false,false,false,true,true,true,true,$5,transaction_timestamp())`,
		kvA04GitCapabilityID, profileHash, kvA04GitBuildID, artifactHash, suiteHash)
	exec(`INSERT INTO public.source_connection (organization_id, id, type, name, latest_revision, active_revision, status, created_by)
		VALUES ($1,$2,'GIT',$2,1,NULL,'DRAFT',$3)`, organizationID, kvA04GitConnectionID, ownerID)
	exec(`INSERT INTO public.source_connection_revision (organization_id, connection_id, revision, credential_reference,
		connector_build_id, connector_type, capability_profile_id, capability_profile_hash, connector_agent_id, execution_target,
		trust_record_id, trust_profile_artifact_id, trust_profile_hash, connector_version, connector_artifact_hash,
		connector_contract_suite_hash, connector_verified_at, allowed_access_modes_json, max_scope_objects, max_scope_bytes, max_object_bytes, created_by)
		VALUES ($1,$2,1,'cred_01ARZ3NDEKTSV4RRFFQ69G5FAV',$3,'GIT',$4,$5,NULL,'CENTRAL_WORKER',$6,$7,$8,'1.0.0',$9,$10,transaction_timestamp(),
		'["WORKSPACE_MANAGED"]'::jsonb,1000,1000000,100000,$11)`,
		organizationID, kvA04GitConnectionID, kvA04GitBuildID, kvA04GitCapabilityID, profileHash, kvA04GitTrustRecordID, kvA04GitTrustArtifact, trustHash, artifactHash, suiteHash, ownerID)
	exec(`INSERT INTO public.source_connection_trust_record (organization_id, id, connection_id, connection_revision,
		connector_agent_id, execution_target, trust_profile_artifact_id, trust_profile_hash, verified_at, expires_at)
		VALUES ($1,$2,$3,1,NULL,'CENTRAL_WORKER',$4,$5,transaction_timestamp(),transaction_timestamp()+interval '1 day')`,
		organizationID, kvA04GitTrustRecordID, kvA04GitConnectionID, kvA04GitTrustArtifact, trustHash)
	exec(`INSERT INTO public.source_connection_trust_projection (organization_id, trust_record_id, revision, status)
		VALUES ($1,$2,1,'VERIFIED')`, organizationID, kvA04GitTrustRecordID)

	identityJSON := []byte(`{"schema_version":"source-scope-identity-v1","external_id":"acme/knowledge@main"}`)
	displayJSON := []byte(`{"schema_version":"source-scope-display-v1","display_name":"Engineering code"}`)
	identityHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeIdentity, organizationID,
		kvA04GitIdentityArt, kvA04GitDiscoveryID, "source_discovered_scope", "identity_artifact_id",
		"SOURCE_SCOPE_IDENTITY", "EXTERNAL_SCOPE_IDENTITY", identityJSON)
	displayHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeDisplayMetadata, organizationID,
		kvA04GitDisplayArt, kvA04GitDiscoveryID, "source_discovered_scope", "display_metadata_artifact_id",
		"SOURCE_SCOPE_METADATA", "DISPLAY_METADATA", displayJSON)
	exec(`INSERT INTO public.source_discovered_scope (organization_id, id, connection_id, connection_revision, source_type,
		identity_digest, identity_digest_key_version, identity_artifact_id, identity_plaintext_hash, display_metadata_artifact_id, display_metadata_hash)
		VALUES ($1,$2,$3,1,'GIT',$4,1,$5,$6,$7,$8)`, organizationID, kvA04GitDiscoveryID, kvA04GitConnectionID, identityDigest, kvA04GitIdentityArt, identityHash, kvA04GitDisplayArt, displayHash)
	exec(`INSERT INTO public.source_scope (organization_id, id, connection_id, discovered_scope_id, source_type, latest_revision, created_by)
		VALUES ($1,$2,$3,$4,'GIT',1,$5)`, organizationID, kvA04GitScopeID, kvA04GitConnectionID, kvA04GitDiscoveryID, ownerID)
	exec(`INSERT INTO public.source_scope_revision (organization_id, source_scope_id, revision, connection_id, connection_revision,
		discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version, source_type, scope_config_artifact_id, scope_config_hash,
		scope_contract_version, access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
		object_limit, byte_limit, max_object_bytes, created_by)
		VALUES ($1,$2,1,$3,1,$4,$5,1,'GIT',$6,$7,'git-v1','WORKSPACE_MANAGED',300,600,NULL,1000,1000000,100000,$8)`,
		organizationID, kvA04GitScopeID, kvA04GitConnectionID, kvA04GitDiscoveryID, identityDigest, kvA04GitConfigArt, configHash, ownerID)
	exec(`INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ($1,$2,1,1,'DRAFT')`, organizationID, kvA04GitScopeID)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit kva04 git scope seed: %v", err)
	}
	return configHash
}

// kvA04GrepResult is the closed structuredContent projection of knowvault_grep.
type kvA04GrepResult struct {
	Matches    []map[string]any `json:"matches"`
	Offset     int64            `json:"offset"`
	Limit      int64            `json:"limit"`
	HasMore    bool             `json:"has_more"`
	NextOffset *int64           `json:"next_offset"`
}

// kvA04ListResult is the closed structuredContent projection of
// knowvault_list_objects.
type kvA04ListResult struct {
	Objects      []map[string]any `json:"objects"`
	Offset       int64            `json:"offset"`
	Limit        int64            `json:"limit"`
	HasMore      bool             `json:"has_more"`
	NextOffset   *int64           `json:"next_offset"`
	Skipped      []map[string]any `json:"skipped"`
	SkippedCount int              `json:"skipped_count"`
}

func kvA04Grep(t *testing.T, handler *workspaceapi.Handler, token, csrf, arguments string) (string, kvA01MCPEnvelope, kvA04GrepResult) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva04-grep", "knowvault_grep", arguments))
	var result kvA04GrepResult
	if envelope.Error == nil && len(envelope.Result.Structured) > 0 {
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &result); err != nil {
			t.Fatalf("kva04 grep structuredContent decode: %v body=%s", err, body)
		}
	}
	return body, envelope, result
}

func kvA04List(t *testing.T, handler *workspaceapi.Handler, token, csrf, arguments string) (string, kvA01MCPEnvelope, kvA04ListResult) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva04-list", "knowvault_list_objects", arguments))
	var result kvA04ListResult
	if envelope.Error == nil && len(envelope.Result.Structured) > 0 {
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &result); err != nil {
			t.Fatalf("kva04 list structuredContent decode: %v body=%s", err, body)
		}
	}
	return body, envelope, result
}

// TestKVA04CodeSourceRefOutcomeFour proves R3a-1 Outcome 4 against real
// PostgreSQL: two immutable versions of one code-source path at two named refs,
// ref-scoped grep/read and the code-source mirror age in the inventory.
func TestKVA04CodeSourceRefOutcomeFour(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedKVA04GitScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		kvA04GitScopeID, configHash, 1, "binding_kva04git", "grant_kva04git", "confirmation_kva04git")

	shaA := strings.Repeat("a", 40)
	shaB := strings.Repeat("b", 40)
	keyA := "native:commit:" + shaA + ";blob:" + strings.Repeat("1", 40)
	keyB := "native:commit:" + shaB + ";blob:" + strings.Repeat("2", 40)
	contentA := []byte("package kv\n\n// KV_A04_REF_A_ONLY needle\nvar RefA = 1\n")
	contentB := []byte("package kv\n\n// KV_A04_REF_B_ONLY needle\nvar RefB = 2\n")

	adapterA := kvA04GitAdapter{object: kvA04GitObject(kvA04GitPath, contentA, keyA)}
	adapterB := kvA04GitAdapter{object: kvA04GitObject(kvA04GitPath, contentB, keyB)}
	resolver := &kvA04GitResolver{}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: t.TempDir()}, s1dWorkerID, time.Now, ids.New).
		WithObservationAdapterResolver(resolver)
	resolver.selectAdapter(adapterA)
	runSyncScope(t, ctx, ingest, queue, workerAccess(t, s1dOrg), kvA04GitScopeID, "kva04-ref-a")
	resolver.selectAdapter(adapterB)
	runSyncScope(t, ctx, ingest, queue, workerAccess(t, s1dOrg), kvA04GitScopeID, "kva04-ref-b")

	versionA := kvA04VersionID(t, ctx, admin, keyA)
	versionB := kvA04VersionID(t, ctx, admin, keyB)
	if versionA == versionB || versionA == "" || versionB == "" {
		t.Fatalf("immutable version identities not distinct: a=%q b=%q", versionA, versionB)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	authority := newAuthorityRuntime(t, ctx)
	handler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, authority)

	t.Run("ref-scoped grep carries the ref-A file:lines address and no ref-B leak", func(t *testing.T) {
		args := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"KV_A04_REF_A_ONLY","ref":` + strconv.Quote(shaA) + `}`
		body, envelope, page := kvA04Grep(t, handler, token, csrf, args)
		if envelope.Error != nil {
			t.Fatalf("ref-A grep refused: %#v body=%s", envelope.Error, body)
		}
		if len(page.Matches) != 1 {
			t.Fatalf("ref-A grep matches=%d want 1 body=%s", len(page.Matches), body)
		}
		hit := page.Matches[0]
		address, ok := hit["address"].(map[string]any)
		if !ok {
			t.Fatalf("ref-A hit has no address: %#v", hit)
		}
		version, ok := address["version"].(map[string]any)
		if !ok {
			t.Fatalf("ref-A hit address has no version: %#v", address)
		}
		if version["ref"] != shaA {
			t.Fatalf("ref-A hit address version.ref=%v want %q", version["ref"], shaA)
		}
		if version["source_version_id"] != versionA {
			t.Fatalf("ref-A hit address version.source_version_id=%v want %q", version["source_version_id"], versionA)
		}
		if version["external_version_key"] != keyA {
			t.Fatalf("ref-A hit address external_version_key=%v want %q", version["external_version_key"], keyA)
		}
		path, _ := hit["path"].(string)
		if path == "" || !strings.Contains(path, kvA04GitPath) {
			t.Fatalf("ref-A hit file locator path=%q does not carry %q", path, kvA04GitPath)
		}
		if line, _ := hit["line"].(float64); line != 3 {
			t.Fatalf("ref-A hit line=%v want 3 (1-based line of the needle)", hit["line"])
		}
		if column, _ := hit["column"].(float64); column < 1 {
			t.Fatalf("ref-A hit column=%v want a 1-based column", hit["column"])
		}
		if _, ok := hit["end_line"]; !ok {
			t.Fatalf("ref-A hit has no end_line: %#v", hit)
		}
		if canonical, _ := hit["canonical_address"].(string); canonical == "" {
			t.Fatalf("ref-A hit has no canonical_address: %#v", hit)
		}

		// Negative control: the same needle asked at ref B (whose file differs)
		// must yield no hit at all.
		cross := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"KV_A04_REF_A_ONLY","ref":` + strconv.Quote(shaB) + `}`
		crossBody, crossEnvelope, crossPage := kvA04Grep(t, handler, token, csrf, cross)
		if crossEnvelope.Error != nil {
			t.Fatalf("ref-B grep of a ref-A needle refused: %#v body=%s", crossEnvelope.Error, crossBody)
		}
		if len(crossPage.Matches) != 0 {
			t.Fatalf("ref-A needle leaked into ref-B grep: %d match(es) body=%s", len(crossPage.Matches), crossBody)
		}

		// The ref-B file is reachable at its own ref, so the ref is not simply
		// unresolved.
		own := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"KV_A04_REF_B_ONLY","ref":` + strconv.Quote(shaB) + `}`
		ownBody, ownEnvelope, ownPage := kvA04Grep(t, handler, token, csrf, own)
		if ownEnvelope.Error != nil || len(ownPage.Matches) != 1 {
			t.Fatalf("ref-B grep of its own needle: matches=%d err=%#v body=%s", len(ownPage.Matches), ownEnvelope.Error, ownBody)
		}
		ownAddress, _ := ownPage.Matches[0]["address"].(map[string]any)
		ownVersion, _ := ownAddress["version"].(map[string]any)
		if ownVersion["source_version_id"] != versionB || ownVersion["ref"] != shaB {
			t.Fatalf("ref-B hit resolved the wrong version: %#v", ownVersion)
		}
	})

	t.Run("ref-scoped read returns exactly the ref bytes and not the other ref", func(t *testing.T) {
		argsA := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"KV_A04_REF_A_ONLY","ref":` + strconv.Quote(shaA) + `}`
		_, _, pageA := kvA04Grep(t, handler, token, csrf, argsA)
		if len(pageA.Matches) != 1 {
			t.Fatalf("ref-A grep for read address: %d match(es)", len(pageA.Matches))
		}
		canonicalA, _ := pageA.Matches[0]["canonical_address"].(string)
		bodyA, envelopeA, readA := kvA01WholeRead(t, handler, token, csrf,
			`{"workspace_id":`+strconv.Quote(s1dWorkspace)+`,"address":`+strconv.Quote(canonicalA)+`,"cursor":"","include_text_base64":true}`)
		if envelopeA.Error != nil {
			t.Fatalf("ref-A read refused: %#v body=%s", envelopeA.Error, bodyA)
		}
		bytesA, err := base64.StdEncoding.DecodeString(readA.TextBase64)
		if err != nil {
			t.Fatalf("ref-A read page did not decode: %v", err)
		}
		if !bytes.Equal(bytesA, contentA) {
			t.Fatalf("ref-A read returned %q, want the ref-A bytes", string(bytesA))
		}
		if bytes.Contains(bytesA, []byte("KV_A04_REF_B_ONLY")) {
			t.Fatalf("ref-A read leaked ref-B content")
		}

		argsB := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"KV_A04_REF_B_ONLY","ref":` + strconv.Quote(shaB) + `}`
		_, _, pageB := kvA04Grep(t, handler, token, csrf, argsB)
		if len(pageB.Matches) != 1 {
			t.Fatalf("ref-B grep for read address: %d match(es)", len(pageB.Matches))
		}
		canonicalB, _ := pageB.Matches[0]["canonical_address"].(string)
		bodyB, envelopeB, readB := kvA01WholeRead(t, handler, token, csrf,
			`{"workspace_id":`+strconv.Quote(s1dWorkspace)+`,"address":`+strconv.Quote(canonicalB)+`,"cursor":"","include_text_base64":true}`)
		if envelopeB.Error != nil {
			t.Fatalf("ref-B read refused: %#v body=%s", envelopeB.Error, bodyB)
		}
		bytesB, err := base64.StdEncoding.DecodeString(readB.TextBase64)
		if err != nil {
			t.Fatalf("ref-B read page did not decode: %v", err)
		}
		if !bytes.Equal(bytesB, contentB) {
			t.Fatalf("ref-B read returned %q, want the ref-B bytes", string(bytesB))
		}
	})

	t.Run("inventory exposes both immutable versions with the code-source mirror age", func(t *testing.T) {
		args := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"all_versions":true}`
		body, envelope, page := kvA04List(t, handler, token, csrf, args)
		if envelope.Error != nil {
			t.Fatalf("all-versions inventory refused: %#v body=%s", envelope.Error, body)
		}
		seenA, seenB := false, false
		for _, object := range page.Objects {
			key, _ := object["external_version_key"].(string)
			switch key {
			case keyA:
				seenA = true
			case keyB:
				seenB = true
			default:
				continue
			}
			age, ok := object["mirror_age_seconds"]
			if !ok {
				t.Fatalf("GIT_FILE object %q has no mirror_age_seconds: %#v", key, object)
			}
			if seconds, ok := age.(float64); !ok || seconds < 0 {
				t.Fatalf("GIT_FILE object %q mirror_age_seconds=%#v, want non-negative", key, age)
			}
		}
		if !seenA || !seenB {
			t.Fatalf("inventory did not expose both immutable versions (a=%v b=%v)", seenA, seenB)
		}
	})
}

// kvA04VersionID resolves the immutable source_version_id of one named
// code-source ref by its external_version_key.
func kvA04VersionID(t *testing.T, ctx context.Context, admin *pgxpool.Pool, externalVersionKey string) string {
	t.Helper()
	var id string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.source_version
		WHERE organization_id=$1 AND external_version_key=$2`, s1dOrg, externalVersionKey).Scan(&id); err != nil {
		t.Fatalf("resolve immutable version for key %q: %v", externalVersionKey, err)
	}
	return id
}
