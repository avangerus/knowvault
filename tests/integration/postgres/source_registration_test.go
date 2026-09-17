package postgres_test

// End-to-end proof of the ADR-0074 registration surface against real
// PostgreSQL 18.4: Register creates the whole DRAFT lineage through the product
// API (not raw SQL), Activate places the durable SOURCE_SCOPE_SYNC job through
// the production queue, a real worker claim executes it, and the workspace
// status projection (ADR-0074 D3-3) exposes activation, sync and typed-error
// state to the repository the HTTP layer is built on.

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	regOrg       = "org_registration"
	regOwner     = "usr_reg_owner"
	regViewer    = "usr_reg_viewer"
	regOutsider  = "usr_reg_outsider"
	regWorkspace = "ws_registration"
	regRootAls   = "docs-root"
	regRootID    = "vol-1"
	regWorkerID  = "worker_registration"
)

type regMounts struct{ root string }

func (m regMounts) Resolve(alias, identity string) (string, bool) {
	if alias == regRootAls && identity == regRootID {
		return m.root, true
	}
	return "", false
}

// regRequest is the caller shape the HTTP layer projects (workspaceapi_sources
// test pins that projection); here it is passed straight to the service.
func regRequest() registration.RegisterRequest {
	return registration.RegisterRequest{
		Name: "Engineering docs", RootAlias: regRootAls, RootIdentity: regRootID,
		RelativeRoot: "projects/alpha", Kind: "documents", Recursive: true,
		IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
		OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN"},
	}
}

func regOwnerAccess(request string) database.AccessContext {
	return database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: request}
}

// seedRegistrationTenant seeds the org, its OWNER, a MEMBER principal (used by
// the authority binding and the status-denied matrix) and the verified FOLDER
// capability profile Register reads. It returns the app-side store, codec and
// registration service bound to the same review surfaces the composition root
// wires (ADR-0074).
func seedRegistrationTenant(t *testing.T, ctx context.Context, admin *pgxpool.Pool) (*database.Store, *artifactcrypto.Codec, *registration.Service) {
	t.Helper()
	seedS1dOrg(t, ctx, admin, regOrg, regOwner)
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`, regViewer, regOrg); err != nil {
		t.Fatalf("seed viewer principal: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_reg_viewer', $1, $2, 'MEMBER', 1, $3)`, regOrg, regViewer, regOwner); err != nil {
		t.Fatalf("seed viewer role: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ('cap_registration', 'sha256:`+strings.Repeat("a", 64)+`', 'folder-build-registration', 'FOLDER', '1.0.0',
			'sha256:`+strings.Repeat("b", 64)+`', true, true, true, false, true, true, true, true, true, true,
			'sha256:`+strings.Repeat("c", 64)+`', transaction_timestamp())`); err != nil {
		t.Fatalf("seed folder capability profile: %v", err)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("audit store: %v", err)
	}
	queue, err := jobs.New(appStore)
	if err != nil {
		t.Fatalf("job queue: %v", err)
	}
	service, err := registration.New(appStore, auditStore, s1dCodec(t, regOrg), queue, s1dDigestKey, 1)
	if err != nil {
		t.Fatalf("registration service: %v", err)
	}
	return appStore, s1dCodec(t, regOrg), service
}

// seedRegistrationWorkspaceBinding is the registration twin of
// seedS1dWorkspaceBinding, parameterized on the registration-derived scope id:
// workspace at revision 1, owner + viewer memberships, the enabled
// WORKSPACE_MANAGED binding, and the organization policy revision. The grant
// and confirmation are minted through the production authority repository by
// the caller.
// seedRegistrationWorkspaceBinding mints one workspace binding for scopeID and
// its authority confirmation. A repeated call on the same tenant adds a
// further binding to the live workspace: the idempotent inserts converge on
// the existing revision-1 rows, and the new workspace_revision_source row
// references the exact committed snapshot (FK exact_workspace_snapshot) rather
// than a re-derived twin.
func seedRegistrationWorkspaceBinding(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeID, scopeConfigHash, bindingID string) authorityOpsFixture {
	t.Helper()
	const policyID = "policy-registration-01ARZ3NDEKTSV4RRFFQ69G5FAV"
	policyHash := "sha256:" + strings.Repeat("d", 64)

	// The snapshot must be the exact canonical workspace configuration the
	// repository re-derives and byte-compares on every load: built through the
	// production Go serializer with the same revision, members and bindings,
	// and hashed the same way.
	//
	// The first call mints revision 1 with the single new binding. A repeated
	// call on the same tenant performs the cutover of 000016/000018: a fresh
	// workspace revision whose canonical document and source projection carry
	// every binding of the current revision plus the new one — the exact-set
	// guard compares the projection rows against the canonical bindings, and
	// the activation liveness check joins the workspace at its CURRENT
	// revision, so a later confirmation must live on the new revision.
	wsRevision := int64(1)
	var bindings []workspace.SourceBinding
	var currentRevision int64
	err := admin.QueryRow(ctx, `SELECT current_revision FROM public.workspace
		WHERE organization_id=$1 AND id=$2`, regOrg, regWorkspace).Scan(&currentRevision)
	switch {
	case err == nil:
		wsRevision = currentRevision + 1
		rows, err := admin.Query(ctx, `SELECT source_scope_id, source_scope_revision, scope_config_hash, enabled
			FROM public.workspace_revision_source
			WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=$3
			ORDER BY source_scope_id`, regOrg, regWorkspace, currentRevision)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var b workspace.SourceBinding
			if err := rows.Scan(&b.SourceScopeID, &b.SourceScopeRevision, &b.ScopeConfigHash, &b.Enabled); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			bindings = append(bindings, b)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	case errors.Is(err, pgx.ErrNoRows):
		// First call: the workspace does not exist yet, mint revision 1.
	default:
		t.Fatalf("registration workspace: %v", err)
	}
	bindings = append(bindings, workspace.SourceBinding{
		SourceScopeID: scopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeConfigHash, Enabled: true,
	})
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: regOrg, ID: regWorkspace, Revision: wsRevision,
		Name: regWorkspace, Status: workspace.StatusActive, OwnerPrincipalID: regOwner,
		Members: []workspace.Member{
			{PrincipalID: regOwner, Role: workspace.RoleOwner},
			{PrincipalID: regViewer, Role: workspace.RoleMember},
		},
		SourceBindings: bindings,
	})
	if err != nil {
		t.Fatalf("normalize registration workspace snapshot: %v", err)
	}
	wsConfigHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("registration workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("registration workspace canonical snapshot: %v", err)
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed registration workspace: %v\n%s", err, sql)
		}
	}
	// The policy row is guarded by a BEFORE INSERT ordinal sequence check
	// (000010), which fires before any conflict is known — a repeated call
	// must skip the insert entirely rather than rely on ON CONFLICT.
	var policyExists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.organization_policy_revision
		WHERE organization_id=$1 AND revision=1)`, regOrg).Scan(&policyExists); err != nil {
		t.Fatal(err)
	}
	if !policyExists {
		exec(`INSERT INTO public.organization_policy_revision
			(organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
			VALUES ($1, 1, $2, $3, '2019-01-01T00:00:00Z', $4)`, regOrg, policyID, policyHash, regOwner)
	}
	exec(`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
		VALUES ($1, $2, $1, 'ACTIVE', $3, $4)
		ON CONFLICT DO NOTHING`, regWorkspace, regOrg, regOwner, wsRevision)
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, regOrg, regWorkspace, wsRevision, wsConfigHash, regOwner)
	exec(`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, regOrg, regWorkspace, wsRevision, wsConfigHash, canonicalBytes)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_reg_owner', $1, $2, $3, 'OWNER', $4, $3)
		ON CONFLICT DO NOTHING`, regOrg, regWorkspace, regOwner, wsRevision)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_reg_viewer', $1, $2, $3, 'MEMBER', $4, $5)
		ON CONFLICT DO NOTHING`, regOrg, regWorkspace, regViewer, wsRevision, regOwner)
	exec(`INSERT INTO public.workspace_source (organization_id, id, workspace_id, source_scope_id, added_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`, regOrg, bindingID, regWorkspace, scopeID, regOwner)
	// Carry the current revision's source projection onto the fresh revision
	// (the repository does the same on production mutations), then add the new
	// binding row; the exact-set guard then sees the canonical bindings and
	// the projection rows agree.
	exec(`INSERT INTO public.workspace_revision_source
		(organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
		 workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
		SELECT $1, $2, $3, $4, workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled
		FROM public.workspace_revision_source
		WHERE organization_id=$1 AND workspace_id=$2 AND workspace_revision=$5`,
		regOrg, regWorkspace, wsRevision, wsConfigHash, currentRevision)
	exec(`INSERT INTO public.workspace_revision_source
		(organization_id, workspace_id, workspace_revision, workspace_configuration_hash, workspace_source_id,
		 source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, 1, $7, 'WORKSPACE_MANAGED', true)`,
		regOrg, regWorkspace, wsRevision, wsConfigHash, bindingID, scopeID, scopeConfigHash)
	exec(`UPDATE public.workspace SET current_revision=$3 WHERE organization_id=$1 AND id=$2`,
		regOrg, regWorkspace, wsRevision)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit registration workspace seed: %v", err)
	}
	return authorityOpsFixture{
		organizationID: regOrg, ownerID: regOwner, workspaceID: regWorkspace,
		policyID: policyID, policyNumber: 1, workspaceRevision: wsRevision, workspaceConfHash: wsConfigHash,
		workspaceSourceID: bindingID, sourceScopeID: scopeID, sourceScopeRevision: 1, scopeConfigHash: scopeConfigHash,
	}
}

// runSyncScopeFor is the registration twin of runSyncScope: a full
// enqueue->claim->handle cycle under the given worker id. begin_sync leases the
// job_attempt the handler claimed, so the claiming worker must be the worker
// the handler is bound to — runSyncScope is hard-wired to the S1d worker, this
// one serves the registration worker.
func runSyncScopeFor(t *testing.T, ctx context.Context, handler *ingestion.Handler, queue *jobs.Queue, access database.AccessContext, workerID, scopeID, label string) {
	t.Helper()
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": scopeID}, IdempotencyKey: label + "-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatalf("enqueue %s: %v", label, err)
	}
	claimed, ok, err := queue.Claim(ctx, access, workerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if err := handler.Handle(ctx, access, claimed); err != nil {
		t.Fatalf("handle %s: %v (code=%s)", label, err, ingestion.CodeOf(err))
	}
}

func TestSourceRegistrationLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)

	t.Run("register creates the DRAFT lineage through the product API", func(t *testing.T) {
		result, err := service.Register(ctx, regOwnerAccess("req_reg_1"), regRequest())
		if err != nil {
			t.Fatalf("register: %v (code=%s)", err, registration.CodeOf(err))
		}
		if !result.Created || result.Revision != 1 {
			t.Fatalf("result = %#v", result)
		}
		for prefix, id := range map[string]string{
			"conn": result.ConnectionID, "discovered": result.DiscoveredScopeID, "scope": result.SourceScopeID,
		} {
			if !strings.HasPrefix(id, prefix+"_") || len(id) != len(prefix)+27 {
				t.Fatalf("%s id shape: %q", prefix, id)
			}
		}

		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1 AND id=$2`,
			regOrg, result.ConnectionID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("connection rows=%d err=%v", count, err)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_scope_revision
			WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`,
			regOrg, result.SourceScopeID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("scope revision rows=%d err=%v", count, err)
		}
		var activationStatus string
		if err := admin.QueryRow(ctx, `SELECT status FROM public.source_scope_activation
			WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`,
			regOrg, result.SourceScopeID).Scan(&activationStatus); err != nil || activationStatus != "DRAFT" {
			t.Fatalf("activation status=%q err=%v", activationStatus, err)
		}
		var trustStatus string
		if err := admin.QueryRow(ctx, `SELECT projection.status FROM public.source_connection_trust_projection AS projection
			JOIN public.source_connection_trust_record AS record
			  ON record.organization_id=projection.organization_id AND record.id=projection.trust_record_id
			WHERE projection.organization_id=$1 AND record.connection_id=$2`,
			regOrg, result.ConnectionID).Scan(&trustStatus); err != nil || trustStatus != "DRAFT" {
			t.Fatalf("trust projection status=%q err=%v", trustStatus, err)
		}
		var artifacts int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact WHERE organization_id=$1`,
			regOrg).Scan(&artifacts); err != nil || artifacts != 4 {
			t.Fatalf("sealed artifacts=%d err=%v", artifacts, err)
		}
		var identityDigest string
		if err := admin.QueryRow(ctx, `SELECT identity_digest FROM public.source_discovered_scope
			WHERE organization_id=$1 AND id=$2`, regOrg, result.DiscoveredScopeID).Scan(&identityDigest); err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^hmac-sha256:k1:[0-9a-f]{64}$`).MatchString(identityDigest) {
			t.Fatalf("identity digest shape: %q", identityDigest)
		}
		var ciphertextLeaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact AS artifact
			WHERE artifact.organization_id=$1
			  AND (position($2 IN encode(artifact.ciphertext,'escape')) > 0
			    OR position($3 IN encode(artifact.ciphertext,'escape')) > 0)`,
			regOrg, regRootAls, regRootID).Scan(&ciphertextLeaks); err != nil {
			t.Fatal(err)
		}
		if ciphertextLeaks != 0 {
			t.Fatalf("source root bytes found in %d sealed artifact ciphertexts", ciphertextLeaks)
		}

		var auditCount int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='source.registration_created' AND resource_id=$2`,
			regOrg, result.SourceScopeID).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatalf("registration audit events=%d err=%v", auditCount, err)
		}
	})

	t.Run("replay converges on created=false without new rows", func(t *testing.T) {
		first, err := service.Register(ctx, regOwnerAccess("req_reg_2"), regRequest())
		if err != nil {
			t.Fatalf("first register: %v", err)
		}
		second, err := service.Register(ctx, regOwnerAccess("req_reg_3"), regRequest())
		if err != nil {
			t.Fatalf("replay register: %v (code=%s)", err, registration.CodeOf(err))
		}
		if second.Created {
			t.Fatal("replay reported created=true")
		}
		if second.ConnectionID != first.ConnectionID || second.SourceScopeID != first.SourceScopeID ||
			second.DiscoveredScopeID != first.DiscoveredScopeID || second.Revision != 1 {
			t.Fatalf("replay ids diverged: first=%#v second=%#v", first, second)
		}
		var connections, artifacts, auditEvents int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1`,
			regOrg).Scan(&connections); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact WHERE organization_id=$1`,
			regOrg).Scan(&artifacts); err != nil {
			t.Fatal(err)
		}
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1`,
			regOrg).Scan(&auditEvents); err != nil {
			t.Fatal(err)
		}
		if connections != 1 || artifacts != 4 || auditEvents != 1 {
			t.Fatalf("replay added rows: connections=%d artifacts=%d audit=%d", connections, artifacts, auditEvents)
		}
	})

	t.Run("a lineage collision with different configuration is a typed conflict", func(t *testing.T) {
		conflicting := regRequest()
		conflicting.Name = "A different display name"
		_, err := service.Register(ctx, regOwnerAccess("req_reg_conflict"), conflicting)
		if registration.CodeOf(err) != registration.CodeConflict {
			t.Fatalf("conflict register: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	t.Run("a non-OWNER registration is denied and creates nothing", func(t *testing.T) {
		access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_reg_viewer"}
		_, err := service.Register(ctx, access, regRequest())
		if registration.CodeOf(err) != registration.CodeDenied {
			t.Fatalf("viewer register: err=%v code=%s", err, registration.CodeOf(err))
		}
		var connections int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_connection WHERE organization_id=$1`,
			regOrg).Scan(&connections); err != nil {
			t.Fatal(err)
		}
		if connections != 1 {
			t.Fatalf("denied register created connections: %d", connections)
		}
	})

	t.Run("request validation fails closed", func(t *testing.T) {
		bad := regRequest()
		bad.MaxFileBytes = 0
		_, err := service.Register(ctx, regOwnerAccess("req_reg_bad"), bad)
		if registration.CodeOf(err) != registration.CodeRequestInvalid {
			t.Fatalf("invalid register: err=%v code=%s", err, registration.CodeOf(err))
		}
	})
}

func TestPostgreSQLQueryRegistrationLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)
	profileHash := "sha256:" + strings.Repeat("e", 64)
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ('cap_pgq_registration', $1, 'pgq-build-registration', 'POSTGRESQL_QUERY', '1.0.0',
			$2, true, true, true, false, true, true, true, true, true, true, $3, transaction_timestamp())`,
		profileHash, "sha256:"+strings.Repeat("f", 64), "sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatalf("seed PostgreSQL query capability profile: %v", err)
	}
	request := registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: "Waste daily", Kind: "business-object",
		DatabaseIdentity: "cluster-demo", LineageID: "waste-daily", ProjectionRevision: 1,
		ContractHash: "sha256:" + strings.Repeat("2", 64), SchemaName: "analytics", RelationName: "waste_daily", RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "tonnes", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
		},
	}
	first, err := service.Register(ctx, regOwnerAccess("req_pgq_reg_1"), request)
	if err != nil {
		t.Fatalf("register PG query source: %v (code=%s) cause=%v", err, registration.CodeOf(err), errors.Unwrap(err))
	}
	if !first.Created || first.Revision != 1 {
		t.Fatalf("unexpected registration result: %#v", first)
	}
	var sourceType, contractVersion, status string
	if err := admin.QueryRow(ctx, `SELECT source_type,scope_contract_version FROM public.source_scope_revision WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, first.SourceScopeID).Scan(&sourceType, &contractVersion); err != nil {
		t.Fatal(err)
	}
	if sourceType != "POSTGRESQL_QUERY" || contractVersion != "postgresql-query-v1" {
		t.Fatalf("scope contract=%q/%q", sourceType, contractVersion)
	}
	if err := admin.QueryRow(ctx, `SELECT status FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, first.SourceScopeID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "DRAFT" {
		t.Fatalf("projection status=%q", status)
	}
	second, err := service.Register(ctx, regOwnerAccess("req_pgq_reg_2"), request)
	if err != nil || second.Created || second.SourceScopeID != first.SourceScopeID {
		t.Fatalf("PG query replay did not converge: %#v err=%v code=%s", second, err, registration.CodeOf(err))
	}
}

func TestRemoteGitAndMailRegistrationLifecycle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)
	for _, profile := range []struct {
		id, build, typ, artifact string
	}{
		{"cap_git_registration", "git-build-registration", "GIT", "a"},
		{"cap_mail_registration", "mail-build-registration", "MAIL", "b"},
	} {
		if _, err := admin.Exec(ctx, `
			INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
				connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
				item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
			VALUES ($1, $2, $3, $4, '1.0.0', $5, true, true, true, false, false, false, true, true, true, true, $6, transaction_timestamp())`,
			profile.id, "sha256:"+strings.Repeat(profile.artifact, 64), profile.build, profile.typ,
			"sha256:"+strings.Repeat("c", 64), "sha256:"+strings.Repeat("d", 64)); err != nil {
			t.Fatalf("seed %s capability profile: %v", profile.typ, err)
		}
	}
	gitRequest := registration.RegisterRequest{SourceType: "GIT", Name: "Engineering code", Kind: "code",
		Provider: "GITHUB", Endpoint: "https://api.github.com", WebBaseURL: "https://github.com",
		RepositoryID: "acme/knowledge", BranchName: "main", IncludeGlobs: []string{"src/**"},
		ExcludeGlobs: []string{"vendor/**"}, TextMediaTypes: []string{"text/plain", "application/json"}, MaxBlobBytes: 1 << 20}
	gitResult, err := service.Register(ctx, regOwnerAccess("req_remote_git"), gitRequest)
	if err != nil || !gitResult.Created {
		t.Fatalf("register Git source result=%#v err=%v code=%s", gitResult, err, registration.CodeOf(err))
	}
	var sourceType, contractVersion string
	if err := admin.QueryRow(ctx, `SELECT source_type, scope_contract_version FROM public.source_scope_revision WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, gitResult.SourceScopeID).Scan(&sourceType, &contractVersion); err != nil {
		t.Fatal(err)
	}
	if sourceType != "GIT" || contractVersion != "git-v1" {
		t.Fatalf("Git scope contract=%q/%q", sourceType, contractVersion)
	}
	gitReplay, err := service.Register(ctx, regOwnerAccess("req_remote_git_replay"), gitRequest)
	if err != nil || gitReplay.Created || gitReplay.SourceScopeID != gitResult.SourceScopeID {
		t.Fatalf("Git replay did not converge: %#v err=%v code=%s", gitReplay, err, registration.CodeOf(err))
	}

	mailRequest := registration.RegisterRequest{SourceType: "MAIL", Provider: "IMAP", Name: "Operations mail", Kind: "mail",
		Endpoint: "imap.example.test:993", Mailbox: "tenant-a", Folder: "INBOX", Username: "reader@example.test",
		IncludeAttachments: true, MaxMessageBytes: 8 << 20, MaxAttachmentBytes: 4 << 20,
		AttachmentMediaTypes: []string{"text/plain", "application/pdf"}}
	mailResult, err := service.Register(ctx, regOwnerAccess("req_remote_mail"), mailRequest)
	if err != nil || !mailResult.Created {
		t.Fatalf("register Mail source result=%#v err=%v code=%s", mailResult, err, registration.CodeOf(err))
	}
	if err := admin.QueryRow(ctx, `SELECT source_type, scope_contract_version FROM public.source_scope_revision WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, mailResult.SourceScopeID).Scan(&sourceType, &contractVersion); err != nil {
		t.Fatal(err)
	}
	if sourceType != "MAIL" || contractVersion != "imap-v1" {
		t.Fatalf("Mail scope contract=%q/%q", sourceType, contractVersion)
	}
}

// TestPostgreSQLQueryPublisherAgainstExternalCluster closes the complete PGQ
// data-plane boundary with a real second PostgreSQL cluster: the external VIEW
// is read into the typed snapshot by the production reader, then the worker
// publishes that snapshot through the lease-fenced catalog/evidence path.
// The test is intentionally skipped unless the operator supplies the external
// cluster URL; a missing dependency is never treated as a green acceptance.
func TestPostgreSQLQueryPublisherAgainstExternalCluster(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the live PGQ publisher proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())
	const schema = "kv_pgq_publish"
	today := time.Now().UTC()
	firstCollected := time.Date(today.Year(), today.Month(), today.Day(), 9, 34, 56, 789000000, time.UTC)
	secondCollected := time.Date(today.Year(), today.Month(), today.Day(), 10, 34, 56, 789000000, time.UTC)
	_, err = external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_publish" CASCADE;
		CREATE SCHEMA "kv_pgq_publish";
		CREATE TABLE "kv_pgq_publish"."waste_daily_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`)
	if err != nil {
		t.Fatalf("seed external PGQ view: %v", err)
	}
	if _, err := external.Exec(ctx, "\n\t\tINSERT INTO \"kv_pgq_publish\".\"waste_daily_data\" VALUES\n\t\t\t('550e8400-e29b-41d4-a716-446655440010', $1, 12.345, 'North route \u043e\u0442\u0445\u043e\u0434\u043e\u0432'),\n\t\t\t('550e8400-e29b-41d4-a716-446655440011', $2, 7.125, 'South route \u043e\u0442\u0445\u043e\u0434\u043e\u0432')\n\t", firstCollected, secondCollected); err != nil {
		t.Fatalf("seed external PGQ rows: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_publish"."waste_daily" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_publish"."waste_daily_data"
	`); err != nil {
		t.Fatalf("create external PGQ view: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_publish" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	profileHash := "sha256:" + strings.Repeat("e", 64)
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.connector_capability_profile (id, profile_hash, connector_build_id, connector_type,
			connector_version, connector_artifact_hash, stable_object_ids, native_versions, incremental_cursor, webhooks,
			item_level_acl, acl_refresh, historical_versions, deep_links, deletion_events, local_extraction, contract_suite_hash, verified_at)
		VALUES ('cap_pgq_publish', $1, 'pgq-build-publish', 'POSTGRESQL_QUERY', '1.0.0',
			$2, true, true, true, false, true, true, true, true, true, true, $3, transaction_timestamp())`,
		profileHash, "sha256:"+strings.Repeat("f", 64), "sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatalf("seed PGQ capability: %v", err)
	}
	request := registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: "Waste daily", Kind: "business-object",
		DatabaseIdentity: "cluster-publish", LineageID: "waste-daily", ProjectionRevision: 1,
		ContractHash: "sha256:" + strings.Repeat("2", 64), SchemaName: schema, RelationName: "waste_daily", RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "route_id", TypeFingerprint: "oid:2950", LogicalType: postgresqlquery.TypeUUID, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 64},
			{Ordinal: 2, Name: "collected_at", TypeFingerprint: "oid:timestamptz:6", LogicalType: postgresqlquery.TypeTimestamptz, Roles: []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence}, Precision: 3, MaxBytes: 64},
			{Ordinal: 3, Name: "tonnes", TypeFingerprint: "oid:1700:p:12:s:3", LogicalType: postgresqlquery.TypeNumeric, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Precision: 12, Scale: 3, MaxBytes: 64},
			{Ordinal: 4, Name: "note", TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
	registered, err := service.Register(ctx, regOwnerAccess("req_pgq_publish_register"), request)
	if err != nil {
		t.Fatalf("register PGQ source: %v (code=%s)", err, registration.CodeOf(err))
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_connection_trust_projection p
		SET status='VERIFIED' WHERE p.organization_id=$1 AND p.trust_record_id=(SELECT trust_record_id FROM public.source_connection_revision WHERE organization_id=$1 AND connection_id=$2 AND revision=1)`, regOrg, registered.ConnectionID); err != nil {
		t.Fatalf("verify PGQ trust: %v", err)
	}
	workspaceBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FC0")
	authorityStore := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, workspaceBinding, "pgq-publish-question-grant")
	if _, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(workspaceBinding, workspaceBinding.ownerID, "req_pgq_publish_question_confirm"), confirmRuntimeRequest(workspaceBinding, grant, "pgq-publish-question-confirm")); err != nil {
		t.Fatalf("confirm PGQ question binding: %v", err)
	}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatal(err)
	}
	jobID := mustID(t, "syncscope")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_pgq_publish_enqueue"), jobs.Spec{
		JobID: jobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "pgq-publish-job", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue PGQ job: %v", err)
	}
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim PGQ job: %v ok=%v", err, ok)
	}
	workerAccessContext := workerAccess(t, regOrg)
	publishSyncRunID := mustID(t, "syncrun")
	var projection postgresqlquery.Projection
	if err := workerStore.Write(ctx, workerAccessContext, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT connection_id,database_identity,lineage_id,projection_revision,contract_hash,schema_name,relation_name,relation_kind,empty_snapshot_policy FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, registered.SourceScopeID).Scan(&projection.ConnectionID, &projection.DatabaseIdentity, &projection.LineageID, &projection.Revision, &projection.ContractHash, &projection.SchemaName, &projection.RelationName, &projection.RelationKind, &projection.EmptySnapshotPolicy); err != nil {
			return err
		}
		var columnsRaw []byte
		if err := tx.QueryRow(ctx, `SELECT columns_json FROM public.postgresql_query_projection WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, registered.SourceScopeID).Scan(&columnsRaw); err != nil {
			return err
		}
		var columns []struct {
			Ordinal         int                         `json:"ordinal"`
			Name            string                      `json:"name"`
			TypeFingerprint string                      `json:"type_fingerprint"`
			LogicalType     postgresqlquery.LogicalType `json:"logical_type"`
			Roles           []postgresqlquery.Role      `json:"roles"`
			Nullable        bool                        `json:"nullable"`
			Precision       int                         `json:"precision"`
			Scale           int                         `json:"scale"`
			MaxBytes        int                         `json:"max_bytes"`
		}
		if err := jsonv2.Unmarshal(columnsRaw, &columns, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
			return err
		}
		projection.Columns = make([]postgresqlquery.Column, len(columns))
		for i, column := range columns {
			projection.Columns[i] = postgresqlquery.Column{Ordinal: column.Ordinal, Name: column.Name, TypeFingerprint: column.TypeFingerprint, LogicalType: column.LogicalType, Roles: column.Roles, Nullable: column.Nullable, Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, publishSyncRunID, registered.SourceScopeID, claimed.ID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("begin PGQ publication: %v", err)
	}
	limits := postgresqlquery.DefaultLimits()
	snapshot, err := postgresqlquery.ReadProjection(ctx, external, projection, limits)
	if err != nil {
		t.Fatalf("read external PGQ projection: %v", err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	result, err := handler.PublishPostgreSQLSnapshot(ctx, workerAccessContext, ingestion.PostgreSQLSnapshotRequest{ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: publishSyncRunID, Projection: projection, Snapshot: snapshot, Claimed: claimed})
	if err != nil {
		t.Fatalf("publish PGQ snapshot: %v (code=%s)", err, ingestion.CodeOf(err))
	}
	if result.ObjectsSeen != 2 || result.ObjectsIngested != 2 || result.VersionsCreated != 2 || result.EvidencePublished != 6 {
		t.Fatalf("publication counters=%#v", result)
	}
	if err := workerQueue.Complete(ctx, workerAccessContext, claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete PGQ job: %v", err)
	}
	var objectCount, evidenceCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1 AND connection_id=$2 AND object_type='POSTGRESQL_QUERY_ROW' AND queryable`, regOrg, registered.ConnectionID).Scan(&objectCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment f JOIN public.source_version v ON v.organization_id=f.organization_id AND v.id=f.source_version_id JOIN public.source_object o ON o.organization_id=v.organization_id AND o.id=v.source_object_id WHERE f.organization_id=$1 AND o.connection_id=$2`, regOrg, registered.ConnectionID).Scan(&evidenceCount); err != nil {
		t.Fatal(err)
	}
	if objectCount != 2 || evidenceCount != 6 {
		t.Fatalf("published catalog objects=%d evidence=%d", objectCount, evidenceCount)
	}

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("inventory_read_and_source_status", func(t *testing.T) {
		// The inventory and evidence surfaces must accept the PG row identity
		// artifact. Its row values remain sealed: the public display is the
		// projection lineage plus the catalog's already keyed opaque digest.
		viewerAccess := regOwnerAccess("req_pgq_inventory_read")
		inventory, err := viewer.ListObjects(ctx, viewerAccess, workspaceBinding.workspaceID, false, 0, 1)
		if err != nil {
			t.Fatalf("PGQ inventory limit=1: %v", err)
		}
		if len(inventory.Items) != 1 || inventory.HasMore != true {
			t.Fatalf("PGQ inventory page=%+v, want one item and a next page", inventory)
		}
		var opaqueDigest string
		if err := admin.QueryRow(ctx, `SELECT external_object_id_digest
		FROM public.source_object WHERE organization_id=$1 AND id=$2`, regOrg, inventory.Items[0].SourceObjectID).Scan(&opaqueDigest); err != nil {
			t.Fatal(err)
		}
		wantSourceDisplay := "postgresql-query/" + request.LineageID + "/" + opaqueDigest
		if inventory.Items[0].ExternalID != wantSourceDisplay {
			t.Fatalf("PGQ inventory external_id=%q, want opaque display %q", inventory.Items[0].ExternalID, wantSourceDisplay)
		}
		searchPage, err := viewer.SearchFragments(ctx, regOwnerAccess("req_pgq_search_read"), workspaceBinding.workspaceID, "North route", false, 0, 10)
		if err != nil || len(searchPage.Hits) == 0 {
			t.Fatalf("PGQ search: %v hits=%d", err, len(searchPage.Hits))
		}
		hit := searchPage.Hits[0]
		var hitDigest string
		if err := admin.QueryRow(ctx, `SELECT external_object_id_digest
		FROM public.source_object WHERE organization_id=$1 AND id=$2`, regOrg, hit.Fragment.SourceObjectID).Scan(&hitDigest); err != nil {
			t.Fatal(err)
		}
		wantHitDisplay := "postgresql-query/" + request.LineageID + "/" + hitDigest
		fragment, err := viewer.Read(ctx, regOwnerAccess("req_pgq_fragment_read"), workspaceBinding.workspaceID, hit.Fragment.FragmentID)
		if err != nil {
			t.Fatalf("PGQ read of search address: %v", err)
		}
		if fragment.SourceObjectID != hit.Fragment.SourceObjectID || fragment.SourcePath != wantHitDisplay {
			t.Fatalf("PGQ read provenance=%+v, want object=%q source_path=%q", fragment, hit.Fragment.SourceObjectID, wantHitDisplay)
		}
		// The owner rows are immutable after their two sealed identity branches are
		// bound. A privileged attempt to swap either branch between the two PG rows
		// must fail before the viewer can ever observe a foreign envelope; this is
		// the database-side tenant/object proof behind the viewer's locator check.
		for _, column := range []string{"canonical_locator_artifact_id", "external_object_id_artifact_id"} {
			assertAdminStatementRejected(t, ctx, admin, `UPDATE public.source_object AS target
			SET `+column+` = foreign_object.`+column+`
			FROM public.source_object AS foreign_object
			WHERE target.organization_id = 'org_registration'
			  AND foreign_object.organization_id = target.organization_id
			  AND target.id = (SELECT id FROM public.source_object WHERE organization_id = 'org_registration' ORDER BY id LIMIT 1)
			  AND foreign_object.id = (SELECT id FROM public.source_object WHERE organization_id = 'org_registration' ORDER BY id DESC LIMIT 1)
			  AND target.id <> foreign_object.id`)
		}
		if _, err := service.Activate(ctx, regOwnerAccess("req_pgq_status_activate"), registration.ActivateRequest{
			IdempotencyKey: "pgq-status-activate", SourceScopeID: registered.SourceScopeID,
		}); err != nil {
			t.Fatalf("activate PGQ source for status projection: %v (code=%s)", err, registration.CodeOf(err))
		}
		statuses, err := authorityStore.ListSources(ctx, regOwnerAccess("req_pgq_status_read"), workspaceBinding.workspaceID)
		if err != nil || len(statuses) != 1 {
			t.Fatalf("PGQ source status rows=%d err=%v", len(statuses), err)
		}
		if status := statuses[0]; status.SourceType != "POSTGRESQL_QUERY" ||
			status.PostgreSQLSchemaName == nil || *status.PostgreSQLSchemaName != schema ||
			status.PostgreSQLRelationName == nil || *status.PostgreSQLRelationName != "waste_daily" {
			t.Fatalf("PGQ source status metadata=%#v", status)
		}
		outsider := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOutsider, RequestID: "req_pgq_status_outsider"}
		if _, err := authorityStore.ListSources(ctx, outsider, workspaceBinding.workspaceID); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("PGQ outsider source status: err=%v code=%s", err, workspacerepository.CodeOf(err))
		}
	})
	// Preserve the explicit SUM contract independently of the tool/read
	// surface above. The unresolved natural-language metric is covered by
	// TestPostgreSQLCreateRejectsUnknownAggregateMetricWithNumericSnapshot.
	t.Run("legacy_extractive_aggregate", func(t *testing.T) {
		questions, err := question.New(appStore, auditStore, codec, viewer)
		if err != nil {
			t.Fatal(err)
		}
		answer, err := questions.Create(ctx, regOwnerAccess("req_pgq_question"), question.CreateRequest{
			WorkspaceID: workspaceBinding.workspaceID, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f? metric_field=tonnes", AnswerMode: "EXTRACTIVE",
			IdempotencyKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		})
		if err != nil {
			t.Fatalf("question over published PGQ rows: %v (code=%s)", err, question.CodeOf(err))
		}
		if answer.ResultStatus != "COMPLETED" || !strings.HasPrefix(answer.Answer, "\u041e\u0442\u0432\u0435\u0442: 19.470.\n") || len(answer.Citations) != 2 {
			t.Fatalf("PGQ question answer=%q status=%s citations=%d", answer.Answer, answer.ResultStatus, len(answer.Citations))
		}
		if result := answer.AnswerResult; result == nil || result.Kind != "CALCULATION" ||
			result.Operation != "SUM" || result.Value != "19.470" ||
			result.Rule != "\u0441\u0443\u043c\u043c\u0430 \u043a\u043e\u043b\u043e\u043d\u043a\u0438 \u00abtonnes\u00bb" || result.Snapshot.RowCount != 2 {
			t.Fatalf("PGQ explicit SUM result=%#v", result)
		}
	})
}

func TestSourceActivationAndStatus(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "line one\nline two\n")
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)

	result, err := service.Register(ctx, regOwnerAccess("req_reg_main"), regRequest())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	scopeID := result.SourceScopeID
	var scopeConfigHash string
	var contentFreshnessSLASeconds int64
	if err := admin.QueryRow(ctx, `SELECT scope_config_hash FROM public.source_scope_revision
		WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, scopeID).Scan(&scopeConfigHash); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT content_freshness_sla_seconds FROM public.source_scope_revision
		WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, scopeID).Scan(&contentFreshnessSLASeconds); err != nil {
		t.Fatal(err)
	}

	t.Run("activation is denied while trust is DRAFT", func(t *testing.T) {
		_, err := service.Activate(ctx, regOwnerAccess("req_act_1"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-1", SourceScopeID: scopeID})
		if registration.CodeOf(err) != registration.CodeDenied {
			t.Fatalf("activate with DRAFT trust: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	if _, err := admin.Exec(ctx, `UPDATE public.source_connection_trust_projection AS projection
		SET status='VERIFIED'
		FROM public.source_connection_trust_record AS record
		WHERE projection.organization_id=$1 AND record.organization_id=projection.organization_id
		  AND record.id=projection.trust_record_id AND record.connection_id=$2`, regOrg, result.ConnectionID); err != nil {
		t.Fatal(err)
	}

	t.Run("unconfirmed WORKSPACE_MANAGED activation is denied", func(t *testing.T) {
		_, err := service.Activate(ctx, regOwnerAccess("req_act_2"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-2", SourceScopeID: scopeID})
		if registration.CodeOf(err) != registration.CodeDenied {
			t.Fatalf("activate without confirmation: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	t.Run("an unknown scope is not found", func(t *testing.T) {
		_, err := service.Activate(ctx, regOwnerAccess("req_act_unknown"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-unknown", SourceScopeID: "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ"})
		if registration.CodeOf(err) != registration.CodeNotFound {
			t.Fatalf("unknown scope: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	// Mint the real authority chain: binding + actor grant + confirmation through
	// the production repository (exact command receipts), exactly as the S1d read
	// test does for its seeded scope.
	fixture := seedRegistrationWorkspaceBinding(t, ctx, admin, scopeID, scopeConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	authorityStore := newAuthorityRuntime(t, ctx)
	workspaces := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authorityStore, fixture, "reg-grant")
	confirmation, err := authorityStore.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_reg_confirm"),
		confirmRuntimeRequest(fixture, grant, "reg-confirm"))
	if err != nil {
		t.Fatalf("confirm managed source: %v", err)
	}

	var jobID string
	t.Run("confirmed activation places the durable sync job", func(t *testing.T) {
		activated, err := service.Activate(ctx, regOwnerAccess("req_act_3"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-3", SourceScopeID: scopeID})
		if err != nil {
			t.Fatalf("activate: %v (code=%s)", err, registration.CodeOf(err))
		}
		jobID = activated.JobID
		if !strings.HasPrefix(jobID, "syncscope_") {
			t.Fatalf("job id shape: %q", jobID)
		}
		var jobType, payload, jobStatus string
		if err := admin.QueryRow(ctx, `SELECT type, payload_json, status FROM public.job
			WHERE organization_id=$1 AND id=$2`, regOrg, jobID).Scan(&jobType, &payload, &jobStatus); err != nil {
			t.Fatalf("job row: %v", err)
		}
		if jobType != "SOURCE_SCOPE_SYNC" || jobStatus != "PENDING" || !strings.Contains(payload, scopeID) {
			t.Fatalf("job type=%q status=%q payload=%q", jobType, jobStatus, payload)
		}
		pendingStatuses, err := workspaces.ListSources(ctx, regOwnerAccess("req_status_pending"), regWorkspace)
		if err != nil || len(pendingStatuses) != 1 {
			t.Fatalf("pending source status rows=%d err=%v", len(pendingStatuses), err)
		}
		pending := pendingStatuses[0]
		if pending.JobID == nil || *pending.JobID != jobID || pending.JobStatus == nil || *pending.JobStatus != "PENDING" {
			t.Fatalf("pending job projection=%#v", pending)
		}
		if pending.JobAttemptCount == nil || *pending.JobAttemptCount != 0 || pending.JobMaxAttempts == nil || *pending.JobMaxAttempts != 3 {
			t.Fatalf("pending job attempts=%v/%v", pending.JobAttemptCount, pending.JobMaxAttempts)
		}
		if pending.JobAvailableAt == nil || pending.JobLeaseExpiresAt != nil || pending.JobLastErrorCode != nil {
			t.Fatalf("pending job timing/error=%v/%v/%v", pending.JobAvailableAt, pending.JobLeaseExpiresAt, pending.JobLastErrorCode)
		}
		if pending.ContentFreshnessSLASeconds != contentFreshnessSLASeconds || pending.LastSuccessfulSyncAt != nil || pending.FreshnessState != "UNKNOWN" {
			t.Fatalf("pending freshness=%d/%v/%s", pending.ContentFreshnessSLASeconds, pending.LastSuccessfulSyncAt, pending.FreshnessState)
		}
		var auditCount int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='source.activation_requested' AND resource_id=$2
			  AND metadata_json @> jsonb_build_object('connector_job_id', $3::text)`,
			regOrg, scopeID, jobID).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatalf("activation audit events=%d err=%v", auditCount, err)
		}

		// Idempotent repeat with the same key returns the same job, no new unit.
		again, err := service.Activate(ctx, regOwnerAccess("req_act_4"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-3", SourceScopeID: scopeID})
		if err != nil || again.JobID != jobID {
			t.Fatalf("idempotent activate: again=%#v err=%v", again, err)
		}
		var jobs int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE organization_id=$1 AND id=$2`,
			regOrg, jobID).Scan(&jobs); err != nil || jobs != 1 {
			t.Fatalf("duplicate jobs=%d err=%v", jobs, err)
		}
		// AUD-005: the replay converges on the original audit record; no second
		// activation audit event may exist for the same job.
		var auditAfterRepeat int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='source.activation_requested' AND resource_id=$2
			  AND metadata_json @> jsonb_build_object('connector_job_id', $3::text)`,
			regOrg, scopeID, jobID).Scan(&auditAfterRepeat); err != nil || auditAfterRepeat != 1 {
			t.Fatalf("audit events after idempotent repeat=%d err=%v (want 1)", auditAfterRepeat, err)
		}
	})

	// A scope is activated more than once in its life: an operator disables and
	// re-enables it, a demo cycle re-runs, a failed activation is retried after
	// the cause is fixed. The activation job id used to be derived from
	// (organization, scope) alone, so every later activation addressed the SAME
	// row -- and a finished job is immutable by design (000013 job_state_guard:
	// "a terminal job never moves again"). That collision first surfaced as an
	// unhandled unique violation (503), and after 000070 taught app.enqueue_job
	// to answer with the colliding row's id it became silent: :activate returned
	// 200 with the id of a job that had already SUCCEEDED or gone DEAD, while
	// enqueuing nothing. Live on the acceptance stand, the GIT and
	// POSTGRESQL_QUERY sources answered 200 on every :activate and never synced
	// again. A second activation after the first job is terminal must place a
	// NEW runnable job.
	t.Run("activation after a terminal job places a new runnable job", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.job
			SET status='RUNNING', attempt_count=1, lease_owner='worker-test', lease_deadline=transaction_timestamp() + interval '1 minute', lease_epoch=1
			WHERE organization_id=$1 AND id=$2`, regOrg, jobID); err != nil {
			t.Fatalf("lease first activation job: %v", err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.job
			SET status='SUCCEEDED', lease_owner=NULL, lease_deadline=NULL, completed_at=transaction_timestamp()
			WHERE organization_id=$1 AND id=$2`, regOrg, jobID); err != nil {
			t.Fatalf("complete first activation job: %v", err)
		}
		reactivated, err := service.Activate(ctx, regOwnerAccess("req_act_reactivate"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-reactivate", SourceScopeID: scopeID})
		if err != nil {
			t.Fatalf("re-activate after terminal job: %v (code=%s)", err, registration.CodeOf(err))
		}
		if reactivated.JobID == jobID {
			t.Fatalf("re-activation returned the terminal job id %q instead of placing a new job", jobID)
		}
		var status string
		if err := admin.QueryRow(ctx, `SELECT status FROM public.job WHERE organization_id=$1 AND id=$2`,
			regOrg, reactivated.JobID).Scan(&status); err != nil {
			t.Fatalf("re-activation job row: %v", err)
		}
		if status != "PENDING" {
			t.Fatalf("re-activation job status=%q, want PENDING", status)
		}
		// The single-writer invariant the derived id used to carry now lives in
		// the live-job predicate: while that new job is PENDING, another
		// activation converges on it instead of placing a duplicate.
		converged, err := service.Activate(ctx, regOwnerAccess("req_act_converge"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-converge", SourceScopeID: scopeID})
		if err != nil || converged.JobID != reactivated.JobID {
			t.Fatalf("concurrent re-activation converged=%#v err=%v, want job %q", converged, err, reactivated.JobID)
		}
		var live int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job
			WHERE organization_id=$1 AND status IN ('PENDING','RUNNING') AND payload_json->>'source_scope_id'=$2`,
			regOrg, scopeID).Scan(&live); err != nil || live != 1 {
			t.Fatalf("live jobs for scope=%d err=%v, want exactly 1", live, err)
		}
		// This re-activation is now the scope's one unit of work, and the rest
		// of this test walks it through the worker exactly as before.
		jobID = reactivated.JobID
	})

	t.Run("a key reused with a different scope is a conflict", func(t *testing.T) {
		// A second registration (same mount, different relative root) produces a
		// second scope through the same product API; the occupied key must
		// refuse it without consulting the second scope's state gates.
		second, err := service.Register(ctx, regOwnerAccess("req_reg_second"), registration.RegisterRequest{
			Name: "Engineering docs beta", RootAlias: regRootAls, RootIdentity: "vol-2",
			RelativeRoot: "projects/beta", Kind: "documents", Recursive: true,
			IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
			OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN"},
		})
		if err != nil {
			t.Fatalf("register second scope: %v (code=%s)", err, registration.CodeOf(err))
		}
		_, err = service.Activate(ctx, regOwnerAccess("req_act_scope2"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-3", SourceScopeID: second.SourceScopeID})
		if registration.CodeOf(err) != registration.CodeConflict {
			t.Fatalf("activate second scope with occupied key: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	t.Run("activation in SYNCING is a typed conflict", func(t *testing.T) {
		// The state guard permits DRAFT->SYNCING and forbids the reverse, so the
		// scope stays SYNCING for the worker that runs next: begin_sync is
		// idempotent over SYNCING (000014) and publish_ready completes it.
		if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation SET status='SYNCING'
			WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, scopeID); err != nil {
			t.Fatal(err)
		}
		_, err := service.Activate(ctx, regOwnerAccess("req_act_syncing"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-syncing", SourceScopeID: scopeID})
		if registration.CodeOf(err) != registration.CodeConflict {
			t.Fatalf("activate while SYNCING: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	// The registered job is claimed and executed by the worker exactly as it is
	// in production: claim picks the only unit of work in the queue.
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, regMounts{root: root}, regWorkerID, time.Now, ids.New)
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: err=%v ok=%v", err, ok)
	}
	if claimed.ID != jobID {
		t.Fatalf("worker claimed %q, want the registered job %q", claimed.ID, jobID)
	}
	if err := handler.Handle(ctx, workerAccess(t, regOrg), claimed); err != nil {
		t.Fatalf("handle sync: %v (code=%s)", err, ingestion.CodeOf(err))
	}

	// The worker-side begin-sync surface stays fail-closed: the web/API role
	// must not EXECUTE the registered confirmation re-check (000018 section 5).
	t.Run("registered begin sync is a worker-only surface", func(t *testing.T) {
		err := appStore.Write(ctx, regOwnerAccess("req_act_workeronly"), func(ctx context.Context, tx database.Transaction) error {
			_, execErr := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1, $2, $3, $4, $5)`,
				scopeID, int64(1), "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ", regWorkerID, int64(1))
			return execErr
		})
		if err == nil {
			t.Fatalf("knowvault_app can execute the worker-only registered begin sync")
		}
	})

	t.Run("a key occupied by a different job type is a conflict", func(t *testing.T) {
		// The client key is the durable job's idempotency key; a job of any
		// other type already holding it must refuse the activation surface
		// before any scope state gate is consulted (WSP-014).
		otherTypeQueue, err := jobs.New(appStore)
		if err != nil {
			t.Fatalf("job queue: %v", err)
		}
		if _, err := otherTypeQueue.Enqueue(ctx, regOwnerAccess("req_act_othertype"), jobs.Spec{
			JobID: "outbox_01H9ABCDEFGHJKMNPQRSTVWXYZ", Type: jobs.TypeOutboxDelivery,
			Payload: jobs.Payload{}, IdempotencyKey: "activate-key-other-type",
			Priority: 100, MaxAttempts: 3, AvailableAfter: 0,
		}); err != nil {
			t.Fatalf("enqueue other-type job: %v", err)
		}
		_, err = service.Activate(ctx, regOwnerAccess("req_act_othertype_2"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-other-type", SourceScopeID: scopeID})
		if registration.CodeOf(err) != registration.CodeConflict {
			t.Fatalf("activate with key of another job type: err=%v code=%s", err, registration.CodeOf(err))
		}
		// The probe job must not leak into the worker claims of the later
		// sub-tests. Rows are delete-fenced (hard-delete gate), so the probe is
		// pushed past the claim horizon instead — this suite owns the whole
		// test database.
		if _, err := admin.Exec(ctx, `UPDATE public.job SET available_at = transaction_timestamp() + interval '1 hour'
			WHERE organization_id=$1 AND id=$2`,
			regOrg, "outbox_01H9ABCDEFGHJKMNPQRSTVWXYZ"); err != nil {
			t.Fatalf("park probe job: %v", err)
		}
	})

	statusOf := func(t *testing.T, access database.AccessContext) []workspacerepository.SourceStatus {
		t.Helper()
		statuses, err := workspaces.ListSources(ctx, access, regWorkspace)
		if err != nil {
			t.Fatalf("list sources: %v (code=%s)", err, workspacerepository.CodeOf(err))
		}
		return statuses
	}

	t.Run("the status API exposes the synced source", func(t *testing.T) {
		statuses := statusOf(t, regOwnerAccess("req_status_1"))
		if len(statuses) != 1 {
			t.Fatalf("status rows=%d", len(statuses))
		}
		status := statuses[0]
		if status.WorkspaceSourceID == "" || status.SourceScopeID != scopeID || !status.Enabled || status.AccessMode != "WORKSPACE_MANAGED" {
			t.Fatalf("status = %#v", status)
		}
		if status.ConnectionID != result.ConnectionID || status.ConnectionName != "Engineering docs" {
			t.Fatalf("connection = %s/%s", status.ConnectionID, status.ConnectionName)
		}
		if status.ActivationStatus != "READY" || !status.TrustVerified {
			t.Fatalf("activation=%s trust=%v", status.ActivationStatus, status.TrustVerified)
		}
		if status.SyncStatus == nil || *status.SyncStatus != "SUCCEEDED" {
			t.Fatalf("sync status=%v", status.SyncStatus)
		}
		if status.ObjectsSeen == nil || *status.ObjectsSeen != 1 || status.ObjectsIngested == nil || *status.ObjectsIngested != 1 {
			t.Fatalf("counters seen=%v ingested=%v", status.ObjectsSeen, status.ObjectsIngested)
		}
		if status.VersionsCreated == nil || *status.VersionsCreated != 1 || status.EvidencePublished == nil || *status.EvidencePublished < 1 {
			t.Fatalf("counters versions=%v evidence=%v", status.VersionsCreated, status.EvidencePublished)
		}
		if status.Quarantined == nil || *status.Quarantined != 0 {
			t.Fatalf("quarantined=%v", status.Quarantined)
		}
		if status.SyncErrorCode != nil {
			t.Fatalf("unexpected sync error code: %s", *status.SyncErrorCode)
		}
		if status.JobID == nil || *status.JobID != jobID || status.JobStatus == nil || *status.JobStatus != "SUCCEEDED" {
			t.Fatalf("terminal job=%v/%v", status.JobID, status.JobStatus)
		}
		if status.JobAttemptCount == nil || *status.JobAttemptCount != 1 || status.JobMaxAttempts == nil || *status.JobMaxAttempts != 3 {
			t.Fatalf("terminal attempts=%v/%v", status.JobAttemptCount, status.JobMaxAttempts)
		}
		if status.JobAvailableAt == nil || status.JobLeaseExpiresAt != nil || status.JobLastErrorCode != nil {
			t.Fatalf("terminal job timing/error=%v/%v/%v", status.JobAvailableAt, status.JobLeaseExpiresAt, status.JobLastErrorCode)
		}
		if status.ContentFreshnessSLASeconds != contentFreshnessSLASeconds || status.LastSuccessfulSyncAt == nil || status.FreshnessState != "FRESH" {
			t.Fatalf("successful freshness=%d/%v/%s", status.ContentFreshnessSLASeconds, status.LastSuccessfulSyncAt, status.FreshnessState)
		}

		// A member of the workspace sees the same status; a non-member is denied
		// with the identical not-found.
		viewer := database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_status_2"}
		if got := statusOf(t, viewer); len(got) != 1 {
			t.Fatalf("viewer status rows=%d", len(got))
		}
		outsider := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOutsider, RequestID: "req_status_3"}
		if _, err := workspaces.ListSources(ctx, outsider, regWorkspace); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("outsider list: err=%v code=%s", err, workspacerepository.CodeOf(err))
		}
	})

	t.Run("freshness changes at the server-owned SLA boundary", func(t *testing.T) {
		freshRunID := mustID(t, "syncrun")
		if _, err := admin.Exec(ctx, `INSERT INTO public.sync_run
			(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, started_at, coverage_complete, completed_at)
			VALUES ($1, $2, $3, 1, $4, 'FULL', 'SUCCEEDED', transaction_timestamp(), true,
				transaction_timestamp() - make_interval(secs => $5::double precision) + interval '1 second')`,
			regOrg, freshRunID, scopeID, jobID, contentFreshnessSLASeconds); err != nil {
			t.Fatal(err)
		}
		fresh := statusOf(t, regOwnerAccess("req_status_fresh_boundary"))
		if len(fresh) != 1 || fresh[0].LastSuccessfulSyncAt == nil || fresh[0].FreshnessState != "FRESH" {
			t.Fatalf("fresh boundary status=%#v", fresh)
		}

		staleRunID := mustID(t, "syncrun")
		if _, err := admin.Exec(ctx, `INSERT INTO public.sync_run
			(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, started_at, coverage_complete, completed_at)
			VALUES ($1, $2, $3, 1, $4, 'FULL', 'SUCCEEDED', transaction_timestamp(), true,
				transaction_timestamp() - make_interval(secs => $5::double precision) - interval '1 microsecond')`,
			regOrg, staleRunID, scopeID, jobID, contentFreshnessSLASeconds); err != nil {
			t.Fatal(err)
		}
		stale := statusOf(t, regOwnerAccess("req_status_stale_boundary"))
		if len(stale) != 1 || stale[0].LastSuccessfulSyncAt == nil || stale[0].FreshnessState != "STALE" {
			t.Fatalf("stale boundary status=%#v", stale)
		}
	})

	t.Run("a broken file is quarantined, not a failure, and surfaces typed", func(t *testing.T) {
		writeS1dFile(t, filepath.Join(dir, "corrupt.bin"), "\x00\x01\x02not-a-known-format\xff\xfe")
		runSyncScopeFor(t, ctx, handler, workerQueue, workerAccess(t, regOrg), regWorkerID, scopeID, "sync-corrupt")
		statuses := statusOf(t, regOwnerAccess("req_status_4"))
		if len(statuses) != 1 || statuses[0].Quarantined == nil || *statuses[0].Quarantined != 1 {
			t.Fatalf("quarantined status = %#v", statuses)
		}
		if statuses[0].SyncStatus == nil || *statuses[0].SyncStatus != "SUCCEEDED" {
			t.Fatalf("quarantine run status=%v", statuses[0].SyncStatus)
		}
	})

	t.Run("a failed run exposes the typed error code", func(t *testing.T) {
		// The worker-side FAILED projection: a later run recorded with a typed
		// operator-facing code, as handler.failSync writes it.
		failedRunID := mustID(t, "syncrun")
		if _, err := admin.Exec(ctx, `INSERT INTO public.sync_run
			(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, error_code, started_at, completed_at)
			VALUES ($1, $2, $3, 1, $4, 'FULL', 'FAILED', 'INGEST_CONNECTOR_READ', now()+interval '1 minute', now())`,
			regOrg, failedRunID, scopeID, jobID); err != nil {
			t.Fatal(err)
		}
		statuses := statusOf(t, regOwnerAccess("req_status_5"))
		if len(statuses) != 1 || statuses[0].SyncStatus == nil || *statuses[0].SyncStatus != "FAILED" {
			t.Fatalf("failed status = %#v", statuses)
		}
		if statuses[0].SyncErrorCode == nil || *statuses[0].SyncErrorCode != "INGEST_CONNECTOR_READ" {
			t.Fatalf("typed error code = %v", statuses[0].SyncErrorCode)
		}
	})

	// A revocation of the confirmation must close the activation gate for any
	// future activation of the same scope (the derived-live mirror, 000018 s3):
	// the same predicate the worker re-checks at claim time. It runs last so the
	// sync sub-tests above still see a live confirmation.
	t.Run("a revoked confirmation refuses a new activation", func(t *testing.T) {
		if _, err := authorityStore.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_reg_revoke"),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey: authorityIdempotencyKey("reg-confirm-revoke"), OrganizationID: fixture.organizationID,
				WorkspaceID: fixture.workspaceID, ConfirmationID: confirmation.ResultID, ConfirmationHash: confirmation.ResultHash,
				ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("revoke confirmation: %v", err)
		}
		_, err := service.Activate(ctx, regOwnerAccess("req_act_revoked"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-revoked", SourceScopeID: scopeID})
		if registration.CodeOf(err) != registration.CodeDenied {
			t.Fatalf("activate after confirmation revocation: err=%v code=%s", err, registration.CodeOf(err))
		}
	})

	// The claim-time derived-live re-check (000018 s5) is a second, independent
	// gate: the worker re-checks the exact-tuple confirmation inside the same
	// fence as begin_sync, because between activation and claim a confirmation
	// can be revoked. The revocation above is terminal, so this scenario runs
	// on a second scope minted the same way: register -> confirm -> activate
	// (durable PENDING job) -> revoke -> claim -> the worker must fail closed
	// with SQLSTATE 55000 — the same predicate the activation gate uses, though
	// that gate denies through its typed CodeDenied — never begin a partial
	// sync.
	t.Run("claim after confirmation revocation fails closed", func(t *testing.T) {
		second, err := service.Register(ctx, regOwnerAccess("req_reg_third"), registration.RegisterRequest{
			Name: "Engineering docs gamma", RootAlias: regRootAls, RootIdentity: "vol-3",
			RelativeRoot: "projects/gamma", Kind: "documents", Recursive: true,
			IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
			OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN"},
		})
		if err != nil {
			t.Fatalf("register claim-time scope: %v (code=%s)", err, registration.CodeOf(err))
		}
		scope2 := second.SourceScopeID
		var scope2ConfigHash string
		if err := admin.QueryRow(ctx, `SELECT scope_config_hash FROM public.source_scope_revision
			WHERE organization_id=$1 AND source_scope_id=$2 AND revision=1`, regOrg, scope2).Scan(&scope2ConfigHash); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.source_connection_trust_projection AS projection
			SET status='VERIFIED'
			FROM public.source_connection_trust_record AS record
			WHERE projection.organization_id=$1 AND record.organization_id=projection.organization_id
			  AND record.id=projection.trust_record_id AND record.connection_id=$2`, regOrg, second.ConnectionID); err != nil {
			t.Fatal(err)
		}
		fixture2 := seedRegistrationWorkspaceBinding(t, ctx, admin, scope2, scope2ConfigHash, "binding_01ARZ3NDEKTSV4RRFFQ69G5FBY")
		authorityStore2 := newAuthorityRuntime(t, ctx)
		grant2 := issueRuntimeGrant(t, ctx, authorityStore2, fixture2, "reg2-grant")
		confirmation2, err := authorityStore2.ConfirmManagedSource(ctx, authorityAccess(fixture2, fixture2.ownerID, "req_reg2_confirm"),
			confirmRuntimeRequest(fixture2, grant2, "reg2-confirm"))
		if err != nil {
			t.Fatalf("confirm claim-time managed source: %v", err)
		}
		activated2, err := service.Activate(ctx, regOwnerAccess("req_act_scope2"), registration.ActivateRequest{
			IdempotencyKey: "activate-key-scope2", SourceScopeID: scope2})
		if err != nil {
			t.Fatalf("activate claim-time scope: %v (code=%s)", err, registration.CodeOf(err))
		}
		// The revocation lands between job placement and the worker claim: the
		// job is already durable, the confirmation no longer is.
		if _, err := authorityStore2.RevokeManagedConfirmation(ctx, authorityAccess(fixture2, fixture2.ownerID, "req_reg2_revoke"),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey: authorityIdempotencyKey("reg2-confirm-revoke"), OrganizationID: fixture2.organizationID,
				WorkspaceID: fixture2.workspaceID, ConfirmationID: confirmation2.ResultID, ConfirmationHash: confirmation2.ResultHash,
				ExpectedPolicyRevision: fixture2.policyID,
			}); err != nil {
			t.Fatalf("revoke claim-time confirmation: %v", err)
		}
		// The worker claims and runs the job through the production path; the
		// claim-time re-check must deny with SQLSTATE 55000 and a typed
		// INGEST_BEGIN_SYNC failure — never a partial sync.
		claimed2, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
		if err != nil || !ok {
			t.Fatalf("claim claim-time scope: err=%v ok=%v", err, ok)
		}
		if claimed2.ID != activated2.JobID {
			t.Fatalf("worker claimed %q, want the claim-time job %q", claimed2.ID, activated2.JobID)
		}
		claimErr := handler.Handle(ctx, workerAccess(t, regOrg), claimed2)
		if claimErr == nil {
			t.Fatal("handle after revocation: expected a fail-closed error, got nil")
		}
		if got := ingestion.CodeOf(claimErr); got != "INGEST_BEGIN_SYNC" {
			t.Fatalf("handle after revocation: code=%s err=%v, want INGEST_BEGIN_SYNC", got, claimErr)
		}
		var pgErr *pgconn.PgError
		if !errors.As(claimErr, &pgErr) || pgErr.Code != "55000" {
			t.Fatalf("handle after revocation: want the 55000 derived-live denial, got %v", claimErr)
		}
	})

	t.Run("revoked viewer receives the same not-found denial", func(t *testing.T) {
		current, err := workspaces.Get(ctx, regOwnerAccess("req_status_remove_viewer_get"), regWorkspace)
		if err != nil {
			t.Fatalf("get current workspace before viewer removal: %v", err)
		}
		if _, err := workspaces.RemoveMember(ctx, regOwnerAccess("req_status_remove_viewer_remove"), workspacerepository.RemoveMemberRequest{
			IdempotencyKey: workspaceIdempotencyKey("status-remove-viewer"), WorkspaceID: regWorkspace,
			ExpectedConfigurationHash: mustWorkspaceHash(t, current), PrincipalID: regViewer,
		}); err != nil {
			t.Fatalf("remove seeded viewer: %v (code=%s)", err, workspacerepository.CodeOf(err))
		}
		viewer := database.AccessContext{OrganizationID: regOrg, PrincipalID: regViewer, RequestID: "req_status_removed_viewer"}
		if _, err := workspaces.Get(ctx, viewer, regWorkspace); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("removed viewer workspace get code=%q err=%v", workspacerepository.CodeOf(err), err)
		}
		if _, err := workspaces.ListSources(ctx, viewer, regWorkspace); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
			t.Fatalf("removed viewer source status code=%q err=%v", workspacerepository.CodeOf(err), err)
		}
	})
}
