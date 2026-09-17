package postgres_test

// The rowset path must resolve the cited fragment's live source scope before
// it scans typed cells. This is an end-to-end contract check for two
// simultaneously enabled PostgreSQL projections: a full rowset for a
// fragment from source A contains A's current rows only, while the existing
// per-fragment readability gate still governs the returned cells.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
)

func TestStructuredRowsetScopedSourceVersionKeepsScopeBoundary(t *testing.T) {
	externalURL := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL"))
	if externalURL == "" {
		if os.Getenv("KNOWVAULT_REQUIRE_EXTERNAL_PG") == "1" {
			t.Fatal("KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL is required")
		}
		t.Skip("set KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL for the scoped rowset proof")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	external, err := pgx.Connect(ctx, externalURL)
	if err != nil {
		t.Fatalf("external PostgreSQL: %v", err)
	}
	defer external.Close(context.Background())

	const schema = "kv_pgq_rowset_scope_bound"
	if _, err := external.Exec(ctx, `
		DROP SCHEMA IF EXISTS "kv_pgq_rowset_scope_bound" CASCADE;
		CREATE SCHEMA "kv_pgq_rowset_scope_bound";
		CREATE TABLE "kv_pgq_rowset_scope_bound"."left_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
		CREATE TABLE "kv_pgq_rowset_scope_bound"."right_data" (
			route_id uuid NOT NULL,
			collected_at timestamptz NOT NULL,
			tonnes numeric(12,3) NOT NULL,
			note text
		);
	`); err != nil {
		t.Fatalf("seed external scoped-rowset tables: %v", err)
	}
	collected := time.Now().UTC().Truncate(time.Millisecond)
	if _, err := external.Exec(ctx, `INSERT INTO "kv_pgq_rowset_scope_bound"."left_data" VALUES ($1, $2, 10.000, 'left-only')`,
		"550e8400-e29b-41d4-a716-446655440071", collected); err != nil {
		t.Fatalf("seed external left row: %v", err)
	}
	if _, err := external.Exec(ctx, `INSERT INTO "kv_pgq_rowset_scope_bound"."right_data" VALUES ($1, $2, 20.000, 'right-only')`,
		"550e8400-e29b-41d4-a716-446655440072", collected); err != nil {
		t.Fatalf("seed external right row: %v", err)
	}
	if _, err := external.Exec(ctx, `
		CREATE VIEW "kv_pgq_rowset_scope_bound"."left_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_rowset_scope_bound"."left_data";
		CREATE VIEW "kv_pgq_rowset_scope_bound"."right_view" AS
			SELECT route_id, collected_at, tonnes, note FROM "kv_pgq_rowset_scope_bound"."right_data";
	`); err != nil {
		t.Fatalf("create external scoped-rowset views: %v", err)
	}
	defer func() { _, _ = external.Exec(context.Background(), `DROP SCHEMA "kv_pgq_rowset_scope_bound" CASCADE`) }()

	admin := resetStage1Database(t)
	appStore, codec, registrations := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	leftRequest := isolationProjectionRequest(schema, "left_view", "rowset-scope-left", "Scoped left", "sha256:"+strings.Repeat("1", 64))
	leftSource, err := registrations.Register(ctx, regOwnerAccess("req_rowset_scope_left_register"), leftRequest)
	if err != nil {
		t.Fatalf("register left projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, leftSource.ConnectionID)

	rightRequest := isolationProjectionRequest(schema, "right_view", "rowset-scope-right", "Scoped right", "sha256:"+strings.Repeat("2", 64))
	rightSource, err := registrations.Register(ctx, regOwnerAccess("req_rowset_scope_right_register"), rightRequest)
	if err != nil {
		t.Fatalf("register right projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, rightSource.ConnectionID)

	authority := newAuthorityRuntime(t, ctx)
	leftBindingID := agg2StableWorkspaceSourceID(regOrg, regWorkspace, leftSource.SourceScopeID)
	leftBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, leftSource.SourceScopeID, leftSource.ScopeConfigHash, leftBindingID)
	leftGrant := issueRuntimeGrant(t, ctx, authority, leftBinding, "rowset-scope-left-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(leftBinding, regOwner, "req_rowset_scope_left_confirm"), confirmRuntimeRequest(leftBinding, leftGrant, "rowset-scope-left-confirm")); err != nil {
		t.Fatalf("confirm left projection: %v", err)
	}

	rightBindingID := agg2StableWorkspaceSourceID(regOrg, regWorkspace, rightSource.SourceScopeID)
	rightBinding := seedRegistrationWorkspaceBinding(t, ctx, admin, rightSource.SourceScopeID, rightSource.ScopeConfigHash, rightBindingID)
	rightGrant := issueRuntimeGrant(t, ctx, authority, rightBinding, "rowset-scope-right-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(rightBinding, regOwner, "req_rowset_scope_right_confirm"), confirmRuntimeRequest(rightBinding, rightGrant, "rowset-scope-right-confirm")); err != nil {
		t.Fatalf("confirm right projection: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, leftSource, leftRequest, "rowset-scope-left")
	publishIsolationProjection(t, ctx, external, appStore, workerStore, workerQueue, handler, rightSource, rightRequest, "rowset-scope-right")

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}

	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_rowset_scope_read"}
	var leftFragment string
	if err := appStore.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT cell.evidence_fragment_id
			  FROM public.structured_snapshot_cell AS cell
			  JOIN public.source_version AS version
			    ON version.organization_id = cell.organization_id
			   AND version.id = cell.source_version_id
			  JOIN public.source_object_scope AS membership
			    ON membership.organization_id = version.organization_id
			   AND membership.source_object_id = version.source_object_id
			   AND membership.source_scope_id = $2
			 WHERE cell.organization_id = $1
			 ORDER BY cell.column_ordinal
			 LIMIT 1
		`, regOrg, leftSource.SourceScopeID).Scan(&leftFragment)
	}); err != nil {
		t.Fatalf("find left structured fragment: %v", err)
	}

	// Publish a newer version for source A. The old fragment must become
	// unreadable, and the new rowset must contain only the current version --
	// the scoped query must not reload historical cells from the same object.
	currentCollected := collected.Add(time.Minute)
	if _, err := external.Exec(ctx, `UPDATE "kv_pgq_rowset_scope_bound"."left_data" SET collected_at=$1, note='left-current'`, currentCollected); err != nil {
		t.Fatalf("advance left projection: %v", err)
	}
	publishScopedRevision(t, ctx, external, appStore, workerStore, workerQueue, handler, leftSource, leftRequest, "rowset-scope-left-current")

	var currentLeftFragment string
	if err := appStore.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		return tx.QueryRow(txCtx, `
			SELECT cell.evidence_fragment_id
			  FROM public.structured_snapshot_cell AS cell
			  JOIN public.source_version AS version
			    ON version.organization_id = cell.organization_id
			   AND version.id = cell.source_version_id
			  JOIN public.source_object AS object
			    ON object.organization_id = version.organization_id
			   AND object.id = version.source_object_id
			  JOIN public.source_object_scope AS membership
			    ON membership.organization_id = object.organization_id
			   AND membership.source_object_id = object.id
			   AND membership.source_scope_id = $2
			 WHERE cell.organization_id = $1
			   AND object.lifecycle_state = 'ACTIVE'
			   AND object.current_version_id = version.id
			   AND version.state = 'CURRENT'
			 ORDER BY cell.column_ordinal
			 LIMIT 1
		`, regOrg, leftSource.SourceScopeID).Scan(&currentLeftFragment)
	}); err != nil {
		t.Fatalf("find current left structured fragment: %v", err)
	}
	if currentLeftFragment == leftFragment {
		t.Fatal("current left fragment did not advance after publishing a new source version")
	}
	oldRowset, err := questions.StructuredRowset(ctx, access, regWorkspace, leftFragment, question.RowsetScopeFull)
	if err != nil {
		t.Fatalf("historical left rowset: %v", err)
	}
	if oldRowset != nil {
		t.Fatalf("historical left fragment remained readable: %#v", oldRowset)
	}

	rowset, err := questions.StructuredRowset(ctx, access, regWorkspace, currentLeftFragment, question.RowsetScopeFull)
	if err != nil {
		t.Fatalf("full scoped rowset: %v", err)
	}
	if rowset == nil || rowset.Snapshot.ID != leftSource.SourceScopeID || rowset.Total != 1 || len(rowset.Rows) != 1 {
		t.Fatalf("left rowset=%#v, want one row from left scope %q", rowset, leftSource.SourceScopeID)
	}
	if rowset.Rows[0]["note"] != "left-current" {
		t.Fatalf("left rowset leaked another live scope: %#v", rowset.Rows)
	}
}

// publishScopedRevision is the existing production publication sequence with
// the repeat-safe counter assertion needed here: republishing an existing
// object creates a new current version but does not count a new object.
func publishScopedRevision(t *testing.T, ctx context.Context, external *pgx.Conn, appStore, workerStore *database.Store, workerQueue *jobs.Queue, handler *ingestion.Handler, registered registration.RegisterResult, request registration.RegisterRequest, label string) {
	t.Helper()
	appQueue, err := jobs.New(appStore)
	if err != nil {
		t.Fatalf("create app queue %s: %v", label, err)
	}
	jobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_iso_enqueue_"+label), jobs.Spec{
		JobID: jobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "iso-job-" + label, Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue %s: %v", label, err)
	}
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if claimed.ID != jobID {
		t.Fatalf("claimed %s job=%q want=%q", label, claimed.ID, jobID)
	}
	publishRunID := mustID(t, "syncrun")
	projection := requestProjection(registered.ConnectionID, request)
	if err := workerStore.Write(ctx, workerAccess(t, regOrg), func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, publishRunID, registered.SourceScopeID, claimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin %s publication: %v", label, err)
	}
	snapshot, err := postgresqlquery.ReadProjection(ctx, external, projection, postgresqlquery.DefaultLimits())
	if err != nil {
		t.Fatalf("read %s external projection: %v", label, err)
	}
	result, err := handler.PublishPostgreSQLSnapshot(ctx, workerAccess(t, regOrg), ingestion.PostgreSQLSnapshotRequest{ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: publishRunID, Projection: projection, Snapshot: snapshot, Claimed: claimed})
	if err != nil {
		t.Fatalf("publish %s snapshot: %v (code=%s)", label, err, ingestion.CodeOf(err))
	}
	expectedRows := len(snapshot.Rows)
	expectedEvidence := expectedPublishedEvidence(t, snapshot, request)
	if result.ObjectsSeen != expectedRows || result.VersionsCreated != expectedRows || result.EvidencePublished != expectedEvidence {
		t.Fatalf("publish %s counters=%#v", label, result)
	}
	if err := workerQueue.Complete(ctx, workerAccess(t, regOrg), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete %s: %v", label, err)
	}
}
