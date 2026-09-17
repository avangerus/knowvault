package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// The production PostgreSQL publisher must expose A -> B -> A as three
// immutable observations, while repeats produce no new version or evidence.
func TestPostgreSQLReobservationPreservesHistoryAndRepeat(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest("kv_returns", "rows", "returns", "Return rows", "sha256:"+strings.Repeat("7", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_return_register"), request)
	if err != nil {
		t.Fatal(err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, binding, "return-grant")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(binding, regOwner, "req_return_confirm"), confirmRuntimeRequest(binding, grant, "return-confirm")); err != nil {
		t.Fatal(err)
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
	projection := requestProjection(registered.ConnectionID, request)
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec, ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New)
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	type retained struct{ version, fragment, text, hash string }
	history := []retained{}
	previous := ""
	for i, amount := range []string{"100.000", "100.000", "200.000", "100.000", "100.000", "200.000", "100.000"} {
		label := fmt.Sprintf("return-%d", i)
		row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{"550e8400-e29b-41d4-a716-000000000001", "2026-08-01T12:34:56.789Z", amount, "region-00"})
		if err != nil {
			t.Fatal(err)
		}
		hash, err := postgresqlquery.SnapshotSetHash([]postgresqlquery.Row{row})
		if err != nil {
			t.Fatal(err)
		}
		snapshot := postgresqlquery.Snapshot{Rows: []postgresqlquery.Row{row}, RowCount: 1, CoverageComplete: true, SnapshotHash: hash}
		if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_"+label), jobs.Spec{JobID: mustID(t, "job"), Type: jobs.TypePostgreSQLQuerySync, Payload: jobs.Payload{"source_scope_id": registered.SourceScopeID}, IdempotencyKey: label, Priority: 100, MaxAttempts: 1}); err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
		if err != nil || !ok {
			t.Fatalf("claim: %v %v", err, ok)
		}
		run := mustID(t, "syncrun")
		if err := workerStore.Write(ctx, workerAccess(t, regOrg), func(ctx context.Context, tx database.Transaction) error {
			if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, run, registered.SourceScopeID, claimed.ID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		result, err := handler.PublishPostgreSQLSnapshot(ctx, workerAccess(t, regOrg), ingestion.PostgreSQLSnapshotRequest{ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: run, Projection: projection, Snapshot: snapshot, Claimed: claimed})
		if err != nil {
			t.Fatalf("step %d publish: %v", i, err)
		}
		if err := workerQueue.Complete(ctx, workerAccess(t, regOrg), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			t.Fatal(err)
		}
		var version, fragment, actualHash string
		if err := admin.QueryRow(ctx, `SELECT v.id,f.id,v.content_hash FROM public.source_object o JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id JOIN public.evidence_fragment f ON f.organization_id=v.organization_id AND f.source_version_id=v.id WHERE o.organization_id=$1 AND o.connection_id=$2 ORDER BY f.ordinal LIMIT 1`, regOrg, registered.ConnectionID).Scan(&version, &fragment, &actualHash); err != nil {
			t.Fatal(err)
		}
		if actualHash != row.Hash {
			t.Fatalf("step %d current hash=%s want=%s", i, actualHash, row.Hash)
		}
		whole, err := viewer.ReadObject(ctx, regOwnerAccess("req_"+label+"_read"), binding.workspaceID, fragment)
		if err != nil {
			t.Fatal(err)
		}
		if amount != previous {
			if result.VersionsCreated != 1 || result.EvidencePublished == 0 {
				t.Fatalf("step %d update counters: %+v", i, result)
			}
			for _, old := range history {
				if old.version == version {
					t.Fatalf("step %d revived historical version", i)
				}
			}
			history = append(history, retained{version, fragment, string(whole.Text), row.Hash})
		} else if result.VersionsCreated != 0 || result.EvidencePublished != 0 || version != history[len(history)-1].version {
			t.Fatalf("step %d repeat changed version: %+v", i, result)
		}
		for _, old := range history {
			read, err := viewer.ReadObjectExactVersion(ctx, regOwnerAccess("req_"+label+"_history"), binding.workspaceID, old.fragment, old.version)
			if err != nil || string(read.Text) != old.text {
				t.Fatalf("step %d retained bytes changed: %v", i, err)
			}
			var state, digest string
			if err := admin.QueryRow(ctx, `SELECT state,content_hash FROM public.source_version WHERE organization_id=$1 AND id=$2`, regOrg, old.version).Scan(&state, &digest); err != nil {
				t.Fatal(err)
			}
			want := "SUPERSEDED"
			if old.version == version {
				want = "CURRENT"
			}
			if state != want || digest != old.hash {
				t.Fatalf("step %d immutable history changed", i)
			}
		}
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version WHERE organization_id=$1`, regOrg).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != len(history) {
			t.Fatalf("versions=%d want=%d", count, len(history))
		}
		previous = amount
	}
}
