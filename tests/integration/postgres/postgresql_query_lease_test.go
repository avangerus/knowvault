package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// TestPostgreSQLPublicationLeaseRenewsInsideLongTransaction proves the lease
// boundary used by PublishPostgreSQLSnapshot. The publication transaction
// holds the job row lock, outlives its original lease, renews while still
// owning the exact row/epoch, and commits before a separate completion
// transaction. It also proves that the fresh-clock guard cannot revive an
// expired lease held by a stale worker, even while its old transaction is
// still open.
func TestPostgreSQLPublicationLeaseRenewsInsideLongTransaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_pg_lease", "usr_pg_owner", "ws_pg_lease")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_pg_lease", "usr_pg_owner", outboxRef("job", 1),
		"POSTGRESQL_QUERY_SYNC", "pg-lease-renewal", 3, 0)
	claimed, ok := claimDurableJob(t, ctx, worker, "org_pg_lease", "wrk_pg_live", 3)
	if !ok {
		t.Fatal("expected to claim PostgreSQL publication job")
	}

	// The job row is locked exactly as PublishPostgreSQLSnapshot locks it. The
	// first heartbeat arrives before the original two-second lease expires,
	// then the transaction remains open for longer than that original lease.
	publication, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, publication, "org_pg_lease", "usr_worker")
	if _, err := publication.Exec(ctx, `SELECT app.lock_job_lease($1, $2, $3)`,
		claimed.id, "wrk_pg_live", claimed.leaseEpoch); err != nil {
		_ = publication.Rollback(ctx)
		t.Fatalf("lock publication lease: %v", err)
	}
	if _, err := publication.Exec(ctx, `SELECT pg_sleep(1.5)`); err != nil {
		_ = publication.Rollback(ctx)
		t.Fatalf("wait before publication renewal: %v", err)
	}
	if _, err := publication.Exec(ctx, `SELECT app.heartbeat_job($1, $2, $3, $4)`,
		claimed.id, "wrk_pg_live", claimed.leaseEpoch, 4); err != nil {
		_ = publication.Rollback(ctx)
		t.Fatalf("renew live publication lease: %v", err)
	}
	if _, err := publication.Exec(ctx, `SELECT pg_sleep(2.8)`); err != nil {
		_ = publication.Rollback(ctx)
		t.Fatalf("long publication wait: %v", err)
	}
	if err := publication.Commit(ctx); err != nil {
		t.Fatalf("commit long publication: %v", err)
	}
	if err := completeDurableJob(t, ctx, worker, "org_pg_lease", "wrk_pg_live", claimed); err != nil {
		t.Fatalf("complete renewed publication lease: %v", err)
	}
	if status, _, _ := jobStatus(t, ctx, worker, "org_pg_lease", claimed.id); status != "SUCCEEDED" {
		t.Fatalf("renewed publication status=%q, want SUCCEEDED", status)
	}

	// A separate expired worker cannot renew, lock for publication, or
	// complete. The heartbeat is attempted from a transaction that began
	// before expiry, which catches regressions back to transaction_timestamp().
	enqueueDurableJob(t, ctx, app, "org_pg_lease", "usr_pg_owner", outboxRef("job", 2),
		"POSTGRESQL_QUERY_SYNC", "pg-lease-expired", 3, 0)
	expired, ok := claimDurableJob(t, ctx, worker, "org_pg_lease", "wrk_pg_stale", 1)
	if !ok {
		t.Fatal("expected to claim stale PostgreSQL publication job")
	}
	staleTx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, staleTx, "org_pg_lease", "usr_worker")
	lockTx, err := worker.Begin(ctx)
	if err != nil {
		_ = staleTx.Rollback(ctx)
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, lockTx, "org_pg_lease", "usr_worker")
	if _, err := staleTx.Exec(ctx, `SELECT pg_sleep(1.2)`); err != nil {
		_ = staleTx.Rollback(ctx)
		_ = lockTx.Rollback(ctx)
		t.Fatalf("wait for lease expiry: %v", err)
	}
	assertTxCallRejected(t, ctx, staleTx, `SELECT app.heartbeat_job($1, $2, $3, $4)`,
		expired.id, "wrk_pg_stale", expired.leaseEpoch, 4)
	if err := staleTx.Rollback(ctx); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT pg_sleep(1.2)`); err != nil {
		_ = lockTx.Rollback(ctx)
		t.Fatalf("wait for stale publication lock: %v", err)
	}
	assertTxCallRejected(t, ctx, lockTx, `SELECT app.lock_job_lease($1, $2, $3)`,
		expired.id, "wrk_pg_stale", expired.leaseEpoch)
	if err := lockTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	assertWorkerCallRejected(t, ctx, worker, "org_pg_lease",
		`SELECT app.complete_job($1, 'wrk_pg_stale', $2)`, expired.id, expired.leaseEpoch)
	if reclaimed := reclaimExpiredJobs(t, ctx, worker, "org_pg_lease"); reclaimed != 1 {
		t.Fatalf("reclaimed stale PostgreSQL publication job=%d, want 1", reclaimed)
	}

	// Completion also samples the clock after acquiring its row lock. A
	// transaction opened before the deadline must not acknowledge the job
	// after sleeping past it.
	enqueueDurableJob(t, ctx, app, "org_pg_lease", "usr_pg_owner", outboxRef("job", 3),
		"POSTGRESQL_QUERY_SYNC", "pg-lease-delayed-complete", 3, 0)
	delayed, ok := claimDurableJob(t, ctx, worker, "org_pg_lease", "wrk_pg_delayed", 2)
	if !ok {
		t.Fatal("expected to claim delayed-completion PostgreSQL publication job")
	}
	delayedTx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, delayedTx, "org_pg_lease", "usr_worker")
	if _, err := delayedTx.Exec(ctx, `SELECT pg_sleep(2.2)`); err != nil {
		_ = delayedTx.Rollback(ctx)
		t.Fatalf("wait for delayed completion lease expiry: %v", err)
	}
	var delayedCompleteErr error
	if _, delayedCompleteErr = delayedTx.Exec(ctx, `SELECT app.complete_job($1, $2, $3)`,
		delayed.id, "wrk_pg_delayed", delayed.leaseEpoch); delayedCompleteErr == nil {
		_ = delayedTx.Rollback(ctx)
		t.Fatal("delayed completion unexpectedly succeeded after lease expiry")
	}
	assertLeaseLostError(t, delayedCompleteErr)
	if err := delayedTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if reclaimed := reclaimExpiredJobs(t, ctx, worker, "org_pg_lease"); reclaimed != 1 {
		t.Fatalf("reclaimed delayed-completion job=%d, want 1", reclaimed)
	}

	// A heartbeat that entered before expiry can block behind a publication row
	// lock. If that publication rolls back after the deadline, the heartbeat
	// must re-check the deadline after it acquires the row and fail closed.
	enqueueDurableJob(t, ctx, app, "org_pg_lease", "usr_pg_owner", outboxRef("job", 4),
		"POSTGRESQL_QUERY_SYNC", "pg-lease-blocked-heartbeat", 3, 0)
	blockedJob, ok := claimDurableJob(t, ctx, worker, "org_pg_lease", "wrk_pg_blocked", 2)
	if !ok {
		t.Fatal("expected to claim blocked-heartbeat PostgreSQL publication job")
	}
	blockedPublication, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, blockedPublication, "org_pg_lease", "usr_worker")
	if _, err := blockedPublication.Exec(ctx, `SELECT app.lock_job_lease($1, $2, $3)`,
		blockedJob.id, "wrk_pg_blocked", blockedJob.leaseEpoch); err != nil {
		_ = blockedPublication.Rollback(ctx)
		t.Fatalf("lock blocked publication lease: %v", err)
	}
	heartbeatTx, err := worker.Begin(ctx)
	if err != nil {
		_ = blockedPublication.Rollback(ctx)
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, heartbeatTx, "org_pg_lease", "usr_worker")
	var heartbeatPID int32
	if err := heartbeatTx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&heartbeatPID); err != nil {
		_ = heartbeatTx.Rollback(ctx)
		_ = blockedPublication.Rollback(ctx)
		t.Fatalf("read heartbeat backend pid: %v", err)
	}
	heartbeatDone := make(chan error, 1)
	go func() {
		_, heartbeatErr := heartbeatTx.Exec(ctx, `SELECT app.heartbeat_job($1, $2, $3, $4)`,
			blockedJob.id, "wrk_pg_blocked", blockedJob.leaseEpoch, 4)
		heartbeatDone <- heartbeatErr
	}()
	blocked := false
	waitDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitDeadline) {
		var waitEventType string
		if err := admin.QueryRow(ctx, `SELECT COALESCE((SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1 AND state='active'), '')`, heartbeatPID).Scan(&waitEventType); err != nil {
			_ = blockedPublication.Rollback(ctx)
			_ = heartbeatTx.Rollback(ctx)
			t.Fatalf("poll blocked heartbeat: %v", err)
		}
		if waitEventType == "Lock" {
			blocked = true
			break
		}
		select {
		case heartbeatErr := <-heartbeatDone:
			_ = blockedPublication.Rollback(ctx)
			_ = heartbeatTx.Rollback(ctx)
			t.Fatalf("heartbeat completed before waiting on publication lock: %v", heartbeatErr)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !blocked {
		_ = blockedPublication.Rollback(ctx)
		heartbeatErr := <-heartbeatDone
		_ = heartbeatTx.Rollback(ctx)
		t.Fatalf("heartbeat never blocked behind publication row lock (err=%v)", heartbeatErr)
	}
	time.Sleep(2200 * time.Millisecond)
	if err := blockedPublication.Rollback(ctx); err != nil {
		_ = heartbeatTx.Rollback(ctx)
		t.Fatalf("rollback expired publication transaction: %v", err)
	}
	heartbeatErr := <-heartbeatDone
	assertLeaseLostError(t, heartbeatErr)
	if err := heartbeatTx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if reclaimed := reclaimExpiredJobs(t, ctx, worker, "org_pg_lease"); reclaimed != 1 {
		t.Fatalf("reclaimed blocked-heartbeat job=%d, want 1", reclaimed)
	}
}

// TestPostgreSQLPublicationRealPathRenewsAcrossBatches drives the production
// publisher with a multi-batch typed snapshot. The test-only delay is injected
// at the same bounded publication boundaries used by the real 2200-row view;
// the transaction therefore outlives its original lease while renewal and
// completion stay on the actual handler/queue path.
func TestPostgreSQLPublicationRealPathRenewsAcrossBatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest("kv_pg_lease", "lease_rows", "lease-real-path", "Lease rows", "sha256:"+strings.Repeat("9", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_pg_lease_register"), request)
	if err != nil {
		t.Fatalf("register lease projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	fixture := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, fixture, "pg-lease-real-path")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(fixture, regOwner, "req_pg_lease_real_path_confirm"), confirmRuntimeRequest(fixture, grant, "pg-lease-real-path-confirm")); err != nil {
		t.Fatalf("confirm lease projection: %v", err)
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
	snapshot := syntheticLeaseSnapshot(t, projection, 97)
	jobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_pg_lease_enqueue"), jobs.Spec{
		JobID: jobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "pg-lease-real-path", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue lease projection: %v", err)
	}
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim lease projection: err=%v ok=%v", err, ok)
	}
	syncRunID := mustID(t, "syncrun")
	if err := workerStore.Write(ctx, workerAccess(t, regOrg), func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, syncRunID, registered.SourceScopeID, claimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin lease publication: %v", err)
	}
	publicationStarted := time.Now()
	batchCount := 0
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithLeaseExtensionSeconds(60).
		WithFault(func(stage string) error {
			if stage == "postgresql_publication_batch" {
				batchCount++
				t.Logf("publication batch %d reached after %s", batchCount, time.Since(publicationStarted))
				time.Sleep(21 * time.Second)
			}
			return nil
		})
	started := time.Now()
	result, err := handler.PublishPostgreSQLSnapshot(ctx, workerAccess(t, regOrg), ingestion.PostgreSQLSnapshotRequest{
		ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: syncRunID,
		Projection: projection, Snapshot: snapshot, Claimed: claimed,
	})
	if err != nil {
		t.Fatalf("publish real lease path: %v (code=%s sqlstate=%s)", err, ingestion.CodeOf(err), database.SQLStateCode(err))
	}
	if batchCount != 3 || time.Since(started) <= 60*time.Second {
		t.Fatalf("publication batches=%d elapsed=%s, want three batches beyond original sixty-second lease", batchCount, time.Since(started))
	}
	if result.ObjectsSeen != 97 || result.ObjectsIngested != 97 || result.VersionsCreated != 97 || result.EvidencePublished != 291 {
		t.Fatalf("publication counters=%#v", result)
	}
	if err := workerQueue.Complete(ctx, workerAccess(t, regOrg), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete real lease path: %v", err)
	}
}

// TestPostgreSQLPublicationTailExpiryRollsBackRealPath proves that a lease
// lost after reconciliation and activation still fences the entire publisher
// transaction. The final renewal is deliberately allowed to expire, so no
// catalog/evidence rows, successful sync status, or activation cutover may
// survive the rollback.
func TestPostgreSQLPublicationTailExpiryRollsBackRealPath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := resetStage1Database(t)
	appStore, codec, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest("kv_pg_lease", "lease_tail", "lease-tail-expiry", "Lease tail expiry", "sha256:"+strings.Repeat("8", 64))
	registered, err := service.Register(ctx, regOwnerAccess("req_pg_lease_tail_register"), request)
	if err != nil {
		t.Fatalf("register tail-expiry projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	fixture := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash, "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, fixture, "pg-lease-tail-expiry")
	if _, err := authority.ConfirmManagedSource(ctx, authorityAccess(fixture, regOwner, "req_pg_lease_tail_confirm"), confirmRuntimeRequest(fixture, grant, "pg-lease-tail-confirm")); err != nil {
		t.Fatalf("confirm tail-expiry projection: %v", err)
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
	snapshot := syntheticLeaseSnapshot(t, projection, 1)
	jobID := mustID(t, "job")
	if _, err := appQueue.Enqueue(ctx, regOwnerAccess("req_pg_lease_tail_enqueue"), jobs.Spec{
		JobID: jobID, Type: jobs.TypePostgreSQLQuerySync,
		Payload:        jobs.Payload{"source_scope_id": registered.SourceScopeID},
		IdempotencyKey: "pg-lease-tail-expiry", Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue tail-expiry projection: %v", err)
	}
	claimed, ok, err := workerQueue.Claim(ctx, workerAccess(t, regOrg), regWorkerID, 3)
	if err != nil || !ok {
		t.Fatalf("claim tail-expiry projection: err=%v ok=%v", err, ok)
	}
	syncRunID := mustID(t, "syncrun")
	if err := workerStore.Write(ctx, workerAccess(t, regOrg), func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`, registered.SourceScopeID, int64(1), claimed.ID, regWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, registered.SourceScopeID, int64(1), request.ContractHash); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO public.sync_run (organization_id,id,source_scope_id,source_scope_revision,job_id,mode,status) VALUES ($1,$2,$3,1,$4,'FULL','RUNNING')`, regOrg, syncRunID, registered.SourceScopeID, claimed.ID)
		return err
	}); err != nil {
		t.Fatalf("begin tail-expiry publication: %v", err)
	}
	tailReached := false
	handler := ingestion.NewHandler(workerStore, workerQueue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, nil, regWorkerID, time.Now, ids.New).
		WithLeaseExtensionSeconds(4).
		WithFault(func(stage string) error {
			if stage == "postgresql_publication_tail" {
				tailReached = true
				time.Sleep(4500 * time.Millisecond)
			}
			return nil
		})
	_, publishErr := handler.PublishPostgreSQLSnapshot(ctx, workerAccess(t, regOrg), ingestion.PostgreSQLSnapshotRequest{
		ScopeID: registered.SourceScopeID, ScopeRevision: 1, SyncRunID: syncRunID,
		Projection: projection, Snapshot: snapshot, Claimed: claimed,
	})
	if !tailReached {
		t.Fatalf("publication failed before the tail-expiry control: %v", publishErr)
	}
	if publishErr == nil {
		t.Fatal("tail-expired publication unexpectedly succeeded")
	}
	if got := ingestion.CodeOf(publishErr); got != "PG_QUERY_PUBLICATION_FAILED" {
		t.Fatalf("tail-expired publication code=%s, want PG_QUERY_PUBLICATION_FAILED", got)
	}
	if got := database.SQLStateCode(publishErr); got != "55000" {
		t.Fatalf("tail-expired publication SQLSTATE=%q, want 55000", got)
	}
	var objects, versions, evidence int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1 AND connection_id=$2`, regOrg, registered.ConnectionID).Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version v JOIN public.source_object o ON o.organization_id=v.organization_id AND o.id=v.source_object_id WHERE v.organization_id=$1 AND o.connection_id=$2`, regOrg, registered.ConnectionID).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment f JOIN public.source_version v ON v.organization_id=f.organization_id AND v.id=f.source_version_id JOIN public.source_object o ON o.organization_id=v.organization_id AND o.id=v.source_object_id WHERE f.organization_id=$1 AND o.connection_id=$2`, regOrg, registered.ConnectionID).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if objects != 0 || versions != 0 || evidence != 0 {
		t.Fatalf("tail-expired publication left catalog rows: objects=%d versions=%d evidence=%d", objects, versions, evidence)
	}
	var syncStatus string
	var completedNull, coverageComplete bool
	if err := admin.QueryRow(ctx, `SELECT status, completed_at IS NULL, coverage_complete FROM public.sync_run WHERE organization_id=$1 AND id=$2`, regOrg, syncRunID).Scan(&syncStatus, &completedNull, &coverageComplete); err != nil {
		t.Fatal(err)
	}
	if syncStatus != "RUNNING" || !completedNull || coverageComplete {
		t.Fatalf("tail-expired sync run status=%q completed_null=%v coverage_complete=%v", syncStatus, completedNull, coverageComplete)
	}
	var activationStatus string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.source_scope_activation WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, regOrg, registered.SourceScopeID).Scan(&activationStatus); err != nil {
		t.Fatal(err)
	}
	if activationStatus != "SYNCING" {
		t.Fatalf("tail-expired activation status=%q, want SYNCING", activationStatus)
	}
	var activeRevisionNull bool
	if err := admin.QueryRow(ctx, `SELECT active_revision IS NULL FROM public.source_scope WHERE organization_id=$1 AND id=$2`, regOrg, registered.SourceScopeID).Scan(&activeRevisionNull); err != nil {
		t.Fatal(err)
	}
	if !activeRevisionNull {
		t.Fatal("tail-expired publication activated a source-scope revision")
	}
	var jobStatus string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.job WHERE organization_id=$1 AND id=$2`, regOrg, claimed.ID).Scan(&jobStatus); err != nil {
		t.Fatal(err)
	}
	if jobStatus != "RUNNING" {
		t.Fatalf("tail-expired job status=%q, want RUNNING", jobStatus)
	}
}

func syntheticLeaseSnapshot(t *testing.T, projection postgresqlquery.Projection, count int) postgresqlquery.Snapshot {
	t.Helper()
	rows := make([]postgresqlquery.Row, 0, count)
	for index := 0; index < count; index++ {
		row, err := postgresqlquery.CanonicalizeRow(projection.Columns, []any{
			fmt.Sprintf("550e8400-e29b-41d4-a716-%012x", index+1),
			fmt.Sprintf("2026-08-%02dT12:34:56.789Z", (index%28)+1),
			fmt.Sprintf("%d.%03d", 100+index, index%1000),
			fmt.Sprintf("region-%02d", index%10),
		})
		if err != nil {
			t.Fatalf("canonicalize lease row %d: %v", index, err)
		}
		rows = append(rows, row)
	}
	hash, err := postgresqlquery.SnapshotSetHash(rows)
	if err != nil {
		t.Fatalf("hash lease snapshot: %v", err)
	}
	return postgresqlquery.Snapshot{Rows: rows, RowCount: len(rows), CoverageComplete: true, SnapshotHash: hash}
}

func completeDurableJob(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, workerID string, claimed leasedJob) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	if _, err := tx.Exec(ctx, `SELECT app.complete_job($1, $2, $3)`, claimed.id, workerID, claimed.leaseEpoch); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func assertTxCallRejected(t *testing.T, ctx context.Context, tx pgx.Tx, statement string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, statement, args...); err == nil {
		t.Fatalf("stale lease call unexpectedly succeeded: %s", statement)
	}
}

func assertLeaseLostError(t *testing.T, err error) {
	t.Helper()
	var pgErr *pgconn.PgError
	if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "55000" {
		t.Fatalf("lease guard error=%v, want SQLSTATE 55000", err)
	}
}
