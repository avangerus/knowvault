package postgres_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// resetSchedulerDatabase uses the same head migration inventory as the operator tests.
func resetSchedulerDatabase(t *testing.T) *pgxpool.Pool {
	t.Helper()
	return resetStage1Database(t)
}

type sourceSchedulerFixture struct {
	admin     *pgxpool.Pool
	store     *database.Store
	queue     *jobs.Queue
	scheduler *registration.Service
	access    database.AccessContext
	authority authorityOpsFixture
	scopeID   string
}

func newFolderSchedulerFixture(t *testing.T, ctx context.Context) sourceSchedulerFixture {
	t.Helper()
	admin := resetSchedulerDatabase(t)
	codec := s1dCodec(t, s1dOrg)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_scheduler_folder", "confirmation_scheduler_folder")
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(store)
	if err != nil {
		t.Fatalf("create worker queue: %v", err)
	}
	auditStore, err := audit.NewStore(store)
	if err != nil {
		t.Fatalf("create worker audit store: %v", err)
	}
	scheduler, err := registration.New(store, auditStore, codec, queue, s1dDigestKey, 1)
	if err != nil {
		t.Fatalf("create worker source scheduler: %v", err)
	}
	access := workerAccess(t, s1dOrg)
	bootstrapScheduledScope(t, ctx, admin, store, queue, access, s1dScopeID, jobs.TypeSourceScopeSync, "")
	return sourceSchedulerFixture{admin: admin, store: store, queue: queue, scheduler: scheduler,
		access: access, authority: fixture, scopeID: s1dScopeID}
}

// bootstrapScheduledScope moves a seeded DRAFT activation through the same
// worker-owned begin/publish/complete primitives used by a first sync. It does
// not create a sync_run, leaving the activation timestamp as the due marker for
// this scheduler-only test.
func bootstrapScheduledScope(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *database.Store,
	queue *jobs.Queue, access database.AccessContext, scopeID string, jobType jobs.Type, contractHash string) {
	t.Helper()
	jobID := mustID(t, "syncscope")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{
		JobID: jobID, Type: jobType,
		Payload:        jobs.Payload{"source_scope_id": scopeID, "operation": "ACTIVATE"},
		IdempotencyKey: "scheduler-bootstrap-" + jobID, Priority: 100, MaxAttempts: 3,
	}); err != nil {
		t.Fatalf("enqueue bootstrap activation: %v", err)
	}
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim bootstrap activation: %v ok=%v", err, ok)
	}
	if err := store.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_scope_registered_begin_sync($1,$2,$3,$4,$5)`,
			scopeID, int64(1), claimed.ID, s1dWorkerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		if jobType == jobs.TypePostgreSQLQuerySync {
			if _, err := tx.Exec(ctx, `SELECT app.postgresql_query_projection_activate($1,$2,$3)`, scopeID, int64(1), contractHash); err != nil {
				return err
			}
		}
		_, err := tx.Exec(ctx, `SELECT app.source_scope_publish_ready($1,$2,$3,$4,$5)`,
			scopeID, int64(1), claimed.ID, s1dWorkerID, claimed.LeaseEpoch)
		return err
	}); err != nil {
		t.Fatalf("publish bootstrap activation: %v", err)
	}
	if err := queue.Complete(ctx, access, claimed.ID, s1dWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete bootstrap activation: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET activated_at = transaction_timestamp() - interval '1 hour'
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, access.OrganizationID, scopeID); err != nil {
		t.Fatalf("make bootstrap activation due: %v", err)
	}
}

func setSourceScheduleNotDue(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, scopeID string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET activated_at = transaction_timestamp()
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, organizationID, scopeID); err != nil {
		t.Fatalf("make source schedule not due: %v", err)
	}
}

func setSourceScheduleDue(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, scopeID string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET activated_at = transaction_timestamp() - interval '1 hour'
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=1`, organizationID, scopeID); err != nil {
		t.Fatalf("make source schedule due: %v", err)
	}
}

func sourceJobs(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, scopeID string) (total, live int) {
	t.Helper()
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2`, organizationID, scopeID).Scan(&total); err != nil {
		t.Fatalf("count source jobs: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2
		  AND status IN ('PENDING','RUNNING')`, organizationID, scopeID).Scan(&live); err != nil {
		t.Fatalf("count live source jobs: %v", err)
	}
	return total, live
}

func sourceConfirmation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceSourceID string) (string, string) {
	t.Helper()
	var id, hash string
	if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_source_id=$2`, organizationID, workspaceSourceID).Scan(&id, &hash); err != nil {
		t.Fatalf("load source confirmation: %v", err)
	}
	return id, hash
}

func TestAutoSyncEnqueuesFolderAndHonorsDueConfirmationGates(t *testing.T) {
	ctx := context.Background()
	fixture := newFolderSchedulerFixture(t, ctx)

	if count, err := fixture.scheduler.AutoSync(ctx, fixture.access); err != nil || count != 1 {
		t.Fatalf("first folder autosync count=%d err=%v", count, err)
	}
	var jobType, status string
	if err := fixture.admin.QueryRow(ctx, `SELECT type,status FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2
		ORDER BY created_at DESC LIMIT 1`, fixture.access.OrganizationID, fixture.scopeID).Scan(&jobType, &status); err != nil {
		t.Fatal(err)
	}
	if jobType != string(jobs.TypeSourceScopeSync) || status != "PENDING" {
		t.Fatalf("folder scheduled job type/status=%q/%q", jobType, status)
	}

	// A second tick sees the live scheduled job and does not enqueue another
	// unit, even though the due timestamp remains old.
	if count, err := fixture.scheduler.AutoSync(ctx, fixture.access); err != nil || count != 0 {
		t.Fatalf("live folder autosync count=%d err=%v", count, err)
	}
	if total, live := sourceJobs(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID); total != 2 || live != 1 {
		t.Fatalf("folder jobs total/live=%d/%d, want bootstrap + one live scheduled job", total, live)
	}

	claimed, ok, err := fixture.queue.Claim(ctx, fixture.access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim scheduled folder job: %v ok=%v", err, ok)
	}
	if err := fixture.queue.Complete(ctx, fixture.access, claimed.ID, s1dWorkerID, claimed.LeaseEpoch); err != nil {
		t.Fatalf("complete scheduled folder job: %v", err)
	}
	setSourceScheduleNotDue(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID)
	if count, err := fixture.scheduler.AutoSync(ctx, fixture.access); err != nil || count != 0 {
		t.Fatalf("not-due folder autosync count=%d err=%v", count, err)
	}

	// Revoking the current confirmation excludes the scope from scheduling.
	setSourceScheduleDue(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID)
	confirmationID, confirmationHash := sourceConfirmation(t, ctx, fixture.admin,
		fixture.access.OrganizationID, fixture.authority.workspaceSourceID)
	authority := newAuthorityRuntime(t, ctx)
	if _, err := authority.RevokeManagedConfirmation(ctx,
		authorityAccess(fixture.authority, fixture.authority.ownerID, "req_scheduler_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("scheduler-revoke"), OrganizationID: fixture.authority.organizationID,
			WorkspaceID: fixture.authority.workspaceID, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
			ExpectedPolicyRevision: fixture.authority.policyID,
		}); err != nil {
		t.Fatalf("revoke folder confirmation: %v", err)
	}
	if count, err := fixture.scheduler.AutoSync(ctx, fixture.access); err != nil || count != 0 {
		t.Fatalf("revoked folder autosync count=%d err=%v", count, err)
	}
	if total, live := sourceJobs(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID); total != 2 || live != 0 {
		t.Fatalf("revoked folder jobs total/live=%d/%d, want no new job", total, live)
	}
}

func TestAutoSyncPreservesPostgreSQLHandlerType(t *testing.T) {
	ctx := context.Background()
	admin := resetSchedulerDatabase(t)
	_, codec, appService := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)
	request := isolationProjectionRequest("analytics", "daily_view", "scheduler-lineage", "Scheduler daily", "sha256:"+strings.Repeat("2", 64))
	request.SyncIntervalSeconds = 60
	registered, err := appService.Register(ctx, regOwnerAccess("req_scheduler_pg_register"), request)
	if err != nil {
		t.Fatalf("register PG source: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	authorityFixture := seedRegistrationWorkspaceBinding(t, ctx, admin, registered.SourceScopeID, registered.ScopeConfigHash,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FBY")
	authority := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, authority, authorityFixture, "scheduler-pg-grant")
	if _, err := authority.ConfirmManagedSource(ctx,
		authorityAccess(authorityFixture, authorityFixture.ownerID, "req_scheduler_pg_confirm"),
		confirmRuntimeRequest(authorityFixture, grant, "scheduler-pg-confirm")); err != nil {
		t.Fatalf("confirm PG source: %v", err)
	}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	workerAudit, err := audit.NewStore(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := registration.New(workerStore, workerAudit, codec, queue, s1dDigestKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	access := workerAccess(t, regOrg)
	bootstrapScheduledScope(t, ctx, admin, workerStore, queue, access, registered.SourceScopeID,
		jobs.TypePostgreSQLQuerySync, request.ContractHash)

	if count, err := scheduler.AutoSync(ctx, access); err != nil || count != 1 {
		t.Fatalf("PG autosync count=%d err=%v", count, err)
	}
	var jobType string
	if err := admin.QueryRow(ctx, `SELECT type FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2
		  AND status='PENDING' ORDER BY created_at DESC LIMIT 1`, regOrg, registered.SourceScopeID).Scan(&jobType); err != nil {
		t.Fatal(err)
	}
	if jobType != string(jobs.TypePostgreSQLQuerySync) {
		t.Fatalf("PG scheduled job type=%q", jobType)
	}
}

func TestAutoSyncConcurrentTicksAndDeadRetryCooldown(t *testing.T) {
	ctx := context.Background()
	fixture := newFolderSchedulerFixture(t, ctx)

	start := make(chan struct{})
	counts := make(chan int, 2)
	errs := make(chan error, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			count, err := fixture.scheduler.AutoSync(ctx, fixture.access)
			counts <- count
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(counts)
	close(errs)
	placed := 0
	for count := range counts {
		if count == 1 {
			placed++
		} else if count != 0 {
			t.Fatalf("concurrent autosync count=%d", count)
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent autosync: %v", err)
		}
	}
	if placed != 1 {
		t.Fatalf("concurrent autosync placed=%d, want one winner", placed)
	}
	if total, live := sourceJobs(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID); total != 2 || live != 1 {
		t.Fatalf("concurrent folder jobs total/live=%d/%d", total, live)
	}

	// Exercise the real queue retry state machine: three failed attempts end in
	// DEAD, and a following scheduler tick does not hot-loop a replacement job.
	for attempt := 1; attempt <= 3; attempt++ {
		claimed, ok, err := fixture.queue.Claim(ctx, fixture.access, s1dWorkerID, 60)
		if err != nil || !ok {
			t.Fatalf("claim failed attempt %d: %v ok=%v", attempt, err, ok)
		}
		if err := fixture.queue.Fail(ctx, fixture.access, claimed.ID, s1dWorkerID, claimed.LeaseEpoch,
			jobs.ErrorCode("TEST_RETRY"), 0); err != nil {
			t.Fatalf("fail attempt %d: %v", attempt, err)
		}
	}
	var status string
	var attemptCount int
	if err := fixture.admin.QueryRow(ctx, `SELECT status,attempt_count FROM public.job
		WHERE organization_id=$1 AND payload_json->>'source_scope_id'=$2
		  AND status='DEAD' ORDER BY completed_at DESC LIMIT 1`, fixture.access.OrganizationID, fixture.scopeID).Scan(&status, &attemptCount); err != nil {
		t.Fatal(err)
	}
	if status != "DEAD" || attemptCount != 3 {
		t.Fatalf("dead scheduled job status/attempts=%q/%d", status, attemptCount)
	}
	setSourceScheduleDue(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID)
	if count, err := fixture.scheduler.AutoSync(ctx, fixture.access); err != nil || count != 0 {
		t.Fatalf("dead cooldown autosync count=%d err=%v", count, err)
	}
	if total, live := sourceJobs(t, ctx, fixture.admin, fixture.access.OrganizationID, fixture.scopeID); total != 2 || live != 0 {
		t.Fatalf("dead cooldown folder jobs total/live=%d/%d", total, live)
	}
}
