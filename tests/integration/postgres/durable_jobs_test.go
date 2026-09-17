package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// enqueueDurableJob registers work through the runtime role and returns the job
// id the database assigned (or reused for an idempotency key).
func enqueueDurableJob(t *testing.T, ctx context.Context, app *pgxpool.Pool, org, principal, jobID, jobType, idempotencyKey string, maxAttempts, availableAfter int) string {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, principal)
	var returnedID string
	if err := tx.QueryRow(ctx, `SELECT app.enqueue_job($1, $2, '{}'::jsonb, $3, 100, $4, $5)`,
		jobID, jobType, idempotencyKey, maxAttempts, availableAfter).Scan(&returnedID); err != nil {
		t.Fatalf("enqueue job: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return returnedID
}

type leasedJob struct {
	id         string
	leaseEpoch int64
	attempt    int
	maxAttempt int
}

// claimDurableJob leases the next runnable job in its own committed transaction,
// so the RUNNING lease persists exactly as a real worker's would.
func claimDurableJob(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, workerID string, leaseSeconds int) (leasedJob, bool) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	var claimed leasedJob
	var jobType string
	var payload []byte
	scanErr := tx.QueryRow(ctx, `SELECT job_id, job_type, payload_json, lease_epoch, attempt_number, max_attempts
		FROM app.claim_next_job($1, $2)`, workerID, leaseSeconds).Scan(
		&claimed.id, &jobType, &payload, &claimed.leaseEpoch, &claimed.attempt, &claimed.maxAttempt)
	if errors.Is(scanErr, pgx.ErrNoRows) {
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return leasedJob{}, false
	}
	if scanErr != nil {
		t.Fatalf("claim job: %v", scanErr)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return claimed, true
}

func failDurableJob(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, workerID, jobID string, leaseEpoch int64, code string, retryAfter int) string {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	var resulting string
	if err := tx.QueryRow(ctx, `SELECT app.fail_job($1, $2, $3, $4, $5)`,
		jobID, workerID, leaseEpoch, code, retryAfter).Scan(&resulting); err != nil {
		t.Fatalf("fail job: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return resulting
}

func jobStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, jobID string) (string, int, *string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	var status string
	var attempts int
	var lastError *string
	if err := tx.QueryRow(ctx, `SELECT status, attempt_count, last_error_code FROM public.job WHERE id = $1`, jobID).
		Scan(&status, &attempts, &lastError); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return status, attempts, lastError
}

// TestDurableJobEnqueueIsIdempotent proves ING-002 at the job layer: a repeat
// enqueue with the same idempotency key returns the original job and never
// creates a second unit of work.
func TestDurableJobEnqueueIsIdempotent(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	first := enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "SOURCE_SCOPE_SYNC", "sync-scope-1", 3, 0)
	second := enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 2), "SOURCE_SCOPE_SYNC", "sync-scope-1", 3, 0)
	if first != second || first != outboxRef("job", 1) {
		t.Fatalf("idempotent enqueue returned %q then %q", first, second)
	}
	var count int
	tx, _ := admin.Begin(ctx)
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE organization_id = 'org_alpha'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("idempotent enqueue created %d jobs, want 1", count)
	}

	// Concurrent enqueues of one further idempotency key still collapse to a
	// single job and never surface a unique violation to any caller.
	const racers = 8
	var waitGroup sync.WaitGroup
	returned := make(chan string, racers)
	failures := make(chan error, racers)
	for index := 0; index < racers; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			tx, err := app.Begin(ctx)
			if err != nil {
				failures <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
			var got string
			if err := tx.QueryRow(ctx, `SELECT app.enqueue_job($1, 'SOURCE_SCOPE_SYNC', '{}'::jsonb, 'race-key', 100, 3, 0)`,
				outboxRef("job", 100+index)).Scan(&got); err != nil {
				failures <- err
				return
			}
			if err := tx.Commit(ctx); err != nil {
				failures <- err
				return
			}
			returned <- got
		}()
	}
	waitGroup.Wait()
	close(returned)
	close(failures)
	for err := range failures {
		t.Fatalf("concurrent idempotent enqueue errored: %v", err)
	}
	winner := ""
	for got := range returned {
		if winner == "" {
			winner = got
		} else if got != winner {
			t.Fatalf("concurrent enqueue returned diverging ids %q and %q", winner, got)
		}
	}
	var raceCount int
	txRace, _ := admin.Begin(ctx)
	defer func() { _ = txRace.Rollback(ctx) }()
	if err := txRace.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE idempotency_key = 'race-key'`).Scan(&raceCount); err != nil {
		t.Fatal(err)
	}
	if raceCount != 1 {
		t.Fatalf("concurrent idempotent enqueue created %d jobs, want 1", raceCount)
	}
}

// TestDurableJobEnqueueIsIdempotentByIDAcrossDifferentIdempotencyKeys proves
// the 000070 fix: a caller whose job id is content-derived rather than
// freshly minted per attempt (registration.Service.Activate's
// syncJobID(organizationID, sourceScopeID), fixed so a scope can never have
// two concurrent activation jobs) repeats that exact id with a NEW
// idempotency key on every later call -- a real POSTGRESQL_QUERY/GIT scope's
// second :activate call after its first job went DEAD hit exactly this path
// live and surfaced an unhandled unique_violation as 503 SERVICE_UNAVAILABLE,
// because the previous ON CONFLICT target (organization_id, idempotency_key)
// never collapsed an id collision paired with a distinct key. This must
// converge on the original job id and never raise an error, matching the
// idempotency-key path's own guarantee.
func TestDurableJobEnqueueIsIdempotentByIDAcrossDifferentIdempotencyKeys(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	fixedJobID := outboxRef("job", 1)
	first := enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", fixedJobID, "SOURCE_SCOPE_SYNC", "activate-key-1", 3, 0)
	second := enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", fixedJobID, "SOURCE_SCOPE_SYNC", "activate-key-2", 3, 0)
	if first != fixedJobID || second != fixedJobID {
		t.Fatalf("repeat enqueue of the same job id with a different idempotency key returned %q then %q, want %q both times", first, second, fixedJobID)
	}
	var count int
	tx, _ := admin.Begin(ctx)
	defer func() { _ = tx.Rollback(ctx) }()
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE organization_id = 'org_alpha' AND id = $1`, fixedJobID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("repeat enqueue by id created %d job rows, want 1", count)
	}
	var storedIdempotencyKey string
	if err := tx.QueryRow(ctx, `SELECT idempotency_key FROM public.job WHERE organization_id = 'org_alpha' AND id = $1`, fixedJobID).Scan(&storedIdempotencyKey); err != nil {
		t.Fatal(err)
	}
	if storedIdempotencyKey != "activate-key-1" {
		t.Fatalf("second enqueue by id must never rewrite the original job's idempotency key; got %q", storedIdempotencyKey)
	}
}

// TestDurableJobLeaseFencingAndSingleClaim proves JOB-004: one job is leased by
// exactly one worker even under concurrency, and a stale fencing epoch is always
// refused.
func TestDurableJobLeaseFencingAndSingleClaim(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "OUTBOX_DELIVERY", "deliver-1", 5, 0)

	const claimers = 8
	var waitGroup sync.WaitGroup
	claimedIDs := make(chan string, claimers)
	for index := 0; index < claimers; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			claimed, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_"+padWorker(index), 60)
			if ok {
				claimedIDs <- claimed.id
			}
		}()
	}
	waitGroup.Wait()
	close(claimedIDs)
	winners := 0
	for range claimedIDs {
		winners++
	}
	if winners != 1 {
		t.Fatalf("concurrent claim produced %d winners, want exactly 1", winners)
	}

	// The single held lease is epoch 1. A heartbeat from the live owner with
	// any other epoch is fenced out by the epoch gate, a heartbeat from any
	// other worker with the correct epoch is fenced out by the owner gate, and
	// the correct owner+epoch keeps the lease alive.
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_worker")
	var leaseOwner string
	var epoch int64
	if err := tx.QueryRow(ctx, `SELECT lease_owner, lease_epoch FROM public.job WHERE id = $1`, outboxRef("job", 1)).Scan(&leaseOwner, &epoch); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if epoch != 1 {
		t.Fatalf("held lease epoch = %d, want 1", epoch)
	}
	assertWorkerCallRejected(t, ctx, worker, "org_alpha",
		`SELECT app.heartbeat_job($1, $2, 999, 30)`, outboxRef("job", 1), leaseOwner)
	assertWorkerCallRejected(t, ctx, worker, "org_alpha",
		`SELECT app.heartbeat_job($1, 'intruder', 1, 30)`, outboxRef("job", 1))
}

// TestDurableJobCompletionRequiresLiveLeaseAndCommit proves JOB-002: a job is
// never acknowledged without a live, matching lease, and the acknowledgement is
// transactional — a rolled-back completion leaves the job RUNNING to be retried.
func TestDurableJobCompletionRequiresLiveLeaseAndCommit(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "SOURCE_OBJECT_EXTRACTION", "extract-1", 3, 0)
	claimed, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_00", 60)
	if !ok {
		t.Fatal("expected to claim the job")
	}

	// A completion with the wrong epoch is fenced out.
	assertWorkerCallRejected(t, ctx, worker, "org_alpha",
		`SELECT app.complete_job($1, 'wrk_00', 999)`, claimed.id)

	// A completion that is rolled back does not acknowledge the job.
	rolledBack, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, rolledBack, "org_alpha", "usr_worker")
	if _, err := rolledBack.Exec(ctx, `SELECT app.complete_job($1, 'wrk_00', $2)`, claimed.id, claimed.leaseEpoch); err != nil {
		t.Fatalf("complete inside soon-rolled-back tx: %v", err)
	}
	if err := rolledBack.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := jobStatus(t, ctx, worker, "org_alpha", claimed.id); status != "RUNNING" {
		t.Fatalf("rolled-back completion left status %q, want RUNNING", status)
	}

	// A committed completion with the live lease acknowledges exactly once.
	committed, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, committed, "org_alpha", "usr_worker")
	if _, err := committed.Exec(ctx, `SELECT app.complete_job($1, 'wrk_00', $2)`, claimed.id, claimed.leaseEpoch); err != nil {
		t.Fatalf("commit completion: %v", err)
	}
	if err := committed.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := jobStatus(t, ctx, worker, "org_alpha", claimed.id); status != "SUCCEEDED" {
		t.Fatalf("committed completion left status %q, want SUCCEEDED", status)
	}
	// A terminal job is not runnable again.
	if _, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_01", 60); ok {
		t.Fatal("a SUCCEEDED job was claimed again")
	}
}

// TestDurableJobRetryBudgetDeadLetters proves JOB-003: retries are bounded and
// observable, and an exhausted budget dead-letters the job with a stable error
// code rather than retrying forever.
func TestDurableJobRetryBudgetDeadLetters(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "SOURCE_OBJECT_EXTRACTION", "extract-1", 2, 0)

	first, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_00", 60)
	if !ok {
		t.Fatal("first claim failed")
	}
	if status := failDurableJob(t, ctx, worker, "org_alpha", "wrk_00", first.id, first.leaseEpoch, "EXTRACT_TIMEOUT", 0); status != "PENDING" {
		t.Fatalf("first failure within budget produced %q, want PENDING", status)
	}

	second, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_01", 60)
	if !ok {
		t.Fatal("retry claim failed")
	}
	if second.attempt != 2 || second.leaseEpoch != 2 {
		t.Fatalf("retry claim attempt=%d epoch=%d, want 2/2", second.attempt, second.leaseEpoch)
	}
	if status := failDurableJob(t, ctx, worker, "org_alpha", "wrk_01", second.id, second.leaseEpoch, "EXTRACT_TIMEOUT", 0); status != "DEAD" {
		t.Fatalf("budget-exhausting failure produced %q, want DEAD", status)
	}

	status, attempts, lastError := jobStatus(t, ctx, worker, "org_alpha", first.id)
	if status != "DEAD" || attempts != 2 || lastError == nil || *lastError != "EXTRACT_TIMEOUT" {
		t.Fatalf("dead-letter state status=%q attempts=%d err=%v", status, attempts, lastError)
	}
	// A dead-lettered (poison) job is not runnable again.
	if _, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_02", 60); ok {
		t.Fatal("a DEAD job was claimed again")
	}
	// It is operator-visible through the content-free counter.
	assertJobStatusCount(t, ctx, worker, "org_alpha", "DEAD", 1)
}

// TestDurableJobCrashRecoveryReclaimsExpiredLease proves JOB-001: a lost worker
// never strands a job. The expired lease is reclaimed, the crashed attempt is
// charged against the retry budget, and a poison job that only ever crashes
// eventually dead-letters instead of looping forever.
func TestDurableJobCrashRecoveryReclaimsExpiredLease(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	// max_attempts=2 so the first crash re-queues and the second dead-letters.
	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "SOURCE_SCOPE_SYNC", "sync-1", 2, 0)

	crashed, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_crash", 1)
	if !ok {
		t.Fatal("claim before crash failed")
	}
	time.Sleep(1200 * time.Millisecond)

	// The crashed worker's lease has lapsed: it can neither extend nor complete.
	assertWorkerCallRejected(t, ctx, worker, "org_alpha",
		`SELECT app.heartbeat_job($1, 'wrk_crash', $2, 30)`, crashed.id, crashed.leaseEpoch)
	assertWorkerCallRejected(t, ctx, worker, "org_alpha",
		`SELECT app.complete_job($1, 'wrk_crash', $2)`, crashed.id, crashed.leaseEpoch)

	reclaimed := reclaimExpiredJobs(t, ctx, worker, "org_alpha")
	if reclaimed != 1 {
		t.Fatalf("reclaimed %d expired jobs, want 1", reclaimed)
	}
	if status, attempts, _ := jobStatus(t, ctx, worker, "org_alpha", crashed.id); status != "PENDING" || attempts != 1 {
		t.Fatalf("after first crash status=%q attempts=%d, want PENDING/1", status, attempts)
	}
	assertAttemptOutcome(t, ctx, worker, "org_alpha", crashed.id, 1, "LEASE_EXPIRED")

	// Second lease also crashes; the budget is now exhausted and reclamation
	// dead-letters the job rather than looping.
	recrashed, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_crash2", 1)
	if !ok {
		t.Fatal("re-claim after reclaim failed")
	}
	if recrashed.leaseEpoch <= crashed.leaseEpoch {
		t.Fatalf("re-claim epoch %d did not advance past %d", recrashed.leaseEpoch, crashed.leaseEpoch)
	}
	time.Sleep(1200 * time.Millisecond)
	if reclaimed := reclaimExpiredJobs(t, ctx, worker, "org_alpha"); reclaimed != 1 {
		t.Fatalf("second reclaim count %d, want 1", reclaimed)
	}
	status, attempts, lastError := jobStatus(t, ctx, worker, "org_alpha", crashed.id)
	if status != "DEAD" || attempts != 2 || lastError == nil || *lastError != "LEASE_EXPIRED" {
		t.Fatalf("exhausted crash budget status=%q attempts=%d err=%v, want DEAD/2/LEASE_EXPIRED", status, attempts, lastError)
	}
}

// TestDurableJobRuntimeAndWorkerGrantSeparation proves the containment boundary:
// the Web/API runtime can enqueue but cannot lease or execute, the worker owns
// execution, and neither role gets direct DML on the job tables.
func TestDurableJobRuntimeAndWorkerGrantSeparation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "OUTBOX_DELIVERY", "deliver-1", 3, 0)

	// The runtime role cannot lease, heartbeat, complete, fail or reclaim.
	for _, call := range []string{
		`SELECT app.claim_next_job('wrk_00', 30)`,
		`SELECT app.reclaim_expired_jobs(10)`,
		`SELECT app.heartbeat_job('` + outboxRef("job", 1) + `', 'wrk_00', 1, 30)`,
		`SELECT app.complete_job('` + outboxRef("job", 1) + `', 'wrk_00', 1)`,
		`SELECT app.fail_job('` + outboxRef("job", 1) + `', 'wrk_00', 1, 'X_CODE', 0)`,
	} {
		assertTenantStatementRejected(t, app, "org_alpha", "usr_alice", call)
	}

	// Neither role holds direct DML; every write flows through a definer function.
	for _, pool := range []struct {
		name string
		db   *pgxpool.Pool
		org  string
		who  string
	}{
		{"app", app, "org_alpha", "usr_alice"},
		{"worker", worker, "org_alpha", "usr_worker"},
	} {
		for _, statement := range []string{
			`UPDATE public.job SET status = 'SUCCEEDED' WHERE id = '` + outboxRef("job", 1) + `'`,
			`DELETE FROM public.job WHERE id = '` + outboxRef("job", 1) + `'`,
			`INSERT INTO public.job_attempt (organization_id, job_id, attempt_number, lease_owner, lease_epoch)
			 VALUES ('org_alpha', '` + outboxRef("job", 1) + `', 1, 'wrk_00', 1)`,
		} {
			assertTenantStatementRejected(t, pool.db, pool.org, pool.who, statement)
		}
	}

	for _, table := range []string{"job", "job_attempt"} {
		for _, role := range []string{"knowvault_app", "knowvault_worker"} {
			var canSelect, canInsert, canUpdate, canDelete bool
			if err := admin.QueryRow(ctx, `
				SELECT has_table_privilege($1, 'public.' || $2, 'SELECT'),
				       has_table_privilege($1, 'public.' || $2, 'INSERT'),
				       has_table_privilege($1, 'public.' || $2, 'UPDATE'),
				       has_table_privilege($1, 'public.' || $2, 'DELETE')
			`, role, table).Scan(&canSelect, &canInsert, &canUpdate, &canDelete); err != nil {
				t.Fatal(err)
			}
			if !canSelect || canInsert || canUpdate || canDelete {
				t.Fatalf("unsafe %s privileges on %s: select=%v insert=%v update=%v delete=%v", role, table, canSelect, canInsert, canUpdate, canDelete)
			}
		}
	}

	// The runtime cannot execute worker-only functions; the worker can enqueue.
	for functionName, appAllowed := range map[string]bool{
		"app.enqueue_job(text,text,jsonb,text,integer,integer,integer)": true,
		"app.claim_next_job(text,integer)":                              false,
		"app.reclaim_expired_jobs(integer)":                             false,
		"app.heartbeat_job(text,text,bigint,integer)":                   false,
		"app.complete_job(text,text,bigint)":                            false,
		"app.fail_job(text,text,bigint,text,integer)":                   false,
	} {
		var appHas, workerHas bool
		if err := admin.QueryRow(ctx, `SELECT has_function_privilege('knowvault_app', $1, 'EXECUTE'),
			has_function_privilege('knowvault_worker', $1, 'EXECUTE')`, functionName).Scan(&appHas, &workerHas); err != nil {
			t.Fatal(err)
		}
		if appHas != appAllowed || !workerHas {
			t.Fatalf("function %s app=%v (want %v) worker=%v (want true)", functionName, appHas, appAllowed, workerHas)
		}
	}
}

// TestDurableJobTenantIsolationAndTerminalImmutability proves RLS isolation
// between tenants and that a terminal job cannot be resurrected even by the
// privileged role.
func TestDurableJobTenantIsolationAndTerminalImmutability(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))

	enqueueDurableJob(t, ctx, app, "org_alpha", "usr_alice", outboxRef("job", 1), "SOURCE_SCOPE_SYNC", "sync-1", 1, 0)

	for _, table := range []string{"job", "job_attempt"} {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity FROM pg_class AS c
			JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1`, table).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s RLS is not forced", table)
		}
	}

	// A worker bound to org_beta cannot see or claim org_alpha's job.
	if claimed, ok := claimDurableJob(t, ctx, worker, "org_beta", "wrk_beta", 60); ok {
		t.Fatalf("org_beta worker claimed foreign job %q", claimed.id)
	}
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_beta", "usr_worker")
	var visible int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.job WHERE id = $1`, outboxRef("job", 1)).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("org_beta observed %d rows of org_alpha's job", visible)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Drive the job to a terminal DEAD state, then prove it cannot move.
	claimed, ok := claimDurableJob(t, ctx, worker, "org_alpha", "wrk_00", 60)
	if !ok {
		t.Fatal("claim for terminal test failed")
	}
	if status := failDurableJob(t, ctx, worker, "org_alpha", "wrk_00", claimed.id, claimed.leaseEpoch, "PARSE_UNSUPPORTED", 0); status != "DEAD" {
		t.Fatalf("single-attempt failure produced %q, want DEAD", status)
	}
	assertAdminStatementRejected(t, ctx, admin, `UPDATE public.job SET status = 'PENDING', completed_at = NULL WHERE id = '`+outboxRef("job", 1)+`'`)
	assertAdminStatementRejected(t, ctx, admin, `UPDATE public.job SET status = 'RUNNING', lease_owner = 'wrk_x', lease_deadline = transaction_timestamp() + interval '1 hour' WHERE id = '`+outboxRef("job", 1)+`'`)
	assertAdminStatementRejected(t, ctx, admin, `UPDATE public.job_attempt SET outcome = 'SUCCEEDED', error_code = NULL WHERE job_id = '`+outboxRef("job", 1)+`' AND attempt_number = 1`)
}

func reclaimExpiredJobs(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org string) int {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	var reclaimed int
	if err := tx.QueryRow(ctx, `SELECT app.reclaim_expired_jobs(100)`).Scan(&reclaimed); err != nil {
		t.Fatalf("reclaim expired jobs: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return reclaimed
}

func assertAttemptOutcome(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, jobID string, attemptNumber int, wantOutcome string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	var outcome string
	if err := tx.QueryRow(ctx, `SELECT outcome FROM public.job_attempt WHERE job_id = $1 AND attempt_number = $2`, jobID, attemptNumber).Scan(&outcome); err != nil {
		t.Fatalf("read attempt outcome: %v", err)
	}
	if outcome != wantOutcome {
		t.Fatalf("attempt %d outcome = %q, want %q", attemptNumber, outcome, wantOutcome)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertJobStatusCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org, status string, want int64) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	rows, err := tx.Query(ctx, `SELECT status, job_count FROM app.job_status_counts()`)
	if err != nil {
		t.Fatalf("job status counts: %v", err)
	}
	defer rows.Close()
	found := int64(0)
	for rows.Next() {
		var gotStatus string
		var gotCount int64
		if err := rows.Scan(&gotStatus, &gotCount); err != nil {
			t.Fatal(err)
		}
		if gotStatus == status {
			found = gotCount
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if found != want {
		t.Fatalf("job_status_counts[%s] = %d, want %d", status, found, want)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// assertWorkerCallRejected runs a worker-role statement expected to fail closed
// (a fencing or authorization rejection) in its own transaction.
func assertWorkerCallRejected(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, statement string, arguments ...any) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	if _, err := tx.Exec(ctx, statement, arguments...); err == nil {
		t.Fatalf("worker statement unexpectedly succeeded: %s", statement)
	}
}

func padWorker(index int) string {
	const digits = "0123456789"
	return string([]byte{digits[(index/10)%10], digits[index%10]})
}
