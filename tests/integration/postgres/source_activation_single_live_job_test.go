package postgres_test

// Review remark Z5: "one live activation job per scope" was enforced only by a
// SELECT of a live job taken immediately before the enqueue. Under READ
// COMMITTED two concurrent :activate calls both read "no live job" and both
// enqueue, so a scope could hold two live sync jobs and be published twice
// concurrently. A predicate read is not a uniqueness guarantee.
//
// Migration 000075 makes it one: a partial unique index over
// (organization_id, payload_json->>'source_scope_id'), restricted to jobs the
// operator-facing activation authority marked (operation = ACTIVATE) and to the
// live statuses. These
// tests prove the guarantee against real PostgreSQL rather than against the Go
// fast path -- the Go fast path is exactly what the race defeats -- and pin the
// deliberate limit of the constraint: worker-internal recovery enqueues carry
// no stamp and must stay outside it, or crash resume becomes a deadlock.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func insertScopeSyncJob(t *testing.T, ctx context.Context, admin *pgxpool.Pool, jobID, jobType, status, scopeID string, byActivationAuthority bool) error {
	t.Helper()
	payload := `jsonb_build_object('source_scope_id', $4::text)`
	if byActivationAuthority {
		payload = `jsonb_build_object('source_scope_id', $4::text, 'operation', 'ACTIVATE')`
	}
	_, err := admin.Exec(ctx, `INSERT INTO public.job
		(organization_id, id, type, payload_json, idempotency_key, status, max_attempts,
		 attempt_count, lease_epoch, lease_owner, lease_deadline, completed_at)
		VALUES ($1, $2, $3, `+payload+`, $5, $6, 3,
		        CASE WHEN $6 = 'RUNNING' THEN 1 ELSE 0 END, 0,
		        CASE WHEN $6 = 'RUNNING' THEN $7::text ELSE NULL END,
		        CASE WHEN $6 = 'RUNNING' THEN transaction_timestamp() - interval '1 hour' ELSE NULL END,
		        CASE WHEN $6 IN ('SUCCEEDED', 'DEAD') THEN transaction_timestamp() ELSE NULL END)`,
		s1dOrg, jobID, jobType, scopeID, mustID(t, "idem"), status, s1dWorkerID)
	return err
}

func TestOnlyOneLiveActivationJobPerScope(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)

	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", s1dScopeID, true); err != nil {
		t.Fatalf("first activation job must be accepted: %v", err)
	}

	// The second concurrent activation of the same scope -- a different job id
	// and a different idempotency key, which is exactly what the losing racer
	// mints -- must be refused by the database itself.
	err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", s1dScopeID, true)
	if err == nil {
		t.Fatal("a second live activation job for the same scope was accepted: the scope can be published twice concurrently")
	}
	if !strings.Contains(err.Error(), "job_one_live_activation_per_scope") {
		t.Fatalf("expected the one-live-activation-per-scope unique index to refuse it, got %v", err)
	}

	// The constraint is about the scope, not the job type: a scheduled
	// POSTGRESQL_QUERY refresh cannot slip past a live activation of the same
	// scope either.
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "POSTGRESQL_QUERY_SYNC", "PENDING", s1dScopeID, true); err == nil {
		t.Fatal("a second live activation job of the other scope-sync type was accepted for the same scope")
	}

	// It is partial on the live statuses: finished work for the same scope
	// stays unconstrained, so the scope can be activated again later.
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "SUCCEEDED", s1dScopeID, true); err != nil {
		t.Fatalf("a terminal job of the same scope must remain insertable: %v", err)
	}

	// And it is per scope, not global: another scope activates freely.
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", "scope_01ARZ3NDEKTSV4RRFFQ69G5FBB", true); err != nil {
		t.Fatalf("another scope must still be activatable: %v", err)
	}
}

// The deliberate limit, pinned so the constraint is never "tightened" into a
// recovery deadlock: crash resume and stale-lease fencing queue fresh work for
// a scope whose previous unit of work is still live. Those enqueues do not come
// from the activation authority and must remain possible.
func TestWorkerRecoveryEnqueueIsOutsideTheActivationConstraint(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)

	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "RUNNING", s1dScopeID, false); err != nil {
		t.Fatalf("seed a crashed running job: %v", err)
	}
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", s1dScopeID, false); err != nil {
		t.Fatalf("crash resume must be able to queue fresh work for a scope with a dead lease: %v", err)
	}
	// An activation may still be queued alongside worker-internal recovery
	// work; only a second ACTIVATION for the same scope is refused.
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", s1dScopeID, true); err != nil {
		t.Fatalf("an activation must not be blocked by unstamped recovery work: %v", err)
	}
	if err := insertScopeSyncJob(t, ctx, admin, mustID(t, "syncscope"), "SOURCE_SCOPE_SYNC", "PENDING", s1dScopeID, true); err == nil {
		t.Fatal("a second live activation for the same scope must still be refused")
	}
}
