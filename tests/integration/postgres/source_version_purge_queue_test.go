package postgres_test

import (
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestSourceVersionPurgeQueueLifecycle proves the real control-plane path:
// one trusted request is idempotently enqueued, the existing source-version
// authority performs fail-close/cleanup/completion, and the durable receipt is
// acknowledged only after retention is PURGED.  Graph rows and encrypted
// source-derived artifacts are checked through the database, not a test-only
// replacement implementation.
func TestSourceVersionPurgeQueueLifecycle(t *testing.T) {
	ctx, admin, versionID, _, purger := s1ePurgeSetup(t)
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	queue, err := purge.NewSourceQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	conversationQueue, err := purge.NewQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	access := purgerAccess()
	spec := purge.SourceRequestSpec{
		RequestID: requestID, SourceVersion: versionID, ReasonCode: "RETENTION_REQUEST",
		IdempotencyKey: "source-purge-queue-idempotency", Priority: 10, MaxAttempts: 3,
	}
	if returned, err := queue.Enqueue(ctx, access, spec); err != nil || returned != requestID {
		t.Fatalf("enqueue returned=%s err=%v, want %s", returned, err, requestID)
	}
	if returned, err := queue.Enqueue(ctx, access, spec); err != nil || returned != requestID {
		t.Fatalf("idempotent replay returned=%s err=%v, want %s", returned, err, requestID)
	}

	runner, err := purge.NewRunnerWithSource(purger, conversationQueue, queue, access, purge.RunnerConfig{
		WorkerID: "source_purge_runner", LeaseSeconds: 30, PollInterval: time.Second, ReclaimLimit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := runner.RunOnce(ctx)
	if err != nil || !outcome.SourceProcessed {
		t.Fatalf("source queue runner outcome=%+v err=%v", outcome, err)
	}

	var requestStatus, retentionState, versionState string
	if err := admin.QueryRow(ctx, `
		SELECT request.status, retention.state, version.state
		  FROM public.source_version_purge_request AS request
		  JOIN public.source_version_retention AS retention
		    ON retention.organization_id=request.organization_id
		   AND retention.source_version_id=request.source_version_id
		  JOIN public.source_version AS version
		    ON version.organization_id=request.organization_id
		   AND version.id=request.source_version_id
		 WHERE request.organization_id=$1 AND request.id=$2`, s1dOrg, requestID).
		Scan(&requestStatus, &retentionState, &versionState); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "SUCCEEDED" || retentionState != "PURGED" || versionState != "REDACTED" {
		t.Fatalf("queue status=%s retention=%s version=%s, want SUCCEEDED/PURGED/REDACTED", requestStatus, retentionState, versionState)
	}
	var purgingAudits, purgedAudits int
	if err := admin.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2 AND action='source.version_purging'),
		  (SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2 AND action='source.version_purged')`, s1dOrg, versionID).
		Scan(&purgingAudits, &purgedAudits); err != nil {
		t.Fatal(err)
	}
	if purgingAudits != 1 || purgedAudits != 1 {
		t.Fatalf("source purge audits purging=%d purged=%d, want 1/1", purgingAudits, purgedAudits)
	}
	var liveArtifacts, entityRows, relationRows, termRows, deleteEvents int
	if err := admin.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM public.encrypted_artifact AS artifact
		    WHERE artifact.organization_id=$1 AND artifact.purged_at IS NULL
		      AND artifact.resource_id IN (
		        SELECT fragment.id FROM public.evidence_fragment AS fragment
		         WHERE fragment.organization_id=$1 AND fragment.source_version_id=$2
		        UNION ALL
		        SELECT chunk.id FROM public.search_chunk AS chunk
		         WHERE chunk.organization_id=$1 AND chunk.source_version_id=$2)),
		  (SELECT count(*) FROM public.canonical_entity AS entity
		    WHERE entity.organization_id=$1 AND entity.source_version_id=$2),
		  (SELECT count(*) FROM public.entity_relation AS relation
		    WHERE relation.organization_id=$1 AND relation.source_version_id=$2),
		  (SELECT count(*) FROM public.semantic_term AS term
		    WHERE term.organization_id=$1 AND term.source_version_id=$2),
		  (SELECT count(*) FROM public.outbox_event AS event
		    WHERE event.organization_id=$1 AND event.event_type='search.chunk.delete'
		      AND event.payload_json->>'source_version_id'=$2)`, s1dOrg, versionID).
		Scan(&liveArtifacts, &entityRows, &relationRows, &termRows, &deleteEvents); err != nil {
		t.Fatal(err)
	}
	if liveArtifacts != 0 || entityRows != 0 || relationRows != 0 || termRows != 0 || deleteEvents == 0 {
		t.Fatalf("post-purge live_artifacts=%d entity_rows=%d relation_rows=%d term_rows=%d delete_events=%d, want 0/0/0/0/>0", liveArtifacts, entityRows, relationRows, termRows, deleteEvents)
	}
}

func TestSourceVersionPurgeQueueAppRoleDenied(t *testing.T) {
	ctx, _, versionID, _, _ := s1ePurgeSetup(t)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	queue, err := purge.NewSourceQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	appAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_source_purge_app"}
	if _, err := queue.Enqueue(ctx, appAccess, purge.SourceRequestSpec{
		RequestID: requestID, SourceVersion: versionID, ReasonCode: "RETENTION_REQUEST",
		IdempotencyKey: "source-purge-app-deny", Priority: 1, MaxAttempts: 3,
	}); err == nil {
		t.Fatal("application role enqueued a source-version purge")
	}
	if _, _, err := queue.Claim(ctx, appAccess, "app_source_worker", 30); err == nil {
		t.Fatal("application role claimed a source-version purge")
	}
}

func TestSourceVersionPurgeQueueLeaseFencing(t *testing.T) {
	ctx, admin, versionID, _, _ := s1ePurgeSetup(t)
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	queue, err := purge.NewSourceQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	access := purgerAccess()
	if _, err := queue.Enqueue(ctx, access, purge.SourceRequestSpec{
		RequestID: requestID, SourceVersion: versionID, ReasonCode: "RETENTION_REQUEST",
		IdempotencyKey: "source-purge-lease", Priority: 1, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	claimed, found, err := queue.Claim(ctx, access, "source_purge_stale", 30)
	if err != nil || !found {
		t.Fatalf("initial claim=%+v found=%v err=%v", claimed, found, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_purge_request
		SET lease_deadline=clock_timestamp()-interval '1 second'
		WHERE organization_id=$1 AND id=$2`, s1dOrg, requestID); err != nil {
		t.Fatal(err)
	}
	if err := queue.Complete(ctx, access, requestID, "source_purge_stale", claimed.LeaseEpoch); err == nil {
		t.Fatal("expired source purge lease completed")
	} else if purge.QueueCodeOf(err) != purge.QueueCodeLeaseLost {
		t.Fatalf("expired lease error code=%s, want %s", purge.QueueCodeOf(err), purge.QueueCodeLeaseLost)
	}
	if reclaimed, err := queue.Reclaim(ctx, access, 10); err != nil || reclaimed != 1 {
		t.Fatalf("reclaim=%d err=%v, want 1", reclaimed, err)
	}
	reclaimedRequest, found, err := queue.Claim(ctx, access, "source_purge_live", 30)
	if err != nil || !found || reclaimedRequest.AttemptNumber != 2 {
		t.Fatalf("reclaimed claim=%+v found=%v err=%v, want attempt 2", reclaimedRequest, found, err)
	}
	if err := queue.Heartbeat(ctx, access, requestID, "source_purge_stale", claimed.LeaseEpoch, 30); err == nil {
		t.Fatal("stale worker heartbeat succeeded")
	}
	if err := queue.Fail(ctx, access, requestID, "source_purge_live", reclaimedRequest.LeaseEpoch, "TEMPORARY_FAILURE", 0); err != nil {
		t.Fatalf("release reclaimed request: %v", err)
	}
}

func TestSourceVersionPurgeQueueConcurrentClaim(t *testing.T) {
	ctx, _, versionID, _, _ := s1ePurgeSetup(t)
	app := openStore(t, ctx, purgerRole, "knowvault_purger")
	queue, err := purge.NewSourceQueue(app)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	access := purgerAccess()
	if _, err := queue.Enqueue(ctx, access, purge.SourceRequestSpec{
		RequestID: requestID, SourceVersion: versionID, ReasonCode: "RETENTION_REQUEST",
		IdempotencyKey: "source-purge-race", Priority: 1, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	stores := []*database.Store{
		openStore(t, ctx, purgerRole, "knowvault_purger"),
		openStore(t, ctx, purgerRole, "knowvault_purger"),
	}
	queues := make([]*purge.SourceQueue, len(stores))
	for index, store := range stores {
		queues[index], err = purge.NewSourceQueue(store)
		if err != nil {
			t.Fatal(err)
		}
	}
	start := make(chan struct{})
	ready := make(chan struct{}, len(queues))
	results := make(chan bool, len(queues))
	var group sync.WaitGroup
	for index, workerID := range []string{"source_purge_race_a", "source_purge_race_b"} {
		index, workerID := index, workerID
		group.Add(1)
		go func() {
			defer group.Done()
			ready <- struct{}{}
			<-start
			_, found, claimErr := queues[index].Claim(ctx, access, workerID, 30)
			if claimErr != nil {
				t.Errorf("worker %s claim: %v", workerID, claimErr)
			}
			results <- found
		}()
	}
	<-ready
	<-ready
	close(start)
	group.Wait()
	close(results)
	claimed := 0
	for found := range results {
		if found {
			claimed++
		}
	}
	if claimed != 1 {
		t.Fatalf("concurrent source purge claims=%d, want exactly one", claimed)
	}
}
