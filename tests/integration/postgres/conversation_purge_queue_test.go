package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestConversationPurgeQueueLifecycle proves the production control-plane
// boundary: an authorized member enqueues an opaque request idempotently, only
// the trusted purger can lease it, the real retention authority is resumed to
// PURGED, and an expired lease is reclaimed without a duplicate request.
func TestConversationPurgeQueueLifecycle(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_purge_queue"
		ownerID        = "usr_purge_queue"
		workspaceID    = "ws_purge_queue"
		conversationID = "conv_purge_queue"
		retryConvID    = "conv_purge_retry"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedConversationForPurgeQueue(t, ctx, appStore, organizationID, ownerID, workspaceID, conversationID)
	seedConversationForPurgeQueue(t, ctx, appStore, organizationID, ownerID, workspaceID, retryConvID)

	appQueue, err := purge.NewQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	appAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_purge_queue_enqueue"}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	spec := purge.RequestSpec{
		RequestID: requestID, WorkspaceID: workspaceID, ConversationID: conversationID,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "purge-queue-idempotency",
		Priority: 10, MaxAttempts: 3,
	}
	firstID, err := appQueue.Enqueue(ctx, appAccess, spec)
	if err != nil || firstID != requestID {
		t.Fatalf("enqueue id=%s err=%v, want %s", firstID, err, requestID)
	}
	replayID, err := appQueue.Enqueue(ctx, appAccess, spec)
	if err != nil || replayID != requestID {
		t.Fatalf("idempotent enqueue id=%s err=%v, want %s", replayID, err, requestID)
	}
	spec.ConversationID = retryConvID
	if _, err := appQueue.Enqueue(ctx, appAccess, spec); err == nil {
		t.Fatal("idempotency key was reused for a different conversation")
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purgeQueue, err := purge.NewQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	purgeAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_purge_worker", RequestID: "req_purge_queue_worker"}
	if _, _, err := appQueue.Claim(ctx, appAccess, "purger_app_denied", 30); err == nil {
		t.Fatal("application role claimed a privileged purge request")
	}

	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	processed, err := purger.ProcessNextConversationPurge(ctx, purgeAccess, purgeQueue, "purger_queue_worker", 30)
	if err != nil || !processed {
		t.Fatalf("process queued purge processed=%v err=%v", processed, err)
	}
	var requestStatus, retentionState string
	if err := admin.QueryRow(ctx, `
		SELECT request.status, retention.state
		  FROM public.conversation_purge_request AS request
		  JOIN public.conversation_retention AS retention
		    ON retention.organization_id = request.organization_id
		   AND retention.conversation_id = request.conversation_id
		 WHERE request.organization_id=$1 AND request.id=$2
	`, organizationID, requestID).Scan(&requestStatus, &retentionState); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "SUCCEEDED" || retentionState != "PURGED" {
		t.Fatalf("processed queue request=%s retention=%s, want SUCCEEDED/PURGED", requestStatus, retentionState)
	}
	var purgingAudits, purgedAudits int
	if err := admin.QueryRow(ctx, `
		SELECT
		  (SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2 AND action='conversation.purging'),
		  (SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2 AND action='conversation.purged')
	`, organizationID, conversationID).Scan(&purgingAudits, &purgedAudits); err != nil {
		t.Fatal(err)
	}
	if purgingAudits != 1 || purgedAudits != 1 {
		t.Fatalf("queue purge audits purging=%d purged=%d, want 1/1", purgingAudits, purgedAudits)
	}

	// A second request demonstrates lease expiry and retry without invoking any
	// test-only mutation path in the runtime roles.
	retryRequestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	retrySpec := purge.RequestSpec{
		RequestID: retryRequestID, WorkspaceID: workspaceID, ConversationID: retryConvID,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "purge-queue-retry",
		Priority: 20, MaxAttempts: 3,
	}
	if _, err := appQueue.Enqueue(ctx, appAccess, retrySpec); err != nil {
		t.Fatalf("enqueue retry request: %v", err)
	}
	retryRequest, found, err := purgeQueue.Claim(ctx, purgeAccess, "purger_queue_retry", 30)
	if err != nil || !found || retryRequest.AttemptNumber != 1 {
		t.Fatalf("claim retry request=%+v found=%v err=%v", retryRequest, found, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.conversation_purge_request SET lease_deadline=clock_timestamp() - interval '1 second' WHERE organization_id=$1 AND id=$2`, organizationID, retryRequestID); err != nil {
		t.Fatal(err)
	}
	if err := purgeQueue.Complete(ctx, purgeAccess, retryRequest.ID, "purger_queue_retry", retryRequest.LeaseEpoch); err == nil {
		t.Fatal("expired worker lease completed a queue request")
	}
	reclaimed, err := purgeQueue.Reclaim(ctx, purgeAccess, 10)
	if err != nil || reclaimed != 1 {
		t.Fatalf("reclaim count=%d err=%v, want 1", reclaimed, err)
	}
	retryRequest, found, err = purgeQueue.Claim(ctx, purgeAccess, "purger_queue_retry_2", 30)
	if err != nil || !found || retryRequest.AttemptNumber != 2 {
		t.Fatalf("reclaimed request=%+v found=%v err=%v, want attempt 2", retryRequest, found, err)
	}
	if err := purgeQueue.Fail(ctx, purgeAccess, retryRequest.ID, "purger_queue_retry_2", retryRequest.LeaseEpoch, "TEMPORARY_FAILURE", 0); err != nil {
		t.Fatalf("fail retry request: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT status FROM public.conversation_purge_request WHERE organization_id=$1 AND id=$2`, organizationID, retryRequestID).Scan(&requestStatus); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "PENDING" {
		t.Fatalf("failed retry request status=%s, want PENDING", requestStatus)
	}
}

func TestConversationPurgeQueueConcurrentClaimSingleLease(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_purge_queue_race"
		ownerID        = "usr_purge_queue_race"
		workspaceID    = "ws_purge_queue_race"
		conversationID = "conv_purge_queue_race"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedConversationForPurgeQueue(t, ctx, appStore, organizationID, ownerID, workspaceID, conversationID)
	appQueue, err := purge.NewQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := appQueue.Enqueue(ctx, database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_purge_queue_race_enqueue"}, purge.RequestSpec{
		RequestID: requestID, WorkspaceID: workspaceID, ConversationID: conversationID,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "purge-queue-race", Priority: 1, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}

	stores := []*database.Store{
		openStore(t, ctx, purgerRole, "knowvault_purger"),
		openStore(t, ctx, purgerRole, "knowvault_purger"),
	}
	queues := make([]*purge.Queue, 2)
	for index, store := range stores {
		queues[index], err = purge.NewQueue(store)
		if err != nil {
			t.Fatal(err)
		}
	}
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_queue_race_worker", RequestID: "req_purge_queue_race_claim"}
	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	type result struct {
		request purge.Request
		worker  string
		found   bool
		err     error
	}
	results := make(chan result, 2)
	var group sync.WaitGroup
	for index, workerID := range []string{"purger_queue_race_a", "purger_queue_race_b"} {
		index, workerID := index, workerID
		group.Add(1)
		go func() {
			defer group.Done()
			ready <- struct{}{}
			<-start
			request, found, err := queues[index].Claim(ctx, access, workerID, 30)
			results <- result{request: request, worker: workerID, found: found, err: err}
		}()
	}
	<-ready
	<-ready
	close(start)
	group.Wait()
	close(results)
	var claimed int
	var winner purge.Request
	var winnerWorker string
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent claim error: %v", item.err)
		}
		if item.found {
			claimed++
			winner = item.request
			winnerWorker = item.worker
		}
	}
	if claimed != 1 || winner.ID != requestID || winner.LeaseEpoch != 1 || winner.AttemptNumber != 1 {
		t.Fatalf("concurrent claim winner=%+v count=%d, want one epoch-1 attempt-1 claim", winner, claimed)
	}
	for index, workerID := range []string{"purger_queue_race_a", "purger_queue_race_b"} {
		if workerID == winnerWorker {
			if err := queues[index].Fail(ctx, access, requestID, workerID, winner.LeaseEpoch, "TEMPORARY_FAILURE", 0); err != nil {
				t.Fatalf("release concurrent claim: %v", err)
			}
		}
	}
}

func TestConversationPurgeRunnerReclaimsAndProcesses(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_purge_runner"
		ownerID        = "usr_purge_runner"
		workspaceID    = "ws_purge_runner"
		conversationID = "conv_purge_runner"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedConversationForPurgeQueue(t, ctx, appStore, organizationID, ownerID, workspaceID, conversationID)
	appQueue, err := purge.NewQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_purge_runner"}
	if _, err := appQueue.Enqueue(ctx, access, purge.RequestSpec{
		RequestID: requestID, WorkspaceID: workspaceID, ConversationID: conversationID,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "purge-runner", Priority: 1, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purgeQueue, err := purge.NewQueue(purgerStore)
	if err != nil {
		t.Fatal(err)
	}
	purgeAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_purge_runner_worker", RequestID: "req_purge_runner_worker"}
	stale, found, err := purgeQueue.Claim(ctx, purgeAccess, "purger_runner_stale", 30)
	if err != nil || !found {
		t.Fatalf("initial claim request=%+v found=%v err=%v", stale, found, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.conversation_purge_request SET lease_deadline=clock_timestamp() - interval '1 second' WHERE organization_id=$1 AND id=$2`, organizationID, requestID); err != nil {
		t.Fatal(err)
	}
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := purge.NewRunner(purger, purgeQueue, purgeAccess, purge.RunnerConfig{
		WorkerID: "purger_runner_live", LeaseSeconds: 30, PollInterval: time.Second, ReclaimLimit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := runner.RunOnce(ctx)
	if err != nil || outcome.Reclaimed != 1 || !outcome.Processed {
		t.Fatalf("runner outcome=%+v err=%v, want reclaim=1 processed=true", outcome, err)
	}
	var requestStatus, retentionState string
	if err := admin.QueryRow(ctx, `
		SELECT request.status, retention.state
		  FROM public.conversation_purge_request AS request
		  JOIN public.conversation_retention AS retention
		    ON retention.organization_id = request.organization_id
		   AND retention.conversation_id = request.conversation_id
		 WHERE request.organization_id=$1 AND request.id=$2
	`, organizationID, requestID).Scan(&requestStatus, &retentionState); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "SUCCEEDED" || retentionState != "PURGED" {
		t.Fatalf("runner request=%s retention=%s, want SUCCEEDED/PURGED", requestStatus, retentionState)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := runner.Run(cancelled); err != nil {
		t.Fatalf("runner cancellation was not clean: %v", err)
	}
}

func TestConversationPurgeRunnerAppRoleDenied(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_purge_runner_deny"
		ownerID        = "usr_purge_runner_deny"
		workspaceID    = "ws_purge_runner_deny"
		conversationID = "conv_purge_runner_deny"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedConversationForPurgeQueue(t, ctx, appStore, organizationID, ownerID, workspaceID, conversationID)
	appQueue, err := purge.NewQueue(appStore)
	if err != nil {
		t.Fatal(err)
	}
	requestID, err := ids.New("purge")
	if err != nil {
		t.Fatal(err)
	}
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_purge_runner_deny"}
	if _, err := appQueue.Enqueue(ctx, access, purge.RequestSpec{
		RequestID: requestID, WorkspaceID: workspaceID, ConversationID: conversationID,
		ReasonCode: "RETENTION_REQUEST", IdempotencyKey: "purge-runner-deny", Priority: 1, MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	purger, err := purge.NewPurger(appStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := purge.NewRunner(purger, appQueue, access, purge.RunnerConfig{
		WorkerID: "purger_runner_app", LeaseSeconds: 30, PollInterval: time.Second, ReclaimLimit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.RunOnce(ctx); err == nil || purge.RunnerCodeOf(err) != purge.RunnerCodeFailed {
		t.Fatalf("application role drove purger runner err=%v code=%s", err, purge.RunnerCodeOf(err))
	}
	var requestStatus string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.conversation_purge_request WHERE organization_id=$1 AND id=$2`, organizationID, requestID).Scan(&requestStatus); err != nil {
		t.Fatal(err)
	}
	if requestStatus != "PENDING" {
		t.Fatalf("application runner changed request status=%s, want PENDING", requestStatus)
	}
}

func seedConversationForPurgeQueue(t *testing.T, ctx context.Context, appStore *database.Store,
	organizationID, ownerID, workspaceID, conversationID string) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_purge_queue_seed_" + conversationID}
	if err := appStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			VALUES ($1,$2,$3,1,$4)
		`, organizationID, conversationID, workspaceID, ownerID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ($1,$2,$3,1)
		`, organizationID, conversationID, workspaceID)
		return err
	}); err != nil {
		t.Fatalf("seed queued conversation %s: %v", conversationID, err)
	}
}
