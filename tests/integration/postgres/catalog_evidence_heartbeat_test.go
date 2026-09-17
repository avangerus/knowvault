package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestS1dHandlerExtendsLeaseAtObjectBoundary proves the composition hook is
// exercised by the real folder-to-Evidence handler, not only by the durable
// job SQL substrate. The fault pauses immediately after publication, while the
// short original lease would otherwise be close to expiry.
func TestS1dHandlerExtendsLeaseAtObjectBoundary(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(directory, "notes.txt"), "heartbeat proof\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New).
		WithLeaseExtensionSeconds(30).
		WithFault(func(stage string) error {
			if stage != "after_publication" {
				return nil
			}
			close(entered)
			<-release
			return errors.New("test fault")
		})
	access := workerAccess(t, s1dOrg)
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "heartbeat-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 5)
	if err != nil || !ok {
		t.Fatalf("claim failed: %v ok=%v", err, ok)
	}

	result := make(chan error, 1)
	go func() { result <- handler.Handle(ctx, access, claimed) }()
	select {
	case <-entered:
	case err := <-result:
		close(release)
		t.Fatalf("handler exited before heartbeat observation: %v", err)
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("handler did not reach the object publication boundary")
	}

	var deadline time.Time
	if err := admin.QueryRow(ctx, `SELECT lease_deadline FROM public.job WHERE organization_id=$1 AND id=$2`, s1dOrg, claimed.ID).Scan(&deadline); err != nil {
		close(release)
		t.Fatal(err)
	}
	if !deadline.After(time.Now().Add(15 * time.Second)) {
		close(release)
		t.Fatalf("heartbeat did not extend lease sufficiently: deadline=%v", deadline)
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("faulted handler unexpectedly succeeded")
	}
}

// TestS1dHandlerExtendsLeaseBeforeDiscovery proves the heartbeat is owned by
// the claim lifecycle rather than by the parser loop. A deliberately paused
// discovery phase outlives the initial five-second claim; the live PostgreSQL
// deadline must still move before the fault is released.
func TestS1dHandlerExtendsLeaseBeforeDiscovery(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(directory, "notes.txt"), "heartbeat discovery proof\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New).
		WithLeaseExtensionSeconds(3).
		WithFault(func(stage string) error {
			if stage != "before_discovery" {
				return nil
			}
			close(entered)
			<-release
			return errors.New("test discovery fault")
		})
	access := workerAccess(t, s1dOrg)
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "heartbeat-discovery-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 5)
	if err != nil || !ok {
		t.Fatalf("claim failed: %v ok=%v", err, ok)
	}

	result := make(chan error, 1)
	go func() { result <- handler.Handle(ctx, access, claimed) }()
	select {
	case <-entered:
	case err := <-result:
		close(release)
		t.Fatalf("handler exited before discovery boundary: %v", err)
	case <-time.After(20 * time.Second):
		close(release)
		t.Fatal("handler did not reach the discovery boundary")
	}
	// Capture the synchronous extension first, then poll for a later deadline
	// instead of relying on one wall-clock sleep. The lifecycle ticker is
	// intentionally asynchronous; under a loaded shared PostgreSQL runner a
	// single two-second sample can race the first tick and make a healthy
	// heartbeat look absent.
	var initialDeadline time.Time
	readDeadline := func() (time.Time, error) {
		var deadline time.Time
		err := admin.QueryRow(ctx, `SELECT lease_deadline FROM public.job WHERE organization_id=$1 AND id=$2`, s1dOrg, claimed.ID).Scan(&deadline)
		return deadline, err
	}
	if initialDeadline, err = readDeadline(); err != nil {
		close(release)
		t.Fatal(err)
	}
	heartbeatObserved := false
	deadline := initialDeadline
	poll := time.NewTicker(100 * time.Millisecond)
	defer poll.Stop()
	timeout := time.NewTimer(8 * time.Second)
	defer timeout.Stop()
	for !heartbeatObserved {
		select {
		case <-poll.C:
			if deadline, err = readDeadline(); err != nil {
				close(release)
				t.Fatal(err)
			}
			heartbeatObserved = deadline.After(initialDeadline.Add(500 * time.Millisecond))
		case <-timeout.C:
			close(release)
			t.Fatalf("lifecycle heartbeat did not move lease deadline from %v; last deadline=%v", initialDeadline, deadline)
		}
	}
	close(release)
	if err := <-result; err == nil {
		t.Fatal("faulted discovery unexpectedly succeeded")
	}
}
