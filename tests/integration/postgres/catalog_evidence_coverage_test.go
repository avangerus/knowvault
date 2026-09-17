package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
)

type unresolvedS1dMounts struct{}

func (unresolvedS1dMounts) Resolve(string, string) (string, bool) { return "", false }

// TestS1dReconciliationSkipsOnPartialCoverage proves the authoritative-absence
// boundary (S1e/C1): absence of an object from a scan closes a membership only if
// the scan proved complete coverage of the exact scope. When the connector could
// not enumerate the whole allowed root — here the entire relative_root subtree is
// gone, the analogue of a temporarily unavailable mount or an I/O failure — the
// scan is PARTIAL, so no membership is REMOVED, no SourceObject is DELETED, and
// the run records partial coverage honestly instead of silently deleting.
func TestS1dReconciliationSkipsOnPartialCoverage(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "a.txt"), "alpha one\nalpha two\n")
	writeS1dFile(t, filepath.Join(dir, "b.txt"), "beta one\nbeta two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, access, "sync-present")

	before := s1dCounts(t, ctx, admin)
	if before.objects != 2 || before.memberships != 2 {
		t.Fatalf("seed: objects=%d memberships=%d, want 2 and 2", before.objects, before.memberships)
	}

	// The whole relative_root subtree disappears: the connector cannot enumerate
	// it, so the scan is not authoritative for absence.
	if err := os.RemoveAll(filepath.Join(root, "projects")); err != nil {
		t.Fatal(err)
	}
	runSync(t, ctx, handler, queue, access, "sync-partial")

	// No membership was removed and no object was closed, although zero objects
	// were observed this pass.
	var activeMemberships, activeObjects int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 2 {
		t.Fatalf("partial scan removed memberships: active=%d, want 2", activeMemberships)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='ACTIVE' AND queryable`, s1dOrg).Scan(&activeObjects); err != nil {
		t.Fatal(err)
	}
	if activeObjects != 2 {
		t.Fatalf("partial scan closed objects: active/queryable=%d, want 2", activeObjects)
	}
	var deleted int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("partial scan produced %d false deletions", deleted)
	}

	// The run honestly reflects partial coverage: SUCCEEDED (it ingested what it
	// saw) but flagged with the partial-coverage code.
	var status string
	var errorCode *string
	if err := admin.QueryRow(ctx, `SELECT status, error_code FROM public.sync_run
		WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&status, &errorCode); err != nil {
		t.Fatal(err)
	}
	if status != "SUCCEEDED" {
		t.Fatalf("partial-coverage run status=%s, want SUCCEEDED", status)
	}
	if errorCode == nil || *errorCode != "INGEST_PARTIAL_COVERAGE" {
		t.Fatalf("partial-coverage run error_code=%v, want INGEST_PARTIAL_COVERAGE", errorCode)
	}
}

// TestS1dUnresolvedAccessDoesNotIndex proves ING-001 at the ingestion state
// boundary. A valid scope with no trusted mount resolution fails with a coded
// error before discovery, and therefore cannot publish an object, version,
// extraction, Evidence, or a queryable projection.
func TestS1dUnresolvedAccessDoesNotIndex(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "unresolved.txt"), "must never be indexed\n")
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
	// The filesystem exists, but the trusted alias/identity resolver is empty.
	// This is an access-resolution failure, not an empty or partial scan.
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, unresolvedS1dMounts{}, s1dWorkerID, time.Now, ids.New)
	runSyncExpectingFailure(t, ctx, handler, queue, workerAccess(t, s1dOrg), "unresolved-access")

	var objects, versions, extractions, fragments int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version WHERE organization_id=$1`, s1dOrg).Scan(&versions); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_extraction WHERE organization_id=$1`, s1dOrg).Scan(&extractions); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment WHERE organization_id=$1`, s1dOrg).Scan(&fragments); err != nil {
		t.Fatal(err)
	}
	if objects != 0 || versions != 0 || extractions != 0 || fragments != 0 {
		t.Fatalf("unresolved access published catalog rows: objects=%d versions=%d extractions=%d fragments=%d", objects, versions, extractions, fragments)
	}
	var status, errorCode string
	if err := admin.QueryRow(ctx, `SELECT status, error_code FROM public.sync_run
		WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&status, &errorCode); err != nil {
		t.Fatal(err)
	}
	if status != "FAILED" || errorCode != "INGEST_ROOT_UNRESOLVED" {
		t.Fatalf("unresolved access run status/error=%s/%s, want FAILED/INGEST_ROOT_UNRESOLVED", status, errorCode)
	}
}

// TestS1dReconciliationHoldsOnEmptyScan proves the empty-scan safety boundary
// (P1-1): a complete authoritative scan that observes nothing at all — the
// signature of a vanished or substituted mount — is never treated as mass
// deletion. No membership is removed, no object is closed, and the run records
// INGEST_EMPTY_SCAN_UNCORROBORATED. Removing an entire catalog is irreversible, so
// absence with zero corroboration is held.
func TestS1dReconciliationHoldsOnEmptyScan(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "a.txt"), "alpha one\nalpha two\n")
	writeS1dFile(t, filepath.Join(dir, "b.txt"), "beta one\nbeta two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, access, "sync-present")

	// Every file is gone but the scope root is still an empty, readable directory —
	// exactly what an unmounted volume presents. The scan is Complete but observes
	// nothing.
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	runSync(t, ctx, handler, queue, access, "sync-empty")

	var activeMemberships, activeObjects, deleted int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 2 {
		t.Fatalf("empty scan removed memberships: active=%d, want 2", activeMemberships)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='ACTIVE' AND queryable`, s1dOrg).Scan(&activeObjects); err != nil {
		t.Fatal(err)
	}
	if activeObjects != 2 {
		t.Fatalf("empty scan closed objects: active/queryable=%d, want 2", activeObjects)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("empty scan produced %d irreversible false deletions", deleted)
	}
	var status string
	var errorCode *string
	if err := admin.QueryRow(ctx, `SELECT status, error_code FROM public.sync_run
		WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&status, &errorCode); err != nil {
		t.Fatal(err)
	}
	if status != "SUCCEEDED" || errorCode == nil || *errorCode != "INGEST_EMPTY_SCAN_UNCORROBORATED" {
		t.Fatalf("empty-scan run status=%s error_code=%v, want SUCCEEDED/INGEST_EMPTY_SCAN_UNCORROBORATED", status, errorCode)
	}
}

// TestS1dReconciliationCrashRollsBack proves reconciliation is atomic: a crash
// after the membership closure but before commit leaves nothing REMOVED and
// nothing DELETED, and a clean reclaimed re-run then converges to the correct
// closure. No false or half-applied deletion survives a crash.
func TestS1dReconciliationCrashRollsBack(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "notes.txt")
	writeS1dFile(t, target, "line one\nline two\n")
	// A survivor keeps the scan non-empty so reconciliation actually runs.
	writeS1dFile(t, filepath.Join(dir, "keep.txt"), "keep one\nkeep two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, access, "sync-present")

	objectID, _, _ := s1dTargetEvidence(t, ctx, admin, "projects/alpha/notes.txt")

	// The target file leaves the source (the directory and the survivor remain, so
	// the scan is complete and non-empty), but the reconciliation transaction
	// crashes before commit.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	runSyncExpectingFailure(t, ctx, handler.WithFault(faultOnce("in_reconcile")), queue, access, "crash-recon")

	var state string
	var lifecycle string
	var queryable bool
	if err := admin.QueryRow(ctx, `SELECT membership_state FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2`, s1dOrg, objectID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ACTIVE" {
		t.Fatalf("crash left membership %s, want rolled-back ACTIVE", state)
	}
	if err := admin.QueryRow(ctx, `SELECT lifecycle_state, queryable FROM public.source_object
		WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&lifecycle, &queryable); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "ACTIVE" || !queryable {
		t.Fatalf("crash left object lifecycle=%s queryable=%v, want rolled-back ACTIVE/true", lifecycle, queryable)
	}

	// A clean reclaimed re-run converges: the now-absent object is closed.
	runSync(t, ctx, handler, queue, access, "resume-recon")
	if err := admin.QueryRow(ctx, `SELECT membership_state FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2`, s1dOrg, objectID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT lifecycle_state, queryable FROM public.source_object
		WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&lifecycle, &queryable); err != nil {
		t.Fatal(err)
	}
	if state != "MISSING" || lifecycle != "MISSING" || queryable {
		t.Fatalf("resume did not converge: membership=%s lifecycle=%s queryable=%v", state, lifecycle, queryable)
	}
}
