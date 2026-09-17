package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestSourceSkipResolutionPartialRecoveryAndFailure(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const retryContent = "original retry bytes\n"
	const stillContent = "recovered still bytes\n"
	const nfdName = "cafe\u0301.txt"
	writeS1dFile(t, filepath.Join(dir, nfdName), "non-NFC path leaves partial coverage\n")
	writeS1dFile(t, filepath.Join(dir, "retry.txt"), retryContent)
	oversized := func(name string) { writeS1dFile(t, filepath.Join(dir, name), strings.Repeat("a", 1100000)) }
	oversized("recover.txt")
	oversized("still.txt")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_skipresolution", "confirmation_skipresolution")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	worker := workerAccess(t, s1dOrg)
	newHandler := func(key []byte, keyVersion int) *ingestion.Handler {
		return ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: key, KeyVersion: keyVersion}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	}
	handler := newHandler(s1dDigestKey, 1)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_skip_resolution"}
	mcpHandler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, newAuthorityRuntime(t, ctx))
	assertSkips := func(names ...string) {
		t.Helper()
		if err := appStore.Read(ctx, viewerAccess, func(ctx context.Context, tx database.Transaction) error {
			var count int
			return tx.QueryRow(ctx, `SELECT count(*) FROM app.source_object_current_skips() WHERE organization_id=$1`, s1dOrg).Scan(&count)
		}); err != nil {
			t.Fatalf("app current-state view: %v", err)
		}
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(page.Skipped))
		want := make([]string, 0, len(names))
		for _, skip := range page.Skipped {
			got = append(got, skip.ExternalID)
		}
		for _, name := range names {
			want = append(want, "projects/alpha/"+name)
		}
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("current skips=%q want=%q", got, want)
		}
	}
	resolutionCount := func() int {
		t.Helper()
		var count int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_skip_resolution WHERE organization_id=$1`, s1dOrg).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	assertPartial := func() {
		t.Helper()
		var status string
		var complete bool
		if err := admin.QueryRow(ctx, `SELECT status, coverage_complete FROM public.sync_run
			WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY started_at DESC, id DESC LIMIT 1`, s1dOrg, s1dScopeID).Scan(&status, &complete); err != nil {
			t.Fatal(err)
		}
		if status != "SUCCEEDED" || complete {
			t.Fatalf("fixture must remain a successful partial scan: status=%s complete=%v", status, complete)
		}
	}
	runSync(t, ctx, handler, queue, worker, "skip-initial")
	assertPartial()
	assertSkips(nfdName, "recover.txt", "still.txt")
	_, retryVersion, _ := s1dTargetEvidence(t, ctx, admin, "projects/alpha/retry.txt")
	writeS1dFile(t, filepath.Join(dir, "recover.txt"), "recovered new object\n")
	runSync(t, ctx, handler, queue, worker, "skip-recovered")
	assertPartial()
	assertSkips(nfdName, "still.txt")
	if resolutionCount() != 1 {
		t.Fatal("one formerly skipped identity must produce one resolution")
	}
	runSync(t, ctx, handler, queue, worker, "skip-recovered-repeat")
	if resolutionCount() != 1 {
		t.Fatal("healthy repeat sync must not append observation/resolution rows")
	}

	// A new skip remains visible although the same identity has an older readable version.
	oversized("retry.txt")
	runSync(t, ctx, handler, queue, worker, "skip-after-readable")
	assertSkips(nfdName, "retry.txt", "still.txt")
	_, currentRetryVersion, _ := s1dTargetEvidence(t, ctx, admin, "projects/alpha/retry.txt")
	if currentRetryVersion != retryVersion {
		t.Fatal("quarantine unexpectedly replaced the older readable version")
	}
	writeS1dFile(t, filepath.Join(dir, "retry.txt"), retryContent)
	checkedRunning := false
	failing := handler.WithFault(func(stage string) error {
		if stage == "after_publication" && resolutionCount() > 1 {
			assertSkips(nfdName, "retry.txt", "still.txt")
			checkedRunning = true
			return errors.New("stop after committing per-object recovery")
		}
		return nil
	})
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, worker, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "skip-failed-" + jobID,
		Priority: 100, MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := queue.Claim(ctx, worker, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim failed-run control: ok=%v err=%v", ok, err)
	}
	if err := failing.Handle(ctx, worker, claimed); err == nil || !checkedRunning {
		t.Fatalf("expected injected failure after running-state proof: err=%v checked=%v", err, checkedRunning)
	}
	assertSkips(nfdName, "retry.txt", "still.txt")
	if resolutionCount() != 2 {
		t.Fatal("failed attempt must retain its inactive resolution fact")
	}
	runSync(t, ctx, handler, queue, worker, "skip-after-failed-retry")
	assertPartial()
	assertSkips(nfdName, "still.txt")
	if resolutionCount() != 3 {
		t.Fatal("successful retry must append a separate confirmation after FAILED run")
	}
	_, sameVersion, _ := s1dTargetEvidence(t, ctx, admin, "projects/alpha/retry.txt")
	if sameVersion != retryVersion {
		t.Fatal("same bytes must resolve the skip without manufacturing a version")
	}

	// Resolve an old key's pending identity after rotating both the key and its version.
	writeS1dFile(t, filepath.Join(dir, "still.txt"), stillContent)
	rotated := newHandler([]byte(strings.Repeat("r", 32)), 2)
	runSync(t, ctx, rotated, queue, worker, "skip-key-rotation")
	assertSkips(nfdName)
	if resolutionCount() != 4 {
		t.Fatal("rotation must resolve the prior key's pending identity exactly once")
	}
	oversized("still.txt")
	runSync(t, ctx, rotated, queue, worker, "skip-after-recovery")
	assertSkips(nfdName, "still.txt")
	writeS1dFile(t, filepath.Join(dir, "still.txt"), stillContent)
	runSync(t, ctx, rotated, queue, worker, "skip-second-recovery")
	assertSkips(nfdName)
	if resolutionCount() != 5 {
		t.Fatal("a later quarantine requires its own new positive recovery")
	}
	runSync(t, ctx, rotated, queue, worker, "skip-confirmed-repeat")
	if resolutionCount() != 5 {
		t.Fatal("already confirmed identities must not grow the resolution ledger")
	}
	_, projection := r3a1MCPListObjects(t, mcpHandler, token, csrf, "skip-recovered-list")
	if projection.SkippedCount != 1 {
		t.Fatalf("MCP skipped_count=%d want 1", projection.SkippedCount)
	}
	_, projection = r3a1RESTListObjects(t, mcpHandler, token)
	if projection.SkippedCount != 1 {
		t.Fatalf("REST skipped_count=%d want 1", projection.SkippedCount)
	}

	// A complete scan can retire an absent skip without deleting its history.
	if err := os.Remove(filepath.Join(dir, nfdName)); err != nil {
		t.Fatal(err)
	}
	runSync(t, ctx, rotated, queue, worker, "skip-complete-cutoff")
	assertSkips()
	var history int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_skip WHERE organization_id=$1`, s1dOrg).Scan(&history); err != nil || history < 3 {
		t.Fatalf("original skip ledger must remain: history=%d err=%v", history, err)
	}
	writeS1dFile(t, filepath.Join(dir, nfdName), "partial again\n")
	runSync(t, ctx, rotated, queue, worker, "skip-after-complete")
	assertSkips(nfdName)

	// Content retention does not erase recovery metadata or resurrect an old skip.
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(ctx, worker, retryVersion, "RETENTION_EXPIRED"); err != nil {
		t.Fatal(err)
	}
	if _, err := purger.Cleanup(ctx, worker, retryVersion); err != nil {
		t.Fatal(err)
	}
	if err := purger.CompletePurge(ctx, worker, retryVersion, "RETENTION_EXPIRED"); err != nil {
		t.Fatal(err)
	}
	assertSkips(nfdName)
	if resolutionCount() != 5 {
		t.Fatal("source version purge must preserve content-free recovery facts")
	}
	for _, mutation := range []string{
		`UPDATE public.source_object_skip_resolution SET resolved_at=now() WHERE organization_id=$1`,
		`DELETE FROM public.source_object_skip_resolution WHERE organization_id=$1`,
	} {
		if _, err := admin.Exec(ctx, mutation, s1dOrg); err == nil {
			t.Fatal("recovery facts must be immutable outside tenant hard-delete")
		}
	}

	// Existing workspace confirmation authority still governs both data and skips.
	var confirmationID, confirmationHash string
	if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_source_id=$2`, s1dOrg, fixture.workspaceSourceID).Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatal(err)
	}
	if _, err := newAuthorityRuntime(t, ctx).RevokeManagedConfirmation(ctx,
		authorityAccess(fixture, fixture.ownerID, "req_skip_resolution_revoke"), workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("skip-resolution-revoke"), OrganizationID: s1dOrg,
			WorkspaceID: s1dWorkspace, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatal(err)
	}
	page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
	if err != nil || len(page.Items) != 0 || len(page.Skipped) != 0 {
		t.Fatalf("revoked workspace disclosed inventory: page=%+v err=%v", page, err)
	}
}

func TestSourceSkipResolutionOwnerBoundary(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "keep.txt"), "readable\n")
	writeS1dFile(t, filepath.Join(dir, "retry.txt"), strings.Repeat("a", 1100000))
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	const foreignOrg, foreignOwner = "org_skip_other", "principal_skip_other"
	seedS1dOrg(t, ctx, admin, foreignOrg, foreignOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	worker := workerAccess(t, s1dOrg)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, worker, "resolution-boundary-skipped")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	mainAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_resolution_owner"}
	foreignAccess := database.AccessContext{OrganizationID: foreignOrg, PrincipalID: foreignOwner, RequestID: "req_resolution_foreign"}
	assertCount := func(access database.AccessContext, query string, want int) {
		t.Helper()
		var count int
		if err := appStore.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
			return tx.QueryRow(ctx, query, s1dOrg).Scan(&count)
		}); err != nil || count != want {
			t.Fatalf("owner query count=%d want=%d err=%v", count, want, err)
		}
	}
	const skipsQuery = `SELECT count(*) FROM app.source_object_current_skips() WHERE organization_id=$1`
	assertCount(mainAccess, skipsQuery, 1)
	assertCount(foreignAccess, skipsQuery, 0)
	writeS1dFile(t, filepath.Join(dir, "retry.txt"), "recovered\n")
	writeS1dFile(t, filepath.Join(dir, "new-skip.txt"), strings.Repeat("b", 1100000))
	runSync(t, ctx, handler, queue, worker, "resolution-boundary-recovered")
	// A newer authoritative FULL scan replaces old failures while retaining
	// the new quarantine it actually observed in that same completed scan.
	assertCount(mainAccess, skipsQuery, 1)
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	page, err := viewer.ListObjects(ctx, mainAccess, s1dWorkspace, false, 0, 100)
	if err != nil || len(page.Skipped) != 1 || page.Skipped[0].ExternalID != "projects/alpha/new-skip.txt" {
		t.Fatalf("full cutoff must keep exactly the new quarantine: skips=%+v err=%v", page.Skipped, err)
	}
	var complete bool
	if err := admin.QueryRow(ctx, `SELECT mode='FULL' AND status='SUCCEEDED' AND coverage_complete FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY completed_at DESC, id DESC LIMIT 1`, s1dOrg, s1dScopeID).Scan(&complete); err != nil || !complete {
		t.Fatalf("new quarantine control must be an authoritative full scan: complete=%v err=%v", complete, err)
	}
	const resolutionsQuery = `SELECT count(*) FROM public.source_object_skip_resolution WHERE organization_id=$1`
	assertCount(mainAccess, resolutionsQuery, 1)
	assertCount(foreignAccess, resolutionsQuery, 0)
	// A worker cannot manufacture another observation from a historical fact.
	if err := workerStore.Write(ctx, worker, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `INSERT INTO public.source_object_skip_resolution
			(organization_id,source_scope_id,source_scope_revision,external_id_digest,digest_key_version,
			 skipped_sync_run_id,resolving_sync_run_id,source_object_id)
			SELECT organization_id,source_scope_id,source_scope_revision,external_id_digest,digest_key_version,
			       skipped_sync_run_id,resolving_sync_run_id,source_object_id
			FROM public.source_object_skip_resolution WHERE organization_id=$1 ON CONFLICT DO NOTHING`, s1dOrg)
		return err
	}); err == nil || !strings.Contains(err.Error(), "live object observation") {
		t.Fatalf("historical observation replay must fail the owner guard: %v", err)
	}
	for _, storeAccess := range []struct {
		store  *database.Store
		access database.AccessContext
	}{{appStore, mainAccess}, {workerStore, worker}} {
		if err := storeAccess.store.Write(ctx, storeAccess.access, func(ctx context.Context, tx database.Transaction) error {
			_, err := tx.Exec(ctx, `DELETE FROM public.source_object_skip_resolution WHERE organization_id=$1`, s1dOrg)
			return err
		}); err == nil {
			t.Fatal("runtime role must not erase recovery facts")
		}
	}
}
