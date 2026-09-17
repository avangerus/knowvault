package postgres_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// seedS1dScopeRevisionN adds an immutable revision N to the S1d scope with a
// narrowed folder config (the given exclude globs) and its own DRAFT activation,
// and advances latest_revision to N — exactly what an admin scope-config edit
// produces (ADR-0047: a config change is a new DRAFT revision, no implicit
// cutover). The worker then syncs latest (=N) and the cutover supersedes the
// prior authoritative revision.
func seedS1dScopeRevisionN(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	codec *artifactcrypto.Codec, organizationID, ownerID string, revision int64, excludeGlobs string) {
	t.Helper()
	const (
		connectionID = "conn_s1d"
		discoveryID  = "discovered_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	)
	configArtifact := fmt.Sprintf("artifact_scope_config_s1d_r%d", revision)
	folderConfigJSON := []byte(`{"root_alias":"docs-root","relative_root":"projects/alpha","path_matcher_version":"scope-glob-v1","recursive":true,"include_globs":["**/*"],"exclude_globs":[` + excludeGlobs + `],"max_file_bytes":1048576,"ocr_mode":"OFF","follow_symlinks":false,"formats":["TXT","MARKDOWN","SOURCE_CODE","CSV","JSON","XML","EML"]}`)
	digest := "hmac-sha256:k1:" + strings.Repeat("1", 64)

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var scopeResourceID string
	if err := tx.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id($1,$2,$3)`, organizationID, s1dScopeID, revision).Scan(&scopeResourceID); err != nil {
		t.Fatal(err)
	}
	configHash := sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceScopeConfig, organizationID,
		configArtifact, scopeResourceID, "source_scope_revision", "scope_config_artifact_id",
		"SOURCE_SCOPE_CONFIG", "SCOPE_CONFIG", folderConfigJSON)
	exec := func(sql string, args ...any) {
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed revision %d: %v\n%s", revision, err, sql)
		}
	}
	exec(`INSERT INTO public.source_scope_revision (organization_id, source_scope_id, revision, connection_id, connection_revision,
		discovered_scope_id, discovered_identity_digest, discovered_identity_digest_key_version, source_type, scope_config_artifact_id, scope_config_hash,
		scope_contract_version, access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
		object_limit, byte_limit, max_object_bytes, created_by)
		VALUES ($1,$2,$9,$3,1,$4,$5,1,'FOLDER',$6,$7,'1.2','WORKSPACE_MANAGED',300,600,NULL,1000,1000000,100000,$8)`,
		organizationID, s1dScopeID, connectionID, discoveryID, digest, configArtifact, configHash, ownerID, revision)
	exec(`INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ($1,$2,$3,1,'DRAFT')`, organizationID, s1dScopeID, revision)
	exec(`UPDATE public.source_scope SET latest_revision=$3 WHERE organization_id=$1 AND id=$2`, organizationID, s1dScopeID, revision)

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit revision %d seed: %v", revision, err)
	}
}

// seedS1dScopeRevision2 is the revision-2 case used by the base cutover tests.
func seedS1dScopeRevision2(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	codec *artifactcrypto.Codec, organizationID, ownerID string, excludeGlobs string) {
	t.Helper()
	seedS1dScopeRevisionN(t, ctx, admin, codec, organizationID, ownerID, 2, excludeGlobs)
}

type cutoverEnv struct {
	admin   *pgxpool.Pool
	codec   *artifactcrypto.Codec
	handler *ingestion.Handler
	queue   *jobs.Queue
	access  database.AccessContext
	root    string
	dir     string
}

// newCutoverEnv resets the database, seeds the org and the revision-1 scope,
// writes two files (notes.txt, beta.txt) under the scope root, and runs the
// first FULL sync so both objects are ACTIVE under revision 1.
func newCutoverEnv(t *testing.T) (context.Context, cutoverEnv) {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "notes one\nnotes two\n")
	writeS1dFile(t, filepath.Join(dir, "beta.txt"), "beta one\nbeta two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live derived-live
	// confirmation for the revision-1 sync target before the first worker run.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, access, "sync-r1")

	return ctx, cutoverEnv{admin: admin, codec: codec, handler: handler, queue: queue, access: access, root: root, dir: dir}
}

func scopeActiveRevision(t *testing.T, ctx context.Context, admin *pgxpool.Pool) int64 {
	t.Helper()
	var rev int64
	if err := admin.QueryRow(ctx, `SELECT COALESCE(active_revision,0) FROM public.source_scope
		WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dScopeID).Scan(&rev); err != nil {
		t.Fatal(err)
	}
	return rev
}

func activationStatus(t *testing.T, ctx context.Context, admin *pgxpool.Pool, revision int64) string {
	t.Helper()
	var status string
	if err := admin.QueryRow(ctx, `SELECT status FROM public.source_scope_activation
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=$3 AND revision=1`,
		s1dOrg, s1dScopeID, revision).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

// TestP2CutoverNarrowsScopeAndClosesRemovedObject is the core cutover proof: a
// revision-2 scope that excludes beta.txt becomes authoritative on a complete
// scan, superseding revision 1 — its activation REVOKED, its memberships REMOVED —
// and the now-unreachable beta object is closed DELETED while notes survives via
// its ACTIVE revision-2 membership. The transition leaves one content-free
// source.scope_activated audit event.
func TestP2CutoverNarrowsScopeAndClosesRemovedObject(t *testing.T) {
	ctx, env := newCutoverEnv(t)

	before := s1dCounts(t, ctx, env.admin)
	if before.objects != 2 || before.memberships != 2 {
		t.Fatalf("revision-1 sync: objects=%d memberships=%d, want 2 and 2", before.objects, before.memberships)
	}
	if got := scopeActiveRevision(t, ctx, env.admin); got != 1 {
		t.Fatalf("active_revision after first sync=%d, want 1", got)
	}

	// Admin narrows the scope: revision 2 excludes beta.txt (which still exists on
	// disk — this is a scope-config change, not a file deletion).
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, `"beta.txt"`)
	// The revision-2 sync target needs its own live confirmation at claim time.
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-cutover")

	// Authority moved to revision 2; revision 1 is superseded (REVOKED).
	if got := scopeActiveRevision(t, ctx, env.admin); got != 2 {
		t.Fatalf("active_revision after cutover=%d, want 2", got)
	}
	if got := activationStatus(t, ctx, env.admin, 1); got != "REVOKED" {
		t.Fatalf("prior activation status=%s, want REVOKED", got)
	}
	if got := activationStatus(t, ctx, env.admin, 2); got != "READY" {
		t.Fatalf("candidate activation status=%s, want READY", got)
	}

	// Every revision-1 membership is REMOVED; the only ACTIVE membership is the
	// revision-2 notes membership.
	var activeRev1, removedRev1, activeRev2 int
	if err := env.admin.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE source_scope_revision=1 AND membership_state='ACTIVE'),
		count(*) FILTER (WHERE source_scope_revision=1 AND membership_state='REMOVED'),
		count(*) FILTER (WHERE source_scope_revision=2 AND membership_state='ACTIVE')
		FROM public.source_object_scope WHERE organization_id=$1`, s1dOrg).Scan(&activeRev1, &removedRev1, &activeRev2); err != nil {
		t.Fatal(err)
	}
	if activeRev1 != 0 || removedRev1 != 2 {
		t.Fatalf("revision-1 memberships active=%d removed=%d, want 0 and 2", activeRev1, removedRev1)
	}
	if activeRev2 != 1 {
		t.Fatalf("revision-2 ACTIVE memberships=%d, want 1 (notes only)", activeRev2)
	}

	// The narrowed-out beta object is closed DELETED and non-queryable; notes stays
	// ACTIVE and queryable.
	var deleted, activeQueryable int
	if err := env.admin.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE lifecycle_state='DELETED' AND NOT queryable),
		count(*) FILTER (WHERE lifecycle_state='ACTIVE' AND queryable)
		FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&deleted, &activeQueryable); err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || activeQueryable != 1 {
		t.Fatalf("object closure: deleted=%d activeQueryable=%d, want 1 and 1", deleted, activeQueryable)
	}

	// The immutable rows are untouched: same object/version/extraction/fragment
	// counts as before the cutover (only membership/lifecycle projections changed).
	after := s1dCounts(t, ctx, env.admin)
	if after.objects != before.objects || after.versions != before.versions ||
		after.extractions != before.extractions || after.fragments != before.fragments {
		t.Fatalf("cutover rewrote immutable rows: before=%+v after=%+v", before, after)
	}

	// One content-free source.scope_activated audit event marks the transition, plus
	// one source.object_deleted for the closed object. Neither carries a path.
	var activatedCount, deletedAudit int
	var metadata string
	if err := env.admin.QueryRow(ctx, `SELECT count(*), COALESCE(max(metadata_json::text),'')
		FROM public.audit_event WHERE organization_id=$1 AND action='source.scope_activated'`, s1dOrg).Scan(&activatedCount, &metadata); err != nil {
		t.Fatal(err)
	}
	if activatedCount != 1 {
		t.Fatalf("source.scope_activated events=%d, want 1", activatedCount)
	}
	if !strings.Contains(metadata, `"source_scope_revision": 2`) {
		t.Fatalf("scope_activated metadata missing revision: %s", metadata)
	}
	for _, forbidden := range []string{"notes", "beta", "projects", "alpha", ".txt", "root"} {
		if strings.Contains(strings.ToLower(metadata), forbidden) {
			t.Fatalf("scope_activated audit leaked content %q: %s", forbidden, metadata)
		}
	}
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='source.object_deleted'`, s1dOrg).Scan(&deletedAudit); err != nil {
		t.Fatal(err)
	}
	if deletedAudit != 1 {
		t.Fatalf("source.object_deleted events=%d, want 1", deletedAudit)
	}
}

// TestP2CutoverPartialCoverageHoldsPriorAuthority proves scan safety (ADR-0061
// §4): a revision-2 whose FULL scan is not complete never cuts over. The prior
// revision stays authoritative, no membership is removed, no object is deleted,
// and the candidate activation is held FAILED.
func TestP2CutoverPartialCoverageHoldsPriorAuthority(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, "")
	// The revision-2 sync target needs its own live confirmation at claim time.
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")

	// The whole relative_root subtree disappears before the revision-2 scan, so the
	// connector cannot enumerate it: coverage is PARTIAL.
	if err := os.RemoveAll(filepath.Join(env.root, "projects")); err != nil {
		t.Fatal(err)
	}
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-partial")

	if got := scopeActiveRevision(t, ctx, env.admin); got != 1 {
		t.Fatalf("partial cutover advanced authority: active_revision=%d, want 1", got)
	}
	if got := activationStatus(t, ctx, env.admin, 2); got != "FAILED" {
		t.Fatalf("held candidate activation=%s, want FAILED", got)
	}
	if got := activationStatus(t, ctx, env.admin, 1); got != "READY" {
		t.Fatalf("prior activation=%s, want READY (untouched)", got)
	}
	var activeRev1, deleted int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_revision=1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeRev1); err != nil {
		t.Fatal(err)
	}
	if activeRev1 != 2 {
		t.Fatalf("partial cutover removed memberships: revision-1 ACTIVE=%d, want 2", activeRev1)
	}
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("partial cutover produced %d false deletions", deleted)
	}
	var errorCode *string
	if err := env.admin.QueryRow(ctx, `SELECT error_code FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_revision=2 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&errorCode); err != nil {
		t.Fatal(err)
	}
	if errorCode == nil || *errorCode != "INGEST_PARTIAL_COVERAGE" {
		t.Fatalf("candidate run error_code=%v, want INGEST_PARTIAL_COVERAGE", errorCode)
	}
}

// TestP2CutoverOverlappingScopeSurvives proves VER-005 across the cutover: a
// shared object an overlapping *different* scope still holds ACTIVE survives the
// supersession of the first scope's revision.
func TestP2CutoverOverlappingScopeSurvives(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	// A second, different scope whose globs also match both files: after its sync
	// the two objects each hold a second ACTIVE membership.
	secondScope, _ := seedS1dSecondScope(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner)
	// Both sync targets (the second scope at revision 1, the first scope at
	// revision 2) need their own live confirmation at claim time (000018 s5).
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, secondScope, 1,
		"binding_02ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d2_admin", "confirmation_s1d2_admin")
	runSyncScope(t, ctx, env.handler, env.queue, env.access, secondScope, "sync-second")

	// Now narrow the first scope to exclude beta and cut over.
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, `"beta.txt"`)
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-cutover")

	// The first scope's revision 1 is superseded, but every object still holds an
	// ACTIVE membership from the overlapping second scope, so no object is DELETED.
	var deleted, activeObjects int
	if err := env.admin.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE lifecycle_state='DELETED'),
		count(*) FILTER (WHERE lifecycle_state='ACTIVE' AND queryable)
		FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&deleted, &activeObjects); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 || activeObjects != 2 {
		t.Fatalf("overlapping scope not preserved: deleted=%d active=%d, want 0 and 2", deleted, activeObjects)
	}
	// The second scope's memberships stay ACTIVE and untouched by the first scope's
	// cutover.
	var secondActive int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_id=$2 AND membership_state='ACTIVE'`, s1dOrg, secondScope).Scan(&secondActive); err != nil {
		t.Fatal(err)
	}
	if secondActive != 2 {
		t.Fatalf("second scope memberships active=%d, want 2", secondActive)
	}
}

// TestP2CutoverDBContainmentRefusesIncompleteCoverage is the independent DB
// containment layer (ADR-0061 §4, charter three-layer proof): the SQL function
// itself refuses a cutover on a run that is not a complete FULL coverage run, and
// assert_scope_revision_syncing raises for a revision that is not SYNCING — even
// if the Go orchestrator gate were bypassed.
func TestP2CutoverDBContainmentRefusesIncompleteCoverage(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, "")

	// A live worker lease.
	jobID := mustID(t, "job")
	if _, err := env.queue.Enqueue(ctx, env.access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "db-containment-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := env.queue.Claim(ctx, env.access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: %v ok=%v", err, ok)
	}

	// A revision-2 run that is FULL/SUCCEEDED but NOT coverage_complete.
	runID := mustID(t, "syncrun")
	if _, err := env.admin.Exec(ctx, `INSERT INTO public.sync_run
		(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, completed_at, coverage_complete)
		VALUES ($1,$2,$3,2,$4,'FULL','SUCCEEDED',now(),false)`, s1dOrg, runID, s1dScopeID, jobID); err != nil {
		t.Fatal(err)
	}

	store := openStore(t, ctx, workerRole, "knowvault_worker")
	// activate_revision must refuse: the coverage run is not complete.
	err = store.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
		_, e := tx.Exec(ctx, `SELECT app.source_scope_activate_revision($1,2,$2,$3,$4,$5)`,
			s1dScopeID, runID, jobID, s1dWorkerID, claimed.LeaseEpoch)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "complete coverage run") {
		t.Fatalf("activate_revision accepted an incomplete coverage run: %v", err)
	}
	// Authority unchanged.
	if got := scopeActiveRevision(t, ctx, env.admin); got != 1 {
		t.Fatalf("refused cutover still advanced authority: active_revision=%d, want 1", got)
	}

	// assert_scope_revision_syncing must raise for revision 2 (still DRAFT, not SYNCING).
	err = store.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
		_, e := tx.Exec(ctx, `SELECT app.assert_scope_revision_syncing($1,2)`, s1dScopeID)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("assert_scope_revision_syncing accepted a non-SYNCING revision: %v", err)
	}
}

// TestP2CutoverFencesSupersededRevision proves the worker fence (ADR-0061 §3): a
// derived write for a revision superseded by a cutover is rejected, because the
// revision's activation is REVOKED and assert_scope_revision_syncing raises.
func TestP2CutoverFencesSupersededRevision(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, "")
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-cutover")
	if got := scopeActiveRevision(t, ctx, env.admin); got != 2 {
		t.Fatalf("active_revision after cutover=%d, want 2", got)
	}

	// A revision-1 worker's derived write is now fenced: revision 1's activation is
	// REVOKED, so assert_scope_revision_syncing(scope, 1) rejects the whole tx.
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	err := store.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
		_, e := tx.Exec(ctx, `SELECT app.assert_scope_revision_syncing($1,1)`, s1dScopeID)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("superseded revision-1 write was not fenced: %v", err)
	}
}

// TestP2CutoverCrashBeforeCommitKeepsPriorAuthoritative proves recovery (ADR-0061
// §5): a crash after the candidate's complete scan but before the authority
// transition commits leaves the prior revision authoritative and the candidate
// still SYNCING; a clean reclaimed re-run then converges to the cutover.
func TestP2CutoverCrashBeforeCommitKeepsPriorAuthoritative(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, `"beta.txt"`)
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")

	// Crash right before the authority transition.
	runSyncExpectingFailure(t, ctx, env.handler.WithFault(faultOnce("before_publish")), env.queue, env.access, "sync-r2-crash")

	if got := scopeActiveRevision(t, ctx, env.admin); got != 1 {
		t.Fatalf("crash before commit advanced authority: active_revision=%d, want 1", got)
	}
	// The failed sync marks its own candidate activation FAILED (it never reached the
	// authority transition); the prior revision stays authoritative and READY. A
	// hard process crash would instead leave it SYNCING — either way FAILED->SYNCING
	// re-sync converges below, and neither closes a prior membership.
	if got := activationStatus(t, ctx, env.admin, 2); got != "FAILED" {
		t.Fatalf("candidate activation after crash=%s, want FAILED", got)
	}
	if got := activationStatus(t, ctx, env.admin, 1); got != "READY" {
		t.Fatalf("prior activation after crash=%s, want READY", got)
	}
	var activeRev1, deleted int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_revision=1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeRev1); err != nil {
		t.Fatal(err)
	}
	if activeRev1 != 2 {
		t.Fatalf("crash rolled forward membership closure: revision-1 ACTIVE=%d, want 2", activeRev1)
	}
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("crash before commit deleted %d objects", deleted)
	}

	// A clean reclaimed re-run converges to the cutover.
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-resume")
	if got := scopeActiveRevision(t, ctx, env.admin); got != 2 {
		t.Fatalf("resume did not converge: active_revision=%d, want 2", got)
	}
	if got := activationStatus(t, ctx, env.admin, 1); got != "REVOKED" {
		t.Fatalf("resume did not supersede prior: revision-1 status=%s, want REVOKED", got)
	}
}

// TestP2CutoverBeginSyncRefusesStaleRevision proves the forward-only begin-sync
// fence: a worker cannot begin a sync for a revision older than the current
// authoritative one, so a reordered stale worker never commits ACTIVE memberships
// at a superseded revision (ADR-0061 §3/§5).
func TestP2CutoverBeginSyncRefusesStaleRevision(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 2, "")
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 3, "")
	// The revision-3 sync target needs its own live confirmation at claim time.
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 3,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAX", "grant_s1d_admin_r3", "confirmation_s1d_admin_r3")
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r3") // cutover to 3
	if got := scopeActiveRevision(t, ctx, env.admin); got != 3 {
		t.Fatalf("active_revision=%d, want 3", got)
	}

	// Revision 2 stayed DRAFT; a stale worker attempting to begin its sync while 3 is
	// authoritative is refused before it can write any membership.
	jobID := mustID(t, "job")
	if _, err := env.queue.Enqueue(ctx, env.access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "stalebegin-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := env.queue.Claim(ctx, env.access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: %v ok=%v", err, ok)
	}
	// Test-only raw invocation of the worker primitive: the registered surface
	// (source_scope_registered_begin_sync, exercised through the production
	// claim path elsewhere) adds the liveness re-check on top; this direct
	// call isolates the stale-revision fence itself.
	store := openStore(t, ctx, workerRole, "knowvault_worker")
	err = store.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
		_, e := tx.Exec(ctx, `SELECT app.source_scope_begin_sync($1,2,$2,$3,$4)`,
			s1dScopeID, jobID, s1dWorkerID, claimed.LeaseEpoch)
		return e
	})
	if err == nil || !strings.Contains(err.Error(), "older than the active revision") {
		t.Fatalf("begin_sync of a stale revision was not refused: %v", err)
	}
	// Revision 2 stays DRAFT (not SYNCING) and nothing was deleted.
	if got := activationStatus(t, ctx, env.admin, 2); got != "DRAFT" {
		t.Fatalf("refused stale begin_sync changed activation to %s, want DRAFT", got)
	}
}

// TestP2CutoverPrimitivesDeniedToWebRole proves the cutover primitives are a
// worker capability only (POKA_YOKE privilege boundary): the web/API role
// knowvault_app, which holds USAGE ON SCHEMA app, cannot invoke the mass-delete
// cutover primitive or its peers — 000016 REVOKEs the PUBLIC default grant.
func TestP2CutoverPrimitivesDeniedToWebRole(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	app := openStore(t, ctx, appRole, "knowvault_app")
	for _, call := range []struct {
		name string
		sql  string
		args []any
	}{
		{"assert_scope_revision_syncing", `SELECT app.assert_scope_revision_syncing($1,1)`, []any{s1dScopeID}},
		{"source_scope_publish_partial", `SELECT app.source_scope_publish_partial($1,1,$2,$3,1)`, []any{s1dScopeID, "job_x", s1dWorkerID}},
		{"source_scope_activate_revision", `SELECT app.source_scope_activate_revision($1,1,$2,$3,$4,1)`, []any{s1dScopeID, "run_x", "job_x", s1dWorkerID}},
	} {
		err := app.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
			_, e := tx.Exec(ctx, call.sql, call.args...)
			return e
		})
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "permission denied") {
			t.Fatalf("%s must be denied to knowvault_app, got: %v", call.name, err)
		}
	}
}

// TestP2CutoverEmptyScanHoldsPriorAuthority proves the empty-complete-scan trap in
// the cutover path: a readable-but-empty relative_root (the "vanished mount
// presents an empty mountpoint" signature) is a complete scan that observed
// nothing, so it must never cut over. The prior revision stays authoritative and
// the candidate is held.
func TestP2CutoverEmptyScanHoldsPriorAuthority(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	seedS1dScopeRevision2(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, "")
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 2,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAW", "grant_s1d_admin_r2", "confirmation_s1d_admin_r2")

	// Empty the relative_root but keep it readable → complete scan, zero observed.
	if err := os.Remove(filepath.Join(env.dir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(env.dir, "beta.txt")); err != nil {
		t.Fatal(err)
	}
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r2-empty")

	if got := scopeActiveRevision(t, ctx, env.admin); got != 1 {
		t.Fatalf("empty-scan cutover advanced authority: active_revision=%d, want 1", got)
	}
	if got := activationStatus(t, ctx, env.admin, 2); got != "FAILED" {
		t.Fatalf("held candidate activation=%s, want FAILED", got)
	}
	var activeRev1, deleted int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_revision=1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeRev1); err != nil {
		t.Fatal(err)
	}
	if activeRev1 != 2 {
		t.Fatalf("empty-scan cutover removed memberships: revision-1 ACTIVE=%d, want 2", activeRev1)
	}
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("empty-scan cutover deleted %d objects", deleted)
	}
	var errorCode *string
	if err := env.admin.QueryRow(ctx, `SELECT error_code FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_revision=2 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&errorCode); err != nil {
		t.Fatal(err)
	}
	if errorCode == nil || *errorCode != "INGEST_EMPTY_SCAN_UNCORROBORATED" {
		t.Fatalf("empty-scan candidate error_code=%v, want INGEST_EMPTY_SCAN_UNCORROBORATED", errorCode)
	}
}

// TestP2CutoverAbandonedIntermediateMembershipClosed proves the fix for the
// zombie-object hazard: a stray ACTIVE membership left by an abandoned
// intermediate revision must not keep a gone object open. A cutover supersedes
// EVERY older revision's memberships, not only the immediately-prior active one.
func TestP2CutoverAbandonedIntermediateMembershipClosed(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	// Revision 2 (abandoned intermediate) and revision 3 (the cutover target,
	// excluding beta). Neither is synced through the worker here; revision 2 gets a
	// stray ACTIVE membership as if a partial scan had written it before failing.
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 2, "")
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 3, `"beta.txt"`)
	// The revision-3 sync target needs its own live confirmation at claim time.
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 3,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAX", "grant_s1d_admin_r3", "confirmation_s1d_admin_r3")
	if _, err := env.admin.Exec(ctx, `INSERT INTO public.source_object_scope
		(organization_id, source_object_id, source_scope_id, source_scope_revision, membership_state)
		SELECT organization_id, id, $2, 2, 'ACTIVE' FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='ACTIVE'`, s1dOrg, s1dScopeID); err != nil {
		t.Fatal(err)
	}

	// Sync latest (=3): a genuine forward cutover to revision 3 that excludes beta.
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r3-cutover")

	if got := scopeActiveRevision(t, ctx, env.admin); got != 3 {
		t.Fatalf("active_revision after cutover=%d, want 3", got)
	}
	// The stray revision-2 memberships are all closed (no zombie ACTIVE membership).
	var strayActive int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_revision=2 AND membership_state='ACTIVE'`, s1dOrg).Scan(&strayActive); err != nil {
		t.Fatal(err)
	}
	if strayActive != 0 {
		t.Fatalf("abandoned revision-2 left %d stray ACTIVE memberships", strayActive)
	}
	// beta, excluded by revision 3 and no longer held by any live revision, is
	// closed DELETED; notes survives via its revision-3 membership.
	var deleted, activeQueryable int
	if err := env.admin.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE lifecycle_state='DELETED' AND NOT queryable),
		count(*) FILTER (WHERE lifecycle_state='ACTIVE' AND queryable)
		FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&deleted, &activeQueryable); err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || activeQueryable != 1 {
		t.Fatalf("abandoned-intermediate closure: deleted=%d activeQueryable=%d, want 1 and 1", deleted, activeQueryable)
	}
}

// TestP2CutoverStaleCandidateRefused proves the forward-only authority guard: a
// candidate strictly older than the current active revision (a reordered stale
// worker) is refused — it never publishes or supersedes the newer authoritative
// revision. Without this a stale retry would REVOKE and mass-delete the newer
// revision.
func TestP2CutoverStaleCandidateRefused(t *testing.T) {
	ctx, env := newCutoverEnv(t)
	// Revisions 2 (stays DRAFT through the revision-3 cutover) and 3.
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 2, "")
	seedS1dScopeRevisionN(t, ctx, env.admin, env.codec, s1dOrg, s1dOwner, 3, "")
	// The revision-3 sync target needs its own live confirmation at claim time.
	seedS1dScopeBinding(t, ctx, env.admin, s1dOrg, s1dWorkspace, s1dOwner, s1dScopeID, 3,
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAX", "grant_s1d_admin_r3", "confirmation_s1d_admin_r3")
	runSync(t, ctx, env.handler, env.queue, env.access, "sync-r3") // cutover to 3
	if got := scopeActiveRevision(t, ctx, env.admin); got != 3 {
		t.Fatalf("active_revision=%d, want 3", got)
	}

	// Revision 2 stayed DRAFT (the cutover revokes only READY/SYNCING older
	// activations); promote it to SYNCING and give it a complete coverage run, then
	// have a worker attempt to activate the stale revision 2 while 3 is authoritative.
	if _, err := env.admin.Exec(ctx, `UPDATE public.source_scope_activation SET status='SYNCING'
		WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=2 AND revision=1`, s1dOrg, s1dScopeID); err != nil {
		t.Fatal(err)
	}
	jobID := mustID(t, "job")
	if _, err := env.queue.Enqueue(ctx, env.access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "stale-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatal(err)
	}
	claimed, ok, err := env.queue.Claim(ctx, env.access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim: %v ok=%v", err, ok)
	}
	runID := mustID(t, "syncrun")
	if _, err := env.admin.Exec(ctx, `INSERT INTO public.sync_run
		(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, completed_at, coverage_complete)
		VALUES ($1,$2,$3,2,$4,'FULL','SUCCEEDED',now(),true)`, s1dOrg, runID, s1dScopeID, jobID); err != nil {
		t.Fatal(err)
	}

	store := openStore(t, ctx, workerRole, "knowvault_worker")
	var outcome string
	if err := store.Write(ctx, env.access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT outcome FROM app.source_scope_activate_revision($1,2,$2,$3,$4,$5) LIMIT 1`,
			s1dScopeID, runID, jobID, s1dWorkerID, claimed.LeaseEpoch).Scan(&outcome)
	}); err != nil {
		t.Fatalf("activate_revision(stale): %v", err)
	}
	if outcome != "HELD" {
		t.Fatalf("stale candidate outcome=%s, want HELD", outcome)
	}
	// The newer authoritative revision 3 is untouched: authority, its activation and
	// its memberships all survive; nothing was deleted.
	if got := scopeActiveRevision(t, ctx, env.admin); got != 3 {
		t.Fatalf("stale candidate moved authority: active_revision=%d, want 3", got)
	}
	if got := activationStatus(t, ctx, env.admin, 3); got != "READY" {
		t.Fatalf("stale candidate disturbed revision 3: status=%s, want READY", got)
	}
	if got := activationStatus(t, ctx, env.admin, 2); got != "FAILED" {
		t.Fatalf("refused stale candidate activation=%s, want FAILED", got)
	}
	var activeRev3, deleted int
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_scope_revision=3 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeRev3); err != nil {
		t.Fatal(err)
	}
	if activeRev3 != 2 {
		t.Fatalf("stale candidate closed revision-3 memberships: ACTIVE=%d, want 2", activeRev3)
	}
	if err := env.admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND lifecycle_state='DELETED'`, s1dOrg).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if deleted != 0 {
		t.Fatalf("stale candidate deleted %d objects", deleted)
	}
}
