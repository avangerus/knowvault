package postgres_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// s1dTargetEvidence resolves the object/version/extraction for one exact
// root-relative path by reproducing the connector's identity digest, so a test
// with several files can address a specific one.
func s1dTargetEvidence(t *testing.T, ctx context.Context, admin *pgxpool.Pool, relativePath string) (objectID, versionID, extractionID string) {
	t.Helper()
	locator, err := canon.FileLocatorBytes("conn_s1d", relativePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := canon.HMACDigest(s1dDigestKey, 1, locator)
	if err := admin.QueryRow(ctx, `SELECT o.id, v.id, ae.extraction_id
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id
		WHERE o.organization_id=$1 AND o.external_object_id_digest=$2`, s1dOrg, digest).
		Scan(&objectID, &versionID, &extractionID); err != nil {
		t.Fatalf("resolve target %q: %v", relativePath, err)
	}
	return objectID, versionID, extractionID
}

// TestS1dReconciliationRemovesAbsentMembership proves the deletion path via a full
// scan (SRC-006, ING-005, ING-008, FRESH-002): when an authoritative full sync no
// longer observes an object, that object's membership in the synced scope is closed
// ACTIVE->MISSING in one lease-fenced write, the SourceVersion and its Evidence stay
// immutably present, and the read-time disclosure gate denies the Evidence body
// with the identical not-found — no half-state, no oracle.
func TestS1dReconciliationRemovesAbsentMembership(t *testing.T) {
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
	// A survivor file keeps every scan non-empty, so absence of the target is an
	// authoritative deletion, not the held empty-scan case (P1-1).
	writeS1dFile(t, filepath.Join(dir, "keep.txt"), "keep one\nkeep two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	scopeConfigHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)

	// The authority chain (binding + grant + confirmation) is minted by the seed
	// through the production repository; the claim-time liveness re-check
	// (000018 s5) demands a live confirmation on the exact tuple.
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, scopeConfigHash)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, access, "sync-present")

	objectID, versionID, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/notes.txt")
	fragmentID := s1dFragments(t, ctx, admin, extractionID)[0].id

	// A fully authorized viewer reads the Evidence while the object is present.
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_view"}
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); err != nil {
		t.Fatalf("authorized read before deletion failed: %v", err)
	}

	// The object leaves the source: the next full scan is authoritative.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	before := s1dCounts(t, ctx, admin)
	runSync(t, ctx, handler, queue, access, "sync-absent")

	// The immutable rows are untouched; only the membership state moves.
	after := s1dCounts(t, ctx, admin)
	if after.objects != before.objects || after.versions != before.versions ||
		after.extractions != before.extractions || after.fragments != before.fragments {
		t.Fatalf("reconciliation mutated immutable rows: before=%+v after=%+v", before, after)
	}
	var state string
	var removedAt *time.Time
	if err := admin.QueryRow(ctx, `SELECT membership_state, missing_at FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3`,
		s1dOrg, objectID, s1dScopeID).Scan(&state, &removedAt); err != nil {
		t.Fatal(err)
	}
	if state != "MISSING" || removedAt == nil {
		t.Fatalf("membership after deletion = %s (missing_at=%v), want MISSING", state, removedAt)
	}
	// The version row itself is unchanged (immutable); the closure is at membership.
	var versionState string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`,
		s1dOrg, versionID).Scan(&versionState); err != nil {
		t.Fatal(err)
	}
	if versionState != "CURRENT" {
		t.Fatalf("version state changed to %s; reconciliation must not rewrite the immutable version", versionState)
	}
	// The object was reachable from no scope, so the full scan is a proven
	// SOURCE_OBJECT_MISSING (DATA_MODEL.md §4): the object closes and stops being
	// queryable, while its immutable version/Evidence rows remain for a later observed return or purge.
	var lifecycle string
	var objectQueryable bool
	if err := admin.QueryRow(ctx, `SELECT lifecycle_state, queryable FROM public.source_object
		WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&lifecycle, &objectQueryable); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "MISSING" || objectQueryable {
		t.Fatalf("object after full-scan deletion: lifecycle=%s queryable=%v, want MISSING and false", lifecycle, objectQueryable)
	}

	// The closure left exactly one content-free SOURCE_OBJECT_MISSING audit event
	// naming the exact object, a SYSTEM actor, carrying no source content (AUD-005).
	var auditCount int
	var actorType, metadata string
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='source.object_missing' AND resource_type='SOURCE_OBJECT' AND resource_id=$2`,
		s1dOrg, objectID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected exactly one source.object_missing event for %s, got %d", objectID, auditCount)
	}
	if err := admin.QueryRow(ctx, `SELECT actor_type, metadata_json::text FROM public.audit_event
		WHERE organization_id=$1 AND action='source.object_missing' AND resource_id=$2`, s1dOrg, objectID).
		Scan(&actorType, &metadata); err != nil {
		t.Fatal(err)
	}
	if actorType != "SYSTEM" {
		t.Fatalf("deletion audit actor_type=%s, want SYSTEM", actorType)
	}

	// Read-time disclosure gate: the same fragment id is now denied identically.
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("read after removal: err=%v, want ErrNotFound", err)
	}
}

// TestS1dReconciliationPreservesOverlappingScope proves VER-005 under a full-scan
// deletion: closing one scope's membership never deletes a SourceObject that
// another overlapping scope still holds ACTIVE, and it never touches the other
// scope's membership. Reconciliation is exact to the synced scope revision.
func TestS1dReconciliationPreservesOverlappingScope(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	keep := filepath.Join(dir, "notes.txt")
	shared := filepath.Join(dir, "shared.txt")
	writeS1dFile(t, keep, "keep one\nkeep two\n")
	writeS1dFile(t, shared, "shared one\nshared two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation on
	// every synced scope: the same tuple for scope A, the second binding for B.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	scopeB, _ := seedS1dSecondScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, scopeB, 1,
		"binding_02ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d2_admin", "confirmation_s1d2_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	handler = handler.WithSearchRepository(repository)
	if err := workerStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return repository.EnsureMountedLexicalProfile(ctx, tx, access, 1, 1)
	}); err != nil {
		t.Fatal(err)
	}

	// Both overlapping scopes see both files, resolving to two shared SourceObjects
	// with two ACTIVE memberships each.
	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, "sync-a")
	runSyncScope(t, ctx, handler, queue, access, scopeB, "sync-b")
	if c := s1dCounts(t, ctx, admin); c.objects != 2 || c.memberships != 4 {
		t.Fatalf("overlapping seed: objects=%d memberships=%d, want 2 and 4", c.objects, c.memberships)
	}

	// The shared file leaves the source; only scope A is re-synced.
	if err := os.Remove(shared); err != nil {
		t.Fatal(err)
	}
	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, "sync-a-absent")

	// Exactly one membership is now MISSING, and it is scope A's membership of the
	// shared object; the object itself is still queryable via scope B.
	var removedObject, removedScope string
	var removedCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='MISSING'`, s1dOrg).Scan(&removedCount); err != nil {
		t.Fatal(err)
	}
	if removedCount != 1 {
		t.Fatalf("expected exactly one MISSING membership, got %d", removedCount)
	}
	if err := admin.QueryRow(ctx, `SELECT source_object_id, source_scope_id FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='MISSING'`, s1dOrg).Scan(&removedObject, &removedScope); err != nil {
		t.Fatal(err)
	}
	if removedScope != s1dScopeID {
		t.Fatalf("MISSING membership is in scope %s, want the re-synced scope %s", removedScope, s1dScopeID)
	}
	// Scope B still holds the shared object ACTIVE: the object survives (VER-005).
	var siblingState string
	if err := admin.QueryRow(ctx, `SELECT membership_state FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3`,
		s1dOrg, removedObject, scopeB).Scan(&siblingState); err != nil {
		t.Fatal(err)
	}
	if siblingState != "ACTIVE" {
		t.Fatalf("overlapping scope B membership = %s, want ACTIVE (object must survive)", siblingState)
	}
	var queryable bool
	var lifecycle string
	if err := admin.QueryRow(ctx, `SELECT queryable, lifecycle_state FROM public.source_object
		WHERE organization_id=$1 AND id=$2`, s1dOrg, removedObject).Scan(&queryable, &lifecycle); err != nil {
		t.Fatal(err)
	}
	if !queryable || lifecycle != "ACTIVE" {
		t.Fatalf("shared object closed (queryable=%v lifecycle=%s) although another scope still holds it ACTIVE", queryable, lifecycle)
	}
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	transport := &presencePausingIndex{base: index}
	client, err := search.New(search.Config{Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg, Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(), HTTPClient: &http.Client{Transport: transport, Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := search.NewApplier(workerStore, repository, codec, client)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := applier.Drain(ctx, access, 100); err != nil || count != 2 || transport.deletes != 0 {
		t.Fatalf("overlapping active membership was deleted or lost: %d %v deletes=%d", count, err, transport.deletes)
	}
	result, err := client.Search(ctx, search.Query{Text: "shared", Size: 10, SourceScopeIDs: []string{scopeB}, VersionState: search.VersionStateCurrent})
	if err != nil || len(result.Hits) != 1 {
		t.Fatalf("overlapping active scope not searchable: %d %v", len(result.Hits), err)
	}
	var objectMissingEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND resource_id=$2 AND action='source.object_missing'`, s1dOrg, removedObject).Scan(&objectMissingEvents); err != nil {
		t.Fatal(err)
	}
	if objectMissingEvents != 0 {
		t.Fatal("one absent overlapping membership was mislabeled as a missing object")
	}
	// The kept file's memberships are untouched in both scopes.
	var activeMemberships int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 3 {
		t.Fatalf("active memberships=%d, want 3 (kept file x2, shared file in scope B)", activeMemberships)
	}
	if err := workerStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(ctx, `UPDATE public.source_object_scope SET membership_state='MOVED',missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3`, s1dOrg, removedObject, s1dScopeID)
		return err
	}); err == nil {
		t.Fatal("worker bypassed missing membership guard on an ACTIVE overlapping object")
	}
	writeS1dFile(t, shared, "shared one\nshared two\n")
	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, "sync-a-returned")
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='ACTIVE'`, s1dOrg).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 4 {
		t.Fatalf("returned overlapping membership remained absent: active=%d", activeMemberships)
	}
	if count, err := applier.Drain(ctx, access, 100); err != nil || count != 1 || transport.deletes != 0 {
		t.Fatalf("returning overlapping scope did not refresh index membership: %d %v deletes=%d", count, err, transport.deletes)
	}
	result, err = client.Search(ctx, search.Query{Text: "shared", Size: 10, SourceScopeIDs: []string{s1dScopeID}, VersionState: search.VersionStateCurrent})
	if err != nil || len(result.Hits) != 1 {
		t.Fatalf("returned overlapping scope absent from search: %d %v", len(result.Hits), err)
	}
	var objectRestoredEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND resource_id=$2 AND action='source.object_restored'`, s1dOrg, removedObject).Scan(&objectRestoredEvents); err != nil {
		t.Fatal(err)
	}
	if objectRestoredEvents != 0 {
		t.Fatal("one returning overlapping membership was mislabeled as an object restoration")
	}
}
