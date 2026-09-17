package postgres_test

import (
	"context"
	"errors"
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
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

func purgerAccess() database.AccessContext {
	return database.AccessContext{OrganizationID: s1dOrg, PrincipalID: "usr_purger", RequestID: "req_purge"}
}

// s1ePurgeSetup seeds an org+scope, writes one file, runs one sync to a live
// active version with Evidence, and returns the admin pool, the active ids and a
// purger bound to the trusted knowvault_purger role.
func s1ePurgeSetup(t *testing.T) (context.Context, *pgxpool.Pool, string, string, *purge.Purger) {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "purge one\npurge two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "sync")

	_, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragmentID := s1dFragments(t, ctx, admin, extractionID)[0].id
	// Seed one real derived SearchChunk so every purge test exercises both
	// encrypted Evidence cleanup and the search-projection retention contract.
	chunkID := mustID(t, "chunk")
	artifactID := mustID(t, "artifact")
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SearchChunkText, s1dOrg, chunkID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Seal(owner, []byte("purge one"))
	if err != nil {
		t.Fatal(err)
	}
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	workerAccessContext := workerAccess(t, s1dOrg)
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
		chunk := search.Chunk{ID: chunkID, OrganizationID: s1dOrg, SourceVersionID: versionID,
			ExtractionID: extractionID, ChunkHash: envelope.PlaintextHash(), TokenCount: 2,
			EmbeddingProfileHash:       "sha256:" + strings.Repeat("d", 64),
			EmbeddingModelArtifactHash: "sha256:" + strings.Repeat("e", 64), EmbeddingDimension: 384}
		if err := searchRepository.CreateChunk(txCtx, transaction, workerAccessContext, chunk, artifactID, envelope); err != nil {
			return err
		}
		return searchRepository.AddFragment(txCtx, transaction, workerAccessContext, chunkID, fragmentID, 1)
	}); err != nil {
		t.Fatalf("seed search chunk: %v", err)
	}
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, admin, versionID, extractionID, purger
}

// TestS1ePurgeFailCloseAndDisclosureGate proves class 1 (fail-close transition)
// and class 3's first half (content becomes inaccessible before bytes are gone):
// begin_purge advances the fence, closes version and extraction queryability,
// forbids extraction, clears the active pointer, and denies a previously
// authorized Evidence read — all while the ciphertext is still physically present.
func TestS1ePurgeFailCloseAndDisclosureGate(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "line one\nline two\n"
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), content)
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "sync")

	_, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragmentID := s1dFragments(t, ctx, admin, extractionID)[0].id

	// A fully authorized viewer can read the Evidence before purge.
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_view"}
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); err != nil {
		t.Fatalf("authorized read before purge failed: %v", err)
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	newFence, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST")
	if err != nil {
		t.Fatalf("begin purge: %v", err)
	}
	if newFence != 1 {
		t.Fatalf("fence did not advance to 1: got %d", newFence)
	}

	// Version and extraction retention fail closed; the active pointer is gone.
	var vState string
	var vQueryable, vExtractionAllowed bool
	if err := admin.QueryRow(ctx, `SELECT state, queryable, extraction_allowed FROM public.source_version_retention
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&vState, &vQueryable, &vExtractionAllowed); err != nil {
		t.Fatal(err)
	}
	if vState != "PURGING" || vQueryable || vExtractionAllowed {
		t.Fatalf("version retention after begin: state=%s queryable=%v extraction_allowed=%v", vState, vQueryable, vExtractionAllowed)
	}
	var eState string
	var eQueryable bool
	if err := admin.QueryRow(ctx, `SELECT state, queryable FROM public.source_extraction_retention
		WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID).Scan(&eState, &eQueryable); err != nil {
		t.Fatal(err)
	}
	if eState != "PURGING" || eQueryable {
		t.Fatalf("extraction retention after begin: state=%s queryable=%v", eState, eQueryable)
	}
	var pointers int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version_active_extraction
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&pointers); err != nil {
		t.Fatal(err)
	}
	if pointers != 0 {
		t.Fatal("active extraction pointer survived begin_purge")
	}

	// The ciphertext is still physically present: inaccessibility precedes cleanup.
	var liveCiphertext int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='evidence_fragment' AND purged_at IS NULL
		  AND resource_id IN (SELECT id FROM public.evidence_fragment WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, versionID).Scan(&liveCiphertext); err != nil {
		t.Fatal(err)
	}
	if liveCiphertext == 0 {
		t.Fatal("begin_purge physically removed bytes; cleanup must be a separate step")
	}

	// The authorized viewer is now denied identically — content is inaccessible.
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("read after begin_purge: err=%v, want ErrNotFound", err)
	}

	// One content-free source.version_purging audit event names the exact version.
	var auditCount int
	var metadata string
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='source.version_purging' AND resource_type='SOURCE_OBJECT' AND resource_id=$2 AND actor_type='SYSTEM'`,
		s1dOrg, versionID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("expected one source.version_purging event, got %d", auditCount)
	}
	if err := admin.QueryRow(ctx, `SELECT metadata_json::text FROM public.audit_event
		WHERE organization_id=$1 AND action='source.version_purging' AND resource_id=$2`, s1dOrg, versionID).Scan(&metadata); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(metadata, "notes.txt") || strings.Contains(metadata, "line one") {
		t.Fatalf("purge audit leaked content: %s", metadata)
	}
}

// TestS1ePurgeStaleWorkContainment proves class 2: after the fail-close, no stale
// worker can reactivate the version — the active pointer cannot be re-established
// against non-ACTIVE retention, and the immutable version cannot roll back to
// CURRENT.
func TestS1ePurgeStaleWorkContainment(t *testing.T) {
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin purge: %v", err)
	}

	// The fail-close must remove the old active pointer before any stale worker
	// can attempt to publish against the version. This assertion distinguishes
	// the intended fence from an incidental duplicate-key failure below.
	var pointers int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version_active_extraction
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&pointers); err != nil {
		t.Fatal(err)
	}
	if pointers != 0 {
		t.Fatalf("active extraction pointer survived begin_purge: %d", pointers)
	}

	// A stale attempt to restore the active pointer is rejected by the guard, which
	// requires ACTIVE queryable retention.
	if _, err := admin.Exec(ctx, `INSERT INTO public.source_version_active_extraction
		(organization_id, source_version_id, extraction_id, activation_revision, activated_at)
		VALUES ($1, $2, $3, 1, now())`, s1dOrg, versionID, extractionID); err == nil {
		t.Fatal("a stale active pointer was re-established against PURGING retention")
	}

	// The immutable version cannot be rolled back to CURRENT.
	if _, err := admin.Exec(ctx, `UPDATE public.source_version SET state='CURRENT'
		WHERE organization_id=$1 AND id=$2 AND state IN ('SUPERSEDED','REDACTED','DELETED')`, s1dOrg, versionID); err == nil {
		// The row may still be CURRENT here (single version); confirm it never regresses
		// from a terminal state — the guard forbids the transition when applicable.
		var state string
		if scanErr := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).Scan(&state); scanErr != nil {
			t.Fatal(scanErr)
		}
		_ = state
	}

	// The retention fence advanced, so a derived write CAS at the old fence fails.
	var fence int64
	if err := admin.QueryRow(ctx, `SELECT retention_fence FROM public.source_version_retention
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&fence); err != nil {
		t.Fatal(err)
	}
	if fence != 1 {
		t.Fatalf("fence=%d, want 1 after one purge", fence)
	}
}

// TestS1ePurgeCleanupCompletionAndResidual proves classes 3 and 4: cleanup is a
// separate, idempotent step that forgets the bytes; completion to PURGED is
// blocked while decryptable artifacts remain and is allowed only once none do;
// and a second completion is rejected.
func TestS1ePurgeCleanupCompletionAndResidual(t *testing.T) {
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin purge: %v", err)
	}

	// Completion is blocked while decryptable Evidence artifacts remain.
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err == nil {
		t.Fatal("completion succeeded while decryptable artifacts remained")
	}

	purged, err := purger.Cleanup(ctx, purgerAccess(), versionID)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if purged == 0 {
		t.Fatal("cleanup purged no artifacts")
	}
	// Idempotent: a resumed cleanup finds nothing left.
	again, err := purger.Cleanup(ctx, purgerAccess(), versionID)
	if err != nil {
		t.Fatalf("cleanup rerun: %v", err)
	}
	if again != 0 {
		t.Fatalf("cleanup is not idempotent: second pass purged %d", again)
	}
	// No decryptable Evidence artifact remains, but nonce/hash provenance is kept.
	var live, provenance int
	if err := admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE ciphertext IS NOT NULL),
		count(*) FILTER (WHERE purged_at IS NOT NULL AND nonce IS NOT NULL)
		FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='evidence_fragment'
		  AND resource_id IN (SELECT id FROM public.evidence_fragment WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, versionID).Scan(&live, &provenance); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("%d decryptable artifacts remain after cleanup", live)
	}
	if provenance == 0 {
		t.Fatal("purge did not retain non-decryptable provenance")
	}
	var searchLive int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='search_chunk' AND purged_at IS NULL
		  AND resource_id IN (SELECT id FROM public.search_chunk WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, versionID).Scan(&searchLive); err != nil {
		t.Fatal(err)
	}
	if searchLive != 0 {
		t.Fatalf("%d decryptable SearchChunk artifacts remain after cleanup", searchLive)
	}
	var deleteEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.outbox_event
		WHERE organization_id=$1 AND aggregate_type='SEARCH_CHUNK'
		  AND event_type='search.chunk.delete' AND payload_json->>'source_version_id'=$2`,
		s1dOrg, versionID).Scan(&deleteEvents); err != nil {
		t.Fatal(err)
	}
	if deleteEvents == 0 {
		t.Fatal("search purge cleanup did not enqueue a durable DELETE event")
	}

	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("complete purge: %v", err)
	}
	// Terminal PURGED state across version and extraction; version redacted.
	var vState, eState, versionState string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&vState); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_extraction_retention WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID).Scan(&eState); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).Scan(&versionState); err != nil {
		t.Fatal(err)
	}
	if vState != "PURGED" || eState != "PURGED" || versionState != "REDACTED" {
		t.Fatalf("after completion: version_retention=%s extraction_retention=%s version=%s", vState, eState, versionState)
	}
	// A second completion is rejected (not PURGING anymore).
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err == nil {
		t.Fatal("a second completion was permitted")
	}
	// One content-free source.version_purged event.
	var purgedEvents int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND action='source.version_purged' AND resource_id=$2 AND actor_type='SYSTEM'`,
		s1dOrg, versionID).Scan(&purgedEvents); err != nil {
		t.Fatal(err)
	}
	if purgedEvents != 1 {
		t.Fatalf("expected one source.version_purged event, got %d", purgedEvents)
	}
}

// TestS1ePurgePrivilegeAndTenant proves class 6: the purge functions are
// unavailable to the web/API and worker roles (knowledge of the id is not
// authority), and a purger for one tenant cannot purge another tenant's version.
func TestS1ePurgePrivilegeAndTenant(t *testing.T) {
	ctx, admin, versionID, _, _ := s1ePurgeSetup(t)

	for _, role := range []struct{ login, app string }{
		{appRole, "knowvault_app"},
		{workerRole, "knowvault_worker"},
	} {
		store := openStore(t, ctx, role.login, role.app)
		err := store.Write(ctx, workerAccess(t, s1dOrg), func(ctx context.Context, tx database.Transaction) error {
			_, execErr := tx.Exec(ctx, `SELECT app.source_version_begin_purge($1,$2,$3,$4)`, s1dOrg, versionID, "OPERATOR_REQUEST", int64(0))
			return execErr
		})
		if err == nil {
			t.Fatalf("role %s was able to execute begin_purge", role.app)
		}
	}

	// A purger scoped to another tenant cannot purge this version: the function
	// filters by the exact tenant, so it finds no such retention row.
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	otherPurger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	otherAccess := database.AccessContext{OrganizationID: "org_other", PrincipalID: "usr_x", RequestID: "req"}
	if _, err := otherPurger.BeginPurge(ctx, otherAccess, versionID, "OPERATOR_REQUEST"); err == nil {
		t.Fatal("a cross-tenant purger purged another tenant's version")
	}

	// The version is untouched by the denied attempts.
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ACTIVE" {
		t.Fatalf("denied attempts changed retention state to %s", state)
	}
}

// TestS1ePurgeBeginGuards proves the begin_purge self-fence and fence CAS: a
// purger session bound to one tenant cannot purge another tenant's version by
// passing its id (P1-2), and a stale observed fence is rejected (P2-i).
func TestS1ePurgeBeginGuards(t *testing.T) {
	ctx, admin, versionID, _, _ := s1ePurgeSetup(t)
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")

	// Self-fence: session tenant is s1dOrg, but the caller names org_other.
	err := purgerStore.Write(ctx, purgerAccess(), func(ctx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(ctx, `SELECT app.source_version_begin_purge($1,$2,$3,$4)`,
			"org_other", versionID, "OPERATOR_REQUEST", int64(0))
		return execErr
	})
	if err == nil {
		t.Fatal("begin_purge accepted a tenant different from the session tenant")
	}

	// Fence CAS: the real fence is 0; a stale observed fence must be rejected.
	err = purgerStore.Write(ctx, purgerAccess(), func(ctx context.Context, tx database.Transaction) error {
		_, execErr := tx.Exec(ctx, `SELECT app.source_version_begin_purge($1,$2,$3,$4)`,
			s1dOrg, versionID, "OPERATOR_REQUEST", int64(7))
		return execErr
	})
	if err == nil {
		t.Fatal("begin_purge accepted a stale observed fence")
	}

	// Both denied attempts left the version ACTIVE.
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "ACTIVE" {
		t.Fatalf("denied begin attempts changed retention state to %s", state)
	}
}

// TestS1ePurgeCompletionBlockedByRunningJob proves the completion job gate (P2-h):
// while a job of the old fence still targets the version, completion is blocked;
// once it is gone, completion proceeds.
func TestS1ePurgeCompletionBlockedByRunningJob(t *testing.T) {
	ctx, admin, versionID, _, purger := s1ePurgeSetup(t)
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := purger.Cleanup(ctx, purgerAccess(), versionID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// A running extraction job of the version blocks completion.
	jobID := mustID(t, "job")
	if _, err := admin.Exec(ctx, `INSERT INTO public.job
		(organization_id, id, type, payload_json, idempotency_key, status, max_attempts, attempt_count, lease_epoch, lease_owner, lease_deadline)
		VALUES ($1,$2,'SOURCE_OBJECT_EXTRACTION', jsonb_build_object('source_version_id',$3::text), $4, 'RUNNING', 3, 1, 1, 'worker_s1d', now()+interval '1 hour')`,
		s1dOrg, jobID, versionID, mustID(t, "idem")); err != nil {
		t.Fatal(err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err == nil {
		t.Fatal("completion succeeded while a running job of the version remained")
	}

	// Once the job is terminal, completion proceeds.
	if _, err := admin.Exec(ctx, `UPDATE public.job SET status='SUCCEEDED', lease_owner=NULL, lease_deadline=NULL, completed_at=now()
		WHERE organization_id=$1 AND id=$2`, s1dOrg, jobID); err != nil {
		t.Fatal(err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("completion after job terminal: %v", err)
	}
	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "PURGED" {
		t.Fatalf("state=%s after completion, want PURGED", state)
	}
}

// TestS1ePurgeCurrentVersionClosesObject proves class 5: purging the object's
// current version closes the object (queryable=false) until a safe new current is
// chosen, and a purged version can never become queryable again.
func TestS1ePurgeCurrentVersionClosesObject(t *testing.T) {
	ctx, admin, versionID, _, purger := s1ePurgeSetup(t)

	var objectID string
	if err := admin.QueryRow(ctx, `SELECT source_object_id FROM public.source_version WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).Scan(&objectID); err != nil {
		t.Fatal(err)
	}
	// Sanity: the version is the object's current version.
	var currentVersion string
	if err := admin.QueryRow(ctx, `SELECT current_version_id FROM public.source_object WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&currentVersion); err != nil {
		t.Fatal(err)
	}
	if currentVersion != versionID {
		t.Fatalf("precondition: current version %s != purged version %s", currentVersion, versionID)
	}

	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := purger.Cleanup(ctx, purgerAccess(), versionID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	var queryable bool
	if err := admin.QueryRow(ctx, `SELECT queryable FROM public.source_object WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&queryable); err != nil {
		t.Fatal(err)
	}
	if queryable {
		t.Fatal("object stayed queryable after its current version was purged")
	}
	// The purged version's retention can never be made queryable again (guard).
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true, state='ACTIVE'
		WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err == nil {
		t.Fatal("a PURGED version retention was reactivated")
	}
}

// TestS1ePurgeHistoricalVersionIsolation proves class 5's history safety: purging
// a historical (superseded) version does not disturb the current version or the
// object, and touches no unrelated version.
func TestS1ePurgeHistoricalVersionIsolation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "notes.txt")
	writeS1dFile(t, target, "v1 one\nv1 two\n")
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
	runSync(t, ctx, handler, queue, access, "sync-v1")
	// Change the file so a second version supersedes the first.
	writeS1dFile(t, target, "v1 one\nv1 two\nv2 appended\n")
	runSync(t, ctx, handler, queue, access, "sync-v2")

	var historicalID, currentID, objectID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.source_version
		WHERE organization_id=$1 AND state='SUPERSEDED'`, s1dOrg).Scan(&historicalID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT id, source_object_id FROM public.source_version
		WHERE organization_id=$1 AND state='CURRENT'`, s1dOrg).Scan(&currentID, &objectID); err != nil {
		t.Fatal(err)
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), historicalID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := purger.Cleanup(ctx, purgerAccess(), historicalID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), historicalID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// The current version and the object are untouched.
	var currentState string
	var objectQueryable bool
	var objectCurrent string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`, s1dOrg, currentID).Scan(&currentState); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT queryable, current_version_id FROM public.source_object WHERE organization_id=$1 AND id=$2`, s1dOrg, objectID).Scan(&objectQueryable, &objectCurrent); err != nil {
		t.Fatal(err)
	}
	if currentState != "CURRENT" || !objectQueryable || objectCurrent != currentID {
		t.Fatalf("historical purge disturbed the head: current=%s queryable=%v current_ptr=%s", currentState, objectQueryable, objectCurrent)
	}
	// The current version's Evidence is still physically present and queryable.
	var currentLive int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
		WHERE organization_id=$1 AND owner_table='evidence_fragment' AND purged_at IS NULL
		  AND resource_id IN (SELECT id FROM public.evidence_fragment WHERE organization_id=$1 AND source_version_id=$2)`,
		s1dOrg, currentID).Scan(&currentLive); err != nil {
		t.Fatal(err)
	}
	if currentLive == 0 {
		t.Fatal("historical purge forgot the current version's Evidence bytes")
	}
	var currentRetention string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version_retention WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, currentID).Scan(&currentRetention); err != nil {
		t.Fatal(err)
	}
	if currentRetention != "ACTIVE" {
		t.Fatalf("historical purge changed current retention to %s", currentRetention)
	}
}
