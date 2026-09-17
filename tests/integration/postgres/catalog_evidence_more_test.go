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
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestS1dEvidenceContainmentAndViewer proves that an Evidence artifact cannot be
// stored without its owning row (14) and that the viewer is fail-closed with no
// existence oracle (12).
func TestS1dEvidenceContainmentAndViewer(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "alpha line\nbeta line\n")
	// An empty text file must be quarantined, not fail the whole sync.
	writeS1dFile(t, filepath.Join(dir, "empty.txt"), "")
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
	runSync(t, ctx, handler, queue, access, "sync")
	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no Evidence produced")
	}

	// (C4) The empty file was quarantined: exactly one object (notes.txt) exists,
	// and the sync run reports a quarantined object and SUCCEEDED, not FAILED.
	t.Run("empty file is quarantined not fatal", func(t *testing.T) {
		var objects int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&objects); err != nil {
			t.Fatal(err)
		}
		if objects != 1 {
			t.Fatalf("expected 1 object (empty file quarantined), got %d", objects)
		}
		var status string
		var quarantined int
		if err := admin.QueryRow(ctx, `SELECT status, quarantined FROM public.sync_run
			WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&status, &quarantined); err != nil {
			t.Fatal(err)
		}
		if status != "SUCCEEDED" || quarantined < 1 {
			t.Fatalf("sync status=%s quarantined=%d, want SUCCEEDED with a quarantine", status, quarantined)
		}
	})

	// (14) An Evidence artifact cannot be bound to a non-existent fragment: the
	// bind function's owning-row update finds nothing and fails closed, so a
	// committed orphan is impossible.
	t.Run("evidence artifact requires an owning fragment", func(t *testing.T) {
		orphanFragment := mustID(t, "fragment")
		orphanArtifact := mustID(t, "art")
		err := workerStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
			_, execErr := tx.Exec(ctx, `SELECT app.evidence_fragment_bind_normalized_text($1,$2,$3,$4,
				decode('abababababababababab','hex'), 3, decode(repeat('5c',12),'hex'), decode('7777','hex'),
				$5, 'kms://tenant', 1, $5, $5)`,
				s1dOrg, orphanFragment, orphanArtifact, orphanFragment, "sha256:"+repeat64('a'))
			return execErr
		})
		if err == nil {
			t.Fatal("bound an Evidence artifact to a non-existent fragment")
		}
		var orphan int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
			WHERE organization_id=$1 AND id=$2`, s1dOrg, orphanArtifact).Scan(&orphan); err != nil {
			t.Fatal(err)
		}
		if orphan != 0 {
			t.Fatal("orphan Evidence artifact was committed")
		}
	})

	// (12) The viewer is fail-closed: a principal with no workspace membership or
	// confirmation, and a caller from another tenant, both receive the identical
	// not-found. There is no existence oracle.
	t.Run("viewer fails closed with no oracle", func(t *testing.T) {
		appStore := openStore(t, ctx, appRole, "knowvault_app")
		viewer, err := evidence.NewViewer(appStore, codec)
		if err != nil {
			t.Fatal(err)
		}
		// Authorized-looking tenant but no membership/confirmation for the fragment.
		if _, err := viewer.Read(ctx, workerAccess(t, s1dOrg), "ws_none", fragmentID0(fragments)); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("unauthorized read err=%v, want ErrNotFound", err)
		}
		// Another tenant sees the same not-found.
		otherViewer, err := evidence.NewViewer(appStore, s1dCodec(t, "org_other"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := otherViewer.Read(ctx, database.AccessContext{OrganizationID: "org_other", PrincipalID: "usr_x", RequestID: "req"}, "ws_none", fragmentID0(fragments)); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("cross-tenant read err=%v, want ErrNotFound", err)
		}
	})
}

// fragmentID0 returns a real stored fragment id, so the no-oracle test proves an
// unauthorized read of an existing fragment is indistinguishable from a miss.
func fragmentID0(fragments []fragmentRow) string { return fragments[0].id }

// TestS1dOverlappingScopes proves that the same file discovered through two
// overlapping scopes resolves to one shared SourceObject with two ACTIVE
// memberships (10, VER-004), and that removing one membership leaves the shared
// object intact and queryable (11, VER-005).
func TestS1dOverlappingScopes(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "shared line one\nshared line two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	scope2, _ := seedS1dSecondScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, scope2, 1,
		"binding_02ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d2_admin", "confirmation_s1d2_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)

	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, "scope1")
	runSyncScope(t, ctx, handler, queue, access, scope2, "scope2")

	// (10) One shared object, no duplicate; two ACTIVE memberships.
	var objects, activeMemberships int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&objects); err != nil {
		t.Fatal(err)
	}
	if objects != 1 {
		t.Fatalf("overlapping scopes produced %d objects, want 1", objects)
	}
	var objectID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&objectID); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2 AND membership_state='ACTIVE'`, s1dOrg, objectID).Scan(&activeMemberships); err != nil {
		t.Fatal(err)
	}
	if activeMemberships != 2 {
		t.Fatalf("shared object has %d ACTIVE memberships, want 2", activeMemberships)
	}

	// (11) Removing one membership leaves the shared object and the other
	// membership intact.
	if _, err := admin.Exec(ctx, `UPDATE public.source_object_scope SET membership_state='REMOVED', removed_at=now()
		WHERE organization_id=$1 AND source_object_id=$2 AND source_scope_id=$3`, s1dOrg, objectID, scope2); err != nil {
		t.Fatal(err)
	}
	var survivingObjects, remainingActive int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object
		WHERE organization_id=$1 AND id=$2 AND lifecycle_state='ACTIVE' AND queryable`, s1dOrg, objectID).Scan(&survivingObjects); err != nil {
		t.Fatal(err)
	}
	if survivingObjects != 1 {
		t.Fatal("removing one membership dropped the shared object")
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object_scope
		WHERE organization_id=$1 AND source_object_id=$2 AND membership_state='ACTIVE'`, s1dOrg, objectID).Scan(&remainingActive); err != nil {
		t.Fatal(err)
	}
	if remainingActive != 1 {
		t.Fatalf("expected 1 surviving ACTIVE membership, got %d", remainingActive)
	}
}

func repeat64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
