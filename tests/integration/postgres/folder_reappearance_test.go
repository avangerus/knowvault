package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// TestFolderReappearanceAfterAuthoritativeAbsence restores the same path and
// bytes after a completed, non-empty scan proved the file absent. This differs
// from A->B->A content reobservation: source membership was closed in between.
// The assertion deliberately uses the authorized inventory/read path, so a
// successful sync that leaves the restored file invisible does not pass.
func TestFolderReappearanceAfterAuthoritativeAbsence(t *testing.T) {
	const original = "reappearing document with unchanged bytes\n"
	f := newExactEvidenceFixture(t, original)
	access := workerAccess(t, s1dOrg)
	current := func() (evidence.ObjectInventoryItem, bool) {
		t.Helper()
		page, err := f.viewer.ListObjects(f.ctx, f.access, s1dWorkspace, false, 0, 100)
		if err != nil || page.HasMore {
			t.Fatalf("current inventory: err=%v has_more=%v", err, page.HasMore)
		}
		var found evidence.ObjectInventoryItem
		for _, item := range page.Items {
			if item.ExternalID != exactEvidencePath {
				continue
			}
			if found.FirstFragmentID != "" {
				t.Fatal("restored path has more than one current readable object")
			}
			found = item
		}
		t.Logf("authorized inventory: total=%d target_present=%v", len(page.Items), found.FirstFragmentID != "")
		return found, found.FirstFragmentID != ""
	}
	before, ok := current()
	if !ok {
		t.Fatal("initial file is absent from authorized inventory")
	}
	initial, err := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, before.FirstFragmentID)
	if err != nil || string(initial.Text) != original {
		t.Fatalf("initial read: text=%q err=%v", initial.Text, err)
	}

	// Keep one real file throughout: an empty scan is intentionally held and
	// would not exercise authoritative reconciliation of the missing target.
	writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "sentinel.txt"), "stable sentinel\n")
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-with-sentinel")
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-absent")
	if _, ok := current(); ok {
		t.Fatal("authoritatively absent file is still in current inventory")
	}
	assertCurrentReadDenied(t, f, s1dWorkspace, before.FirstFragmentID, "absent file")
	assertExactReadDenied(t, f, f.access, s1dWorkspace, before.FirstFragmentID, before.SourceVersionID, "missing retained version")
	workerStore := openStore(t, f.ctx, workerRole, "knowvault_worker")
	for _, statement := range []string{
		`UPDATE public.source_object SET lifecycle_state='ACTIVE',queryable=true WHERE organization_id=$1 AND id=$2`,
		`UPDATE public.source_object SET queryable=true WHERE organization_id=$1 AND id=$2`,
		`UPDATE public.source_object_scope SET membership_state='ACTIVE',missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2`,
		`UPDATE public.source_object_scope SET membership_state='MOVED',missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2`,
	} {
		err := workerStore.Write(f.ctx, access, func(ctx context.Context, tx database.Transaction) error {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.source_presence_publication','true',true)`); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, statement, s1dOrg, before.SourceObjectID)
			return err
		})
		if err == nil {
			t.Fatal("worker bypassed fenced publication with a direct UPDATE")
		}
	}
	for _, transitions := range [][2]string{
		{`UPDATE public.source_object_scope SET membership_state='REMOVED',removed_at=now(),missing_at=NULL,missing_sync_run_id=NULL WHERE organization_id=$1 AND source_object_id=$2`, `UPDATE public.source_object_scope SET membership_state='ACTIVE',removed_at=NULL WHERE organization_id=$1 AND source_object_id=$2`},
		{`UPDATE public.source_object SET lifecycle_state='DELETED' WHERE organization_id=$1 AND id=$2`, `UPDATE public.source_object SET lifecycle_state='ACTIVE',queryable=true WHERE organization_id=$1 AND id=$2`},
	} {
		err := workerStore.Write(f.ctx, access, func(ctx context.Context, tx database.Transaction) error {
			for _, statement := range transitions {
				if _, err := tx.Exec(ctx, statement, s1dOrg, before.SourceObjectID); err != nil {
					return err
				}
			}
			return nil
		})
		if err == nil {
			t.Fatal("worker resurrected absence through an intermediate terminal state")
		}
	}

	writeS1dFile(t, f.target, original)
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-restored")
	var syncStatus, lifecycle, membership string
	var queryable bool
	if err := f.admin.QueryRow(f.ctx, `SELECT status FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY started_at DESC, id DESC LIMIT 1`, s1dOrg, s1dScopeID).Scan(&syncStatus); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(f.ctx, `SELECT o.lifecycle_state, o.queryable, m.membership_state
		FROM public.source_object o JOIN public.source_object_scope m
		ON m.organization_id=o.organization_id AND m.source_object_id=o.id
		WHERE o.organization_id=$1 AND o.id=$2 AND m.source_scope_id=$3 AND m.source_scope_revision=1`,
		s1dOrg, before.SourceObjectID, s1dScopeID).Scan(&lifecycle, &queryable, &membership); err != nil {
		t.Fatal(err)
	}
	oldAddress, oldErr := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, before.FirstFragmentID)
	t.Logf("after restoration: sync=%s original_object=%s queryable=%v membership=%s old_address_error=%v old_address_bytes=%d",
		syncStatus, lifecycle, queryable, membership, oldErr, len(oldAddress.Text))
	restored, ok := current()
	if !ok {
		t.Fatal("successful sync permanently hid a restored path with unchanged bytes")
	}
	whole, err := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, restored.FirstFragmentID)
	if err != nil || string(whole.Text) != original || !restored.Current {
		t.Fatalf("restored current read: text=%q current=%v err=%v", whole.Text, restored.Current, err)
	}
	if restored.SourceObjectID != before.SourceObjectID || restored.SourceVersionID != before.SourceVersionID || restored.FirstFragmentID != before.FirstFragmentID {
		t.Fatal("same bytes return failed to preserve the immutable object/version/fragment identity")
	}

	// Reincarnation may allocate a new object/version, but it must leave the
	// old immutable version intact and an ordinary subsequent sync idempotent.
	var oldHash string
	if err := f.admin.QueryRow(f.ctx, `SELECT content_hash FROM public.source_version
		WHERE organization_id=$1 AND id=$2`, s1dOrg, before.SourceVersionID).Scan(&oldHash); err != nil {
		t.Fatal(err)
	}
	if oldHash != before.ContentHash {
		t.Fatal("reappearance changed the retained version's content hash")
	}
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-repeat")
	repeated, ok := current()
	if !ok || repeated.SourceObjectID != restored.SourceObjectID || repeated.SourceVersionID != restored.SourceVersionID || repeated.FirstFragmentID != restored.FirstFragmentID {
		t.Fatal("unchanged repeat lost the restored file or created another incarnation")
	}
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-absent-again")
	assertExactReadDenied(t, f, f.access, s1dWorkspace, before.FirstFragmentID, before.SourceVersionID, "second absence")
	const changed = "reappearing document with changed authoritative bytes\n"
	writeS1dFile(t, f.target, changed)
	runSync(t, f.ctx, f.handler, f.queue, access, "reappearance-changed")
	updated, ok := current()
	if !ok || updated.SourceObjectID != before.SourceObjectID || updated.SourceVersionID == before.SourceVersionID {
		t.Fatal("changed return did not publish a new current version on the same identity")
	}
	newRead, err := f.viewer.ReadObject(f.ctx, f.access, s1dWorkspace, updated.FirstFragmentID)
	if err != nil || string(newRead.Text) != changed {
		t.Fatalf("changed return bytes: %v", err)
	}
	historical, err := f.viewer.ReadObjectExactVersion(f.ctx, f.access, s1dWorkspace, before.FirstFragmentID, before.SourceVersionID)
	if err != nil || string(historical.Text) != original {
		t.Fatalf("changed return damaged old immutable history: %v", err)
	}
	var missingEvents, restoredEvents int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FILTER(WHERE action='source.object_missing'),count(*) FILTER(WHERE action='source.object_restored') FROM public.audit_event WHERE organization_id=$1 AND resource_id=$2`, s1dOrg, before.SourceObjectID).Scan(&missingEvents, &restoredEvents); err != nil {
		t.Fatal(err)
	}
	if missingEvents != 2 || restoredEvents != 2 {
		t.Fatalf("presence audit per transition: missing=%d restored=%d", missingEvents, restoredEvents)
	}
}
