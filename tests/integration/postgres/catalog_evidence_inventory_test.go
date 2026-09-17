package postgres_test

// KV-A02 inventory correctness and denial journalling, against real PostgreSQL.
//
// The workspace object inventory (Viewer.ListObjects, behind the
// knowvault_workspace_list MCP tool) must return exactly one row per
// (source_object_id, source_version_id) even when the same object is reachable
// through two enabled overlapping scopes, must page with a stable cursor and no
// duplicate or omitted row, must only present a version the evidence read gate
// app.evidence_fragment_readable would allow (WORKSPACE_MANAGED access mode, a
// live unrevoked confirmation and a queryable version retention), and must
// journal an unknown/foreign workspace denial with a NULL workspace so the
// denial is recorded without failing the workspace foreign key.

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
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// inventoryUnknownWorkspace is a workspace id that exists for no tenant; the
// denial for it must be journalled with a NULL workspace.
const inventoryUnknownWorkspace = "ws_inventory_unknown"

func inventoryRowKey(item evidence.ObjectInventoryItem) string {
	return item.SourceObjectID + "|" + item.SourceVersionID
}

func TestKVWorkspaceInventoryListObjects(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "alpha first line\nalpha second line\n")
	writeS1dFile(t, filepath.Join(dir, "other.txt"), "other first line\nother second line\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check needs a live confirmation on the first
	// scope; the overlapping second scope gets its own through the seed helper.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	scope2, _ := seedS1dSecondScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, scope2, 1,
		"binding_02ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d2_admin", "confirmation_s1d2_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	worker := workerAccess(t, s1dOrg)

	runSyncScope(t, ctx, handler, queue, worker, s1dScopeID, "inventory-scope1")
	runSyncScope(t, ctx, handler, queue, worker, scope2, "inventory-scope2")

	// Precondition for the deduplication proof: both objects are reachable
	// through two ACTIVE scope memberships, so a plain join would multiply rows.
	var sharedObjects int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT source_object_id
		FROM public.source_object_scope
		WHERE organization_id=$1 AND membership_state='ACTIVE'
		GROUP BY source_object_id
		HAVING count(DISTINCT source_scope_id) >= 2
	) shared`, s1dOrg).Scan(&sharedObjects); err != nil {
		t.Fatal(err)
	}
	if sharedObjects != 2 {
		t.Fatalf("objects reachable through two scopes = %d, want 2", sharedObjects)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_inventory"}

	t.Run("member current-only inventory is one row per object version", func(t *testing.T) {
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatalf("member current-only inventory: %v", err)
		}
		if len(page.Items) != 2 {
			t.Fatalf("current-only inventory rows = %d, want 2 (one per object)", len(page.Items))
		}
		if page.HasMore {
			t.Fatal("complete current-only inventory reported HasMore")
		}
		seen := map[string]bool{}
		for _, item := range page.Items {
			key := inventoryRowKey(item)
			if seen[key] {
				t.Fatalf("duplicate inventory row %s despite two overlapping scopes", key)
			}
			seen[key] = true
			if !item.Current || item.VersionState != "CURRENT" {
				t.Fatalf("current-only row %s is not CURRENT: %+v", key, item)
			}
			if item.FragmentCount < 1 || item.FirstFragmentID == "" {
				t.Fatalf("current-only row %s has no readable fragment span: %+v", key, item)
			}
		}
	})

	t.Run("paging reassembles the inventory with no duplicate and no omission", func(t *testing.T) {
		assembled := map[string]bool{}
		offset := int64(0)
		for pages := 0; ; pages++ {
			if pages > 10 {
				t.Fatal("inventory paging did not terminate")
			}
			page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, true, offset, 1)
			if err != nil {
				t.Fatalf("page at offset %d: %v", offset, err)
			}
			for _, item := range page.Items {
				key := inventoryRowKey(item)
				if assembled[key] {
					t.Fatalf("duplicate row %s across pages", key)
				}
				assembled[key] = true
			}
			if !page.HasMore {
				break
			}
			if page.NextOffset <= offset {
				t.Fatalf("stable cursor did not advance: offset=%d next_offset=%d", offset, page.NextOffset)
			}
			offset = page.NextOffset
		}
		if len(assembled) != 2 {
			t.Fatalf("reassembled rows = %d, want 2", len(assembled))
		}
	})

	t.Run("re-extraction inventory selects only the active extraction", func(t *testing.T) {
		before, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		previous := map[string]evidence.ObjectInventoryItem{}
		for _, item := range before.Items {
			previous[inventoryRowKey(item)] = item
		}
		// Unchanged source bytes, a new extraction profile and retained old
		// fragments reproduce the native PDF failure without fixture SQL writes.
		reparse := handler.WithParserRevision("inventory-reparse-v2")
		runSyncScope(t, ctx, reparse, queue, worker, s1dScopeID, "inventory-reparse")
		for _, allVersions := range []bool{false, true} {
			after, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, allVersions, 0, 100)
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Items) != len(previous) {
				t.Fatal("re-extraction changed object/version inventory")
			}
			for _, item := range after.Items {
				old, exists := previous[inventoryRowKey(item)]
				if !exists || item.FragmentCount != old.FragmentCount || item.FirstFragmentID == old.FirstFragmentID {
					t.Fatalf("inventory mixed active and retained fragments: before=%+v after=%+v", old, item)
				}
				whole, err := viewer.ReadObject(ctx, viewerAccess, s1dWorkspace, item.FirstFragmentID)
				if err != nil || whole.FragmentCount != item.FragmentCount {
					t.Fatalf("inventory does not describe its readable active extraction: count=%d read=%d err=%v", item.FragmentCount, whole.FragmentCount, err)
				}
			}
		}
	})

	// A changed file creates a second version of one object through the real
	// sync path, so all_versions has something to add to the current-only set.
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "alpha first line\nalpha second line modified\n")
	runSyncScope(t, ctx, handler, queue, worker, s1dScopeID, "inventory-scope1-resync")

	t.Run("all_versions inventory includes the superseded version once", func(t *testing.T) {
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, true, 0, 100)
		if err != nil {
			t.Fatalf("all_versions inventory: %v", err)
		}
		if len(page.Items) != 3 {
			t.Fatalf("all_versions rows = %d, want 3 (two objects, one with two versions)", len(page.Items))
		}
		current, superseded := 0, 0
		seen := map[string]bool{}
		for _, item := range page.Items {
			key := inventoryRowKey(item)
			if seen[key] {
				t.Fatalf("duplicate all_versions row %s", key)
			}
			seen[key] = true
			if item.Current {
				current++
			} else {
				superseded++
			}
		}
		if current != 2 || superseded != 1 {
			t.Fatalf("all_versions current=%d superseded=%d, want 2/1", current, superseded)
		}
	})

	t.Run("non-queryable retention is not presented and the read refuses", func(t *testing.T) {
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Items) != 2 {
			t.Fatalf("baseline current-only rows = %d, want 2", len(page.Items))
		}
		victim := page.Items[0]
		if victim.FirstFragmentID == "" {
			t.Fatal("victim row carries no fragment id to read")
		}
		if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=false
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, victim.SourceVersionID); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true
				WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, victim.SourceVersionID); err != nil {
				t.Errorf("restore retention: %v", err)
			}
		}()

		after, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		if len(after.Items) != 1 {
			t.Fatalf("current-only rows after dequeryable = %d, want 1", len(after.Items))
		}
		for _, item := range after.Items {
			if item.SourceVersionID == victim.SourceVersionID {
				t.Fatalf("non-queryable version %s presented as readable", item.SourceVersionID)
			}
		}
		if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, victim.FirstFragmentID); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("read of a non-queryable version = %v, want ErrNotFound", err)
		}
	})

	t.Run("unknown workspace denial is journalled with a NULL workspace", func(t *testing.T) {
		page, err := viewer.ListObjects(ctx, viewerAccess, inventoryUnknownWorkspace, false, 0, 100)
		if !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("unknown workspace inventory = %v, want ErrNotFound", err)
		}
		if len(page.Items) != 0 || page.HasMore || page.NextOffset != 0 {
			t.Fatalf("unknown workspace denial leaked a page: %+v", page)
		}
		var denied int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='evidence.read.admitted' AND outcome='DENIED'
			  AND error_code='WORKSPACE_OBJECTS_DENIED' AND workspace_id IS NULL
			  AND resource_id=$2`, s1dOrg, inventoryUnknownWorkspace).Scan(&denied); err != nil {
			t.Fatal(err)
		}
		if denied != 1 {
			t.Fatalf("journalled unknown-workspace denials = %d, want 1", denied)
		}
	})
}

// ensureSourceObjectSkipSchema makes the KV-A02 typed skip ledger available to
// a test database built from the suite's hardcoded migration sequence. When the
// additive migration 000095 is already part of that sequence this is a no-op.
func ensureSourceObjectSkipSchema(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	var present bool
	if err := admin.QueryRow(ctx, `SELECT to_regclass('public.source_object_skip') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		return
	}
	migration, err := readMigrationFile(t, "000095_stage3_source_object_skip.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, migration); err != nil {
		t.Fatalf("apply 000095 source object skip migration: %v", err)
	}
}

// TestKVWorkspaceInventoryTypedSkips proves the KV-A02 skip ledger end to end
// against real PostgreSQL: a discoverable oversized object (a connector
// quarantine code) and an object the extraction phase skips for an unsupported
// format both get exactly one typed row under the run, the numeric
// sync_run.quarantined counter still matches that row count, and the authorized
// inventory returns the typed skips alongside the readable rows.
func TestKVWorkspaceInventoryTypedSkips(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	ensureSourceObjectSkipSchema(t, ctx, admin)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "alpha readable line\n")
	// Larger than the seeded scope's max_file_bytes (1048576): the connector
	// quarantines it during discovery with FOLDER_OBJECT_OVERSIZED.
	if err := os.WriteFile(filepath.Join(dir, "oversized.txt"), []byte(strings.Repeat("a", 1100000)), 0o644); err != nil {
		t.Fatal(err)
	}
	// A .docx whose bytes are plain text passes the connector's text family
	// gate but cannot be extracted as an OOXML package, so it is an
	// extraction-phase skip that carries no connector code of its own.
	writeS1dFile(t, filepath.Join(dir, "broken.docx"), "not an ooxml package\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	worker := workerAccess(t, s1dOrg)
	runSyncScope(t, ctx, handler, queue, worker, s1dScopeID, "inventory-skips")

	var runID string
	var quarantined, ingested int
	if err := admin.QueryRow(ctx, `SELECT id, quarantined, objects_ingested FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY started_at DESC, id DESC LIMIT 1`,
		s1dOrg, s1dScopeID).Scan(&runID, &quarantined, &ingested); err != nil {
		t.Fatal(err)
	}
	if ingested != 1 {
		t.Fatalf("objects_ingested=%d, want 1", ingested)
	}

	type storedSkip struct {
		digest     string
		keyVersion int64
		artifactID string
		reason     string
		moment     time.Time
	}
	rows, err := admin.Query(ctx, `SELECT external_id_digest, digest_key_version, external_id_artifact_id, reason_code, observed_at
		FROM public.source_object_skip
		WHERE organization_id=$1 AND sync_run_id=$2 ORDER BY external_id_digest`, s1dOrg, runID)
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]storedSkip{}
	for rows.Next() {
		var digest, artifactID, reason string
		var keyVersion int64
		var moment time.Time
		if err := rows.Scan(&digest, &keyVersion, &artifactID, &reason, &moment); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		switch digest {
		case canon.HMACDigest(s1dDigestKey, 1, []byte("projects/alpha/oversized.txt")):
			stored["oversized.txt"] = storedSkip{digest: digest, keyVersion: keyVersion, artifactID: artifactID, reason: reason, moment: moment}
		case canon.HMACDigest(s1dDigestKey, 1, []byte("projects/alpha/broken.docx")):
			stored["broken.docx"] = storedSkip{digest: digest, keyVersion: keyVersion, artifactID: artifactID, reason: reason, moment: moment}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(stored) != 2 {
		t.Fatalf("typed skip rows=%d, want 2 (%v)", len(stored), stored)
	}
	if stored["oversized.txt"].reason != "FOLDER_OBJECT_OVERSIZED" {
		t.Fatalf("oversized skip reason=%q", stored["oversized.txt"].reason)
	}
	if stored["broken.docx"].reason != "INGEST_EXTRACTION_SKIPPED" {
		t.Fatalf("extraction skip reason=%q", stored["broken.docx"].reason)
	}
	if stored["oversized.txt"].keyVersion != 1 || stored["oversized.txt"].artifactID == "" {
		t.Fatalf("oversized skip identity is not keyed/sealed: %+v", stored["oversized.txt"])
	}
	// The raw native identity must no longer be a column of the ledger: the
	// value that used to sit in external_id is now an org-keyed digest plus an
	// encrypted artifact, so a bare table read leaks no path or mail id.
	var rawColumns int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema='public' AND table_name='source_object_skip' AND column_name='external_id'`).Scan(&rawColumns); err != nil {
		t.Fatal(err)
	}
	if rawColumns != 0 {
		t.Fatalf("source_object_skip still exposes a raw external_id column")
	}
	if quarantined != 2 {
		t.Fatalf("sync_run.quarantined=%d, want 2 (matches the typed row count)", quarantined)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_inventory_skips"}
	page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
	if err != nil {
		t.Fatalf("member inventory with typed skips: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("readable rows=%d, want 1", len(page.Items))
	}
	if page.HasMore || page.NextOffset != 0 {
		t.Fatalf("complete inventory reported a cursor: has_more=%v next_offset=%d", page.HasMore, page.NextOffset)
	}
	if len(page.Skipped) != 2 {
		t.Fatalf("typed skips=%d, want 2 (%+v)", len(page.Skipped), page.Skipped)
	}
	seen := map[string]string{}
	for _, skip := range page.Skipped {
		if skip.ExternalID == "" || skip.ReasonCode == "" || skip.ObservedAt.IsZero() {
			t.Fatalf("incomplete skip projection: %+v", skip)
		}
		seen[skip.ExternalID] = skip.ReasonCode
	}
	if seen["projects/alpha/oversized.txt"] != "FOLDER_OBJECT_OVERSIZED" || seen["projects/alpha/broken.docx"] != "INGEST_EXTRACTION_SKIPPED" {
		t.Fatalf("typed skip projection=%v", seen)
	}

	// KV-A02b negative control: a ledger row whose stored digest no longer
	// matches the sealed identity is withheld fail closed. The digest is
	// rewritten to another valid, org-keyed digest; the artifact and the row
	// stay in place, so only the read-path consistency check can hide it.
	t.Run("tampered skip digest is withheld fail closed", func(t *testing.T) {
		original := stored["broken.docx"].digest
		tampered := canon.HMACDigest(s1dDigestKey, 1, []byte("tampered"))
		if _, err := admin.Exec(ctx, `UPDATE public.source_object_skip SET external_id_digest=$1
			WHERE organization_id=$2 AND sync_run_id=$3 AND external_id_digest=$4`,
			tampered, s1dOrg, runID, original); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE public.source_object_skip SET external_id_digest=$1
				WHERE organization_id=$2 AND sync_run_id=$3 AND external_id_digest=$4`,
				original, s1dOrg, runID, tampered); err != nil {
				t.Fatal(err)
			}
		}()
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatalf("inventory after digest tamper: %v", err)
		}
		if len(page.Skipped) != 1 || page.Skipped[0].ExternalID != "projects/alpha/oversized.txt" {
			t.Fatalf("tampered skip not withheld: %+v", page.Skipped)
		}
	})

	// Fail-closed parity controls: the typed skips must be withheld under the
	// same authority collapse that withholds the readable object rows, and never
	// leak an external id, reason code or moment. The scope_config_hash equality
	// clause is structurally guaranteed here: workspace_revision_source and
	// workspace_managed_grant_confirmation both carry a composite foreign key to
	// the same (organization_id, source_scope_id, revision)-keyed
	// source_scope_revision row, so one scope revision resolves exactly one hash
	// and the two can never disagree for the tuple the skip rows name. The
	// reachable perturbations are therefore a stale workspace revision (the wrs
	// row no longer belongs to the workspace's CURRENT revision) and a revoked
	// authority: both must empty Items and Skipped together.
	authorityStore := newAuthorityRuntime(t, ctx)
	var confirmationID, confirmationHash, grantID, grantHash string
	var grantRevision int64
	if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash, confirmation_actor_grant_id
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_source_id=$2`, s1dOrg, fixture.workspaceSourceID).
		Scan(&confirmationID, &confirmationHash, &grantID); err != nil {
		t.Fatalf("resolve seeded confirmation: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT revision, grant_hash FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id=$1 AND grant_id=$2`, s1dOrg, grantID).
		Scan(&grantRevision, &grantHash); err != nil {
		t.Fatalf("resolve seeded actor grant: %v", err)
	}
	assertFailsClosed := func(t *testing.T, label string) {
		t.Helper()
		hidden, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatalf("%s: inventory error: %v", label, err)
		}
		if len(hidden.Items) != 0 {
			t.Fatalf("%s disclosed %d readable object rows", label, len(hidden.Items))
		}
		if len(hidden.Skipped) != 0 {
			t.Fatalf("%s disclosed %d typed skips: %+v", label, len(hidden.Skipped), hidden.Skipped)
		}
		if hidden.HasMore || hidden.NextOffset != 0 {
			t.Fatalf("%s reported a cursor over an empty page: has_more=%v next_offset=%d", label, hidden.HasMore, hidden.NextOffset)
		}
	}

	t.Run("stale workspace revision hides typed skips and objects alike", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.workspace SET current_revision=2 WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE public.workspace SET current_revision=1 WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dWorkspace); err != nil {
				t.Fatal(err)
			}
		}()
		assertFailsClosed(t, "stale workspace revision")
	})

	t.Run("revoked confirmation actor grant hides typed skips and objects alike", func(t *testing.T) {
		if _, err := authorityStore.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_inventory_skip_grant_revoke"),
			workspacerepository.RevokeGrantRequest{
				IdempotencyKey:         authorityIdempotencyKey("inventory-skip-grant-revoke"),
				OrganizationID:         s1dOrg,
				WorkspaceID:            s1dWorkspace,
				GrantID:                grantID,
				GrantRevision:          grantRevision,
				GrantHash:              grantHash,
				ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("revoke confirmation actor grant: %v", err)
		}
		assertFailsClosed(t, "revoked actor grant")
	})

	t.Run("revoked confirmation hides typed skips and objects alike", func(t *testing.T) {
		if _, err := authorityStore.RevokeManagedConfirmation(ctx, authorityAccess(fixture, fixture.ownerID, "req_inventory_skip_confirm_revoke"),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey:         authorityIdempotencyKey("inventory-skip-confirm-revoke"),
				OrganizationID:         s1dOrg,
				WorkspaceID:            s1dWorkspace,
				ConfirmationID:         confirmationID,
				ConfirmationHash:       confirmationHash,
				ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("revoke confirmation: %v", err)
		}
		assertFailsClosed(t, "revoked confirmation")
	})

	t.Run("foreign workspace denial stays content-free", func(t *testing.T) {
		deniedPage, err := viewer.ListObjects(ctx, viewerAccess, inventoryUnknownWorkspace, false, 0, 100)
		if !errors.Is(err, evidence.ErrNotFound) {
			t.Fatalf("unknown workspace inventory = %v, want ErrNotFound", err)
		}
		if len(deniedPage.Items) != 0 || len(deniedPage.Skipped) != 0 || deniedPage.HasMore {
			t.Fatalf("unknown workspace denial leaked a page: %+v", deniedPage)
		}
	})
}

// TestKVWorkspaceInventoryNonFolderTypedReason drives a GIT_FILE object whose
// format determination is not admitted through the production ingestion skip
// path against real PostgreSQL. It is the r6-finding control: the ledger row and
// the knowvault_list_objects projection (MCP structuredContent and the REST
// list-objects parity route) carry the git source kind's own closed code
// GIT_UNSUPPORTED_MEDIA_TYPE and never FOLDER_UNSUPPORTED_TYPE, while a
// source-neutral extraction skip keeps its existing code (proved by
// TestKVWorkspaceInventoryTypedSkips's broken.docx -> INGEST_EXTRACTION_SKIPPED).
func TestKVWorkspaceInventoryNonFolderTypedReason(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	ensureSourceObjectSkipSchema(t, ctx, admin)
	codec := s1dCodec(t, s1dOrg)

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedKVA04GitScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		kvA04GitScopeID, configHash, 1, "binding_kva02git", "grant_kva02git", "confirmation_kva02git")

	// A GIT_FILE path with no admitted extension: the GIT adapter only admits
	// TXT, so the pipeline's format-determination branch quarantines the object
	// and carries the git source's own code.
	const nonFolderPath = "src/module"
	object := kvA04GitObject(nonFolderPath, []byte("opaque bytes\n"),
		"native:commit:"+strings.Repeat("c", 40)+";blob:"+strings.Repeat("3", 40))
	resolver := &kvA04GitResolver{}
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: t.TempDir()}, s1dWorkerID, time.Now, ids.New).
		WithObservationAdapterResolver(resolver)
	resolver.selectAdapter(kvA04GitAdapter{object: object})
	runSyncScope(t, ctx, handler, queue, workerAccess(t, s1dOrg), kvA04GitScopeID, "kva02-nonfolder-format")

	var runID, runStatus string
	var quarantined, ingested int
	if err := admin.QueryRow(ctx, `SELECT id, status, quarantined, objects_ingested FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY started_at DESC, id DESC LIMIT 1`,
		s1dOrg, kvA04GitScopeID).Scan(&runID, &runStatus, &quarantined, &ingested); err != nil {
		t.Fatal(err)
	}
	if runStatus != "SUCCEEDED" {
		t.Fatalf("sync run status=%q want SUCCEEDED", runStatus)
	}
	if ingested != 0 || quarantined != 1 {
		t.Fatalf("run counters ingested=%d quarantined=%d, want 0/1", ingested, quarantined)
	}

	// The persisted ledger row must carry the git source kind's own code, keyed
	// by the org-scoped digest of the object's native id, and never collapse to
	// the folder-specific code.
	var ledgerReason string
	if err := admin.QueryRow(ctx, `SELECT reason_code FROM public.source_object_skip
		WHERE organization_id=$1 AND sync_run_id=$2 AND external_id_digest=$3`,
		s1dOrg, runID, canon.HMACDigest(s1dDigestKey, 1, []byte(nonFolderPath))).Scan(&ledgerReason); err != nil {
		t.Fatalf("resolve non-folder ledger row: %v", err)
	}
	if ledgerReason != "GIT_UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf("git ledger reason=%q want GIT_UNSUPPORTED_MEDIA_TYPE", ledgerReason)
	}
	if ledgerReason == "FOLDER_UNSUPPORTED_TYPE" {
		t.Fatal("git ledger reason collapsed to the folder-specific code")
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_kva02_nonfolder"}
	page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
	if err != nil {
		t.Fatalf("member inventory with a non-folder skip: %v", err)
	}
	if len(page.Items) != 0 {
		t.Fatalf("readable rows=%d, want 0", len(page.Items))
	}
	if len(page.Skipped) != 1 {
		t.Fatalf("typed skips=%d, want 1 (%+v)", len(page.Skipped), page.Skipped)
	}
	if page.Skipped[0].ExternalID != nonFolderPath {
		t.Fatalf("viewer skip external_id=%q want %q", page.Skipped[0].ExternalID, nonFolderPath)
	}
	if page.Skipped[0].ReasonCode != "GIT_UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf("viewer skip reason=%q want GIT_UNSUPPORTED_MEDIA_TYPE", page.Skipped[0].ReasonCode)
	}

	mcpHandler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, newAuthorityRuntime(t, ctx))

	mcpBody, mcpProjection := r3a1MCPListObjects(t, mcpHandler, token, csrf, "kva02-list-nonfolder")
	if mcpProjection.SkippedCount != 1 || len(mcpProjection.Skipped) != 1 {
		t.Fatalf("MCP list-objects skips=%d/%d want 1 body=%s", mcpProjection.SkippedCount, len(mcpProjection.Skipped), mcpBody)
	}
	if mcpProjection.Skipped[0].ExternalID != nonFolderPath {
		t.Fatalf("MCP skip external_id=%q want %q body=%s", mcpProjection.Skipped[0].ExternalID, nonFolderPath, mcpBody)
	}
	if mcpProjection.Skipped[0].ReasonCode != "GIT_UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf("MCP skip reason=%q want GIT_UNSUPPORTED_MEDIA_TYPE body=%s", mcpProjection.Skipped[0].ReasonCode, mcpBody)
	}

	restBody, restProjection := r3a1RESTListObjects(t, mcpHandler, token)
	if restProjection.SkippedCount != 1 || len(restProjection.Skipped) != 1 {
		t.Fatalf("REST list-objects skips=%d/%d want 1 body=%s", restProjection.SkippedCount, len(restProjection.Skipped), restBody)
	}
	if restProjection.Skipped[0].ExternalID != nonFolderPath {
		t.Fatalf("REST skip external_id=%q want %q body=%s", restProjection.Skipped[0].ExternalID, nonFolderPath, restBody)
	}
	if restProjection.Skipped[0].ReasonCode != "GIT_UNSUPPORTED_MEDIA_TYPE" {
		t.Fatalf("REST skip reason=%q want GIT_UNSUPPORTED_MEDIA_TYPE body=%s", restProjection.Skipped[0].ReasonCode, restBody)
	}
}
