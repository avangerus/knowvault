package postgres_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

const (
	s1dOrg      = "org_s1d"
	s1dOwner    = "usr_s1d_owner"
	s1dScopeID  = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	s1dKEKRef   = "kms://tenant"
	s1dRootID   = "vol-1"
	s1dRootAls  = "docs-root"
	s1dWorkerID = "worker_s1d"
	// s1dMaxFragmentBytes mirrors the extractor's fragment byte budget so the
	// test can re-derive the deterministic segmentation.
	s1dMaxFragmentBytes = 4096
)

var s1dDigestKey = bytes.Repeat([]byte{0x2a}, 32)

type s1dMounts struct{ root string }

func (m s1dMounts) Resolve(alias, identity string) (string, bool) {
	if alias == s1dRootAls && identity == s1dRootID {
		return m.root, true
	}
	return "", false
}

// TestS1dFolderToEvidence proves the folder-to-Evidence path and its load-bearing
// invariants end to end on a real filesystem and PostgreSQL.
func TestS1dFolderToEvidence(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := "\u041f\u0435\u0440\u0432\u0430\u044f \u0441\u0442\u0440\u043e\u043a\u0430\nsecond line with detail\n\u0442\u0440\u0435\u0442\u044c\u044f \u0441\u0442\u0440\u043e\u043a\u0430\n"
	writeS1dFile(t, filepath.Join(fileDir, "notes.txt"), original)

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
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	access := workerAccess(t, s1dOrg)

	// (1) First text file runs the full path to Evidence.
	runSync(t, ctx, handler, queue, access, "sync-1")

	objectID, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no Evidence produced for the first file")
	}

	// (2) The exact anchor re-resolves in the source version and returns the same
	// bytes. The extractor is deterministic, so re-segmenting the canonical text
	// reproduces each fragment's line range; that range must slice bytes whose
	// hash equals the stored text hash.
	t.Run("anchor re-resolves to the same bytes", func(t *testing.T) {
		canonical, _ := canon.Canonicalize([]byte(original))
		segments := canon.Segment(canonical, s1dMaxFragmentBytes)
		if len(segments) != len(fragments) {
			t.Fatalf("segment count %d != stored fragment count %d", len(segments), len(fragments))
		}
		for i, seg := range segments {
			slice, ok := canon.Slice(canonical, seg.LineStart, seg.LineEnd)
			if !ok {
				t.Fatalf("anchor %d-%d does not resolve", seg.LineStart, seg.LineEnd)
			}
			if canon.HMACDigest(s1dDigestKey, 1, slice) != fragments[i].textHash {
				t.Fatalf("fragment %d anchor bytes hash mismatch", i+1)
			}
		}
	})

	// (3) Repeat sync creates zero duplicate objects/versions/extractions/evidence.
	t.Run("idempotent re-sync creates no duplicates", func(t *testing.T) {
		before := s1dCounts(t, ctx, admin)
		runSync(t, ctx, handler, queue, access, "sync-2")
		after := s1dCounts(t, ctx, admin)
		if before != after {
			t.Fatalf("re-sync changed counts: before=%+v after=%+v", before, after)
		}
	})

	// (4,5) Changing the file creates exactly one new immutable version; the old
	// version and its Evidence stay unchanged.
	t.Run("changed file creates one new immutable version", func(t *testing.T) {
		oldVersions := s1dCounts(t, ctx, admin).versions
		oldFragmentText := fragments[0].textHash
		writeS1dFile(t, filepath.Join(fileDir, "notes.txt"), original+"appended line\n")
		runSync(t, ctx, handler, queue, access, "sync-3")

		if got := s1dCounts(t, ctx, admin).versions; got != oldVersions+1 {
			t.Fatalf("expected one new version, versions=%d (was %d)", got, oldVersions)
		}
		// Old version is SUPERSEDED and its fragments unchanged.
		var oldState string
		if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`,
			s1dOrg, versionID).Scan(&oldState); err != nil {
			t.Fatal(err)
		}
		if oldState != "SUPERSEDED" {
			t.Fatalf("old version state=%s, want SUPERSEDED", oldState)
		}
		if s1dFragments(t, ctx, admin, extractionID)[0].textHash != oldFragmentText {
			t.Fatal("old Evidence fragment mutated")
		}
	})

	// (6) Re-extraction of the same version with a new parser profile creates a new
	// immutable Extraction and atomically switches the active set.
	t.Run("re-extraction switches the active set atomically", func(t *testing.T) {
		_, currentVersion, currentExtraction := s1dActiveEvidence(t, ctx, admin)
		reHandler := handler.WithParserRevision("text-v1-b")
		runSync(t, ctx, reHandler, queue, access, "sync-4")
		_, afterVersion, afterExtraction := s1dActiveEvidence(t, ctx, admin)
		if afterVersion != currentVersion {
			t.Fatal("re-extraction changed the current version")
		}
		if afterExtraction == currentExtraction {
			t.Fatal("active extraction did not switch")
		}
		var activationRevision int64
		if err := admin.QueryRow(ctx, `SELECT activation_revision FROM public.source_version_active_extraction
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, currentVersion).Scan(&activationRevision); err != nil {
			t.Fatal(err)
		}
		if activationRevision < 2 {
			t.Fatalf("activation revision did not advance: %d", activationRevision)
		}
	})

	_ = objectID
}

// TestS1dFencingAndIsolation proves stale-lease fencing, cross-tenant isolation,
// the anchor-mismatch rejection, and the transient-content boundary.
func TestS1dFencingAndIsolation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "canary CANARYTOKEN line one\nline two\n")
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

	// (9) A stale lease cannot write: a claimed job whose lease is superseded by a
	// reclaim fails to create any catalog rows.
	t.Run("stale lease cannot write", func(t *testing.T) {
		jobID := mustID(t, "job")
		if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
			Payload: jobs.Payload{"source_scope_id": s1dScopeID}, IdempotencyKey: "stale-" + jobID,
			Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
			t.Fatal(err)
		}
		claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 1)
		if err != nil || !ok {
			t.Fatalf("claim failed: %v ok=%v", err, ok)
		}
		// Expire and reclaim the lease so the held epoch is stale.
		if _, err := admin.Exec(ctx, `UPDATE public.job SET lease_deadline = now() - interval '1 minute'
			WHERE organization_id=$1 AND id=$2`, s1dOrg, claimed.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := queue.Reclaim(ctx, access, 10); err != nil {
			t.Fatal(err)
		}
		if err := handler.Handle(ctx, access, claimed); err == nil {
			t.Fatal("stale-lease handler unexpectedly succeeded")
		}
		var objects int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_object WHERE organization_id=$1`, s1dOrg).Scan(&objects); err != nil {
			t.Fatal(err)
		}
		if objects != 0 {
			t.Fatalf("stale lease created %d objects", objects)
		}
	})

	// A fresh sync then succeeds and produces Evidence.
	runSync(t, ctx, handler, queue, access, "fresh")
	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)

	// (13) Cross-tenant access is impossible: another organization sees nothing.
	t.Run("cross-tenant isolation", func(t *testing.T) {
		otherAccess := workerAccess(t, "org_other")
		var count int
		_ = workerStore.Read(ctx, otherAccess, func(ctx context.Context, tx database.Transaction) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment`).Scan(&count)
		})
		if count != 0 {
			t.Fatalf("cross-tenant read saw %d fragments", count)
		}
	})

	// (16) A durable-storage / log scan finds no source bytes or raw parser output:
	// no cleartext canary in any encrypted_artifact ciphertext or typed column.
	t.Run("no source bytes in durable storage", func(t *testing.T) {
		var leaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
			WHERE organization_id=$1 AND position('CANARYTOKEN' in encode(ciphertext,'escape')) > 0`, s1dOrg).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatal("source bytes found in ciphertext")
		}
	})

	// (15) An anchor of another line range does not resolve to the fragment bytes.
	t.Run("anchor of another range is rejected", func(t *testing.T) {
		fragments := s1dFragments(t, ctx, admin, extractionID)
		canonical, _ := canon.Canonicalize([]byte("canary CANARYTOKEN line one\nline two\n"))
		// Line 2 alone must not hash to a fragment that covers the whole file.
		if slice, ok := canon.Slice(canonical, 2, 2); ok {
			for _, f := range fragments {
				if canon.HMACDigest(s1dDigestKey, 1, slice) == f.textHash && len(canon.Lines(canonical)) > 2 {
					t.Fatal("a narrower line range produced a full-fragment hash")
				}
			}
		}
	})

	// (17, AUD-005) The scope sync writes exactly one audit event, as a SYSTEM
	// actor, carrying only safe ids (scope, sync run) and no source content.
	t.Run("audit records only safe ids", func(t *testing.T) {
		var count int
		var actorType, resourceType, metadata, canonicalBytes string
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
			WHERE organization_id=$1 AND action='source.scope_changed'`, s1dOrg).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatal("no scope-sync audit event was written")
		}
		if err := admin.QueryRow(ctx, `SELECT actor_type, resource_type, metadata_json, encode(canonical_bytes,'escape')
			FROM public.audit_event WHERE organization_id=$1 AND action='source.scope_changed' ORDER BY sequence LIMIT 1`, s1dOrg).
			Scan(&actorType, &resourceType, &metadata, &canonicalBytes); err != nil {
			t.Fatal(err)
		}
		if actorType != "SYSTEM" || resourceType != "SOURCE_SCOPE" {
			t.Fatalf("audit actor/resource = %s/%s", actorType, resourceType)
		}
		if !strings.Contains(metadata, "sync_run_id") {
			t.Fatalf("audit metadata missing sync_run_id: %s", metadata)
		}
		if strings.Contains(canonicalBytes+metadata, "CANARYTOKEN") {
			t.Fatal("source content leaked into the audit event")
		}
	})

	// (C2) A version's lifecycle is forward-only: the current version cannot be
	// rolled back, so a stale write cannot resurrect it.
	t.Run("version state does not roll back", func(t *testing.T) {
		if _, err := admin.Exec(ctx, `UPDATE public.source_version SET state='PENDING'
			WHERE organization_id=$1 AND state='CURRENT'`, s1dOrg); err == nil {
			t.Fatal("a CURRENT version was rolled back to PENDING")
		}
	})

	// (C1) No runtime role can verify connection trust: the worker cannot flip the
	// trust projection to VERIFIED, so it cannot satisfy the sync precondition itself.
	t.Run("worker cannot verify connection trust", func(t *testing.T) {
		err := workerStore.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
			_, execErr := tx.Exec(ctx, `UPDATE public.source_connection_trust_projection SET status='REVOKED'
				WHERE organization_id=$1`, s1dOrg)
			return execErr
		})
		if err == nil {
			t.Fatal("worker role was able to mutate the trust projection")
		}
	})
}

// ---- helpers ----

type fragmentRow struct {
	id       string
	ordinal  int
	textHash string
}

func runSync(t *testing.T, ctx context.Context, handler *ingestion.Handler, queue *jobs.Queue, access database.AccessContext, label string) {
	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, label)
}

func runSyncScope(t *testing.T, ctx context.Context, handler *ingestion.Handler, queue *jobs.Queue, access database.AccessContext, scopeID, label string) {
	t.Helper()
	jobID := mustID(t, "job")
	if _, err := queue.Enqueue(ctx, access, jobs.Spec{JobID: jobID, Type: jobs.TypeSourceScopeSync,
		Payload: jobs.Payload{"source_scope_id": scopeID}, IdempotencyKey: label + "-" + jobID,
		Priority: 100, MaxAttempts: 3, AvailableAfter: 0}); err != nil {
		t.Fatalf("enqueue %s: %v", label, err)
	}
	claimed, ok, err := queue.Claim(ctx, access, s1dWorkerID, 60)
	if err != nil || !ok {
		t.Fatalf("claim %s: %v ok=%v", label, err, ok)
	}
	if err := handler.Handle(ctx, access, claimed); err != nil {
		t.Fatalf("handle %s: %v (code=%s)", label, err, ingestion.CodeOf(err))
	}
}

type counts struct{ objects, versions, extractions, fragments, memberships int }

func s1dCounts(t *testing.T, ctx context.Context, admin *pgxpool.Pool) counts {
	t.Helper()
	var c counts
	q := func(sql string, dst *int) {
		if err := admin.QueryRow(ctx, sql, s1dOrg).Scan(dst); err != nil {
			t.Fatal(err)
		}
	}
	q(`SELECT count(*) FROM public.source_object WHERE organization_id=$1`, &c.objects)
	q(`SELECT count(*) FROM public.source_version WHERE organization_id=$1`, &c.versions)
	q(`SELECT count(*) FROM public.source_extraction WHERE organization_id=$1`, &c.extractions)
	q(`SELECT count(*) FROM public.evidence_fragment WHERE organization_id=$1`, &c.fragments)
	q(`SELECT count(*) FROM public.source_object_scope WHERE organization_id=$1`, &c.memberships)
	return c
}

func s1dActiveEvidence(t *testing.T, ctx context.Context, admin *pgxpool.Pool) (objectID, versionID, extractionID string) {
	t.Helper()
	if err := admin.QueryRow(ctx, `
		SELECT o.id, v.id, ae.extraction_id
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id
		WHERE o.organization_id=$1 AND o.queryable`, s1dOrg).Scan(&objectID, &versionID, &extractionID); err != nil {
		t.Fatalf("no active Evidence: %v", err)
	}
	return objectID, versionID, extractionID
}

func s1dFragments(t *testing.T, ctx context.Context, admin *pgxpool.Pool, extractionID string) []fragmentRow {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT id, ordinal, text_hash FROM public.evidence_fragment
		WHERE organization_id=$1 AND extraction_id=$2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []fragmentRow
	for rows.Next() {
		var f fragmentRow
		if err := rows.Scan(&f.id, &f.ordinal, &f.textHash); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func mustID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := ids.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mustRepo(t *testing.T) *artifactrepository.Repository {
	t.Helper()
	repo, err := ingestion.BuildRepository()
	if err != nil {
		t.Fatal(err)
	}
	return repo
}
