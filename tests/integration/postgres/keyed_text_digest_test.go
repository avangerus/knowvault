package postgres_test

// ADR-0077 keyed Evidence text digest on the real PostgreSQL: newly written
// fragments carry an organization-scoped HMAC-SHA-256 text_hash with a
// mandatory text_digest_key_version; the schema check rejects plain SHA-256
// and a missing version; a historical (legacy plain-SHA) row fails closed on
// read and cannot be re-published; purge removes the keyed projection rows
// while the fragment provenance stays; and a digest rotation completes even
// when purged-version fragments carry legacy projections (they are excluded,
// not blockers).

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/rotation"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

var plainSHA = "sha256:" + strings.Repeat("ab", 32)

// TestKeyedTextDigestSchema proves the schema contract of the keyed text
// digest: every pipeline-written fragment is keyed under version 1 with a
// matching text projection, and a new row with a plain SHA-256 text hash — or
// with a keyed hash but no digest version — is rejected by the check.
func TestKeyedTextDigestSchema(t *testing.T) {
	ctx, admin, _, extractionID, _ := s1ePurgeSetup(t)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}

	// Every fragment is keyed and its text projection is an exact pair.
	for _, fragment := range fragments {
		var textHash, projectionHash string
		var version, projectionVersion int64
		if err := admin.QueryRow(ctx, `SELECT text_hash, text_digest_key_version
			FROM public.evidence_fragment WHERE organization_id = $1 AND id = $2`,
			s1dOrg, fragment.id).Scan(&textHash, &version); err != nil {
			t.Fatal(err)
		}
		if version != 1 || !strings.HasPrefix(textHash, "hmac-sha256:k1:") {
			t.Fatalf("fragment %s: text digest %q version %d, want keyed version 1", fragment.id, textHash, version)
		}
		if err := admin.QueryRow(ctx, `SELECT p.text_hash, p.digest_key_version
			FROM public.evidence_text_projection p WHERE p.organization_id = $1 AND p.fragment_id = $2`,
			s1dOrg, fragment.id).Scan(&projectionHash, &projectionVersion); err != nil {
			t.Fatalf("fragment %s has no text projection: %v", fragment.id, err)
		}
		if projectionHash != textHash || projectionVersion != version {
			t.Fatalf("fragment %s projection %q/%d != fragment %q/%d", fragment.id, projectionHash, projectionVersion, textHash, version)
		}
	}

	// A new row with a plain SHA-256 text hash is rejected by the keyed check.
	var ordinal int
	if err := admin.QueryRow(ctx, `SELECT COALESCE(max(ordinal), 0) + 1 FROM public.evidence_fragment
		WHERE organization_id = $1 AND extraction_id = $2`, s1dOrg, extractionID).Scan(&ordinal); err != nil {
		t.Fatal(err)
	}
	keyedAnchor := canon.HMACDigest(s1dDigestKey, 1, []byte("anchor bytes"))
	_, versionID2, extractionID2 := s1dActiveEvidence(t, ctx, admin)
	if _, err := admin.Exec(ctx, `INSERT INTO public.evidence_fragment
		(organization_id, id, source_version_id, extraction_id, ordinal, text_hash, text_digest_key_version,
		 token_count, byte_count, anchor_hash, anchor_digest_key_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())`,
		s1dOrg, mustID(t, "fragment"), versionID2, extractionID2, ordinal, plainSHA, 1,
		1, 4, keyedAnchor, 1); err == nil {
		t.Fatal("a plain SHA-256 text_hash was accepted by the schema")
	} else if !strings.Contains(err.Error(), "evidence_fragment_text_digest_check") {
		t.Fatalf("plain text_hash rejected for the wrong reason: %v", err)
	}

	// A keyed hash without a digest version is rejected by the state guard
	// (the NULL pair is the purge shape and must never be ingested).
	keyedText := canon.HMACDigest(s1dDigestKey, 1, []byte("text bytes"))
	if _, err := admin.Exec(ctx, `INSERT INTO public.evidence_fragment
		(organization_id, id, source_version_id, extraction_id, ordinal, text_hash, text_digest_key_version,
		 token_count, byte_count, anchor_hash, anchor_digest_key_version, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, $10, now())`,
		s1dOrg, mustID(t, "fragment"), versionID2, extractionID2, ordinal, keyedText,
		1, 4, keyedAnchor, 1); err == nil {
		t.Fatal("a keyed text_hash without a digest version was accepted by the schema")
	} else if !strings.Contains(err.Error(), "keyed anchor and text digests") {
		t.Fatalf("missing-version text_hash rejected for the wrong reason: %v", err)
	}
}

// TestKeyedTextDigestLegacyFailClosed proves the fail-closed read and
// publication gates for a historical plain-SHA row: an authorized viewer is
// denied identically to a missing fragment, the readable gate is false, and
// the active-extraction pointer of the version can no longer be re-advanced.
func TestKeyedTextDigestLegacyFailClosed(t *testing.T) {
	ctx, admin, _, extractionID, _ := s1ePurgeSetup(t)
	fragmentID := s1dFragments(t, ctx, admin, extractionID)[0].id
	_, versionID, _ := s1dActiveEvidence(t, ctx, admin)

	codec := s1dCodec(t, s1dOrg)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_view"}
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); err != nil {
		t.Fatalf("authorized read before the legacy conversion failed: %v", err)
	}

	// Model a historical row written before the keyed check existed: disable
	// the fragment triggers, replace the keyed text pair with a plain SHA-256
	// value and no version (the pre-000020 shape), drop the text projection
	// (which did not exist pre-000020), then re-arm the schema boundary as
	// NOT VALID — exactly how the migration treats historical rows.
	for _, statement := range []string{
		`ALTER TABLE public.evidence_fragment DISABLE TRIGGER evidence_fragment_state_guard`,
		`ALTER TABLE public.evidence_fragment DISABLE TRIGGER evidence_fragment_artifact_exact`,
		`ALTER TABLE public.evidence_fragment DROP CONSTRAINT evidence_fragment_text_digest_check`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, `UPDATE public.evidence_fragment
		SET text_hash = $1, text_digest_key_version = NULL
		WHERE organization_id = $2 AND id = $3`, plainSHA, s1dOrg, fragmentID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.evidence_text_projection
		WHERE organization_id = $1 AND fragment_id = $2`, s1dOrg, fragmentID); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`ALTER TABLE public.evidence_fragment
			ADD CONSTRAINT evidence_fragment_text_digest_check
			CHECK ((text_digest_key_version IS NULL AND text_hash IS NULL)
			   OR (text_digest_key_version IS NOT NULL
			      AND app.source_keyed_digest_matches_version(text_hash, text_digest_key_version))) NOT VALID`,
		`ALTER TABLE public.evidence_fragment ENABLE TRIGGER evidence_fragment_state_guard`,
		`ALTER TABLE public.evidence_fragment ENABLE TRIGGER evidence_fragment_artifact_exact`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	// Fail closed on read: the authorized viewer is denied identically to a
	// missing fragment, and the readable gate is false.
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("read after legacy conversion: err=%v, want ErrNotFound", err)
	}
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, tx, s1dOrg, s1dViewer)
	var readable bool
	if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`,
		fragmentID, s1dWorkspace).Scan(&readable); err != nil {
		t.Fatalf("readable gate: %v", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if readable {
		t.Fatal("the readable gate opened for a legacy plain-SHA fragment")
	}

	// Fail closed on publication: the active pointer of the version cannot be
	// re-advanced while a legacy fragment exists in the active extraction.
	if _, err := admin.Exec(ctx, `UPDATE public.source_version_active_extraction
		SET activation_revision = activation_revision + 1
		WHERE organization_id = $1 AND source_version_id = $2`, s1dOrg, versionID); err == nil {
		t.Fatal("the active pointer was re-advanced despite a legacy text fragment")
	} else if !strings.Contains(err.Error(), "keyed anchor and text projections") {
		t.Fatalf("publication closed for the wrong reason: %v", err)
	}
}

// TestKeyedTextDigestPurgeAndRotation proves the purge/rotation interplay:
// cleanup removes both keyed projection rows while the fragment provenance
// survives, and a DIGEST rotation completes in the first pass because
// purged-version fragments are excluded from candidates and zero-remaining.
func TestKeyedTextDigestPurgeAndRotation(t *testing.T) {
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("begin purge: %v", err)
	}
	if _, err := purger.Cleanup(ctx, purgerAccess(), versionID); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// Both projection rows of the version are gone; the fragment rows keep
	// their identity provenance, but both hash pairs are erased (ADR-0077
	// §1.4): no plain-SHA projection of purged content survives in the tree,
	// and the erased rows are not a usable hash oracle without the digest key.
	var textProjections, anchorProjections int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_text_projection pt
		JOIN public.evidence_fragment f ON f.organization_id = pt.organization_id AND f.id = pt.fragment_id
		WHERE f.organization_id = $1 AND f.source_version_id = $2`, s1dOrg, versionID).Scan(&textProjections); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_anchor_projection pa
		JOIN public.evidence_fragment f ON f.organization_id = pa.organization_id AND f.id = pa.fragment_id
		WHERE f.organization_id = $1 AND f.source_version_id = $2`, s1dOrg, versionID).Scan(&anchorProjections); err != nil {
		t.Fatal(err)
	}
	if textProjections != 0 || anchorProjections != 0 {
		t.Fatalf("projection rows survived cleanup: text=%d anchor=%d", textProjections, anchorProjections)
	}
	var provenance, erased int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment
		WHERE organization_id = $1 AND source_version_id = $2`, s1dOrg, versionID).Scan(&provenance); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment
		WHERE organization_id = $1 AND source_version_id = $2
		  AND text_hash IS NULL AND text_digest_key_version IS NULL
		  AND anchor_hash IS NULL AND anchor_digest_key_version IS NULL`, s1dOrg, versionID).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if provenance != len(fragments) || erased != len(fragments) {
		t.Fatalf("fragment provenance=%d erased=%d, want %d for both", provenance, erased, len(fragments))
	}

	// The DIGEST rotation excludes the purged version: zero remaining up
	// front, and the first pass completes instead of blocking forever.
	handler, queue, coordinator, _ := newRotationHandler(t, ctx, s1dOrg, 2)
	access := workerAccess(t, s1dOrg)
	if err := coordinator.Begin(ctx, access, rotation.DomainDigest, "source-digest", 1, "source-digest", 2); err != nil {
		t.Fatalf("begin: %v", err)
	}
	if remaining := digestRemainingCount(t, ctx, admin, s1dOrg, 1); remaining != 0 {
		t.Fatalf("remaining=%d with a purged version, want 0 (purged fragments are excluded)", remaining)
	}
	if err := runRotationPass(t, ctx, handler, queue, access, jobs.TypeDigestRecompute); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if state := rotationStateOf(t, ctx, admin, s1dOrg, "DIGEST"); state.phase != "COMPLETE" {
		t.Fatalf("state after pass: %+v, want COMPLETE", state)
	}
}
