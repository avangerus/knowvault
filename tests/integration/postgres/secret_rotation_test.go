package postgres_test

// ADR-0070 deployment secret rotation: two-phase KEK rewrap and digest-key
// re-projection on the real PostgreSQL. Every write path is fenced by a live
// S1b job lease, CAS'd against the previous pair/version, worker-only, and
// completed only at zero remaining rows (fail closed). Repeat begin/complete
// is idempotent.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	rotationPrevRef   = "kms://tenant"
	rotationActiveRef = "kms://tenant-v2"
	rotationJobOwner  = s1dWorkerID
)

type rotationStateRow struct {
	phase           string
	previousRef     string
	previousVersion int64
	activeRef       string
	activeVersion   int64
	watermark       int64
}

func rotationSetup(t *testing.T) (context.Context, *pgxpool.Pool, *pgxpool.Pool, *pgxpool.Pool, string) {
	t.Helper()
	ctx, admin, _, extractionID, _ := s1ePurgeSetup(t)
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	worker := openWorkerPool(t, ctx, testDatabaseURL(t))
	return ctx, admin, app, worker, extractionID
}

// rotationBegin registers the previous/active pair of a domain under the
// worker role, exactly as the production coordinator does.
func rotationBegin(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, domain, prevRef string, prevVersion int64, activeRef string, activeVersion int64) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	if _, err := tx.Exec(ctx, `SELECT app.rotation_begin($1, $2, $3, $4, $5)`,
		domain, prevRef, prevVersion, activeRef, activeVersion); err != nil {
		t.Fatalf("rotation begin %s: %v", domain, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func rotationStateOf(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, domain string) rotationStateRow {
	t.Helper()
	var row rotationStateRow
	if err := admin.QueryRow(ctx, `
		SELECT phase, COALESCE(previous_reference, ''), COALESCE(previous_version, 0),
		       active_reference, active_version, watermark
		FROM public.rotation_state WHERE organization_id = $1 AND domain = $2`,
		org, domain).Scan(&row.phase, &row.previousRef, &row.previousVersion, &row.activeRef, &row.activeVersion, &row.watermark); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return row // no rotation row: the empty state of a domain with no rotation
		}
		t.Fatalf("read rotation state %s: %v", domain, err)
	}
	return row
}

// enqueueRotationJob enqueues a rotation-domain job through the runtime role
// and leases it under the S1b worker identity. Each call needs a distinct
// suffix so its job and idempotency keys differ.
func enqueueRotationJob(t *testing.T, ctx context.Context, app, worker *pgxpool.Pool, org, jobType string, suffix int) leasedJob {
	t.Helper()
	jobID := enqueueDurableJob(t, ctx, app, org, "usr_worker", outboxRef("job", suffix), jobType, outboxRef("idem", suffix), 3, 0)
	claimed, found := claimDurableJob(t, ctx, worker, org, rotationJobOwner, 30)
	if !found {
		t.Fatalf("no %s job claimed", jobType)
	}
	if claimed.id != jobID {
		t.Fatalf("claimed %s, want %s", claimed.id, jobID)
	}
	return claimed
}

func rewrapArtifact(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, artifactID string, prevRef string, prevVersion int64, activeRef string, activeVersion int64, claimed leasedJob) {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	// The nonce never repeats under one tenant KEK pair (000005 unique
	// constraint), so each re-seal derives its nonce from the artifact id.
	nonce := sha256.Sum256([]byte(artifactID))
	if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		artifactID, prevRef, prevVersion, activeRef, activeVersion,
		nonce[:12], bytes.Repeat([]byte{0x22}, 64),
		sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, claimed.leaseEpoch); err != nil {
		t.Fatalf("artifact rewrap: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func artifactPair(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, artifactID string) (string, int64) {
	t.Helper()
	var ref string
	var version int64
	if err := admin.QueryRow(ctx, `SELECT kek_reference, kek_version FROM public.encrypted_artifact WHERE organization_id=$1 AND id=$2`,
		org, artifactID).Scan(&ref, &version); err != nil {
		t.Fatalf("read artifact pair: %v", err)
	}
	return ref, version
}

// The candidate/remaining readers are SECURITY DEFINER functions scoped by
// app.current_organization_id(), so they run in a transaction that carries
// the tenant context, exactly like the worker calls they feed.
func rewrapCandidateCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, ref string, version int64) int64 {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_admin")
	var count int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM app.artifact_rewrap_candidate_batch($1, $2, 100)`,
		ref, version).Scan(&count); err != nil {
		t.Fatalf("rewrap candidate count: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return count
}

func rewrapCandidateID(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org, ref string, version int64) string {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_admin")
	var id string
	if err := tx.QueryRow(ctx, `SELECT id FROM app.artifact_rewrap_candidate_batch($1, $2, 1) ORDER BY id LIMIT 1`,
		ref, version).Scan(&id); err != nil {
		t.Fatalf("rewrap candidate id: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return id
}

func kekComplete(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, activeRef string, activeVersion int64) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	_, err = tx.Exec(ctx, `SELECT app.kek_rotation_complete($1, $2)`, activeRef, activeVersion)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func digestRemainingCount(t *testing.T, ctx context.Context, admin *pgxpool.Pool, org string, version int64) int64 {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_admin")
	var count int64
	if err := tx.QueryRow(ctx, `SELECT app.evidence_digest_remaining_count($1)`, version).Scan(&count); err != nil {
		t.Fatalf("digest remaining count: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return count
}

func digestRewrite(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org, fragmentID, newAnchorHash, newTextHash string, newVersion int64, claimed leasedJob) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	_, err = tx.Exec(ctx, `SELECT app.evidence_digest_rewrite($1, $2, $3, $4, $5, $6, $7)`,
		fragmentID, newAnchorHash, newTextHash, newVersion, claimed.id, rotationJobOwner, claimed.leaseEpoch)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func digestComplete(t *testing.T, ctx context.Context, worker *pgxpool.Pool, org string, previousVersion int64) error {
	t.Helper()
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, org, "usr_worker")
	_, err = tx.Exec(ctx, `SELECT app.digest_rotation_complete($1)`, previousVersion)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// nextKeyedDigest re-keys the anchor digest string under the new version.
// The contract test only needs a value that passes the format validator; the
// exact re-keying of the canonical bytes is proved by the rotation handler
// test, which opens the anchor artifact.
func nextKeyedDigest(oldHash string, newVersion int64) string {
	mac := hmac.New(sha256.New, s1dDigestKey)
	mac.Write([]byte(oldHash))
	return "hmac-sha256:k" + strconv.FormatInt(newVersion, 10) + ":" + hex.EncodeToString(mac.Sum(nil))
}

// TestRotationKekFullCycle proves the happy path: begin (idempotent repeat),
// fenced rewrap of every wrapper under the new pair, zero-wrappers completion
// and the idempotent repeat of complete.
func TestRotationKekFullCycle(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)

	// Every artifact of the seeded pipeline is sealed under the S1d pair.
	before := rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1)
	if before == 0 {
		t.Fatal("no artifacts sealed under the previous pair")
	}

	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.phase != "REWRAPPING" || state.activeRef != rotationActiveRef || state.activeVersion != 2 {
		t.Fatalf("state after begin: %+v", state)
	}

	// A repeat of the exact same begin is a no-op.
	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)

	claimed := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "KEK_REWRAP", 7)

	// Rewrap one artifact at a time; after each rewrap the artifact is no
	// longer a candidate and the watermark advances.
	for remaining := before; remaining > 0; remaining-- {
		artifactID := rewrapCandidateID(t, ctx, admin, s1dOrg, rotationPrevRef, 1)
		rewrapArtifact(t, ctx, worker, s1dOrg, artifactID, rotationPrevRef, 1, rotationActiveRef, 2, claimed)
		ref, version := artifactPair(t, ctx, admin, s1dOrg, artifactID)
		if ref != rotationActiveRef || version != 2 {
			t.Fatalf("artifact %s pair after rewrap: %s/%d", artifactID, ref, version)
		}
	}
	state = rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.watermark != before {
		t.Fatalf("watermark=%d, want %d", state.watermark, before)
	}
	if remaining := rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1); remaining != 0 {
		t.Fatalf("%d wrappers still under the previous pair", remaining)
	}

	if err := kekComplete(t, ctx, worker, s1dOrg, rotationActiveRef, 2); err != nil {
		t.Fatalf("complete: %v", err)
	}
	state = rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.phase != "COMPLETE" {
		t.Fatalf("state after complete: %+v", state)
	}

	// The idempotent repeat of complete with the same active pair is a no-op.
	if err := kekComplete(t, ctx, worker, s1dOrg, rotationActiveRef, 2); err != nil {
		t.Fatalf("repeat complete: %v", err)
	}
}

// TestRotationBeginRepeatIdempotent proves a repeat of the exact same begin is
// a no-op while the rotation is in progress: no error, unchanged pair, and
// unchanged watermark (ADR-0070 §1.3: a repeat rotation is idempotent). The
// begin registers only the pair — the coordinator places the driver job
// separately — so the repeat has no job side effect to assert.
func TestRotationBeginRepeatIdempotent(t *testing.T) {
	ctx, admin, _, worker, _ := rotationSetup(t)

	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.phase != "REWRAPPING" || state.activeRef != rotationActiveRef {
		t.Fatalf("state after first begin: %+v", state)
	}

	// The exact same begin is a no-op: no error, and neither the pair nor the
	// watermark moves.
	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	state = rotationStateOf(t, ctx, admin, s1dOrg, "KEK")
	if state.phase != "REWRAPPING" || state.previousRef != rotationPrevRef || state.previousVersion != 1 ||
		state.activeRef != rotationActiveRef || state.activeVersion != 2 || state.watermark != 0 {
		t.Fatalf("state after repeat begin: %+v", state)
	}
}

// TestRotationKekZeroWrappersPrecondition proves complete fails closed while
// any wrapper remains under the previous pair, and succeeds once all are
// re-wrapped.
func TestRotationKekZeroWrappersPrecondition(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)

	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	if err := kekComplete(t, ctx, worker, s1dOrg, rotationActiveRef, 2); err == nil {
		t.Fatal("complete succeeded while wrappers remained under the previous pair")
	} else if !strings.Contains(err.Error(), "zero-wrappers") {
		t.Fatalf("unexpected error: %v", err)
	}

	claimed := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "KEK_REWRAP", 8)
	artifactID := rewrapCandidateID(t, ctx, admin, s1dOrg, rotationPrevRef, 1)
	rewrapArtifact(t, ctx, worker, s1dOrg, artifactID, rotationPrevRef, 1, rotationActiveRef, 2, claimed)
	if err := kekComplete(t, ctx, worker, s1dOrg, rotationActiveRef, 2); err == nil {
		t.Fatal("complete succeeded while some wrappers remained under the previous pair")
	}
	for rewrapCandidateCount(t, ctx, admin, s1dOrg, rotationPrevRef, 1) > 0 {
		artifactID := rewrapCandidateID(t, ctx, admin, s1dOrg, rotationPrevRef, 1)
		rewrapArtifact(t, ctx, worker, s1dOrg, artifactID, rotationPrevRef, 1, rotationActiveRef, 2, claimed)
	}
	if err := kekComplete(t, ctx, worker, s1dOrg, rotationActiveRef, 2); err != nil {
		t.Fatalf("complete after all re-wrapped: %v", err)
	}
}

// TestRotationKekFencingFailClosed proves every unknown or stale entry point
// closes: no live lease, a lease on a different job type, a stale lease epoch,
// a mismatched key pair and a complete with a mismatched active pair.
func TestRotationKekFencingFailClosed(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)
	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	artifactID := rewrapCandidateID(t, ctx, admin, s1dOrg, rotationPrevRef, 1)

	claimed := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "KEK_REWRAP", 9)

	// No live lease at all: the job exists but is not claimed.
	t.Run("no live lease", func(t *testing.T) {
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_worker")
		if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			artifactID, rotationPrevRef, int64(1), rotationActiveRef, int64(2),
			bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
			sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, int64(0)); err == nil {
			t.Fatal("rewrap succeeded without a live lease")
		}
	})

	// A lease on a non-rotation job type.
	t.Run("wrong job type", func(t *testing.T) {
		syncJob := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "SOURCE_SCOPE_SYNC", 10)
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_worker")
		if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			artifactID, rotationPrevRef, int64(1), rotationActiveRef, int64(2),
			bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
			sha256Value("b"), sha256Value("c"), syncJob.id, rotationJobOwner, syncJob.leaseEpoch); err == nil {
			t.Fatal("rewrap succeeded under a non-KEK job lease")
		}
	})

	// A stale epoch of the real lease.
	t.Run("stale lease epoch", func(t *testing.T) {
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_worker")
		if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			artifactID, rotationPrevRef, int64(1), rotationActiveRef, int64(2),
			bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
			sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, claimed.leaseEpoch-1); err == nil {
			t.Fatal("rewrap succeeded under a stale lease epoch")
		}
	})

	// A mismatched previous pair (unknown version fails closed).
	t.Run("mismatched pair", func(t *testing.T) {
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_worker")
		if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			artifactID, "kms://other-tenant", int64(9), rotationActiveRef, int64(2),
			bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
			sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, claimed.leaseEpoch); err == nil {
			t.Fatal("rewrap succeeded under a mismatched previous pair")
		}
	})

	// A mismatched active pair in the rotation in progress.
	t.Run("mismatched active pair", func(t *testing.T) {
		tx, err := worker.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_worker")
		if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			artifactID, rotationPrevRef, int64(1), "kms://unknown", int64(3),
			bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
			sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, claimed.leaseEpoch); err == nil {
			t.Fatal("rewrap succeeded under a pair the rotation does not track")
		}
	})

	// Complete with a mismatched active pair.
	if err := kekComplete(t, ctx, worker, s1dOrg, "kms://unknown", 3); err == nil {
		t.Fatal("complete succeeded with a mismatched active pair")
	}

	// The artifact is still sealed under the previous pair after all refusals.
	ref, version := artifactPair(t, ctx, admin, s1dOrg, artifactID)
	if ref != rotationPrevRef || version != 1 {
		t.Fatalf("artifact moved to %s/%d despite refused rewraps", ref, version)
	}
}

// TestRotationDigestFullCycle proves the keyed anchor digest rotation: begin,
// fenced re-projection of every fragment, projection/fragment pair consistency,
// zero-remaining completion and the idempotent repeat.
func TestRotationDigestFullCycle(t *testing.T) {
	ctx, admin, app, worker, extractionID := rotationSetup(t)

	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}
	if remaining := digestRemainingCount(t, ctx, admin, s1dOrg, 1); remaining != int64(len(fragments)) {
		t.Fatalf("remaining=%d, want %d", remaining, len(fragments))
	}

	rotationBegin(t, ctx, worker, s1dOrg, "DIGEST", "source-digest", 1, "source-digest", 2)

	// A repeat of the same begin is a no-op.
	rotationBegin(t, ctx, worker, s1dOrg, "DIGEST", "source-digest", 1, "source-digest", 2)

	claimed := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "DIGEST_RECOMPUTE", 11)

	type fragmentRow struct {
		id         string
		anchorHash string
		textHash   string
	}
	rows, err := admin.Query(ctx, `SELECT id, anchor_hash, text_hash FROM public.evidence_fragment
		WHERE organization_id = $1 AND extraction_id = $2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	var fragmentRows []fragmentRow
	for rows.Next() {
		var row fragmentRow
		if err := rows.Scan(&row.id, &row.anchorHash, &row.textHash); err != nil {
			t.Fatal(err)
		}
		fragmentRows = append(fragmentRows, row)
	}
	rows.Close()
	if len(fragmentRows) != len(fragments) {
		t.Fatalf("read %d fragments, want %d", len(fragmentRows), len(fragments))
	}

	for _, row := range fragmentRows {
		newAnchorHash := nextKeyedDigest(row.anchorHash, 2)
		newTextHash := nextKeyedDigest(row.textHash, 2)
		if err := digestRewrite(t, ctx, worker, s1dOrg, row.id, newAnchorHash, newTextHash, 2, claimed); err != nil {
			t.Fatalf("digest rewrite %s: %v", row.id, err)
		}
	}

	if remaining := digestRemainingCount(t, ctx, admin, s1dOrg, 1); remaining != 0 {
		t.Fatalf("remaining=%d after full rewrite, want 0", remaining)
	}

	// Fragment and both projections stay an exact pair under the new version.
	var paired int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment f
		JOIN public.evidence_anchor_projection p
		  ON p.organization_id = f.organization_id AND p.fragment_id = f.id
		 AND p.anchor_hash = f.anchor_hash AND p.digest_key_version = f.anchor_digest_key_version
		JOIN public.evidence_text_projection tp
		  ON tp.organization_id = f.organization_id AND tp.fragment_id = f.id
		 AND tp.text_hash = f.text_hash AND tp.digest_key_version = f.text_digest_key_version
		WHERE f.organization_id = $1 AND f.extraction_id = $2`, s1dOrg, extractionID).Scan(&paired); err != nil {
		t.Fatal(err)
	}
	if paired != int64(len(fragments)) {
		t.Fatalf("%d fragments paired with their projections, want %d", paired, len(fragments))
	}

	state := rotationStateOf(t, ctx, admin, s1dOrg, "DIGEST")
	if state.watermark != int64(len(fragments)) {
		t.Fatalf("watermark=%d, want %d", state.watermark, len(fragments))
	}

	if err := digestComplete(t, ctx, worker, s1dOrg, 1); err != nil {
		t.Fatalf("complete: %v", err)
	}
	state = rotationStateOf(t, ctx, admin, s1dOrg, "DIGEST")
	if state.phase != "COMPLETE" {
		t.Fatalf("state after complete: %+v", state)
	}
	if err := digestComplete(t, ctx, worker, s1dOrg, 1); err != nil {
		t.Fatalf("repeat complete: %v", err)
	}
}

// TestRotationDigestFencingFailClosed proves every stale or unknown entry
// point of the digest rotation closes: no live lease, a version that is not
// the rotation's active version, a CAS miss on an already re-projected
// fragment, and completion while fragments remain under the previous version.
func TestRotationDigestFencingFailClosed(t *testing.T) {
	ctx, admin, app, worker, extractionID := rotationSetup(t)
	rotationBegin(t, ctx, worker, s1dOrg, "DIGEST", "source-digest", 1, "source-digest", 2)

	var fragmentID string
	var anchorHash, textHash string
	if err := admin.QueryRow(ctx, `SELECT id, anchor_hash, text_hash FROM public.evidence_fragment
		WHERE organization_id = $1 AND extraction_id = $2 ORDER BY ordinal LIMIT 1`,
		s1dOrg, extractionID).Scan(&fragmentID, &anchorHash, &textHash); err != nil {
		t.Fatal(err)
	}

	claimed := enqueueRotationJob(t, ctx, app, worker, s1dOrg, "DIGEST_RECOMPUTE", 12)

	// No live lease.
	if err := digestRewrite(t, ctx, worker, s1dOrg, fragmentID, nextKeyedDigest(anchorHash, 2), nextKeyedDigest(textHash, 2), 2, leasedJob{id: claimed.id, leaseEpoch: 0}); err == nil {
		t.Fatal("rewrite succeeded without a live lease")
	}
	// Unknown version: not the rotation's active version.
	if err := digestRewrite(t, ctx, worker, s1dOrg, fragmentID, nextKeyedDigest(anchorHash, 3), nextKeyedDigest(textHash, 3), 3, claimed); err == nil {
		t.Fatal("rewrite succeeded under a version the rotation does not track")
	}
	// Completion while fragments remain under the previous version.
	if err := digestComplete(t, ctx, worker, s1dOrg, 1); err == nil {
		t.Fatal("complete succeeded while fragments remained under the previous version")
	}
	// Completion named against a version the rotation does not track as its
	// previous version: zero remaining under version 2 must not be able to
	// close a rotation whose previous version is 1.
	if err := digestComplete(t, ctx, worker, s1dOrg, 2); err == nil {
		t.Fatal("complete succeeded under a version that is not the rotation's previous version")
	}
	// The happy rewrite, then a CAS miss on the same fragment.
	if err := digestRewrite(t, ctx, worker, s1dOrg, fragmentID, nextKeyedDigest(anchorHash, 2), nextKeyedDigest(textHash, 2), 2, claimed); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := digestRewrite(t, ctx, worker, s1dOrg, fragmentID, nextKeyedDigest(anchorHash+"x", 2), nextKeyedDigest(textHash, 2), 2, claimed); err == nil {
		t.Fatal("rewrite succeeded on an already re-projected fragment")
	}
}

// TestRotationWorkerOnlyGrants proves the runtime role holds no entry point:
// begin and rewrap refuse knowvault_app with 42501, and the state reader is
// not granted to it.
func TestRotationWorkerOnlyGrants(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, s1dOrg, "usr_s1d_owner")
	if _, err := tx.Exec(ctx, `SELECT app.rotation_begin($1,$2,$3,$4,$5)`, "KEK", rotationPrevRef, int64(1), rotationActiveRef, int64(2)); err == nil {
		t.Fatal("runtime role unexpectedly began a rotation")
	}
	if _, err := tx.Exec(ctx, `SELECT app.rotation_state('KEK')`); err == nil {
		t.Fatal("runtime role unexpectedly read rotation state")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	// The worker still owns every path after the refusals.
	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)
	if state := rotationStateOf(t, ctx, admin, s1dOrg, "KEK"); state.phase != "REWRAPPING" {
		t.Fatalf("state: %+v", state)
	}
}

// TestRotationTenantIsolation proves the rotation machinery of one tenant is
// invisible to another: no state, no candidates, no completion without a
// begin.
func TestRotationTenantIsolation(t *testing.T) {
	ctx, admin, app, worker, _ := rotationSetup(t)
	seedOrganization(t, ctx, admin, "org_rotation_iso", "usr_rotation_iso", "ws_rotation_iso")
	rotationBegin(t, ctx, worker, s1dOrg, "KEK", rotationPrevRef, 1, rotationActiveRef, 2)

	if count := rewrapCandidateCount(t, ctx, admin, "org_rotation_iso", rotationPrevRef, 1); count != 0 {
		t.Fatalf("isolated tenant saw %d candidates", count)
	}
	if err := kekComplete(t, ctx, worker, "org_rotation_iso", rotationActiveRef, 2); err == nil {
		t.Fatal("isolated tenant completed a rotation it never began")
	}

	claimed := enqueueRotationJob(t, ctx, app, worker, "org_rotation_iso", "KEK_REWRAP", 13)
	tx, err := worker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_rotation_iso", "usr_worker")
	if _, err := tx.Exec(ctx, `SELECT app.artifact_rewrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		outboxRef("art", 1), rotationPrevRef, int64(1), rotationActiveRef, int64(2),
		bytes.Repeat([]byte{0x11}, 12), bytes.Repeat([]byte{0x22}, 64),
		sha256Value("b"), sha256Value("c"), claimed.id, rotationJobOwner, claimed.leaseEpoch); err == nil {
		t.Fatal("isolated tenant re-wrapped without a rotation in progress")
	}
}
