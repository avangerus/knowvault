package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/eml"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// crlf joins message lines with CRLF, the RFC 5322 line ending.
func crlf(lines ...string) string { return strings.Join(lines, "\r\n") }

// emlAnchorFragment is one stored Evidence fragment of an EMAIL extraction with
// the columns needed to prove the anchor re-resolves.
type emlAnchorFragment struct {
	ordinal    int
	textHash   string
	anchorHash string
}

func emlFragments(t *testing.T, ctx context.Context, admin *pgxpool.Pool, extractionID string) []emlAnchorFragment {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT ordinal, text_hash, anchor_hash FROM public.evidence_fragment
		WHERE organization_id=$1 AND extraction_id=$2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []emlAnchorFragment
	for rows.Next() {
		var f emlAnchorFragment
		if err := rows.Scan(&f.ordinal, &f.textHash, &f.anchorHash); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// TestS2aEMLExtraction proves the S2a EML slice (ADR-0060 sub-slice 4): a file
// `.eml` becomes EMAIL-anchored Evidence whose message/MIME-part/byte-range anchor
// re-resolves to the exact canonical slice, keyed by the deterministic
// source-object identity (never the RFC Message-ID header); only inline text/plain
// is extracted while HTML is gated and attachments are never stored; and a
// malformed or HTML-only message is quarantined with no fallback.
func TestS2aEMLExtraction(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// A nested multipart message: an alternative group (plain "1.1" extracted, html
	// "1.2" gated) plus a binary attachment "2" (never stored). The plain body
	// carries a canary and Cyrillic Unicode. A Message-ID header is present so the
	// test can prove the anchor identity does NOT come from it.
	mailEML := crlf(
		"From: a@example.com",
		"To: b@example.com",
		"Subject: =?UTF-8?B?0J/RgNC40LLQtdGC?=",
		"Message-ID: <shared-header-id@example.com>",
		"Content-Type: multipart/mixed; boundary=OUT",
		"",
		"--OUT",
		"Content-Type: multipart/alternative; boundary=IN",
		"",
		"--IN",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"\u041f\u0440\u0438\u0432\u0435\u0442 CANARYTOKEN \U0001f30d",
		"\u0432\u0442\u043e\u0440\u043e\u0439 \u0441\u0442\u0440\u043e\u043a\u043e\u0439",
		"--IN",
		"Content-Type: text/html; charset=utf-8",
		"",
		"<p>CANARYTOKEN in html</p>",
		"--IN--",
		"--OUT",
		"Content-Type: application/octet-stream",
		"Content-Disposition: attachment; filename=secret.bin",
		"Content-Transfer-Encoding: base64",
		"",
		"Q0FOQVJZVE9LRU4=", // base64("CANARYTOKEN") — must never be decoded/stored
		"--OUT--",
		"",
	)
	writeS1dFile(t, filepath.Join(dir, "mail.eml"), mailEML)

	// A valid single-part message with NO Message-ID header still ingests: identity
	// never depends on the header.
	noIDEML := crlf(
		"From: c@example.com",
		"Content-Type: text/plain; charset=utf-8",
		"",
		"body without a message id",
		"",
	)
	writeS1dFile(t, filepath.Join(dir, "noid.eml"), noIDEML)

	// Quarantined: an HTML-only message (no text/plain, no fallback), and a file
	// that is not a MIME message at all.
	writeS1dFile(t, filepath.Join(dir, "htmlonly.eml"), crlf(
		"Content-Type: text/html; charset=utf-8", "", "<html>only html CANARYTOKEN</html>", ""))
	writeS1dFile(t, filepath.Join(dir, "broken.eml"), "this is not an email at all\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "eml-sync")

	// Both valid emails carry the EMAIL canonical format and the eml-v1 profile.
	for _, path := range []string{"projects/alpha/mail.eml", "projects/alpha/noid.eml"} {
		if got := s2aActiveRevision(t, ctx, admin, path); got != "eml-v1" {
			t.Fatalf("%s parser_profile_revision = %q, want eml-v1", path, got)
		}
	}
	// The two bad files are quarantined: no object, no fallback.
	for _, path := range []string{"projects/alpha/htmlonly.eml", "projects/alpha/broken.eml"} {
		if got := s2aActiveRevision(t, ctx, admin, path); got != "" {
			t.Fatalf("%s should have been quarantined, got extraction %q", path, got)
		}
	}
	// Exactly two objects ingested (mail.eml, noid.eml); two quarantined.
	if c := s1dCounts(t, ctx, admin); c.objects != 2 {
		t.Fatalf("objects=%d, want 2", c.objects)
	}
	var seen, quarantined int64
	if err := admin.QueryRow(ctx, `SELECT objects_seen, quarantined FROM public.sync_run
		WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&seen, &quarantined); err != nil {
		t.Fatal(err)
	}
	if seen != 4 || quarantined != 2 {
		t.Fatalf("sync_run seen=%d quarantined=%d, want 4 and 2", seen, quarantined)
	}

	objectID, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/mail.eml")

	// The extraction is EMAIL / text-v1.
	var canonicalFormat, normalization string
	if err := admin.QueryRow(ctx, `SELECT canonical_format, normalization_version
		FROM public.source_extraction WHERE organization_id=$1 AND id=$2`, s1dOrg, extractionID).
		Scan(&canonicalFormat, &normalization); err != nil {
		t.Fatal(err)
	}
	if canonicalFormat != "EMAIL" || normalization != "text-v1" {
		t.Fatalf("canonical_format/normalization = %s/%s, want EMAIL/text-v1", canonicalFormat, normalization)
	}

	// Anchor replay: re-parse the exact source bytes, rebuild the extractable text
	// parts exactly as the pipeline does, and prove every stored fragment's text and
	// EMAIL anchor re-resolve — with the message id bound to the source-object id,
	// not the RFC Message-ID header.
	messageID := "source-object:" + objectID
	if strings.Contains(messageID, "shared-header-id") {
		t.Fatal("anchor message id must not derive from the RFC Message-ID header")
	}
	doc, err := eml.Parse([]byte(mailEML))
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(doc.Parts) != 1 || doc.Parts[0].MIMEPart != "1.1" {
		t.Fatalf("expected exactly the plain part 1.1, got %+v", doc.Parts)
	}
	type expected struct{ textHash, anchorHash string }
	var want []expected
	for _, part := range doc.Parts {
		for _, seg := range canon.Segment(part.Canonical, s1dMaxFragmentBytes) {
			anchorBytes, err := canon.EmailAnchorBytes(messageID, part.MIMEPart, seg.ByteStart, seg.ByteEnd)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, expected{textHash: canon.HMACDigest(s1dDigestKey, 1, seg.Text), anchorHash: canon.HMACDigest(s1dDigestKey, 1, anchorBytes)})
		}
	}
	got := emlFragments(t, ctx, admin, extractionID)
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("fragment count %d != expected %d", len(got), len(want))
	}
	for i := range want {
		if got[i].textHash != want[i].textHash {
			t.Fatalf("fragment %d text_hash mismatch: anchor does not re-resolve", i+1)
		}
		if got[i].anchorHash != want[i].anchorHash {
			t.Fatalf("fragment %d anchor_hash mismatch: EMAIL anchor not reproducible", i+1)
		}
	}

	// Neither the html part, the attachment, nor the base64-encoded attachment
	// canary reaches durable storage: no cleartext canary in any ciphertext.
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

	// Re-running the sync is idempotent: the same immutable EMAIL Evidence, no
	// duplicate object/version/extraction/fragment.
	t.Run("repeat sync is deterministic", func(t *testing.T) {
		before := s1dCounts(t, ctx, admin)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "eml-resync")
		after := s1dCounts(t, ctx, admin)
		if before != after {
			t.Fatalf("re-sync changed catalog counts: %+v -> %+v", before, after)
		}
	})
}
