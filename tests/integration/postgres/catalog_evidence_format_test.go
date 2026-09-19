package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// s2aActiveRevision returns the active extraction's parser_profile_revision for the
// object at one exact root-relative path, or "" if the path produced no object
// (quarantined).
func s2aActiveRevision(t *testing.T, ctx context.Context, admin *pgxpool.Pool, relativePath string) string {
	t.Helper()
	locator, err := canon.FileLocatorBytes("conn_s1d", relativePath)
	if err != nil {
		t.Fatal(err)
	}
	digest := canon.HMACDigest(s1dDigestKey, 1, locator)
	var revision string
	err = admin.QueryRow(ctx, `SELECT e.parser_profile_revision
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id
		JOIN public.source_extraction e ON e.organization_id=ae.organization_id AND e.id=ae.extraction_id
		WHERE o.organization_id=$1 AND o.external_object_id_digest=$2`, s1dOrg, digest).Scan(&revision)
	if err != nil {
		return ""
	}
	return revision
}

// TestS2aFormatAwareExtraction proves the S2a extractor (ADR-0060): each allowed
// text/structured format is validated and carries its own immutable
// parser-profile revision, and a malformed document or a DTD/entity XML is
// quarantined with no Evidence and no fallback.
func TestS2aFormatAwareExtraction(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "data.json"), "{\"a\":1,\"b\":[2,3]}\n")
	writeS1dFile(t, filepath.Join(dir, "doc.xml"), "<?xml version=\"1.0\"?><root><a>x</a></root>\n")
	writeS1dFile(t, filepath.Join(dir, "table.csv"), "h1,h2\n1,2\n3,4\n")
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "line one\nline two\n")
	// Quarantined: malformed JSON, and an XML carrying a DTD/entity payload.
	writeS1dFile(t, filepath.Join(dir, "bad.json"), "{\"a\":1,\n")
	writeS1dFile(t, filepath.Join(dir, "evil.xml"),
		"<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e \"v\">]><root>&e;</root>\n")

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

	// Each valid format carries its own immutable parser-profile revision.
	for _, c := range []struct{ path, revision string }{
		{"projects/alpha/data.json", "json-v1-layout-v2"},
		{"projects/alpha/doc.xml", "xml-v1-layout-v2"},
		{"projects/alpha/table.csv", "csv-v1-layout-v2"},
		{"projects/alpha/notes.txt", "text-v1-layout-v2"},
	} {
		if got := s2aActiveRevision(t, ctx, admin, c.path); got != c.revision {
			t.Fatalf("%s parser_profile_revision = %q, want %q", c.path, got, c.revision)
		}
	}

	// The malformed and DTD-bearing documents are quarantined: no object at all.
	for _, path := range []string{"projects/alpha/bad.json", "projects/alpha/evil.xml"} {
		if got := s2aActiveRevision(t, ctx, admin, path); got != "" {
			t.Fatalf("%s should have been quarantined, but produced an extraction (%q)", path, got)
		}
	}

	// Exactly four objects were ingested; the two bad files were counted quarantined.
	if c := s1dCounts(t, ctx, admin); c.objects != 4 {
		t.Fatalf("objects=%d, want 4 (json,xml,csv,txt)", c.objects)
	}
	var seen, quarantined int64
	if err := admin.QueryRow(ctx, `SELECT objects_seen, quarantined FROM public.sync_run
		WHERE organization_id=$1 ORDER BY started_at DESC LIMIT 1`, s1dOrg).Scan(&seen, &quarantined); err != nil {
		t.Fatal(err)
	}
	if seen != 6 || quarantined != 2 {
		t.Fatalf("sync_run seen=%d quarantined=%d, want 6 and 2", seen, quarantined)
	}

	// The JSON anchor re-resolves to the exact canonical slice, exactly as TEXT.
	_, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/data.json")
	frags := s1dFragments(t, ctx, admin, extractionID)
	if len(frags) == 0 {
		t.Fatal("JSON object produced no Evidence")
	}
	canonical, _ := canon.Canonicalize([]byte("{\"a\":1,\"b\":[2,3]}\n"))
	segments := canon.Segment(canonical, s1dMaxFragmentBytes)
	if len(segments) != len(frags) {
		t.Fatalf("segment count %d != fragment count %d", len(segments), len(frags))
	}
	for i, seg := range segments {
		slice, ok := canon.Slice(canonical, seg.LineStart, seg.LineEnd)
		if !ok || canon.HMACDigest(s1dDigestKey, 1, slice) != frags[i].textHash {
			t.Fatalf("JSON fragment %d anchor does not re-resolve", i+1)
		}
	}
}
