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
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/tests/integration/parserv2harness"
)

// The S2b Office proofs run against the REAL isolated worker image, not a stub: the
// properties under test — sandbox hardening, hostile-package refusal, crash and
// timeout atomicity, the absence of any durable trace of the source document — only
// exist across a real process and container boundary.
//
// The image reference may be supplied by the environment like the PostgreSQL URL;
// otherwise the qualification pins the selected local release tag. The harness
// verifies the image's exact entrypoint, artifact bytes and runtime contract, and
// treats missing prerequisites as fatal when KNOWVAULT_REQUIRE_REAL_V2=1.
const officeWorkerImageEnv = "KNOWVAULT_TEST_OFFICE_WORKER_IMAGE"

func officeWorkerImage(t *testing.T) string {
	t.Helper()
	image := strings.TrimSpace(os.Getenv(officeWorkerImageEnv))
	if image == "" {
		image = parserv2harness.DefaultImage
	}
	return image
}

// officeFragment is one stored Evidence fragment with the columns needed to prove an
// exact structural anchor replays.
type officeFragment struct {
	ordinal    int
	textHash   string
	anchorHash string
}

func officeFragments(t *testing.T, ctx context.Context, admin *pgxpool.Pool, extractionID string) []officeFragment {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT ordinal, text_hash, anchor_hash FROM public.evidence_fragment
		WHERE organization_id=$1 AND extraction_id=$2 ORDER BY ordinal`, s1dOrg, extractionID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []officeFragment
	for rows.Next() {
		var f officeFragment
		if err := rows.Scan(&f.ordinal, &f.textHash, &f.anchorHash); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

// TestS2bOfficeFolderExtraction is the end-to-end S2b proof: DOCX, PPTX and XLSX
// files in a connected folder become versioned, citeable Evidence through the
// existing ingestion and publication owner, with exact structural anchors that
// replay; every hostile OOXML class is quarantined per object with no fallback; and
// no source document, hostile carrier or worker temporary output reaches any durable
// sink.
func TestS2bOfficeFolderExtraction(t *testing.T) {
	runtime := newProductionParserRuntime(t)
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	docx := validDOCX(t)
	write := func(name string, body []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("report.docx", docx)
	write("deck.pptx", validPPTX(t))
	write("budget.xlsx", validXLSX(t))

	// Hostile classes, each a per-object quarantine and never a sync-run failure.
	hostile := map[string][]byte{
		"macro.docx":      macroDOCX(t),
		"ole.docx":        oleDOCX(t),
		"empty.docx":      emptyDOCX(t),
		"external.docx":   externalRelationshipDOCX(t),
		"entity.docx":     entityDOCX(t),
		"traversal.docx":  traversalDOCX(t),
		"duplicate.docx":  duplicateEntryDOCX(t),
		"bomb.docx":       compressionBombDOCX(t),
		"notoffice.docx":  []byte("plain text pretending to be an office document " + ooxmlCanary),
		"mismatched.xlsx": docx, // a DOCX package delivered under an XLSX extension
	}
	for name, body := range hostile {
		write(name, body)
	}

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
		WithOfficeExtractor(runtime.office)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "office-sync")

	// The three valid documents ingested, each under its own extraction profile.
	for path, revision := range map[string]string{
		"projects/alpha/report.docx": "docx-v1",
		"projects/alpha/deck.pptx":   "pptx-v1",
		"projects/alpha/budget.xlsx": "xlsx-v1",
	} {
		if got := s2aActiveRevision(t, ctx, admin, path); got != revision {
			t.Fatalf("%s parser_profile_revision = %q, want %q", path, got, revision)
		}
	}
	// Every hostile object quarantined: no extraction at all, no partial Evidence.
	for name := range hostile {
		path := "projects/alpha/" + name
		if got := s2aActiveRevision(t, ctx, admin, path); got != "" {
			t.Fatalf("%s should have been quarantined, got extraction profile %q", path, got)
		}
	}
	if c := s1dCounts(t, ctx, admin); c.objects != 3 {
		t.Fatalf("objects=%d, want 3 (only the valid Office documents)", c.objects)
	}

	t.Run("canonical format and normalization are the runtime's", func(t *testing.T) {
		for path, format := range map[string]string{
			"projects/alpha/report.docx": "DOCX",
			"projects/alpha/deck.pptx":   "PPTX",
			"projects/alpha/budget.xlsx": "XLSX",
		} {
			_, _, extractionID := s1dTargetEvidence(t, ctx, admin, path)
			var canonicalFormat, normalization string
			if err := admin.QueryRow(ctx, `SELECT canonical_format, normalization_version
				FROM public.source_extraction WHERE organization_id=$1 AND id=$2`, s1dOrg, extractionID).
				Scan(&canonicalFormat, &normalization); err != nil {
				t.Fatal(err)
			}
			if canonicalFormat != format || normalization != canon.NormalizationVersion {
				t.Fatalf("%s canonical_format/normalization = %s/%s, want %s/%s",
					path, canonicalFormat, normalization, format, canon.NormalizationVersion)
			}
		}
	})

	// Exact structural anchor replay: re-run the document through the sandbox, rebuild
	// every anchor through canon, and require the stored Evidence to match hash for
	// hash. This is the property that makes a DOCX citation resolvable later.
	t.Run("exact structural anchors replay", func(t *testing.T) {
		result, err := runtime.office.Extract(ctx, docparser.FormatDOCX, docx)
		if err != nil {
			t.Fatalf("replay extraction: %v", err)
		}
		_, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/report.docx")
		stored := officeFragments(t, ctx, admin, extractionID)
		if len(stored) != len(result.Fragments) || len(stored) == 0 {
			t.Fatalf("stored fragment count %d != replayed %d", len(stored), len(result.Fragments))
		}
		for i, fragment := range result.Fragments {
			if stored[i].textHash != canon.HMACDigest(s1dDigestKey, 1, fragment.CanonicalText) {
				t.Fatalf("fragment %d text hash does not replay", i+1)
			}
			if stored[i].anchorHash != canon.HMACDigest(s1dDigestKey, 1, fragment.AnchorBytes) {
				t.Fatalf("fragment %d anchor hash does not replay", i+1)
			}
		}
		// The DOCX table cell keeps its own structural position rather than being
		// flattened into the body.
		var sawTableSection bool
		for _, fragment := range result.Fragments {
			if len(fragment.Anchor.SectionPath) > 2 {
				sawTableSection = true
			}
		}
		if !sawTableSection {
			t.Fatal("the table cell did not keep a distinct structural position")
		}
	})

	// The single-owner rule, observed end to end: the document carries decomposed
	// text, and the stored Evidence hashes the precomposed canonical form, because
	// canon — not the sandbox — decided what the canonical bytes are.
	t.Run("the runtime canonicalized the sandbox observation", func(t *testing.T) {
		decomposed := string([]rune{'C', 'a', 'f', 'e', 0x0301, ' ', 'p', 'l', 'a', 'n'})
		precomposed := string([]rune{'C', 'a', 'f', 0x00e9, ' ', 'p', 'l', 'a', 'n'})
		_, _, extractionID := s1dTargetEvidence(t, ctx, admin, "projects/alpha/report.docx")
		stored := officeFragments(t, ctx, admin, extractionID)
		var found bool
		for _, fragment := range stored {
			if fragment.textHash == canon.HMACDigest(s1dDigestKey, 1, []byte(precomposed)) {
				found = true
			}
			if fragment.textHash == canon.HMACDigest(s1dDigestKey, 1, []byte(decomposed)) {
				t.Fatal("Evidence was stored in the document's decomposed form: the runtime did not canonicalize")
			}
		}
		if !found {
			t.Fatal("the canonicalized paragraph is absent from the stored Evidence")
		}
	})

	t.Run("no source document or hostile carrier reaches a durable sink", func(t *testing.T) {
		var leaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.encrypted_artifact
			WHERE organization_id=$1 AND (
				position($2 in encode(ciphertext,'escape')) > 0 OR
				position('evil.example' in encode(ciphertext,'escape')) > 0 OR
				position('vbaProject' in encode(ciphertext,'escape')) > 0 OR
				position('etc/passwd' in encode(ciphertext,'escape')) > 0 OR
				position('PK' in encode(substring(ciphertext from 1 for 2),'escape')) > 0)`,
			s1dOrg, ooxmlCanary).Scan(&leaks); err != nil {
			t.Fatal(err)
		}
		if leaks != 0 {
			t.Fatal("a hostile carrier, an external URL or raw package bytes reached durable storage")
		}
		// Job payloads, job error codes and sync-run rows must stay content-free too:
		// a coded refusal from the sandbox may name a class, never a document.
		var payloadLeaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.job
			WHERE organization_id=$1 AND (
				position($2 in payload_json::text) > 0 OR
				position($2 in coalesce(last_error_code,'')) > 0)`, s1dOrg, ooxmlCanary).Scan(&payloadLeaks); err != nil {
			t.Fatal(err)
		}
		if payloadLeaks != 0 {
			t.Fatal("source content reached a job payload or error code")
		}
		var runLeaks int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.sync_run
			WHERE organization_id=$1 AND (
				position($2 in coalesce(error_code,'')) > 0 OR
				position($2 in coalesce(error_summary,'')) > 0 OR
				position($2 in coalesce(cursor_after,'')) > 0)`, s1dOrg, ooxmlCanary).Scan(&runLeaks); err != nil {
			t.Fatal(err)
		}
		if runLeaks != 0 {
			t.Fatal("source content reached a sync-run row")
		}
	})

	t.Run("repeat sync is deterministic", func(t *testing.T) {
		before := s1dCounts(t, ctx, admin)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "office-resync")
		after := s1dCounts(t, ctx, admin)
		if before != after {
			t.Fatalf("re-sync changed catalog counts: %+v -> %+v", before, after)
		}
	})

	// A new parser profile revision mints a NEW immutable Extraction and switches the
	// active set atomically; it never rewrites the Evidence already published.
	t.Run("profile upgrade is immutable", func(t *testing.T) {
		_, versionID, firstExtraction := s1dTargetEvidence(t, ctx, admin, "projects/alpha/report.docx")
		firstFragments := officeFragments(t, ctx, admin, firstExtraction)

		upgraded := handler.WithParserRevision("docx-v2")
		runSync(t, ctx, upgraded, queue, workerAccess(t, s1dOrg), "office-upgrade")

		_, _, secondExtraction := s1dTargetEvidence(t, ctx, admin, "projects/alpha/report.docx")
		if secondExtraction == firstExtraction {
			t.Fatal("a new profile revision did not mint a new Extraction")
		}
		// Verify the publication boundary itself, not only the convenience
		// resolver above: the active pointer must move to the new immutable
		// Extraction and advance its monotone revision. A second SUCCEEDED row
		// left orphaned behind the historical pointer is not a valid re-extraction.
		var activeExtraction string
		var activationRevision int64
		if err := admin.QueryRow(ctx, `SELECT extraction_id, activation_revision
			FROM public.source_version_active_extraction
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).
			Scan(&activeExtraction, &activationRevision); err != nil {
			t.Fatalf("read active extraction pointer after profile upgrade: %v", err)
		}
		if activeExtraction != secondExtraction || activationRevision < 2 {
			t.Fatalf("profile upgrade did not atomically switch active pointer: extraction=%q want=%q revision=%d", activeExtraction, secondExtraction, activationRevision)
		}
		var extractionCount int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_extraction
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID).Scan(&extractionCount); err != nil {
			t.Fatalf("count version extractions after profile upgrade: %v", err)
		}
		if extractionCount != 2 {
			t.Fatalf("profile upgrade produced %d extractions for one version, want 2", extractionCount)
		}
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/report.docx"); got != "docx-v2" {
			t.Fatalf("active profile revision = %q, want docx-v2", got)
		}
		// The historical Extraction and its Evidence are untouched.
		after := officeFragments(t, ctx, admin, firstExtraction)
		if len(after) != len(firstFragments) {
			t.Fatal("the historical Extraction's Evidence set changed")
		}
		for i := range after {
			if after[i].textHash != firstFragments[i].textHash || after[i].anchorHash != firstFragments[i].anchorHash {
				t.Fatal("a published Evidence fragment was rewritten by the profile upgrade")
			}
		}
		var versions int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version
			WHERE organization_id=$1 AND id=$2`, s1dOrg, versionID).Scan(&versions); err != nil {
			t.Fatal(err)
		}
		if versions != 1 {
			t.Fatal("the profile upgrade created a new SourceVersion for unchanged bytes")
		}
	})
}

// TestS2bOfficeSandboxFailureAtomicity proves the failure modes of a hostile
// data-plane component are non-events for the catalog: a real worker that is
// fenced by its caller deadline, or a missing dispatcher boundary, produces a
// quarantine and no Evidence — never a partially published Extraction and never
// a failed sync run.
func TestS2bOfficeSandboxFailureAtomicity(t *testing.T) {
	ctx := context.Background()
	t.Run("wall clock exceeded", func(t *testing.T) {
		runtime := newProductionParserRuntime(t)
		// Keep the production facade's exact request tuple and exercise the real
		// dispatcher with a caller deadline shorter than worker startup. No parser
		// result can cross the boundary after this deadline, so the object must
		// quarantine while the neighbouring text object still completes.
		deadlineOffice := officeWithDeadline{office: runtime.office, timeout: 50 * time.Millisecond}
		admin := resetStage1Database(t)
		codec := s1dCodec(t, s1dOrg)
		root := t.TempDir()
		dir := filepath.Join(root, "projects", "alpha")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "report.docx"), validDOCX(t), 0o644); err != nil {
			t.Fatal(err)
		}
		writeS1dFile(t, filepath.Join(dir, "notes.txt"), "a plain text neighbour")

		seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
		configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
		// The claim-time liveness re-check (000018 s5) needs a live confirmation.
		seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
			s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
		workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
		queue, _ := jobs.New(workerStore)
		handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
			WithOfficeExtractor(deadlineOffice)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "office-failure")

		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/report.docx"); got != "" {
			t.Fatalf("a failed sandbox published an Extraction: %q", got)
		}
		// The neighbouring object still ingested: one document's sandbox failure is
		// a per-object quarantine, not a sync-run failure.
		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/notes.txt"); got != "text-v1" {
			t.Fatalf("the sync run did not continue past the quarantine: notes.txt profile %q", got)
		}
		var fragments int
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment
				WHERE organization_id=$1`, s1dOrg).Scan(&fragments); err != nil {
			t.Fatal(err)
		}
		if fragments == 0 {
			t.Fatal("the text neighbour produced no Evidence at all")
		}
	})

	t.Run("no sandbox configured", func(t *testing.T) {
		admin := resetStage1Database(t)
		codec := s1dCodec(t, s1dOrg)
		root := t.TempDir()
		dir := filepath.Join(root, "projects", "alpha")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "report.docx"), validDOCX(t), 0o644); err != nil {
			t.Fatal(err)
		}
		seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
		configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
		// The claim-time liveness re-check (000018 s5) needs a live confirmation.
		seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
			s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
		workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
		queue, _ := jobs.New(workerStore)
		// Deliberately no WithOfficeExtractor: there is no in-process fallback parser.
		handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "office-nosandbox")

		if got := s2aActiveRevision(t, ctx, admin, "projects/alpha/report.docx"); got != "" {
			t.Fatalf("an Office document was extracted without a sandbox: %q", got)
		}
	})
}
