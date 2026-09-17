package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/tests/integration/parserv2harness"
)

// TestS2bWorkerSwapMintsNewExtraction keeps the historical qualification name while
// proving the production worker identity is attested and stable. A fresh Java
// process is started for every object by the external supervisor; because both
// processes present the same artifact/profile tuple, an unchanged object correctly
// reuses its immutable Extraction. A parser-profile upgrade still mints a new
// Extraction below, while the worker identity remains visible in fragment metadata.
func TestS2bWorkerSwapMintsNewExtraction(t *testing.T) {
	runtime := newProductionParserRuntime(t)
	ctx := context.Background()
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
	const path = "projects/alpha/report.docx"
	newHandler := func() *ingestion.Handler {
		t.Helper()
		return ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New).
			WithOfficeExtractor(runtime.office)
	}

	runSync(t, ctx, newHandler(), queue, workerAccess(t, s1dOrg), "worker-identity-first")
	_, versionID, firstExtraction := s1dTargetEvidence(t, ctx, admin, path)
	firstFragments := officeFragments(t, ctx, admin, firstExtraction)
	if len(firstFragments) == 0 {
		t.Fatal("the first sync published no Evidence")
	}
	if got := s2aActiveRevision(t, ctx, admin, path); got != "docx-v1" {
		t.Fatalf("parser_profile_revision = %q, want docx-v1", got)
	}

	// Re-running the same production facade must not mint anything: the identity
	// binding must discriminate a real observer change, not make every sync produce
	// a new Extraction.
	runSync(t, ctx, newHandler(), queue, workerAccess(t, s1dOrg), "worker-identity-resync")
	if _, _, again := s1dTargetEvidence(t, ctx, admin, path); again != firstExtraction {
		t.Fatal("an unchanged observer minted a new Extraction: the short-circuit no longer holds")
	}

	// The production facade is code-locked to the exact artifact and observation
	// profile. A fresh one-shot Java process therefore remains the same observer
	// identity even though its PID and pidfd are new.
	runSync(t, ctx, newHandler(), queue, workerAccess(t, s1dOrg), "worker-identity-fresh-process")

	_, swappedVersionID, secondExtraction := s1dTargetEvidence(t, ctx, admin, path)
	if secondExtraction != firstExtraction {
		t.Fatal("a fresh process with the same attested worker identity minted a new Extraction")
	}
	if got := s2aActiveRevision(t, ctx, admin, path); got != "docx-v1" {
		t.Fatalf("the fresh worker changed parser_profile_revision to %q", got)
	}
	if swappedVersionID != versionID {
		t.Fatal("the worker swap created a new SourceVersion for unchanged bytes")
	}

	// The unchanged object keeps one profile hash and one source version.
	var firstHash, secondHash string
	if err := admin.QueryRow(ctx, `SELECT profile_hash FROM public.source_extraction
		WHERE organization_id=$1 AND id=$2`, s1dOrg, firstExtraction).Scan(&firstHash); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT profile_hash FROM public.source_extraction
		WHERE organization_id=$1 AND id=$2`, s1dOrg, secondExtraction).Scan(&secondHash); err != nil {
		t.Fatal(err)
	}
	if firstHash != secondHash {
		t.Fatal("the same attested worker identity changed the extraction profile hash")
	}
	var profileJSON string
	if err := admin.QueryRow(ctx, `SELECT profile_json::text FROM public.source_extraction
		WHERE organization_id=$1 AND id=$2`, s1dOrg, firstExtraction).Scan(&profileJSON); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(profileJSON) == "" {
		t.Fatal("production extraction omitted its immutable observer profile")
	}
	if !strings.Contains(profileJSON, "docx-v1") {
		t.Fatal("production extraction profile omitted parser revision")
	}
	probe, err := runtime.office.Extract(ctx, docparser.FormatDOCX, validDOCX(t))
	if err != nil {
		t.Fatalf("fresh one-shot worker identity probe: %v", err)
	}
	if probe.Parser.ArtifactHash != parserv2harness.QualifiedArtifactHash ||
		probe.Parser.ObservationProfileRevision != "office-obs-v1" || probe.Parser.RuntimeProfileHash == "" {
		t.Fatalf("production worker identity attestation drifted: %#v", probe.Parser)
	}

	// The historical Extraction is immutable: a fresh observer never reinterprets
	// Evidence that was already published under the old identity.
	after := officeFragments(t, ctx, admin, firstExtraction)
	if len(after) != len(firstFragments) {
		t.Fatal("the historical Extraction's Evidence set changed")
	}
	for i := range after {
		if after[i].textHash != firstFragments[i].textHash || after[i].anchorHash != firstFragments[i].anchorHash {
			t.Fatal("a published Evidence fragment was rewritten by the worker swap")
		}
	}
}
