package postgres_test

// Real-PostgreSQL regression coverage for the FIN-1 demo-readiness defect
// ("confirmation reset"), the app.evidence_fragment_readable half of it:
// this predicate (000014, last replaced by 000020, fixed by 000077) had the
// exact same coupling as app.source_scope_activation_confirmed (000018,
// fixed by 000076) -- it required the confirmation's own recorded
// workspace_revision to equal workspace.current_revision. Because every
// workspace configuration mutation (enabling/disabling ANY source, issuing an
// access code, a membership change) advances current_revision, this made
// EVERY evidence fragment of EVERY confirmed source unreadable the instant
// any one of them changed -- the owner-reported symptom "answers arrive
// without citations" after a few unrelated actions in "Sources". This is
// the more directly demo-visible half of the defect: it gates every
// citation, and AGG-1's loadStructuredSnapshot calls this same function per
// structured-snapshot cell.
//
// This test seeds one real, confirmed, synced WORKSPACE_MANAGED source
// through the production ingestion pipeline (seedS1dWorkspaceBinding +
// ingestion.Handler, exactly like TestEvidenceReadableGateRejectsForeign
// WorkspaceAndSourceEnforced in the same package), so the fragment id and its
// authorization chain are real, not hand-forged. It then advances the
// workspace revision the same way TestExplicitSourceReconfirmationStale
// ReconfirmRevokeReplay's advanceManagedWorkspaceRevision does -- carrying the
// SAME binding tuple forward unchanged, modelling a mutation that touches
// something else in the workspace (another source, a membership, an access
// code) but not this scope -- and calls the real product predicate directly,
// never a test-local reimplementation.

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestEvidenceFragmentReadableSurvivesUnrelatedWorkspaceMutation proves the
// fix: a real, confirmed source's evidence fragment stays readable after the
// workspace's current_revision advances for a reason that does not touch
// this scope's own binding tuple.
func TestEvidenceFragmentReadableSurvivesUnrelatedWorkspaceMutation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "line one\nline two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	scopeConfigHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, scopeConfigHash)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "sync")

	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded")
	}
	fragmentID := fragments[0].id

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	readable := func() bool {
		t.Helper()
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, s1dOrg, s1dViewer)
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, s1dWorkspace).Scan(&ok); err != nil {
			t.Fatalf("readable gate: %v", err)
		}
		return ok
	}

	if !readable() {
		t.Fatal("evidence_fragment_readable is false right after a real confirm+sync, before any further mutation")
	}

	// A workspace revision advance that carries this scope's own binding
	// tuple forward UNCHANGED -- exactly what enabling/disabling a different
	// source, issuing an access code or changing membership all do to every
	// binding's projection row (000008's copy-forward exact-set guard). This
	// scope's own confirmation was never touched.
	advanceManagedWorkspaceRevision(t, ctx, admin, fixture)

	if !readable() {
		t.Fatal("evidence_fragment_readable went false after an UNRELATED workspace revision advance -- FIN-1 regression: a foreign workspace mutation must not make every source's citations unreadable")
	}
}
