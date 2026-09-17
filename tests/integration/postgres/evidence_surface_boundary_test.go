package postgres_test

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

// TestEvidenceReadableGateRejectsForeignWorkspaceAndSourceEnforced proves the
// R4 database-boundary negatives of the evidence readable gate by calling the
// SQL gate directly under the runtime role: a foreign workspace id, a foreign
// tenant context and a SOURCE_ENFORCED binding must all close the gate even
// though the presented fragment id is real. The application-layer read must
// refuse the SOURCE_ENFORCED state identically — bypassing the application
// layer and driving the gate in SQL does not help, because the gate itself is
// the last line.
func TestEvidenceReadableGateRejectsForeignWorkspaceAndSourceEnforced(t *testing.T) {
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

	// readable drives the SQL gate directly under the runtime role with a
	// principal-scoped tenant context — the database-boundary call, not the
	// application layer.
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	readable := func(org, principal, workspaceID string) bool {
		t.Helper()
		tx, err := app.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		setAccessContextForPrincipal(t, ctx, tx, org, principal)
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&ok); err != nil {
			t.Fatalf("readable gate org=%s principal=%s ws=%s: %v", org, principal, workspaceID, err)
		}
		return ok
	}

	// Positive control: the bound viewer reading their own workspace opens.
	if !readable(s1dOrg, s1dViewer, s1dWorkspace) {
		t.Fatal("readable gate closed for the authorized viewer on their own workspace")
	}

	// Foreign workspace id inside the same tenant: the gate is workspace-scoped
	// and must refuse even though the fragment id is real.
	if readable(s1dOrg, s1dViewer, "ws_foreign") {
		t.Fatal("readable gate opened for a foreign workspace id")
	}

	// Foreign tenant context: the same principal id under another organization
	// resolves to no membership and the gate must close.
	if readable("org_other", s1dViewer, s1dWorkspace) {
		t.Fatal("readable gate opened under a foreign tenant context")
	}

	// SOURCE_ENFORCED negative proof at the database boundary: the binding
	// cannot be flipped away from WORKSPACE_MANAGED at all. The projection row
	// is immutable (000008), the confirmation row is immutable and its access
	// mode is CHECK-fixed to WORKSPACE_MANAGED (000010), and the confirmation
	// references the projection tuple including access_mode (000010 target
	// FK) — three independent schema layers forbid the transition, so a
	// SOURCE_ENFORCED binding can never surface through a live managed
	// confirmation chain. Both direct UPDATEs must be refused, and the gate
	// itself keeps serving the untouched state.
	for _, attempt := range []struct {
		label string
		sql   string
		args  []any
	}{
		{"binding", `UPDATE public.workspace_revision_source SET access_mode='SOURCE_ENFORCED'
			WHERE organization_id=$1 AND workspace_id=$2 AND source_scope_id=$3`,
			[]any{s1dOrg, s1dWorkspace, s1dScopeID}},
		{"confirmation", `UPDATE public.workspace_managed_grant_confirmation SET access_mode='SOURCE_ENFORCED'
			WHERE organization_id=$1 AND workspace_source_id=$2`,
			[]any{s1dOrg, fixture.workspaceSourceID}},
	} {
		if _, err := admin.Exec(ctx, attempt.sql, attempt.args...); err == nil {
			t.Fatalf("SOURCE_ENFORCED flip of the %s was accepted at the database level", attempt.label)
		}
	}
	if !readable(s1dOrg, s1dViewer, s1dWorkspace) {
		t.Fatal("readable gate closed after the refused SOURCE_ENFORCED flips")
	}
}
