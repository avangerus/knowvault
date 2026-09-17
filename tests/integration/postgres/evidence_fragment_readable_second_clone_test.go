package postgres_test

// FIX-3 #3 real-PostgreSQL regression coverage for the "source disabled ->
// citations still appear" defect FACTS recorded as flaky on the acc stand.
// Root cause, confirmed live on acc (2026-09-08): demo1-acceptance.mjs's own
// "fresh identity" FOLDER registration step never disabled its own scope at
// the end of a run, so every acceptance run left behind ANOTHER permanently
// enabled clone of the identical demo corpus bound to the same shared
// workspace -- dozens accumulated, several simultaneously enabled. The later
// "disable the EXISTING scope -> expect no citations" assertion then answers
// from whichever OTHER still-enabled clone happens to carry the same content,
// not from the scope it just disabled. That is a test-fixture hygiene bug
// (fixed in knowvault-demo1-acceptance.mjs: the fresh scope is now disabled
// right after its own assertions run), not a defect in the authorization
// boundary itself.
//
// This test proves the boundary side of that conclusion with real Postgres:
// two independent workspace bindings can make the SAME evidence fragment
// readable (TestS1dOverlappingScopes' "shared object, two ACTIVE
// memberships" shape -- exactly the "second active clone" condition), and the
// production RemoveSource path ("DELETE binding", what the acc stand's
// "Disable" button and demo1-acceptance.mjs's disable step both call)
// narrows readability exactly as far as the surviving enabled bindings allow:
// disabling ONE binding while the OTHER remains enabled must NOT make the
// shared fragment unreadable (that binding never granted exclusive control),
// but disabling BOTH must. A regression that made app.evidence_fragment_
// readable ignore a binding's own current enabled flag (the literal "second
// clone" failure mode) would make the first assertion below correctly pass
// but the second one -- the one that actually matters for "disabled -> no
// citations" -- fail.
import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
)

// disableOneOfTwoCloneBindings advances the workspace to a fresh revision that
// carries BOTH bindings' rows forward from fromRevision, flipping enabled to
// false for exactly targetScopeID and leaving the other binding's own enabled
// flag untouched -- the real "DELETE binding" effect
// (internal/workspace/repository.RemoveSource), applied directly against the
// gating table (public.workspace_revision_source) the way
// TestSnapshotAggregateExcludesSourceDisabledInThisWorkspace's own comment
// describes RemoveSource's effect, for a fixture (catalog_evidence_seed_test.go's
// s1d* helpers) whose workspace_revision_snapshot is deliberately the inert
// '{}' document (not a real canonical snapshot), so the domain repository's own
// Get/RemoveSource cannot be used against it -- this seeds the SAME two tables
// (workspace_revision, workspace_revision_source) those commands themselves
// write, keyed off the two real bindings this test created.
func disableOneOfTwoCloneBindings(t *testing.T, ctx context.Context, admin *pgxpool.Pool, fromRevision int64, targetScopeID string) int64 {
	t.Helper()
	newRevision := fromRevision + 1
	type bindingRow struct {
		workspaceSourceID, sourceScopeID, scopeConfigHash string
		sourceScopeRevision                               int64
		enabled                                            bool
	}
	rows, err := admin.Query(ctx, `SELECT workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $3
		ORDER BY source_scope_id`, s1dOrg, s1dWorkspace, fromRevision)
	if err != nil {
		t.Fatalf("read current revision bindings: %v", err)
	}
	var bindings []bindingRow
	for rows.Next() {
		var row bindingRow
		if err := rows.Scan(&row.workspaceSourceID, &row.sourceScopeID, &row.sourceScopeRevision, &row.scopeConfigHash, &row.enabled); err != nil {
			rows.Close()
			t.Fatalf("scan binding: %v", err)
		}
		if row.sourceScopeID == targetScopeID {
			row.enabled = false
		}
		bindings = append(bindings, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected exactly 2 bindings at revision %d, got %d", fromRevision, len(bindings))
	}

	memberList := []workspace.Member{{PrincipalID: s1dOwner, Role: workspace.RoleOwner}, {PrincipalID: s1dViewer, Role: workspace.RoleMember}}
	bindingList := make([]workspace.SourceBinding, 0, len(bindings))
	for _, binding := range bindings {
		bindingList = append(bindingList, workspace.SourceBinding{
			SourceScopeID: binding.sourceScopeID, SourceScopeRevision: binding.sourceScopeRevision,
			ScopeConfigHash: binding.scopeConfigHash, Enabled: binding.enabled,
		})
	}
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: s1dOrg, ID: s1dWorkspace, Revision: newRevision,
		Name: s1dWorkspace, Status: workspace.StatusActive, OwnerPrincipalID: s1dOwner,
		Members: memberList, SourceBindings: bindingList,
	})
	if err != nil {
		t.Fatalf("normalize advanced workspace snapshot: %v", err)
	}
	newHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("advanced workspace configuration hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("advanced workspace canonical snapshot: %v", err)
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)`, s1dOrg, s1dWorkspace, newRevision, newHash, s1dOwner); err != nil {
		t.Fatalf("insert advanced workspace revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, $3, $4, $5)`, s1dOrg, s1dWorkspace, newRevision, newHash, canonicalBytes); err != nil {
		t.Fatalf("insert advanced workspace snapshot: %v", err)
	}
	for _, binding := range bindings {
		if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_revision_source (
				organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
				workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'WORKSPACE_MANAGED', $9)`,
			s1dOrg, s1dWorkspace, newRevision, newHash,
			binding.workspaceSourceID, binding.sourceScopeID, binding.sourceScopeRevision, binding.scopeConfigHash, binding.enabled); err != nil {
			t.Fatalf("carry binding %s onto advanced revision: %v", binding.sourceScopeID, err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision = $3 WHERE organization_id = $1 AND id = $2`,
		s1dOrg, s1dWorkspace, newRevision); err != nil {
		t.Fatalf("advance workspace current revision: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace revision advance: %v", err)
	}
	return newRevision
}

func TestEvidenceFragmentReadableNarrowsAsEachDuplicateBindingIsDisabled(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "duplicate clone line one\nduplicate clone line two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)

	// scope1 (s1dScopeID) and scope2 are two INDEPENDENT bindings (own
	// binding ids, own confirmations) that both resolve to the SAME
	// underlying file -- the exact "second active clone" shape
	// TestS1dOverlappingScopes documents, here used to prove the disable path
	// rather than the catalog dedup it proves.
	configHash1 := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash1, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_clone1", "confirmation_s1d_clone1")
	scope2, _ := seedS1dSecondScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, scope2, 1,
		"binding_02ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_clone2", "confirmation_s1d_clone2")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	access := workerAccess(t, s1dOrg)
	runSyncScope(t, ctx, handler, queue, access, s1dScopeID, "clone1-sync")
	runSyncScope(t, ctx, handler, queue, access, scope2, "clone2-sync")

	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments produced")
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
		t.Fatal("fragment must be readable while both duplicate clone bindings are enabled")
	}

	// Disable clone1's binding (the real "DELETE binding" effect, see
	// disableOneOfTwoCloneBindings). Clone2's binding is untouched and still
	// enabled, and it independently authorizes the SAME shared fragment: this
	// must still be readable. If it were not, this test would be indifferent
	// to the actual defect class (it would look identical whether or not the
	// gate correctly used the CURRENT per-binding enabled flag).
	revision := disableOneOfTwoCloneBindings(t, ctx, admin, 1, s1dScopeID)
	if !readable() {
		t.Fatal("disabling clone1's binding must not revoke a fragment clone2's own still-enabled binding independently authorizes")
	}

	// Now disable clone2's binding too -- no enabled binding authorizes this
	// fragment through either clone any more, so it must become unreadable.
	// This is the assertion the acc regression actually violated: a
	// "disabled -> no citations" check must observe THIS state, not a state
	// where some OTHER still-enabled duplicate keeps the answer alive.
	disableOneOfTwoCloneBindings(t, ctx, admin, revision, scope2)
	if readable() {
		t.Fatal("fragment stayed readable after BOTH duplicate clone bindings were disabled -- the exact demo1-acceptance regression: a disabled scope's evidence must not be citable once no enabled binding authorizes it")
	}
}
