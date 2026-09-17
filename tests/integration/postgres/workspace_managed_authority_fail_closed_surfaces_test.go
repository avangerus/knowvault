package postgres_test

// rest-mcp-fail-closed (r53 line explicit-source-reconfirmation): once a
// WORKSPACE_MANAGED confirmation is revoked — or the source it names is
// disabled — both operator-visible answer surfaces must stop disclosing the
// confirmed source and return the identical content-free not-found, with no
// existence oracle. An UNRELATED workspace mutation (a different source
// toggled, an access code issued, membership changed) must NOT do the same
// (FIN-1, migrations 000076/000077): only revoking the confirmation, or a
// mutation that changes THIS scope's own binding tuple, may close the gate.
//
// Both surfaces reduce, in production, to the same database-boundary gate
// app.evidence_fragment_readable(fragment_id, workspace_id):
//
//   - the REST Evidence GET route is served by the evidence Viewer
//     (internal/source/evidence.Viewer.Read, wired through the workspaceapi
//     EvidenceService.Read), which calls app.evidence_fragment_readable before
//     it fetches any ciphertext; every denial collapses to ErrNotFound.
//   - the retrieval gate behind the MCP knowvault_question tool filters every
//     answerable fragment through the same app.evidence_fragment_readable
//     predicate in internal/retrieval/repository.go (and the question-run /
//     citation binding guards in 000024/000044), so a closed gate yields no
//     candidate context and no citation content.
//
// This test drives the real evidence Viewer (REST surface) and the exact
// production retrieval-gate predicate (MCP surface) against real PostgreSQL:
// before a revocation the confirmed source is answered, and after a
// revocation and after disabling the source itself both transports return the
// same content-free NOT_FOUND while the evidence row itself remains in the
// catalog (content is withheld by the gate, never deleted — no existence
// oracle). Revocation, confirmation and the disable/re-enable cycle go
// through the production authority and source-plane runtime
// (RevokeManagedConfirmation / IssueConfirmationGrant / ConfirmManagedSource /
// RemoveSource / AddSource), never through raw INSERT forgery; the evidence
// chain is built by the real worker sync pipeline so the "answers the
// confirmed source" control is real.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// managedAnswerGate reports whether the real retrieval gate that both the REST
// Evidence GET route and the MCP knowvault_question tool reduce to opens for a
// given fragment in a workspace, evaluated under the app runtime role with a
// transaction-local principal context. A false result is the answer-surface
// NOT_FOUND: no content disclosure and no distinguishable existence oracle.
func managedAnswerGate(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, workspaceID, fragmentID string) bool {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatalf("begin answer-gate read: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&ok); err != nil {
		t.Fatalf("answer-gate org=%s principal=%s ws=%s fragment=%s: %v", organizationID, principalID, workspaceID, fragmentID, err)
	}
	return ok
}

// evidenceFragmentStillInCatalog proves the row is not deleted: the content-free
// NOT_FOUND comes from the fail-closed gate, not from row removal (no existence
// oracle is created by revocation or staleness).
func evidenceFragmentStillInCatalog(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, fragmentID string) bool {
	t.Helper()
	var present bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM public.evidence_fragment WHERE organization_id=$1 AND id=$2)`,
		organizationID, fragmentID).Scan(&present); err != nil {
		t.Fatalf("probe evidence fragment catalog presence: %v", err)
	}
	return present
}

// TestManagedSourceAnswerSurfacesFailClosedAfterRevocationOrStale proves the
// operator-visible answer surfaces stay fail-closed when a WORKSPACE_MANAGED
// confirmation is revoked, or when the source it names is disabled (its own
// binding tuple changes -- fail-closed for the scope that actually mutated,
// unchanged by 000076/000077). It also proves the disable/re-enable recovery
// cycle: re-enabling the same scope reopens both the real REST evidence
// Viewer and the MCP retrieval gate app.evidence_fragment_readable off the
// SAME still-live, unrevoked confirmation issued before the disable -- no
// fresh ConfirmManagedSource call is needed, because 000076/000077 key
// liveness to the scope's own current binding tuple rather than to the
// confirmation's own recorded workspace revision.
func TestManagedSourceAnswerSurfacesFailClosedAfterRevocationOrStale(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	// Build a real, worker-synced WORKSPACE_MANAGED evidence chain with a live
	// production confirmation (seedS1dScopeAuthority mints it through the
	// authority runtime), so "the same request before revocation answers" is a
	// genuine content-bearing control.
	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(fileDir, "notes.txt"), "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "fail-closed-surfaces")

	_, _, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) == 0 {
		t.Fatal("no evidence fragments seeded for the managed source")
	}
	fragmentID := fragments[0].id

	// The real evidence Viewer is the REST Evidence GET dependency.
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	surfaceAccess := authorityAccess(fixture, fixture.ownerID, "req_fail_closed_surface_read")

	// The MCP retrieval-gate predicate is evaluated under the app role exactly
	// as the MCP retrieval path consumes it.
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	// The authority runtime driving revocation/re-confirmation in production.
	store := newAuthorityRuntime(t, ctx)

	// Phase 0 — live confirmation, before any revocation: both transports
	// answer the confirmed source (the positive control).
	if !liveConfirmationExists(t, ctx, admin, fixture) {
		t.Fatal("no live confirmation present on the seeded managed source")
	}
	if !managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate was closed for a confirmed source before any revocation")
	}
	restFragment, err := viewer.Read(ctx, surfaceAccess, fixture.workspaceID, fragmentID)
	if err != nil {
		t.Fatalf("REST evidence viewer refused a confirmed source before revocation: %v", err)
	}
	if len(restFragment.Text) == 0 {
		t.Fatal("REST evidence viewer returned empty content for a confirmed source")
	}

	// Load the live confirmation (minted by the seed) so we can revoke it
	// through the production runtime, not by raw SQL.
	confirmationID, confirmationHash := loadLiveManagedConfirmation(t, ctx, admin, fixture)

	// Phase 1 — revocation: after RevokeManagedConfirmation, both transports
	// must return the same content-free NOT_FOUND.
	if _, err := store.RevokeManagedConfirmation(ctx,
		authorityAccess(fixture, fixture.ownerID, "req_fail_closed_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("fail-closed-surfaces-revoke"),
			OrganizationID: fixture.organizationID, WorkspaceID: fixture.workspaceID,
			ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke the live managed confirmation: %v", err)
	}
	if managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate stayed open after the confirmation was revoked")
	}
	if _, err := viewer.Read(ctx, surfaceAccess, fixture.workspaceID, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("REST evidence viewer after revocation err=%v, want the content-free ErrNotFound", err)
	}
	if !evidenceFragmentStillInCatalog(t, ctx, admin, fixture.organizationID, fragmentID) {
		t.Fatal("revocation deleted the evidence row — the NOT_FOUND came from row removal, an existence oracle")
	}

	// Phase 2 — re-open control: revoke-then-re-confirm the current revision is
	// a normal operator cycle. Issue exactly ONE confirmation grant (at the
	// current, original revision) and re-confirm that same revision through the
	// runtime (the revoked seed is excluded from the live guard). This single
	// lifecycle grant is reused unchanged after the advance below — never a fresh
	// grant bound to the stale original revision.
	lifecycleGrant := issueRuntimeGrant(t, ctx, store, fixture, "fail-closed-surfaces-lifecycle")
	first, err := store.ConfirmManagedSource(ctx,
		authorityAccess(fixture, fixture.ownerID, "req_fail_closed_reopen"),
		confirmRuntimeRequest(fixture, lifecycleGrant, "fail-closed-surfaces-reopen"))
	if err != nil {
		t.Fatalf("re-confirm the current revision after revocation: %v", err)
	}
	if !derivedLive(ctx, admin, fixture.organizationID, first.ResultID) {
		t.Fatal("re-opened row is not derived-live at its current revision")
	}
	if !managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate stayed closed after re-confirming the current revision")
	}

	// Phase 3 — own-scope mutation: disabling the very source this
	// confirmation names must still stale it. 000076/000077 stop an UNRELATED
	// workspace mutation from staling a confirmation, but a mutation that
	// touches THIS scope's own binding (enabled -> disabled) still changes the
	// current-revision binding tuple the confirmation must match, so both
	// answer surfaces must go fail-closed exactly as before.
	//
	// The revision advance is seeded directly (advanceManagedWorkspaceRevision
	// SettingBindingEnabled below), exactly like the workspace revision advance
	// elsewhere in this test family: this fixture's revision-1 canonical
	// snapshot is the INERT '{}' fixture (seedS1dScopeAuthority's own doc
	// comment), so the production workspace-plane commands (store.Get /
	// RemoveSource / AddSource, which decode the existing snapshot) cannot run
	// against it -- only a freshly-built canonical snapshot, produced the same
	// way advanceManagedWorkspaceRevision already does, can move it forward.
	disabledRevision, _ := advanceManagedWorkspaceRevisionSettingBindingEnabled(t, ctx, admin, fixture, fixture.workspaceRevision, false)
	if managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate stayed open after disabling its own confirmed source")
	}
	if _, err := viewer.Read(ctx, surfaceAccess, fixture.workspaceID, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("REST evidence viewer for a disabled source err=%v, want the content-free ErrNotFound", err)
	}
	if !evidenceFragmentStillInCatalog(t, ctx, admin, fixture.organizationID, fragmentID) {
		t.Fatal("disabling the source deleted the evidence row — the NOT_FOUND came from row removal, an existence oracle")
	}

	// Phase 4 — re-enable reopens both surfaces immediately, off the SAME
	// still-live, unrevoked confirmation from Phase 2 (first): 000076/000077
	// make the reopened binding's tuple (source_scope_id, source_scope_revision,
	// scope_config_hash, access_mode, enabled) match that confirmation again --
	// no workspace-revision coincidence required, unlike before this fix, where
	// a fresh confirmation naming the new revision was the only way back in
	// (the production re-enable path itself, managedReenableConfirmationLive,
	// is proved separately and in full by workspace_managed_source_reenable_
	// test.go; this phase only proves the READ-SIDE predicate this fix changed).
	advanceManagedWorkspaceRevisionSettingBindingEnabled(t, ctx, admin, fixture, disabledRevision, true)
	if !managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate stayed closed after re-enabling with a live confirmation")
	}
	reopenedFragment, err := viewer.Read(ctx, surfaceAccess, fixture.workspaceID, fragmentID)
	if err != nil {
		t.Fatalf("REST evidence viewer refused the confirmed fragment after re-enabling: %v", err)
	}
	if len(reopenedFragment.Text) == 0 {
		t.Fatal("REST evidence viewer returned empty content after re-enabling")
	}

	// Phase 5 — revoking that SAME confirmation (first) closes both answer
	// surfaces again while the evidence fragment row stays in the catalog
	// (confirmation-revocation fail-closed, no existence oracle).
	if _, err := store.RevokeManagedConfirmation(ctx,
		authorityAccess(fixture, fixture.ownerID, "req_fail_closed_revoke_reenabled"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("fail-closed-surfaces-revoke-reenabled"),
			OrganizationID: fixture.organizationID, WorkspaceID: fixture.workspaceID,
			ConfirmationID: first.ResultID, ConfirmationHash: first.ResultHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke the re-enabled source's confirmation: %v", err)
	}
	if managedAnswerGate(t, ctx, app, fixture.organizationID, fixture.ownerID, fixture.workspaceID, fragmentID) {
		t.Fatal("MCP retrieval gate stayed open after the re-enabled source's confirmation was revoked")
	}
	if _, err := viewer.Read(ctx, surfaceAccess, fixture.workspaceID, fragmentID); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("REST evidence viewer after revoking the re-enabled source's confirmation err=%v, want the content-free ErrNotFound", err)
	}
	if !evidenceFragmentStillInCatalog(t, ctx, admin, fixture.organizationID, fragmentID) {
		t.Fatal("revoking the re-enabled source's confirmation deleted the evidence row — the NOT_FOUND came from row removal, an existence oracle")
	}
}

// advanceManagedWorkspaceRevisionSettingBindingEnabled is
// advanceManagedWorkspaceRevision (workspace_managed_authority_
// reconfirmation_test.go), generalized to take an explicit "from" revision
// (so it can be called twice in sequence against the same fixture) and to
// override the fixture's own binding's enabled flag when carrying it forward
// -- modelling a mutation that touches THIS scope's own binding, the
// counterpart to advanceManagedWorkspaceRevision's own "carries every
// binding forward unchanged" (an unrelated mutation).
func advanceManagedWorkspaceRevisionSettingBindingEnabled(
	t *testing.T, ctx context.Context, admin *pgxpool.Pool, fixture authorityOpsFixture,
	fromRevision int64, enabled bool,
) (int64, string) {
	t.Helper()
	newRevision := fromRevision + 1

	type memberRow struct{ principalID, role string }
	var members []memberRow
	memberRows, err := admin.Query(ctx, `SELECT principal_id, role FROM public.workspace_member
		WHERE organization_id = $1 AND workspace_id = $2 AND removed_at IS NULL
		ORDER BY principal_id`, fixture.organizationID, fixture.workspaceID)
	if err != nil {
		t.Fatalf("read workspace members: %v", err)
	}
	for memberRows.Next() {
		var row memberRow
		if err := memberRows.Scan(&row.principalID, &row.role); err != nil {
			memberRows.Close()
			t.Fatalf("scan member: %v", err)
		}
		members = append(members, row)
	}
	memberRows.Close()
	if err := memberRows.Err(); err != nil {
		t.Fatalf("iterate members: %v", err)
	}

	type bindingRow struct {
		sourceScopeID       string
		sourceScopeRevision int64
		scopeConfigHash     string
		enabled             bool
	}
	var bindings []bindingRow
	bindingQuery, err := admin.Query(ctx, `SELECT source_scope_id, source_scope_revision, scope_config_hash, enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $3
		ORDER BY source_scope_id`, fixture.organizationID, fixture.workspaceID, fromRevision)
	if err != nil {
		t.Fatalf("read current revision bindings: %v", err)
	}
	for bindingQuery.Next() {
		var row bindingRow
		if err := bindingQuery.Scan(&row.sourceScopeID, &row.sourceScopeRevision, &row.scopeConfigHash, &row.enabled); err != nil {
			bindingQuery.Close()
			t.Fatalf("scan binding: %v", err)
		}
		if row.sourceScopeID == fixture.sourceScopeID {
			row.enabled = enabled
		}
		bindings = append(bindings, row)
	}
	bindingQuery.Close()
	if err := bindingQuery.Err(); err != nil {
		t.Fatalf("iterate bindings: %v", err)
	}

	memberList := make([]workspace.Member, 0, len(members))
	for _, member := range members {
		memberList = append(memberList, workspace.Member{PrincipalID: member.principalID, Role: workspace.Role(member.role)})
	}
	bindingList := make([]workspace.SourceBinding, 0, len(bindings))
	for _, binding := range bindings {
		bindingList = append(bindingList, workspace.SourceBinding{
			SourceScopeID: binding.sourceScopeID, SourceScopeRevision: binding.sourceScopeRevision,
			ScopeConfigHash: binding.scopeConfigHash, Enabled: binding.enabled,
		})
	}

	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: fixture.organizationID, ID: fixture.workspaceID, Revision: newRevision,
		Name: fixture.workspaceID, Status: workspace.StatusActive, OwnerPrincipalID: fixture.ownerID,
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
		t.Fatalf("begin revision advance: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1, $2, $3, $4, $5)`, fixture.organizationID, fixture.workspaceID, newRevision, newHash, fixture.ownerID); err != nil {
		t.Fatalf("insert advanced workspace revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1, $2, $3, $4, $5)`, fixture.organizationID, fixture.workspaceID, newRevision, newHash, canonicalBytes); err != nil {
		t.Fatalf("insert advanced workspace snapshot: %v", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.workspace_revision_source (
			organization_id, workspace_id, workspace_revision, workspace_configuration_hash,
			workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled
		)
		SELECT $1, $2, $3, $4, workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode, $6
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $5`,
		fixture.organizationID, fixture.workspaceID, newRevision, newHash, fromRevision, enabled); err != nil {
		t.Fatalf("carry source projection onto advanced revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.workspace SET current_revision = $3
		WHERE organization_id = $1 AND id = $2`, fixture.organizationID, fixture.workspaceID, newRevision); err != nil {
		t.Fatalf("advance workspace current revision: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit workspace revision advance: %v", err)
	}
	return newRevision, newHash
}

// liveConfirmationExists reports whether any confirmation row is present for the
// fixture (used to make the Phase-0 control readable before we load its id/hash).
func liveConfirmationExists(t *testing.T, ctx context.Context, admin *pgxpool.Pool, fixture authorityOpsFixture) bool {
	t.Helper()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS(
		SELECT 1 FROM public.workspace_managed_grant_confirmation
		WHERE organization_id=$1 AND workspace_id=$2)`,
		fixture.organizationID, fixture.workspaceID).Scan(&exists); err != nil {
		t.Fatalf("probe live managed confirmation: %v", err)
	}
	return exists
}

// loadLiveManagedConfirmation reads the confirmation_id and confirmation_hash of
// the managed confirmation for the fixture so the test can revoke it through the
// production runtime.
func loadLiveManagedConfirmation(t *testing.T, ctx context.Context, admin *pgxpool.Pool, fixture authorityOpsFixture) (confirmationID, confirmationHash string) {
	t.Helper()
	if err := admin.QueryRow(ctx, `
		SELECT confirmation_id, confirmation_hash
		  FROM public.workspace_managed_grant_confirmation
		 WHERE organization_id=$1 AND workspace_id=$2
		 ORDER BY confirmation_id LIMIT 1`,
		fixture.organizationID, fixture.workspaceID).Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatalf("load live managed confirmation: %v", err)
	}
	return confirmationID, confirmationHash
}
