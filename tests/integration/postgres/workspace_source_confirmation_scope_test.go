package postgres_test

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	workspaceConfirmationSiblingID     = "ws_s1d_sibling"
	workspaceConfirmationSiblingViewer = s1dViewer
)

var workspaceConfirmationSiblingBindingID = stableWorkspaceConfirmationBindingID()

func stableWorkspaceConfirmationBindingID() string {
	digest := sha256.Sum256([]byte("workspace-source-lineage-v1\x00" + s1dOrg + "\x00" + workspaceConfirmationSiblingID + "\x00" + s1dScopeID))
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	encoded := make([]byte, 0, 26)
	var accumulator uint32
	bits := uint(2)
	for _, item := range digest[:16] {
		accumulator = (accumulator << 8) | uint32(item)
		bits += 8
		for bits >= 5 {
			bits -= 5
			encoded = append(encoded, alphabet[(accumulator>>bits)&31])
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= (1 << bits) - 1
			}
		}
	}
	return "binding_" + string(encoded)
}

// TestWorkspaceSourceConfirmationStatusIsWorkspaceScoped proves that the
// operator status projection follows the exact workspace_source tuple. A
// confirmation in workspace A keeps the worker's global source activation
// gate live, but does not make workspace B's status or inventory readable.
// Confirming B then enables B; revoking only B leaves A live and B closed.
func TestWorkspaceSourceConfirmationStatusIsWorkspaceScoped(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "projects", "alpha"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(root, "projects", "alpha", "scope.txt"), "workspace confirmation scope proof\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	scopeConfigHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixtureA := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, scopeConfigHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_scope_a", "confirmation_s1d_scope_a", true)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "workspace-confirmation-scope")

	fixtureB := seedWorkspaceConfirmationSibling(t, ctx, admin, scopeConfigHash)
	store := newAuthorityRuntime(t, ctx)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	status := func(workspaceID, requestID string) workspacerepository.SourceStatus {
		t.Helper()
		rows, listErr := store.ListSources(ctx, database.AccessContext{
			OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: requestID,
		}, workspaceID)
		if listErr != nil {
			t.Fatalf("list sources %s: %v", workspaceID, listErr)
		}
		if len(rows) != 1 {
			t.Fatalf("list sources %s rows=%d, want 1", workspaceID, len(rows))
		}
		return rows[0]
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_workspace_confirmation_inventory"}
	inventory := func(workspaceID string) int {
		t.Helper()
		page, listErr := viewer.ListObjects(ctx, viewerAccess, workspaceID, false, 0, 100)
		if listErr != nil {
			t.Fatalf("list objects %s: %v", workspaceID, listErr)
		}
		return len(page.Items)
	}
	predicateAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_workspace_confirmation_predicate"}
	readLive := func(access database.AccessContext, fixture authorityOpsFixture, workspaceID, scopeRevisionHash string, accessMode string) (workspaceLive, globalLive bool) {
		t.Helper()
		if err := appStore.Read(ctx, access,
			func(queryCtx context.Context, tx database.Transaction) error {
				return tx.QueryRow(queryCtx, `
					SELECT app.workspace_source_confirmation_live($1,$2,$3,$4,$5,$6),
					       app.source_scope_activation_confirmed($3,$4,$5)
				`, workspaceID, fixture.workspaceSourceID, fixture.sourceScopeID, fixture.sourceScopeRevision, scopeRevisionHash, accessMode).
					Scan(&workspaceLive, &globalLive)
			}); err != nil {
			t.Fatalf("read confirmation predicates: %v", err)
		}
		return workspaceLive, globalLive
	}

	if got := status(s1dWorkspace, "req_workspace_confirmation_a_before"); !got.Confirmed {
		t.Fatalf("workspace A status before B confirmation = %#v, want confirmed", got)
	}
	if got := status(workspaceConfirmationSiblingID, "req_workspace_confirmation_b_before"); got.Confirmed {
		t.Fatalf("workspace B status before B confirmation = %#v, want unconfirmed", got)
	}
	if got := inventory(workspaceConfirmationSiblingID); got != 0 {
		t.Fatalf("workspace B inventory before B confirmation=%d, want 0", got)
	}
	if workspaceLive, globalLive := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive || !globalLive {
		t.Fatalf("before B confirmation workspaceLive=%v globalLive=%v, want false/true", workspaceLive, globalLive)
	}
	if workspaceLive, globalLive := readLive(predicateAccess, fixtureA, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive || !globalLive {
		t.Fatalf("foreign binding workspaceLive=%v globalLive=%v, want false/true", workspaceLive, globalLive)
	}
	if workspaceLive, _ := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, "sha256:"+strings.Repeat("9", 64), "WORKSPACE_MANAGED"); workspaceLive {
		t.Fatal("unrelated scope config hash unexpectedly reported live")
	}
	if workspaceLive, _ := readLive(database.AccessContext{OrganizationID: s1dOrg, PrincipalID: "usr_s1d_foreign", RequestID: "req_workspace_confirmation_foreign_principal"}, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive {
		t.Fatal("foreign principal unexpectedly saw a live workspace confirmation")
	}
	if workspaceLive, _ := readLive(database.AccessContext{OrganizationID: "org_s1d_foreign", PrincipalID: "usr_s1d_foreign", RequestID: "req_workspace_confirmation_foreign_tenant"}, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive {
		t.Fatal("foreign tenant unexpectedly saw a live workspace confirmation")
	}

	grantB := issueRuntimeGrant(t, ctx, store, fixtureB, "workspace-scope-b-grant")
	confirmationB, err := store.ConfirmManagedSource(ctx, authorityAccess(fixtureB, fixtureB.ownerID, "req_workspace_scope_b_confirm"),
		confirmRuntimeRequest(fixtureB, grantB, "workspace-scope-b-confirm"))
	if err != nil {
		t.Fatalf("confirm workspace B: %v", err)
	}
	if got := status(s1dWorkspace, "req_workspace_confirmation_a_after"); !got.Confirmed {
		t.Fatalf("workspace A status after B confirmation = %#v, want confirmed", got)
	}
	if got := status(workspaceConfirmationSiblingID, "req_workspace_confirmation_b_after"); !got.Confirmed {
		t.Fatalf("workspace B status after B confirmation = %#v, want confirmed", got)
	}
	if got := inventory(workspaceConfirmationSiblingID); got == 0 {
		t.Fatal("workspace B inventory after B confirmation is empty")
	}
	if workspaceLive, globalLive := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); !workspaceLive || !globalLive {
		t.Fatalf("after B confirmation workspaceLive=%v globalLive=%v, want true/true", workspaceLive, globalLive)
	}
	if workspaceLive, _ := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "SOURCE_ENFORCED"); workspaceLive {
		t.Fatal("unrelated access mode unexpectedly reported live")
	}

	if _, err := store.RemoveSource(ctx, authorityAccess(fixtureB, fixtureB.ownerID, "req_workspace_scope_b_disable"),
		workspacerepository.RemoveSourceRequest{
			IdempotencyKey: workspaceIdempotencyKey("workspace-scope-b-disable"), WorkspaceID: fixtureB.workspaceID,
			ExpectedWorkspaceRevision: fixtureB.workspaceRevision, ExpectedConfigurationHash: fixtureB.workspaceConfHash,
			WorkspaceSourceID: fixtureB.workspaceSourceID, SourceScopeID: fixtureB.sourceScopeID,
			SourceScopeRevision: fixtureB.sourceScopeRevision, ScopeConfigHash: fixtureB.scopeConfigHash,
			AccessMode: workspacerepository.SourceAccessWorkspaceManaged,
		}); err != nil {
		t.Fatalf("disable workspace B: %v", err)
	}
	if got := status(workspaceConfirmationSiblingID, "req_workspace_confirmation_b_disabled"); !got.Confirmed || got.Enabled {
		t.Fatalf("workspace B disabled status = %#v, want disabled but live-confirmed for re-enable", got)
	}
	if got := inventory(workspaceConfirmationSiblingID); got != 0 {
		t.Fatalf("workspace B inventory while disabled=%d, want 0", got)
	}
	if workspaceLive, globalLive := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive || !globalLive {
		t.Fatalf("disabled binding predicates workspaceLive=%v globalLive=%v, want false/true", workspaceLive, globalLive)
	}

	if _, err := store.RevokeManagedConfirmation(ctx, authorityAccess(fixtureB, fixtureB.ownerID, "req_workspace_scope_b_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("workspace-scope-b-revoke"), OrganizationID: fixtureB.organizationID,
			WorkspaceID: fixtureB.workspaceID, ConfirmationID: confirmationB.ResultID, ConfirmationHash: confirmationB.ResultHash,
			ExpectedPolicyRevision: fixtureB.policyID,
		}); err != nil {
		t.Fatalf("revoke workspace B: %v", err)
	}
	if got := status(s1dWorkspace, "req_workspace_confirmation_a_after_revoke"); !got.Confirmed {
		t.Fatalf("workspace A status after B revoke = %#v, want confirmed", got)
	}
	if got := status(workspaceConfirmationSiblingID, "req_workspace_confirmation_b_after_revoke"); got.Confirmed {
		t.Fatalf("workspace B status after B revoke = %#v, want unconfirmed", got)
	}
	if got := inventory(workspaceConfirmationSiblingID); got != 0 {
		t.Fatalf("workspace B inventory after B revoke=%d, want 0", got)
	}
	if workspaceLive, globalLive := readLive(predicateAccess, fixtureB, workspaceConfirmationSiblingID, scopeConfigHash, "WORKSPACE_MANAGED"); workspaceLive || !globalLive {
		t.Fatalf("after B revoke workspaceLive=%v globalLive=%v, want false/true", workspaceLive, globalLive)
	}
}

func seedWorkspaceConfirmationSibling(t *testing.T, ctx context.Context, admin *pgxpool.Pool, scopeConfigHash string) authorityOpsFixture {
	t.Helper()
	const policyID = "policy-s1d-01ARZ3NDEKTSV4RRFFQ69G5FAV"
	snapshot := workspace.Snapshot{
		OrganizationID: s1dOrg, ID: workspaceConfirmationSiblingID, Revision: 1,
		Name: workspaceConfirmationSiblingID, Status: workspace.StatusActive, OwnerPrincipalID: s1dOwner,
		Members: []workspace.Member{
			{PrincipalID: s1dOwner, Role: workspace.RoleOwner},
			{PrincipalID: workspaceConfirmationSiblingViewer, Role: workspace.RoleMember},
		},
		SourceBindings: []workspace.SourceBinding{{
			SourceScopeID: s1dScopeID, SourceScopeRevision: 1, ScopeConfigHash: scopeConfigHash, Enabled: true,
		}},
	}
	workspaceHash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		t.Fatalf("sibling workspace hash: %v", err)
	}
	canonicalBytes, err := workspace.CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("sibling workspace snapshot: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(sql string, args ...any) {
		if _, execErr := tx.Exec(ctx, sql, args...); execErr != nil {
			t.Fatalf("seed sibling workspace: %v\n%s", execErr, sql)
		}
	}
	exec(`INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
		VALUES ($1,$2,$1,'ACTIVE',$3,1)`, workspaceConfirmationSiblingID, s1dOrg, s1dOwner)
	exec(`INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
		VALUES ($1,$2,1,$3,$4)`, s1dOrg, workspaceConfirmationSiblingID, workspaceHash, s1dOwner)
	exec(`INSERT INTO public.workspace_revision_snapshot (organization_id, workspace_id, revision, configuration_hash, canonical_bytes)
		VALUES ($1,$2,1,$3,$4)`, s1dOrg, workspaceConfirmationSiblingID, workspaceHash, canonicalBytes)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_s1d_sibling_owner',$1,$2,$3,'OWNER',1,$3)`, s1dOrg, workspaceConfirmationSiblingID, s1dOwner)
	exec(`INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wm_s1d_sibling_viewer',$1,$2,$3,'MEMBER',1,$4)`, s1dOrg, workspaceConfirmationSiblingID, workspaceConfirmationSiblingViewer, s1dOwner)
	exec(`INSERT INTO public.workspace_source (organization_id, id, workspace_id, source_scope_id, added_by)
		VALUES ($1,$2,$3,$4,$5)`, s1dOrg, workspaceConfirmationSiblingBindingID, workspaceConfirmationSiblingID, s1dScopeID, s1dOwner)
	exec(`INSERT INTO public.workspace_revision_source
		(organization_id, workspace_id, workspace_revision, workspace_configuration_hash, workspace_source_id,
		 source_scope_id, source_scope_revision, scope_config_hash, access_mode, enabled)
		VALUES ($1,$2,1,$3,$4,$5,1,$6,'WORKSPACE_MANAGED',true)`,
		s1dOrg, workspaceConfirmationSiblingID, workspaceHash, workspaceConfirmationSiblingBindingID, s1dScopeID, scopeConfigHash)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit sibling workspace: %v", err)
	}
	return authorityOpsFixture{
		organizationID: s1dOrg, ownerID: s1dOwner, workspaceID: workspaceConfirmationSiblingID,
		policyID: policyID, policyNumber: 1, workspaceRevision: 1, workspaceConfHash: workspaceHash,
		workspaceSourceID: workspaceConfirmationSiblingBindingID, sourceScopeID: s1dScopeID,
		sourceScopeRevision: 1, scopeConfigHash: scopeConfigHash,
	}
}
