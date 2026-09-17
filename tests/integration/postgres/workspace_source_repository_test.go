package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	repositoryTestScopeID   = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	repositoryTestScopeHash = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
)

func TestWorkspaceSourceRepositoryAddRemoveAndReenableStableLineage(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	store := newWorkspaceSourceRepository(t, ctx)
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_source_add"}
	initial, err := store.Get(ctx, access, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	addRequest := workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-add-first"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	added, err := store.AddSource(ctx, access, addRequest)
	if err != nil {
		t.Fatalf("add source: %v", err)
	}
	assertSingleRepositoryBinding(t, added, initial.Revision+1, true)
	if replayed, replayErr := store.AddSource(ctx, database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_source_add_replay",
	}, addRequest); replayErr != nil || !reflect.DeepEqual(replayed, added) {
		t.Fatalf("add replay=%#v err=%v", replayed, replayErr)
	}
	conflict := addRequest
	conflict.ScopeConfigHash = "sha256:" + strings.Repeat("7", 64)
	if _, conflictErr := store.AddSource(ctx, access, conflict); workspacerepository.CodeOf(conflictErr) != workspacerepository.CodeIdempotencyConflict {
		t.Fatalf("changed add replay code=%q err=%v", workspacerepository.CodeOf(conflictErr), conflictErr)
	}

	bindingID := repositoryWorkspaceSourceID(t, ctx, admin, "ws_alpha")
	removeRequest := workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-remove"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	removed, err := store.RemoveSource(ctx, access, removeRequest)
	if err != nil {
		t.Fatalf("remove source: %v", err)
	}
	assertSingleRepositoryBinding(t, removed, added.Revision+1, false)

	readdRequest := addRequest
	readdRequest.IdempotencyKey = workspaceIdempotencyKey("source-reenable")
	readdRequest.ExpectedWorkspaceRevision = removed.Revision
	readdRequest.ExpectedConfigurationHash = mustWorkspaceHash(t, removed)
	reenabled, err := store.AddSource(ctx, access, readdRequest)
	if err != nil {
		t.Fatalf("re-enable source: %v", err)
	}
	assertSingleRepositoryBinding(t, reenabled, removed.Revision+1, true)
	var lineageCount int
	var stableBindingID string
	if err := admin.QueryRow(ctx, `
		SELECT count(*), min(id) FROM public.workspace_source
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND source_scope_id=$1
	`, repositoryTestScopeID).Scan(&lineageCount, &stableBindingID); err != nil {
		t.Fatal(err)
	}
	if lineageCount != 1 || stableBindingID != bindingID {
		t.Fatalf("stable lineage count/id=%d/%q, want 1/%q", lineageCount, stableBindingID, bindingID)
	}

	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_ADD", workspaceIdempotencyKey("source-add-first"), bindingID, 1, 2, true, "SUCCESS", "SUCCESS", "")
	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_REMOVE", workspaceIdempotencyKey("source-remove"), bindingID, 2, 3, false, "SUCCESS", "SUCCESS", "")
	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_ADD", workspaceIdempotencyKey("source-reenable"), bindingID, 3, 4, true, "SUCCESS", "SUCCESS", "")
	assertRepositorySourceConfigurationRemainsDraft(t, ctx, admin)
}

// TestWorkspaceSourceRepositoryReenablesAlreadyActivatedScope is the
// regression proof for the S2 defect measured on knowvault-acc: re-enabling a
// binding via AddSource answered 404 once the underlying scope had ever left
// DRAFT (the very first successful :activate moves the scope's revision-1
// activation row DRAFT -> SYNCING -> READY through the production worker
// path), because mutateSource unconditionally required the DRAFT-only tuple
// exactDraftScopeTupleExists checks even for a re-enable of a binding that
// already existed. This drives the scope's activation row through the exact
// transition sequence app.source_scope_activation_guard enforces for every
// session and then proves AddSource still re-enables the disabled binding.
func TestWorkspaceSourceRepositoryReenablesAlreadyActivatedScope(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")

	store := newWorkspaceSourceRepository(t, ctx)
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_source_add_active"}
	initial, err := store.Get(ctx, access, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	addRequest := workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-add-active-first"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	added, err := store.AddSource(ctx, access, addRequest)
	if err != nil {
		t.Fatalf("add source: %v", err)
	}

	bindingID := repositoryWorkspaceSourceID(t, ctx, admin, "ws_alpha")
	removeRequest := workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-remove-active"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	removed, err := store.RemoveSource(ctx, access, removeRequest)
	if err != nil {
		t.Fatalf("remove source: %v", err)
	}

	// Simulate the real production activation path (worker-driven, never
	// this repository): the scope's revision-1 activation row leaves DRAFT
	// for good, through the exact DRAFT -> SYNCING -> READY sequence the
	// guard trigger enforces.
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET status='SYNCING' WHERE organization_id='org_alpha' AND source_scope_id=$1 AND source_scope_revision=1 AND revision=1`,
		repositoryTestScopeID); err != nil {
		t.Fatalf("advance activation to SYNCING: %v", err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope_activation
		SET status='READY' WHERE organization_id='org_alpha' AND source_scope_id=$1 AND source_scope_revision=1 AND revision=1`,
		repositoryTestScopeID); err != nil {
		t.Fatalf("advance activation to READY: %v", err)
	}

	readdRequest := addRequest
	readdRequest.IdempotencyKey = workspaceIdempotencyKey("source-reenable-active")
	readdRequest.ExpectedWorkspaceRevision = removed.Revision
	readdRequest.ExpectedConfigurationHash = mustWorkspaceHash(t, removed)
	reenabled, err := store.AddSource(ctx, access, readdRequest)
	if err != nil {
		t.Fatalf("re-enable an already-activated scope must not be NOT_FOUND: %v (code=%s)", err, workspacerepository.CodeOf(err))
	}
	assertSingleRepositoryBinding(t, reenabled, removed.Revision+1, true)
}

func TestWorkspaceSourceRepositoryFailsClosedForStaleDeniedAndForeignScopeTuple(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_bob','org_alpha','USER','Bob','ACTIVE'),
		       ('usr_carol','org_alpha','USER','Carol','ACTIVE')`); err != nil {
		t.Fatal(err)
	}

	store := newWorkspaceSourceRepository(t, ctx)
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_source_setup"}
	initial, err := store.Get(ctx, alice, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	added, err := store.AddSource(ctx, alice, workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-fail-setup"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
		SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	})
	if err != nil {
		t.Fatal(err)
	}
	bindingID := repositoryWorkspaceSourceID(t, ctx, admin, "ws_alpha")
	withBob, err := store.AddMember(ctx, alice, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-add-member"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, added), PrincipalID: "usr_bob", Role: workspace.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}

	staleRevision := workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-stale-revision"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: added.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, added),
		WorkspaceSourceID: bindingID, SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	if _, staleErr := store.RemoveSource(ctx, alice, staleRevision); workspacerepository.CodeOf(staleErr) != workspacerepository.CodeRevisionConflict {
		t.Fatalf("stale revision code=%q err=%v", workspacerepository.CodeOf(staleErr), staleErr)
	}
	if _, replayErr := store.RemoveSource(ctx, alice, staleRevision); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeRevisionConflict {
		t.Fatalf("stale revision replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}
	staleHash := staleRevision
	staleHash.IdempotencyKey = workspaceIdempotencyKey("source-stale-hash")
	staleHash.ExpectedWorkspaceRevision = withBob.Revision
	staleHash.ExpectedConfigurationHash = "sha256:" + strings.Repeat("9", 64)
	if _, staleErr := store.RemoveSource(ctx, alice, staleHash); workspacerepository.CodeOf(staleErr) != workspacerepository.CodeRevisionConflict {
		t.Fatalf("stale hash code=%q err=%v", workspacerepository.CodeOf(staleErr), staleErr)
	}

	bob := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_source_member_denied"}
	denied := staleRevision
	denied.IdempotencyKey = workspaceIdempotencyKey("source-member-denied")
	denied.ExpectedWorkspaceRevision = withBob.Revision
	denied.ExpectedConfigurationHash = mustWorkspaceHash(t, withBob)
	if _, deniedErr := store.RemoveSource(ctx, bob, denied); workspacerepository.CodeOf(deniedErr) != workspacerepository.CodeDenied {
		t.Fatalf("member remove code=%q err=%v", workspacerepository.CodeOf(deniedErr), deniedErr)
	}
	if _, replayErr := store.RemoveSource(ctx, bob, denied); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeDenied {
		t.Fatalf("member remove replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}

	missingScope := workspacerepository.AddSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-scope-not-found"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: withBob.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, withBob),
		SourceScopeID: "scope_01BX5ZZKBKACTAV9WEVGEMMVRZ", SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	if _, missingErr := store.AddSource(ctx, alice, missingScope); workspacerepository.CodeOf(missingErr) != workspacerepository.CodeNotFound {
		t.Fatalf("missing scope code=%q err=%v", workspacerepository.CodeOf(missingErr), missingErr)
	}
	if _, replayErr := store.AddSource(ctx, alice, missingScope); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeNotFound {
		t.Fatalf("missing scope replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}
	substitutedTuple := missingScope
	substitutedTuple.IdempotencyKey = workspaceIdempotencyKey("source-scope-substitution")
	substitutedTuple.SourceScopeID = repositoryTestScopeID
	substitutedTuple.ScopeConfigHash = "sha256:" + strings.Repeat("7", 64)
	if _, substitutionErr := store.AddSource(ctx, alice, substitutedTuple); workspacerepository.CodeOf(substitutionErr) != workspacerepository.CodeNotFound {
		t.Fatalf("scope substitution code=%q err=%v", workspacerepository.CodeOf(substitutionErr), substitutionErr)
	}
	hidden := missingScope
	hidden.IdempotencyKey = workspaceIdempotencyKey("source-hidden-workspace")
	hidden.SourceScopeID = repositoryTestScopeID
	hidden.ScopeConfigHash = repositoryTestScopeHash
	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_source_hidden"}
	if _, hiddenErr := store.AddSource(ctx, carol, hidden); workspacerepository.CodeOf(hiddenErr) != workspacerepository.CodeNotFound {
		t.Fatalf("hidden workspace code=%q err=%v", workspacerepository.CodeOf(hiddenErr), hiddenErr)
	}
	if _, replayErr := store.AddSource(ctx, carol, hidden); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeNotFound {
		t.Fatalf("hidden workspace replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}
	crossTenant := hidden
	crossTenant.IdempotencyKey = workspaceIdempotencyKey("source-cross-tenant-hidden")
	eve := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_eve", RequestID: "req_source_cross_tenant"}
	if _, hiddenErr := store.AddSource(ctx, eve, crossTenant); workspacerepository.CodeOf(hiddenErr) != workspacerepository.CodeNotFound {
		t.Fatalf("cross-tenant hidden workspace code=%q err=%v", workspacerepository.CodeOf(hiddenErr), hiddenErr)
	}
	if _, replayErr := store.AddSource(ctx, eve, crossTenant); workspacerepository.CodeOf(replayErr) != workspacerepository.CodeNotFound {
		t.Fatalf("cross-tenant hidden replay code=%q err=%v", workspacerepository.CodeOf(replayErr), replayErr)
	}

	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_REMOVE", workspaceIdempotencyKey("source-stale-revision"), bindingID, added.Revision, 0, false, "PRECONDITION_FAILED", "FAILED", string(workspacerepository.CodeRevisionConflict))
	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_REMOVE", workspaceIdempotencyKey("source-member-denied"), bindingID, withBob.Revision, 0, false, "DENIED", "DENIED", string(workspacerepository.CodeDenied))
	assertSourceTerminalFailure(t, ctx, admin, "org_alpha", "usr_alice", workspaceIdempotencyKey("source-scope-not-found"),
		"WORKSPACE_SOURCE_ADD", "NOT_FOUND", string(workspacerepository.CodeNotFound),
		"scope_01BX5ZZKBKACTAV9WEVGEMMVRZ", repositoryTestScopeHash, mustWorkspaceHash(t, withBob), withBob.Revision, true)
	assertSourceTerminalFailure(t, ctx, admin, "org_alpha", "usr_alice", workspaceIdempotencyKey("source-scope-substitution"),
		"WORKSPACE_SOURCE_ADD", "NOT_FOUND", string(workspacerepository.CodeNotFound),
		repositoryTestScopeID, "sha256:"+strings.Repeat("7", 64), mustWorkspaceHash(t, withBob), withBob.Revision, true)
	assertSourceTerminalFailure(t, ctx, admin, "org_alpha", "usr_carol", workspaceIdempotencyKey("source-hidden-workspace"),
		"WORKSPACE_SOURCE_ADD", "NOT_FOUND", string(workspacerepository.CodeNotFound),
		repositoryTestScopeID, repositoryTestScopeHash, mustWorkspaceHash(t, withBob), withBob.Revision, true)
	assertSourceTerminalFailure(t, ctx, admin, "org_beta", "usr_eve", workspaceIdempotencyKey("source-cross-tenant-hidden"),
		"WORKSPACE_SOURCE_ADD", "NOT_FOUND", string(workspacerepository.CodeNotFound),
		repositoryTestScopeID, repositoryTestScopeHash, mustWorkspaceHash(t, withBob), withBob.Revision, true)

	current, err := store.Get(ctx, alice, "ws_alpha")
	if err != nil || current.Revision != withBob.Revision || len(current.SourceBindings) != 1 || !current.SourceBindings[0].Enabled {
		t.Fatalf("failed commands mutated source configuration: %#v err=%v", current, err)
	}
	managed, err := store.ChangeMemberRole(ctx, alice, workspacerepository.ChangeMemberRoleRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-promote-manager"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, current), PrincipalID: "usr_bob", Role: workspace.RoleManager,
	})
	if err != nil {
		t.Fatal(err)
	}
	managerRemove := workspacerepository.RemoveSourceRequest{
		IdempotencyKey: workspaceIdempotencyKey("source-manager-remove"), WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision: managed.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, managed),
		WorkspaceSourceID: bindingID, SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
		ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
	}
	managerResult, err := store.RemoveSource(ctx, database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_source_manager_success",
	}, managerRemove)
	if err != nil {
		t.Fatalf("manager remove: %v", err)
	}
	assertSingleRepositoryBinding(t, managerResult, managed.Revision+1, false)
	assertSourceCommandReceiptAndAudit(t, ctx, admin, "WORKSPACE_SOURCE_REMOVE", workspaceIdempotencyKey("source-manager-remove"), bindingID, managed.Revision, managerResult.Revision, false, "SUCCESS", "SUCCESS", "")
	assertRepositorySourceConfigurationRemainsDraft(t, ctx, admin)
}

func TestWorkspaceSourceRepositorySerializesSameAndDifferentIdempotencyKeys(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		sameKey bool
	}{
		{name: "same key replays one result", sameKey: true},
		{name: "different keys make one stale", sameKey: false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "alpha", "")
			store := newWorkspaceSourceRepository(t, ctx)
			access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice"}
			initial, err := store.Get(ctx, database.AccessContext{
				OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_concurrent_get",
			}, "ws_alpha")
			if err != nil {
				t.Fatal(err)
			}
			base := workspacerepository.AddSourceRequest{
				IdempotencyKey: workspaceIdempotencyKey("source-concurrent-a"), WorkspaceID: "ws_alpha",
				ExpectedWorkspaceRevision: initial.Revision, ExpectedConfigurationHash: mustWorkspaceHash(t, initial),
				SourceScopeID: repositoryTestScopeID, SourceScopeRevision: 1,
				ScopeConfigHash: repositoryTestScopeHash, AccessMode: workspacerepository.SourceAccessSourceEnforced,
			}
			requests := []workspacerepository.AddSourceRequest{base, base}
			if !scenario.sameKey {
				requests[1].IdempotencyKey = workspaceIdempotencyKey("source-concurrent-b")
			}
			type outcome struct {
				snapshot workspace.Snapshot
				err      error
			}
			outcomes := make([]outcome, 2)
			start := make(chan struct{})
			var wait sync.WaitGroup
			for index := range requests {
				index := index
				wait.Add(1)
				go func() {
					defer wait.Done()
					<-start
					callAccess := access
					callAccess.RequestID = "req_source_concurrent_" + string(rune('a'+index))
					outcomes[index].snapshot, outcomes[index].err = store.AddSource(ctx, callAccess, requests[index])
				}()
			}
			close(start)
			wait.Wait()

			if scenario.sameKey {
				if outcomes[0].err != nil || outcomes[1].err != nil || !reflect.DeepEqual(outcomes[0].snapshot, outcomes[1].snapshot) {
					t.Fatalf("same-key outcomes=%#v", outcomes)
				}
			} else {
				successes, conflicts := 0, 0
				for _, got := range outcomes {
					if got.err == nil {
						successes++
					} else if workspacerepository.CodeOf(got.err) == workspacerepository.CodeRevisionConflict {
						conflicts++
					} else {
						t.Fatalf("unexpected concurrent error: %v", got.err)
					}
				}
				if successes != 1 || conflicts != 1 {
					t.Fatalf("different-key success/conflict=%d/%d", successes, conflicts)
				}
			}
			current, err := store.Get(ctx, database.AccessContext{
				OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_concurrent_final",
			}, "ws_alpha")
			if err != nil {
				t.Fatal(err)
			}
			assertSingleRepositoryBinding(t, current, 2, true)
			var lineages, receipts, audits int
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source
				WHERE organization_id='org_alpha' AND workspace_id='ws_alpha'`).Scan(&lineages); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt
				WHERE organization_id='org_alpha' AND operation='WORKSPACE_SOURCE_ADD'`).Scan(&receipts); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
				WHERE organization_id='org_alpha' AND action='workspace.source_added'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			wantTerminals := 1
			if !scenario.sameKey {
				wantTerminals = 2
			}
			if lineages != 1 || receipts != wantTerminals || audits != wantTerminals {
				t.Fatalf("concurrent lineage/receipt/audit=%d/%d/%d, want 1/%d/%d", lineages, receipts, audits, wantTerminals, wantTerminals)
			}
		})
	}
}

func newWorkspaceSourceRepository(t *testing.T, ctx context.Context) *workspacerepository.Store {
	t.Helper()
	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	databaseStore, err := database.Open(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(databaseStore.Close)
	auditStore, err := audit.NewStore(databaseStore)
	if err != nil {
		t.Fatal(err)
	}
	store, err := workspacerepository.New(databaseStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func assertSingleRepositoryBinding(t *testing.T, snapshot workspace.Snapshot, revision int64, enabled bool) {
	t.Helper()
	if snapshot.Revision != revision || len(snapshot.SourceBindings) != 1 ||
		snapshot.SourceBindings[0].SourceScopeID != repositoryTestScopeID ||
		snapshot.SourceBindings[0].SourceScopeRevision != 1 ||
		snapshot.SourceBindings[0].ScopeConfigHash != repositoryTestScopeHash ||
		snapshot.SourceBindings[0].Enabled != enabled {
		t.Fatalf("source snapshot=%#v, want revision=%d enabled=%v", snapshot, revision, enabled)
	}
}

func repositoryWorkspaceSourceID(t *testing.T, ctx context.Context, admin *pgxpool.Pool, workspaceID string) string {
	t.Helper()
	var bindingID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.workspace_source
		WHERE organization_id='org_alpha' AND workspace_id=$1 AND source_scope_id=$2`, workspaceID, repositoryTestScopeID).Scan(&bindingID); err != nil {
		t.Fatal(err)
	}
	return bindingID
}

func assertSourceCommandReceiptAndAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, operation, idempotencyKey, bindingID string, baseRevision, resultRevision int64, enabled bool, receiptStatus, auditOutcome, errorCode string) {
	t.Helper()
	keyHash, err := repositoryIdempotencyKeyHash(idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var gateVersion int16
	var gotBaseRevision int64
	var gotOperation, workspaceID, resourceType, resourceID, expectedHash, gotBindingID, scopeID, scopeHash, accessMode, gotStatus, auditID string
	var scopeRevision int64
	var nullableResultRevision *int64
	if err := admin.QueryRow(ctx, `
		SELECT gate_version, operation, command_workspace_id, command_resource_type, command_resource_id,
		       source_expected_workspace_revision, source_expected_configuration_hash, command_workspace_source_id, command_source_scope_id,
		       command_source_scope_revision, command_scope_config_hash, command_access_mode, status,
		       result_workspace_revision, audit_event_id
		FROM public.workspace_command_receipt
		WHERE organization_id='org_alpha' AND actor_principal_id IN ('usr_alice','usr_bob')
		  AND idempotency_key_hash=$1
	`, keyHash).Scan(&gateVersion, &gotOperation, &workspaceID, &resourceType, &resourceID, &gotBaseRevision,
		&expectedHash, &gotBindingID, &scopeID, &scopeRevision, &scopeHash, &accessMode, &gotStatus,
		&nullableResultRevision, &auditID); err != nil {
		t.Fatal(err)
	}
	if gateVersion != 2 || gotOperation != operation || workspaceID != "ws_alpha" || gotBaseRevision != baseRevision || resourceType != "WORKSPACE_SOURCE" ||
		resourceID != bindingID || gotBindingID != bindingID || scopeID != repositoryTestScopeID || scopeRevision != 1 ||
		scopeHash != repositoryTestScopeHash || accessMode != "SOURCE_ENFORCED" || gotStatus != receiptStatus ||
		!workspace.IsConfigurationHash(expectedHash) {
		t.Fatalf("inexact gate-v2 receipt: gate=%d op=%s workspace=%s resource=%s/%s tuple=%s/%d/%s/%s status=%s",
			gateVersion, gotOperation, workspaceID, resourceType, resourceID, scopeID, scopeRevision, scopeHash, accessMode, gotStatus)
	}
	var exactBaseHash string
	if err := admin.QueryRow(ctx, `SELECT configuration_hash FROM public.workspace_revision
		WHERE organization_id='org_alpha' AND workspace_id='ws_alpha' AND revision=$1`, baseRevision).Scan(&exactBaseHash); err != nil {
		t.Fatal(err)
	}
	if expectedHash != exactBaseHash {
		t.Fatalf("receipt base hash=%q, want exact revision hash %q", expectedHash, exactBaseHash)
	}
	if resultRevision == 0 {
		if nullableResultRevision != nil {
			t.Fatalf("failed receipt has result revision %v", *nullableResultRevision)
		}
	} else if nullableResultRevision == nil || *nullableResultRevision != resultRevision {
		t.Fatalf("result revision=%v, want %d", nullableResultRevision, resultRevision)
	}

	var action, auditResourceType, auditResourceID, gotOutcome string
	var workspaceIDAtAudit *string
	var gotErrorCode *string
	var metadata []byte
	if err := admin.QueryRow(ctx, `SELECT action, resource_type, resource_id, workspace_id, outcome, error_code, metadata_json
		FROM public.audit_event WHERE organization_id='org_alpha' AND id=$1`, auditID).Scan(
		&action, &auditResourceType, &auditResourceID, &workspaceIDAtAudit, &gotOutcome, &gotErrorCode, &metadata,
	); err != nil {
		t.Fatal(err)
	}
	wantAction := "workspace.source_added"
	if operation == "WORKSPACE_SOURCE_REMOVE" {
		wantAction = "workspace.source_removed"
	}
	if action != wantAction || auditResourceType != "WORKSPACE_SOURCE" || auditResourceID != bindingID || gotOutcome != auditOutcome {
		t.Fatalf("inexact source audit action/resource/outcome=%s/%s/%s/%s", action, auditResourceType, auditResourceID, gotOutcome)
	}
	if errorCode == "" {
		if gotErrorCode != nil {
			t.Fatalf("success audit error=%q", *gotErrorCode)
		}
	} else if gotErrorCode == nil || *gotErrorCode != errorCode {
		t.Fatalf("audit error=%v, want %q", gotErrorCode, errorCode)
	}
	var projection map[string]any
	if err := json.Unmarshal(metadata, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 7 || projection["workspace_source_id"] != bindingID || projection["source_scope_id"] != repositoryTestScopeID ||
		projection["scope_config_hash"] != repositoryTestScopeHash || projection["access_mode"] != "SOURCE_ENFORCED" || projection["enabled"] != enabled ||
		projection["workspace_revision"] != float64(func() int64 {
			if resultRevision != 0 {
				return resultRevision
			}
			return baseRevision
		}()) ||
		projection["source_scope_revision"] != float64(1) {
		t.Fatalf("source audit metadata is not exact: %#v", projection)
	}
	var receiptCount, auditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt
		WHERE organization_id='org_alpha' AND idempotency_key_hash=$1`, keyHash).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id='org_alpha' AND id=$1`, auditID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 || auditCount != 1 {
		t.Fatalf("command replay duplicated receipt/audit=%d/%d", receiptCount, auditCount)
	}
}

func assertSourceTerminalFailure(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, actorID, idempotencyKey,
	operation, receiptStatus, errorCode, scopeID, scopeHash, baseHash string, baseRevision int64, enabled bool,
) {
	t.Helper()
	keyHash, err := repositoryIdempotencyKeyHash(idempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	var gateVersion int16
	var bindingID, gotOperation, gotStatus, auditID, gotScopeID, gotScopeHash, accessMode string
	var workspaceID, receiptResourceType, receiptResourceID, gotBaseHash string
	var gotBaseRevision int64
	var gotScopeRevision int64
	var resultRevision *int64
	if err := admin.QueryRow(ctx, `
		SELECT gate_version, operation, command_workspace_id, command_resource_type, command_resource_id,
		       command_workspace_source_id, source_expected_workspace_revision, source_expected_configuration_hash,
		       command_source_scope_id, command_source_scope_revision,
		       command_scope_config_hash, command_access_mode, status, result_workspace_revision, audit_event_id
		FROM public.workspace_command_receipt
		WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key_hash=$3
	`, organizationID, actorID, keyHash).Scan(&gateVersion, &gotOperation, &workspaceID, &receiptResourceType, &receiptResourceID,
		&bindingID, &gotBaseRevision, &gotBaseHash, &gotScopeID, &gotScopeRevision,
		&gotScopeHash, &accessMode, &gotStatus, &resultRevision, &auditID); err != nil {
		t.Fatal(err)
	}
	if gateVersion != 2 || gotOperation != operation || gotStatus != receiptStatus || gotBaseRevision != baseRevision ||
		resultRevision != nil || !strings.HasPrefix(bindingID, "binding_") || gotScopeID != scopeID || gotScopeRevision != 1 ||
		gotScopeHash != scopeHash || accessMode != "SOURCE_ENFORCED" || workspaceID != "ws_alpha" ||
		receiptResourceType != "WORKSPACE_SOURCE" || receiptResourceID != bindingID || gotBaseHash != baseHash {
		t.Fatalf("terminal failure receipt=%d/%s/%s/%d result=%v binding=%q", gateVersion, gotOperation, gotStatus, gotBaseRevision, resultRevision, bindingID)
	}
	var auditWorkspaceID, gotErrorCode *string
	var gotActor, action, resourceType, resourceID, outcome string
	var metadata []byte
	if err := admin.QueryRow(ctx, `
		SELECT actor_principal_id, action, resource_type, resource_id, workspace_id, outcome, error_code, metadata_json
		FROM public.audit_event WHERE organization_id=$1 AND id=$2
	`, organizationID, auditID).Scan(&gotActor, &action, &resourceType, &resourceID, &auditWorkspaceID, &outcome, &gotErrorCode, &metadata); err != nil {
		t.Fatal(err)
	}
	wantAction := "workspace.source_added"
	if operation == "WORKSPACE_SOURCE_REMOVE" {
		wantAction = "workspace.source_removed"
	}
	if gotActor != actorID || action != wantAction || resourceType != "WORKSPACE_SOURCE" || resourceID != bindingID ||
		auditWorkspaceID != nil || outcome != "DENIED" || gotErrorCode == nil || *gotErrorCode != errorCode {
		t.Fatalf("terminal failure audit actor/action/resource/workspace/outcome/error=%s/%s/%s:%s/%v/%s/%v",
			gotActor, action, resourceType, resourceID, auditWorkspaceID, outcome, gotErrorCode)
	}
	var projection map[string]any
	if err := json.Unmarshal(metadata, &projection); err != nil {
		t.Fatal(err)
	}
	if len(projection) != 7 || projection["workspace_revision"] != float64(baseRevision) ||
		projection["workspace_source_id"] != bindingID || projection["source_scope_id"] != scopeID ||
		projection["source_scope_revision"] != float64(1) || projection["scope_config_hash"] != scopeHash ||
		projection["access_mode"] != "SOURCE_ENFORCED" || projection["enabled"] != enabled {
		t.Fatalf("terminal failure audit metadata is not exact: %#v", projection)
	}
	var receiptCount, auditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_command_receipt
		WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key_hash=$3`, organizationID, actorID, keyHash).Scan(&receiptCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND id=$2`, organizationID, auditID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 1 || auditCount != 1 {
		t.Fatalf("terminal replay duplicated receipt/audit=%d/%d", receiptCount, auditCount)
	}
}

func assertRepositorySourceConfigurationRemainsDraft(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	var connectionActive, scopeActive *int64
	var scopeStatus, activationStatus string
	if err := admin.QueryRow(ctx, `
		SELECT connection.active_revision, scope.active_revision, scope.status, activation.status
		FROM public.source_scope AS scope
		JOIN public.source_scope_activation AS activation
		  ON activation.organization_id=scope.organization_id AND activation.source_scope_id=scope.id
		 AND activation.source_scope_revision=1
		JOIN public.source_connection AS connection
		  ON connection.organization_id=scope.organization_id AND connection.id=scope.connection_id
		WHERE scope.organization_id='org_alpha' AND scope.id=$1
	`, repositoryTestScopeID).Scan(&connectionActive, &scopeActive, &scopeStatus, &activationStatus); err != nil {
		t.Fatal(err)
	}
	if connectionActive != nil || scopeActive != nil || scopeStatus != "DRAFT" || activationStatus != "DRAFT" {
		t.Fatalf("source command created authority: connection=%v scope=%v statuses=%s/%s", connectionActive, scopeActive, scopeStatus, activationStatus)
	}
}

func repositoryIdempotencyKeyHash(key string) (string, error) {
	// The public request carries the opaque key; the receipt stores only the
	// accepted SHA-256 digest. Reuse the test fixture's deterministic key format
	// without importing an internal repository helper.
	digest := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}
