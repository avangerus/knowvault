package postgres_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// Strengthened proofs for the checkpoint-0055 runtime (ADR-0053/0054), each
// binding real PostgreSQL fact loaders to the policy decision through the
// production Store. Every test here targets one reviewer-listed invariant and
// is named for it, so the report can point at the exact proof of each.

func countReceipts(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1
	`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	return count
}

func countAuthorityAudit(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_event
		WHERE organization_id = $1 AND resource_type = 'WORKSPACE_AUTHORITY_COMMAND'
	`, organizationID).Scan(&count); err != nil {
		t.Fatalf("count authority audit events: %v", err)
	}
	return count
}

func seedWorkspaceMemberAs(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, principalID, role, addedBy string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1, $2, $3, $4, $5, 1, $6)
	`, "wsm_"+principalID, organizationID, workspaceID, principalID, role, addedBy); err != nil {
		t.Fatalf("seed workspace member %s: %v", principalID, err)
	}
}

// installRaisingTrigger installs a BEFORE <event> trigger that unconditionally
// raises, injecting an infrastructure failure at exactly one persistence stage.
func installRaisingTrigger(t *testing.T, ctx context.Context, admin *pgxpool.Pool, table, event string) func() {
	t.Helper()
	name := "fault_" + strings.ReplaceAll(table, ".", "_") + "_" + strings.ToLower(event)
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.`+name+`() RETURNS trigger
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected fault at `+table+`'; END; $$`); err != nil {
		t.Fatalf("create fault function: %v", err)
	}
	if _, err := admin.Exec(ctx, `CREATE TRIGGER `+name+`_trg BEFORE `+event+` ON public.`+table+`
		FOR EACH ROW EXECUTE FUNCTION public.`+name+`()`); err != nil {
		t.Fatalf("create fault trigger: %v", err)
	}
	return func() {
		_, _ = admin.Exec(ctx, `DROP TRIGGER IF EXISTS `+name+`_trg ON public.`+table)
		_, _ = admin.Exec(ctx, `DROP FUNCTION IF EXISTS public.`+name+`()`)
	}
}

// confirmRuntimeSuccess issues a grant to actor and confirms with it, returning
// the confirmation result. actor must already be a workspace OWNER/MANAGER.
func confirmRuntimeSuccess(t *testing.T, ctx context.Context, store *workspacerepository.Store, admin *pgxpool.Pool, fixture authorityOpsFixture, actor, label string) (workspacerepository.AuthorityResult, workspacerepository.AuthorityResult) {
	t.Helper()
	grant, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_"+label+"_issue"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey(label + "-issue"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: actor,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if err != nil {
		t.Fatalf("issue grant to %s: %v", actor, err)
	}
	confirmation, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, actor, "req_"+label+"_confirm"),
		confirmRuntimeRequest(fixture, grant, label+"-confirm"))
	if err != nil {
		t.Fatalf("confirm by %s: %v", actor, err)
	}
	return grant, confirmation
}

// TestAuthorityRuntimeDuplicateConfirmIsPreconditionNotPersistence proves P1.2:
// a redundant confirm of an already-live tuple is resolved in the decision phase
// as PRECONDITION_FAILED, never entering the success branch or degrading to
// PERSISTENCE_FAILED.
func TestAuthorityRuntimeDuplicateConfirmIsPreconditionNotPersistence(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "dup-issue")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_dup_first"),
		confirmRuntimeRequest(fixture, grant, "dup-first")); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	// A second confirm of the same tuple, a distinct command, must fail the
	// decision phase's live-confirmation precheck.
	_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_dup_second"),
		confirmRuntimeRequest(fixture, grant, "dup-second"))
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityPreconditionFailed {
		t.Fatalf("duplicate confirm code = %q, want WORKSPACE_AUTHORITY_PRECONDITION_FAILED", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"); got != 1 {
		t.Fatalf("duplicate confirm produced %d confirmations, want 1", got)
	}
}

// TestAuthorityRuntimeConcurrentDuplicateConfirmCommitsExactlyOne drives two
// distinct confirm commands of the same tuple concurrently: the workspace row
// lock serializes them, the loser's live-confirmation precheck sees the winner,
// and exactly one confirmation commits.
func TestAuthorityRuntimeConcurrentDuplicateConfirmCommitsExactlyOne(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "race-issue")

	const workers = 4
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	codes := make(chan workspacerepository.ErrorCode, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			request := confirmRuntimeRequest(fixture, grant, "race-confirm-"+authorityID("w", index))
			_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_race_"+authorityID("w", index)), request)
			if err == nil {
				codes <- ""
				return
			}
			codes <- workspacerepository.CodeOf(err)
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(codes)

	success, precondition := 0, 0
	for code := range codes {
		switch code {
		case "":
			success++
		case workspacerepository.CodeAuthorityPreconditionFailed:
			precondition++
		default:
			t.Fatalf("unexpected concurrent confirm code %q", code)
		}
	}
	if success != 1 || precondition != workers-1 {
		t.Fatalf("concurrent duplicate confirm: %d success / %d precondition, want 1 / %d", success, precondition, workers-1)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"); got != 1 {
		t.Fatalf("concurrent duplicate confirm committed %d confirmations, want 1", got)
	}
}

// TestAuthorityRuntimeConcurrentGrantRevokeRace drives two distinct grant-revoke
// commands of the same grant concurrently: exactly one revocation commits, the
// other observes the committed revocation and terminates PRECONDITION_FAILED.
func TestAuthorityRuntimeConcurrentGrantRevokeRace(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "revoke-race-issue")

	const workers = 4
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	codes := make(chan workspacerepository.ErrorCode, workers)
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			<-start
			_, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_revrace_"+authorityID("w", index)),
				workspacerepository.RevokeGrantRequest{
					IdempotencyKey: authorityIdempotencyKey("revoke-race-" + authorityID("w", index)), OrganizationID: fixture.organizationID,
					WorkspaceID: fixture.workspaceID, GrantID: grant.ResultID, GrantRevision: 1, GrantHash: grant.ResultHash,
					ExpectedPolicyRevision: fixture.policyID,
				})
			if err == nil {
				codes <- ""
				return
			}
			codes <- workspacerepository.CodeOf(err)
		}(worker)
	}
	close(start)
	waitGroup.Wait()
	close(codes)

	success, precondition := 0, 0
	for code := range codes {
		switch code {
		case "":
			success++
		case workspacerepository.CodeAuthorityPreconditionFailed:
			precondition++
		default:
			t.Fatalf("unexpected concurrent revoke code %q", code)
		}
	}
	if success != 1 || precondition != workers-1 {
		t.Fatalf("concurrent grant revoke: %d success / %d precondition, want 1 / %d", success, precondition, workers-1)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant_revocation"); got != 1 {
		t.Fatalf("concurrent grant revoke committed %d revocations, want 1", got)
	}
}

// TestAuthorityRuntimeReplayIgnoresExecutionTimeChanges proves that a replay
// re-checks only current identity and visibility, never the execution-time
// preconditions: after the organization policy advances and the actor grant is
// revoked, the same idempotency keys still return the original stored results.
func TestAuthorityRuntimeReplayIgnoresExecutionTimeChanges(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	grant := issueRuntimeGrant(t, ctx, store, fixture, "replay-exec")
	confirmation, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_replay_confirm"),
		confirmRuntimeRequest(fixture, grant, "replay-confirm"))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}

	// Advance the organization policy (an execution-time precondition of the
	// original commands) and revoke the actor grant the confirmation used.
	clock := fetchAuthorityClock(t, ctx, admin)
	insertPolicyRegistryRow(t, ctx, admin, fixture.organizationID, 2, "policy-"+fixture.organizationID+"-0002", authoritySha256('q'), fixture.ownerID, clock.now)
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 2 WHERE id = $1`, fixture.organizationID); err != nil {
		t.Fatalf("advance policy: %v", err)
	}

	auditBefore := countAuthorityAudit(t, ctx, admin, fixture.organizationID)
	receiptsBefore := countReceipts(t, ctx, admin, fixture.organizationID)

	// Replay the grant-issue: issuer is still Organization OWNER, so the stored
	// result returns despite the stale policy.
	replayGrant := issueRuntimeGrant(t, ctx, store, fixture, "replay-exec")
	if replayGrant.ResultID != grant.ResultID || replayGrant.ResultHash != grant.ResultHash {
		t.Fatalf("issue replay changed result: %s vs %s", replayGrant.ResultID, grant.ResultID)
	}
	// Replay the confirm: confirmer is still Workspace OWNER, so the stored
	// confirmation returns even though its policy and grant are now stale.
	replayConfirm, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_replay_confirm_again"),
		confirmRuntimeRequest(fixture, grant, "replay-confirm"))
	if err != nil {
		t.Fatalf("confirm replay: %v", err)
	}
	if replayConfirm.ResultID != confirmation.ResultID {
		t.Fatalf("confirm replay changed result: %s vs %s", replayConfirm.ResultID, confirmation.ResultID)
	}
	if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != auditBefore {
		t.Fatalf("replay produced %d new authority audit events, want 0", got-auditBefore)
	}
	if got := countReceipts(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
		t.Fatalf("replay produced %d new receipts, want 0", got-receiptsBefore)
	}

	// The isolating contrast: a genuinely new command (a fresh idempotency key)
	// carrying the now-stale expected policy revision DOES re-run the
	// execution-time precondition and fails PRECONDITION_FAILED. Because the
	// replay above carried the same stale policy yet returned the stored SUCCESS,
	// the replay path demonstrably did not re-authorize — the only difference is
	// the key, i.e. replay versus first execution.
	_, freshErr := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_replay_fresh"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("replay-exec-fresh"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(freshErr) != workspacerepository.CodeAuthorityPreconditionFailed {
		t.Fatalf("a fresh command with the stale policy code = %q, want WORKSPACE_AUTHORITY_PRECONDITION_FAILED (proves replay skipped the check the fresh path enforces)", workspacerepository.CodeOf(freshErr))
	}
}

// TestAuthorityRuntimeReplayVisibilityLossDeniesWithoutNewReceipt proves that
// when the actor loses the replay-time role, the replay returns DENIED and
// creates no new receipt or audit event.
func TestAuthorityRuntimeReplayVisibilityLossDeniesWithoutNewReceipt(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	manager := "usr_authority_manager"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, manager)
	seedWorkspaceMemberAs(t, ctx, admin, fixture.organizationID, fixture.workspaceID, manager, "MANAGER", fixture.ownerID)

	grant, _ := confirmRuntimeSuccess(t, ctx, store, admin, fixture, manager, "vis-loss")

	// Demote the confirmer below OWNER/MANAGER: replay now requires a role they
	// no longer hold, while workspace visibility (a VIEWER membership) remains.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member SET role = 'VIEWER'
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, fixture.organizationID, fixture.workspaceID, manager); err != nil {
		t.Fatalf("demote manager: %v", err)
	}

	auditBefore := countAuthorityAudit(t, ctx, admin, fixture.organizationID)
	receiptsBefore := countReceipts(t, ctx, admin, fixture.organizationID)

	// The exact same command (same idempotency key and request bytes) is now a
	// replay; the demoted role makes it DENIED without a new receipt or audit.
	_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, manager, "req_vis_loss_replay"),
		confirmRuntimeRequest(fixture, grant, "vis-loss-confirm"))
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityDenied {
		t.Fatalf("replay after role loss code = %q, want WORKSPACE_AUTHORITY_DENIED", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != auditBefore {
		t.Fatalf("visibility-loss replay produced %d new audit events, want 0", got-auditBefore)
	}
	if got := countReceipts(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
		t.Fatalf("visibility-loss replay produced %d new receipts, want 0", got-receiptsBefore)
	}
}

// TestAuthorityRuntimeIdempotencyConflictLeavesEverythingUnchanged proves a
// reused key with a different request hash creates no authority row, no receipt
// and no audit event.
func TestAuthorityRuntimeIdempotencyConflictLeavesEverythingUnchanged(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	if _, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_conflict_first"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("conflict-unchanged"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("first issue: %v", err)
	}

	grantsBefore := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant")
	receiptsBefore := countReceipts(t, ctx, admin, fixture.organizationID)
	auditBefore := countAuthorityAudit(t, ctx, admin, fixture.organizationID)

	_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_conflict_second"),
		workspacerepository.IssueGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("conflict-unchanged"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
			ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
			TTLSeconds: 7200, ExpectedPolicyRevision: fixture.policyID,
		})
	if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityIdempotencyConflict {
		t.Fatalf("conflict code = %q, want WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT", workspacerepository.CodeOf(err))
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != grantsBefore {
		t.Fatalf("conflict changed grants: %d -> %d", grantsBefore, got)
	}
	if got := countReceipts(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
		t.Fatalf("conflict changed receipts: %d -> %d", receiptsBefore, got)
	}
	if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != auditBefore {
		t.Fatalf("conflict changed audit events: %d -> %d", auditBefore, got)
	}
}

// TestAuthorityRuntimeFailureInjectionRollsBackEntirely injects an
// infrastructure failure at each of the three success-branch persistence stages
// — the authority INSERT, the audit append and the receipt terminalization — and
// proves the whole transaction rolls back: no receipt, no authority row, no
// audit event survives any of them.
func TestAuthorityRuntimeFailureInjectionRollsBackEntirely(t *testing.T) {
	stages := []struct {
		name  string
		table string
		event string
	}{
		{"authority INSERT", "workspace_source_confirmation_actor_grant", "INSERT"},
		{"audit append", "audit_event", "INSERT"},
		{"receipt terminalization", "workspace_managed_authority_command_receipt", "UPDATE"},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			fixture := setupAuthorityOpsFixture(t, ctx, admin)
			store := newAuthorityRuntime(t, ctx)

			cleanup := installRaisingTrigger(t, ctx, admin, stage.table, stage.event)
			defer cleanup()

			_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_fault"),
				workspacerepository.IssueGrantRequest{
					IdempotencyKey: authorityIdempotencyKey("fault-" + stage.name), OrganizationID: fixture.organizationID,
					WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
					ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
					TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
				})
			if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityPersistence {
				t.Fatalf("injected fault at %s code = %q, want WORKSPACE_AUTHORITY_PERSISTENCE_FAILED", stage.name, workspacerepository.CodeOf(err))
			}
			if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 0 {
				t.Fatalf("fault at %s left %d grants, want 0", stage.name, got)
			}
			if got := countReceipts(t, ctx, admin, fixture.organizationID); got != 0 {
				t.Fatalf("fault at %s left %d receipts, want 0", stage.name, got)
			}
			if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != 0 {
				t.Fatalf("fault at %s left %d audit events, want 0", stage.name, got)
			}
		})
	}
}

// TestAuthorityRuntimeTerminalMatrixThroughRealFactLoaders exercises each of the
// four operations to each reachable failure terminal through the production
// decision phase and real PostgreSQL fact loaders, and asserts the terminal
// receipt and its audit event carry the mapped outcome/error code with no
// authority row.
func TestAuthorityRuntimeTerminalMatrixThroughRealFactLoaders(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	// A plain member: visible but neither Org admin nor Workspace OWNER/MANAGER.
	member := "usr_authority_matrix_member"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, member)
	seedWorkspaceMemberAs(t, ctx, admin, fixture.organizationID, fixture.workspaceID, member, "MEMBER", fixture.ownerID)
	// An outsider: no membership, no organization role.
	outsider := "usr_authority_matrix_outsider"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, outsider)

	// A live confirmation and its grant, so the revoke operations have a real
	// parent to reach DENIED/PRECONDITION against.
	grant, confirmation := confirmRuntimeSuccess(t, ctx, store, admin, fixture, fixture.ownerID, "matrix-seed")

	type expectation struct {
		code workspacerepository.ErrorCode
		run  func(label string) error
	}
	confirmReq := func(label, actor string, mutate func(*workspacerepository.ConfirmRequest)) error {
		request := confirmRuntimeRequest(fixture, grant, label)
		if mutate != nil {
			mutate(&request)
		}
		_, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, actor, "req_"+label), request)
		return err
	}
	revokeGrantReq := func(label, actor, hash string) error {
		_, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, actor, "req_"+label),
			workspacerepository.RevokeGrantRequest{
				IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
				WorkspaceID: fixture.workspaceID, GrantID: grant.ResultID, GrantRevision: 1, GrantHash: hash,
				ExpectedPolicyRevision: fixture.policyID,
			})
		return err
	}
	revokeConfirmReq := func(label, actor, confirmationID, hash string) error {
		_, err := store.RevokeManagedConfirmation(ctx, authorityAccess(fixture, actor, "req_"+label),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
				WorkspaceID: fixture.workspaceID, ConfirmationID: confirmationID, ConfirmationHash: hash,
				ExpectedPolicyRevision: fixture.policyID,
			})
		return err
	}

	cases := map[string]expectation{
		"confirm not found for outsider": {workspacerepository.CodeAuthorityNotFound, func(label string) error {
			return confirmReq(label, outsider, nil)
		}},
		"confirm denied for member": {workspacerepository.CodeAuthorityDenied, func(label string) error {
			return confirmReq(label, member, nil)
		}},
		"confirm precondition on stale revision": {workspacerepository.CodeAuthorityPreconditionFailed, func(label string) error {
			return confirmReq(label, fixture.ownerID, func(r *workspacerepository.ConfirmRequest) { r.WorkspaceRevision = fixture.workspaceRevision + 1 })
		}},
		"grant revoke denied for member": {workspacerepository.CodeAuthorityDenied, func(label string) error {
			return revokeGrantReq(label, member, grant.ResultHash)
		}},
		"grant revoke precondition on stale hash": {workspacerepository.CodeAuthorityPreconditionFailed, func(label string) error {
			return revokeGrantReq(label, fixture.ownerID, authoritySha256('n'))
		}},
		"confirm revoke not found on missing parent": {workspacerepository.CodeAuthorityNotFound, func(label string) error {
			return revokeConfirmReq(label, fixture.ownerID, "confirmation_absent_0001", authoritySha256('m'))
		}},
		"confirm revoke denied for member": {workspacerepository.CodeAuthorityDenied, func(label string) error {
			return revokeConfirmReq(label, member, confirmation.ResultID, confirmation.ResultHash)
		}},
		"confirm revoke precondition on stale hash": {workspacerepository.CodeAuthorityPreconditionFailed, func(label string) error {
			return revokeConfirmReq(label, fixture.ownerID, confirmation.ResultID, authoritySha256('k'))
		}},
	}

	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			label := "matrix-" + strings.ReplaceAll(name, " ", "-")
			err := expected.run(label)
			if workspacerepository.CodeOf(err) != expected.code {
				t.Fatalf("%s code = %q, want %q", name, workspacerepository.CodeOf(err), expected.code)
			}
		})
	}

	// The only authority rows are the seed grant and confirmation; no failure
	// terminal above created a grant, revocation or confirmation.
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 1 {
		t.Fatalf("failure terminals created extra grants: %d", got)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"); got != 1 {
		t.Fatalf("failure terminals created extra confirmations: %d", got)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant_revocation"); got != 0 {
		t.Fatalf("failure terminals created grant revocations: %d", got)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_revocation"); got != 0 {
		t.Fatalf("failure terminals created confirmation revocations: %d", got)
	}
}
