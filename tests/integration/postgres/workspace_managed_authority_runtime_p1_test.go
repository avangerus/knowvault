package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// Proofs for the five accepted-contract P1s of checkpoint 0055, each binding the
// real PostgreSQL fact loaders to the policy decision through the production
// Store. Every test targets one P1 and is named for it.

// setWorkspaceStatus forces a workspace lifecycle status for a test.
func setWorkspaceStatus(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, status string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `UPDATE public.workspace SET status = $3 WHERE organization_id = $1 AND id = $2`,
		organizationID, workspaceID, status); err != nil {
		t.Fatalf("set workspace status %s: %v", status, err)
	}
}

// TestAuthorityRuntimeWorkspaceLockPrecedesActorReload is the non-vacuous proof
// of P1.1 over real locks, with no production observability hook. An external
// transaction holds the organization row FOR UPDATE. The command's actor reload
// takes a FOR SHARE lock on that row, so the command blocks there — but, if the
// ADR-0053 order holds, only after it has already taken the workspace FOR UPDATE
// lock. While the command is blocked reloading the actor, a FOR UPDATE NOWAIT
// probe on the workspace must fail with lock_not_available: it can only fail if
// the command already holds the workspace lock. Reversing the order (actor
// before workspace) would leave the workspace unlocked at that point and the
// probe would succeed, failing this test.
func TestAuthorityRuntimeWorkspaceLockPrecedesActorReload(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	holder, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire holder connection: %v", err)
	}
	defer holder.Release()
	holderTx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatalf("begin holder transaction: %v", err)
	}
	defer func() { _ = holderTx.Rollback(ctx) }()
	if _, err := holderTx.Exec(ctx, `SELECT status FROM public.organization WHERE id = $1 FOR UPDATE`, fixture.organizationID); err != nil {
		t.Fatalf("hold organization row: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, runErr := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_lock_order"),
			baseMatrixIssue(fixture, "lock-order", fixture.ownerID, fixture.workspaceRevision))
		done <- runErr
	}()

	deadline := time.Now().Add(10 * time.Second)
	blocked := false
	for time.Now().Before(deadline) {
		var count int
		if err := admin.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE application_name = 'knowvault-runtime' AND state = 'active' AND wait_event_type = 'Lock'
		`).Scan(&count); err != nil {
			t.Fatalf("poll for the blocked command: %v", err)
		}
		if count > 0 {
			blocked = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !blocked {
		t.Fatal("the command never blocked reloading the actor; cannot prove the lock ordering")
	}

	_, probeErr := admin.Exec(ctx, `SELECT status FROM public.workspace WHERE organization_id = $1 AND id = $2 FOR UPDATE NOWAIT`,
		fixture.organizationID, fixture.workspaceID)
	var pgErr *pgconn.PgError
	if !errors.As(probeErr, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("workspace FOR UPDATE NOWAIT = %v, want lock_not_available (55P03): the workspace lock must already be held while the actor reload blocks", probeErr)
	}

	_ = holderTx.Rollback(ctx)
	if err := <-done; err != nil {
		t.Fatalf("the command must complete once the organization lock releases: %v", err)
	}
}

// TestAuthorityRuntimeTenantMismatchIsNeverAnOracle is the P1.5 proof. A request
// naming a foreign organization is always NOT_FOUND. A first-time cross-tenant
// command reserves one trusted-tenant NOT_FOUND receipt and audit event; a
// reused idempotency key returns NOT_FOUND without a new receipt or audit and
// without becoming a conflict or an existence oracle.
func TestAuthorityRuntimeTenantMismatchIsNeverAnOracle(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	crossTenant := func(key string) error {
		_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_"+key),
			workspacerepository.IssueGrantRequest{
				IdempotencyKey: authorityIdempotencyKey(key), OrganizationID: "org_somewhere_else",
				WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
				ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
				TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
			})
		return err
	}

	t.Run("first call reserves one NOT_FOUND receipt and audit, no grant", func(t *testing.T) {
		if err := crossTenant("tenant-fresh"); workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
			t.Fatalf("fresh cross-tenant code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", workspacerepository.CodeOf(err))
		}
		if got := countReceipts(t, ctx, admin, fixture.organizationID); got != 1 {
			t.Fatalf("fresh cross-tenant left %d receipts, want 1 (the NOT_FOUND receipt)", got)
		}
		if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != 1 {
			t.Fatalf("fresh cross-tenant left %d audit events, want 1", got)
		}
		if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != 0 {
			t.Fatalf("fresh cross-tenant created %d grants, want 0", got)
		}
		var status string
		var workspaceID *string
		if err := admin.QueryRow(ctx, `
			SELECT receipt.status, event.workspace_id
			FROM public.workspace_managed_authority_command_receipt AS receipt
			JOIN public.audit_event AS event
			  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
			WHERE receipt.organization_id = $1
		`, fixture.organizationID).Scan(&status, &workspaceID); err != nil {
			t.Fatalf("load NOT_FOUND receipt: %v", err)
		}
		if status != "NOT_FOUND" || workspaceID != nil {
			t.Fatalf("cross-tenant receipt = (%s, workspace=%v), want NOT_FOUND with null workspace", status, workspaceID)
		}
	})

	t.Run("reused key is NOT_FOUND, never a conflict, no new records", func(t *testing.T) {
		// A legitimate same-tenant SUCCESS consumes the key.
		if _, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_reused_legit"),
			workspacerepository.IssueGrantRequest{
				IdempotencyKey: authorityIdempotencyKey("tenant-reused"), OrganizationID: fixture.organizationID,
				WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
				ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
				TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("legit issue consuming the key: %v", err)
		}
		receiptsBefore := countReceipts(t, ctx, admin, fixture.organizationID)
		auditBefore := countAuthorityAudit(t, ctx, admin, fixture.organizationID)
		grantsBefore := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant")

		// The same key, now cross-tenant, must be NOT_FOUND — not a conflict —
		// and must not reveal or disturb the existing receipt.
		if err := crossTenant("tenant-reused"); workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
			t.Fatalf("reused-key cross-tenant code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND (never IDEMPOTENCY_CONFLICT)", workspacerepository.CodeOf(err))
		}
		if got := countReceipts(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
			t.Fatalf("reused-key cross-tenant changed receipts: %d -> %d", receiptsBefore, got)
		}
		if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != auditBefore {
			t.Fatalf("reused-key cross-tenant changed audit events: %d -> %d", auditBefore, got)
		}
		if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != grantsBefore {
			t.Fatalf("reused-key cross-tenant changed grants: %d -> %d", grantsBefore, got)
		}
	})
}

// TestAuthorityRuntimeReplayForbiddenInDeletingOrDeleted is the P1.4 proof:
// a stored result is replayable only while the workspace is ACTIVE, READ_ONLY or
// ARCHIVED. A DELETING or DELETED workspace terminates NOT_FOUND without
// revealing the result and without new records.
func TestAuthorityRuntimeReplayForbiddenInDeletingOrDeleted(t *testing.T) {
	for _, status := range []string{"DELETING", "DELETED"} {
		t.Run(status, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			fixture := setupAuthorityOpsFixture(t, ctx, admin)
			store := newAuthorityRuntime(t, ctx)

			request := workspacerepository.IssueGrantRequest{
				IdempotencyKey: authorityIdempotencyKey("replay-lifecycle-" + status), OrganizationID: fixture.organizationID,
				WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: fixture.workspaceRevision,
				ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: fixture.ownerID,
				TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
			}
			grant, issueErr := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_replay_lifecycle_issue"), request)
			if issueErr != nil {
				t.Fatalf("seed grant: %v", issueErr)
			}

			setWorkspaceStatus(t, ctx, admin, fixture.organizationID, fixture.workspaceID, status)
			receiptsBefore := countReceipts(t, ctx, admin, fixture.organizationID)
			auditBefore := countAuthorityAudit(t, ctx, admin, fixture.organizationID)

			// The exact same command (same key and request bytes) is now a replay
			// against a non-replayable workspace: NOT_FOUND, the stored grant is
			// not returned.
			result, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_replay_lifecycle_replay"), request)
			if workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
				t.Fatalf("replay in %s code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", status, workspacerepository.CodeOf(err))
			}
			if result.ResultID == grant.ResultID {
				t.Fatal("replay in a non-replayable workspace revealed the stored result")
			}
			if got := countReceipts(t, ctx, admin, fixture.organizationID); got != receiptsBefore {
				t.Fatalf("replay in %s created %d receipts", status, got-receiptsBefore)
			}
			if got := countAuthorityAudit(t, ctx, admin, fixture.organizationID); got != auditBefore {
				t.Fatalf("replay in %s created %d audit events", status, got-auditBefore)
			}
		})
	}
}

// TestAuthorityRuntimeGrantRevokedConfirmationDoesNotBlock is the P1.3 proof: a
// confirmation whose actor grant was later revoked is not derived-live, so it
// does not block a fresh confirm of the same tuple under a new live grant. The
// Go precheck matches the database derived-live set exactly.
func TestAuthorityRuntimeGrantRevokedConfirmationDoesNotBlock(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	// First confirmation under grant G1.
	firstGrant := issueRuntimeGrant(t, ctx, store, fixture, "block-g1")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_block_confirm1"),
		confirmRuntimeRequest(fixture, firstGrant, "block-confirm1")); err != nil {
		t.Fatalf("first confirm: %v", err)
	}
	// Revoke G1: the first confirmation is now grant-revoked and no longer live.
	if _, err := store.RevokeConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_block_revoke"),
		workspacerepository.RevokeGrantRequest{
			IdempotencyKey: authorityIdempotencyKey("block-revoke"), OrganizationID: fixture.organizationID,
			WorkspaceID: fixture.workspaceID, GrantID: firstGrant.ResultID, GrantRevision: 1, GrantHash: firstGrant.ResultHash,
			ExpectedPolicyRevision: fixture.policyID,
		}); err != nil {
		t.Fatalf("revoke first grant: %v", err)
	}

	// A fresh grant G2 and a confirm of the exact same tuple must succeed: the
	// grant-revoked first confirmation does not count as a live duplicate.
	secondGrant := issueRuntimeGrant(t, ctx, store, fixture, "block-g2")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, fixture.ownerID, "req_block_confirm2"),
		confirmRuntimeRequest(fixture, secondGrant, "block-confirm2")); err != nil {
		t.Fatalf("second confirm after grant revoke must succeed, got: %v", err)
	}
	if got := countAuthorityRows(t, ctx, admin, "workspace_managed_grant_confirmation"); got != 2 {
		t.Fatalf("confirmations = %d, want 2 (one grant-revoked, one live)", got)
	}
}

// TestAuthorityRuntimeGrantIssueTerminalMatrix drives GRANT_ISSUE to each
// reachable terminal through the production decision phase and asserts the
// persisted receipt status, the audit outcome/error code and workspace_id, and
// the absence of a grant row on every failure — not merely the returned code.
func TestAuthorityRuntimeGrantIssueTerminalMatrix(t *testing.T) {
	type expectation struct {
		code          workspacerepository.ErrorCode
		receiptStatus string
		auditOutcome  string
		auditError    string // "" means NULL
		wantWorkspace bool
		wantGrants    int64
	}
	cases := map[string]struct {
		expectation
		run func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store, fixture authorityOpsFixture) error
	}{
		"SUCCESS": {
			expectation{"", "SUCCESS", "SUCCESS", "", true, 1},
			func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store, fixture authorityOpsFixture) error {
				_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_matrix_success"), baseMatrixIssue(fixture, "matrix-success", fixture.ownerID, fixture.workspaceRevision))
				return err
			},
		},
		"DENIED": {
			expectation{workspacerepository.CodeAuthorityDenied, "DENIED", "DENIED", "WORKSPACE_AUTHORITY_DENIED", true, 0},
			func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store, fixture authorityOpsFixture) error {
				member := "usr_matrix_member"
				insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, member)
				seedWorkspaceMemberAs(t, ctx, admin, fixture.organizationID, fixture.workspaceID, member, "MEMBER", fixture.ownerID)
				_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, member, "req_matrix_denied"), baseMatrixIssue(fixture, "matrix-denied", fixture.ownerID, fixture.workspaceRevision))
				return err
			},
		},
		"NOT_FOUND": {
			expectation{workspacerepository.CodeAuthorityNotFound, "NOT_FOUND", "DENIED", "WORKSPACE_AUTHORITY_NOT_FOUND", false, 0},
			func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store, fixture authorityOpsFixture) error {
				outsider := "usr_matrix_outsider"
				insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, outsider)
				_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, outsider, "req_matrix_notfound"), baseMatrixIssue(fixture, "matrix-notfound", fixture.ownerID, fixture.workspaceRevision))
				return err
			},
		},
		"PRECONDITION_FAILED": {
			expectation{workspacerepository.CodeAuthorityPreconditionFailed, "PRECONDITION_FAILED", "FAILED", "WORKSPACE_AUTHORITY_PRECONDITION_FAILED", true, 0},
			func(t *testing.T, ctx context.Context, admin *pgxpool.Pool, store *workspacerepository.Store, fixture authorityOpsFixture) error {
				_, err := store.IssueConfirmationGrant(ctx, authorityAccess(fixture, fixture.ownerID, "req_matrix_precondition"), baseMatrixIssue(fixture, "matrix-precondition", fixture.ownerID, fixture.workspaceRevision+1))
				return err
			},
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			fixture := setupAuthorityOpsFixture(t, ctx, admin)
			store := newAuthorityRuntime(t, ctx)

			err := testCase.run(t, ctx, admin, store, fixture)
			if testCase.code == "" {
				if err != nil {
					t.Fatalf("%s returned %v, want success", name, err)
				}
			} else if workspacerepository.CodeOf(err) != testCase.code {
				t.Fatalf("%s returned code %q, want %q", name, workspacerepository.CodeOf(err), testCase.code)
			}
			var status, outcome string
			var errorCode, workspaceID *string
			if err := admin.QueryRow(ctx, `
				SELECT receipt.status, event.outcome, event.error_code, event.workspace_id
				FROM public.workspace_managed_authority_command_receipt AS receipt
				JOIN public.audit_event AS event
				  ON event.organization_id = receipt.organization_id AND event.id = receipt.audit_event_id
				WHERE receipt.organization_id = $1 AND receipt.operation = 'WORKSPACE_CONFIRMATION_GRANT_ISSUE'
			`, fixture.organizationID).Scan(&status, &outcome, &errorCode, &workspaceID); err != nil {
				t.Fatalf("load persisted receipt and audit: %v", err)
			}
			if status != testCase.receiptStatus || outcome != testCase.auditOutcome {
				t.Fatalf("%s persisted (status=%s, outcome=%s), want (%s, %s)", name, status, outcome, testCase.receiptStatus, testCase.auditOutcome)
			}
			gotError := ""
			if errorCode != nil {
				gotError = *errorCode
			}
			if gotError != testCase.auditError {
				t.Fatalf("%s audit error_code = %q, want %q", name, gotError, testCase.auditError)
			}
			if (workspaceID != nil) != testCase.wantWorkspace {
				t.Fatalf("%s audit workspace_id present = %v, want %v", name, workspaceID != nil, testCase.wantWorkspace)
			}
			if got := countAuthorityRows(t, ctx, admin, "workspace_source_confirmation_actor_grant"); got != testCase.wantGrants {
				t.Fatalf("%s grants = %d, want %d", name, got, testCase.wantGrants)
			}
		})
	}
}

func baseMatrixIssue(fixture authorityOpsFixture, label, target string, expectedRevision int64) workspacerepository.IssueGrantRequest {
	return workspacerepository.IssueGrantRequest{
		IdempotencyKey: authorityIdempotencyKey(label), OrganizationID: fixture.organizationID,
		WorkspaceID: fixture.workspaceID, ExpectedWorkspaceRevision: expectedRevision,
		ExpectedWorkspaceConfigurationHash: fixture.workspaceConfHash, TargetPrincipalID: target,
		TTLSeconds: 3600, ExpectedPolicyRevision: fixture.policyID,
	}
}

// TestAuthorityRuntimeDeniedVersusNotFoundOnMembershipLoss proves the two are
// distinct: an insufficient role with visibility is DENIED, while a real loss of
// membership visibility is NOT_FOUND.
func TestAuthorityRuntimeDeniedVersusNotFoundOnMembershipLoss(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityOpsFixture(t, ctx, admin)
	store := newAuthorityRuntime(t, ctx)

	// A MANAGER with a live grant confirms once, establishing they were eligible.
	manager := "usr_membership_manager"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, manager)
	seedWorkspaceMemberAs(t, ctx, admin, fixture.organizationID, fixture.workspaceID, manager, "MANAGER", fixture.ownerID)
	grant, _ := confirmRuntimeSuccess(t, ctx, store, admin, fixture, manager, "membership")

	// Insufficient role with visibility: demote to MEMBER, a fresh confirm is DENIED.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member SET role = 'MEMBER'
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, fixture.organizationID, fixture.workspaceID, manager); err != nil {
		t.Fatalf("demote to member: %v", err)
	}
	deniedRequest := confirmRuntimeRequest(fixture, grant, "membership-denied")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, manager, "req_membership_denied"), deniedRequest); workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityDenied {
		t.Fatalf("insufficient role code = %q, want WORKSPACE_AUTHORITY_DENIED", workspacerepository.CodeOf(err))
	}

	// Real loss of membership visibility: remove membership, a fresh confirm is NOT_FOUND.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member SET removed_at = transaction_timestamp(), valid_to_revision = 1000000
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, fixture.organizationID, fixture.workspaceID, manager); err != nil {
		t.Fatalf("remove membership: %v", err)
	}
	notFoundRequest := confirmRuntimeRequest(fixture, grant, "membership-notfound")
	if _, err := store.ConfirmManagedSource(ctx, authorityAccess(fixture, manager, "req_membership_notfound"), notFoundRequest); workspacerepository.CodeOf(err) != workspacerepository.CodeAuthorityNotFound {
		t.Fatalf("membership loss code = %q, want WORKSPACE_AUTHORITY_NOT_FOUND", workspacerepository.CodeOf(err))
	}
}
