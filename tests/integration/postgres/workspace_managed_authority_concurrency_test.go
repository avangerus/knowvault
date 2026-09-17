package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The warning contract registry is global and append-only, so its head is
// max(revision) rather than a row a command can lock. A confirmation command
// cannot protect its warning tuple with `SELECT ... FOR SHARE`: no row lock
// blocks the INSERT of a *new* revision, which is exactly how the head moves.
//
// The writer protocol is what makes that safe, and it is exactly one writer: a
// migration. Migration 000010 seeds revision 1 and then installs a guard that
// refuses every INSERT, UPDATE and DELETE unconditionally — from the runtime
// role, from an operator, from the table owner. A future migration introducing
// a v2 contract must therefore drop that guard explicitly.
//
// These tests prove both halves. The first pins the writer protocol as it
// stands. The rest prove that the deferred gate does not merely rely on it: with
// the guard dropped, exactly as the future v2 migration must, an advance still
// cannot slip between a command's deferred check and its commit, and an advance
// that lands earlier fails the command closed.

const (
	authorityRaceOrganization = "org_authority_race"
	authorityRaceOwner        = "usr_authority_race_owner"
	authorityRaceWorkspace    = "ws_authority_race"
)

// warningAdvanceSQL appends a second warning revision — the head move a
// confirmation must never commit across.
const warningAdvanceSQL = `
	INSERT INTO public.workspace_managed_warning_contract (
		revision, schema_version, warning_version, access_mode, risk_codes_json,
		acknowledgement_code, canonical_bytes, warning_contract_hash
	)
	SELECT 2, 'workspace-managed-warning-contract-v2', 'workspace-managed-risk-v2',
	       'WORKSPACE_MANAGED', '["SOURCE_NATIVE_ACL_NOT_ENFORCED"]'::jsonb,
	       'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL',
	       $1::bytea, 'sha256:' || encode(sha256($1::bytea), 'hex')
`

var warningAdvanceBytes = []byte(`{"schema_version":"workspace-managed-warning-contract-v2"}`)

// dropWarningImmutabilityGuard simulates the one writer the protocol permits:
// the future migration that introduces a v2 contract and must therefore drop
// the 000010 guard explicitly. Everything the tests below observe after this
// call is about the deferred gate alone, with the guard's protection removed.
func dropWarningImmutabilityGuard(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		DROP TRIGGER workspace_managed_warning_contract_immutable
		ON public.workspace_managed_warning_contract
	`); err != nil {
		t.Fatalf("drop the warning immutability guard: %v", err)
	}
}

// runConfirmUpToDeferredGate performs a whole confirmation command inside tx but
// stops short of COMMIT, then forces the deferred gates to run now with SET
// CONSTRAINTS ALL IMMEDIATE. After it returns, tx is still open and — if the
// gate is correct — holds the SHARE lock that a warning advance must wait for.
func runConfirmUpToDeferredGate(
	t *testing.T, ctx context.Context, tx pgx.Tx, fixture authorityOpsFixture, op authorityOp,
) (authorityOp, error) {
	t.Helper()
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, op.actor)
	op.at, _ = authorityTransactionSecond(t, ctx, tx)
	if err := fixture.reserve(t, ctx, tx, op); err != nil {
		return op, err
	}
	if err := fixture.insertResult(t, ctx, tx, op); err != nil {
		return op, err
	}
	if err := fixture.appendAudit(t, ctx, tx, op); err != nil {
		return op, err
	}
	if err := fixture.terminalize(t, ctx, tx, op); err != nil {
		return op, err
	}
	_, err := tx.Exec(ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	return op, err
}

func setupAuthorityRaceFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool) authorityOpsFixture {
	t.Helper()
	return setupAuthorityOpsTenant(t, ctx, admin,
		authorityRaceOrganization, authorityRaceOwner, authorityRaceWorkspace)
}

// TestAuthorityWarningRegistryHasExactlyOneWriter pins the writer protocol the
// deferred gate is designed around: while migration 000010's guard stands, no
// session of any role can move the warning head, so no runtime race exists to
// win. A change that made the registry writable at runtime must red this test
// before it could reach the gates below.
func TestAuthorityWarningRegistryHasExactlyOneWriter(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	app := openAuthorityAppPool(t, ctx)

	// The runtime role: no privilege, and no policy that would grant one.
	if _, err := app.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes); err == nil {
		t.Fatal("the runtime role advanced the warning contract registry")
	}

	// An operator connection with full table privileges: refused by the guard,
	// not by privileges. This is the assertion that makes the head immovable
	// rather than merely hard to move.
	_, err := admin.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes)
	if err == nil {
		t.Fatal("the warning contract registry is not immutable")
	}
	if !strings.Contains(err.Error(), "warning contract registry is immutable") {
		t.Fatalf("the advance was refused for the wrong reason: %v", err)
	}
}

// TestAuthorityWarningAdvanceCannotSlipBetweenDeferredCheckAndCommit is the
// proof the deferred gate stands on its own. With the immutability guard
// dropped — the only state in which an advance is possible at all — a
// concurrent advance still cannot land between a command's commit-time warning
// check and its commit. Without the SHARE lock the advance would commit inside
// that window and the confirmation would commit naming a warning contract that
// is no longer current, which is exactly what ADR-0053 forbids.
func TestAuthorityWarningAdvanceCannotSlipBetweenDeferredCheckAndCommit(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityRaceFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)
	dropWarningImmutabilityGuard(t, ctx, admin)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	confirm := fixture.baseOp(operationConfirm, 50)
	confirm.parentID, confirm.parentRevision, confirm.parentHash = grantID, grantRevision, grantHash

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	confirm, err = runConfirmUpToDeferredGate(t, ctx, tx, fixture, confirm)
	if err != nil {
		t.Fatalf("the honest confirmation must pass its deferred gate: %v", err)
	}

	// The command's deferred gate has now run and the transaction is still
	// open: this is exactly the window an advance would have to exploit. A
	// separate connection tries to take it, and must block — so a short
	// statement timeout is what distinguishes "blocked" from "slipped through".
	// Without the timeout a correct implementation would simply hang here.
	blocked, err := admin.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Release()
	if _, err := blocked.Exec(ctx, `SET statement_timeout = '2s'`); err != nil {
		t.Fatal(err)
	}
	_, err = blocked.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes)
	if err == nil {
		t.Fatal("a warning advance slipped in between the deferred check and commit")
	}
	if !strings.Contains(err.Error(), "canceling statement due to statement timeout") {
		t.Fatalf("the advance failed for a reason other than waiting on the command's lock: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("the confirmation must commit: %v", err)
	}

	var confirmations int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1 AND confirmation_id = $2
	`, fixture.organizationID, confirm.resultID).Scan(&confirmations); err != nil {
		t.Fatal(err)
	}
	if confirmations != 1 {
		t.Fatalf("the committed confirmation is missing: %d rows", confirmations)
	}

	// Once the command has committed, the advance is no longer a race and must
	// proceed. This is the control for the assertion above: it proves the
	// advance was blocked by the command's lock rather than by something
	// permanently broken about the statement itself.
	if _, err := blocked.Exec(ctx, `SET statement_timeout = '10s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes); err != nil {
		t.Fatalf("the advance must proceed once the command has committed: %v", err)
	}
}

// TestAuthorityWarningAdvanceBeforeCommitFailsTheCommandClosed is the other
// direction of the race: an advance that lands after the BEFORE INSERT gate
// proved the tuple current, but before the command reaches its deferred check,
// must fail the whole command rather than commit a confirmation naming a
// superseded warning contract.
func TestAuthorityWarningAdvanceBeforeCommitFailsTheCommandClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityRaceFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)
	dropWarningImmutabilityGuard(t, ctx, admin)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	confirm := fixture.baseOp(operationConfirm, 51)
	confirm.parentID, confirm.parentRevision, confirm.parentHash = grantID, grantRevision, grantHash

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, confirm.actor)
	confirm.at, _ = authorityTransactionSecond(t, ctx, tx)
	if err := fixture.reserve(t, ctx, tx, confirm); err != nil {
		t.Fatal(err)
	}
	if err := fixture.insertResult(t, ctx, tx, confirm); err != nil {
		t.Fatalf("the warning tuple is current at insert time: %v", err)
	}

	// The BEFORE INSERT gate alone would let this command commit; only the
	// deferred gate catches the advance.
	if _, err := admin.Exec(ctx, warningAdvanceSQL, warningAdvanceBytes); err != nil {
		t.Fatalf("advance the warning contract: %v", err)
	}

	if err := fixture.appendAudit(t, ctx, tx, confirm); err != nil {
		t.Fatal(err)
	}
	if err := fixture.terminalize(t, ctx, tx, confirm); err != nil {
		t.Fatal(err)
	}
	// Two deferred gates cover this direction and either may fire first:
	// 000010's confirmation exact guard already re-read the warning head at
	// commit, and 000011's gate re-reads it again under the share lock it takes
	// for the other direction. The contract is that the command fails closed at
	// commit naming the warning head, not which of the two says so.
	err = tx.Commit(ctx)
	if err == nil {
		t.Fatal("a confirmation naming a superseded warning contract was committed")
	}
	if !strings.Contains(err.Error(), "lost the current warning contract before commit") &&
		!strings.Contains(err.Error(), "warning is not the current registry revision") {
		t.Fatalf("the command failed for the wrong reason: %v", err)
	}

	var confirmations int64
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1
	`, fixture.organizationID).Scan(&confirmations); err != nil {
		t.Fatal(err)
	}
	if confirmations != 0 {
		t.Fatalf("the rolled-back command left %d confirmations behind", confirmations)
	}
}

// TestAuthorityConfirmationRefusesAnIsolationLevelItCannotProve closes the hole
// the share lock alone leaves. A table lock serializes the writer but does not
// advance this transaction's snapshot, so under REPEATABLE READ or SERIALIZABLE
// the gate's re-read would see the pre-advance snapshot and pass — the gate
// would degrade into a silent no-op exactly where it is supposed to fail
// closed. The policy gate has a row to lock and so gets a serialization failure
// for free; this one does not, so it asserts its precondition instead.
func TestAuthorityConfirmationRefusesAnIsolationLevelItCannotProve(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityRaceFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, grantRevision, grantHash := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	for _, level := range []pgx.TxIsoLevel{pgx.RepeatableRead, pgx.Serializable} {
		t.Run(string(level), func(t *testing.T) {
			confirm := fixture.baseOp(operationConfirm, 60+len(level))
			confirm.parentID, confirm.parentRevision, confirm.parentHash = grantID, grantRevision, grantHash

			tx, err := app.BeginTx(ctx, pgx.TxOptions{IsoLevel: level})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()

			_, err = runConfirmUpToDeferredGate(t, ctx, tx, fixture, confirm)
			if err == nil {
				err = tx.Commit(ctx)
			}
			if err == nil {
				t.Fatalf("a confirmation committed under %s, where the warning gate cannot observe an advance", level)
			}
			if !strings.Contains(err.Error(), "require READ COMMITTED") {
				t.Fatalf("the command failed for the wrong reason under %s: %v", level, err)
			}

			var confirmations int64
			if err := admin.QueryRow(ctx, `
				SELECT count(*) FROM public.workspace_managed_grant_confirmation
				WHERE organization_id = $1
			`, fixture.organizationID).Scan(&confirmations); err != nil {
				t.Fatal(err)
			}
			if confirmations != 0 {
				t.Fatalf("the refused command left %d confirmations behind", confirmations)
			}
		})
	}
}

// TestAuthorityConfirmationsOfTwoTenantsDoNotBlockEachOther proves SHARE is the
// right mode and not merely a sufficient one. The warning registry is global,
// so a lock on it is the one gate in this migration that could couple tenants
// together; SHARE is self-compatible, so it must not. A stricter mode would
// still close the race and would still pass every test above, and would
// serialize every confirmation in the deployment behind one lock.
//
// Two tenants, not two commands of one tenant: same-tenant commands already
// serialize on their audit chain head, which would mask the property under test.
func TestAuthorityConfirmationsOfTwoTenantsDoNotBlockEachOther(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	first := setupAuthorityRaceFixture(t, ctx, admin)
	second := setupAuthorityOpsTenant(t, ctx, admin,
		authorityRaceOrganization+"_b", authorityRaceOwner+"_b", authorityRaceWorkspace+"_b")
	app := openAuthorityAppPool(t, ctx)

	firstGrant, firstRevision, firstHash := issueOpsGrant(t, ctx, app, admin, first, 1)
	secondGrant, secondRevision, secondHash := issueOpsGrant(t, ctx, app, admin, second, 2)

	firstConfirm := first.baseOp(operationConfirm, 52)
	firstConfirm.parentID, firstConfirm.parentRevision, firstConfirm.parentHash =
		firstGrant, firstRevision, firstHash
	secondConfirm := second.baseOp(operationConfirm, 53)
	secondConfirm.parentID, secondConfirm.parentRevision, secondConfirm.parentHash =
		secondGrant, secondRevision, secondHash

	firstTx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = firstTx.Rollback(ctx) }()
	if _, err := runConfirmUpToDeferredGate(t, ctx, firstTx, first, firstConfirm); err != nil {
		t.Fatalf("the first tenant's confirmation must pass its deferred gate: %v", err)
	}

	// The first tenant's command is holding its SHARE lock on the global
	// registry. The second tenant's command must still take the same lock and
	// pass its own gate; the short timeout makes a regression to a conflicting
	// mode fail here rather than hang.
	secondCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	secondTx, err := app.Begin(secondCtx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = secondTx.Rollback(ctx) }()
	if _, err := secondTx.Exec(secondCtx, `SET statement_timeout = '3s'`); err != nil {
		t.Fatal(err)
	}
	if _, err := runConfirmUpToDeferredGate(t, secondCtx, secondTx, second, secondConfirm); err != nil {
		t.Fatalf("two tenants' confirmations must not block each other: %v", err)
	}

	if err := firstTx.Commit(ctx); err != nil {
		t.Fatalf("commit the first tenant's confirmation: %v", err)
	}
	if err := secondTx.Commit(secondCtx); err != nil {
		t.Fatalf("commit the second tenant's confirmation: %v", err)
	}
}

// TestAuthorityReceiptSurvivesRuntimeButYieldsToTenantHardDelete pins the two
// halves of the receipt's delete contract. Ordinary runtime can never delete a
// receipt — it is the evidence that a command happened. A tenant hard-delete
// must still remove it child-first, or the receipt would pin the tenant's rows
// forever and make erasure impossible.
func TestAuthorityReceiptSurvivesRuntimeButYieldsToTenantHardDelete(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityRaceFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	grantID, _, _ := issueOpsGrant(t, ctx, app, admin, fixture, 1)

	// The runtime role cannot delete its own receipt, even inside its own
	// tenant and as the actor who created it. It is refused before the guard
	// even runs: the role holds no DELETE privilege on the relation at all.
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, fixture.organizationID, fixture.ownerID)
	if _, err := tx.Exec(ctx, `
		DELETE FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1
	`, fixture.organizationID); err == nil {
		t.Fatal("the runtime role deleted an authority receipt")
	} else if !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("the runtime delete failed for the wrong reason: %v", err)
	}
	_ = tx.Rollback(ctx)

	// The hard-delete path is not an operator escape hatch either: it opens
	// only while the organization is DELETING or DELETED. An operator delete
	// against a live tenant is still refused by the guard.
	_, err = admin.Exec(ctx, `
		DELETE FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1
	`, fixture.organizationID)
	if err == nil {
		t.Fatal("a receipt of a live tenant was hard-deleted")
	}
	if !strings.Contains(err.Error(), "append-only outside tenant hard-delete") {
		t.Fatalf("the live-tenant delete was refused for the wrong reason: %v", err)
	}

	if _, err := admin.Exec(ctx, `
		UPDATE public.organization SET status = 'DELETING' WHERE id = $1
	`, fixture.organizationID); err != nil {
		t.Fatalf("mark the tenant deleting: %v", err)
	}

	// Child-first: the authority row references the receipt, so it goes first.
	// Deleting the receipt while the grant still names it must be impossible —
	// otherwise erasure could leave a grant claiming a receipt that is gone.
	if _, err := admin.Exec(ctx, `
		DELETE FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1
	`, fixture.organizationID); err == nil {
		t.Fatal("a receipt was deleted out from under the authority row that names it")
	}
	if _, err := admin.Exec(ctx, `
		DELETE FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id = $1 AND grant_id = $2
	`, fixture.organizationID, grantID); err != nil {
		t.Fatalf("hard-delete the authority row: %v", err)
	}
	deleted, err := admin.Exec(ctx, `
		DELETE FROM public.workspace_managed_authority_command_receipt WHERE organization_id = $1
	`, fixture.organizationID)
	if err != nil {
		t.Fatalf("hard-delete the receipt of a deleting tenant: %v", err)
	}
	if deleted.RowsAffected() == 0 {
		t.Fatal("the tenant hard-delete removed no receipt")
	}
}
