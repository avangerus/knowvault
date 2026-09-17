package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// authorityID produces a valid app.source_generated_id_is_valid(value, prefix)
// identifier: prefix + "_0" + 25 zero-padded decimal digits. Digits are all
// members of the closed Crockford-alphabet character class the validator
// requires, and the leading "0" satisfies the required first-character range.
func authorityID(prefix string, sequence int) string {
	return fmt.Sprintf("%s_0%025d", prefix, sequence)
}

// authoritySha256 derives a distinct, well-formed "sha256:<64 lowercase
// hex>" value from a single seed byte, so tests can name hashes memorably
// ('g' for grant, 'w' for warning, ...) while guaranteeing every distinct
// seed produces a distinct, valid hex digest (a real SHA-256 of the seed).
func authoritySha256(seed byte) string {
	sum := sha256.Sum256([]byte{seed})
	return "sha256:" + hex.EncodeToString(sum[:])
}

const (
	confirmationScopeID    = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	confirmationScopeHash  = "sha256:6666666666666666666666666666666666666666666666666666666666666666"
	confirmationWarningVer = "workspace-managed-risk-v1"
	confirmationWarnHash   = "sha256:58a05c0a7a3960ed45ccea66d8c9a570e581ff97438f407c20ec9c669512cd2d"
	confirmationAckCode    = "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
)

// authorityClock is one consistent snapshot of canonical authority-timestamp-v1
// strings, every one of them derived from a single real PostgreSQL
// transaction_timestamp() call (never the Go process clock). Using offsets
// relative to the live server clock instead of calendar-fixed dates means
// these tests never expire: a fixed "2026-07-16" fixture would silently start
// failing every positive-path test once the real date passed it (the actor
// grant's not-in-the-future and validity-window guards compare directly
// against the server's live "now"). No sleep is used anywhere; every field
// below is computed in one SQL statement so they share one exact instant.
type authorityClock struct {
	now         string // the current second, exactly.
	grantedAt   string // now - 3h: safely before validFrom.
	validFrom   string // now - 2h: safely in the past, before confirmedAt.
	confirmedAt string // now - 2m: safely in the past, before revokedAt.
	revokedAt   string // now - 1m: safely in the past, before now.
	validUntil  string // now + 24h: safely in the future.
	farFuture   string // now + 50y: unambiguously "in the future" for any test run.
}

// fetchAuthorityClock captures one authorityClock snapshot from the real
// PostgreSQL server clock. All fields come from the same transaction_
// timestamp() evaluation, so their relative ordering is guaranteed regardless
// of wall-clock date.
func fetchAuthorityClock(t *testing.T, ctx context.Context, admin *pgxpool.Pool) authorityClock {
	t.Helper()
	const format = `'YYYY-MM-DD"T"HH24:MI:SS"Z"'`
	var clock authorityClock
	if err := admin.QueryRow(ctx, `
		SELECT
			to_char(date_trunc('second', transaction_timestamp()) AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) - interval '3 hours') AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) - interval '2 hours') AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) - interval '2 minutes') AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) - interval '1 minute') AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) + interval '24 hours') AT TIME ZONE 'UTC', `+format+`),
			to_char((date_trunc('second', transaction_timestamp()) + interval '50 years') AT TIME ZONE 'UTC', `+format+`)
	`).Scan(&clock.now, &clock.grantedAt, &clock.validFrom, &clock.confirmedAt, &clock.revokedAt, &clock.validUntil, &clock.farFuture); err != nil {
		t.Fatalf("fetch authority clock snapshot from PostgreSQL: %v", err)
	}
	return clock
}

// confirmationFixture captures everything needed to compose one exact valid
// workspace_managed_grant_confirmation row and its actor grant.
type confirmationFixture struct {
	organizationID    string
	ownerID           string
	workspaceID       string
	workspaceRevision int64
	workspaceConfHash string

	sourceScopeID       string
	sourceScopeRevision int64
	scopeConfigHash     string

	policyNumber int64
	policyID     string

	grantID       string
	grantRevision int64
	grantHash     string

	clock authorityClock
}

// insertPolicyRegistryRow inserts one organization_policy_revision row.
func insertPolicyRegistryRow(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string, revision int64, policyID, policyHash, activatedBy, activatedAt string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (
			organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by
		) VALUES ($1, $2, $3, $4, $5, $6)
	`, organizationID, revision, policyID, policyHash, activatedAt, activatedBy); err != nil {
		t.Fatalf("insert policy registry row: %v", err)
	}
}

// grantInsertParams is every field needed to insert one
// workspace_source_confirmation_actor_grant row using a shared authorityClock
// snapshot, so every ad hoc grant across these tests is built from the same
// server-relative timestamp source instead of a calendar-fixed literal.
type grantInsertParams struct {
	organizationID string
	grantID        string
	workspaceID    string
	principalID    string
	grantedBy      string
	policyNumber   int64
	policyID       string
	grantHash      string
	clock          authorityClock
}

func insertGrantRow(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, p grantInsertParams) error {
	_, err := executor.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant (
			organization_id, grant_id, revision, workspace_id, principal_id, permission,
			valid_from, valid_until, policy_revision_number, policy_revision, grant_hash, granted_by, granted_at
		) VALUES ($1, $2, 1, $3, $4, 'workspace.source.confirm', $5, $6, $7, $8, $9, $10, $11)
	`, p.organizationID, p.grantID, p.workspaceID, p.principalID,
		p.clock.validFrom, p.clock.validUntil, p.policyNumber, p.policyID, p.grantHash, p.grantedBy, p.clock.grantedAt)
	return err
}

// setupConfirmationFixture builds: organization+workspace (revision 1),
// WORKSPACE_MANAGED source scope chain, an enabled WORKSPACE_MANAGED binding
// at workspace revision 2, the first policy registry row and one valid actor
// grant. It returns everything needed to compose a valid confirmation row.
func setupConfirmationFixture(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, ownerID, workspaceID string) confirmationFixture {
	t.Helper()
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	insertSourceScopeDraftChain(t, ctx, admin, organizationID, ownerID, organizationID, "workspace_managed")
	insertWorkspaceSourceSnapshot(t, ctx, admin, organizationID, ownerID, workspaceID, "workspace_managed")

	var workspaceRevision int64
	var workspaceConfHash string
	if err := admin.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash
		FROM public.workspace AS workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		WHERE workspace.organization_id = $1 AND workspace.id = $2
	`, organizationID, workspaceID).Scan(&workspaceRevision, &workspaceConfHash); err != nil {
		t.Fatalf("load seeded workspace revision: %v", err)
	}

	clock := fetchAuthorityClock(t, ctx, admin)

	policyID := "policy-" + organizationID + "-0001"
	insertPolicyRegistryRow(t, ctx, admin, organizationID, 1, policyID, authoritySha256('p'), ownerID, clock.grantedAt)

	grantID := authorityID("grant", 1)
	grantHash := authoritySha256('g')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: organizationID, grantID: grantID, workspaceID: workspaceID, principalID: ownerID,
		grantedBy: ownerID, policyNumber: 1, policyID: policyID, grantHash: grantHash, clock: clock,
	}); err != nil {
		t.Fatalf("insert actor grant: %v", err)
	}

	return confirmationFixture{
		organizationID: organizationID, ownerID: ownerID, workspaceID: workspaceID,
		workspaceRevision: workspaceRevision, workspaceConfHash: workspaceConfHash,
		sourceScopeID: confirmationScopeID, sourceScopeRevision: 1, scopeConfigHash: confirmationScopeHash,
		policyNumber: 1, policyID: policyID,
		grantID: grantID, grantRevision: 1, grantHash: grantHash,
		clock: clock,
	}
}

// confirmationRow is a mutable projection of every confirmation column so
// tests can forge exactly one field at a time.
type confirmationRow struct {
	organizationID      string
	confirmationID      string
	confirmationHash    string
	workspaceID         string
	workspaceRevision   int64
	workspaceConfHash   string
	workspaceSourceID   string
	sourceScopeID       string
	sourceScopeRevision int64
	scopeConfigHash     string
	accessMode          string
	grantID             string
	grantRevision       int64
	grantHash           string
	warningVersion      string
	warningContractHash string
	acknowledgementCode string
	confirmedBy         string
	confirmedAt         string
	policyNumber        int64
	policyID            string
}

func (fixture confirmationFixture) baseConfirmation(confirmationSequence int, confirmedAt string) confirmationRow {
	return confirmationRow{
		organizationID: fixture.organizationID, confirmationID: authorityID("confirmation", confirmationSequence),
		confirmationHash: authoritySha256(byte('a' + confirmationSequence)),
		workspaceID:      fixture.workspaceID, workspaceRevision: fixture.workspaceRevision, workspaceConfHash: fixture.workspaceConfHash,
		workspaceSourceID: testWorkspaceBindingID, sourceScopeID: fixture.sourceScopeID,
		sourceScopeRevision: fixture.sourceScopeRevision, scopeConfigHash: fixture.scopeConfigHash,
		accessMode: "WORKSPACE_MANAGED", grantID: fixture.grantID, grantRevision: fixture.grantRevision, grantHash: fixture.grantHash,
		warningVersion: confirmationWarningVer, warningContractHash: confirmationWarnHash, acknowledgementCode: confirmationAckCode,
		confirmedBy: fixture.ownerID, confirmedAt: confirmedAt,
		policyNumber: fixture.policyNumber, policyID: fixture.policyID,
	}
}

func insertConfirmationRow(ctx context.Context, executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, row confirmationRow) error {
	_, err := executor.Exec(ctx, `
		INSERT INTO public.workspace_managed_grant_confirmation (
			organization_id, confirmation_id, confirmation_hash, workspace_id, workspace_revision, workspace_configuration_hash,
			workspace_source_id, source_scope_id, source_scope_revision, scope_config_hash, access_mode,
			confirmation_actor_grant_id, confirmation_actor_grant_revision, confirmation_actor_grant_hash,
			warning_version, warning_contract_hash, acknowledgement_code, confirmed_by, confirmed_at,
			policy_revision_number, policy_revision
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
	`, row.organizationID, row.confirmationID, row.confirmationHash, row.workspaceID, row.workspaceRevision, row.workspaceConfHash,
		row.workspaceSourceID, row.sourceScopeID, row.sourceScopeRevision, row.scopeConfigHash, row.accessMode,
		row.grantID, row.grantRevision, row.grantHash,
		row.warningVersion, row.warningContractHash, row.acknowledgementCode, row.confirmedBy, row.confirmedAt,
		row.policyNumber, row.policyID)
	return err
}

func insertGrantRevocationRow(ctx context.Context, admin *pgxpool.Pool, organizationID, revocationID, revocationHash, grantID string, grantRevision int64, grantHash, revokedBy, revokedAt string, policyNumber int64, policyID string) error {
	_, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant_revocation (
			organization_id, revocation_id, confirmation_actor_grant_revocation_hash, grant_id, grant_revision, grant_hash,
			revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'AUTHORITY_REVOKED',$9,$10)
	`, organizationID, revocationID, revocationHash, grantID, grantRevision, grantHash, revokedBy, revokedAt, policyNumber, policyID)
	return err
}

func insertConfirmationRevocationRow(ctx context.Context, admin *pgxpool.Pool, organizationID, revocationID, revocationHash, confirmationID, confirmationHash, revokedBy, revokedAt string, policyNumber int64, policyID string) error {
	_, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_managed_grant_revocation (
			organization_id, revocation_id, workspace_managed_confirmation_revocation_hash, confirmation_id, confirmation_hash,
			revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision
		) VALUES ($1,$2,$3,$4,$5,$6,$7,'ACCESS_REVOKED',$8,$9)
	`, organizationID, revocationID, revocationHash, confirmationID, confirmationHash, revokedBy, revokedAt, policyNumber, policyID)
	return err
}

func assertPGCode(t *testing.T, err error, code string) *pgconn.PgError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PostgreSQL error %s, got success", code)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected PostgreSQL error, got %T: %v", err, err)
	}
	if pgErr.Code != code {
		t.Fatalf("error code = %s (%s), want %s", pgErr.Code, pgErr.Message, code)
	}
	return pgErr
}

// ---------------------------------------------------------------------------
// 1. Migration applies and creates the expected relations.
// ---------------------------------------------------------------------------

func TestConfirmationAuthorityMigrationApplies(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	for _, tableName := range []string{
		"organization_policy_revision", "workspace_managed_warning_contract",
		"workspace_source_confirmation_actor_grant", "workspace_source_confirmation_actor_grant_revocation",
		"workspace_managed_grant_confirmation", "workspace_managed_grant_revocation",
	} {
		var exists bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`, tableName).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("expected migration 000010 to create table %s", tableName)
		}
	}
}

// ---------------------------------------------------------------------------
// 2. Policy revision bridge invariants.
// ---------------------------------------------------------------------------

func TestOrganizationPolicyRegistryBridge(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	clock := fetchAuthorityClock(t, ctx, admin)

	// Existing organization gets no synthetic policy ID/hash: no registry row
	// exists yet even though organization.policy_revision defaults to 1.
	var registryCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.organization_policy_revision WHERE organization_id = 'org_alpha'`).Scan(&registryCount); err != nil {
		t.Fatal(err)
	}
	if registryCount != 0 {
		t.Fatalf("fresh organization already has %d policy registry rows", registryCount)
	}

	// Authority insert without a registered current policy is rejected
	// (fail closed): the grant references policy number 1, but no registry
	// row for organization_id=org_alpha exists yet.
	err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: authorityID("grant", 900), workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: 1, policyID: "policy-nonexistent", grantHash: authoritySha256('z'), clock: clock,
	})
	assertPGCode(t, err, "23503")

	// The first registered row must equal the current numeric counter (1);
	// revision 2 is rejected before any row 1 exists.
	_, err = admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ('org_alpha', 2, 'policy-0002', $1, $2, 'usr_alice')
	`, authoritySha256('1'), clock.grantedAt)
	assertPGCode(t, err, "23514")

	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 1, "policy-0001", authoritySha256('1'), "usr_alice", clock.grantedAt)

	// Duplicate policy ID rejected.
	_, err = admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ('org_alpha', 2, 'policy-0001', $1, $2, 'usr_alice')
	`, authoritySha256('2'), clock.grantedAt)
	assertPGCode(t, err, "23505")

	// Duplicate policy hash rejected.
	_, err = admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ('org_alpha', 2, 'policy-0002', $1, $2, 'usr_alice')
	`, authoritySha256('1'), clock.grantedAt)
	assertPGCode(t, err, "23505")

	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 2, "policy-0002", authoritySha256('2'), "usr_alice", clock.grantedAt)

	// policy-0007 and policy-7 are never equivalent: register revision 3 as
	// "policy-0007" and advance the organization to it (current-policy guard
	// requires the grant's own policy number to match the live counter), then
	// prove a grant naming the same number with the differently formatted
	// opaque ID "policy-7" still fails the exact registry FK.
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 3, "policy-0007", authoritySha256('3'), "usr_alice", clock.grantedAt)
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 3 WHERE id = 'org_alpha'`); err != nil {
		t.Fatalf("advance organization policy revision to 3: %v", err)
	}
	err = insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: authorityID("grant", 901), workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: 3, policyID: "policy-7", grantHash: authoritySha256('y'), clock: clock,
	})
	assertPGCode(t, err, "23503")

	// Decrease is rejected: organization.policy_revision is 3 here; setting it
	// back to the already-registered revision 1 must still fail because it is
	// numerically lower than the current value.
	_, err = admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 1 WHERE id = 'org_alpha'`)
	assertPGCode(t, err, "55000")

	// Runtime role can never change organization.policy_revision, even to a
	// distinct, already-registered value.
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	_, err = tx.Exec(ctx, `UPDATE public.organization SET policy_revision = 2 WHERE id = 'org_alpha'`)
	assertPGCode(t, err, "55000")
}

// ---------------------------------------------------------------------------
// 2b. Safe numeric organization policy counter (P0).
// ---------------------------------------------------------------------------

func TestOrganizationPolicyRevisionSafeIntegerBound(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	clock := fetchAuthorityClock(t, ctx, admin)

	// The first registry row must equal the current counter (1); the upper
	// safe-integer bound is then registered as a monotonic gap and accepted.
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 1, "policy-0001", authoritySha256('1'), "usr_alice", clock.grantedAt)
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 9007199254740991, "policy-max", authoritySha256('m'), "usr_alice", clock.grantedAt)
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 9007199254740991 WHERE id = 'org_alpha'`); err != nil {
		t.Fatalf("advance organization policy revision to the safe-integer bound: %v", err)
	}

	// One past the safe-integer bound is rejected by the CHECK constraint
	// itself. Going through the ordinary advance path would always hit the
	// "must match an existing registry revision" guard first (23503, since
	// no such revision could ever legitimately be registered either), so
	// this is exercised directly on INSERT, which the change guard does not
	// intercept (it only fires on UPDATE), isolating the CHECK constraint.
	_, err := admin.Exec(ctx, `
		INSERT INTO public.organization (id, name, status, region, policy_revision, owner_principal_id)
		VALUES ('org_out_of_bound', 'org_out_of_bound', 'ACTIVE', 'ru', 9007199254740992, 'usr_missing')
	`)
	if err == nil {
		t.Fatal("organization.policy_revision accepted a value beyond the safe integer bound")
	}
	assertPGCode(t, err, "23514")

	// Existing organizations with an in-bound counter are never broken by the
	// added constraint: a freshly seeded organization defaults to 1.
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	var betaPolicyRevision int64
	if err := admin.QueryRow(ctx, `SELECT policy_revision FROM public.organization WHERE id = 'org_beta'`).Scan(&betaPolicyRevision); err != nil {
		t.Fatal(err)
	}
	if betaPolicyRevision != 1 {
		t.Fatalf("freshly seeded organization policy_revision = %d, want 1", betaPolicyRevision)
	}
}

// ---------------------------------------------------------------------------
// 2c. Policy registry is monotonic only; gaps are allowed (not contiguous).
// ---------------------------------------------------------------------------

func TestPolicyRegistryAllowsMonotonicGapsNotContiguous(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	clock := fetchAuthorityClock(t, ctx, admin)

	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 1, "policy-0001", authoritySha256('1'), "usr_alice", clock.grantedAt)

	// Registering revision 7 straight after revision 1 is a monotonic gap,
	// not a contiguous "previous + 1" sequence, and must be accepted: the
	// accepted contract only requires monotonic ordinals. No synthetic ID or
	// hash is derived from the number; the caller supplies its own opaque ID.
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 7, "policy-gap-0007", authoritySha256('7'), "usr_alice", clock.grantedAt)

	// Repeat of an existing ordinal is rejected.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ('org_alpha', 7, 'policy-repeat', $1, $2, 'usr_alice')
	`, authoritySha256('8'), clock.grantedAt); err == nil {
		t.Fatal("repeated policy registry ordinal was accepted")
	}

	// Decrease (any value at or below the existing max of 7) is rejected.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_policy_revision (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
		VALUES ('org_alpha', 5, 'policy-below-max', $1, $2, 'usr_alice')
	`, authoritySha256('9'), clock.grantedAt); err == nil {
		t.Fatal("policy registry ordinal below the existing max was accepted")
	}

	// A further gap (e.g. 20 after 7) remains valid.
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 20, "policy-gap-0020", authoritySha256(byte(20)), "usr_alice", clock.grantedAt)

	var registeredRevisions []int64
	rows, err := admin.Query(ctx, `SELECT revision FROM public.organization_policy_revision WHERE organization_id = 'org_alpha' ORDER BY revision`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var revision int64
		if err := rows.Scan(&revision); err != nil {
			t.Fatal(err)
		}
		registeredRevisions = append(registeredRevisions, revision)
	}
	if len(registeredRevisions) != 3 || registeredRevisions[0] != 1 || registeredRevisions[1] != 7 || registeredRevisions[2] != 20 {
		t.Fatalf("registered revisions = %v, want [1 7 20]", registeredRevisions)
	}
}

// ---------------------------------------------------------------------------
// 2d. Current-policy invariant (P0): every new authority row's own
// policy_revision_number must exact-match organization.policy_revision at
// INSERT time, independent of what policy a parent row references.
// ---------------------------------------------------------------------------

func TestCurrentPolicyInvariantAcrossAuthorityTables(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// setupConfirmationFixture registers policy revision 1 and leaves
	// organization.policy_revision at its default of 1 (current = 1).

	// A confirmation created now, while policy 1 is current, must succeed; it
	// stays around as the "stale parent" once policy 2 becomes current below.
	confirmationUnderPolicy1 := fixture.baseConfirmation(10, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmationUnderPolicy1); err != nil {
		t.Fatalf("confirmation under the then-current policy 1 should succeed: %v", err)
	}

	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 2, "policy-org_alpha-0002", authoritySha256('2'), "usr_alice", fixture.clock.grantedAt)

	// With policy 1 and 2 both registered and current = 1, a brand new grant
	// naming policy 2 is rejected even though 2 is a validly registered
	// revision: it is simply not the *current* one.
	err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: authorityID("grant", 700), workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: 2, policyID: "policy-org_alpha-0002", grantHash: authoritySha256('q'), clock: fixture.clock,
	})
	assertPGCode(t, err, "23514")

	// After advancing current policy to 2, the reverse is true: a brand new
	// grant naming the now-stale policy 1 is rejected.
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 2 WHERE id = 'org_alpha'`); err != nil {
		t.Fatalf("advance organization policy revision to 2: %v", err)
	}
	err = insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: authorityID("grant", 701), workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: 1, policyID: fixture.policyID, grantHash: authoritySha256('n'), clock: fixture.clock,
	})
	assertPGCode(t, err, "23514")

	// A confirmation naming the now-stale policy 1 is also rejected, even
	// though the referenced grant and binding are otherwise entirely valid.
	staleConfirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	err = insertConfirmationRow(ctx, admin, staleConfirmation)
	assertPGCode(t, err, "23514")

	// A confirmation naming a policy that does not exist yet ("future") is
	// likewise rejected by the same guard.
	futureConfirmation := fixture.baseConfirmation(2, fixture.clock.confirmedAt)
	futureConfirmation.policyNumber = 3
	futureConfirmation.policyID = "policy-org_alpha-0003"
	err = insertConfirmationRow(ctx, admin, futureConfirmation)
	assertPGCode(t, err, "23514")

	// Stale parents remain revocable under the *current* policy: the grant
	// (created under policy 1, now stale) can still be revoked, but only if
	// the revocation's own policy provenance is current (2), never the
	// grant's original stale policy (1).
	_, err = admin.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant_revocation (
			organization_id, revocation_id, confirmation_actor_grant_revocation_hash, grant_id, grant_revision, grant_hash,
			revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision
		) VALUES ('org_alpha', $1, $2, $3, $4, $5, 'usr_alice', $6, 'AUTHORITY_REVOKED', 1, $7)
	`, authorityID("grantrevoke", 1), authoritySha256('r'), fixture.grantID, fixture.grantRevision, fixture.grantHash,
		fixture.clock.revokedAt, fixture.policyID)
	assertPGCode(t, err, "23514")

	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 2), authoritySha256('s'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, 2, "policy-org_alpha-0002"); err != nil {
		t.Fatalf("revoking a stale grant under the current policy must succeed: %v", err)
	}

	// The same stale-vs-current rule applies to confirmation revocation: the
	// confirmation created under policy 1 (now stale, and independent of the
	// grant revocation above) can still be revoked, but only under the
	// current policy (2), never under its own original stale policy (1).
	_, err = admin.Exec(ctx, `
		INSERT INTO public.workspace_managed_grant_revocation (
			organization_id, revocation_id, workspace_managed_confirmation_revocation_hash, confirmation_id, confirmation_hash,
			revoked_by, revoked_at, reason_code, policy_revision_number, policy_revision
		) VALUES ('org_alpha', $1, $2, $3, $4, 'usr_alice', $5, 'ACCESS_REVOKED', 1, $6)
	`, authorityID("confirmrevoke", 1), authoritySha256('c'), confirmationUnderPolicy1.confirmationID,
		confirmationUnderPolicy1.confirmationHash, fixture.clock.revokedAt, fixture.policyID)
	assertPGCode(t, err, "23514")

	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 2), authoritySha256('d'),
		confirmationUnderPolicy1.confirmationID, confirmationUnderPolicy1.confirmationHash, "usr_alice",
		fixture.clock.revokedAt, 2, "policy-org_alpha-0002"); err != nil {
		t.Fatalf("revoking a stale confirmation under the current policy must succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2e. Grant expiry/backdating (P0): an expired or not-yet-started grant can
// never mint a new confirmation, even with a historical confirmed_at that
// would otherwise fall inside the grant's old window.
// ---------------------------------------------------------------------------

func TestGrantExpiryCannotBeBackdated(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	// Reuse the fixture's own authorityClock snapshot (already fetched from
	// the real PostgreSQL server clock, never the Go process clock) for
	// "now"; only the expired/not-yet-started grant windows below need their
	// own bespoke, still server-relative, offsets.
	nowText := fixture.clock.now
	var grantedAt, validFrom, validUntil string
	if err := admin.QueryRow(ctx, `
		SELECT
			to_char((date_trunc('second', transaction_timestamp()) - interval '2 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			to_char((date_trunc('second', transaction_timestamp()) - interval '2 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			to_char((date_trunc('second', transaction_timestamp()) - interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`).Scan(&grantedAt, &validFrom, &validUntil); err != nil {
		t.Fatal(err)
	}

	// An already-expired grant: valid_until is one hour in the past.
	expiredGrantID := authorityID("grant", 800)
	expiredGrantHash := authoritySha256('x')
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant (
			organization_id, grant_id, revision, workspace_id, principal_id, permission,
			valid_from, valid_until, policy_revision_number, policy_revision, grant_hash, granted_by, granted_at
		) VALUES ('org_alpha', $1, 1, 'ws_alpha', 'usr_alice', 'workspace.source.confirm', $2, $3, 1, $4, $5, 'usr_alice', $6)
	`, expiredGrantID, validFrom, validUntil, fixture.policyID, expiredGrantHash, grantedAt); err != nil {
		t.Fatal(err)
	}

	// Attempt to confirm it with a historical confirmed_at that falls inside
	// the grant's own (now expired) window: this must still be rejected,
	// because the *current* server transaction second is checked too.
	backdated := fixture.baseConfirmation(1, validFrom)
	backdated.grantID = expiredGrantID
	backdated.grantHash = expiredGrantHash
	err := insertConfirmationRow(ctx, admin, backdated)
	assertPGCode(t, err, "23514")

	// A grant that has not started yet (valid_from in the future) is equally
	// unusable right now, even confirmed with a confirmed_at inside its
	// future window.
	var futureValidFrom, futureValidUntil string
	if err := admin.QueryRow(ctx, `
		SELECT
			to_char((date_trunc('second', transaction_timestamp()) + interval '1 hour') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
			to_char((date_trunc('second', transaction_timestamp()) + interval '2 hours') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
	`).Scan(&futureValidFrom, &futureValidUntil); err != nil {
		t.Fatal(err)
	}
	notYetStartedGrantID := authorityID("grant", 801)
	notYetStartedGrantHash := authoritySha256('y')
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_source_confirmation_actor_grant (
			organization_id, grant_id, revision, workspace_id, principal_id, permission,
			valid_from, valid_until, policy_revision_number, policy_revision, grant_hash, granted_by, granted_at
		) VALUES ('org_alpha', $1, 1, 'ws_alpha', 'usr_alice', 'workspace.source.confirm', $2, $3, 1, $4, $5, 'usr_alice', $6)
	`, notYetStartedGrantID, futureValidFrom, futureValidUntil, fixture.policyID, notYetStartedGrantHash, nowText); err != nil {
		t.Fatal(err)
	}
	notYetLive := fixture.baseConfirmation(2, futureValidFrom)
	notYetLive.grantID = notYetStartedGrantID
	notYetLive.grantHash = notYetStartedGrantHash
	err = insertConfirmationRow(ctx, admin, notYetLive)
	assertPGCode(t, err, "23514")

	// A currently-valid grant still confirms successfully with a real,
	// current confirmed_at, proving the guard only rejects genuinely expired
	// or not-yet-started grants.
	valid := fixture.baseConfirmation(3, nowText)
	if err := insertConfirmationRow(ctx, admin, valid); err != nil {
		t.Fatalf("confirmation against a currently valid grant should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 2f. Authority IDs are opaque, not part of the source generated-ID contract.
// ---------------------------------------------------------------------------

func TestAuthorityIDsAcceptCanonicalOpaqueForms(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	grantID := "confirm-grant-admin"
	grantHash := authoritySha256('k')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: grantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: grantHash, clock: fixture.clock,
	}); err != nil {
		t.Fatalf("canonical-style grant ID %q rejected: %v", grantID, err)
	}

	confirmationID := "wmc_projects_3"
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	confirmation.confirmationID = confirmationID
	confirmation.grantID = grantID
	confirmation.grantHash = grantHash
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatalf("canonical-style confirmation ID %q rejected: %v", confirmationID, err)
	}

	grantRevocationID := "revoke-grant-1"
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", grantRevocationID, authoritySha256('l'),
		grantID, 1, grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("canonical-style grant revocation ID %q rejected: %v", grantRevocationID, err)
	}

	confirmationRevocationID := "revoke-confirmation-1"
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", confirmationRevocationID, authoritySha256('m'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("canonical-style confirmation revocation ID %q rejected: %v", confirmationRevocationID, err)
	}

	// Existing source connection/scope/binding generated-ID rules are
	// unaffected: the fixture's binding ID must still be the ULID-shaped
	// app.source_generated_id_is_valid form, not an arbitrary opaque string.
	var bindingIDValid bool
	if err := admin.QueryRow(ctx, `SELECT app.source_generated_id_is_valid($1, 'binding')`, testWorkspaceBindingID).Scan(&bindingIDValid); err != nil {
		t.Fatal(err)
	}
	if !bindingIDValid {
		t.Fatalf("workspace_source binding ID no longer satisfies the generated-ID contract: %q", testWorkspaceBindingID)
	}
}

// ---------------------------------------------------------------------------
// 3. Protected warning registry.
// ---------------------------------------------------------------------------

func TestWarningRegistryV1IsSealedAndImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)

	var schemaVersion, warningVersion, accessMode, ackCode, hash string
	var riskCodesJSON string
	if err := admin.QueryRow(ctx, `
		SELECT schema_version, warning_version, access_mode, acknowledgement_code, warning_contract_hash, risk_codes_json::text
		FROM public.workspace_managed_warning_contract WHERE revision = 1
	`).Scan(&schemaVersion, &warningVersion, &accessMode, &ackCode, &hash, &riskCodesJSON); err != nil {
		t.Fatal(err)
	}
	if schemaVersion != "workspace-managed-warning-contract-v1" ||
		warningVersion != "workspace-managed-risk-v1" ||
		accessMode != "WORKSPACE_MANAGED" ||
		ackCode != confirmationAckCode ||
		hash != confirmationWarnHash ||
		riskCodesJSON != `["SOURCE_NATIVE_ACL_NOT_ENFORCED", "WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"]` {
		t.Fatalf("unexpected seeded warning contract: schema=%q warning=%q mode=%q ack=%q hash=%q risks=%q",
			schemaVersion, warningVersion, accessMode, ackCode, hash, riskCodesJSON)
	}

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_managed_warning_contract (
			revision, schema_version, warning_version, access_mode, risk_codes_json, acknowledgement_code, canonical_bytes, warning_contract_hash
		) VALUES (2, 'x', 'x', 'WORKSPACE_MANAGED', '[]'::jsonb, 'x', convert_to('{}','UTF8'), $1)
	`, authoritySha256('0')); err == nil {
		t.Fatal("warning contract registry accepted an INSERT")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.workspace_managed_warning_contract SET warning_version = 'x' WHERE revision = 1`); err == nil {
		t.Fatal("warning contract registry accepted an UPDATE")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_managed_warning_contract WHERE revision = 1`); err == nil {
		t.Fatal("warning contract registry accepted a DELETE")
	}

	for privilege, want := range map[string]bool{
		"SELECT": true, "INSERT": false, "UPDATE": false, "DELETE": false,
		"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
	} {
		var got bool
		if err := admin.QueryRow(ctx, "SELECT has_table_privilege('knowvault_app', 'public.workspace_managed_warning_contract', $1)", privilege).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("knowvault_app %s on warning registry = %v, want %v", privilege, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// 3b. Current-warning invariant (P0 hardening): "current" warning is defined
// as the registry row with the maximum revision, not merely "any historically
// registered row the confirmation's warning_version/hash happen to match".
// ---------------------------------------------------------------------------

// emulateFutureWarningRevision emulates a future privileged migration that
// registers a new workspace_managed_warning_contract revision: it disables
// the immutability trigger, runs insert within the SAME transaction, then
// re-enables the trigger before committing. Trigger disable/enable is
// transactional DDL in PostgreSQL, so if insert (or anything else) fails, the
// deferred rollback below undoes the disable too: the trigger can never be
// left disabled outside this one transaction, on any path, including test
// failure. Production runtime (knowvault_app) still never gets INSERT/UPDATE/
// DELETE on this registry; only the trusted migration-owner connection used
// by these tests can run ALTER TABLE ... DISABLE/ENABLE TRIGGER at all.
func emulateFutureWarningRevision(t *testing.T, ctx context.Context, admin *pgxpool.Pool, insert func(tx pgx.Tx) error) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin emulated future warning revision transaction: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `ALTER TABLE public.workspace_managed_warning_contract DISABLE TRIGGER workspace_managed_warning_contract_immutable`); err != nil {
		t.Fatalf("disable warning immutability trigger: %v", err)
	}
	if err := insert(tx); err != nil {
		t.Fatalf("insert emulated future warning revision: %v", err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE public.workspace_managed_warning_contract ENABLE TRIGGER workspace_managed_warning_contract_immutable`); err != nil {
		t.Fatalf("re-enable warning immutability trigger: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit emulated future warning revision: %v", err)
	}
	committed = true
}

func TestWarningRevisionAdvanceMakesOldConfirmationStaleAndBlocksNewConfirmations(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	confirmationV1 := fixture.baseConfirmation(10, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmationV1); err != nil {
		t.Fatalf("confirmation against warning v1 should succeed while it is current: %v", err)
	}
	if !derivedLive(ctx, admin, "org_alpha", confirmationV1.confirmationID) {
		t.Fatal("confirmation is not derived-live before any warning advance")
	}

	// Emulate a future privileged migration registering warning revision 2.
	// schema_version, warning_version and acknowledgement_code are pinned by
	// the confirmation table's own CHECK constraints, so any warning revision
	// a confirmation could ever reference necessarily keeps them; only the
	// risk codes (and therefore the canonical hash) differ here.
	canonicalV2 := `{"access_mode":"WORKSPACE_MANAGED","acknowledgement_code":"WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",` +
		`"risk_codes":["NEW_RISK_EXAMPLE","SOURCE_NATIVE_ACL_NOT_ENFORCED","WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"],` +
		`"schema_version":"workspace-managed-warning-contract-v1","warning_version":"workspace-managed-risk-v1"}`
	sum := sha256.Sum256([]byte(canonicalV2))
	warningHashV2 := "sha256:" + hex.EncodeToString(sum[:])

	emulateFutureWarningRevision(t, ctx, admin, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO public.workspace_managed_warning_contract (
				revision, schema_version, warning_version, access_mode, risk_codes_json,
				acknowledgement_code, canonical_bytes, warning_contract_hash
			) VALUES (
				2, 'workspace-managed-warning-contract-v1', 'workspace-managed-risk-v1', 'WORKSPACE_MANAGED',
				'["NEW_RISK_EXAMPLE","SOURCE_NATIVE_ACL_NOT_ENFORCED","WORKSPACE_MEMBERS_RECEIVE_DERIVED_CONTENT_ACCESS"]'::jsonb,
				'WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL', convert_to($1, 'UTF8'), $2
			)
		`, canonicalV2, warningHashV2)
		return err
	})

	// The v1 confirmation becomes stale purely because it no longer names the
	// current warning revision: nothing about the confirmation row itself,
	// the workspace, the binding or the policy changed.
	if derivedLive(ctx, admin, "org_alpha", confirmationV1.confirmationID) {
		t.Fatal("confirmation is still derived-live after a newer warning revision was registered")
	}

	// A brand new confirmation still naming warning v1's hash is rejected:
	// only the current (now v2) warning revision may be used going forward.
	secondGrantID := authorityID("grant", 2)
	secondGrantHash := authoritySha256('h')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: secondGrantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: secondGrantHash, clock: fixture.clock,
	}); err != nil {
		t.Fatal(err)
	}
	staleWarningConfirmation := fixture.baseConfirmation(11, fixture.clock.confirmedAt)
	staleWarningConfirmation.grantID = secondGrantID
	staleWarningConfirmation.grantHash = secondGrantHash
	insertErr := insertConfirmationRow(ctx, admin, staleWarningConfirmation)
	assertPGCode(t, insertErr, "23514")
}

// ---------------------------------------------------------------------------
// 4. Canonical authority timestamp validator (format + calendar + round trip).
// ---------------------------------------------------------------------------

func TestAuthorityTimestampV1Validator(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)

	cases := map[string]bool{
		"2026-07-16T10:00:00Z":      true,
		"2024-02-29T10:00:00Z":      true,  // leap year day is valid
		"2023-02-29T10:00:00Z":      false, // not a leap year
		"2026-02-30T10:00:00Z":      false, // no such calendar date
		"2026-07-16T10:00:00.000Z":  false, // fractional seconds forbidden
		"2026-07-16T10:00:00+00:00": false, // explicit offset forbidden
		"2026-07-16T10:00:00":       false, // missing Z
		"2026-06-30T23:59:60Z":      false, // leap second forbidden
		"26-07-16T10:00:00Z":        false, // year must be exactly four digits
		"2026-13-01T10:00:00Z":      false, // invalid month
		"2026-07-32T10:00:00Z":      false, // invalid day
	}
	for value, want := range cases {
		value, want := value, want
		t.Run(value, func(t *testing.T) {
			var got bool
			if err := admin.QueryRow(ctx, `SELECT app.authority_timestamp_v1_is_valid($1)`, value).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("authority_timestamp_v1_is_valid(%q) = %v, want %v", value, got, want)
			}
		})
	}

	var nullResult bool
	if err := admin.QueryRow(ctx, `SELECT app.authority_timestamp_v1_is_valid(NULL)`).Scan(&nullResult); err != nil {
		t.Fatal(err)
	}
	if nullResult {
		t.Fatal("NULL timestamp accepted as valid")
	}
}

// TestTemporalBoundaryCases covers every half-open/closed ordering boundary:
// granted_at<=valid_from<valid_until, valid_from<=confirmed_at<valid_until,
// and both revoked_at >= their parent timestamp.
func TestTemporalBoundaryCases(t *testing.T) {
	t.Run("grant validity window", func(t *testing.T) {
		ctx := context.Background()
		admin := resetAuthorityHistoricalDatabase(t)
		seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
		clock := fetchAuthorityClock(t, ctx, admin)
		insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 1, "policy-0001", authoritySha256('1'), "usr_alice", clock.grantedAt)

		insertGrant := func(sequence int, grantedAt, validFrom, validUntil string) error {
			_, err := admin.Exec(ctx, `
				INSERT INTO public.workspace_source_confirmation_actor_grant (
					organization_id, grant_id, revision, workspace_id, principal_id, permission,
					valid_from, valid_until, policy_revision_number, policy_revision, grant_hash, granted_by, granted_at
				) VALUES ('org_alpha', $1, 1, 'ws_alpha', 'usr_alice', 'workspace.source.confirm', $2, $3, 1, 'policy-0001', $4, 'usr_alice', $5)
			`, authorityID("grant", sequence), validFrom, validUntil, authoritySha256(byte('a'+sequence)), grantedAt)
			return err
		}
		// granted_at == valid_from is allowed (inclusive lower bound).
		if err := insertGrant(1, clock.validFrom, clock.validFrom, clock.validUntil); err != nil {
			t.Fatalf("granted_at == valid_from must be accepted: %v", err)
		}
		// valid_from == valid_until is rejected (window must be non-empty).
		if err := insertGrant(2, clock.validFrom, clock.validFrom, clock.validFrom); err == nil {
			t.Fatal("valid_from == valid_until must be rejected")
		}
		// granted_at after valid_from is rejected. clock.now (safely non-future)
		// is well after clock.validFrom (now - 2h), isolating exactly this fault.
		if err := insertGrant(3, clock.now, clock.validFrom, clock.validUntil); err == nil {
			t.Fatal("granted_at after valid_from must be rejected")
		}
	})

	t.Run("confirmed_at against grant window and future clock", func(t *testing.T) {
		ctx := context.Background()
		admin := resetAuthorityHistoricalDatabase(t)
		fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

		// confirmed_at == valid_from is allowed.
		row := fixture.baseConfirmation(1, fixture.clock.validFrom)
		if err := insertConfirmationRow(ctx, admin, row); err != nil {
			t.Fatalf("confirmed_at == valid_from must be accepted: %v", err)
		}

		// confirmed_at == valid_until is rejected (half-open upper bound).
		row2 := fixture.baseConfirmation(2, fixture.clock.validUntil)
		if err := insertConfirmationRow(ctx, admin, row2); err == nil {
			t.Fatal("confirmed_at == valid_until must be rejected")
		}

		// confirmed_at in the future relative to server clock is rejected.
		row3 := fixture.baseConfirmation(3, fixture.clock.farFuture)
		if err := insertConfirmationRow(ctx, admin, row3); err == nil {
			t.Fatal("future confirmed_at must be rejected")
		}
	})
}

// ---------------------------------------------------------------------------
// 5. Composite foreign key forgery: every element must be exact.
// ---------------------------------------------------------------------------

func TestConfirmationCompositeForeignKeysRejectForgery(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		mutate func(*confirmationRow)
	}{
		{"tenant", func(row *confirmationRow) { row.organizationID = "org_missing" }},
		{"workspace", func(row *confirmationRow) { row.workspaceID = "ws_missing" }},
		{"workspace_revision", func(row *confirmationRow) { row.workspaceRevision = 999 }},
		{"configuration_hash", func(row *confirmationRow) { row.workspaceConfHash = authoritySha256('9') }},
		{"binding_id", func(row *confirmationRow) { row.workspaceSourceID = "binding_0" + strings.Repeat("9", 25) }},
		{"scope_id", func(row *confirmationRow) { row.sourceScopeID = "scope_0" + strings.Repeat("9", 25) }},
		{"scope_revision", func(row *confirmationRow) { row.sourceScopeRevision = 999 }},
		{"scope_hash", func(row *confirmationRow) { row.scopeConfigHash = authoritySha256('8') }},
		{"grant_id", func(row *confirmationRow) { row.grantID = authorityID("grant", 999) }},
		{"grant_revision", func(row *confirmationRow) { row.grantRevision = 999 }},
		{"grant_hash", func(row *confirmationRow) { row.grantHash = authoritySha256('7') }},
		{"principal", func(row *confirmationRow) { row.confirmedBy = "usr_carol" }},
		{"policy_number", func(row *confirmationRow) { row.policyNumber = 999 }},
		{"policy_id", func(row *confirmationRow) { row.policyID = "policy-forged" }},
		{"warning_version", func(row *confirmationRow) { row.warningVersion = "workspace-managed-risk-v2" }},
		{"warning_hash", func(row *confirmationRow) { row.warningContractHash = authoritySha256('6') }},
	} {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			ctx := context.Background()
			admin := resetAuthorityHistoricalDatabase(t)
			fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
			if _, err := admin.Exec(ctx, `
				INSERT INTO public.principal (id, organization_id, type, display_name, status)
				VALUES ('usr_carol', 'org_alpha', 'USER', 'Carol', 'ACTIVE')
			`); err != nil {
				t.Fatal(err)
			}
			row := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
			mutation.mutate(&row)
			if err := insertConfirmationRow(ctx, admin, row); err == nil {
				t.Fatalf("forged %s unexpectedly committed", mutation.name)
			}
		})
	}

	// acknowledgement_code is a closed value, not part of a lookup table; any
	// other string is rejected by its own CHECK constraint.
	t.Run("acknowledgement_code", func(t *testing.T) {
		ctx := context.Background()
		admin := resetAuthorityHistoricalDatabase(t)
		fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
		row := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
		row.acknowledgementCode = "SOMETHING_ELSE"
		err := insertConfirmationRow(ctx, admin, row)
		assertPGCode(t, err, "23514")
	})
}

// ---------------------------------------------------------------------------
// 6. SOURCE_ENFORCED can never be confirmed.
// ---------------------------------------------------------------------------

func TestSourceEnforcedConfirmationRejected(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	// Default fault "" builds a SOURCE_ENFORCED scope chain.
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "org_alpha", "")
	insertWorkspaceSourceSnapshot(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha", "")

	var workspaceRevision int64
	var workspaceConfHash string
	if err := admin.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash
		FROM public.workspace AS workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		WHERE workspace.organization_id = 'org_alpha' AND workspace.id = 'ws_alpha'
	`).Scan(&workspaceRevision, &workspaceConfHash); err != nil {
		t.Fatal(err)
	}
	clock := fetchAuthorityClock(t, ctx, admin)
	insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 1, "policy-0001", authoritySha256('1'), "usr_alice", clock.grantedAt)
	grantID := authorityID("grant", 1)
	grantHash := authoritySha256('g')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: grantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: 1, policyID: "policy-0001", grantHash: grantHash, clock: clock,
	}); err != nil {
		t.Fatal(err)
	}

	row := confirmationRow{
		organizationID: "org_alpha", confirmationID: authorityID("confirmation", 1), confirmationHash: authoritySha256('a'),
		workspaceID: "ws_alpha", workspaceRevision: workspaceRevision, workspaceConfHash: workspaceConfHash,
		workspaceSourceID: testWorkspaceBindingID, sourceScopeID: confirmationScopeID,
		sourceScopeRevision: 1, scopeConfigHash: confirmationScopeHash, accessMode: "WORKSPACE_MANAGED",
		grantID: grantID, grantRevision: 1, grantHash: grantHash,
		warningVersion: confirmationWarningVer, warningContractHash: confirmationWarnHash, acknowledgementCode: confirmationAckCode,
		confirmedBy: "usr_alice", confirmedAt: clock.confirmedAt,
		policyNumber: 1, policyID: "policy-0001",
	}
	err := insertConfirmationRow(ctx, admin, row)
	assertPGCode(t, err, "23503")
}

// ---------------------------------------------------------------------------
// 7. One revocation per exact parent.
// ---------------------------------------------------------------------------

func TestOneRevocationPerParent(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}

	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("first grant revocation: %v", err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 2), authoritySha256('s'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err == nil {
		t.Fatal("second grant revocation on the same grant unexpectedly committed")
	}

	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("first confirmation revocation: %v", err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 2), authoritySha256('u'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err == nil {
		t.Fatal("second confirmation revocation on the same confirmation unexpectedly committed")
	}
}

// ---------------------------------------------------------------------------
// 8. Grant revocation and confirmation revocation are independent kill-switches.
// ---------------------------------------------------------------------------

func TestGrantAndConfirmationRevocationsAreIndependent(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}
	// Revoking the confirmation itself must not touch the grant, and vice
	// versa: both relations are independent append-only tables with no shared
	// row, so there is nothing to assert beyond both inserts succeeding
	// without one another as a prerequisite.
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("confirmation revocation: %v", err)
	}
	var grantRevocations int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_source_confirmation_actor_grant_revocation WHERE organization_id = 'org_alpha'`).Scan(&grantRevocations); err != nil {
		t.Fatal(err)
	}
	if grantRevocations != 0 {
		t.Fatalf("confirmation revocation unexpectedly created %d grant revocations", grantRevocations)
	}

	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("grant revocation: %v", err)
	}
	var confirmationHashAfter string
	if err := admin.QueryRow(ctx, `SELECT confirmation_hash FROM public.workspace_managed_grant_confirmation WHERE organization_id = 'org_alpha' AND confirmation_id = $1`, confirmation.confirmationID).Scan(&confirmationHashAfter); err != nil {
		t.Fatal(err)
	}
	if confirmationHashAfter != confirmation.confirmationHash {
		t.Fatal("grant revocation mutated the confirmation row")
	}
}

// ---------------------------------------------------------------------------
// 9. Immutability of confirmation and both revocation relations.
// ---------------------------------------------------------------------------

func TestAuthorityRowsAreImmutable(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}

	for label, statement := range map[string]string{
		"grant update":                   `UPDATE public.workspace_source_confirmation_actor_grant SET revision = revision WHERE organization_id = 'org_alpha'`,
		"grant delete":                   `DELETE FROM public.workspace_source_confirmation_actor_grant WHERE organization_id = 'org_alpha'`,
		"grant revocation update":        `UPDATE public.workspace_source_confirmation_actor_grant_revocation SET reason_code = 'AUTHORITY_REVOKED' WHERE organization_id = 'org_alpha'`,
		"grant revocation delete":        `DELETE FROM public.workspace_source_confirmation_actor_grant_revocation WHERE organization_id = 'org_alpha'`,
		"confirmation update":            `UPDATE public.workspace_managed_grant_confirmation SET confirmed_at = confirmed_at WHERE organization_id = 'org_alpha'`,
		"confirmation delete":            `DELETE FROM public.workspace_managed_grant_confirmation WHERE organization_id = 'org_alpha'`,
		"confirmation revocation update": `UPDATE public.workspace_managed_grant_revocation SET reason_code = 'ACCESS_REVOKED' WHERE organization_id = 'org_alpha'`,
		"confirmation revocation delete": `DELETE FROM public.workspace_managed_grant_revocation WHERE organization_id = 'org_alpha'`,
		"policy registry update":         `UPDATE public.organization_policy_revision SET policy_hash = policy_hash WHERE organization_id = 'org_alpha'`,
		"policy registry delete":         `DELETE FROM public.organization_policy_revision WHERE organization_id = 'org_alpha'`,
	} {
		label, statement := label, statement
		t.Run(label, func(t *testing.T) {
			if _, err := admin.Exec(ctx, statement); err == nil {
				t.Fatalf("%s unexpectedly succeeded", label)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 10. Tenant hard delete requires exact child-first order.
// ---------------------------------------------------------------------------

func TestTenantHardDeleteRequiresChildFirstOrder(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.Exec(ctx, `DELETE FROM public.organization_policy_revision WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("policy registry deleted for an active tenant")
	}
	if _, err := admin.Exec(ctx, `UPDATE public.organization SET status = 'DELETING' WHERE id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_source_confirmation_actor_grant WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("grant deleted before its dependent revocation and confirmation")
	}
	if _, err := admin.Exec(ctx, `DELETE FROM public.workspace_managed_grant_confirmation WHERE organization_id = 'org_alpha'`); err == nil {
		t.Fatal("confirmation deleted before its dependent revocation")
	}

	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, statement := range []string{
		`DELETE FROM public.workspace_managed_grant_revocation WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.workspace_managed_grant_confirmation WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.workspace_source_confirmation_actor_grant_revocation WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.workspace_source_confirmation_actor_grant WHERE organization_id = 'org_alpha'`,
		`DELETE FROM public.organization_policy_revision WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("ordered hard delete failed at %q: %v", statement, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit ordered hard delete: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 11. RLS fails closed: no context, cross tenant, same-tenant outsider.
// ---------------------------------------------------------------------------

func TestAuthorityRLSFailsClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixtureAlpha := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmationAlpha := fixtureAlpha.baseConfirmation(1, fixtureAlpha.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmationAlpha); err != nil {
		t.Fatal(err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixtureAlpha.grantID, fixtureAlpha.grantRevision, fixtureAlpha.grantHash, "usr_alice", fixtureAlpha.clock.revokedAt, fixtureAlpha.policyNumber, fixtureAlpha.policyID); err != nil {
		t.Fatal(err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('u'),
		confirmationAlpha.confirmationID, confirmationAlpha.confirmationHash, "usr_alice", fixtureAlpha.clock.revokedAt, fixtureAlpha.policyNumber, fixtureAlpha.policyID); err != nil {
		t.Fatal(err)
	}

	fixtureBeta := setupConfirmationFixture(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	confirmationBeta := fixtureBeta.baseConfirmation(1, fixtureBeta.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmationBeta); err != nil {
		t.Fatal(err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_beta", authorityID("grantrevoke", 2), authoritySha256('v'),
		fixtureBeta.grantID, fixtureBeta.grantRevision, fixtureBeta.grantHash, "usr_bob", fixtureBeta.clock.revokedAt, fixtureBeta.policyNumber, fixtureBeta.policyID); err != nil {
		t.Fatal(err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_beta", authorityID("confirmrevoke", 2), authoritySha256('w'),
		confirmationBeta.confirmationID, confirmationBeta.confirmationHash, "usr_bob", fixtureBeta.clock.revokedAt, fixtureBeta.policyNumber, fixtureBeta.policyID); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_eve', 'org_alpha', 'USER', 'Eve', 'ACTIVE')
	`); err != nil {
		t.Fatal(err)
	}

	// Every tenant-owned table introduced by 000010 now has at least one real,
	// non-empty row in *both* tenants (including both revocation relations),
	// so "0 rows" assertions below cannot be a false-green artifact of an
	// empty table.
	tenantTables := []string{
		"organization_policy_revision", "workspace_source_confirmation_actor_grant",
		"workspace_source_confirmation_actor_grant_revocation", "workspace_managed_grant_confirmation",
		"workspace_managed_grant_revocation",
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	for _, tableName := range tenantTables {
		tableName := tableName
		t.Run(tableName+"/no context", func(t *testing.T) {
			var count int
			if err := app.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("unscoped %s returned %d rows", tableName, count)
			}
		})
		t.Run(tableName+"/cross tenant", func(t *testing.T) {
			tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName+" WHERE organization_id = 'org_beta'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("org_alpha saw %d org_beta rows in %s", count, tableName)
			}
		})
		t.Run(tableName+"/same tenant outsider", func(t *testing.T) {
			tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_eve")
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName+" WHERE organization_id = 'org_alpha'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if tableName == "organization_policy_revision" {
				// The policy registry is organization scoped, not workspace
				// membership scoped, so a same-tenant non-member still sees it.
				if count == 0 {
					t.Fatalf("organization-scoped registry unexpectedly hid rows from a same-tenant principal")
				}
				return
			}
			if count != 0 {
				t.Fatalf("workspace outsider saw %d rows in %s", count, tableName)
			}
		})
		t.Run(tableName+"/workspace member sees own rows", func(t *testing.T) {
			tx, err := app.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName+" WHERE organization_id = 'org_alpha'").Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count == 0 {
				t.Fatalf("real workspace member saw 0 rows in %s, want its own row visible", tableName)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 12. Catalog privilege matrix: SELECT only for every new table.
// ---------------------------------------------------------------------------

func TestAuthorityCatalogPrivilegeMatrixIsSelectOnly(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	tables := []string{
		"organization_policy_revision", "workspace_managed_warning_contract",
		"workspace_source_confirmation_actor_grant", "workspace_source_confirmation_actor_grant_revocation",
		"workspace_managed_grant_confirmation", "workspace_managed_grant_revocation",
	}
	for _, tableName := range tables {
		tableName := tableName
		t.Run(tableName, func(t *testing.T) {
			for privilege, want := range map[string]bool{
				"SELECT": true, "INSERT": false, "UPDATE": false, "DELETE": false,
				"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
			} {
				var got bool
				if err := admin.QueryRow(ctx, "SELECT has_table_privilege('knowvault_app', $1, $2)", "public."+tableName, privilege).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if got != want {
					t.Fatalf("knowvault_app %s on %s = %v, want %v", privilege, tableName, got, want)
				}
				var publicGot bool
				if err := admin.QueryRow(ctx, "SELECT has_table_privilege('public', $1, $2)", "public."+tableName, privilege).Scan(&publicGot); err != nil {
					t.Fatal(err)
				}
				if publicGot {
					t.Fatalf("PUBLIC unexpectedly has %s on %s", privilege, tableName)
				}
			}
			if tableName != "workspace_managed_warning_contract" {
				var forced bool
				if err := admin.QueryRow(ctx, `
					SELECT c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
					WHERE n.nspname = 'public' AND c.relname = $1
				`, tableName).Scan(&forced); err != nil {
					t.Fatal(err)
				}
				if !forced {
					t.Fatalf("%s does not FORCE RLS", tableName)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 13. Every new validator/helper function is unreachable by PUBLIC and by
// knowvault_app.
// ---------------------------------------------------------------------------

func TestAuthorityHelperFunctionsAreNotExecutable(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	for _, signature := range []string{
		"app.authority_timestamp_v1_is_valid(text)",
		"app.authority_timestamp_v1_to_epoch(text)",
		"app.authority_transaction_epoch()",
		"app.organization_policy_revision_sequence_guard()",
		"app.organization_policy_revision_change_guard()",
		"app.authority_current_policy_guard()",
		"app.workspace_managed_warning_contract_immutable_guard()",
		"app.workspace_managed_warning_contract_current_revision()",
		"app.workspace_source_confirmation_actor_grant_temporal_guard()",
		"app.actor_grant_revocation_temporal_guard()",
		"app.workspace_managed_grant_confirmation_exact_guard()",
		"app.workspace_managed_grant_confirmation_derived_live_guard()",
		"app.workspace_managed_grant_revocation_temporal_guard()",
	} {
		signature := signature
		t.Run(signature, func(t *testing.T) {
			var knowvaultCanExecute, publicCanExecute bool
			if err := admin.QueryRow(ctx, `SELECT has_function_privilege('knowvault_app', $1, 'EXECUTE')`, signature).Scan(&knowvaultCanExecute); err != nil {
				t.Fatal(err)
			}
			if knowvaultCanExecute {
				t.Fatalf("knowvault_app unexpectedly has EXECUTE on %s", signature)
			}
			if err := admin.QueryRow(ctx, `SELECT has_function_privilege('public', $1, 'EXECUTE')`, signature).Scan(&publicCanExecute); err != nil {
				t.Fatal(err)
			}
			if publicCanExecute {
				t.Fatalf("PUBLIC unexpectedly has EXECUTE on %s", signature)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 14. Two real concurrent transactions never both create a live confirmation
// for the exact same tuple.
// ---------------------------------------------------------------------------

func TestConcurrentConfirmationsForSameTupleCommitAtMostOnce(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")

	secondGrantID := authorityID("grant", 2)
	secondGrantHash := authoritySha256('h')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: secondGrantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: secondGrantHash, clock: fixture.clock,
	}); err != nil {
		t.Fatal(err)
	}

	rowA := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	rowB := rowA
	rowB.confirmationID = authorityID("confirmation", 2)
	rowB.confirmationHash = authoritySha256('z')
	rowB.grantID = secondGrantID
	rowB.grantHash = secondGrantHash

	var wait sync.WaitGroup
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, row := range []confirmationRow{rowA, rowB} {
		row := row
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			tx, err := admin.Begin(ctx)
			if err != nil {
				results <- err
				return
			}
			if err := insertConfirmationRow(ctx, tx, row); err != nil {
				_ = tx.Rollback(ctx)
				results <- err
				return
			}
			results <- tx.Commit(ctx)
		}()
	}
	close(start)
	wait.Wait()
	close(results)

	successCount := 0
	for err := range results {
		if err == nil {
			successCount++
		}
	}
	if successCount != 1 {
		t.Fatalf("concurrent confirmations for the same tuple: %d succeeded, want exactly 1", successCount)
	}
	var liveCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace_managed_grant_confirmation WHERE organization_id = 'org_alpha'`).Scan(&liveCount); err != nil {
		t.Fatal(err)
	}
	if liveCount != 1 {
		t.Fatalf("workspace_managed_grant_confirmation has %d rows after the race, want 1", liveCount)
	}
}

// ---------------------------------------------------------------------------
// 14b. Grant revocation and confirmation revocation serialize with
// confirmation/source commands on the same workspace row (P0 hardening):
// two real concurrent transactions never leave an ambiguous live authority
// state, regardless of which one commits first.
// ---------------------------------------------------------------------------

func TestConfirmationVersusGrantRevocationConcurrency(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)

	var wait sync.WaitGroup
	confirmationErr := make(chan error, 1)
	revocationErr := make(chan error, 1)
	start := make(chan struct{})

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		tx, err := admin.Begin(ctx)
		if err != nil {
			confirmationErr <- err
			return
		}
		if err := insertConfirmationRow(ctx, tx, confirmation); err != nil {
			_ = tx.Rollback(ctx)
			confirmationErr <- err
			return
		}
		confirmationErr <- tx.Commit(ctx)
	}()

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		revocationErr <- insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
			fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID)
	}()

	close(start)
	wait.Wait()

	revokeErrValue := <-revocationErr
	confirmErrValue := <-confirmationErr

	// Grant revocation itself never depends on confirmation state, so it must
	// always reach a defined successful outcome regardless of interleaving.
	if revokeErrValue != nil {
		t.Fatalf("grant revocation did not reach a defined success outcome: %v", revokeErrValue)
	}

	// The confirmation either committed before the revocation was visible, or
	// was rejected because the grant was already revoked. Any other error is
	// a real defect, not an acceptable race outcome.
	if confirmErrValue != nil {
		assertPGCode(t, confirmErrValue, "23514")
	}

	// Fail-closed invariant: whichever order won, the confirmation must never
	// be derived-live once its actor grant is revoked (and the grant is now
	// unconditionally revoked, per the assertion above).
	if derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
		t.Fatal("confirmation is derived-live even though its actor grant is revoked")
	}
}

func TestReplacementConfirmationVersusConfirmationRevocationConcurrency(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	original := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, original); err != nil {
		t.Fatal(err)
	}

	secondGrantID := authorityID("grant", 2)
	secondGrantHash := authoritySha256('h')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: secondGrantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: secondGrantHash, clock: fixture.clock,
	}); err != nil {
		t.Fatal(err)
	}
	replacement := original
	replacement.confirmationID = authorityID("confirmation", 2)
	replacement.confirmationHash = authoritySha256('z')
	replacement.grantID = secondGrantID
	replacement.grantHash = secondGrantHash

	var wait sync.WaitGroup
	replacementErr := make(chan error, 1)
	revocationErr := make(chan error, 1)
	start := make(chan struct{})

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		tx, err := admin.Begin(ctx)
		if err != nil {
			replacementErr <- err
			return
		}
		if err := insertConfirmationRow(ctx, tx, replacement); err != nil {
			_ = tx.Rollback(ctx)
			replacementErr <- err
			return
		}
		replacementErr <- tx.Commit(ctx)
	}()

	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		revocationErr <- insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
			original.confirmationID, original.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID)
	}()

	close(start)
	wait.Wait()

	revokeErrValue := <-revocationErr
	replacementErrValue := <-replacementErr

	// Revoking the original confirmation never depends on a concurrent
	// replacement attempt, so it must always reach a defined success outcome.
	if revokeErrValue != nil {
		t.Fatalf("original confirmation revocation did not reach a defined success outcome: %v", revokeErrValue)
	}

	// The replacement either committed (because the revocation was already
	// visible when its derived-live count ran) or was rejected because two
	// unrevoked confirmations briefly existed for the exact same tuple. Any
	// other error is a real defect, not an acceptable race outcome.
	if replacementErrValue != nil {
		assertPGCode(t, replacementErrValue, "23514")
	}

	// Fail-closed invariant: the original is always revoked, and at most one
	// derived-live confirmation exists for the tuple afterward.
	if derivedLive(ctx, admin, "org_alpha", original.confirmationID) {
		t.Fatal("original confirmation is still derived-live after being revoked")
	}
	var liveCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_managed_grant_confirmation AS confirmation
		WHERE confirmation.organization_id = 'org_alpha'
		  AND NOT EXISTS (
			  SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
			  WHERE revocation.organization_id = confirmation.organization_id
			    AND revocation.confirmation_id = confirmation.confirmation_id
		  )
	`).Scan(&liveCount); err != nil {
		t.Fatal(err)
	}
	if liveCount > 1 {
		t.Fatalf("more than one unrevoked confirmation remains for the tuple: %d", liveCount)
	}
}

// ---------------------------------------------------------------------------
// 15. Revoke-then-replace only ever admits a brand new confirmation ID.
// ---------------------------------------------------------------------------

func TestRevokeThenReplaceRequiresNewConfirmationID(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	first := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, first); err != nil {
		t.Fatal(err)
	}

	secondGrantID := authorityID("grant", 2)
	secondGrantHash := authoritySha256('h')
	if err := insertGrantRow(ctx, admin, grantInsertParams{
		organizationID: "org_alpha", grantID: secondGrantID, workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: secondGrantHash, clock: fixture.clock,
	}); err != nil {
		t.Fatal(err)
	}

	// Before revocation, a second confirmation for the exact same tuple must
	// be rejected by the derived-live validator.
	duplicateBeforeRevoke := first
	duplicateBeforeRevoke.confirmationID = authorityID("confirmation", 2)
	duplicateBeforeRevoke.confirmationHash = authoritySha256('z')
	duplicateBeforeRevoke.grantID = secondGrantID
	duplicateBeforeRevoke.grantHash = secondGrantHash
	if err := insertConfirmationRow(ctx, admin, duplicateBeforeRevoke); err == nil {
		t.Fatal("duplicate live confirmation committed before any revocation")
	}

	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		first.confirmationID, first.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatalf("revoke original confirmation: %v", err)
	}

	// The exact same confirmation_id can never be reinserted (primary key).
	replay := first
	if err := insertConfirmationRow(ctx, admin, replay); err == nil {
		t.Fatal("re-inserting the same revoked confirmation ID unexpectedly committed")
	}

	// A brand new confirmation ID for the same tuple now succeeds because the
	// prior live confirmation is revoked.
	replacement := first
	replacement.confirmationID = authorityID("confirmation", 3)
	replacement.confirmationHash = authoritySha256('w')
	replacement.grantID = secondGrantID
	replacement.grantHash = secondGrantHash
	if err := insertConfirmationRow(ctx, admin, replacement); err != nil {
		t.Fatalf("replacement confirmation after revoke should succeed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 16. Grant revocation is a kill switch for every confirmation referencing it.
// ---------------------------------------------------------------------------

// derivedLive mirrors the ADR-0052 definition of a derived-live confirmation
// using the persisted relations only (no runtime effective-state view is
// created by this checkpoint; this query lives only in the test). Every
// element of the derived-live tuple is matched explicitly and never implied
// only by workspace_source_id: workspace_configuration_hash, source_scope_id,
// source_scope_revision, scope_config_hash and access_mode are all exact-
// matched against the confirmation's own binding row (which must still be
// enabled), the warning contract is re-joined to prove it is still the
// current registry row, and both revocation relations are considered.
func derivedLive(ctx context.Context, admin *pgxpool.Pool, organizationID, confirmationID string) bool {
	var isLive bool
	_ = admin.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.workspace_managed_grant_confirmation AS confirmation
			JOIN public.workspace AS workspace
			  ON workspace.organization_id = confirmation.organization_id
			 AND workspace.id = confirmation.workspace_id
			 AND workspace.current_revision = confirmation.workspace_revision
			JOIN public.organization AS organization
			  ON organization.id = confirmation.organization_id
			 AND organization.policy_revision = confirmation.policy_revision_number
			JOIN public.workspace_revision_source AS binding
			  ON binding.organization_id = confirmation.organization_id
			 AND binding.workspace_id = confirmation.workspace_id
			 AND binding.workspace_revision = confirmation.workspace_revision
			 AND binding.workspace_configuration_hash = confirmation.workspace_configuration_hash
			 AND binding.workspace_source_id = confirmation.workspace_source_id
			 AND binding.source_scope_id = confirmation.source_scope_id
			 AND binding.source_scope_revision = confirmation.source_scope_revision
			 AND binding.scope_config_hash = confirmation.scope_config_hash
			 AND binding.access_mode = confirmation.access_mode
			 AND binding.enabled
			JOIN public.workspace_managed_warning_contract AS warning
			  ON warning.warning_version = confirmation.warning_version
			 AND warning.warning_contract_hash = confirmation.warning_contract_hash
			 AND warning.revision = (SELECT max(revision) FROM public.workspace_managed_warning_contract)
			WHERE confirmation.organization_id = $1 AND confirmation.confirmation_id = $2
			  AND NOT EXISTS (
				  SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
				  WHERE revocation.organization_id = confirmation.organization_id
				    AND revocation.confirmation_id = confirmation.confirmation_id
			  )
			  AND NOT EXISTS (
				  SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation
				  WHERE grant_revocation.organization_id = confirmation.organization_id
				    AND grant_revocation.grant_id = confirmation.confirmation_actor_grant_id
				    AND grant_revocation.grant_revision = confirmation.confirmation_actor_grant_revision
			  )
		)
	`, organizationID, confirmationID).Scan(&isLive)
	return isLive
}

func TestGrantRevocationKillSwitchDisablesDependentConfirmations(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}
	if !derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
		t.Fatal("fresh confirmation is not derived-live before any revocation")
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}
	if derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
		t.Fatal("confirmation is still derived-live after its actor grant was revoked")
	}
	// The confirmation row itself is untouched; only its derived state moved.
	var stillPresent bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.workspace_managed_grant_confirmation WHERE organization_id='org_alpha' AND confirmation_id=$1)`, confirmation.confirmationID).Scan(&stillPresent); err != nil {
		t.Fatal(err)
	}
	if !stillPresent {
		t.Fatal("grant revocation deleted the confirmation row")
	}
}

// ---------------------------------------------------------------------------
// 17. Workspace/policy advance makes a prior confirmation stale (derived).
// ---------------------------------------------------------------------------

func TestWorkspaceAndPolicyAdvanceMakeConfirmationStale(t *testing.T) {
	t.Run("workspace revision advance", func(t *testing.T) {
		ctx := context.Background()
		admin := resetAuthorityHistoricalDatabase(t)
		fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
		confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
		if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
			t.Fatal(err)
		}
		if !derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
			t.Fatal("confirmation is not derived-live immediately after being confirmed")
		}
		// Advance to a new WorkspaceRevision that carries the same binding
		// forward unchanged; carry-forward is never implicit, so the
		// confirmation must become stale even though nothing about the
		// binding itself changed.
		newHash := authoritySha256('n')
		if _, err := admin.Exec(ctx, `
			INSERT INTO public.workspace_revision (organization_id, workspace_id, revision, configuration_hash, created_by)
			VALUES ('org_alpha', 'ws_alpha', $1, $2, 'usr_alice')
		`, fixture.workspaceRevision+1, newHash); err != nil {
			t.Fatal(err)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.workspace SET current_revision = $1 WHERE organization_id='org_alpha' AND id='ws_alpha'`, fixture.workspaceRevision+1); err != nil {
			t.Fatal(err)
		}
		if derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
			t.Fatal("confirmation is still derived-live after workspace revision advanced")
		}
	})

	t.Run("policy advance", func(t *testing.T) {
		ctx := context.Background()
		admin := resetAuthorityHistoricalDatabase(t)
		fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
		confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
		if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
			t.Fatal(err)
		}
		insertPolicyRegistryRow(t, ctx, admin, "org_alpha", 2, "policy-org_alpha-0002", authoritySha256('2'), "usr_alice", fixture.clock.grantedAt)
		if _, err := admin.Exec(ctx, `UPDATE public.organization SET policy_revision = 2 WHERE id = 'org_alpha'`); err != nil {
			t.Fatal(err)
		}
		if derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
			t.Fatal("confirmation is still derived-live after the organization policy advanced")
		}
	})

	// Warning-contract advance cannot be exercised in this checkpoint: only
	// v1 exists, and introducing v2 is explicitly reserved for a future
	// migration. The derivedLive() join already keys on warning_version and
	// warning_contract_hash, so the same staleness behavior is structural.
}

// ---------------------------------------------------------------------------
// 18. Advancing source_scope.latest_revision alone never carries a confirmation.
// ---------------------------------------------------------------------------

func TestScopeLatestRevisionAloneDoesNotCarryConfirmation(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}

	// Advance the scope's mutable management-lineage pointer to a brand new
	// revision 2, without ever changing the workspace binding (still revision
	// 1) that the confirmation was created against.
	newConfigArtifactID := "artifact_scope_config_alpha_v2"
	newConfigHash := authoritySha256('v')
	var resourceID string
	if err := admin.QueryRow(ctx, `SELECT app.source_scope_revision_resource_id('org_alpha', $1, 2)`, confirmationScopeID).Scan(&resourceID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name, ciphertext, size_bytes, nonce,
			wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
		) VALUES (
			'org_alpha', $1, 'source_scope_revision', 'scope_config_artifact_id', 'SOURCE_SCOPE_CONFIG', $2, 'SCOPE_CONFIG',
			decode(repeat('ab', 17), 'hex'), 1, decode(repeat('34', 12), 'hex'),
			decode('77726170706564', 'hex'), $3, 'kms://tenant', 1, $3, $3
		)
	`, newConfigArtifactID, resourceID, newConfigHash); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.source_scope_revision (
			organization_id, source_scope_id, revision, connection_id, connection_revision, discovered_scope_id,
			discovered_identity_digest, discovered_identity_digest_key_version, source_type, scope_config_artifact_id, scope_config_hash,
			scope_contract_version, access_mode, sync_interval_seconds, content_freshness_sla_seconds, acl_freshness_sla_seconds,
			object_limit, byte_limit, max_object_bytes, created_by
		) VALUES (
			'org_alpha', $1, 2, 'conn_org_alpha', 1, 'discovered_01ARZ3NDEKTSV4RRFFQ69G5FAV',
			$2, 1, 'FOLDER', $3, $4,
			'1.2', 'WORKSPACE_MANAGED', 300, 600, 300, 500, 500000, 100000, 'usr_alice'
		)
	`, confirmationScopeID, "hmac-sha256:k1:"+strings.Repeat("1", 64), newConfigArtifactID, newConfigHash); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.source_scope_activation (organization_id, source_scope_id, source_scope_revision, revision, status)
		VALUES ('org_alpha', $1, 2, 1, 'DRAFT')
	`, confirmationScopeID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_scope SET latest_revision = 2 WHERE organization_id = 'org_alpha' AND id = $1`, confirmationScopeID); err != nil {
		t.Fatalf("advance source_scope.latest_revision: %v", err)
	}

	// The confirmation, its target binding and workspace revision all still
	// reference source_scope_revision 1 and remain untouched and live.
	if !derivedLive(ctx, admin, "org_alpha", confirmation.confirmationID) {
		t.Fatal("confirmation liveness was affected by source_scope.latest_revision advancing alone")
	}
	var boundRevision int64
	if err := admin.QueryRow(ctx, `SELECT source_scope_revision FROM public.workspace_managed_grant_confirmation WHERE organization_id='org_alpha' AND confirmation_id=$1`, confirmation.confirmationID).Scan(&boundRevision); err != nil {
		t.Fatal(err)
	}
	if boundRevision != 1 {
		t.Fatalf("confirmation source_scope_revision = %d, want unchanged 1", boundRevision)
	}
}

// ---------------------------------------------------------------------------
// 19. Inertness: no runtime write authority, no downstream side effects.
// ---------------------------------------------------------------------------

func TestConfirmationAuthorityRemainsInert(t *testing.T) {
	ctx := context.Background()
	admin := resetAuthorityHistoricalDatabase(t)
	fixture := setupConfirmationFixture(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	confirmation := fixture.baseConfirmation(1, fixture.clock.confirmedAt)
	if err := insertConfirmationRow(ctx, admin, confirmation); err != nil {
		t.Fatal(err)
	}
	if err := insertGrantRevocationRow(ctx, admin, "org_alpha", authorityID("grantrevoke", 1), authoritySha256('r'),
		fixture.grantID, fixture.grantRevision, fixture.grantHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}
	if err := insertConfirmationRevocationRow(ctx, admin, "org_alpha", authorityID("confirmrevoke", 1), authoritySha256('t'),
		confirmation.confirmationID, confirmation.confirmationHash, "usr_alice", fixture.clock.revokedAt, fixture.policyNumber, fixture.policyID); err != nil {
		t.Fatal(err)
	}

	var connectionActiveRevision, scopeActiveRevision any
	var scopeStatus, activationStatus, trustProjectionStatus string
	if err := admin.QueryRow(ctx, `
		SELECT connection.active_revision, scope.active_revision, scope.status, activation.status, projection.status
		FROM public.source_scope AS scope
		JOIN public.source_connection AS connection
		  ON connection.organization_id = scope.organization_id AND connection.id = scope.connection_id
		JOIN public.source_scope_activation AS activation
		  ON activation.organization_id = scope.organization_id AND activation.source_scope_id = scope.id AND activation.source_scope_revision = scope.latest_revision
		JOIN public.source_connection_revision AS connectionRevision
		  ON connectionRevision.organization_id = connection.organization_id AND connectionRevision.connection_id = connection.id AND connectionRevision.revision = connection.latest_revision
		JOIN public.source_connection_trust_projection AS projection
		  ON projection.organization_id = connectionRevision.organization_id AND projection.trust_record_id = connectionRevision.trust_record_id
		WHERE scope.organization_id = 'org_alpha' AND scope.id = $1
	`, confirmationScopeID).Scan(&connectionActiveRevision, &scopeActiveRevision, &scopeStatus, &activationStatus, &trustProjectionStatus); err != nil {
		t.Fatal(err)
	}
	if connectionActiveRevision != nil || scopeActiveRevision != nil || scopeStatus != "DRAFT" || activationStatus != "DRAFT" || trustProjectionStatus != "DRAFT" {
		t.Fatalf("confirmation lifecycle disturbed connection/scope authority: connActive=%v scopeActive=%v scope=%s activation=%s trust=%s",
			connectionActiveRevision, scopeActiveRevision, scopeStatus, activationStatus, trustProjectionStatus)
	}

	var outboxCount, auditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.outbox_event WHERE organization_id = 'org_alpha'`).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = 'org_alpha'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 0 {
		t.Fatalf("confirmation lifecycle created %d outbox events", outboxCount)
	}
	if auditCount != 0 {
		t.Fatalf("confirmation lifecycle created %d audit events", auditCount)
	}

	// The runtime role can read every new relation but cannot write to any of
	// them, directly confirming the "knowvault_app: SELECT only" boundary end
	// to end through a real pooled connection.
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_alpha")
	if err := insertGrantRow(ctx, tx, grantInsertParams{
		organizationID: "org_alpha", grantID: authorityID("grant", 500), workspaceID: "ws_alpha", principalID: "usr_alice",
		grantedBy: "usr_alice", policyNumber: fixture.policyNumber, policyID: fixture.policyID, grantHash: authoritySha256('x'), clock: fixture.clock,
	}); err == nil {
		t.Fatal("runtime role unexpectedly inserted an actor grant")
	}
}
