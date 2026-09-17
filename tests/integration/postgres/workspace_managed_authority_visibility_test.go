package postgres_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration 000011 replaces each authority relation's 000010 tenant-isolation
// policy with an authority-metadata read policy, and replaces one 000009 audit
// guard. The 000010 suite pins the policies it shipped, against the 000010
// schema, so nothing there covers the replacements. These tests pin them at
// head: the widened read predicate is the one security-relevant thing 000011
// changes about reads, and it would otherwise ship unproved.

func insertAuthorityPrincipal(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, principalID string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')
	`, principalID, organizationID); err != nil {
		t.Fatalf("seed principal %s: %v", principalID, err)
	}
}

func addAuthorityWorkspaceMember(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, principalID, role string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.workspace_member (
			id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
		) VALUES ($1, $2, $3, $4, $5, 1, $6)
	`, "wsm_"+principalID, organizationID, workspaceID, principalID, role, authorityCommandOwner); err != nil {
		t.Fatalf("seed workspace member %s: %v", principalID, err)
	}
}

func assignAuthorityOrganizationRole(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, principalID, role string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment (
			id, organization_id, principal_id, role, valid_from_revision, assigned_by
		) VALUES ($1, $2, $3, $4, 1, $5)
	`, "ora_"+principalID, organizationID, principalID, role, authorityCommandOwner); err != nil {
		t.Fatalf("assign organization role to %s: %v", principalID, err)
	}
}

// countVisibleGrants reads the authority relation as one exact principal, under
// the runtime role and its row-level security.
func countVisibleGrants(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID string) int {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var visible int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM public.workspace_source_confirmation_actor_grant
	`).Scan(&visible); err != nil {
		t.Fatalf("read authority metadata as %s: %v", principalID, err)
	}
	return visible
}

// TestAuthorityMetadataVisibilityMatchesTheAuthorityMatrix proves the read
// policy 000011 installed is exactly the ADR-0053 matrix — existing membership,
// Organization OWNER/ADMIN, and the exact self principal — and nothing wider.
func TestAuthorityMetadataVisibilityMatchesTheAuthorityMatrix(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	// The grant is issued BY the owner TO a distinct target, so granted_by and
	// principal_id are different principals and their visibility can be told
	// apart.
	target := "usr_authority_target"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, target)
	addAuthorityWorkspaceMember(t, ctx, admin, fixture.organizationID, fixture.workspaceID, target, "MANAGER")

	command := fixture.baseGrantIssue(20)
	command.targetID = target
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("seed an authority grant: %v", err)
	}

	// A same-tenant principal who is neither a workspace member, nor an
	// Organization OWNER/ADMIN, nor the grant principal sees nothing.
	outsider := "usr_authority_outsider"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, outsider)
	assignAuthorityOrganizationRole(t, ctx, admin, fixture.organizationID, outsider, "MEMBER")
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, outsider); visible != 0 {
		t.Fatalf("unrelated same-tenant principal sees %d authority rows, want 0", visible)
	}

	// Organization membership alone is not an authority-metadata role, and a
	// SECURITY_AUDITOR is no exception.
	auditor := "usr_authority_auditor"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, auditor)
	assignAuthorityOrganizationRole(t, ctx, admin, fixture.organizationID, auditor, "SECURITY_AUDITOR")
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, auditor); visible != 0 {
		t.Fatalf("SECURITY_AUDITOR sees %d authority rows, want 0", visible)
	}

	// Organization ADMIN reaches authority metadata without workspace membership.
	organizationAdmin := "usr_authority_org_admin"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, organizationAdmin)
	assignAuthorityOrganizationRole(t, ctx, admin, fixture.organizationID, organizationAdmin, "ADMIN")
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, organizationAdmin); visible != 1 {
		t.Fatalf("Organization ADMIN sees %d authority rows, want 1", visible)
	}

	// The exact grant principal keeps self-visibility after losing workspace
	// membership: self-revoke visibility never requires current membership.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member SET removed_at = transaction_timestamp(), valid_to_revision = 2
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3
	`, fixture.organizationID, fixture.workspaceID, target); err != nil {
		t.Fatalf("remove the grant principal from the workspace: %v", err)
	}
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, target); visible != 1 {
		t.Fatalf("exact grant principal sees %d authority rows after losing membership, want 1", visible)
	}
}

// TestAuthorityMetadataIssuerHasNoSelfVisibility proves granted_by is not a
// self-visibility disjunct. An issuer reaches authority metadata through their
// current Organization role; a personal disjunct would let one who lost that
// role keep telling DENIED apart from NOT_FOUND.
//
// The database gate does not evaluate the ADR-0053 policy matrix — that is the
// deferred Go policy layer — so a grant issued by a bare principal is
// representable here, which is exactly what isolates the granted_by question.
func TestAuthorityMetadataIssuerHasNoSelfVisibility(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	issuer := "usr_authority_issuer"
	target := "usr_authority_holder"
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, issuer)
	insertAuthorityPrincipal(t, ctx, admin, fixture.organizationID, target)

	command := fixture.baseGrantIssue(21)
	command.grantedBy = issuer
	command.targetID = target
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("seed a grant issued by a bare principal: %v", err)
	}

	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, issuer); visible != 0 {
		t.Fatalf("granted_by principal sees %d authority rows, want 0: granted_by is not self-visibility", visible)
	}
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, target); visible != 1 {
		t.Fatalf("exact grant principal sees %d authority rows, want 1", visible)
	}
}

// TestAuthorityMetadataRLSFailsClosedAcrossTenants proves the replacement read
// policies keep the tenant fence the 000010 policies provided.
func TestAuthorityMetadataRLSFailsClosedAcrossTenants(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	fixture := setupAuthorityCommandFixture(t, ctx, admin)
	app := openAuthorityAppPool(t, ctx)

	command := fixture.baseGrantIssue(22)
	if err := fixture.runGrantIssueCommand(t, ctx, app, command); err != nil {
		t.Fatalf("seed an authority grant: %v", err)
	}

	other := "org_authority_other"
	otherOwner := "usr_authority_other_owner"
	seedOrganization(t, ctx, admin, other, otherOwner, "ws_authority_other")

	// Being an Organization OWNER of another tenant reveals nothing, and
	// claiming the victim tenant's ID reveals nothing either.
	if visible := countVisibleGrants(t, ctx, app, other, otherOwner); visible != 0 {
		t.Fatalf("foreign tenant owner sees %d authority rows, want 0", visible)
	}
	if visible := countVisibleGrants(t, ctx, app, fixture.organizationID, otherOwner); visible != 0 {
		t.Fatalf("foreign principal claiming the victim tenant sees %d authority rows, want 0", visible)
	}
}

// TestAuthorityAuditVocabularyIsReservedInTheDatabase proves the database
// refuses the authority metadata vocabulary on a non-authority event, exactly
// as the Go validator does. ADR-0054 calls the two validators deliberate
// mirrors; without this gate the database was the weaker of the two.
func TestAuthorityAuditVocabularyIsReservedInTheDatabase(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, authorityCommandOrganization, authorityCommandOwner, authorityCommandWorkspace)

	_, err := admin.Exec(ctx, `
		INSERT INTO public.audit_event (
			id, organization_id, sequence, actor_type, actor_principal_id, action,
			resource_type, resource_id, request_id, outcome, metadata_json,
			canonical_bytes, previous_event_hash, event_hash, occurred_at
		) VALUES (
			'aud_reserved_vocab', $1, 1, 'HUMAN', $2, 'identity.login',
			'IDENTITY', $2, 'req_test', 'SUCCESS',
			'{"authority_operation":"WORKSPACE_MANAGED_CONFIRM"}'::jsonb,
			'\x7b7d'::bytea, 'sha256:' || repeat('0',64), 'sha256:' || repeat('1',64),
			transaction_timestamp()
		)
	`, authorityCommandOrganization, authorityCommandOwner)
	if err == nil {
		t.Fatal("a non-authority audit event carrying the authority vocabulary must be rejected")
	}
}

// TestAuthorityGuardsAreSecurityDefiner pins prosecdef on every trigger guard
// this checkpoint owns or replaces. CREATE OR REPLACE silently drops SECURITY
// DEFINER when the new body omits the clause, the protected-hash gate hashes
// the defining file rather than the effective schema, and nothing else notices.
// That is a formalizable invariant, so it belongs in a deterministic gate
// rather than in review attention.
// TestAuthorityPrivilegeMatrixAtHeadIsInsertOnly is the head-of-history proof
// of ADR-0054's claim that the runtime role receives INSERT on the four
// authority relations and nothing else. The 000010 suite pins the SELECT-only
// matrix that migration shipped, against the 000010 schema, so nothing there
// covers what 000011 grants. Without this, widening one GRANT line by a single
// word would ship with every test green.
func TestAuthorityPrivilegeMatrixAtHeadIsInsertOnly(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	// The receipt is the one relation the runtime role may UPDATE: a command
	// terminalizes its own reservation. It may still never DELETE one.
	matrix := map[string]map[string]bool{
		"workspace_source_confirmation_actor_grant": {
			"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		},
		"workspace_source_confirmation_actor_grant_revocation": {
			"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		},
		"workspace_managed_grant_confirmation": {
			"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		},
		"workspace_managed_grant_revocation": {
			"SELECT": true, "INSERT": true, "UPDATE": false, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		},
		"workspace_managed_authority_command_receipt": {
			"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": false,
			"TRUNCATE": false, "REFERENCES": false, "TRIGGER": false,
		},
	}

	for relation, privileges := range matrix {
		for privilege, want := range privileges {
			var granted bool
			if err := admin.QueryRow(ctx, `
				SELECT has_table_privilege('knowvault_app', $1, $2)
			`, "public."+relation, privilege).Scan(&granted); err != nil {
				t.Fatalf("read %s on %s: %v", privilege, relation, err)
			}
			if granted != want {
				t.Fatalf("knowvault_app has %s on %s = %v, want %v", privilege, relation, granted, want)
			}
		}
	}

	// FORCE ROW LEVEL SECURITY on all five, so the tenant boundary applies to
	// the table owner too rather than only to unprivileged roles.
	for relation := range matrix {
		var enabled, forced bool
		if err := admin.QueryRow(ctx, `
			SELECT relrowsecurity, relforcerowsecurity FROM pg_class
			WHERE oid = ('public.' || $1)::regclass
		`, relation).Scan(&enabled, &forced); err != nil {
			t.Fatalf("read row security of %s: %v", relation, err)
		}
		if !enabled || !forced {
			t.Fatalf("%s has row security enabled=%v forced=%v, want both true", relation, enabled, forced)
		}
	}
}

func TestAuthorityGuardsAreSecurityDefiner(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)

	for _, function := range []string{
		"workspace_managed_authority_receipt_projection_guard",
		"workspace_source_confirmation_actor_grant_receipt_guard",
		"actor_grant_revocation_receipt_guard",
		"workspace_managed_grant_confirmation_receipt_guard",
		"workspace_managed_grant_revocation_receipt_guard",
		"workspace_managed_authority_receipt_result_binding",
		"workspace_managed_authority_receipt_audit_binding",
		"authority_audit_event_is_claimed",
		"authority_current_policy_deferred_guard",
		"workspace_managed_confirmation_warning_at_commit",
		"authority_audit_projection_guard",
		"workspace_managed_authority_fresh_receipt",
		// Declared SECURITY DEFINER by 000009 and replaced by 000011: the
		// attribute must survive the replacement.
		"workspace_source_audit_projection_guard",
	} {
		var securityDefiner bool
		if err := admin.QueryRow(ctx, `
			SELECT p.prosecdef FROM pg_proc AS p
			JOIN pg_namespace AS n ON n.oid = p.pronamespace
			WHERE n.nspname = 'app' AND p.proname = $1
		`, function).Scan(&securityDefiner); err != nil {
			t.Fatalf("look up app.%s: %v", function, err)
		}
		if !securityDefiner {
			t.Fatalf("app.%s lost SECURITY DEFINER", function)
		}
	}
}
