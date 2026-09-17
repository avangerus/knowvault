package postgres_test

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/operator"
)

func tenantProvisionFixture() operator.TenantProvisionRequest {
	return operator.TenantProvisionRequest{
		OrganizationID:       "org_operator_tenant",
		OrganizationName:     "Operator Tenant",
		Region:               "ru",
		OwnerPrincipalID:     "usr_operator_owner",
		OwnerDisplayName:     "Operator Owner",
		WorkspaceID:          "ws_operator_tenant",
		WorkspaceName:        "Knowledge Workspace",
		WorkspaceDescription: "Initial owner workspace",
	}
}

// TestOperatorTenantProvisionIsAtomicAndIdempotent exercises the production
// operation against the current migrated PostgreSQL schema. The first call
// creates every owner-tenant relation and one canonical audit event; the
// exact repeat verifies those rows and reports created=false without adding a
// second audit chain link.
func TestOperatorTenantProvisionIsAtomicAndIdempotent(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	request := tenantProvisionFixture()

	created, err := operator.TenantProvision(ctx, admin, request)
	if err != nil || !created {
		t.Fatalf("first tenant provision: created=%v err=%v", created, err)
	}
	created, err = operator.TenantProvision(ctx, admin, request)
	if err != nil || created {
		t.Fatalf("exact tenant provision repeat: created=%v err=%v", created, err)
	}

	for table, want := range map[string]int{
		"organization":                 1,
		"principal":                    1,
		"organization_role_assignment": 1,
		"workspace":                    1,
		"workspace_revision":           1,
		"workspace_revision_snapshot":  1,
		"workspace_member":             1,
		"audit_event":                  1,
		"audit_chain_head":             1,
	} {
		var got int
		query := "SELECT count(*) FROM public." + table + " WHERE organization_id = $1"
		if table == "organization" || table == "principal" {
			// principal is filtered by organization_id; organization uses id.
			if table == "organization" {
				query = "SELECT count(*) FROM public.organization WHERE id = $1"
			}
		}
		if err := admin.QueryRow(ctx, query, request.OrganizationID).Scan(&got); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if got != want {
			t.Fatalf("%s count=%d, want %d", table, got, want)
		}
	}

	var organizationName, region, ownerID, workspaceName, workspaceStatus, action, resourceType, outcome string
	if err := admin.QueryRow(ctx, `
		SELECT organization.name, organization.region, organization.owner_principal_id,
		       workspace.name, workspace.status,
		       audit.action, audit.resource_type, audit.outcome
		FROM public.organization
		JOIN public.workspace ON workspace.organization_id = organization.id
		JOIN public.audit_event AS audit ON audit.organization_id = organization.id
		WHERE organization.id = $1`, request.OrganizationID).
		Scan(&organizationName, &region, &ownerID, &workspaceName, &workspaceStatus, &action, &resourceType, &outcome); err != nil {
		t.Fatal(err)
	}
	if organizationName != request.OrganizationName || region != request.Region || ownerID != request.OwnerPrincipalID ||
		workspaceName != request.WorkspaceName || workspaceStatus != "ACTIVE" || action != "workspace.created" ||
		resourceType != "WORKSPACE" || outcome != "SUCCESS" {
		t.Fatalf("provisioned state=%s/%s/%s/%s/%s/%s/%s/%s", organizationName, region, ownerID, workspaceName, workspaceStatus, action, resourceType, outcome)
	}
	var sequence int64
	var eventCount int
	if err := admin.QueryRow(ctx, `SELECT last_sequence FROM public.audit_chain_head WHERE organization_id = $1`, request.OrganizationID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id = $1 AND action = 'workspace.created'`, request.OrganizationID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if sequence != 1 || eventCount != 1 {
		t.Fatalf("audit chain sequence/events=%d/%d, want 1/1", sequence, eventCount)
	}
}

// TestOperatorTenantProvisionRejectsPartialState proves that an owner base
// inserted outside the operation is not completed or repaired silently. The
// operation reports the closed migration incompatibility and leaves the
// workspace half of the requested tenant absent.
func TestOperatorTenantProvisionRejectsPartialState(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	request := tenantProvisionFixture()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization (id, name, status, region, owner_principal_id)
		VALUES ($1, $2, 'ACTIVE', $3, $4)`, request.OrganizationID, request.OrganizationName, request.Region, request.OwnerPrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $3, 'ACTIVE')`, request.OwnerPrincipalID, request.OrganizationID, request.OwnerDisplayName); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
		(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ($1, $2, $3, 'OWNER', 1, $3)`, "ora_"+request.OrganizationID, request.OrganizationID, request.OwnerPrincipalID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	created, err := operator.TenantProvision(ctx, admin, request)
	if created {
		t.Fatal("partial owner tenant was reported as created")
	}
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("partial owner tenant error=%v, want MIGRATION_INCOMPATIBLE", err)
	}
	var workspaces int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.workspace WHERE organization_id = $1`, request.OrganizationID).Scan(&workspaces); err != nil {
		t.Fatal(err)
	}
	if workspaces != 0 {
		t.Fatalf("partial-state rejection created %d workspace rows", workspaces)
	}
}

// TestOperatorTenantProvisionRejectsCrossTenantOwnerID proves that a globally
// colliding principal ID cannot be rebound into a second organization.
func TestOperatorTenantProvisionRejectsCrossTenantOwnerID(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	first := tenantProvisionFixture()
	if _, err := operator.TenantProvision(ctx, admin, first); err != nil {
		t.Fatalf("first tenant provision: %v", err)
	}
	second := first
	second.OrganizationID = "org_operator_other"
	second.OrganizationName = "Other Tenant"
	second.WorkspaceID = "ws_operator_other"
	second.WorkspaceName = "Other Workspace"
	created, err := operator.TenantProvision(ctx, admin, second)
	if created {
		t.Fatal("cross-tenant owner collision was reported as created")
	}
	failure, ok := operator.IsFailure(err)
	if !ok || failure.Code != operator.FailureMigrationIncompatible {
		t.Fatalf("cross-tenant owner collision error=%v, want MIGRATION_INCOMPATIBLE", err)
	}
	var organizations int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.organization WHERE id = $1`, second.OrganizationID).Scan(&organizations); err != nil {
		t.Fatal(err)
	}
	if organizations != 0 {
		t.Fatal("cross-tenant rejection created the second organization")
	}
}
