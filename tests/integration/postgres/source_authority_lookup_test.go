package postgres_test

// B2.2b1 — the real-PostgreSQL positive chain and opaque denials of the typed
// source authority lookup (Store.ResolvePostgreSQLAuthorityRequest).
//
// The lookup turns one caller-known workspace/scope/connection identity triple
// into the candidate PostgreSQLAuthorityRequest the existing execution resolver
// consumes. This card proves exactly three facts against real PostgreSQL 18.4:
//
//  1. the positive chain: an admitted managed source resolves to a candidate
//     that equals the admitted request exactly, and that candidate is accepted
//     unchanged by Store.ResolvePostgreSQLAuthority, which returns the exact
//     workspace/source/scope/hash/access identity and a valid projection bound
//     to the direct-control connection;
//  2. a well-formed but different connection collapses to the zero candidate
//     and one content-free NOT_FOUND surface;
//  3. an active organization MEMBER that holds no workspace membership
//     collapses to the identical zero candidate and the identical NOT_FOUND
//     surface.
//
// Case 3 is the reason the card exists: a caller whose only fault is the missing
// workspace membership must not be able to distinguish a live binding from a
// wrong connection, so the lookup is not an existence oracle.
//
// Deliberately not covered here (B2.2b2): SOURCE_ENFORCED bindings, malformed
// server facts, duplicate result sets, driver failures, revocation races and
// mutation after lookup.
//
// The fixture is newAdmittedAuthorityFixture from
// source_authority_admission_negative_test.go. The exact connection identity is
// a direct-control fact: it is read from public.source_scope and never inferred
// from the fixture or hardcoded.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	// authorityLookupWrongConnectionID is one well-formed connection identity —
	// it uses exactly the identifier alphabet every real connection id uses, so
	// admission accepts it — that no fixture ever creates.
	authorityLookupWrongConnectionID = "con_01ARZ3NDEKTSV4RRFFQ69G5FAZ"

	// authorityLookupOrgMemberPrincipal is seeded as an ACTIVE organization
	// MEMBER that deliberately holds no workspace membership.
	authorityLookupOrgMemberPrincipal = "usr_authority_lookup_org_member"
	authorityLookupOrgMemberRoleID    = "ora_authority_lookup_org_member"
)

// authorityLookupDenialSurface requires one failed lookup to be exactly the
// content-free denial — the zero candidate, the exact NOT_FOUND code as the
// whole error text, no unwrap/cause chain and no identifier, SQL or credential
// leak — and returns its canonical observable surface so that two independent
// denial causes can be compared for identical collapse.
func authorityLookupDenialSurface(
	t *testing.T,
	label string,
	candidate workspacerepository.PostgreSQLAuthorityRequest,
	err error,
	identifiers ...string,
) string {
	t.Helper()
	if candidate != (workspacerepository.PostgreSQLAuthorityRequest{}) {
		t.Fatalf("%s: candidate = %#v, want the zero candidate", label, candidate)
	}
	if err == nil {
		t.Fatalf("%s: lookup unexpectedly resolved a candidate", label)
	}
	if got := workspacerepository.CodeOf(err); got != workspacerepository.CodeNotFound {
		t.Fatalf("%s: failure code = %q, want %q", label, got, workspacerepository.CodeNotFound)
	}
	if err.Error() != string(workspacerepository.CodeNotFound) {
		t.Fatalf("%s: failure text = %q, want %q", label, err.Error(), workspacerepository.CodeNotFound)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("%s: failure retained an unwrap/cause chain: %v", label, unwrapped)
	}
	var repositoryError *workspacerepository.Error
	if !errors.As(err, &repositoryError) {
		t.Fatalf("%s: failure is not a repository error: %#v", label, err)
	}
	// %#v renders the repository error's private code and cause, so a retained
	// cause would become visible here even though the error text stays
	// content-free; the surface therefore also proves no cause was kept.
	surface := fmt.Sprintf("candidate=%#v error_type=%T error_value=%#v error_text=%q",
		candidate, err, repositoryError, err.Error())
	forbidden := append([]string{
		authorityCredentialSentinel,
		authorityDSNSentinel,
		authoritySQLSentinel,
		"postgres://",
		"postgresql://",
		"password",
		"credential",
		"dsn",
		"select ",
		"insert ",
		"update ",
		"delete ",
		"permission",
	}, identifiers...)
	lower := strings.ToLower(surface)
	for _, marker := range forbidden {
		if marker != "" && strings.Contains(lower, strings.ToLower(marker)) {
			t.Fatalf("%s: denial surface leaked %q: %s", label, marker, surface)
		}
	}
	return surface
}

func TestPostgreSQLSourceAuthorityLookupPositiveAndOpaqueDenials(t *testing.T) {
	ctx := context.Background()
	fixture := newAdmittedAuthorityFixture(t)

	// The exact connection identity is one direct-control fact. The lookup is
	// keyed on it, so it is read from the exact scope row rather than derived
	// from the fixture or pinned as a literal.
	var directConnectionID string
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id
		FROM public.source_scope
		WHERE organization_id = $1 AND id = $2`,
		regOrg, fixture.request.SourceScopeID).Scan(&directConnectionID); err != nil {
		t.Fatalf("direct control read of the source scope connection: %v", err)
	}
	if directConnectionID == "" {
		t.Fatal("direct control read returned an empty connection id")
	}
	if directConnectionID == authorityLookupWrongConnectionID {
		t.Fatal("the wrong-connection lookup id is the live connection id")
	}

	lookup := workspacerepository.PostgreSQLAuthorityLookup{
		WorkspaceID:   fixture.request.WorkspaceID,
		SourceScopeID: fixture.request.SourceScopeID,
		ConnectionID:  directConnectionID,
	}

	// Case 1 — positive chain: the candidate is the exact admitted request, and
	// the existing authority resolver accepts it unchanged.
	candidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, lookup)
	if err != nil {
		t.Fatalf("positive lookup: %v", err)
	}
	if candidate != fixture.request {
		t.Fatalf("positive lookup candidate = %#v, want the exact admitted request %#v", candidate, fixture.request)
	}
	resolved, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, candidate)
	if err != nil {
		t.Fatalf("resolve the looked-up candidate: %v", err)
	}
	if resolved.WorkspaceID() != fixture.request.WorkspaceID ||
		resolved.WorkspaceRevision() != fixture.binding.workspaceRevision ||
		resolved.WorkspaceConfigurationHash() != fixture.binding.workspaceConfHash ||
		resolved.WorkspaceSourceID() != fixture.request.WorkspaceSourceID ||
		resolved.SourceScopeID() != fixture.request.SourceScopeID ||
		resolved.SourceScopeRevision() != fixture.request.SourceScopeRevision ||
		resolved.ScopeConfigHash() != fixture.request.ScopeConfigHash ||
		resolved.AccessMode() != fixture.request.AccessMode {
		t.Fatalf("candidate authority drifted: %s", formatAuthorityResult(t, resolved))
	}
	projection := resolved.Projection()
	if err := projection.Validate(); err != nil {
		t.Fatalf("candidate authority projection invalid: %v", err)
	}
	if projection.ConnectionID != directConnectionID {
		t.Fatalf("candidate authority projection connection = %q, want the direct control %q",
			projection.ConnectionID, directConnectionID)
	}

	// Case 2 — one well-formed different connection must collapse to the zero
	// candidate and the content-free denial.
	wrongLookup := lookup
	wrongLookup.ConnectionID = authorityLookupWrongConnectionID
	wrongCandidate, wrongErr := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, wrongLookup)
	wrongSurface := authorityLookupDenialSurface(t, "wrong connection", wrongCandidate, wrongErr,
		directConnectionID, authorityLookupWrongConnectionID,
		fixture.request.WorkspaceID, fixture.request.WorkspaceSourceID, fixture.request.SourceScopeID)

	// Case 3 — an active organization MEMBER without workspace membership must
	// collapse to the identical surface. The actor is seeded with admin SQL and
	// deliberately receives no workspace_member row.
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1, $2, 'USER', $1, 'ACTIVE')`,
		authorityLookupOrgMemberPrincipal, regOrg); err != nil {
		t.Fatalf("seed active organization member principal: %v", err)
	}
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
			(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ($1, $2, $3, 'MEMBER', 1, $4)`,
		authorityLookupOrgMemberRoleID, regOrg, authorityLookupOrgMemberPrincipal, regOwner); err != nil {
		t.Fatalf("seed organization MEMBER role: %v", err)
	}
	// Control read of the exact seeded facts: the actor is ACTIVE and holds the
	// organization MEMBER role, and holds no membership in the fixture
	// workspace, so the denial cannot come from a missing organization role.
	var memberStatus string
	var organizationMember, workspaceMember bool
	if err := fixture.admin.QueryRow(ctx, `
		SELECT principal.status,
		       EXISTS (
		           SELECT 1
		           FROM public.organization_role_assignment AS assignment
		           WHERE assignment.organization_id = $2
		             AND assignment.principal_id = $1
		             AND assignment.role = 'MEMBER'
		             AND assignment.revoked_at IS NULL
		       ),
		       EXISTS (
		           SELECT 1
		           FROM public.workspace_member AS member
		           WHERE member.organization_id = $2
		             AND member.workspace_id = $3
		             AND member.principal_id = $1
		             AND member.removed_at IS NULL
		       )
		FROM public.principal AS principal
		WHERE principal.organization_id = $2 AND principal.id = $1`,
		authorityLookupOrgMemberPrincipal, regOrg, fixture.request.WorkspaceID).
		Scan(&memberStatus, &organizationMember, &workspaceMember); err != nil {
		t.Fatalf("control read of the seeded organization member: %v", err)
	}
	if memberStatus != "ACTIVE" || !organizationMember || workspaceMember {
		t.Fatalf("seeded actor is status=%q organization_member=%t workspace_member=%t, want ACTIVE/true/false",
			memberStatus, organizationMember, workspaceMember)
	}
	memberCandidate, memberErr := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx,
		authorityAccess(fixture.binding, authorityLookupOrgMemberPrincipal, "req_authority_lookup_org_member"), lookup)
	memberSurface := authorityLookupDenialSurface(t, "organization member without workspace membership",
		memberCandidate, memberErr, directConnectionID, authorityLookupWrongConnectionID,
		authorityLookupOrgMemberPrincipal,
		fixture.request.WorkspaceID, fixture.request.WorkspaceSourceID, fixture.request.SourceScopeID)
	if memberSurface != wrongSurface {
		t.Fatalf("organization member denial surface differs from the wrong-connection surface:\nwrong connection: %s\norganization member: %s",
			wrongSurface, memberSurface)
	}
}
