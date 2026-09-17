package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestAuditJournalIncludesOwnOpaqueReadDenialsAcrossPages(t *testing.T) {
	f := newExactEvidenceFixture(t, "audit denial fixture\n")
	_, version, extraction := s1dActiveEvidence(t, f.ctx, f.admin)
	fragment := s1dFragments(t, f.ctx, f.admin, extraction)[0].id
	seedJournalSecondWorkspace(t, f.ctx, f.admin, s1dOrg, "ws_other_audit", s1dOwner)
	seedOrganization(t, f.ctx, f.admin, "org_foreign_audit", "usr_foreign_audit", "ws_foreign_audit")
	// A valid source version with an unknown fragment drives the real denial
	// writer. It must persist without a workspace FK and disclose no bytes.
	wanted := map[string]bool{}
	for i := 0; i < 105; i++ {
		access := f.access
		access.RequestID = fmt.Sprintf("req_opaque_denial_%03d", i)
		read, err := f.viewer.ReadObjectExactVersion(f.ctx, access, s1dWorkspace,
			"fragment_01ARZ3NDEKTSV4RRFFQ69G5FAZ", version)
		if !errors.Is(err, evidence.ErrNotFound) || len(read.Text) != 0 {
			t.Fatalf("denial disclosed bytes: %v", err)
		}
		wanted[access.RequestID] = true
	}
	for _, ws := range []string{"ws_other_audit", "ws_missing_audit"} {
		if _, err := f.viewer.ReadObjectExactVersion(f.ctx, f.access, ws, fragment, version); !errors.Is(err, evidence.ErrNotFound) {
			t.Fatal(err)
		}
	}
	foreign := database.AccessContext{OrganizationID: "org_foreign_audit", PrincipalID: "usr_foreign_audit", RequestID: "req_foreign_opaque_denial"}
	if _, err := f.viewer.ReadObjectExactVersion(f.ctx, foreign, s1dWorkspace, fragment, version); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(f.ctx, `INSERT INTO public.organization_role_assignment (id,organization_id,principal_id,role,valid_from_revision,assigned_by) VALUES ('ora_opaque_auditor',$1,$2,'SECURITY_AUDITOR',1,$3)`, s1dOrg, s1dViewer, s1dOwner); err != nil {
		t.Fatal(err)
	}
	store := newWorkspaceSourceRepository(t, f.ctx)
	page, err := store.AuditJournal(f.ctx, f.access, s1dWorkspace)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for {
		for _, entry := range page.Events {
			if entry.ErrorCode == nil || *entry.ErrorCode != "WORKSPACE_OBJECT_DENIED" {
				continue
			}
			if !wanted[entry.RequestID] || seen[entry.RequestID] || entry.ResourceID != s1dWorkspace || entry.Outcome != audit.OutcomeDenied {
				t.Fatalf("wrong or duplicate denial: %+v", entry)
			}
			seen[entry.RequestID] = true
		}
		if !page.Truncated {
			break
		}
		if page.NextBeforeSequence == nil {
			t.Fatal("missing continuation")
		}
		page, err = store.AuditJournalBefore(f.ctx, f.access, s1dWorkspace, *page.NextBeforeSequence)
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != len(wanted) {
		t.Fatalf("visible denials=%d want=%d", len(seen), len(wanted))
	}
	var stored int
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND workspace_id IS NULL AND resource_id=$2 AND error_code='WORKSPACE_OBJECT_DENIED'`, s1dOrg, s1dWorkspace).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != len(wanted) {
		t.Fatalf("stored denial workspace binding changed: %d", stored)
	}
}

// TestAuditJournalGatesAndContent proves the R4 audit-journal server slice on
// real PostgreSQL: only audit.read_metadata grants read the journal, every
// refusal is the same CodeNotFound with no existence oracle, a successful
// read records its own audit.viewed event, and tenant isolation holds at the
// database boundary even for direct SQL under the runtime role.
func TestAuditJournalGatesAndContent(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status) VALUES
		('usr_carol','org_alpha','USER','Carol','ACTIVE'),
		('usr_bob','org_alpha','USER','Bob','ACTIVE'),
		('usr_dave','org_alpha','USER','Dave','ACTIVE'),
		('usr_fred','org_alpha','USER','Fred','ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	// dave: organization security auditor with no workspace membership
	// (policy leg 1). Carol and bob's memberships are created through the
	// repository below — a direct SQL insert would change the member set
	// without advancing the revision and trip the configuration-hash check
	// that Get performs, which is exactly the integrity mechanism under test.
	if _, err := admin.Exec(ctx, `INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_dave','org_alpha','usr_dave','SECURITY_AUDITOR',1,'usr_alice')`); err != nil {
		t.Fatal(err)
	}

	store := newWorkspaceSourceRepository(t, ctx)
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_journal_setup"}
	initial, err := store.Get(ctx, alice, "ws_alpha")
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := store.Update(ctx, alice, workspacerepository.UpdateRequest{
		IdempotencyKey: workspaceIdempotencyKey("journal-update"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, initial), Name: "Alpha Renamed", Description: "", RetentionPolicyID: "",
	})
	if err != nil {
		t.Fatal(err)
	}
	withBob, err := store.AddMember(ctx, alice, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("journal-add-bob"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, renamed), PrincipalID: "usr_bob", Role: workspace.RoleMember,
	})
	if err != nil {
		t.Fatal(err)
	}
	// carol: workspace auditor membership (policy leg 2).
	if _, err := store.AddMember(ctx, alice, workspacerepository.AddMemberRequest{
		IdempotencyKey: workspaceIdempotencyKey("journal-add-carol"), WorkspaceID: "ws_alpha",
		ExpectedConfigurationHash: mustWorkspaceHash(t, withBob), PrincipalID: "usr_carol", Role: workspace.RoleAuditor,
	}); err != nil {
		t.Fatal(err)
	}

	// The workspace owner is not an auditor: the journal gate must refuse even
	// the tenant's own owner with the same closed code as a stranger.
	if _, ownerErr := store.AuditJournal(ctx, alice, "ws_alpha"); workspacerepository.CodeOf(ownerErr) != workspacerepository.CodeNotFound {
		t.Fatalf("owner journal code=%q err=%v", workspacerepository.CodeOf(ownerErr), ownerErr)
	}

	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_carol"}
	journal, err := store.AuditJournal(ctx, carol, "ws_alpha")
	if err != nil {
		t.Fatalf("auditor journal: %v", err)
	}
	if journal.WorkspaceID != "ws_alpha" {
		t.Fatalf("journal workspace id=%q", journal.WorkspaceID)
	}
	if journal.HeadSequence < 2 || journal.HeadHash == "" {
		t.Fatalf("chain head missing: seq=%d hash=%q", journal.HeadSequence, journal.HeadHash)
	}
	hasUpdate, hasMemberAdded := false, false
	for _, entry := range journal.Events {
		switch entry.Action {
		case audit.ActionWorkspaceUpdated:
			hasUpdate = true
		case audit.ActionWorkspaceMemberAdded:
			hasMemberAdded = true
		}
		if entry.EventHash == "" || entry.PreviousEventHash == "" || entry.OccurredAt.IsZero() {
			t.Fatalf("event missing chain fields: %#v", entry)
		}
	}
	if !hasUpdate || !hasMemberAdded {
		t.Fatalf("journal missing workspace events: update=%v member_added=%v events=%d", hasUpdate, hasMemberAdded, len(journal.Events))
	}

	// The plain member is refused with the same closed code, and the refusal
	// itself is recorded as an audit.viewed DENIED event visible to auditors.
	bob := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_bob", RequestID: "req_journal_bob"}
	if _, bobErr := store.AuditJournal(ctx, bob, "ws_alpha"); workspacerepository.CodeOf(bobErr) != workspacerepository.CodeNotFound {
		t.Fatalf("member journal code=%q err=%v", workspacerepository.CodeOf(bobErr), bobErr)
	}
	carolAgain := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_carol_2"}
	afterRefusal, err := store.AuditJournal(ctx, carolAgain, "ws_alpha")
	if err != nil {
		t.Fatalf("auditor journal after refusal: %v", err)
	}
	deniedViewed := false
	for _, entry := range afterRefusal.Events {
		if entry.Action == audit.ActionAuditViewed && entry.Outcome == audit.OutcomeDenied &&
			entry.ActorPrincipalID != nil && *entry.ActorPrincipalID == "usr_bob" {
			deniedViewed = true
			if len(entry.Metadata.ReasonCodes) == 0 {
				t.Fatalf("denied audit.viewed carries no reason codes: %#v", entry)
			}
		}
	}
	if !deniedViewed {
		t.Fatalf("refused journal read was not recorded as a denied audit.viewed event")
	}

	// The organization security auditor reads the same journal without any
	// workspace membership (policy leg 1).
	dave := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_dave", RequestID: "req_journal_dave"}
	daveJournal, err := store.AuditJournal(ctx, dave, "ws_alpha")
	if err != nil {
		t.Fatalf("security auditor journal: %v", err)
	}
	if len(daveJournal.Events) == 0 {
		t.Fatalf("security auditor saw an empty journal")
	}
	if daveJournal.Truncated {
		t.Fatalf("short stream reported truncation: %#v", daveJournal)
	}
	// The journal gate is the audit.read_metadata policy, not snapshot
	// visibility: the same auditor holds no membership, so the workspace
	// snapshot itself stays invisible to them while the journal does not.
	if _, snapshotErr := store.Get(ctx, dave, "ws_alpha"); workspacerepository.CodeOf(snapshotErr) != workspacerepository.CodeNotFound {
		t.Fatalf("security auditor saw the workspace snapshot: %v", snapshotErr)
	}

	// A tenant principal with neither an audit role nor membership is refused
	// by the policy leg, and the refusal is recorded workspace-scoped because
	// the workspace row itself is tenant-visible.
	fred := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_fred", RequestID: "req_journal_fred"}
	if _, fredErr := store.AuditJournal(ctx, fred, "ws_alpha"); workspacerepository.CodeOf(fredErr) != workspacerepository.CodeNotFound {
		t.Fatalf("plain principal journal code=%q err=%v", workspacerepository.CodeOf(fredErr), fredErr)
	}
	carolAfterFred := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_carol_3"}
	afterFred, err := store.AuditJournal(ctx, carolAfterFred, "ws_alpha")
	if err != nil {
		t.Fatalf("auditor journal after plain-principal refusal: %v", err)
	}
	fredDeniedSeen := false
	for _, entry := range afterFred.Events {
		if entry.Action == audit.ActionAuditViewed && entry.Outcome == audit.OutcomeDenied &&
			entry.ActorPrincipalID != nil && *entry.ActorPrincipalID == "usr_fred" {
			fredDeniedSeen = true
			if len(entry.Metadata.ReasonCodes) == 0 {
				t.Fatalf("plain principal audit.viewed carries no reason codes: %#v", entry)
			}
		}
	}
	if !fredDeniedSeen {
		t.Fatalf("plain principal refusal was not recorded as a denied audit.viewed event")
	}

	// A cross-tenant principal receives the identical closed code, and the
	// refusal is audited in their own organization, never in the target's.
	eve := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_eve", RequestID: "req_journal_eve"}
	if _, eveErr := store.AuditJournal(ctx, eve, "ws_alpha"); workspacerepository.CodeOf(eveErr) != workspacerepository.CodeNotFound {
		t.Fatalf("foreign journal code=%q err=%v", workspacerepository.CodeOf(eveErr), eveErr)
	}
	var alphaViewedByEve int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id='org_alpha' AND action='audit.viewed' AND actor_principal_id='usr_eve'`).Scan(&alphaViewedByEve); err != nil {
		t.Fatal(err)
	}
	if alphaViewedByEve != 0 {
		t.Fatalf("cross-tenant refusal leaked into the target organization audit chain: %d", alphaViewedByEve)
	}

	// Database-boundary negative: under the runtime role with the beta tenant
	// context, direct SQL sees none of alpha's events even with an explicit
	// workspace filter — RLS, not the repository, is the last line.
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContext(t, ctx, tx, "org_beta")
	var betaLeak int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE workspace_id = 'ws_alpha'`).Scan(&betaLeak); err != nil {
		t.Fatal(err)
	}
	if betaLeak != 0 {
		t.Fatalf("beta tenant saw %d alpha audit rows through direct SQL", betaLeak)
	}
	// The app role has no UPDATE/DELETE on audit_event (append-only at the
	// privilege boundary), which keeps a journal denial tamper-proof.
	var hasUpdatePrivilege bool
	if err := admin.QueryRow(ctx, `SELECT has_table_privilege('knowvault_app', 'public.audit_event', 'UPDATE')`).Scan(&hasUpdatePrivilege); err != nil {
		t.Fatal(err)
	}
	if hasUpdatePrivilege {
		t.Fatalf("runtime role has UPDATE on audit_event")
	}
}

// TestAuditJournalRefusalIsContentFree proves a refused journal read never
// echoes the presented workspace id or any internal error text through the
// repository error contract.
func TestAuditJournalRefusalIsContentFree(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	store := newWorkspaceSourceRepository(t, ctx)
	alice := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_journal_refusal"}
	_, err := store.AuditJournal(ctx, alice, "ws_alpha")
	if err == nil {
		t.Fatal("owner journal read unexpectedly succeeded")
	}
	if strings.Contains(err.Error(), "ws_alpha") || strings.Contains(err.Error(), "sql") {
		t.Fatalf("refusal error leaks context: %v", err)
	}
	if workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("refusal code=%q", workspacerepository.CodeOf(err))
	}
}
