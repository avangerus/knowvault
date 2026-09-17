package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// appendJournalAuditEvents seeds real audit_event rows through the same
// canonical builder the runtime uses, continuing the organization chain head
// the database trigger maintains. It returns the generated event ids in
// insertion order so a pagination test can prove losslessness without reading
// the table directly.
func appendJournalAuditEvents(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, principalID, label string, count int) []string {
	t.Helper()
	var headSequence int64
	var headHash string
	if err := admin.QueryRow(ctx, `
		SELECT COALESCE((SELECT last_sequence FROM public.audit_chain_head WHERE organization_id = $1), 0),
		       COALESCE((SELECT last_event_hash FROM public.audit_chain_head WHERE organization_id = $1),
		                'sha256:' || repeat('0', 64))
	`, organizationID).Scan(&headSequence, &headHash); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, 0, count)
	for index := 0; index < count; index++ {
		event, err := audit.Build(organizationID, audit.EventInput{
			EventID:          fmt.Sprintf("aud_%s_%05d", label, index),
			WorkspaceID:      &workspaceID,
			ActorType:        audit.ActorHuman,
			ActorPrincipalID: &principalID,
			Action:           audit.ActionWorkspaceUpdated,
			ResourceType:     audit.ResourceWorkspace,
			ResourceID:       workspaceID,
			RequestID:        fmt.Sprintf("req_%s_%05d", label, index),
			Outcome:          audit.OutcomeSuccess,
			OccurredAt:       time.Now().UTC(),
		}, headSequence, headHash)
		if err != nil {
			t.Fatalf("build audit event: %v", err)
		}
		if _, err := admin.Exec(ctx, `
			INSERT INTO public.audit_event (
				id, organization_id, sequence, workspace_id, actor_type, actor_principal_id,
				action, resource_type, resource_id, request_id, outcome,
				canonical_bytes, previous_event_hash, event_hash, occurred_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		`, event.EventID, event.OrganizationID, event.Sequence, event.WorkspaceID, string(event.ActorType),
			event.ActorPrincipalID, string(event.Action), string(event.ResourceType), event.ResourceID,
			event.RequestID, string(event.Outcome), event.CanonicalBytes, event.PreviousEventHash,
			event.EventHash, event.OccurredAt); err != nil {
			t.Fatalf("insert audit event: %v", err)
		}
		headSequence, headHash = event.Sequence, event.EventHash
		ids = append(ids, event.EventID)
	}
	return ids
}

// seedJournalSecondWorkspace creates a second ACTIVE workspace in the same
// organization with its declared owner membership in one transaction, so the
// deferred owner invariant holds and a workspace-scoped journal read can be
// proved not to leak the sibling workspace's stream.
func seedJournalSecondWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, ownerID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id)
		VALUES ($1,$2,$1,'ACTIVE',$3)`, workspaceID, organizationID, ownerID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1,$2,$3,$4,'OWNER',1,$4)`, "wsm_"+workspaceID, organizationID, workspaceID, ownerID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func seedJournalAuditor(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, workspaceID, principalID string) {
	t.Helper()
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1,$2,'USER',$1,'ACTIVE')`, principalID, organizationID); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1,$2,$3,$4,'AUDITOR',1,'usr_alice')`, "wsm_"+workspaceID+"_"+principalID, organizationID, workspaceID, principalID); err != nil {
		t.Fatal(err)
	}
}

// TestAuditJournalBeforeSequencePaginatesRealPostgres proves N1 keyset
// pagination on real PostgreSQL: more than two pages of workspace-scoped
// events are reachable through before_sequence with no loss and no duplicate,
// new events inserted between reads do not shift or duplicate older pages, the
// final empty tail carries no cursor, a sibling workspace's stream never
// leaks, and the chain head stays organization-scoped.
func TestAuditJournalBeforeSequencePaginatesRealPostgres(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedJournalAuditor(t, ctx, admin, "org_alpha", "ws_alpha", "usr_carol")
	seedJournalSecondWorkspace(t, ctx, admin, "org_alpha", "ws_alpha_two", "usr_alice")

	seeded := appendJournalAuditEvents(t, ctx, admin, "org_alpha", "ws_alpha", "usr_alice", "alpha", 205)
	sibling := appendJournalAuditEvents(t, ctx, admin, "org_alpha", "ws_alpha_two", "usr_alice", "two", 7)
	if len(seeded) != 205 {
		t.Fatalf("seeded %d events", len(seeded))
	}

	store := newWorkspaceSourceRepository(t, ctx)
	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_page_1"}

	first, err := store.AuditJournal(ctx, carol, "ws_alpha")
	if err != nil {
		t.Fatalf("first page: %v", err)
	}
	if len(first.Events) != 100 || !first.Truncated || first.NextBeforeSequence == nil {
		t.Fatalf("first page shape: events=%d truncated=%v cursor=%v", len(first.Events), first.Truncated, first.NextBeforeSequence)
	}
	if first.HeadSequence < 205 || first.HeadHash == "" {
		t.Fatalf("organization chain head missing: seq=%d hash=%q", first.HeadSequence, first.HeadHash)
	}

	// New events arrive between reads. They are newer than the page-one
	// cursor, so the continuation must still return exactly the older stream
	// without duplicates and without skipping the seeded events.
	interlopers := appendJournalAuditEvents(t, ctx, admin, "org_alpha", "ws_alpha", "usr_alice", "interloper", 3)

	seen := map[string]int{}
	for _, entry := range first.Events {
		seen[entry.EventID]++
	}
	cursor := *first.NextBeforeSequence
	var pages [][]audit.JournalEntry
	pages = append(pages, first.Events)
	for page := 2; page <= 3; page++ {
		next, pageErr := store.AuditJournalBefore(ctx, carol, "ws_alpha", cursor)
		if pageErr != nil {
			t.Fatalf("page %d: %v", page, pageErr)
		}
		for _, entry := range next.Events {
			seen[entry.EventID]++
		}
		pages = append(pages, next.Events)
		if page == 3 {
			if next.Truncated || next.NextBeforeSequence != nil {
				t.Fatalf("final page must end the stream: truncated=%v cursor=%v", next.Truncated, next.NextBeforeSequence)
			}
			break
		}
		if !next.Truncated || next.NextBeforeSequence == nil {
			t.Fatalf("page %d should continue: events=%d truncated=%v cursor=%v", page, len(next.Events), next.Truncated, next.NextBeforeSequence)
		}
		cursor = *next.NextBeforeSequence
	}

	for _, id := range seeded {
		if seen[id] != 1 {
			t.Fatalf("seeded event %s returned %d times, want exactly 1", id, seen[id])
		}
	}
	for _, id := range sibling {
		if seen[id] != 0 {
			t.Fatalf("sibling workspace event %s leaked into ws_alpha: %d", id, seen[id])
		}
	}
	for _, id := range interlopers {
		if seen[id] != 0 {
			t.Fatalf("event inserted between reads appeared in an older page: %s", id)
		}
	}
	for index, page := range pages {
		for position := 1; position < len(page); position++ {
			if page[position-1].Sequence <= page[position].Sequence {
				t.Fatalf("page %d not sequence DESC at %d: %d <= %d", index+1, position, page[position-1].Sequence, page[position].Sequence)
			}
		}
	}

	// A cursor older than the oldest event is an empty tail with no cursor.
	tail, err := store.AuditJournalBefore(ctx, carol, "ws_alpha", 1)
	if err != nil {
		t.Fatalf("empty tail: %v", err)
	}
	if len(tail.Events) != 0 || tail.Truncated || tail.NextBeforeSequence != nil {
		t.Fatalf("empty tail shape: events=%d truncated=%v cursor=%v", len(tail.Events), tail.Truncated, tail.NextBeforeSequence)
	}
	if tail.HeadSequence < 205 {
		t.Fatalf("empty tail lost the organization head: %d", tail.HeadSequence)
	}
}

// TestAuditJournalBeforeSequenceAuthorizationRegressions proves the
// continuation read repeats the per-page gate: a revoked workspace auditor,
// a foreign tenant and a missing capability all fail closed, while a failed
// audit append forbids the page instead of returning it unlogged.
func TestAuditJournalBeforeSequenceAuthorizationRegressions(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_eve", "ws_beta")
	seedJournalAuditor(t, ctx, admin, "org_alpha", "ws_alpha", "usr_carol")
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_dave','org_alpha','USER','Dave','ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_dave','org_alpha','usr_dave','SECURITY_AUDITOR',1,'usr_alice')`); err != nil {
		t.Fatal(err)
	}
	appendJournalAuditEvents(t, ctx, admin, "org_alpha", "ws_alpha", "usr_alice", "auth", 120)

	store := newWorkspaceSourceRepository(t, ctx)
	carol := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_auth_1"}

	first, err := store.AuditJournal(ctx, carol, "ws_alpha")
	if err != nil || first.NextBeforeSequence == nil {
		t.Fatalf("first authorized page: events=%d cursor=%v err=%v", len(first.Events), first.NextBeforeSequence, err)
	}
	cursor := *first.NextBeforeSequence

	// Revocation between pages closes the membership at the current revision
	// (the schema requires valid_to_revision and removed_at to move together).
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member
		SET removed_at = transaction_timestamp(), valid_to_revision = 2
		WHERE organization_id = 'org_alpha' AND workspace_id = 'ws_alpha' AND principal_id = 'usr_carol'
	`); err != nil {
		t.Fatalf("revoke auditor membership: %v", err)
	}
	revoked := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_carol", RequestID: "req_journal_auth_2"}
	if _, err := store.AuditJournalBefore(ctx, revoked, "ws_alpha", cursor); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("revoked continuation code=%q err=%v", workspacerepository.CodeOf(err), err)
	}

	// A foreign tenant receives the same closed code for a continuation.
	eve := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_eve", RequestID: "req_journal_auth_3"}
	if _, err := store.AuditJournalBefore(ctx, eve, "ws_alpha", cursor); workspacerepository.CodeOf(err) != workspacerepository.CodeNotFound {
		t.Fatalf("foreign continuation code=%q err=%v", workspacerepository.CodeOf(err), err)
	}

	// A non-positive cursor is a request error, not a silent first page.
	dave := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_dave", RequestID: "req_journal_auth_4"}
	if _, err := store.AuditJournalBefore(ctx, dave, "ws_alpha", 0); workspacerepository.CodeOf(err) != workspacerepository.CodeRequestInvalid {
		t.Fatalf("zero cursor code=%q err=%v", workspacerepository.CodeOf(err), err)
	}

	// A failed audit append must forbid the page: with INSERT revoked from the
	// runtime role, the authorized continuation fails content-free as
	// CodePersistence and returns no journal.
	if _, err := admin.Exec(ctx, `REVOKE INSERT ON TABLE public.audit_event FROM knowvault_app`); err != nil {
		t.Fatalf("revoke append privilege: %v", err)
	}
	restore := func() {
		if _, err := admin.Exec(ctx, `GRANT INSERT ON TABLE public.audit_event TO knowvault_app`); err != nil {
			t.Fatalf("restore append privilege: %v", err)
		}
	}
	defer restore()
	failed, err := store.AuditJournalBefore(ctx, dave, "ws_alpha", cursor)
	if workspacerepository.CodeOf(err) != workspacerepository.CodePersistence {
		t.Fatalf("append failure code=%q err=%v", workspacerepository.CodeOf(err), err)
	}
	if len(failed.Events) != 0 || failed.NextBeforeSequence != nil {
		t.Fatalf("append failure returned a journal: events=%d cursor=%v", len(failed.Events), failed.NextBeforeSequence)
	}
	if strings.Contains(err.Error(), "ws_alpha") || strings.Contains(err.Error(), "sql") {
		t.Fatalf("append failure leaked context: %v", err)
	}
	restore()
	daveAfter := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_dave", RequestID: "req_journal_auth_5"}
	if _, err := store.AuditJournalBefore(ctx, daveAfter, "ws_alpha", cursor); err != nil {
		t.Fatalf("authorized continuation after privilege restore: %v", err)
	}
}
