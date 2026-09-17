package postgres_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// TestConversationListPageKeysetPagination proves the bounded keyset read path
// against real PostgreSQL: more than 150 conversations, equal created_at with
// different ids, a topic inserted between pages, an archived cursor, the last
// page, an empty workspace, a foreign tenant/workspace and a revoked
// membership. No row is lost or duplicated and the cursor is the id of the
// last returned conversation only when a continuation exists.
func TestConversationListPageKeysetPagination(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_page_alpha", "usr_page_alice", "ws_page_alpha")
	seedOrganization(t, ctx, admin, "org_page_beta", "usr_page_bob", "ws_page_beta")
	// A distinct non-owner member proves revocation through its own
	// membership. The declared owner row must stay active because the tenancy
	// trigger rejects a workspace whose declared owner membership is gone.
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_page_member','org_page_alpha','USER','usr_page_member','ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wsm_ws_page_alpha_member','org_page_alpha','ws_page_alpha','usr_page_member','MEMBER',1,'usr_page_alice')`); err != nil {
		t.Fatal(err)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	access := database.AccessContext{OrganizationID: "org_page_alpha", PrincipalID: "usr_page_alice", RequestID: "req_page_read"}
	memberAccess := database.AccessContext{OrganizationID: "org_page_alpha", PrincipalID: "usr_page_member", RequestID: "req_page_member"}
	foreignAccess := database.AccessContext{OrganizationID: "org_page_beta", PrincipalID: "usr_page_bob", RequestID: "req_page_foreign"}

	// All rows share one created_at so ordering must fall back to id DESC and
	// the keyset predicate (created_at, id) < (cursor.created_at, cursor.id)
	// has to page deterministically by id alone.
	baseTime := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	const total = 160
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		for index := 0; index < total; index++ {
			id := fmt.Sprintf("conv_page_%03d", index)
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by,created_at)
				VALUES ($1,$2,'ws_page_alpha',1,'usr_page_alice',$3)
			`, "org_page_alpha", id, baseTime); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
				VALUES ($1,$2,'ws_page_alpha',1)
			`, "org_page_alpha", id); err != nil {
				return err
			}
		}
		// One real turn on the newest conversation proves turns are projected
		// for the returned page through the existing batched loader.
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id, question_hash, answer_mode,
				verification_method, workspace_scope_hash, policy_revision
			) VALUES ($1,'qrun_page_159','ws_page_alpha',1,'usr_page_alice','conv_page_159','turn_page_159',$2,'EXTRACTIVE','BYTE_EXACT_CITATION',$2,'policy-page')
		`, "org_page_alpha", "sha256:"+strings.Repeat("a", 64)); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id)
			VALUES ($1,'turn_page_159','conv_page_159','ws_page_alpha',1,1,'qrun_page_159')
		`, "org_page_alpha"); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	seen := map[string]int{}
	collect := func(page conversation.Page) {
		for _, view := range page.Conversations {
			seen[view.ID]++
		}
	}

	page1, err := service.ListPage(ctx, access, "ws_page_alpha", 50, "")
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1.Conversations) != 50 || page1.NextCursor != "conv_page_110" {
		t.Fatalf("page1 len=%d cursor=%q, want 50/conv_page_110", len(page1.Conversations), page1.NextCursor)
	}
	if page1.Conversations[0].ID != "conv_page_159" || len(page1.Conversations[0].Turns) != 1 {
		t.Fatalf("page1 head=%+v, want conv_page_159 with one turn", page1.Conversations[0])
	}
	collect(page1)

	// A topic inserted between reads is newer than the cursor, so it can never
	// reappear in a continuation page and can never duplicate an already-seen id.
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by,created_at)
			VALUES ('org_page_alpha','conv_page_new','ws_page_alpha',1,'usr_page_alice',$1)
		`, baseTime.Add(time.Hour)); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ('org_page_alpha','conv_page_new','ws_page_alpha',1)
		`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// The cursor of page1 is archived between reads; archived metadata stays
	// visible exactly as List's own query leaves it, so continuation still works.
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte("page-archive-key"))
	if _, err := service.Archive(ctx, access, conversation.ArchiveRequest{
		WorkspaceID: "ws_page_alpha", ConversationID: "conv_page_110", IdempotencyKey: base64.RawURLEncoding.EncodeToString(keyBytes),
	}); err != nil {
		t.Fatalf("archive cursor conversation: %v", err)
	}

	page2, err := service.ListPage(ctx, access, "ws_page_alpha", 50, "conv_page_110")
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2.Conversations) != 50 || page2.NextCursor != "conv_page_060" {
		t.Fatalf("page2 len=%d cursor=%q, want 50/conv_page_060", len(page2.Conversations), page2.NextCursor)
	}
	collect(page2)

	page3, err := service.ListPage(ctx, access, "ws_page_alpha", 50, "conv_page_060")
	if err != nil {
		t.Fatalf("page3: %v", err)
	}
	if len(page3.Conversations) != 50 || page3.NextCursor != "conv_page_010" {
		t.Fatalf("page3 len=%d cursor=%q, want 50/conv_page_010", len(page3.Conversations), page3.NextCursor)
	}
	collect(page3)

	// Last page: exactly the remaining ten rows and no cursor.
	page4, err := service.ListPage(ctx, access, "ws_page_alpha", 50, "conv_page_010")
	if err != nil {
		t.Fatalf("page4: %v", err)
	}
	if len(page4.Conversations) != 10 || page4.NextCursor != "" {
		t.Fatalf("page4 len=%d cursor=%q, want 10/empty", len(page4.Conversations), page4.NextCursor)
	}
	collect(page4)

	for index := 0; index < total; index++ {
		id := fmt.Sprintf("conv_page_%03d", index)
		if seen[id] != 1 {
			t.Fatalf("conversation %s seen %d times, want exactly once", id, seen[id])
		}
	}
	if seen["conv_page_new"] != 0 {
		t.Fatalf("a topic inserted after page1 reappeared in a continuation page")
	}

	// limit above the bound is clamped to the 50-row page, never unbounded.
	clamped, err := service.ListPage(ctx, access, "ws_page_alpha", 1000, "")
	if err != nil || len(clamped.Conversations) != 50 {
		t.Fatalf("clamped page len=%d err=%v, want 50", len(clamped.Conversations), err)
	}

	// An unknown or foreign cursor collapses to one content-free invalid error.
	if _, err := service.ListPage(ctx, access, "ws_page_alpha", 50, "conv_page_foreign"); conversation.CodeOf(err) != conversation.CodeInvalid {
		t.Fatalf("unknown cursor code=%s err=%v, want REQUEST_INVALID", conversation.CodeOf(err), err)
	}
	if _, err := service.ListPage(ctx, foreignAccess, "ws_page_beta", 50, "conv_page_110"); conversation.CodeOf(err) != conversation.CodeInvalid {
		t.Fatalf("foreign-tenant cursor code=%s err=%v, want REQUEST_INVALID", conversation.CodeOf(err), err)
	}

	// Empty workspace, another workspace of the same tenant, and a foreign
	// tenant all return an empty page rather than leaking rows.
	assertEmptyPage := func(name string, callAccess database.AccessContext, workspaceID string) {
		t.Helper()
		page, err := service.ListPage(ctx, callAccess, workspaceID, 50, "")
		if err != nil || len(page.Conversations) != 0 || page.NextCursor != "" {
			t.Fatalf("%s len=%d cursor=%q err=%v, want empty page", name, len(page.Conversations), page.NextCursor, err)
		}
	}
	assertEmptyPage("empty_workspace", access, "ws_page_empty")
	assertEmptyPage("other_workspace", access, "ws_page_beta")
	assertEmptyPage("foreign_tenant", foreignAccess, "ws_page_beta")

	// Revoked membership of a non-owner member removes the protected rows from
	// the same read path. The declared owner usr_page_alice and its OWNER
	// membership stay active; only the member's own row is revoked.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member
		   SET removed_at = transaction_timestamp(), valid_to_revision = 2
		 WHERE organization_id = 'org_page_alpha' AND workspace_id = 'ws_page_alpha' AND principal_id = 'usr_page_member'
	`); err != nil {
		t.Fatal(err)
	}
	revoked, err := service.ListPage(ctx, memberAccess, "ws_page_alpha", 50, "")
	if err != nil || len(revoked.Conversations) != 0 || revoked.NextCursor != "" {
		t.Fatalf("revoked membership len=%d cursor=%q err=%v, want empty page", len(revoked.Conversations), revoked.NextCursor, err)
	}
}
