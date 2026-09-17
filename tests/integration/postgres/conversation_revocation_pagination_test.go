package postgres_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// TestConversationRevokedMembershipContinuationStaysContentFree is the R1
// regression against real PostgreSQL: an issued nonempty cursor must not turn
// into CONVERSATION_REQUEST_INVALID (400) merely because the caller's workspace
// membership was revoked between pages. The same fixture also proves ordinary
// authorized pagination, a foreign-tenant cursor in a workspace that is still
// visible (stays invalid), and a cursor aimed at a workspace the caller cannot
// see (content-free denial, never a 400).
func TestConversationRevokedMembershipContinuationStaysContentFree(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_revoke_alpha", "usr_revoke_owner", "ws_revoke_alpha")
	seedOrganization(t, ctx, admin, "org_revoke_beta", "usr_revoke_bob", "ws_revoke_beta")
	// A distinct non-owner member whose own membership is the one revoked. The
	// declared owner stays active because the tenancy trigger requires it.
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_revoke_member','org_revoke_alpha','USER','usr_revoke_member','ACTIVE')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ('wsm_ws_revoke_alpha_member','org_revoke_alpha','ws_revoke_alpha','usr_revoke_member','MEMBER',1,'usr_revoke_owner')`); err != nil {
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

	ownerAccess := database.AccessContext{OrganizationID: "org_revoke_alpha", PrincipalID: "usr_revoke_owner", RequestID: "req_revoke_owner"}
	memberAccess := database.AccessContext{OrganizationID: "org_revoke_alpha", PrincipalID: "usr_revoke_member", RequestID: "req_revoke_member"}
	foreignAccess := database.AccessContext{OrganizationID: "org_revoke_beta", PrincipalID: "usr_revoke_bob", RequestID: "req_revoke_foreign"}

	// 120 conversations share one created_at so the keyset pages fall back to
	// id DESC deterministically.
	baseTime := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	const total = 120
	if err := appStore.Write(ctx, ownerAccess, func(txCtx context.Context, tx database.Transaction) error {
		for index := 0; index < total; index++ {
			id := fmt.Sprintf("conv_revoke_%03d", index)
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by,created_at)
				VALUES ($1,$2,'ws_revoke_alpha',1,'usr_revoke_owner',$3)
			`, "org_revoke_alpha", id, baseTime); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
				VALUES ($1,$2,'ws_revoke_alpha',1)
			`, "org_revoke_alpha", id); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Ordinary authorized pagination is unchanged: the first page and its
	// server cursor, then a continuation with no row lost or duplicated.
	ownerPage1, err := service.ListPage(ctx, ownerAccess, "ws_revoke_alpha", 50, "")
	if err != nil {
		t.Fatalf("owner page1: %v", err)
	}
	if len(ownerPage1.Conversations) != 50 || ownerPage1.NextCursor != "conv_revoke_070" {
		t.Fatalf("owner page1 len=%d cursor=%q, want 50/conv_revoke_070", len(ownerPage1.Conversations), ownerPage1.NextCursor)
	}
	ownerPage2, err := service.ListPage(ctx, ownerAccess, "ws_revoke_alpha", 50, ownerPage1.NextCursor)
	if err != nil {
		t.Fatalf("owner page2: %v", err)
	}
	if len(ownerPage2.Conversations) != 50 || ownerPage2.NextCursor != "conv_revoke_020" {
		t.Fatalf("owner page2 len=%d cursor=%q, want 50/conv_revoke_020", len(ownerPage2.Conversations), ownerPage2.NextCursor)
	}
	ownerPage3, err := service.ListPage(ctx, ownerAccess, "ws_revoke_alpha", 50, ownerPage2.NextCursor)
	if err != nil {
		t.Fatalf("owner page3: %v", err)
	}
	if len(ownerPage3.Conversations) != 20 || ownerPage3.NextCursor != "" {
		t.Fatalf("owner page3 len=%d cursor=%q, want 20/empty", len(ownerPage3.Conversations), ownerPage3.NextCursor)
	}

	// The member may read the same first page and receives the issued cursor.
	memberPage1, err := service.ListPage(ctx, memberAccess, "ws_revoke_alpha", 50, "")
	if err != nil {
		t.Fatalf("member page1: %v", err)
	}
	issuedCursor := memberPage1.NextCursor
	if len(memberPage1.Conversations) != 50 || issuedCursor != "conv_revoke_070" {
		t.Fatalf("member page1 len=%d cursor=%q, want 50/conv_revoke_070", len(memberPage1.Conversations), issuedCursor)
	}

	// A visible workspace's unknown/foreign cursor stays content-free invalid.
	if _, err := service.ListPage(ctx, ownerAccess, "ws_revoke_alpha", 50, "conv_revoke_foreign"); conversation.CodeOf(err) != conversation.CodeInvalid {
		t.Fatalf("unknown cursor code=%s err=%v, want CONVERSATION_REQUEST_INVALID", conversation.CodeOf(err), err)
	}
	if _, err := service.ListPage(ctx, foreignAccess, "ws_revoke_beta", 50, issuedCursor); conversation.CodeOf(err) != conversation.CodeInvalid {
		t.Fatalf("foreign-tenant cursor code=%s err=%v, want CONVERSATION_REQUEST_INVALID", conversation.CodeOf(err), err)
	}

	// The caller's membership in the workspace is revoked between pages.
	if _, err := admin.Exec(ctx, `
		UPDATE public.workspace_member
		   SET removed_at = transaction_timestamp(), valid_to_revision = 2
		 WHERE organization_id = 'org_revoke_alpha' AND workspace_id = 'ws_revoke_alpha' AND principal_id = 'usr_revoke_member'
	`); err != nil {
		t.Fatal(err)
	}

	// R1: the previously issued cursor must not become REQUEST_INVALID merely
	// because the membership was revoked. It collapses to the same content-free
	// denial every other conversation read uses.
	_, err = service.ListPage(ctx, memberAccess, "ws_revoke_alpha", 50, issuedCursor)
	code := conversation.CodeOf(err)
	if code != conversation.CodeDenied && code != conversation.CodeNotFound {
		t.Fatalf("revoked issued cursor code=%s err=%v, want CONVERSATION_DENIED or CONVERSATION_NOT_FOUND", code, err)
	}

	// A cursor aimed at a workspace this caller cannot see is a content-free
	// denial too, never a 400 that would misread as a malformed cursor.
	_, err = service.ListPage(ctx, ownerAccess, "ws_revoke_beta", 50, issuedCursor)
	invisibleCode := conversation.CodeOf(err)
	if invisibleCode != conversation.CodeDenied && invisibleCode != conversation.CodeNotFound {
		t.Fatalf("invisible workspace cursor code=%s err=%v, want content-free denial", invisibleCode, err)
	}

	// The owner keeps paging the same workspace after the member's revocation.
	ownerStill, err := service.ListPage(ctx, ownerAccess, "ws_revoke_alpha", 50, "conv_revoke_070")
	if err != nil || len(ownerStill.Conversations) != 50 {
		t.Fatalf("owner continuation len=%d err=%v, want 50 rows", len(ownerStill.Conversations), err)
	}
}
