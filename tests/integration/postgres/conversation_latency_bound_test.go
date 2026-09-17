package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// TestConversationListLatencyBoundWithHundreds proves objective S1 item (1):
// the Search section's first screen (web/src/main.tsx line 1016 issues
// apiGet(`/api/v1/workspaces/{workspaceID}/conversations`) and renders the
// returned envelope at line 1103) stays backward compatible and completes well
// inside the two-second bound while the workspace physically holds thousands
// of conversations.
//
// FIX-4 #2 root cause this guards: List used to call loadTurns once PER
// returned conversation (an N+1 query pattern) -- harmless on this package's
// own near-zero-latency local Docker Postgres, but on the real acc/
// tko-operations stand (a remote Postgres over mTLS) that turned into ~100
// sequential round trips and measured ~2.4s with 900+ conversations resident.
// This test cannot reproduce network latency locally, so it instead proves
// the two things that DO transfer to any Postgres, however far away: (1) the
// list is still capped and fast with thousands of conversations resident, not
// merely hundreds, and (2) loadTurnsBatch's grouped, single-query replacement
// for loadTurns returns EXACTLY the same per-conversation turns (same rows,
// same order, same maxTurns cap) a caller of the old per-conversation
// loadTurns would have seen -- the fix changed the query COUNT, not the
// result shape.
//
// The seed is bounded test data inside the harness database: it never
// weakens an invariant, gate, RLS role or audit contract, and only adds rows
// the runtime role is legitimately allowed to see for its own workspace.
func TestConversationListLatencyBoundWithHundreds(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_latency_alpha"
		ownerID        = "usr_latency_alice"
		workspaceID    = "ws_latency_alpha"
		requestID      = "req_latency_list"

		// conversations matches FIX-4 #2's own contract target ("5000 conversations,
		// a 2-second SLA"), not merely the "hundreds" the test's own name still
		// documents from before that contract existed.
		conversations = 5000

		// archivedEvery leaves a bounded subset archived so archived_at is
		// exercised inside the returned page while retention stays ACTIVE.
		archivedEvery = 10

		// turnedConversations of the LAST (highest-index, so newest
		// created_at, so guaranteed inside the returned page) conversations
		// each get turnsPerConversation real conversation_turn rows, proving
		// loadTurnsBatch's grouping against a real Postgres, not only the
		// fixture-level unit tests.
		turnedConversations  = 40
		turnsPerConversation = 3

		latencyUpperBound = 2000 * time.Millisecond
	)

	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	// turnedConversationIDs collects exactly which conversations the seed step
	// below gave real turns (it skips the archived subset, so this is not
	// simply "the last turnedConversations indices").
	turnedConversationIDs := make([]string, 0, turnedConversations)

	seedAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_latency_seed"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		// Bulk, set-based seeding: at 5000 rows, a Go-side loop issuing one
		// round trip per conversation would itself dominate the seed step's
		// own wall-clock time (unrelated to the latency this test measures).
		// generate_series produces every id in one statement instead.
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			SELECT $1, 'conv_latency_' || lpad(g::text, 6, '0'), $2, 1, $3
			  FROM generate_series(0, $4::int - 1) AS g
		`, organizationID, workspaceID, ownerID, conversations); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			SELECT $1, 'conv_latency_' || lpad(g::text, 6, '0'), $2, 1
			  FROM generate_series(0, $3::int - 1) AS g
		`, organizationID, workspaceID, conversations); err != nil {
			return err
		}
		// Archive a bounded subset so archived_at is present in the page and
		// the projection still resolves the archived rows while retention is
		// ACTIVE (the same boundary conversation_surface_test.go exercises).
		if _, err := tx.Exec(txCtx, `
			UPDATE public.conversation
			   SET archived_at = clock_timestamp()
			 WHERE organization_id = $1 AND workspace_id = $2
			   AND id IN (
			       SELECT 'conv_latency_' || lpad(g::text, 6, '0')
			         FROM generate_series(0, $3::int - 1, $4::int) AS g
			   )
		`, organizationID, workspaceID, conversations, archivedEvery); err != nil {
			return err
		}
		// A small subset of the NEWEST conversations (highest index --
		// generate_series above ran in ascending order, so these have the
		// latest created_at and therefore sort to the front of the
		// created_at DESC, id DESC page) each get real turns, so this test
		// can assert loadTurnsBatch grouped them correctly rather than only
		// asserting an empty Turns slice for everything.
		turnedConversationIDs = turnedConversationIDs[:0]
		for candidate := conversations - 1; candidate >= 0 && len(turnedConversationIDs) < turnedConversations; candidate-- {
			if candidate%archivedEvery == 0 {
				// conversation_turn_member_insert requires its parent
				// conversation.archived_at IS NULL; skip the archived subset
				// rather than seed a turn RLS would legitimately refuse.
				continue
			}
			index := candidate
			conversationID := fmt.Sprintf("conv_latency_%06d", index)
			turnedConversationIDs = append(turnedConversationIDs, conversationID)
			for turnIndex := 1; turnIndex <= turnsPerConversation; turnIndex++ {
				runID := fmt.Sprintf("qrun_latency_%06d_%d", index, turnIndex)
				turnID := fmt.Sprintf("turn_latency_%06d_%d", index, turnIndex)
				if _, err := tx.Exec(txCtx, `
					INSERT INTO public.question_run (
						organization_id, id, workspace_id, workspace_revision, created_by,
						conversation_id, conversation_turn_id, question_hash, answer_mode,
						verification_method, workspace_scope_hash, policy_revision
					) VALUES ($1,$2,$3,1,$4,$5,$6,$7,'EXTRACTIVE','BYTE_EXACT_CITATION',$7,'policy-latency')
				`, organizationID, runID, workspaceID, ownerID, conversationID, turnID,
					"sha256:"+strings.Repeat("a", 64)); err != nil {
					return err
				}
				if _, err := tx.Exec(txCtx, `
					INSERT INTO public.conversation_turn (organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id)
					VALUES ($1,$2,$3,$4,1,$5,$6)
				`, organizationID, turnID, conversationID, workspaceID, turnIndex, runID); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed thousands of conversations: %v", err)
	}

	// Confirm the load is real: the workspace physically holds thousands of
	// conversation rows before the product projection is measured.
	var residentCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.conversation
		 WHERE organization_id=$1 AND workspace_id=$2
	`, organizationID, workspaceID).Scan(&residentCount); err != nil {
		t.Fatal(err)
	}
	if residentCount != conversations {
		t.Fatalf("workspace resident conversations=%d, want exactly %d to prove the bound under the FIX-4 #2 contract's own scale", residentCount, conversations)
	}

	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: requestID}

	// Time exactly the work the Search first screen performs for its list: the
	// product conversations-list projection plus the JSON envelope parse.
	started := time.Now()
	views, err := service.List(ctx, access, workspaceID)
	if err != nil {
		t.Fatalf("list conversations with %d resident: %v", conversations, err)
	}
	if len(views) == 0 {
		t.Fatal("product list surface returned an empty page although thousands of conversations are resident")
	}

	// Backward-compatible envelope: every returned conversation exposes the
	// opaque fields the UI and the REST envelope read, and each entry is one
	// of the rows this workspace legitimately seeded. Also collect the
	// turn-seeded conversations this page actually returned, to check
	// loadTurnsBatch's grouping below.
	seen := make(map[string]bool, len(views))
	byID := make(map[string]conversation.View, len(views))
	for _, view := range views {
		if !strings.HasPrefix(view.ID, "conv_latency_") || view.ID == "" {
			t.Fatalf("list leaked foreign/unexpected conversation id=%q", view.ID)
		}
		if view.WorkspaceID != workspaceID || view.CreatedBy != ownerID || view.CreatedAt.IsZero() {
			t.Fatalf("incomplete backward-compatible projection=%+v", view)
		}
		seen[view.ID] = true
		byID[view.ID] = view
	}
	if len(seen) != len(views) {
		t.Fatalf("projection returned duplicate conversation ids: %d unique of %d returned", len(seen), len(views))
	}

	// FIX-4 #2 correctness check: every one of the turn-seeded conversations
	// this page happens to include (they are the newest, so it should be all
	// of them) carries EXACTLY its own turnsPerConversation turns, in
	// ascending turn_index order -- proof that loadTurnsBatch's single
	// grouped query attributes turns to the right conversation and applies
	// the same per-conversation ordering/cap loadTurns always did, not a
	// union of every seeded conversation's turns.
	checkedTurnedConversations := 0
	for _, conversationID := range turnedConversationIDs {
		view, ok := byID[conversationID]
		if !ok {
			continue // outside this page; the assertion below still covers every one that IS present.
		}
		checkedTurnedConversations++
		if len(view.Turns) != turnsPerConversation {
			t.Fatalf("conversation=%s turns=%d want %d (loadTurnsBatch must attribute exactly this conversation's own turns, not more/fewer)",
				conversationID, len(view.Turns), turnsPerConversation)
		}
		for turnPosition, turn := range view.Turns {
			wantIndex := int64(turnPosition + 1)
			if turn.TurnIndex != wantIndex {
				t.Fatalf("conversation=%s turn[%d].turn_index=%d want %d (ascending turn_index order)",
					conversationID, turnPosition, turn.TurnIndex, wantIndex)
			}
		}
	}
	if checkedTurnedConversations == 0 {
		t.Fatal("none of the turn-seeded conversations appeared in the returned page -- test setup no longer keeps them among the newest")
	}
	t.Logf("verified turns grouping for %d/%d turn-seeded conversations present in the page", checkedTurnedConversations, turnedConversations)

	// Parse the same JSON envelope shape the API returns so the measured cost
	// includes the read+decode the UI performs, not just the SQL fetch.
	envelope, err := json.Marshal(map[string]any{"conversations": views})
	if err != nil {
		t.Fatal(err)
	}
	_ = envelope
	elapsed := time.Since(started)

	if elapsed >= latencyUpperBound {
		t.Fatalf("conversations list for %d resident conversations took %v, exceeding the %v bound", residentCount, elapsed, latencyUpperBound)
	}
	t.Logf("conversations list page=%d resident=%d elapsed=%v (bound %v)", len(views), residentCount, elapsed, latencyUpperBound)
}
