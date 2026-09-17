package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestConversationProjectionLatencyBoundWithRealArtifacts proves FIX-5 #2's
// own contract target end to end: GET /conversations' actual bottleneck was
// never conversation.Service.List (FIX-4 #2 already batched that -- see
// conversation_latency_bound_test.go) but internal/platform/workspaceapi's
// projectConversation calling question.Service.Get once PER TURN, each its
// own transaction, to decrypt every disclosed field (question, answer,
// citations) for every turn of every returned conversation. That per-turn
// cost is invisible to a test that seeds question_run rows with raw SQL and
// no artifacts (as TestConversationListLatencyBoundWithHundreds does): a
// Get()/GetBatch() call against an artifact-free row skips every encrypted
// Fetch this test exists to exercise.
//
// It seeds the SAME 5000-conversation scale as TestConversationListLatency-
// BoundWithHundreds (List always caps its own returned page at
// maxConversations regardless of how many more conversations exist, so
// beyond that cap the workspace's total conversation count cannot move GET
// conversations' latency -- only how many turns the returned PAGE carries
// can) via bulk SQL, then adds real question.Service.Create() runs -- with
// real encrypted Question/Answer artifacts and a real citation each --
// forming 40 conversations of 3 turns apiece (matching FIX-4 #2's own turn
// scale), which is exactly the "5000 conversations, 3 turns" shape FIX-5's
// contract names. Because Create() commits with a real, later created_at
// than the bulk-seeded filler, these 40 conversations are guaranteed to be
// among the newest and therefore inside List's own returned page.
func TestConversationProjectionLatencyBoundWithRealArtifacts(t *testing.T) {
	ctx := context.Background()
	const (
		fillerConversations  = 5000
		realConversations    = 40
		turnsPerConversation = 3

		latencyUpperBound = 2000 * time.Millisecond
	)

	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "waste.txt"), []byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_cpl_admin", "confirmation_cpl_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "conversation-projection-latency")

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_cpl_seed"}

	// Bulk filler: proves the 5000-conversation-in-the-workspace scale
	// without paying per-row artifact cost for rows the returned page can
	// never include anyway (List's own query is capped independent of table
	// size -- see conversation_latency_bound_test.go's own comment).
	seedAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_cpl_filler"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by,created_at)
			SELECT $1, 'conv_cpl_filler_' || lpad(g::text, 6, '0'), $2, 1, $3, clock_timestamp() - interval '1 hour'
			  FROM generate_series(0, $4::int - 1) AS g
		`, s1dOrg, s1dWorkspace, s1dOwner, fillerConversations); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			SELECT $1, 'conv_cpl_filler_' || lpad(g::text, 6, '0'), $2, 1
			  FROM generate_series(0, $3::int - 1) AS g
		`, s1dOrg, s1dWorkspace, fillerConversations)
		return err
	}); err != nil {
		t.Fatalf("seed filler conversations: %v", err)
	}
	var fillerCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.conversation WHERE organization_id=$1 AND workspace_id=$2`,
		s1dOrg, s1dWorkspace).Scan(&fillerCount); err != nil {
		t.Fatal(err)
	}
	if fillerCount != fillerConversations {
		t.Fatalf("filler conversations resident=%d, want %d", fillerCount, fillerConversations)
	}

	// Real conversations: every turn gets a real encrypted Question/Answer
	// artifact pair and a real citation (Excerpt/Anchor/DeepLink artifacts),
	// exactly what GetBatch/Get decrypt -- created AFTER the filler above, so
	// their real clock_timestamp() created_at sorts them into List's newest
	// page ahead of every filler row.
	realConversationIDs := make([]string, 0, realConversations)
	for g := 0; g < realConversations; g++ {
		firstKey := cplIdempotencyKey(g, 0)
		first, err := questions.Create(ctx, access, question.CreateRequest{
			WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: firstKey,
		})
		if err != nil {
			t.Fatalf("create conversation g=%d turn=0: %v (code=%s)", g, err, question.CodeOf(err))
		}
		if first.ResultStatus != "COMPLETED" || len(first.Citations) == 0 || first.ConversationID == "" {
			t.Fatalf("g=%d turn=0 not a complete, cited, conversation-bound run: %+v", g, first)
		}
		realConversationIDs = append(realConversationIDs, first.ConversationID)
		for turnIndex := 1; turnIndex < turnsPerConversation; turnIndex++ {
			key := cplIdempotencyKey(g, turnIndex)
			run, err := questions.Create(ctx, access, question.CreateRequest{
				WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
				Question: "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c?", AnswerMode: "EXTRACTIVE", IdempotencyKey: key,
			})
			if err != nil {
				t.Fatalf("create conversation g=%d turn=%d: %v (code=%s)", g, turnIndex, err, question.CodeOf(err))
			}
			if run.ResultStatus != "COMPLETED" || len(run.Citations) == 0 {
				t.Fatalf("g=%d turn=%d not a complete, cited run: %+v", g, turnIndex, run)
			}
		}
	}

	// Time exactly the work GET /conversations performs: List's own
	// projection, then resolving every returned turn's Question Run through
	// ONE GetBatch call (FIX-5 #2) instead of one Get() call per turn, then
	// the same JSON envelope encode the HTTP handler performs.
	started := time.Now()
	views, err := conversations.List(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("list conversations: %v", err)
	}
	if len(views) == 0 {
		t.Fatal("conversation list returned an empty page")
	}
	runIDs := make([]string, 0, len(views)*turnsPerConversation)
	seenRunIDs := make(map[string]bool)
	for _, view := range views {
		for _, turn := range view.Turns {
			if !seenRunIDs[turn.QuestionRunID] {
				seenRunIDs[turn.QuestionRunID] = true
				runIDs = append(runIDs, turn.QuestionRunID)
			}
		}
	}
	runsByID, err := questions.GetBatch(ctx, access, s1dWorkspace, runIDs)
	if err != nil {
		t.Fatalf("GetBatch %d runs: %v", len(runIDs), err)
	}
	type wireTurn struct {
		TurnID        string        `json:"turn_id"`
		QuestionRunID string        `json:"question_run_id"`
		QuestionRun   *question.Run `json:"question_run,omitempty"`
	}
	type wireConversation struct {
		ConversationID string     `json:"conversation_id"`
		Turns          []wireTurn `json:"turns"`
	}
	envelopeItems := make([]wireConversation, 0, len(views))
	for _, view := range views {
		item := wireConversation{ConversationID: view.ID}
		for _, turn := range view.Turns {
			run, ok := runsByID[turn.QuestionRunID]
			wireItem := wireTurn{TurnID: turn.ID, QuestionRunID: turn.QuestionRunID}
			if ok {
				runCopy := run
				wireItem.QuestionRun = &runCopy
			}
			item.Turns = append(item.Turns, wireItem)
		}
		envelopeItems = append(envelopeItems, item)
	}
	envelope, err := json.Marshal(map[string]any{"conversations": envelopeItems})
	if err != nil {
		t.Fatal(err)
	}
	_ = envelope
	elapsed := time.Since(started)

	// Correctness: every one of the real, cited, artifact-bearing
	// conversations that landed in the returned page (they are the newest,
	// so it should be every one of them) resolves through GetBatch to its
	// full, correctly decrypted Question/Answer/Citations -- proof this is
	// measuring the real decrypted projection, not a shortcut that skips it.
	realFoundInPage := 0
	byID := make(map[string]conversation.View, len(views))
	for _, view := range views {
		byID[view.ID] = view
	}
	for _, conversationID := range realConversationIDs {
		view, ok := byID[conversationID]
		if !ok {
			continue // outside the page's own maxConversations cap; the rest still count.
		}
		realFoundInPage++
		if len(view.Turns) != turnsPerConversation {
			t.Fatalf("conversation=%s turns=%d want %d", conversationID, len(view.Turns), turnsPerConversation)
		}
		for _, turn := range view.Turns {
			run, ok := runsByID[turn.QuestionRunID]
			if !ok {
				t.Fatalf("conversation=%s turn=%s missing from GetBatch result", conversationID, turn.ID)
			}
			direct, err := questions.Get(ctx, access, s1dWorkspace, turn.QuestionRunID)
			if err != nil {
				t.Fatalf("direct Get for comparison run=%s: %v", turn.QuestionRunID, err)
			}
			if run.Question != direct.Question || run.Answer != direct.Answer || len(run.Citations) != len(direct.Citations) {
				t.Fatalf("GetBatch run=%s diverges from Get(): batch question=%q/answer=%q/citations=%d, direct question=%q/answer=%q/citations=%d",
					turn.QuestionRunID, run.Question, run.Answer, len(run.Citations), direct.Question, direct.Answer, len(direct.Citations))
			}
			for index, citation := range run.Citations {
				directCitation := direct.Citations[index]
				if citation.Excerpt == "" || citation.Anchor == "" || citation.DeepLink == "" {
					t.Fatalf("GetBatch run=%s citation[%d] has an empty disclosed field: %+v", turn.QuestionRunID, index, citation)
				}
				if citation.Excerpt != directCitation.Excerpt || citation.Anchor != directCitation.Anchor || citation.DeepLink != directCitation.DeepLink {
					t.Fatalf("GetBatch run=%s citation[%d] diverges from Get(): batch=%+v direct=%+v", turn.QuestionRunID, index, citation, directCitation)
				}
			}
		}
	}
	if realFoundInPage == 0 {
		t.Fatal("none of the real artifact-bearing conversations appeared in the returned page")
	}
	t.Logf("verified %d/%d real conversations, %d total resolved runs, %d filler conversations resident",
		realFoundInPage, realConversations, len(runsByID), fillerCount)

	if elapsed >= latencyUpperBound {
		t.Fatalf("conversation list+projection for %d resident (%d real, %d filler) took %v, exceeding the %v bound",
			fillerCount+realConversations, realConversations, fillerCount, elapsed, latencyUpperBound)
	}
	t.Logf("conversation list+projection page=%d runs=%d elapsed=%v (bound %v)", len(views), len(runIDs), elapsed, latencyUpperBound)
}

func cplIdempotencyKey(group, turn int) string {
	raw := make([]byte, 32)
	copy(raw, []byte(fmt.Sprintf("cpl-idem-%06d-%02d", group, turn)))
	return base64.RawURLEncoding.EncodeToString(raw)
}
