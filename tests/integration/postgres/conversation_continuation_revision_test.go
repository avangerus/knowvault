package postgres_test

// FIX-2 #5, real-PostgreSQL regression: a conversation continues across an
// unrelated workspace revision bump, and an access change between turns is
// still honestly reflected on the new turn -- neither corrupts the other.
//
// Before migration 000080 (see its own header for the full root cause),
// question.Service.start's own conversation-binding check and migration
// 000048's conversation/conversation_turn/conversation_retention RLS
// policies both required a NEW turn's workspace_revision to equal the
// conversation's ORIGINAL, frozen creation-time revision. Any workspace
// mutation unrelated to this conversation (issuing an access code, toggling
// a different source, a membership change) advances
// workspace.current_revision and made every existing conversation's next
// turn fail that equality -- both the Go-level check and, independently,
// the RLS join -- even though every right is re-checked on every hop.
//
// This test proves the fix on real Postgres, filesystem and encrypted-
// artifact paths, driven entirely through question.Service.Create:
//
//  1. TestQuestionConversationContinuesAcrossUnrelatedWorkspaceRevisionBump:
//     a real, confirmed, synced FOLDER source; a first turn that gets a real
//     answer; an UNRELATED workspace revision advance (the same fixture
//     helper workspace_managed_authority_reconfirmation_test.go's own
//     TestExplicitSourceReconfirmationStaleReconfirmRevokeReplay uses,
//     carrying this scope's binding tuple forward unchanged); then a second
//     turn in the SAME conversation, which must succeed -- not CodeDenied,
//     not an unhandled RLS constraint violation.
//  2. TestQuestionConversationContinuationAfterSourceDisabledDeclinesEvidence:
//     the same setup, but the mutation BETWEEN turns disables this scope's
//     own binding (a real access revocation, not an unrelated one). The
//     continuation turn must still be CREATED (conversation continuity is
//     an access-control concern, not an evidence-availability one) but must
//     honestly report INSUFFICIENT_EVIDENCE with no citations -- never
//     silently reuse the first turn's now-stale citations, and never crash.
import (
	"context"
	"encoding/base64"
	"errors"
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

func TestQuestionConversationContinuesAcrossUnrelatedWorkspaceRevisionBump(t *testing.T) {
	ctx := context.Background()
	adminPool := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "waste.txt"), []byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, adminPool, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, adminPool, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, adminPool, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAY", "grant_s1d_revbump", "confirmation_s1d_revbump")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "conversation-continuation-revbump")

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
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_revbump_first"}

	firstKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	first, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: firstKey,
	})
	if err != nil {
		t.Fatalf("create first turn: %v (code=%s)", err, question.CodeOf(err))
	}
	if first.ConversationID == "" || len(first.Citations) == 0 {
		t.Fatalf("first turn has no conversation/citations: %+v", first)
	}

	// The unrelated mutation: advance the workspace to a fresh revision that
	// carries THIS scope's own binding tuple forward UNCHANGED -- exactly
	// what issuing an access code, toggling a different source, or a
	// membership change does to every binding's projection row.
	newRevision, _ := advanceManagedWorkspaceRevision(t, ctx, adminPool, fixture)
	if newRevision <= fixture.workspaceRevision {
		t.Fatalf("workspace revision did not advance: %d", newRevision)
	}

	continuationKey := make([]byte, 32)
	copy(continuationKey, []byte("revbump-continuation-turn"))
	continuation, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u0410 \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(continuationKey),
	})
	if err != nil {
		t.Fatalf("continue conversation after an UNRELATED workspace revision bump: %v / unwrap=%v (code=%s) -- "+
			"FIX-2 #5 regression: an unrelated mutation must not block continuing an existing conversation", err, errors.Unwrap(errors.Unwrap(err)), question.CodeOf(err))
	}
	if continuation.ConversationID != first.ConversationID || continuation.ConversationTurnID == first.ConversationTurnID {
		t.Fatalf("continuation binding=%s/%s, first=%s/%s", continuation.ConversationID, continuation.ConversationTurnID, first.ConversationID, first.ConversationTurnID)
	}
	if continuation.WorkspaceRevision != newRevision {
		t.Fatalf("continuation turn workspace_revision=%d, want the CURRENT revision %d (a snapshot of now, not the conversation's original)", continuation.WorkspaceRevision, newRevision)
	}

	// Get (the standalone read path, independent of Create's own return
	// value) must also see the continuation turn under the SAME conversation.
	reread, err := questions.Get(ctx, access, s1dWorkspace, continuation.ID)
	if err != nil {
		t.Fatalf("re-read continuation turn: %v (code=%s)", err, question.CodeOf(err))
	}
	if reread.ConversationID != first.ConversationID {
		t.Fatalf("re-read conversation_id=%s, want %s", reread.ConversationID, first.ConversationID)
	}
	conversationView, err := conversations.Get(ctx, access, s1dWorkspace, first.ConversationID)
	if err != nil || len(conversationView.Turns) != 2 {
		t.Fatalf("conversation.Get turns=%d err=%v, want 2 after continuation at revision %d", len(conversationView.Turns), err, newRevision)
	}
	conversationList, err := conversations.List(ctx, access, s1dWorkspace)
	if err != nil {
		t.Fatalf("conversation.List after continuation at revision %d: %v", newRevision, err)
	}
	listedTurns := -1
	for _, item := range conversationList {
		if item.ID == first.ConversationID {
			listedTurns = len(item.Turns)
			break
		}
	}
	if listedTurns != 2 {
		t.Fatalf("conversation.List turns=%d for %s, want 2", listedTurns, first.ConversationID)
	}
	archived, err := conversations.Archive(ctx, access, conversation.ArchiveRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		IdempotencyKey: workspaceIdempotencyKey("conversation-continuation-revbump-archive"),
	})
	if err != nil || len(archived.Turns) != 2 {
		t.Fatalf("conversation.Archive turns=%d err=%v, want 2 after continuation at revision %d", len(archived.Turns), err, newRevision)
	}
}

func TestQuestionConversationContinuationAfterSourceDisabledDeclinesEvidence(t *testing.T) {
	ctx := context.Background()
	adminPool := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "waste.txt"), []byte("\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, adminPool, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, adminPool, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, adminPool, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAZ", "grant_s1d_revoke", "confirmation_s1d_revoke")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "conversation-continuation-revoke")

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
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_revoke_first"}

	firstKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	first, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: firstKey,
	})
	if err != nil {
		t.Fatalf("create first turn: %v (code=%s)", err, question.CodeOf(err))
	}
	if first.ConversationID == "" || len(first.Citations) == 0 {
		t.Fatalf("first turn has no conversation/citations: %+v", first)
	}

	// The access-revoking mutation: disable THIS scope's own binding on a
	// fresh revision -- the counterpart to the unrelated-mutation test above.
	newRevision, _ := advanceManagedWorkspaceRevisionSettingBindingEnabled(t, ctx, adminPool, fixture, fixture.workspaceRevision, false)
	if newRevision <= fixture.workspaceRevision {
		t.Fatalf("workspace revision did not advance: %d", newRevision)
	}

	continuationKey := make([]byte, 32)
	copy(continuationKey, []byte("revoke-continuation-turn"))
	continuation, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u0410 \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(continuationKey),
	})
	if err != nil {
		t.Fatalf("continue conversation after the source was disabled: %v / unwrap=%v (code=%s) -- "+
			"the conversation itself must still accept a new turn; only the EVIDENCE must go missing", err, errors.Unwrap(errors.Unwrap(err)), question.CodeOf(err))
	}
	if continuation.ConversationID != first.ConversationID {
		t.Fatalf("continuation left the conversation: got %s, want %s", continuation.ConversationID, first.ConversationID)
	}
	if len(continuation.Citations) != 0 {
		t.Fatalf("continuation carries %d citations from a disabled source -- must be 0", len(continuation.Citations))
	}
	// The disabled source's evidence fragment fails re-authorization
	// (app.evidence_fragment_readable), so the DB-only fallback candidate
	// reader marks the corpus PARTIAL rather than finding zero candidates
	// outright (question.Service.execute: "a metadata row without readable
	// evidence is an incomplete corpus"); deriveSignals then reports exactly
	// one of CORPUS_PARTIAL/INSUFFICIENT_EVIDENCE for the same Evidence set
	// (the database forbids reusing an Evidence ID across two uncertainty
	// records). Either is an honest "the basis went missing" signal -- what
	// this test must never see is a stale reuse of the first turn's citation.
	if continuation.ResultStatus == "COMPLETED" {
		t.Fatalf("continuation status=COMPLETED with 0 citations after the source was disabled -- must not silently complete: %+v", continuation)
	}
	if continuation.CorpusStatus != "PARTIAL" &&
		!containsUncertaintyCodeForTest(continuation.Uncertainties, "INSUFFICIENT_EVIDENCE") &&
		!containsUncertaintyCodeForTest(continuation.Uncertainties, "CORPUS_PARTIAL") {
		t.Fatalf("continuation status=%s corpus=%s uncertainties=%+v, want an honest missing-basis signal (CORPUS_PARTIAL or INSUFFICIENT_EVIDENCE)",
			continuation.ResultStatus, continuation.CorpusStatus, continuation.Uncertainties)
	}
}

func containsUncertaintyCodeForTest(items []question.Uncertainty, code string) bool {
	for _, item := range items {
		if item.Code == code {
			return true
		}
	}
	return false
}
