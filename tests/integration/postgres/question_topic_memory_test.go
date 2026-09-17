package postgres_test

// FIX-1 #4, real-PostgreSQL regression: minimal topic memory.
//
// Before this fix a bare period follow-up ("and yesterday?") carried no subject of
// its own for the planner to work with: internal/question/service.go's
// CreateRequest.ConversationID doc comment said as much ("It is never used
// as model memory"), and planning "and yesterday?" alone classifies it as an
// ordinary (and unanswerable) LOOKUP over the literal word for "yesterday".
//
// This test proves the fix on real Postgres, filesystem and encrypted-
// artifact paths, driven entirely through question.Service.Create: a
// second-turn "and yesterday?" is spliced onto the immediately preceding turn's own
// literal (decrypted) question text (planner.PeriodFollowUp +
// SpliceFollowUpPeriod, wired into Create via previousTurnQuestionText), and
// the COMBINED question is what actually gets planned and persisted -- never
// the bare follow-up alone.
//
// A companion half of FIX-1 #4 -- tolerating a conversation continuation
// across an unrelated workspace revision bump -- was investigated and
// deferred here: migration 000048's conversation/conversation_turn/
// conversation_retention RLS policies independently enforced the identical
// exact-revision equality this slice's own Go-level check made
// (`parent.workspace_revision = conversation_turn.workspace_revision`, in
// all three tables' member_read/member_insert/member_update policies), so
// relaxing only the Go-level check would not have changed the outcome -- it
// would only have replaced an intentional, typed CodeDenied with an
// unhandled RLS constraint violation (SQLSTATE 42501). FIX-2 #5 (migration
// 000080) makes the coordinated fix: see
// TestQuestionConversationContinuesAcrossUnrelatedWorkspaceRevisionBump in
// conversation_continuation_revision_test.go for the real-Postgres proof.
import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

func TestQuestionConversationTopicMemorySplicesPeriodFollowUp(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "waste.txt"), []byte("\u0412\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAX", "grant_s1d_topic", "confirmation_s1d_topic")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-topic-memory")

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
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_topic_first"}

	firstKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	first, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0442\u043e\u043d\u043d \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e?", AnswerMode: "EXTRACTIVE", IdempotencyKey: firstKey,
	})
	if err != nil {
		t.Fatalf("create first turn: %v (code=%s)", err, question.CodeOf(err))
	}
	if first.ConversationID == "" {
		t.Fatalf("first run was not bound to a conversation: %+v", first)
	}

	continuationKey := make([]byte, 32)
	copy(continuationKey, []byte("topic-memory-continuation"))
	continuation, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u0430 \u0432\u0447\u0435\u0440\u0430?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(continuationKey),
	})
	if err != nil {
		t.Fatalf("continue conversation with a bare period follow-up: %v (code=%s)", err, question.CodeOf(err))
	}
	if continuation.ConversationID != first.ConversationID || continuation.ConversationTurnID == first.ConversationTurnID {
		t.Fatalf("continuation binding=%s/%s, first=%s/%s", continuation.ConversationID, continuation.ConversationTurnID, first.ConversationID, first.ConversationTurnID)
	}
	// The persisted question is the SPLICED combination, not the bare
	// follow-up: it carries the prior turn's own subject ("waste") and the
	// new period word ("yesterday"), proving previousTurnQuestionText correctly
	// resolved and decrypted the prior turn's text and SpliceFollowUpPeriod
	// combined it, rather than planning "and yesterday?" in isolation.
	if continuation.Question == "\u0430 \u0432\u0447\u0435\u0440\u0430?" {
		t.Fatalf("continuation planned the bare follow-up instead of the spliced question: %+v", continuation)
	}
	if !strings.Contains(continuation.Question, "\u043e\u0442\u0445\u043e\u0434\u043e\u0432") || !strings.HasSuffix(strings.TrimRight(continuation.Question, "?. "), "\u0432\u0447\u0435\u0440\u0430") {
		t.Fatalf("continuation.Question=%q, want the prior subject plus the new period", continuation.Question)
	}
}
