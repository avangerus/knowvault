package postgres_test

import (
	"context"
	"encoding/base64"
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

// TestQuestionRunInterruptedAfterRestart proves card D-4 against real
// PostgreSQL: a question that was being answered when its server process died
// no longer stays RUNNING forever. The answering process is simulated exactly
// as the database records it — a RUNNING row owned by a process that stopped
// refreshing its heartbeat — while a second RUNNING row with a fresh heartbeat
// stands for a live replica (or a slow model call) and must be left alone.
//
// The startup reconciliation the server runs before its listener exists is
// driven directly. Then the same three reads the conversation view uses are
// checked: the run itself, the conversation turn that links it, and the
// batched hydration. Finally a new question in the same conversation must
// still complete, so finishing an orphan never poisons its topic.
func TestQuestionRunInterruptedAfterRestart(t *testing.T) {
	ctx := context.Background()
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
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-interruption")

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

	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_interruption"}
	firstKey := make([]byte, 32)
	copy(firstKey, []byte("interruption-first"))
	first, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?",
		AnswerMode: "EXTRACTIVE", IdempotencyKey: base64.RawURLEncoding.EncodeToString(firstKey),
	})
	if err != nil {
		t.Fatalf("create first question run: %v", err)
	}
	if first.ResultStatus != "COMPLETED" || first.ConversationID == "" {
		t.Fatalf("first run was not a completed conversation turn: %+v", first)
	}

	// Simulated restart: the run was committed RUNNING and its owner process
	// then died, so its last heartbeat is far outside the grace window. A
	// second RUNNING row stands for a live replica answering a slow call and
	// carries a fresh heartbeat.
	deadRunID := "qrun_01ARZ3NDEKTSV4RRFFQ69G5F10"
	liveRunID := "qrun_01ARZ3NDEKTSV4RRFFQ69G5F11"
	deadTurnID := "turn_01ARZ3NDEKTSV4RRFFQ69G5F12"
	liveTurnID := "turn_01ARZ3NDEKTSV4RRFFQ69G5F13"
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id,
				question_hash, answer_mode, verification_method, result_status,
				corpus_status, workspace_scope_hash, policy_revision,
				planner_status, planner_operation, planner_confidence, planner_plan_hash,
				owner_id, owner_heartbeat_at
			)
			SELECT organization_id, $3, workspace_id, workspace_revision, created_by,
			       conversation_id, $4,
			       question_hash, answer_mode, verification_method, 'RUNNING',
			       corpus_status, workspace_scope_hash, policy_revision,
			       planner_status, planner_operation, planner_confidence, planner_plan_hash,
			       $5, $6
			  FROM public.question_run
			 WHERE organization_id = $1 AND id = $2
		`, s1dOrg, first.ID, deadRunID, deadTurnID, "proc_dead_replica", time.Now().Add(-10*time.Minute).UTC()); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id,
				question_hash, answer_mode, verification_method, result_status,
				corpus_status, workspace_scope_hash, policy_revision,
				planner_status, planner_operation, planner_confidence, planner_plan_hash,
				owner_id, owner_heartbeat_at
			)
			SELECT organization_id, $3, workspace_id, workspace_revision, created_by,
			       conversation_id, $4,
			       question_hash, answer_mode, verification_method, 'RUNNING',
			       corpus_status, workspace_scope_hash, policy_revision,
			       planner_status, planner_operation, planner_confidence, planner_plan_hash,
			       $5, clock_timestamp()
			  FROM public.question_run
			 WHERE organization_id = $1 AND id = $2
		`, s1dOrg, first.ID, liveRunID, liveTurnID, "proc_live_replica"); err != nil {
			return err
		}
		for _, run := range []struct{ runID, turnID string; index int64 }{
			{deadRunID, deadTurnID, 2}, {liveRunID, liveTurnID, 3},
		} {
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.question_run_retention (organization_id, question_run_id)
				VALUES ($1, $2)
			`, s1dOrg, run.runID); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
				INSERT INTO public.conversation_turn (
					organization_id, id, conversation_id, workspace_id, workspace_revision,
					turn_index, question_run_id
				)
				SELECT organization_id, $3, $4, workspace_id, workspace_revision, $5, $2
				  FROM public.question_run
				 WHERE organization_id = $1 AND id = $6
			`, s1dOrg, run.runID, run.turnID, first.ConversationID, run.index, first.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed simulated-restart runs: %v", err)
	}

	// Start the service: the pre-listener reconciliation. Exactly the dead
	// owner's run is finished; the live replica's run is untouched.
	reconciled, err := questions.ReconcileInterruptedRuns(ctx, access)
	if err != nil {
		t.Fatalf("reconcile interrupted runs: %v", err)
	}
	if reconciled != 1 {
		t.Fatalf("reconciled=%d, want exactly the dead owner's run", reconciled)
	}
	dead, err := questions.Get(ctx, access, s1dWorkspace, deadRunID)
	if err != nil {
		t.Fatalf("get interrupted run: %v", err)
	}
	if dead.ResultStatus != "INTERRUPTED" || dead.CompletedAt == nil || dead.FailureCode != "QUESTION_INTERRUPTED" {
		t.Fatalf("dead owner's run=%s completed=%v code=%s, want a terminal INTERRUPTED run", dead.ResultStatus, dead.CompletedAt, dead.FailureCode)
	}
	if dead.Answer != "" || len(dead.Citations) != 0 {
		t.Fatalf("an interrupted run must not expose a partial answer: answer=%q citations=%d", dead.Answer, len(dead.Citations))
	}
	live, err := questions.Get(ctx, access, s1dWorkspace, liveRunID)
	if err != nil {
		t.Fatalf("get live run: %v", err)
	}
	if live.ResultStatus != "RUNNING" {
		t.Fatalf("a live owner's RUNNING run was touched: status=%s", live.ResultStatus)
	}

	// The conversation shows it: the turn is still linked and the batched
	// hydration the conversation projection uses answers INTERRUPTED.
	view, err := conversations.Get(ctx, access, s1dWorkspace, first.ConversationID)
	if err != nil {
		t.Fatalf("get conversation: %v", err)
	}
	foundTurn := false
	for _, turn := range view.Turns {
		if turn.QuestionRunID == deadRunID {
			foundTurn = true
		}
	}
	if !foundTurn {
		t.Fatalf("conversation %s no longer links the interrupted run", first.ConversationID)
	}
	hydrated, err := questions.GetBatch(ctx, access, s1dWorkspace, []string{deadRunID, liveRunID})
	if err != nil {
		t.Fatalf("hydrate conversation runs: %v", err)
	}
	if hydrated[deadRunID].ResultStatus != "INTERRUPTED" {
		t.Fatalf("conversation hydration status=%s, want INTERRUPTED", hydrated[deadRunID].ResultStatus)
	}
	if hydrated[liveRunID].ResultStatus != "RUNNING" {
		t.Fatalf("conversation hydration touched the live run: status=%s", hydrated[liveRunID].ResultStatus)
	}

	// Finishing is recorded like any other terminal outcome.
	var auditCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_event
		 WHERE organization_id = $1 AND resource_type = 'QUESTION_RUN' AND resource_id = $2
		   AND action = 'question.failed' AND error_code = 'QUESTION_INTERRUPTED' AND outcome = 'FAILED'
	`, s1dOrg, deadRunID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("interruption audit events=%d, want exactly one", auditCount)
	}

	// A new question in the same conversation works normally after the
	// interrupted turn.
	secondKey := make([]byte, 32)
	copy(secondKey, []byte("interruption-second"))
	second, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c?",
		AnswerMode: "EXTRACTIVE", IdempotencyKey: base64.RawURLEncoding.EncodeToString(secondKey),
	})
	if err != nil {
		t.Fatalf("create follow-up question after interruption: %v", err)
	}
	if second.ResultStatus != "COMPLETED" || second.ConversationID != first.ConversationID {
		t.Fatalf("follow-up after interruption=%+v, want a COMPLETED turn in conversation %s", second, first.ConversationID)
	}
}
