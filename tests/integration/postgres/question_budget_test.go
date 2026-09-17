package postgres_test

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestGenerativeQuestionCreateUsesCallerDeadline proves the GENERATIVE budget
// is applied to the actual Create path before its database/retrieval/model
// work, while a stricter caller deadline remains authoritative. The model
// endpoint holds the connection open, so the test synchronizes on the caller's
// deadline and releases the test handler after Create returns instead of
// sleeping for the production budget.
func TestGenerativeQuestionCreateUsesCallerDeadline(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "projects", "alpha"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(root, "projects", "alpha", "waste.txt"), "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_question_budget", "confirmation_question_budget")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-budget")

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

	modelRequestSeen := make(chan struct{}, 1)
	modelHandlerExited := make(chan struct{})
	modelRelease := make(chan struct{})
	var modelHandlerExitOnce sync.Once
	var modelReleaseOnce sync.Once
	releaseModel := func() { modelReleaseOnce.Do(func() { close(modelRelease) }) }
	modelServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case modelRequestSeen <- struct{}{}:
		default:
		}
		select {
		case <-request.Context().Done():
		case <-modelRelease:
		}
		modelHandlerExitOnce.Do(func() { close(modelHandlerExited) })
	}))
	t.Cleanup(modelServer.Close)
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion:   modelgateway.LabAdapterSchemaVersion,
		Endpoint:        modelServer.URL,
		ModelID:         "question-budget-model",
		Timeout:         10 * time.Second,
		MaxOutputTokens: 32768,
		InsecureLabMode: true,
	})
	if err != nil {
		t.Fatalf("create bounded model adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	verifier, err := modelgateway.NewVerifier(modelgateway.LocalHashEmbedFunc(), modelgateway.LocalHashVerifierThreshold)
	if err != nil {
		t.Fatalf("create verifier: %v", err)
	}
	questions.EnableGeneration(adapter, verifier)

	callerCtx, cancelCaller := context.WithTimeout(ctx, 3*time.Second)
	callerDeadline, _ := callerCtx.Deadline()
	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte("question-budget"))
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	resultCh := make(chan questionCreateResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		run, createErr := questions.Create(callerCtx, database.AccessContext{
			OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_budget",
		}, question.CreateRequest{
			WorkspaceID:    s1dWorkspace,
			Question:       "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?",
			AnswerMode:     "GENERATIVE",
			IdempotencyKey: key,
		})
		resultCh <- questionCreateResult{run: run, err: createErr}
	}()
	modelSeen := false
	t.Cleanup(func() {
		cancelCaller()
		releaseModel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Errorf("question Create did not stop during cleanup")
		}
		if modelSeen {
			select {
			case <-modelHandlerExited:
			case <-time.After(5 * time.Second):
				t.Errorf("model request handler did not exit during cleanup")
			}
		}
	})

	select {
	case <-modelRequestSeen:
		modelSeen = true
	case result := <-resultCh:
		t.Fatalf("GENERATIVE Create returned before model endpoint: status=%s error_code=%s", result.run.ResultStatus, question.CodeOf(result.err))
	case <-time.After(10 * time.Second):
		t.Fatal("GENERATIVE Create never reached the bounded model endpoint")
	}

	var result questionCreateResult
	select {
	case result = <-resultCh:
	case <-time.After(10 * time.Second):
		t.Fatal("GENERATIVE Create did not return after caller deadline")
	}
	if result.err == nil || question.CodeOf(result.err) != question.CodeUnavailable {
		t.Fatalf("deadline Create result status=%s error=%v code=%s, want QUESTION_UNAVAILABLE", result.run.ResultStatus, result.err, question.CodeOf(result.err))
	}
	if !errors.Is(callerCtx.Err(), context.DeadlineExceeded) {
		t.Fatalf("caller context error=%v, want context deadline exceeded", callerCtx.Err())
	}
	if time.Now().After(callerDeadline.Add(7 * time.Second)) {
		t.Fatalf("GENERATIVE Create returned too long after caller deadline=%s", callerDeadline)
	}
	releaseModel()
	select {
	case <-modelHandlerExited:
	case <-time.After(5 * time.Second):
		t.Fatal("model endpoint did not exit after caller deadline")
	}

	var runID string
	if err := admin.QueryRow(ctx, `SELECT question_run_id
		FROM public.question_idempotency
		WHERE organization_id=$1 AND actor_principal_id=$2 AND idempotency_key=$3`,
		s1dOrg, s1dOwner, key).Scan(&runID); err != nil {
		t.Fatalf("find failed GENERATIVE run: %v", err)
	}
	var status string
	var answerHash, answerArtifact, structuredArtifact, manifestArtifact sql.NullString
	var completedAt *time.Time
	if err := admin.QueryRow(ctx, `SELECT result_status, answer_hash, answer_markdown_artifact_id,
		answer_structured_artifact_id, manifest_content_artifact_id, completed_at
		FROM public.question_run WHERE organization_id=$1 AND id=$2`, s1dOrg, runID).
		Scan(&status, &answerHash, &answerArtifact, &structuredArtifact, &manifestArtifact, &completedAt); err != nil {
		t.Fatalf("read failed GENERATIVE run: %v", err)
	}
	if status != "FAILED" || completedAt == nil || answerHash.Valid || answerArtifact.Valid || structuredArtifact.Valid || manifestArtifact.Valid {
		t.Fatalf("failed GENERATIVE run status/completion/answer fields=%q/%v/%v/%v/%v/%v, want FAILED/completed/no answer", status, completedAt != nil, answerHash.Valid, answerArtifact.Valid, structuredArtifact.Valid, manifestArtifact.Valid)
	}

	failed, err := questions.Get(ctx, database.AccessContext{
		OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_budget_get",
	}, s1dWorkspace, runID)
	if err != nil {
		t.Fatalf("read failed GENERATIVE projection: %v", err)
	}
	if failed.ResultStatus != "FAILED" || failed.Answer != "" || failed.AnswerHash != "" || len(failed.Citations) != 0 {
		t.Fatalf("failed GENERATIVE projection status/answer/hash/citations=%q/%q/%q/%d, want FAILED/no answer", failed.ResultStatus, failed.Answer, failed.AnswerHash, len(failed.Citations))
	}

	var failedAuditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event
		WHERE organization_id=$1 AND resource_type='QUESTION_RUN' AND resource_id=$2
		  AND action=$3 AND outcome='FAILED' AND error_code='QUESTION_EXECUTION_FAILED'`,
		s1dOrg, runID, string(audit.ActionQuestionFailed)).Scan(&failedAuditCount); err != nil {
		t.Fatalf("count GENERATIVE failure audit: %v", err)
	}
	if failedAuditCount != 1 {
		t.Fatalf("GENERATIVE failure audit count=%d, want exactly one", failedAuditCount)
	}
}

type questionCreateResult struct {
	run question.Run
	err error
}
