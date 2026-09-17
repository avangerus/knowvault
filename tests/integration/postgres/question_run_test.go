package postgres_test

import (
	"context"
	"encoding/base64"
	"fmt"
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
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestQuestionRunExtractiveLive proves the first user-visible Question Run
// slice against the same real PostgreSQL, filesystem, encrypted-artifact and
// Evidence paths used by the catalog acceptance suite. It deliberately checks
// replay and conflict behavior too: a UI retry must not mint a second answer,
// and an idempotency key must never be reusable for another question.
func TestQuestionRunExtractiveLive(t *testing.T) {
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
	workerAccess := workerAccess(t, s1dOrg)
	runSync(t, ctx, handler, queue, workerAccess, "question-live")

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
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_live"}
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	first, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("create question run: %v (code=%s)", err, question.CodeOf(err))
	}
	if first.ResultStatus != "COMPLETED" {
		t.Fatalf("result status=%s, want COMPLETED", first.ResultStatus)
	}
	if first.Freshness.State != "FRESH" || first.Freshness.CapturedAt == nil || first.Freshness.LastSuccessfulSyncAt == nil {
		t.Fatalf("question freshness=%+v, want a captured fresh source snapshot", first.Freshness)
	}
	if len(first.Uncertainties) != 0 || len(first.Conflicts) != 0 {
		t.Fatalf("complete run exposed signals: uncertainties=%#v conflicts=%#v", first.Uncertainties, first.Conflicts)
	}
	if first.PlanningStatus != "READY" || first.PlanningOperation != "LOOKUP" || first.PlanHash == "" {
		t.Fatalf("planner provenance=%s/%s hash=%q", first.PlanningStatus, first.PlanningOperation, first.PlanHash)
	}
	if !strings.Contains(first.Answer, "42") || len(first.Citations) == 0 {
		t.Fatalf("answer=%q citations=%d, want an exact answer with evidence", first.Answer, len(first.Citations))
	}
	if first.ConversationID == "" || first.ConversationTurnID == "" {
		t.Fatalf("first run was not bound to a conversation turn: %+v", first)
	}
	for _, citation := range first.Citations {
		if citation.CitationID == "" || citation.Excerpt == "" || citation.Anchor == "" || citation.DeepLink == "" {
			t.Fatalf("incomplete citation: %+v", citation)
		}
		if !strings.HasPrefix(citation.EvidenceTextHash, "hmac-sha256:k") {
			t.Fatalf("citation exposed a non-keyed evidence digest: %+v", citation)
		}
	}

	// A follow-up uses the same durable conversation but gets a distinct
	// append-only turn. This question is a full new question on its own
	// subject, so it plans on its own text unchanged: FIX-1 #4's minimal
	// topic memory only ever splices a prior turn's text onto a BARE period
	// follow-up ("and yesterday?", see question_topic_memory_test.go), never a
	// question that already carries its own subject.
	continuationKey := make([]byte, 32)
	copy(continuationKey, []byte("question-continuation"))
	continuation, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(continuationKey),
	})
	if err != nil {
		t.Fatalf("continue conversation: %v (code=%s)", err, question.CodeOf(err))
	}
	if continuation.ConversationID != first.ConversationID || continuation.ConversationTurnID == "" || continuation.ConversationTurnID == first.ConversationTurnID {
		t.Fatalf("continuation binding=%s/%s, first=%s/%s", continuation.ConversationID, continuation.ConversationTurnID, first.ConversationID, first.ConversationTurnID)
	}
	if continuation.ResultStatus != "COMPLETED" || len(continuation.Citations) == 0 {
		t.Fatalf("continuation was not an evidence-backed completed run: %+v", continuation)
	}
	var conversationCount, turnCount, linkedRunCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.conversation WHERE organization_id=$1 AND id=$2`, s1dOrg, first.ConversationID).Scan(&conversationCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.conversation_turn WHERE organization_id=$1 AND conversation_id=$2`, s1dOrg, first.ConversationID).Scan(&turnCount); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.question_run WHERE organization_id=$1 AND conversation_id=$2`, s1dOrg, first.ConversationID).Scan(&linkedRunCount); err != nil {
		t.Fatal(err)
	}
	if conversationCount != 1 || turnCount != 2 || linkedRunCount != 2 {
		t.Fatalf("conversation graph counts conversation=%d turns=%d linked_runs=%d, want 1/2/2", conversationCount, turnCount, linkedRunCount)
	}
	if _, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u0434\u0440\u0443\u0433\u0430\u044f \u0444\u043e\u0440\u043c\u0443\u043b\u0438\u0440\u043e\u0432\u043a\u0430", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(continuationKey),
	}); question.CodeOf(err) != question.CodeIdempotencyConflict {
		t.Fatalf("conversation-aware idempotency conflict code=%s err=%v", question.CodeOf(err), err)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.conversation SET archived_at=clock_timestamp() WHERE organization_id=$1 AND id=$2`, s1dOrg, first.ConversationID); err != nil {
		t.Fatal(err)
	}
	archivedKey := make([]byte, 32)
	copy(archivedKey, []byte("question-archived"))
	if _, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, ConversationID: first.ConversationID,
		Question: "\u043f\u043e\u0441\u043b\u0435 \u0430\u0440\u0445\u0438\u0432\u0430", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(archivedKey),
	}); question.CodeOf(err) != question.CodeDenied {
		t.Fatalf("archived conversation continuation code=%s err=%v", question.CodeOf(err), err)
	}

	replay, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: key,
	})
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replay.ID != first.ID || replay.AnswerHash != first.AnswerHash {
		t.Fatalf("replay minted a different result: first=%s/%s replay=%s/%s", first.ID, first.AnswerHash, replay.ID, replay.AnswerHash)
	}
	if _, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0434\u0440\u0443\u0433\u0430\u044f \u0444\u043e\u0440\u043c\u0443\u043b\u0438\u0440\u043e\u0432\u043a\u0430", AnswerMode: "EXTRACTIVE", IdempotencyKey: key,
	}); question.CodeOf(err) != question.CodeIdempotencyConflict {
		t.Fatalf("idempotency conflict code=%s err=%v", question.CodeOf(err), err)
	}
	if _, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: "ws_other", Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE", IdempotencyKey: key,
	}); question.CodeOf(err) != question.CodeIdempotencyConflict {
		t.Fatalf("cross-workspace idempotency conflict code=%s err=%v", question.CodeOf(err), err)
	}

	got, err := questions.Get(ctx, access, s1dWorkspace, first.ID)
	if err != nil {
		t.Fatalf("get question run: %v", err)
	}
	if got.ID != first.ID || got.Answer != first.Answer || len(got.Citations) != len(first.Citations) {
		t.Fatalf("get projection drifted: got=%+v first=%+v", got, first)
	}

	var auditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_type='QUESTION_RUN' AND resource_id=$2`, s1dOrg, first.ID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 2 {
		t.Fatalf("question run audit events=%d, want created+completed", auditCount)
	}

	unknownKey := make([]byte, 32)
	copy(unknownKey, []byte("planner-unknown"))
	unknown, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "???", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(unknownKey),
	})
	if err != nil {
		t.Fatalf("unknown planner request: %v", err)
	}
	if unknown.PlanningStatus != "UNKNOWN" || unknown.PlanningOperation != "UNKNOWN" || unknown.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(unknown.Citations) != 0 {
		t.Fatalf("unknown request was not fail-closed: %+v", unknown)
	}
	if len(unknown.Uncertainties) != 1 || unknown.Uncertainties[0].Code != question.UncertaintyPlannerUnknown || len(unknown.Conflicts) != 0 {
		t.Fatalf("unknown planner signal=%#v conflicts=%#v", unknown.Uncertainties, unknown.Conflicts)
	}

	var valid bool
	if err := admin.QueryRow(ctx, `SELECT app.question_run_uncertainties_valid($1::jsonb)`, `[ {"code":"BAD","evidence_ids":[],"extra":true} ]`).Scan(&valid); err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("uncertainty validator accepted an unknown member")
	}
	if err := admin.QueryRow(ctx, `SELECT app.question_run_conflicts_valid($1::jsonb)`, `[{"code":"SOURCE_CONFLICT","evidence_ids":["evidence_a"]}]`).Scan(&valid); err != nil {
		t.Fatal(err)
	}
	if valid {
		t.Fatal("conflict validator accepted a single Evidence ID")
	}
}

// TestQuestionRunMarksTruncatedCorpusPartial proves that the bounded
// extraction path never presents a truncated corpus as a COMPLETE one. A
// single real source file is deliberately large enough to create more Evidence
// fragments than the bounded Question Run reader admits.
//
// POKA_YOKE SRCH-004 requires that truncation degrade the corpus status, and
// QRY-002 requires that status to be persisted "separately from answer prose"
// and shown above the answer. So the contract is: corpus_status=PARTIAL plus
// the CORPUS_PARTIAL uncertainty bound to the selected Evidence, WITH the
// cited answer -- not the erasure of both. Erasing them made the retrieval
// budget an absolute answering ceiling: maximumSearchHits is finite by
// construction, so every corpus with more matches than that window is
// permanently partial and a workspace stopped answering anything at all the
// moment a second, larger source was connected (verified live on the
// acceptance stand: a three-file corpus answered until an 819-file repository
// joined the same organization index, after which every question in the
// workspace returned INSUFFICIENT_EVIDENCE with authorized_candidate_count=7).
// Every citation below is still individually authorized and hash-verified by
// the same Evidence gate; nothing about that path is relaxed here.
func TestQuestionRunMarksTruncatedCorpusPartial(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	var content strings.Builder
	for index := 0; index < 65; index++ {
		// Each long line is one deterministic fragment (canon.Segment never
		// splits a line), so this creates 65 authorized fragments while
		// remaining under the one-megabyte source limit.
		fmt.Fprintf(&content, "needle fragment %03d %s\n", index, strings.Repeat("x", 5000))
	}
	if err := os.WriteFile(filepath.Join(fileDir, "large.txt"), []byte(content.String()), 0o644); err != nil {
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-partial")

	var fragmentCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment WHERE organization_id=$1`, s1dOrg).Scan(&fragmentCount); err != nil {
		t.Fatal(err)
	}
	if fragmentCount <= 64 {
		t.Fatalf("fragment count=%d, want more than the bounded candidate window", fragmentCount)
	}

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
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_partial"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "needle", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("create partial question run: %v", err)
	}
	if run.CorpusStatus != "PARTIAL" {
		t.Fatalf("truncated corpus was presented as complete: status=%s corpus=%s answer=%q citations=%d", run.ResultStatus, run.CorpusStatus, run.Answer, len(run.Citations))
	}
	if run.ResultStatus != "COMPLETED" || len(run.Citations) == 0 ||
		run.Answer == "" || run.Answer == "\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u0434\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432 \u0432 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445." {
		t.Fatalf("a partial corpus with authorized Evidence must still answer, with the PARTIAL status beside it: status=%s corpus=%s answer=%q citations=%d",
			run.ResultStatus, run.CorpusStatus, run.Answer, len(run.Citations))
	}
	if len(run.Uncertainties) != 1 || run.Uncertainties[0].Code != question.UncertaintyCorpusPartial || len(run.Uncertainties[0].EvidenceIDs) == 0 || len(run.Conflicts) != 0 {
		t.Fatalf("partial run signals=%#v conflicts=%#v", run.Uncertainties, run.Conflicts)
	}
}

// TestQuestionRunGenericCompareLive proves that Compare is a reusable
// evidence operation, not a branch for a named business question. The two
// source files deliberately use the same arbitrary key and different values;
// the live PostgreSQL Question authority must surface both exact Evidence
// lines and persist a conflict signal with their IDs.
func TestQuestionRunGenericCompareLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "contract.txt"), []byte("status = signed \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "mail.txt"), []byte("status = pending \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f\n"), 0o644); err != nil {
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-compare")

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
	compareKey := make([]byte, 32)
	copy(compareKey, []byte("compare-live"))
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_compare"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0415\u0441\u0442\u044c \u043b\u0438 \u0440\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u044f status?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(compareKey),
	})
	if err != nil {
		t.Fatalf("create compare question run: %v", err)
	}
	if run.PlanningOperation != "COMPARE" || run.ResultStatus != "COMPLETED" || len(run.Citations) != 2 {
		t.Fatalf("compare run projection=%+v", run)
	}
	if !strings.Contains(run.Answer, "\u0420\u0430\u0441\u0445\u043e\u0436\u0434\u0435\u043d\u0438\u0435 \u043f\u043e status") || !strings.Contains(run.Answer, "signed") || !strings.Contains(run.Answer, "pending") {
		t.Fatalf("compare answer=%q", run.Answer)
	}
	if len(run.Conflicts) != 1 || run.Conflicts[0].Code != "CONFLICT_FACT_VALUE" || len(run.Conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("compare conflicts=%#v", run.Conflicts)
	}
	for _, citation := range run.Citations {
		if citation.EvidenceFragment == "" || citation.Excerpt == "" || !strings.Contains(citation.Excerpt, "status = ") {
			t.Fatalf("compare citation=%+v", citation)
		}
	}
}

// TestQuestionRunGenericExplainLive proves that Explain has a reusable,
// Evidence-bound definition path. The term is arbitrary; no business noun or
// question-specific branch is selected by the authority.
func TestQuestionRunGenericExplainLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "glossary.txt"), []byte("Kafka means event bus.\nThe event bus is used by operations.\n"), 0o644); err != nil {
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-explain")

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
	explainKey := make([]byte, 32)
	copy(explainKey, []byte("explain-live"))
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_explain"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0427\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442 Kafka?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(explainKey),
	})
	if err != nil {
		t.Fatalf("create explain question run: %v", err)
	}
	if run.PlanningOperation != "EXPLAIN" || run.ResultStatus != "COMPLETED" || len(run.Citations) != 1 {
		t.Fatalf("explain run projection=%+v", run)
	}
	if !strings.Contains(run.Answer, "Kafka \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442: event bus.") || run.Citations[0].Excerpt != "Kafka means event bus." {
		t.Fatalf("explain answer=%q citations=%+v", run.Answer, run.Citations)
	}
}

// TestQuestionRunGenericCodeTraceLive proves that CODE_TRACE is a reusable
// source-aware operation rather than a branch for a named process or repository.
// The code file and the design file share an arbitrary assertion key; the
// authority may report it only because the immutable extraction profiles prove
// one side is source code and the other is non-code.
func TestQuestionRunGenericCodeTraceLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "billing_flow.go"), []byte("billing_flow = implemented\nbusiness process is handled in code\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "billing-design.txt"), []byte("billing_flow = described\nbusiness process is documented in design\n"), 0o644); err != nil {
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-code-trace")

	// The profile is the authority used at query time; a filename alone is not
	// sufficient to classify a source as code.
	locator, err := canon.FileLocatorBytes("conn_s1d", "projects/alpha/billing_flow.go")
	if err != nil {
		t.Fatal(err)
	}
	var codeRevision string
	if err := admin.QueryRow(ctx, `SELECT e.parser_profile_revision
		FROM public.source_object o
		JOIN public.source_version v ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		JOIN public.source_version_active_extraction ae ON ae.organization_id=v.organization_id AND ae.source_version_id=v.id
		JOIN public.source_extraction e ON e.organization_id=ae.organization_id AND e.id=ae.extraction_id
		WHERE o.organization_id=$1 AND o.external_object_id_digest=$2`, s1dOrg,
		canon.HMACDigest(s1dDigestKey, 1, locator)).Scan(&codeRevision); err != nil {
		t.Fatal(err)
	}
	if codeRevision != canon.TextLayoutParserRevision("source-code-v1") {
		t.Fatalf("source-code parser revision=%q, want source-code layout-v2", codeRevision)
	}

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
	key := make([]byte, 32)
	copy(key, []byte("code-trace-live"))
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_code_trace"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace,
		Question:    "Which business processes are implemented in code and only described?",
		AnswerMode:  "EXTRACTIVE", IdempotencyKey: base64.RawURLEncoding.EncodeToString(key),
	})
	if err != nil {
		t.Fatalf("create code trace question run: %v", err)
	}
	if run.PlanningOperation != "CODE_TRACE" || run.ResultStatus != "COMPLETED" || len(run.Citations) != 2 {
		t.Fatalf("code trace run projection=%+v", run)
	}
	if !strings.Contains(run.Answer, "billing_flow") || !strings.Contains(run.Answer, "implemented") || !strings.Contains(run.Answer, "described") {
		t.Fatalf("code trace answer=%q", run.Answer)
	}
	if len(run.Conflicts) != 1 || run.Conflicts[0].Code != "CONFLICT_CODE_TRACE_VALUE" || len(run.Conflicts[0].EvidenceIDs) != 2 {
		t.Fatalf("code trace conflicts=%#v", run.Conflicts)
	}
	for _, citation := range run.Citations {
		if citation.Excerpt != "billing_flow = implemented" && citation.Excerpt != "billing_flow = described" {
			t.Fatalf("unexpected code-trace citation=%+v", citation)
		}
	}
}

// TestQuestionRunGenericAuditLive proves that AUDIT is a reusable control
// assertion operation, not a compliance-product branch.  An arbitrary control
// is accepted only when an immutable source-code extraction and an independent
// document extraction carry the same explicit positive status.
func TestQuestionRunGenericAuditLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "retention_control.go"), []byte("compliance confirmed retention_control\nretention_control = confirmed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "retention-control-policy.txt"), []byte("compliance confirmed retention_control\nretention_control = confirmed\n"), 0o644); err != nil {
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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-audit")

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
	key := make([]byte, 32)
	copy(key, []byte("audit-controls-live"))
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_question_audit"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace,
		Question:    "\u041a\u0430\u043a\u0438\u0435 compliance-\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u044b \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u043c\u0438 \u0438 \u043a\u043e\u0434\u043e\u043c?",
		AnswerMode:  "EXTRACTIVE", IdempotencyKey: base64.RawURLEncoding.EncodeToString(key),
	})
	if err != nil {
		t.Fatalf("create audit question run: %v", err)
	}
	if run.PlanningOperation != "AUDIT" || run.ResultStatus != "COMPLETED" || len(run.Citations) != 2 {
		t.Fatalf("audit run projection=%+v", run)
	}
	if !strings.Contains(run.Answer, "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u043e \u043f\u043e retention_control") || !strings.Contains(run.Answer, "confirmed") {
		t.Fatalf("audit answer=%q", run.Answer)
	}
	if len(run.Conflicts) != 0 || len(run.Uncertainties) != 0 {
		t.Fatalf("audit signals: uncertainties=%#v conflicts=%#v", run.Uncertainties, run.Conflicts)
	}
	for _, citation := range run.Citations {
		if citation.Excerpt != "retention_control = confirmed" {
			t.Fatalf("unexpected audit citation=%+v", citation)
		}
	}
}

// seedNumericAggregateCorpus writes one file per numeric Evidence line so each
// line becomes its own fragment (canon.Segment groups consecutive lines up to
// a byte budget, so several short lines in one file would land in a single
// fragment and never match the "column = value" Evidence shape the analytic
// adapter aggregates).
func seedNumericAggregateCorpus(t *testing.T, root string, count int) {
	t.Helper()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < count; index++ {
		name := fmt.Sprintf("amount-%03d.txt", index)
		if err := os.WriteFile(filepath.Join(fileDir, name), []byte("amount = 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// TestQuestionRunPartialCorpusWithholdsExactAggregate is review remark Z1's
// positive case: "PARTIAL + Aggregate does not publish an exact number".
//
// The bounded candidate window is what makes a large corpus PARTIAL, and an
// aggregate computed inside that window is not an approximation of the real
// total -- it is the exact answer to a different question (the visible rows),
// published as COMPLETED with a precise number and no marking. Prose degrades
// honestly under truncation; a number does not. The run must therefore reach
// its ordinary insufficient-evidence terminal state with corpus_status PARTIAL
// beside it, and no digit of a total may appear in the answer.
func TestQuestionRunPartialCorpusWithholdsExactAggregate(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	// One more numeric fragment than the bounded candidate window, so the
	// corpus is genuinely truncated rather than merely large.
	seedNumericAggregateCorpus(t, root, 65)

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
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "question-partial-aggregate")

	var fragmentCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.evidence_fragment WHERE organization_id=$1`, s1dOrg).Scan(&fragmentCount); err != nil {
		t.Fatal(err)
	}
	if fragmentCount <= 64 {
		t.Fatalf("fragment count=%d, want more than the bounded candidate window", fragmentCount)
	}

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
	run, err := questions.Create(ctx, database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_partial_aggregate"}, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0441\u0443\u043c\u043c\u0430 amount", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	if err != nil {
		t.Fatalf("create partial aggregate question run: %v", err)
	}
	if run.CorpusStatus != "PARTIAL" {
		t.Fatalf("truncated corpus was presented as complete: corpus=%s status=%s answer=%q", run.CorpusStatus, run.ResultStatus, run.Answer)
	}
	if run.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(run.Citations) != 0 {
		t.Fatalf("an aggregate over a truncated corpus must not be published: status=%s citations=%d answer=%q",
			run.ResultStatus, len(run.Citations), run.Answer)
	}
	if strings.ContainsAny(run.Answer, "0123456789") {
		t.Fatalf("a PARTIAL corpus published a number as an exact aggregate: answer=%q", run.Answer)
	}
	if len(run.Uncertainties) == 0 {
		t.Fatalf("a PARTIAL aggregate must still carry its corpus signal: %#v", run.Uncertainties)
	}
}

// The precise control for this guard -- the same plan and structured cell
// Evidence publishing an exact total when the corpus is COMPLETE, and nothing
// when it is PARTIAL -- is internal/question/partial_aggregate_test.go, which
// can build POSTGRESQL_QUERY cell anchors directly (the analytic adapter
// reduces cell Evidence, so a FOLDER corpus cannot exercise it end to end).
