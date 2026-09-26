package postgres_test

// Card D-6a: a form-rejected final answer is shown, not lost. The scripted
// model reads the source schema, runs one SQL statement, and then submits an
// answer that carries a service label and raw relation/column names; the
// product rejects the form, the forced final turn cleans the presentation, and
// the persisted run keeps the answer's content and its claim binding. Reading
// the run back through the real service proves the displayed bytes and the
// persisted evidence still agree.
//
// The second case covers the acceptance remark of card D-6a: a question about
// the data structure itself is not an exception. Its answer must use business
// words too, so the same cleaning and the same persisted-run proof apply.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// d6aBadAnswer is the answer the scripted model keeps submitting for a count
// question: a self-label, the raw relation name next to "table" and the raw
// column name next to "field". The number it carries is the gathered content
// that must survive.
const d6aBadAnswer = "Answer: the registered contracts table holds 42 rows, where the status field equals active."

// d6aSchemaBadAnswer is the answer the scripted model keeps submitting for a
// question about the data structure itself: a self-label, the raw relation name
// next to "table" and the raw column names next to "columns". The acceptance
// remark of card D-6a is that such an answer may not be shown as-is either; the
// business wording in the second sentence is the content that must survive.
const d6aSchemaBadAnswer = "Answer: the contracts table has columns id and status. The live read returns 42 rows of the registered agreements."

func TestToolLoopFinalAnswerFormRejectionShowsGatheredAnswer(t *testing.T) {
	run, questions, ctx, access := d6aPresentationRun(t, "How many contracts are registered?", d6aScriptedModel)

	if run.ResultStatus != "COMPLETED" || run.ToolLoop == nil || run.ToolLoop.StopReason != "ANSWER" {
		t.Fatalf("run = %+v tool_loop=%+v", run.ResultStatus, run.ToolLoop)
	}
	if run.ToolLoop.PresentedClaims == nil {
		t.Fatal("the forced final turn did not record presented claims")
	}
	answer := run.Answer
	if strings.TrimSpace(answer) == "" || strings.Contains(answer, "did not submit an answer") {
		t.Fatalf("a form-rejected final answer was lost to a stub: %q", answer)
	}
	for _, forbidden := range []string{"Answer:", "contracts table", "status field"} {
		if strings.Contains(answer, forbidden) {
			t.Fatalf("the shown answer still carries %q: %q", forbidden, answer)
		}
	}
	if !strings.Contains(answer, "42") {
		t.Fatalf("the shown answer lost the gathered content: %q", answer)
	}

	// The displayed bytes are persisted and still bind to their claim evidence:
	// the real read path must return exactly the shown answer, not refuse it.
	readBack, err := questions.Get(ctx, access, s1dWorkspace, run.ID)
	if err != nil {
		t.Fatalf("read the persisted run back: %v (%s)", err, question.CodeOf(err))
	}
	if readBack.Answer != answer {
		t.Fatalf("persisted answer = %q, want the shown %q", readBack.Answer, answer)
	}
}

// TestToolLoopSchemaQuestionAnswerDropsRawNames is the acceptance remark of card
// D-6a at the persisted-run level: an answer about the data structure that names
// the raw relation and its columns is cleaned to business words instead of being
// shown as-is, and the persisted run still holds that shown answer.
func TestToolLoopSchemaQuestionAnswerDropsRawNames(t *testing.T) {
	run, questions, ctx, access := d6aPresentationRun(t, "What data does the database hold about contracts?", d6aSchemaScriptedModel)

	if run.ResultStatus != "COMPLETED" || run.ToolLoop == nil || run.ToolLoop.StopReason != "ANSWER" {
		t.Fatalf("run = %+v tool_loop=%+v", run.ResultStatus, run.ToolLoop)
	}
	if run.ToolLoop.PresentedClaims == nil {
		t.Fatal("the forced final turn did not record presented claims")
	}
	answer := run.Answer
	if strings.TrimSpace(answer) == "" || strings.Contains(answer, "did not submit an answer") {
		t.Fatalf("a form-rejected schema answer was lost to a stub: %q", answer)
	}
	for _, forbidden := range []string{"Answer:", "contracts table"} {
		if strings.Contains(answer, forbidden) {
			t.Fatalf("the shown schema answer still carries %q: %q", forbidden, answer)
		}
	}
	if match := regexp.MustCompile(`(?i)\b(?:contracts|id|status)\b`).FindString(answer); match != "" {
		t.Fatalf("the shown schema answer still carries the raw name %q: %q", match, answer)
	}
	for _, want := range []string{"42", "registered agreements"} {
		if !strings.Contains(answer, want) {
			t.Fatalf("the shown schema answer lost its gathered content %q: %q", want, answer)
		}
	}

	readBack, err := questions.Get(ctx, access, s1dWorkspace, run.ID)
	if err != nil {
		t.Fatalf("read the persisted run back: %v (%s)", err, question.CodeOf(err))
	}
	if readBack.Answer != answer {
		t.Fatalf("persisted answer = %q, want the shown %q", readBack.Answer, answer)
	}
}

// d6aPresentationRun mounts the real service, the scripted source tools and the
// scripted model, then creates one run for questionText. Every D-6a integration
// case shares this setup.
func d6aPresentationRun(t *testing.T, questionText string, modelHandler http.HandlerFunc) (question.Run, *question.Service, context.Context, database.AccessContext) {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_4K895FKH1CRX252KVCTX0FNXXZ", "grant_s1d_admin", "confirmation_s1d_admin", true)

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
	authority, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	sources := &sqlToolLoopSourceService{}
	handler, _, _ := scriptedSourceSQLHandler(t, s1dOrg, s1dOwner, sources, viewer, authority)
	questions.EnableToolLoop(handler)

	model := httptest.NewServer(modelHandler)
	defer model.Close()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: model.URL, ModelID: "d6a-scripted",
		MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{ID: "d6a-fixture", MaxTurns: 3, MaxToolCalls: 4,
			MaxInputBytes: 60000, MaxToolResultBytes: 16000, MaxOutputTokens: 2048, TimeoutSeconds: 120},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	questions.EnableGeneration(adapter, nil)

	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_d6a_presentation"}
	key := make([]byte, 32)
	key[0] = 0x6a
	run, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: questionText,
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(key),
	})
	if err != nil {
		logQuestionCauses(t, err)
		t.Fatalf("create run: %v (%s)", err, question.CodeOf(err))
	}
	return run, questions, ctx, access
}

// d6aScriptedModel drives one deterministic run: read the schema, run one SQL
// statement, then keep submitting the form-rejected answer. The product's loop
// owns the repair and the final cleaning.
func d6aScriptedModel(w http.ResponseWriter, r *http.Request) {
	d6aScriptedSubmit(w, r, d6aBadAnswer)
}

// d6aSchemaScriptedModel is the same deterministic run for the data-structure
// question: it ends by submitting an answer that names the raw relation and its
// columns.
func d6aSchemaScriptedModel(w http.ResponseWriter, r *http.Request) {
	d6aScriptedSubmit(w, r, d6aSchemaBadAnswer)
}

func d6aScriptedSubmit(w http.ResponseWriter, r *http.Request, badAnswer string) {
	var input struct {
		Messages []modelgateway.Message        `json:"messages"`
		Tools    []modelgateway.ToolDefinition `json:"tools"`
	}
	if json.NewDecoder(r.Body).Decode(&input) != nil || len(input.Messages) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	message := map[string]any{"role": "assistant"}
	finish := "stop"
	toolCall := func(id, name, arguments string) {
		message["tool_calls"] = []any{map[string]any{"id": id, "type": "function",
			"function": map[string]any{"name": name, "arguments": arguments}}}
		finish = "tool_calls"
	}
	schemaSeen := false
	for _, m := range input.Messages {
		if m.Role == "tool" && strings.Contains(m.Content, `"tables"`) {
			schemaSeen = true
		}
	}
	sqlAttempt, receipt := lastSQLReceipt(input.Messages)
	switch {
	case !schemaSeen:
		toolCall("d6a-schema", "knowvault_source_schema", `{"source_id":"`+sourceSQLToolLoopSourceID+`"}`)
	case sqlAttempt == "":
		toolCall("d6a-sql", "knowvault_source_sql",
			`{"source_id":"`+sourceSQLToolLoopSourceID+`","sql":"SELECT count(*) FROM public.contracts","purpose":"count contracts"}`)
	default:
		arguments, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{map[string]any{
			"text":       badAnswer,
			"citations":  []any{},
			"live_reads": []any{map[string]any{"result_id": sqlAttempt, "receipt_digest": receipt}},
		}}})
		toolCall("d6a-submit", "submit_answer", string(arguments))
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"model": "d6a-scripted",
		"choices": []any{map[string]any{"message": message, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}})
}
