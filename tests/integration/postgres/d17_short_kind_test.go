package postgres_test

// Card D-17 result 1 and 2, deterministically: a run whose separate
// recognition step returned off_topic or vague is answered by the server in
// one step with no answering model call at all. This file proves with the real
// product database, the real workspace tool runtime and the real encrypted run
// persistence, and the model channel scripted:
//
//  1. the off_topic and vague runs make zero model answering calls, mount no
//     tool and reach no SQL, live-data or document-search tool;
//  2. their answers have the required shape (at most two sentences for
//     off_topic; exactly one question of at most 400 characters for vague) and
//     name a subject the synthetic workspace really holds;
//  3. the run record carries the recognised kind and the ANSWER stop reason;
//  4. a run whose recognition returned full keeps exactly today's route: the
//     model is called and the full tool catalog is offered.
//
// The real-model runs of H1, H2 and the executor's own rewordings live in
// d17_short_kind_real_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

// d17StaticRecogniser fixes the recognised kind so the route is chosen by the
// recognition outcome, never by the question's wording.
type d17StaticRecogniser struct {
	kind question.AnswerKind
}

func (recogniser d17StaticRecogniser) Recognise(context.Context, string) question.KindRecognition {
	return question.KindRecognition{Kind: recogniser.kind, Valid: true}
}

// d17ForbiddenDataTools are the SQL, live-data and metric tools a short kind
// may never reach. Document-search tools are covered separately below.
var d17ForbiddenDataTools = map[string]bool{
	"knowvault_source_sql": true, "knowvault_source_schema": true,
	"knowvault_ask_live_data": true, "knowvault_compare_metric": true, "knowvault_analyze": true,
}

// d17ForbiddenSearchTools are the document-search and read tools a short kind
// may never reach.
var d17ForbiddenSearchTools = map[string]bool{
	"knowvault_search": true, "knowvault_read": true, "knowvault_grep": true,
	"knowvault_evidence_read": true, "knowvault_list_objects": true, "knowvault_related": true,
}

// d17ScriptedAdapter mounts one scripted OpenAI-compatible model channel.
func d17ScriptedAdapter(t *testing.T, endpoint string) *modelgateway.LabAdapter {
	t.Helper()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: endpoint, ModelID: "d17-script",
		MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "d17-fixture", MaxTurns: 6, MaxToolCalls: 8, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 2048, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("d17 scripted adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return adapter
}

// d17RunQuestion creates one run against the synthetic proving environment with
// the given recognised kind.
func d17RunQuestion(t *testing.T, env *e1aEnvironment, adapter *modelgateway.LabAdapter,
	kind question.AnswerKind, questionText, idempotency string) question.Run {
	t.Helper()
	ctx := context.Background()
	env.Questions.EnableGeneration(adapter, nil)
	env.Questions.EnableAnswerKindRecogniser(d17StaticRecogniser{kind: kind})
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_" + idempotency}
	run, err := env.Questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: questionText, IdempotencyKey: e1aIdempotencyKey(idempotency),
	})
	if err != nil {
		t.Fatalf("d17 run %q: %v (code=%s)", questionText, err, question.CodeOf(err))
	}
	return run
}

// d17ClarificationCall is the scripted full-route submission.
func d17ClarificationCall(text string) map[string]any {
	encoded, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{}, "clarification": text})
	return map[string]any{
		"role": "assistant",
		"tool_calls": []any{map[string]any{
			"id": "d17-submit", "type": "function",
			"function": map[string]any{"name": "submit_answer", "arguments": string(encoded)},
		}},
	}
}

// d17AnsweringHandler serves the scripted full-route call and records the tools
// it was offered.
func d17AnsweringHandler(t *testing.T, answer map[string]any, captured *[]string) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Tools []modelgateway.ToolDefinition `json:"tools"`
		}
		_ = json.NewDecoder(request.Body).Decode(&input)
		names := make([]string, 0, len(input.Tools))
		for _, tool := range input.Tools {
			names = append(names, tool.Function.Name)
		}
		*captured = append(*captured, names...)
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"model": "d17-script",
			"choices": []any{map[string]any{
				"message": answer, "finish_reason": "tool_calls",
			}},
			"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
		})
	}
}

// d17UncalledHandler fails the test if the model channel is reached at all.
func d17UncalledHandler(t *testing.T, calls *atomic.Int64) http.HandlerFunc {
	t.Helper()
	return func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		t.Errorf("the short-kind route made a model call")
		http.Error(writer, "unexpected model call", http.StatusInternalServerError)
	}
}

// d17AssertShortKindRun checks the deterministic shape shared by both short
// kinds.
func d17AssertShortKindRun(t *testing.T, run question.Run, kind question.AnswerKind) {
	t.Helper()
	if run.ToolLoop == nil {
		t.Fatalf("run has no tool loop record")
	}
	if run.ToolLoop.AnswerKind != string(kind) {
		t.Fatalf("run kind = %q, want %q", run.ToolLoop.AnswerKind, kind)
	}
	if run.ToolLoop.StopReason != "ANSWER" {
		t.Fatalf("run stop reason = %q, want ANSWER", run.ToolLoop.StopReason)
	}
	if run.ResultStatus != "COMPLETED" {
		t.Fatalf("run status = %q, want COMPLETED", run.ResultStatus)
	}
	if len(run.ToolLoop.Calls) == 0 {
		t.Fatal("run recorded no read at all; the workspace orientation read is missing")
	}
	for _, call := range run.ToolLoop.Calls {
		if !call.System {
			t.Fatalf("short-kind run made a model-requested tool call: %+v", call)
		}
		if d17ForbiddenDataTools[call.Name] || d17ForbiddenSearchTools[call.Name] {
			t.Fatalf("short-kind run reached the tool %s", call.Name)
		}
	}
	named := false
	for _, subject := range []string{"Договоры", "Клиенты", "МНО"} {
		if strings.Contains(run.Answer, subject) {
			named = true
			break
		}
	}
	if !named {
		t.Fatalf("short-kind answer names nothing the workspace holds: %q", run.Answer)
	}
}

func TestD17OffTopicRunIsServerRendered(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var modelCalls atomic.Int64
	model := httptest.NewServer(d17UncalledHandler(t, &modelCalls))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d17-offtopic"})
	run := d17RunQuestion(t, env, d17ScriptedAdapter(t, model.URL), question.AnswerKindOffTopic,
		"какая погода в Москве?", "d17-off-topic")

	if modelCalls.Load() != 0 {
		t.Fatalf("the off_topic route made %d model call(s), want 0", modelCalls.Load())
	}
	d17AssertShortKindRun(t, run, question.AnswerKindOffTopic)
	if sentences := d17SentenceCount(run.Answer); sentences > 2 {
		t.Fatalf("off_topic answer has %d sentences, want at most 2: %q", sentences, run.Answer)
	}
	if !strings.Contains(run.Answer, "не относится") {
		t.Fatalf("off_topic answer does not say the question is outside the workspace: %q", run.Answer)
	}
}

func TestD17VagueRunIsServerRendered(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var modelCalls atomic.Int64
	model := httptest.NewServer(d17UncalledHandler(t, &modelCalls))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d17-vague"})
	run := d17RunQuestion(t, env, d17ScriptedAdapter(t, model.URL), question.AnswerKindVague,
		"покажи данные", "d17-vague")

	if modelCalls.Load() != 0 {
		t.Fatalf("the vague route made %d model call(s), want 0", modelCalls.Load())
	}
	d17AssertShortKindRun(t, run, question.AnswerKindVague)
	if marks := strings.Count(run.Answer, "?"); marks != 1 {
		t.Fatalf("vague answer has %d question marks, want exactly 1: %q", marks, run.Answer)
	}
	if length := len([]rune(run.Answer)); length > 400 {
		t.Fatalf("vague answer has %d characters, want at most 400: %q", length, run.Answer)
	}
}

func TestD17FullKindKeepsTheFullRoute(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var captured []string
	model := httptest.NewServer(d17AnsweringHandler(t,
		d17ClarificationCall("В рабочей области есть сведения о договорах."), &captured))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d17-full"})
	run := d17RunQuestion(t, env, d17ScriptedAdapter(t, model.URL), question.AnswerKindFull,
		"сколько договоров действует?", "d17-full")

	if len(captured) == 0 {
		t.Fatal("the full-kind route made no model call")
	}
	offered := map[string]bool{}
	for _, name := range captured {
		offered[name] = true
	}
	if !offered["knowvault_source_sql"] || !offered["knowvault_search"] {
		t.Fatalf("the full-kind route lost its full tool catalog: %v", captured)
	}
	if run.ToolLoop == nil || run.ToolLoop.AnswerKind != string(question.AnswerKindFull) {
		t.Fatalf("run record kind = %#v, want full", run.ToolLoop)
	}
}

// d17SentenceCount mirrors the question set's max_sentences rule.
func d17SentenceCount(answer string) int {
	count := 0
	for _, part := range strings.FieldsFunc(strings.ReplaceAll(answer, "\n", " "), func(r rune) bool {
		return r == '.' || r == '!' || r == '?' || r == '…'
	}) {
		if strings.TrimSpace(part) != "" {
			count++
		}
	}
	return count
}
