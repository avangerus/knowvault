package postgres_test

// Card D-16: the plain_overview kind has its own answer route. This file proves
// two things deterministically with the real product database, the real
// workspace tool runtime and the real encrypted run persistence, and the model
// channel scripted:
//
//  1. A run whose separate recognition step returned plain_overview is answered
//     with the kind-specific instruction and only the read-only knowledge
//     tools: knowvault_source_sql, knowvault_source_schema, the live-data tool,
//     the metric tool and the analytic scalar tool are never offered, so the
//     route can make no SQL query and no live-data read. The run records the
//     recognized kind.
//  2. The server requires the answer to end with a next question: a submission
//     without one is rejected with a repair hint and the model's next
//     submission is the answer.
//  3. A run whose recognition returned full keeps exactly today's route: the
//     generic instruction and the full tool catalog.
//
// The real-model runs of Q13 and the executor's own rewordings live in
// d16_plain_overview_real_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

// d16StaticRecogniser is the stubbed recognition step: the route under test must
// be chosen by the recognised kind, not by any wording, so the test fixes it.
type d16StaticRecogniser struct {
	kind question.AnswerKind
}

func (recogniser d16StaticRecogniser) Recognise(context.Context, string) question.KindRecognition {
	return question.KindRecognition{Kind: recogniser.kind, Valid: true}
}

// d16ModelRequest is what one scripted answering call saw.
type d16ModelRequest struct {
	tools    []string
	system   string
	messages string
}

func d16ToolNames(tools []modelgateway.ToolDefinition) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Function.Name)
	}
	return names
}

func d16HasTool(names []string, want string) bool {
	for _, name := range names {
		if name == want {
			return true
		}
	}
	return false
}

func d16AnswerCall(content string) map[string]any {
	return map[string]any{
		"role": "assistant",
		"tool_calls": []any{map[string]any{
			"id": "d16-submit", "type": "function",
			"function": map[string]any{"name": "submit_answer", "arguments": content},
		}},
	}
}

func d16Clarification(text string) string {
	encoded, _ := json.Marshal(map[string]any{"no_data": false, "claims": []any{}, "clarification": text})
	return string(encoded)
}

// d16ScriptedAdapter mounts the scripted model endpoint.
func d16ScriptedAdapter(t *testing.T, endpoint string) *modelgateway.LabAdapter {
	t.Helper()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion, Endpoint: endpoint, ModelID: "d16-script",
		MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "d16-fixture", MaxTurns: 6, MaxToolCalls: 8, MaxInputBytes: 262144,
			MaxToolResultBytes: 65536, MaxOutputTokens: 2048, TimeoutSeconds: 120,
		},
	})
	if err != nil {
		t.Fatalf("d16 scripted adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return adapter
}

// d16RunQuestion creates one run against the synthetic proving environment with
// the given recognised kind.
func d16RunQuestion(t *testing.T, env *e1aEnvironment, adapter *modelgateway.LabAdapter,
	kind question.AnswerKind, questionText, idempotency string) question.Run {
	t.Helper()
	ctx := context.Background()
	env.Questions.EnableGeneration(adapter, nil)
	env.Questions.EnableAnswerKindRecogniser(d16StaticRecogniser{kind: kind})
	access := database.AccessContext{OrganizationID: regOrg, PrincipalID: regOwner, RequestID: "req_" + idempotency}
	run, err := env.Questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: regWorkspace, Question: questionText, IdempotencyKey: e1aIdempotencyKey(idempotency),
	})
	if err != nil {
		t.Fatalf("d16 run %q: %v (code=%s)", questionText, err, question.CodeOf(err))
	}
	return run
}

// d16AnsweringHandler serves the scripted answering calls. answers maps the
// zero-based answering call index to the submit_answer argument JSON; the last
// entry is reused for every later call.
func d16AnsweringHandler(t *testing.T, answers []string, captured *[]d16ModelRequest) http.HandlerFunc {
	t.Helper()
	var mutex sync.Mutex
	index := 0
	return func(writer http.ResponseWriter, request *http.Request) {
		var input struct {
			Messages []modelgateway.Message        `json:"messages"`
			Tools    []modelgateway.ToolDefinition `json:"tools"`
		}
		if json.NewDecoder(request.Body).Decode(&input) != nil || len(input.Messages) == 0 {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		mutex.Lock()
		tools := d16ToolNames(input.Tools)
		system := ""
		var all strings.Builder
		for _, message := range input.Messages {
			if message.Role == "system" {
				system = message.Content
			}
			all.WriteString(message.Content)
			all.WriteString("\n")
		}
		*captured = append(*captured, d16ModelRequest{tools: tools, system: system, messages: all.String()})
		content := answers[len(answers)-1]
		if index < len(answers) {
			content = answers[index]
		}
		index++
		mutex.Unlock()
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"model": "d16-script",
			"choices": []any{map[string]any{
				"message": d16AnswerCall(content), "finish_reason": "tool_calls",
			}},
			"usage": map[string]any{"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
		})
	}
}

func TestD16PlainOverviewRouteMountsKnowledgeToolsOnly(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var captured []d16ModelRequest
	model := httptest.NewServer(d16AnsweringHandler(t, []string{
		d16Clarification("В рабочей области есть сведения о договорах. Хотите узнать подробности?"),
	}, &captured))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d16-plain"})
	run := d16RunQuestion(t, env, d16ScriptedAdapter(t, model.URL), question.AnswerKindPlainOverview,
		"объясни простыми словами, что там с договорами", "d16-plain-route")

	if len(captured) == 0 {
		t.Fatal("the plain_overview run made no answering call")
	}
	first := captured[0]
	if !d16HasTool(first.tools, "knowvault_search") || !d16HasTool(first.tools, "knowvault_read") {
		t.Fatalf("plain_overview route did not mount the knowledge tools: %v", first.tools)
	}
	for _, forbidden := range []string{"knowvault_source_sql", "knowvault_source_schema", "knowvault_ask_live_data", "knowvault_compare_metric", "knowvault_analyze"} {
		if d16HasTool(first.tools, forbidden) {
			t.Fatalf("plain_overview route mounted the data tool %q: %v", forbidden, first.tools)
		}
	}
	if !strings.Contains(first.system, "Always finish with at least one concrete question") {
		t.Fatalf("plain_overview route did not use its own instruction: %.200q", first.system)
	}
	if strings.Contains(first.system, "using this argument format") {
		t.Fatal("plain_overview route used the full loop's instruction")
	}
	// ADR-0099 amendment 1 decision 5: a rule of one kind never appears in
	// another kind's prompt. The full loop's SQL retrieval order must not leak
	// into the plain_overview instruction block.
	if strings.Contains(first.system, "Retrieval order.") {
		t.Fatal("the full loop's SQL retrieval rule leaked into the plain_overview prompt")
	}
	if run.ToolLoop == nil || run.ToolLoop.AnswerKind != string(question.AnswerKindPlainOverview) {
		t.Fatalf("run record kind = %#v, want plain_overview", run.ToolLoop)
	}
	if !toolLoopAnswerEndsWithQuestion(run.Answer) {
		t.Fatalf("plain_overview answer does not end with a next question: %q", run.Answer)
	}
	if run.ToolLoop.StopReason != "CLARIFICATION" {
		t.Fatalf("plain_overview stop reason = %q, want CLARIFICATION", run.ToolLoop.StopReason)
	}
	for _, call := range run.ToolLoop.Calls {
		switch call.Name {
		case "knowvault_source_sql", "knowvault_source_schema", "knowvault_ask_live_data", "knowvault_compare_metric", "knowvault_analyze":
			t.Fatalf("plain_overview run reached a data tool: %+v", call)
		}
	}
}

func TestD16PlainOverviewAnswerMustEndWithNextQuestion(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var captured []d16ModelRequest
	model := httptest.NewServer(d16AnsweringHandler(t, []string{
		d16Clarification("В рабочей области есть сведения о договорах."),
		d16Clarification("В рабочей области есть сведения о договорах. Хотите узнать подробности?"),
	}, &captured))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d16-repair"})
	run := d16RunQuestion(t, env, d16ScriptedAdapter(t, model.URL), question.AnswerKindPlainOverview,
		"расскажи простыми словами про договоры", "d16-plain-repair")

	if len(captured) != 2 {
		t.Fatalf("the missing next question produced %d answering calls, want 2", len(captured))
	}
	if !strings.Contains(captured[1].messages, "SUBMIT_ANSWER_MISSING_NEXT_QUESTION") {
		t.Fatal("the rejected answer did not receive the next-question repair hint")
	}
	if !toolLoopAnswerEndsWithQuestion(run.Answer) || !strings.Contains(run.Answer, "подробности") {
		t.Fatalf("the answered text is not the repaired submission: %q", run.Answer)
	}
}

// Card D-16 result 1: a subject the workspace holds nothing about is still
// answered with the short text that says so and ends with a next question. A
// bare no_data is rejected and the model is asked for that text.
func TestD16PlainOverviewEmptySubjectNeedsText(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var captured []d16ModelRequest
	model := httptest.NewServer(d16AnsweringHandler(t, []string{
		`{"no_data":true,"claims":[]}`,
		d16Clarification("Данных о пирогах в рабочей области нет. Хотите узнать, какие темы в ней есть?"),
	}, &captured))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d16-empty"})
	run := d16RunQuestion(t, env, d16ScriptedAdapter(t, model.URL), question.AnswerKindPlainOverview,
		"объясни простыми словами, что у нас есть про пироги", "d16-plain-empty")

	if len(captured) != 2 {
		t.Fatalf("the empty no_data produced %d answering calls, want 2", len(captured))
	}
	if !strings.Contains(captured[1].messages, "SUBMIT_ANSWER_PLAIN_OVERVIEW_NEEDS_TEXT") {
		t.Fatal("the empty no_data did not receive the plain-overview text repair hint")
	}
	if !toolLoopAnswerEndsWithQuestion(run.Answer) || !strings.Contains(run.Answer, "пирогах") {
		t.Fatalf("the answered text is not the repaired empty-subject text: %q", run.Answer)
	}
}

func TestD16OtherRecognisedKindKeepsTheFullRoute(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	set := loadE1aSet(t)

	var captured []d16ModelRequest
	model := httptest.NewServer(d16AnsweringHandler(t, []string{
		d16Clarification("В рабочей области есть сведения о договорах. Хотите узнать подробности?"),
	}, &captured))
	defer model.Close()

	env := buildE1aEnvironment(t, ctx, admin, set, e1aEnvOptions{SourceIdentity: "pgdb-d16-full"})
	run := d16RunQuestion(t, env, d16ScriptedAdapter(t, model.URL), question.AnswerKindFull,
		"объясни простыми словами, что там с договорами", "d16-full-route")

	if len(captured) != 1 {
		t.Fatalf("the full-kind run made %d answering calls, want 1", len(captured))
	}
	if !d16HasTool(captured[0].tools, "knowvault_source_sql") {
		t.Fatalf("a full-kind question lost its data tools: %v", captured[0].tools)
	}
	if !strings.Contains(captured[0].system, "using this argument format") {
		t.Fatal("a full-kind question lost the full loop's instruction")
	}
	if strings.Contains(captured[0].system, "Always finish with at least one concrete question") {
		t.Fatal("the plain_overview instruction leaked into a full-kind question")
	}
	if run.ToolLoop == nil || run.ToolLoop.AnswerKind != string(question.AnswerKindFull) {
		t.Fatalf("run record kind = %#v, want full", run.ToolLoop)
	}
}

// toolLoopAnswerEndsWithQuestion mirrors the server rule from the external test
// package: the answer's last question mark ends the visible text.
func toolLoopAnswerEndsWithQuestion(text string) bool {
	index := strings.LastIndex(text, "?")
	if index < 0 {
		return false
	}
	tail := strings.Trim(strings.TrimSpace(text[index+1:]), " \t\r\n\"'\u00bb)]}.")
	return tail == ""
}
