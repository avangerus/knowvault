package question

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
)

// Card D-15 result 1: the kind is a closed list and anything outside it is not
// a recognition.
func TestAnswerKindClosedList(t *testing.T) {
	kinds := AnswerKinds()
	if len(kinds) != 9 {
		t.Fatalf("closed kind list has %d entries, want 9: %v", len(kinds), kinds)
	}
	for _, kind := range kinds {
		if !kind.Valid() {
			t.Fatalf("listed kind %q is not valid", kind)
		}
	}
	for _, value := range []string{"", "overview", "banana", "greeting_", "full stop"} {
		if kind, ok := ParseAnswerKind(value); ok {
			t.Fatalf("ParseAnswerKind(%q) = %q, true; want not listed", value, kind)
		}
	}
	if kind, ok := ParseAnswerKind(" FULL "); !ok || kind != AnswerKindFull {
		t.Fatalf("ParseAnswerKind trimmed full = %q, %v", kind, ok)
	}
}

// Card D-15 result 1: only the model's own answer is read, in its tool call or
// its content, and two different kinds in one answer are not a recognition.
func TestParseRecognisedAnswerKindReadsOnlyModelOutput(t *testing.T) {
	cases := []struct {
		name    string
		content string
		calls   []modelgateway.ToolCall
		want    AnswerKind
		ok      bool
	}{
		{name: "tool call", calls: []modelgateway.ToolCall{kindToolCall(`{"kind":"vague"}`)}, want: AnswerKindVague, ok: true},
		{name: "content token", content: "full", want: AnswerKindFull, ok: true},
		{name: "content quoted", content: "`change`.", want: AnswerKindChange, ok: true},
		{name: "content sentence", content: "The kind is greeting.", want: AnswerKindGreeting, ok: true},
		{name: "content json", content: `{"kind":"off_topic"}`, want: AnswerKindOffTopic, ok: true},
		{name: "unknown content", content: "banana", ok: false},
		{name: "empty", content: "", ok: false},
		{name: "ambiguous", content: "It is either full or change.", ok: false},
		{name: "tool call unknown kind", calls: []modelgateway.ToolCall{kindToolCall(`{"kind":"banana"}`)}, ok: false},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			got, ok := parseRecognisedAnswerKind(example.content, example.calls)
			if ok != example.ok || (ok && got != example.want) {
				t.Fatalf("parseRecognisedAnswerKind(%q, %d calls) = %q, %v; want %q, %v",
					example.content, len(example.calls), got, ok, example.want, example.ok)
			}
		})
	}
}

func kindToolCall(arguments string) modelgateway.ToolCall {
	var call modelgateway.ToolCall
	call.ID = "call-1"
	call.Type = "function"
	call.Function.Name = kindRecognitionToolName
	call.Function.Arguments = arguments
	return call
}

// Card D-15 result 1: a failed recognition step or a kind outside the list is
// full; a successful listed kind is recorded as returned.
func TestRecogniseAnswerKindResolvesFullOnDoubt(t *testing.T) {
	cases := []struct {
		name      string
		recognise KindRecognition
		want      AnswerKind
	}{
		{name: "listed kind", recognise: KindRecognition{Kind: AnswerKindPlainOverview, Valid: true}, want: AnswerKindPlainOverview},
		{name: "failed step", recognise: KindRecognition{Valid: false}, want: AnswerKindFull},
		{name: "unlisted kind", recognise: KindRecognition{Kind: "banana", Valid: true}, want: AnswerKindFull},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			service := &Service{}
			stub := &stubKindRecogniser{outcome: example.recognise}
			service.EnableAnswerKindRecogniser(stub)
			got, _ := service.recogniseAnswerKind(context.Background(), nil, "ws_kind_test", "вопрос")
			if got != example.want {
				t.Fatalf("recogniseAnswerKind = %q, want %q", got, example.want)
			}
		})
	}
	off := &Service{}
	if got, _ := off.recogniseAnswerKind(context.Background(), nil, "ws_kind_test", "вопрос"); got != AnswerKindFull {
		t.Fatalf("recognition off resolved %q, want full", got)
	}
}

// A failed step still reports its token usage so a caller can record the cost
// of an attempt that produced no kind.
func TestRecogniseAnswerKindKeepsFailedStepUsage(t *testing.T) {
	service := &Service{}
	service.EnableAnswerKindRecogniser(&stubKindRecogniser{outcome: KindRecognition{
		Usage: modelgateway.TokenUsage{Input: 700, Output: 3, Total: 703},
	}})
	kind, usage := service.recogniseAnswerKind(context.Background(), nil, "ws_kind_test", "вопрос")
	if kind != AnswerKindFull || usage.Input != 700 || usage.Output != 3 {
		t.Fatalf("failed step = %q, usage %+v; want full with the attempt's usage", kind, usage)
	}
}

type stubKindRecogniser struct {
	outcome  KindRecognition
	question string
}

func (stub *stubKindRecogniser) Recognise(_ context.Context, question string) KindRecognition {
	stub.question = question
	return stub.outcome
}

// Card D-15 result 1: the model-backed step treats a failed call and an answer
// outside the list as full, and a listed kind as itself.
func TestModelKindRecogniserAgainstStubbedModel(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    AnswerKind
		valid   bool
	}{
		{
			name: "failed call",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "unavailable", http.StatusServiceUnavailable)
			},
			want: AnswerKindFull,
		},
		{
			name:    "unlisted answer",
			handler: kindStubContent(`banana`),
			want:    AnswerKindFull,
		},
		{
			name:    "listed content",
			handler: kindStubContent(`hypothetical`),
			want:    AnswerKindHypothetical,
			valid:   true,
		},
		{
			name:    "listed tool call",
			handler: kindStubToolCall(`{"kind":"sources_overview"}`),
			want:    AnswerKindSourcesOverview,
			valid:   true,
		},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			server := httptest.NewServer(example.handler)
			defer server.Close()
			adapter := kindTestAdapter(t, server.URL)
			recogniser := NewModelKindRecogniser(adapter, "ws_kind_test")
			if recogniser == nil {
				t.Fatal("recogniser was not built for a valid adapter and workspace")
			}
			outcome := recogniser.Recognise(context.Background(), "вопрос о рабочей области")
			if outcome.Resolved() != example.want || outcome.Valid != example.valid {
				t.Fatalf("recognised %q valid=%v, want %q valid=%v", outcome.Kind, outcome.Valid, example.want, example.valid)
			}
		})
	}
	if NewModelKindRecogniser(nil, "ws_kind_test") != nil {
		t.Fatal("a nil adapter must not build a recogniser")
	}
	if NewModelKindRecogniser(kindTestAdapterForNil(), "bad workspace") != nil {
		t.Fatal("an invalid workspace must not build a recogniser")
	}
}

func kindStubContent(content string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writeKindStubResponse(writer, map[string]any{"role": "assistant", "content": content}, "stop")
	}
}

func kindStubToolCall(arguments string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writeKindStubResponse(writer, map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"id": "call-1", "type": "function",
				"function": map[string]any{"name": kindRecognitionToolName, "arguments": arguments},
			}},
		}, "tool_calls")
	}
}

func writeKindStubResponse(writer http.ResponseWriter, message map[string]any, finish string) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"model": "kind-test",
		"choices": []any{map[string]any{
			"message": message, "finish_reason": finish,
		}},
		"usage": map[string]any{"prompt_tokens": 700, "completion_tokens": 4, "total_tokens": 704},
	})
}

func kindTestAdapter(t *testing.T, endpoint string) *modelgateway.LabAdapter {
	t.Helper()
	adapter, err := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion,
		Endpoint:      endpoint, ModelID: "kind-test",
		MaxOutputTokens: 2048, InsecureLabMode: true,
		ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "kind-test", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 65536,
			MaxToolResultBytes: 8192, MaxOutputTokens: 2048, TimeoutSeconds: 30,
		},
	})
	if err != nil {
		t.Fatalf("build kind test adapter: %v", err)
	}
	t.Cleanup(func() { _ = adapter.Close() })
	return adapter
}

// kindTestAdapterForNil builds an adapter only to prove the workspace check; the
// endpoint is never called.
func kindTestAdapterForNil() *modelgateway.LabAdapter {
	adapter, _ := modelgateway.NewLabAdapter(modelgateway.LabAdapterConfig{
		SchemaVersion: modelgateway.LabAdapterSchemaVersion,
		Endpoint:      "http://127.0.0.1:1", ModelID: "kind-test",
		MaxOutputTokens: 2048, InsecureLabMode: true,
		ThinkingMode: modelgateway.ThinkingModeDisabled,
		ToolLoop: &modelgateway.ToolLoopProfile{
			ID: "kind-test", MaxTurns: 2, MaxToolCalls: 2, MaxInputBytes: 65536,
			MaxToolResultBytes: 8192, MaxOutputTokens: 2048, TimeoutSeconds: 30,
		},
	})
	return adapter
}
