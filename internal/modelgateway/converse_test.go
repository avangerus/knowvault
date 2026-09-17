package modelgateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testConverseProfile() *ToolLoopProfile {
	return &ToolLoopProfile{ID: "test-tools-v1", MaxTurns: 8, MaxToolCalls: 12, MaxInputBytes: 24576, MaxToolResultBytes: 6000, MaxOutputTokens: 1024, TimeoutSeconds: 120}
}

func testConverseTools() []ToolDefinition {
	return []ToolDefinition{{Type: "function", Function: ToolFunction{Name: "knowvault_read", Parameters: json.RawMessage(`{"type":"object"}`)}}}
}

func TestConverseToolRoundTripDiscardsReasoning(t *testing.T) {
	for _, mode := range []ThinkingMode{ThinkingModeDisabled, ThinkingModeEnabled} {
		t.Run(string(mode), func(t *testing.T) { testConverseToolRoundTrip(t, mode) })
	}
}

func testConverseToolRoundTrip(t *testing.T, mode ThinkingMode) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		var body map[string]json.RawMessage
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid request")
		}
		wantTemplate, _ := json.Marshal(map[string]bool{"enable_thinking": mode == ThinkingModeEnabled})
		wantMode, _ := json.Marshal(map[string]ThinkingMode{"type": mode})
		if string(body["chat_template_kwargs"]) != string(wantTemplate) || string(body["thinking"]) != string(wantMode) {
			t.Error("thinking mode differs from the configured profile")
		}
		if string(body["temperature"]) != "0" || body["presence_penalty"] != nil || body["top_k"] != nil {
			t.Error("legacy profile changed its sampling request")
		}
		if requests == 1 {
			_, _ = w.Write([]byte(`{"model":"test-chat","choices":[{"finish_reason":"tool_calls","message":{"role":"assistant","reasoning_content":"SECRET_REASONING","tool_calls":[{"id":"call-1","type":"function","function":{"name":"knowvault_read","arguments":"{\"address\":\"kv1:test\"}"}}]}}],"usage":{"prompt_tokens":40,"completion_tokens":10,"total_tokens":50}}`))
		} else {
			if !strings.Contains(string(body["messages"]), `"role":"tool"`) || !strings.Contains(string(body["messages"]), `"tool_call_id":"call-1"`) {
				t.Error("tool response missing from second turn")
			}
			_, _ = w.Write([]byte(`{"model":"test-chat","choices":[{"finish_reason":"stop","message":{"role":"assistant","content":"<think>SECRET_REASONING</think>Answer","reasoning_content":"ALSO_SECRET"}}]}`))
		}
	}))
	defer server.Close()
	adapter, err := NewLabAdapter(LabAdapterConfig{SchemaVersion: LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "test-chat", MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: mode, ToolLoop: testConverseProfile()})
	if err != nil {
		t.Fatal(err)
	}
	if profile, ok := adapter.ToolLoopProfile(); !ok || profile.ThinkingMode != mode {
		t.Fatal("recorded profile lost effective thinking mode")
	}
	messages := []Message{{Role: "system", Content: "Read facts"}, {Role: "user", Content: "Question"}}
	first, attempt, err := adapter.Converse(context.Background(), "ws-test", messages, testConverseTools())
	if err != nil || !attempt.Succeeded || len(first.Message.ToolCalls) != 1 || first.Usage.Input != 40 {
		t.Fatalf("first turn: %#v %#v %v", first, attempt, err)
	}
	messages = append(messages, first.Message, Message{Role: "tool", ToolCallID: "call-1", Content: "Evidence"})
	second, _, err := adapter.Converse(context.Background(), "ws-test", messages, testConverseTools())
	if err != nil || second.Message.Content != "Answer" {
		t.Fatalf("second turn: %#v %v", second, err)
	}
	stored, _ := json.Marshal([]ConverseResult{first, second})
	if strings.Contains(string(stored), "SECRET") {
		t.Fatal("reasoning entered serializable result")
	}
}

func TestConverseRefusesWorkspaceAndOversizedContextBeforeNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; w.WriteHeader(500) }))
	defer server.Close()
	adapter := &LabAdapter{config: LabAdapterConfig{Endpoint: server.URL, ModelID: "test-chat", ExternalRuntimeWorkspaceIDs: []string{"ws-allowed"}, ToolLoop: testConverseProfile()}, http: server.Client()}
	for _, scenario := range []struct{ workspace, text string }{{"ws-other", "question"}, {"ws-allowed", strings.Repeat("x", 30000)}} {
		_, _, err := adapter.Converse(context.Background(), scenario.workspace, []Message{{Role: "system", Content: "rules"}, {Role: "user", Content: scenario.text}}, testConverseTools())
		if err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if requests != 0 {
		t.Fatal("forbidden content reached model")
	}
}
