package questions

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
)

// StubModel is an OpenAI-compatible chat-completions endpoint used by the
// runner smoke test, so CI can exercise the whole question-run pipeline
// without the DeepSeek key. It answers every turn deterministically: the first
// turn of a run asks for the workspace source inventory (when the tool is
// offered), and every later turn submits an explicit no-data answer.
type StubModel struct {
	requests atomic.Int64
	// SourcesCall, when true, makes the first turn call knowvault_sources.
	SourcesCall bool
}

// NewStubModel returns a stub model endpoint.
func NewStubModel() *StubModel { return &StubModel{SourcesCall: true} }

// Requests is the number of completion requests served.
func (stub *StubModel) Requests() int { return int(stub.requests.Load()) }

type stubMessage struct {
	Role       string         `json:"role"`
	Content    string         `json:"content"`
	ToolCalls  []stubToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type stubToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type stubTool struct {
	Function struct {
		Name string `json:"name"`
	} `json:"function"`
}

// ServeHTTP implements one OpenAI-compatible chat completion.
func (stub *StubModel) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	stub.requests.Add(1)
	var input struct {
		Model    string        `json:"model"`
		Messages []stubMessage `json:"messages"`
		Tools    []stubTool    `json:"tools"`
	}
	if err := json.NewDecoder(request.Body).Decode(&input); err != nil || len(input.Messages) == 0 {
		http.Error(writer, "bad request", http.StatusBadRequest)
		return
	}
	sourcesOffered := false
	for _, tool := range input.Tools {
		if tool.Function.Name == "knowvault_sources" {
			sourcesOffered = true
		}
	}
	last := input.Messages[len(input.Messages)-1]
	message := map[string]any{"role": "assistant"}
	finish := "stop"
	if stub.SourcesCall && sourcesOffered && last.Role == "user" {
		message["tool_calls"] = []any{map[string]any{
			"id": "stub-sources-1", "type": "function",
			"function": map[string]any{"name": "knowvault_sources", "arguments": `{"limit":1}`},
		}}
		finish = "tool_calls"
	} else {
		content, _ := json.Marshal(map[string]any{"no_data": true, "claims": []any{}})
		message["content"] = string(content)
	}
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"model": strings.TrimSpace(input.Model),
		"choices": []any{map[string]any{
			"message":       message,
			"finish_reason": finish,
		}},
		"usage": map[string]any{"prompt_tokens": 120, "completion_tokens": 12, "total_tokens": 132},
	})
}
