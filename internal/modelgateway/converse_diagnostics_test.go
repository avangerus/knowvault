package modelgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func diagnosticResponse(finish string, calls []ToolCall) []byte {
	body, _ := json.Marshal(map[string]any{
		"model": "test-chat", "choices": []any{map[string]any{
			"finish_reason": finish, "message": map[string]any{
				"role": "assistant", "content": nil, "tool_calls": calls,
				"reasoning_content": "PRIVATE_PROVIDER_REASONING",
			},
		}},
	})
	return body
}

func diagnosticCall(id, arguments string) ToolCall {
	call := ToolCall{ID: id, Type: "function"}
	call.Function.Name, call.Function.Arguments = "knowvault_read", arguments
	return call
}

func TestConverseResponseDiagnosticsPreserveClosedBoundaries(t *testing.T) {
	valid := diagnosticCall("call_1", `{"address":"kv1:test"}`)
	changeCall := func(edit func(*ToolCall), finish string) []byte {
		call := valid
		edit(&call)
		return diagnosticResponse(finish, []ToolCall{call})
	}
	boundaryArgs := `{"x":"` + strings.Repeat("x", 16384-len(`{"x":""}`)) + `"}`
	if len(boundaryArgs) != 16384 || !json.Valid([]byte(boundaryArgs)) {
		t.Fatal("invalid argument-boundary fixture")
	}
	calls := make([]ToolCall, 17)
	for index := range calls {
		calls[index] = diagnosticCall(fmt.Sprintf("call_%d", index), `{}`)
	}
	baseline := diagnosticResponse("tool_calls", []ToolCall{valid})
	cases := []struct {
		name        string
		body        []byte
		status      int
		want        ResponseDiagnostic
		wireFailure bool
		wantCalls   int
	}{
		{"null-content-valid-tool-call", baseline, 200, "", false, 1},
		{"argument-byte-boundary", diagnosticResponse("tool_calls", []ToolCall{diagnosticCall("call_1", boundaryArgs)}), 200, "", false, 1},
		{"sixteen-tool-calls", diagnosticResponse("tool_calls", calls[:16]), 200, "", false, 16},
		{"outer-json-invalid", []byte(`{"PRIVATE_PROVIDER_BODY":`), 200, ResponseJSONInvalid, false, 0},
		{"typed-content-invalid", []byte(strings.Replace(string(baseline), `"content":null`, `"content":["PRIVATE_PROVIDER_BODY"]`, 1)), 200, ResponseJSONInvalid, false, 0},
		{"model-mismatch", []byte(strings.Replace(string(baseline), `"model":"test-chat"`, `"model":"another-model"`, 1)), 200, ResponseModelMismatch, false, 0},
		{"zero-choices", []byte(`{"model":"test-chat","choices":[]}`), 200, ResponseChoiceCountInvalid, false, 0},
		{"multiple-choices", []byte(`{"model":"test-chat","choices":[{},{}]}`), 200, ResponseChoiceCountInvalid, false, 0},
		{"role-invalid", []byte(strings.Replace(string(baseline), `"role":"assistant"`, `"role":"user"`, 1)), 200, ResponseRoleInvalid, false, 0},
		{"unknown-finish", diagnosticResponse("PRIVATE_PROVIDER_FINISH", nil), 200, ResponseFinishInvalid, false, 0},
		{"provider-resource", diagnosticResponse("insufficient_system_resource", nil), 200, ResponseProviderResource, false, 0},
		{"provider-aborted", diagnosticResponse("aborted", nil), 200, ResponseProviderAborted, false, 0},
		{"provider-filtered", diagnosticResponse("content_filter", nil), 200, ResponseProviderFiltered, false, 0},
		{"length-with-complete-arguments", diagnosticResponse("length", []ToolCall{valid}), 200, ResponseOutputLimit, false, 0},
		{"length-with-truncated-arguments", diagnosticResponse("length", []ToolCall{diagnosticCall("call_1", `{"PRIVATE_ARGUMENTS":`)}), 200, ResponseOutputLimit, false, 0},
		{"length-without-tool-call", diagnosticResponse("length", nil), 200, ResponseOutputLimit, false, 0},
		{"seventeen-tool-calls", diagnosticResponse("tool_calls", calls), 200, ResponseToolCountExceeded, false, 0},
		{"invalid-tool-id", changeCall(func(call *ToolCall) { call.ID = " bad" }, "tool_calls"), 200, ResponseToolIDInvalid, false, 0},
		{"duplicate-tool-id", diagnosticResponse("tool_calls", []ToolCall{valid, valid}), 200, ResponseToolIDDuplicate, false, 0},
		{"invalid-tool-type", changeCall(func(call *ToolCall) { call.Type = "PRIVATE_TYPE" }, "tool_calls"), 200, ResponseToolTypeInvalid, false, 0},
		{"invalid-tool-name", changeCall(func(call *ToolCall) { call.Function.Name = " bad" }, "tool_calls"), 200, ResponseToolNameInvalid, false, 0},
		{"arguments-too-large", changeCall(func(call *ToolCall) { call.Function.Arguments = boundaryArgs + " " }, "tool_calls"), 200, ResponseArgumentsTooLarge, false, 0},
		{"arguments-invalid-json", changeCall(func(call *ToolCall) { call.Function.Arguments = `{"PRIVATE_ARGUMENTS":` }, "tool_calls"), 200, ResponseArgumentsJSONInvalid, false, 0},
		{"length-does-not-bypass-model", []byte(strings.Replace(string(diagnosticResponse("length", []ToolCall{valid})), `"model":"test-chat"`, `"model":"another-model"`, 1)), 200, ResponseModelMismatch, false, 0},
		{"length-does-not-bypass-size", changeCall(func(call *ToolCall) { call.Function.Arguments = boundaryArgs + " " }, "length"), 200, ResponseArgumentsTooLarge, false, 0},
		{"length-does-not-bypass-call-count", diagnosticResponse("length", calls), 200, ResponseToolCountExceeded, false, 0},
		{"length-does-not-bypass-duplicate-id", diagnosticResponse("length", []ToolCall{valid, valid}), 200, ResponseToolIDDuplicate, false, 0},
		{"http-failure-remains-wire", []byte(`{"PRIVATE_ERROR":"detail"}`), 429, "", true, 0},
		{"response-byte-cap-remains-wire", []byte(strings.Repeat(" ", labMaxResponseBytes+1)), 200, "", true, 0},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(example.status)
				_, _ = w.Write(example.body)
			}))
			defer server.Close()
			adapter, err := NewLabAdapter(LabAdapterConfig{SchemaVersion: LabAdapterSchemaVersion, Endpoint: server.URL, ModelID: "test-chat", MaxOutputTokens: 2048, InsecureLabMode: true, ThinkingMode: ThinkingModeDisabled, ToolLoop: testConverseProfile()})
			if err != nil {
				t.Fatal(err)
			}
			defer adapter.Close()
			result, attempt, err := adapter.Converse(context.Background(), "ws-test", []Message{{Role: "system", Content: "rules"}, {Role: "user", Content: "neutral"}}, testConverseTools())
			if requests != 1 || attempt.StatusCode != example.status || attempt.ResponseDiagnostic != example.want {
				t.Fatalf("attempt classification or request count changed: requests=%d attempt=%+v", requests, attempt)
			}
			if example.want != "" || example.wireFailure {
				if err == nil || attempt.Succeeded || !reflect.DeepEqual(result, ConverseResult{}) {
					t.Fatal("rejected provider response became an executable result")
				}
				if strings.Contains(err.Error(), "PRIVATE") || strings.Contains(attempt.ResponseDiagnostic.ReasonCode(), "PRIVATE") {
					t.Fatal("provider-controlled content entered public error or reason code")
				}
				wantCode, wantStage := CodeInvalid, ResponseStageJSON
				if example.wireFailure {
					wantCode, wantStage = CodeUnavailable, ResponseStageWire
				}
				if attempt.FailureCode != wantCode || CodeOf(err) != wantCode || attempt.ResponseStage != wantStage {
					t.Fatalf("existing error/stage contract changed: %+v %v", attempt, err)
				}
			} else if err != nil || !attempt.Succeeded || len(result.Message.ToolCalls) != example.wantCalls || result.Message.Content != "" {
				t.Fatalf("compatible successful shape rejected: %+v %v", attempt, err)
			}
		})
	}
}

func TestResponseDiagnosticReasonCodeRejectsUntrustedValues(t *testing.T) {
	for _, value := range []ResponseDiagnostic{"", "PRIVATE_RESPONSE", "MODEL_RESPONSE_JSON_INVALID\nPRIVATE", ResponseDiagnostic(strings.Repeat("A", 10000))} {
		if value.ReasonCode() != "" {
			t.Fatal("noncanonical diagnostic admitted")
		}
	}
}
