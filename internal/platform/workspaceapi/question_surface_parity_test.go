package workspaceapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

const parityConversationID = "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV"

type parityQuestionService struct {
	*fakeQuestionService
	createCalls int
}

func (service *parityQuestionService) Create(ctx context.Context, access database.AccessContext, request question.CreateRequest) (question.Run, error) {
	service.createCalls++
	return service.fakeQuestionService.Create(ctx, access, request)
}

func effectiveParityActorKind(kind database.ActorKind) database.ActorKind {
	if kind == "" {
		return database.ActorKindHuman
	}
	return kind
}

func callParityREST(t *testing.T, harness *testHarness, service *parityQuestionService) (database.AccessContext, question.CreateRequest, map[string]any) {
	t.Helper()
	service.createCalls = 0
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions",
		`{"question":"How many?","conversation_id":"`+parityConversationID+`","answer_mode":"EXTRACTIVE"}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.createCalls != 1 || service.call != "create" {
		t.Fatalf("REST status=%d calls=%d call=%q body=%s", response.Code, service.createCalls, service.call, response.Body.String())
	}
	return service.access, service.request, decodeJSONObject(t, response.Body.String())
}

func callParityMCP(t *testing.T, harness *testHarness, service *parityQuestionService) (database.AccessContext, question.CreateRequest, map[string]any, bool) {
	t.Helper()
	service.createCalls = 0
	service.call = ""
	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"parity","method":"tools/call","params":{"name":"knowvault_question","arguments":{"workspace_id":"ws_alpha","conversation_id":"`+parityConversationID+`","question":"How many?","answer_mode":"EXTRACTIVE"}}}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.createCalls != 1 || service.call != "create" {
		t.Fatalf("MCP status=%d calls=%d call=%q body=%s", response.Code, service.createCalls, service.call, response.Body.String())
	}
	var envelope struct {
		Result struct {
			Structured map[string]any `json:"structuredContent"`
			IsError    bool           `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Result.Structured == nil {
		t.Fatalf("decode MCP parity response: err=%v body=%s", err, response.Body.String())
	}
	return service.access, service.request, envelope.Result.Structured, envelope.Result.IsError
}

func newParityHarness(t *testing.T) (*testHarness, *parityQuestionService) {
	t.Helper()
	harness := newTestHarness(t)
	service := &parityQuestionService{fakeQuestionService: harness.questions}
	harness.handler.questions = service
	return harness, service
}

func TestQuestionRESTAndMCPDelegateEquivalentAuthority(t *testing.T) {
	harness, service := newParityHarness(t)
	restAccess, restRequest, restRun := callParityREST(t, harness, service)
	mcpAccess, mcpRequest, mcpRun, isError := callParityMCP(t, harness, service)

	if restAccess.OrganizationID != mcpAccess.OrganizationID || restAccess.PrincipalID != mcpAccess.PrincipalID ||
		effectiveParityActorKind(restAccess.ActorKind) != effectiveParityActorKind(mcpAccess.ActorKind) {
		t.Fatalf("authority identity differs: REST=%#v MCP=%#v", restAccess, mcpAccess)
	}
	if restAccess.RequestID == "" || mcpAccess.RequestID == "" {
		t.Fatalf("missing request provenance: REST=%#v MCP=%#v", restAccess, mcpAccess)
	}
	if effectiveParityActorKind(restAccess.ActorKind) != database.ActorKindHuman {
		t.Fatalf("session parity actor=%q, want HUMAN", effectiveParityActorKind(restAccess.ActorKind))
	}
	if restRequest != mcpRequest {
		t.Fatalf("QuestionService.Create input differs: REST=%#v MCP=%#v", restRequest, mcpRequest)
	}
	want := question.CreateRequest{WorkspaceID: "ws_alpha", ConversationID: parityConversationID, Question: "How many?", AnswerMode: "EXTRACTIVE", IdempotencyKey: harness.idempotencyKey}
	if restRequest != want {
		t.Fatalf("authority input=%#v want=%#v", restRequest, want)
	}
	if !reflect.DeepEqual(restRun, mcpRun) || isError {
		t.Fatalf("terminal projection differs or completed MCP is error: REST=%#v MCP=%#v isError=%v", restRun, mcpRun, isError)
	}
}

func TestQuestionRESTAndMCPTerminalSemantics(t *testing.T) {
	for _, status := range []string{"COMPLETED", "INSUFFICIENT_EVIDENCE", "FAILED", "CANCELLED", "INTERRUPTED"} {
		t.Run(status, func(t *testing.T) {
			harness, service := newParityHarness(t)
			service.run.ResultStatus = status
			_, _, restRun := callParityREST(t, harness, service)
			_, _, mcpRun, isError := callParityMCP(t, harness, service)
			if !reflect.DeepEqual(restRun, mcpRun) {
				t.Fatalf("terminal projection differs: REST=%#v MCP=%#v", restRun, mcpRun)
			}
			if restRun["status"] != status || mcpRun["status"] != status {
				t.Fatalf("status rewritten: REST=%#v MCP=%#v want=%q", restRun["status"], mcpRun["status"], status)
			}
			if isError != (status != "COMPLETED") {
				t.Fatalf("MCP isError=%v for status %q", isError, status)
			}
		})
	}
}
