package workspaceapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func TestCreateAuthenticatesThenCSRFFirstAndReturnsNoStoreETag(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, workspacesPath, `{"name":"Alpha","description":"","retention_policy_id":""}`)
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	harness.mutationHeaders(request, harness.hash)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.service.call != "create" || harness.auth.authenticateCalls != 1 || harness.auth.csrfCalls != 1 {
		t.Fatalf("status=%d call=%q auth=%d csrf=%d body=%s", response.Code, harness.service.call, harness.auth.authenticateCalls, harness.auth.csrfCalls, response.Body.String())
	}
	if harness.service.access.RequestID != "req_server_001" || harness.service.createRequest.IdempotencyKey == "" {
		t.Fatalf("service did not receive authenticated request context: %#v %#v", harness.service.access, harness.service.createRequest)
	}
	if response.Header().Get("ETag") != `"`+harness.hash+`"` || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Content-Type") != "application/json; charset=utf-8" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Request-ID") != "req_server_001" {
		t.Fatalf("headers=%#v", response.Header())
	}
	if strings.Contains(response.Body.String(), harness.idempotencyKey) {
		t.Fatalf("idempotency key leaked in response: %s", response.Body.String())
	}
}

func TestUnsafeRoutesStopBeforeBodyOrServiceOnAuthenticationAndCSRF(t *testing.T) {
	for name, prepare := range map[string]func(*testHarness){
		"authentication": func(h *testHarness) { h.auth.authenticateErr = errors.New("session rejected") },
		"csrf":           func(h *testHarness) { h.auth.csrfErr = errors.New("origin rejected") },
	} {
		name, prepare := name, prepare
		wantStatus := http.StatusUnauthorized
		if name == "csrf" {
			wantStatus = http.StatusForbidden
		}
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			prepare(harness)
			request := harness.request(http.MethodPost, workspacesPath, `{"unexpected":true}`)
			harness.mutationHeaders(request, harness.hash)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != wantStatus || harness.service.call != "" {
				t.Fatalf("status=%d service=%q body=%s", response.Code, harness.service.call, response.Body.String())
			}
			if name == "authentication" && harness.auth.csrfCalls != 0 {
				t.Fatal("csrf ran after failed authentication")
			}
		})
	}
}

func TestStrictJSONAndConditionalHeadersFailClosed(t *testing.T) {
	for name, fixture := range map[string]struct {
		body        string
		contentType string
		headers     func(*http.Request, *testHarness)
		wantStatus  int
	}{
		"unknown member":            {`{"name":"Alpha","description":"","retention_policy_id":"","extra":true}`, jsonContentType, nil, http.StatusBadRequest},
		"duplicate member":          {`{"name":"Alpha","name":"Beta","description":"","retention_policy_id":""}`, jsonContentType, nil, http.StatusBadRequest},
		"trailing value":            {`{"name":"Alpha","description":"","retention_policy_id":""} {}`, jsonContentType, nil, http.StatusBadRequest},
		"case variant":              {`{"Name":"Alpha","description":"","retention_policy_id":""}`, jsonContentType, nil, http.StatusBadRequest},
		"null required":             {`{"name":null,"description":"","retention_policy_id":""}`, jsonContentType, nil, http.StatusBadRequest},
		"array":                     {`[]`, jsonContentType, nil, http.StatusBadRequest},
		"wrong content type":        {`{"name":"Alpha","description":"","retention_policy_id":""}`, "text/plain", nil, http.StatusUnsupportedMediaType},
		"content encoding":          {`{"name":"Alpha","description":"","retention_policy_id":""}`, jsonContentType, func(request *http.Request, _ *testHarness) { request.Header.Set("Content-Encoding", "gzip") }, http.StatusBadRequest},
		"invalid utf8":              {string([]byte{'{', '"', 'n', 'a', 'm', 'e', '"', ':', '"', 0xff, '"', ',', '"', 'd', 'e', 's', 'c', 'r', 'i', 'p', 't', 'i', 'o', 'n', '"', ':', '"', '"', ',', '"', 'r', 'e', 't', 'e', 'n', 't', 'i', 'o', 'n', '_', 'p', 'o', 'l', 'i', 'c', 'y', '_', 'i', 'd', '"', ':', '"', '"', '}'}), jsonContentType, nil, http.StatusBadRequest},
		"too large":                 {`{"name":"` + strings.Repeat("a", maxBodyBytes) + `","description":"","retention_policy_id":""}`, jsonContentType, nil, http.StatusRequestEntityTooLarge},
		"create if match forbidden": {`{"name":"Alpha","description":"","retention_policy_id":""}`, jsonContentType, func(request *http.Request, h *testHarness) { request.Header.Set("If-Match", `"`+h.hash+`"`) }, http.StatusBadRequest},
		"duplicate idempotency case insensitive": {`{"name":"Alpha","description":"","retention_policy_id":""}`, jsonContentType, func(request *http.Request, h *testHarness) {
			request.Header["idempotency-key"] = []string{h.idempotencyKey}
		}, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost, workspacesPath, fixture.body)
			request.Header.Set("Content-Type", fixture.contentType)
			harness.mutationHeaders(request, harness.hash)
			if fixture.headers != nil {
				fixture.headers(request, harness)
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || harness.service.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
			}
		})
	}
}

func TestMutationsRequireCanonicalIfMatchAndDispatchAllRepositoryOperations(t *testing.T) {
	for name, fixture := range map[string]struct {
		method string
		path   string
		body   string
		call   string
		setup  func(*http.Request, *testHarness)
		status int
	}{
		"update":                           {http.MethodPut, workspacesPath + "/ws_alpha", `{"name":"Beta","description":"new","retention_policy_id":""}`, "update", nil, http.StatusOK},
		"archive":                          {http.MethodPost, workspacesPath + "/ws_alpha:archive", "", "archive", nil, http.StatusOK},
		"add member":                       {http.MethodPost, workspacesPath + "/ws_alpha/members", `{"principal_id":"usr_bob","role":"MEMBER"}`, "add_member", nil, http.StatusOK},
		"change role":                      {http.MethodPut, workspacesPath + "/ws_alpha/members/usr_bob", `{"role":"VIEWER"}`, "change_member_role", nil, http.StatusOK},
		"remove member":                    {http.MethodDelete, workspacesPath + "/ws_alpha/members/usr_bob", "", "remove_member", nil, http.StatusOK},
		"transfer":                         {http.MethodPost, workspacesPath + "/ws_alpha:transfer-ownership", `{"new_owner_principal_id":"usr_bob"}`, "transfer_ownership", nil, http.StatusOK},
		"missing if match":                 {http.MethodPut, workspacesPath + "/ws_alpha", `{"name":"Beta","description":"new","retention_policy_id":""}`, "", func(request *http.Request, _ *testHarness) { request.Header.Del("If-Match") }, http.StatusPreconditionRequired},
		"malformed if match":               {http.MethodPut, workspacesPath + "/ws_alpha", `{"name":"Beta","description":"new","retention_policy_id":""}`, "", func(request *http.Request, _ *testHarness) { request.Header.Set("If-Match", `W/"sha256:wrong"`) }, http.StatusBadRequest},
		"duplicate if match":               {http.MethodPut, workspacesPath + "/ws_alpha", `{"name":"Beta","description":"new","retention_policy_id":""}`, "", func(request *http.Request, h *testHarness) { request.Header["if-match"] = []string{`"` + h.hash + `"`} }, http.StatusBadRequest},
		"bodyless archive rejects content": {http.MethodPost, workspacesPath + "/ws_alpha:archive", `{}`, "", nil, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(fixture.method, fixture.path, fixture.body)
			harness.mutationHeaders(request, harness.hash)
			if fixture.setup != nil {
				fixture.setup(request, harness)
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != fixture.status || harness.service.call != fixture.call {
				t.Fatalf("status=%d call=%q want=%q body=%s", response.Code, harness.service.call, fixture.call, response.Body.String())
			}
			if fixture.call != "" && response.Header().Get("ETag") != `"`+harness.hash+`"` {
				t.Fatalf("missing ETag: %#v", response.Header())
			}
		})
	}
}

func TestGetListAndCSRFBootstrap(t *testing.T) {
	harness := newTestHarness(t)
	for name, fixture := range map[string]struct {
		method string
		path   string
		call   string
	}{
		"csrf": {http.MethodGet, csrfPath, ""},
		"list": {http.MethodGet, workspacesPath, "list"},
		"get":  {http.MethodGet, workspacesPath + "/ws_alpha", "get"},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			request := harness.request(fixture.method, fixture.path, "")
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || harness.service.call != fixture.call {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
			}
			if name == "csrf" && (!strings.Contains(response.Body.String(), "csrf_token") || strings.Contains(response.Body.String(), harness.token)) {
				t.Fatalf("csrf bootstrap response is wrong: %s", response.Body.String())
			}
			harness.service.call = ""
		})
	}
}

func TestQuestionRoutesUseAuthorityAndRejectUnknownEnvelope(t *testing.T) {
	harness := newTestHarness(t)
	harness.questions.run.ConversationID = "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	harness.questions.run.ConversationTurnID = "turn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?","conversation_id":"conv_01ARZ3NDEKTSV4RRFFQ69G5FAV","answer_mode":"EXTRACTIVE"}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.questions.call != "create" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}
	if harness.questions.request.WorkspaceID != "ws_alpha" || harness.questions.request.ConversationID != "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV" || harness.questions.request.IdempotencyKey == "" || harness.questions.access.RequestID != "req_server_001" {
		t.Fatalf("question authority context=%#v request=%#v", harness.questions.access, harness.questions.request)
	}
	if !strings.Contains(response.Body.String(), `"question_run_id"`) || strings.Contains(response.Body.String(), "How many?") == false ||
		!strings.Contains(response.Body.String(), `"conversation_id"`) || !strings.Contains(response.Body.String(), `"conversation_turn_id"`) ||
		!strings.Contains(response.Body.String(), `"uncertainties":[]`) || !strings.Contains(response.Body.String(), `"conflicts":[]`) {
		t.Fatalf("question response=%s", response.Body.String())
	}

	request = harness.request(http.MethodGet, workspacesPath+"/ws_alpha/questions/qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV", "")
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.questions.call != "get" || harness.questions.runID != "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("get status=%d call=%q id=%q body=%s", response.Code, harness.questions.call, harness.questions.runID, response.Body.String())
	}

	request = harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?","extra":true}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	harness.questions.call = ""
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || harness.questions.call != "" {
		t.Fatalf("unknown-member status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}

	// GEN-1 (ADR-0088): GENERATIVE is a real mode. The transport boundary only
	// rejects a mode outside the closed {EXTRACTIVE, GENERATIVE} vocabulary
	// before touching the injected authority; question.Service is the sole
	// place that decides whether the capability is actually wired
	// (question.CodeUnsupportedMode otherwise, asserted below).
	request = harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?","answer_mode":"GENERATIVE"}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	harness.questions.call = ""
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.questions.call != "create" || harness.questions.request.AnswerMode != "GENERATIVE" {
		t.Fatalf("GENERATIVE did not reach the authority: status=%d call=%q mode=%q body=%s", response.Code, harness.questions.call, harness.questions.request.AnswerMode, response.Body.String())
	}

	request = harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?","answer_mode":"SUMMARY"}`)
	request.Header.Set("Content-Type", jsonContentType)
	harness.mutationHeaders(request, harness.hash)
	request.Header.Del("If-Match")
	harness.questions.call = ""
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || harness.questions.call != "" {
		t.Fatalf("unknown answer mode reached authority: status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}
}

func TestMCPAdapterUsesQuestionAuthority(t *testing.T) {
	harness := newTestHarness(t)
	harness.questions.run.ConversationID = "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	harness.questions.run.ConversationTurnID = "turn_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	request := harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"protocolVersion"`) {
		t.Fatalf("initialize status=%d body=%s", response.Code, response.Body.String())
	}
	harness.questions.run.Answer = "12.3"
	harness.questions.call = ""
	request = harness.request(http.MethodPost, apiPrefix+"/mcp", "{\"jsonrpc\":\"2.0\",\"id\":\"q1\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_question\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"conversation_id\":\"conv_01ARZ3NDEKTSV4RRFFQ69G5FAV\",\"question\":\"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?\"}}}")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.questions.call != "create" || !strings.Contains(response.Body.String(), `"structuredContent"`) || !strings.Contains(response.Body.String(), "12.3") ||
		!strings.Contains(response.Body.String(), `"conversation_id"`) || !strings.Contains(response.Body.String(), `"conversation_turn_id"`) ||
		!strings.Contains(response.Body.String(), `"uncertainties":[]`) || !strings.Contains(response.Body.String(), `"conflicts":[]`) {
		t.Fatalf("tool call status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"isError":false`) {
		t.Fatalf("completed Question Run was reported as MCP error: %s", response.Body.String())
	}
	if harness.questions.request.WorkspaceID != "ws_alpha" || harness.questions.request.ConversationID != "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("tool call request=%#v", harness.questions.request)
	}
}

func TestMCPAdapterReturnsJSONRPCErrorForMalformedEnvelope(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":`)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"jsonrpc":"2.0"`) || !strings.Contains(response.Body.String(), `"code":-32600`) {
		t.Fatalf("malformed MCP envelope did not return JSON-RPC invalid-request error: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestConversationRoutesUseOneAuthorizedProjection(t *testing.T) {
	harness := newTestHarness(t)
	harness.conversations.view = conversation.View{ID: "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV", WorkspaceID: "ws_alpha", WorkspaceRevision: 1, CreatedBy: "usr_alice", CreatedAt: time.Now().UTC(), Turns: []conversation.Turn{{ID: "turn_01ARZ3NDEKTSV4RRFFQ69G5FAV", QuestionRunID: "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV", TurnIndex: 1, CreatedAt: time.Now().UTC()}}}
	harness.conversations.list = []conversation.View{harness.conversations.view}
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.conversations.call != "list" || !strings.Contains(response.Body.String(), `"conversations"`) || !strings.Contains(response.Body.String(), `"question_run"`) {
		t.Fatalf("list status=%d call=%q body=%s", response.Code, harness.conversations.call, response.Body.String())
	}
	harness.conversations.call = ""
	request = harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations/conv_01ARZ3NDEKTSV4RRFFQ69G5FAV", "")
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.conversations.call != "get" || !strings.Contains(response.Body.String(), `"conversation_id"`) || !strings.Contains(response.Body.String(), `"question_run"`) {
		t.Fatalf("get status=%d call=%q body=%s", response.Code, harness.conversations.call, response.Body.String())
	}
	harness.conversations.call = ""
	request = harness.request(http.MethodPost, workspacesPath+"/ws_alpha/conversations/conv_01ARZ3NDEKTSV4RRFFQ69G5FAV:archive", "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	request.Header.Del("If-Match")
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.conversations.call != "archive" || harness.conversations.archiveRequest.ConversationID != "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV" || !strings.Contains(response.Body.String(), `"archived_at"`) {
		t.Fatalf("archive status=%d call=%q request=%#v body=%s", response.Code, harness.conversations.call, harness.conversations.archiveRequest, response.Body.String())
	}
}

func TestConversationListReturnsEmptyPageWithoutQuestionProjection(t *testing.T) {
	harness := newTestHarness(t)
	harness.conversations.list = []conversation.View{}
	harness.questions.err = errors.New("question projection must not run for an empty conversation page")
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "{\"conversations\":[]}" {
		t.Fatalf("empty list status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMCPConversationToolsShareProjectionAndArchiveAuthority(t *testing.T) {
	harness := newTestHarness(t)
	harness.conversations.list = []conversation.View{{ID: "conv_01ARZ3NDEKTSV4RRFFQ69G5FAV", WorkspaceID: "ws_alpha", WorkspaceRevision: 1, CreatedBy: "usr_alice", CreatedAt: time.Now().UTC(), Turns: []conversation.Turn{}}}
	request := harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	for _, name := range []string{"knowvault_question", "knowvault_conversations_list", "knowvault_conversation_get", "knowvault_conversation_archive"} {
		if !strings.Contains(response.Body.String(), name) {
			t.Fatalf("tools/list omitted %q: %s", name, response.Body.String())
		}
	}
	request = harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"knowvault_conversations_list","arguments":{"workspace_id":"ws_alpha"}}}`)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"structuredContent"`) || !strings.Contains(response.Body.String(), `"conversations"`) || harness.conversations.call != "list" {
		t.Fatalf("MCP list status=%d call=%q body=%s", response.Code, harness.conversations.call, response.Body.String())
	}
	harness.conversations.call = ""
	request = harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"knowvault_conversation_archive","arguments":{"workspace_id":"ws_alpha","conversation_id":"conv_01ARZ3NDEKTSV4RRFFQ69G5FAV"}}}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response = httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.conversations.call != "archive" || !strings.Contains(response.Body.String(), `"structuredContent"`) {
		t.Fatalf("MCP archive status=%d call=%q body=%s", response.Code, harness.conversations.call, response.Body.String())
	}
}

func TestInvalidRoutesQueriesAndMethodsDoNotReachService(t *testing.T) {
	for name, fixture := range map[string]struct {
		path       string
		wantStatus int
	}{
		"query":          {workspacesPath + "?page=1", http.StatusBadRequest},
		"empty query":    {workspacesPath + "?", http.StatusBadRequest},
		"encoded slash":  {workspacesPath + "/ws_alpha%2Fother", http.StatusNotFound},
		"backslash":      {workspacesPath + "\\ws_alpha", http.StatusNotFound},
		"trailing slash": {workspacesPath + "/", http.StatusNotFound},
		"invalid id":     {workspacesPath + "/x", http.StatusNotFound},
		"unknown":        {apiPrefix + "/unknown", http.StatusNotFound},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodGet, fixture.path, "")
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || harness.service.call != "" || harness.auth.authenticateCalls != 0 {
				t.Fatalf("status=%d call=%q auth=%d", response.Code, harness.service.call, harness.auth.authenticateCalls)
			}
		})
	}

	harness := newTestHarness(t)
	request := harness.request(http.MethodPatch, workspacesPath+"/ws_alpha", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || harness.service.call != "" || harness.auth.authenticateCalls != 1 || harness.auth.csrfCalls != 1 || response.Header().Get("Allow") != http.MethodPut {
		t.Fatalf("method response status=%d call=%q auth=%d csrf=%d allow=%q", response.Code, harness.service.call, harness.auth.authenticateCalls, harness.auth.csrfCalls, response.Header().Get("Allow"))
	}
}

func TestRepositoryFailuresHaveContentFreePublicMapping(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.err = errors.New("database host includes sensitive detail")
	request := harness.request(http.MethodGet, workspacesPath, "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "sensitive") || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Request-ID") != "req_server_001" {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestServiceErrorMappingPreservesPreconditionsAndResourceNonEnumeration(t *testing.T) {
	deniedStatus, deniedCode := serviceErrorResponse(workspacerepository.CodeDenied, false)
	notFoundStatus, notFoundCode := serviceErrorResponse(workspacerepository.CodeNotFound, false)
	if deniedStatus != http.StatusNotFound || deniedStatus != notFoundStatus || deniedCode != "NOT_FOUND" || deniedCode != notFoundCode {
		t.Fatalf("denied=%d/%q not-found=%d/%q", deniedStatus, deniedCode, notFoundStatus, notFoundCode)
	}
	if status, code := serviceErrorResponse(workspacerepository.CodeRevisionConflict, false); status != http.StatusPreconditionFailed || code != "WORKSPACE_REVISION_CONFLICT" {
		t.Fatalf("revision conflict=%d/%q", status, code)
	}
	if status, code := serviceErrorResponse(workspacerepository.CodeIdempotencyConflict, false); status != http.StatusConflict || code != "WORKSPACE_IDEMPOTENCY_CONFLICT" {
		t.Fatalf("idempotency conflict=%d/%q", status, code)
	}
	if status, code := serviceErrorResponse(workspacerepository.CodeDenied, true); status != http.StatusForbidden || code != "FORBIDDEN" {
		t.Fatalf("create denial=%d/%q", status, code)
	}
}

func TestRequestIDFailureDoesNotAuthenticateCallServiceOrEchoClientValue(t *testing.T) {
	harness := newTestHarness(t)
	handler, err := newHandler(harness.auth, harness.service, harness.sources, harness.evidence, failingRequestIDSource{})
	if err != nil {
		t.Fatal(err)
	}
	request := harness.request(http.MethodGet, workspacesPath, "")
	request.Header.Set("X-Request-ID", "client-controlled")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || harness.auth.authenticateCalls != 0 || harness.service.call != "" || response.Header().Get("X-Request-ID") != "" || strings.Contains(response.Body.String(), "client-controlled") {
		t.Fatalf("status=%d auth=%d service=%q headers=%#v body=%s", response.Code, harness.auth.authenticateCalls, harness.service.call, response.Header(), response.Body.String())
	}
}

func TestBodylessMutationsApplyEncodingAndSizeGate(t *testing.T) {
	for name, fixture := range map[string]struct {
		configure  func(*http.Request)
		wantStatus int
	}{
		"content encoding": {func(request *http.Request) { request.Header.Set("Content-Encoding", "gzip") }, http.StatusBadRequest},
		"declared too large": {func(request *http.Request) {
			request.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxBodyBytes+1)))
			request.ContentLength = maxBodyBytes + 1
		}, http.StatusRequestEntityTooLarge},
		"chunked too large": {func(request *http.Request) {
			request.Body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxBodyBytes+1)))
			request.ContentLength = -1
		}, http.StatusRequestEntityTooLarge},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha:archive", "")
			harness.mutationHeaders(request, harness.hash)
			fixture.configure(request)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || harness.service.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
			}
		})
	}
}

func TestCryptoRequestIDsAreOpaqueAndNotClientSupplied(t *testing.T) {
	source := cryptoRequestIDSource{}
	first, err := source.New()
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.New()
	if err != nil || !validRequestID(first) || !validRequestID(second) || first == second {
		t.Fatalf("request IDs=%q/%q err=%v", first, second, err)
	}
}

type testHarness struct {
	handler        *Handler
	auth           *authSpy
	service        *fakeWorkspaceService
	sources        *fakeSourceService
	evidence       *fakeEvidenceService
	questions      *fakeQuestionService
	conversations  *fakeConversationService
	token          string
	csrf           string
	hash           string
	idempotencyKey string
}

func newTestHarness(t *testing.T) *testHarness {
	t.Helper()
	token := testOpaqueToken("session")
	digestor := &testDigestor{}
	proof, err := digestor.Digest("csrf", token)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := identity.NewClaims("org_alpha", "usr_alice", 1, "idp_alpha", 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := httpauth.New(testTenantResolver{digestor: digestor}, testSessionResolver{claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	service := &fakeWorkspaceService{snapshot: testSnapshot(t)}
	sources := &fakeSourceService{}
	evidence := &fakeEvidenceService{}
	questions := &fakeQuestionService{run: question.Run{ID: "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV", WorkspaceID: "ws_alpha", Question: "How many?", AnswerMode: "EXTRACTIVE", VerificationMethod: "BYTE_EXACT_CITATION", ResultStatus: "COMPLETED", Citations: []question.Citation{}, Uncertainties: []question.Uncertainty{}, Conflicts: []question.Conflict{}}}
	conversations := &fakeConversationService{}
	spy := &authSpy{delegate: authenticator}
	handler, err := newHandlerWithQuestionsAndConversations(spy, service, sources, evidence, questions, conversations, fixedRequestIDSource("req_server_001"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := workspace.ConfigurationHash(service.snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return &testHarness{handler: handler, auth: spy, service: service, sources: sources, evidence: evidence, questions: questions, conversations: conversations, token: token, csrf: proof.Value(), hash: hash, idempotencyKey: testOpaqueToken("idempotency")}
}

func (harness *testHarness) request(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example"+path, strings.NewReader(body))
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+harness.token)
	if body != "" {
		request.Header.Set("Content-Type", jsonContentType)
	}
	if unsafeMethod(method) {
		request.Header.Set("Origin", "https://workspace.example")
		request.Header.Set(httpauth.CSRFHeader, harness.csrf)
	}
	return request
}

func (harness *testHarness) mutationHeaders(request *http.Request, hash string) {
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	if request.Method != http.MethodPost || request.URL.EscapedPath() != workspacesPath {
		request.Header.Set("If-Match", `"`+hash+`"`)
	}
}

type fixedRequestIDSource string

func (source fixedRequestIDSource) New() (string, error) { return string(source), nil }

type failingRequestIDSource struct{}

func (failingRequestIDSource) New() (string, error) { return "", errors.New("entropy unavailable") }

type authSpy struct {
	delegate          *httpauth.Authenticator
	authenticateCalls int
	csrfCalls         int
	authenticateErr   error
	csrfErr           error
}

func (spy *authSpy) Authenticate(request *http.Request, requestID string) (httpauth.Authentication, error) {
	spy.authenticateCalls++
	if spy.authenticateErr != nil {
		return httpauth.Authentication{}, spy.authenticateErr
	}
	return spy.delegate.Authenticate(request, requestID)
}

func (spy *authSpy) VerifyCSRF(request *http.Request, authentication httpauth.Authentication) error {
	spy.csrfCalls++
	if spy.csrfErr != nil {
		return spy.csrfErr
	}
	return spy.delegate.VerifyCSRF(request, authentication)
}

func (spy *authSpy) RefreshCookie(writer http.ResponseWriter, request *http.Request, authentication httpauth.Authentication) error {
	return spy.delegate.RefreshCookie(writer, request, authentication)
}

type testTenantResolver struct{ digestor httpauth.Digestor }

func (resolver testTenantResolver) Resolve(context.Context) (httpauth.TenantSecurityContext, error) {
	return httpauth.TenantSecurityContext{OrganizationID: "org_alpha", Origin: "https://workspace.example", Digestor: resolver.digestor}, nil
}

type testSessionResolver struct{ claims identity.Claims }

func (resolver testSessionResolver) ResolveSession(_ context.Context, request identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	return identityrepository.AuthenticatedSession{
		SessionID: "ses_alpha", Claims: resolver.claims,
		Access: database.AccessContext{OrganizationID: string(request.OrganizationID), PrincipalID: string(resolver.claims.PrincipalID()), RequestID: request.RequestID},
	}, nil
}

type testDigestor struct{}

func (testDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	if purpose != "session_token" && purpose != "csrf" {
		return identity.KeyedDigest{}, errors.New("invalid purpose")
	}
	digest := sha256.Sum256([]byte(purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + fmt.Sprintf("%x", digest[:]))
}

type fakeWorkspaceService struct {
	call                    string
	access                  database.AccessContext
	err                     error
	snapshot                workspace.Snapshot
	list                    []workspacerepository.Summary
	journal                 audit.Journal
	journalWorkspaceID      string
	createRequest           workspacerepository.CreateRequest
	updateRequest           workspacerepository.UpdateRequest
	archiveRequest          workspacerepository.ArchiveRequest
	addMemberRequest        workspacerepository.AddMemberRequest
	changeMemberRoleRequest workspacerepository.ChangeMemberRoleRequest
	removeMemberRequest     workspacerepository.RemoveMemberRequest
	transferRequest         workspacerepository.TransferOwnershipRequest
	addSourceRequest        workspacerepository.AddSourceRequest
	removeSourceRequest     workspacerepository.RemoveSourceRequest
}

type fakeQuestionService struct {
	call        string
	access      database.AccessContext
	request     question.CreateRequest
	run         question.Run
	runID       string
	err         error
	rowset      *question.RowsetEvidence
	rowsetErr   error
	rowsetCalls []fakeStructuredRowsetCall
}

type fakeStructuredRowsetCall struct {
	access      database.AccessContext
	workspaceID string
	fragmentID  string
	scope       string
}

type fakeConversationService struct {
	call           string
	access         database.AccessContext
	list           []conversation.View
	view           conversation.View
	archiveRequest conversation.ArchiveRequest
	err            error
}

func (service *fakeConversationService) List(_ context.Context, access database.AccessContext, _ string) ([]conversation.View, error) {
	service.call, service.access = "list", access
	return service.list, service.err
}

func (service *fakeConversationService) Get(_ context.Context, access database.AccessContext, _, _ string) (conversation.View, error) {
	service.call, service.access = "get", access
	return service.view, service.err
}

func (service *fakeConversationService) Archive(_ context.Context, access database.AccessContext, request conversation.ArchiveRequest) (conversation.View, error) {
	service.call, service.access, service.archiveRequest = "archive", access, request
	if service.view.ArchivedAt == nil {
		now := time.Now().UTC()
		service.view.ArchivedAt = &now
	}
	return service.view, service.err
}

func (service *fakeQuestionService) Create(_ context.Context, access database.AccessContext, request question.CreateRequest) (question.Run, error) {
	service.call, service.access, service.request = "create", access, request
	return service.run, service.err
}

func (service *fakeQuestionService) Get(_ context.Context, access database.AccessContext, workspaceID, runID string) (question.Run, error) {
	service.call, service.access, service.runID = "get", access, runID
	if service.run.WorkspaceID == "" {
		service.run.WorkspaceID = workspaceID
	}
	return service.run, service.err
}

func (service *fakeQuestionService) GetBatch(_ context.Context, access database.AccessContext, workspaceID string, runIDs []string) (map[string]question.Run, error) {
	service.call, service.access = "getbatch", access
	if service.err != nil {
		return nil, service.err
	}
	result := make(map[string]question.Run, len(runIDs))
	for _, runID := range runIDs {
		run := service.run
		if run.WorkspaceID == "" {
			run.WorkspaceID = workspaceID
		}
		run.ID = runID
		result[runID] = run
	}
	return result, nil
}

func (service *fakeQuestionService) ProcessingMode(string) (string, string) {
	return question.ProcessingModeInternalUnavailable, ""
}

func (service *fakeQuestionService) StructuredRowset(_ context.Context, access database.AccessContext, workspaceID, fragmentID, scope string) (*question.RowsetEvidence, error) {
	service.call, service.access = "structured_rowset", access
	service.rowsetCalls = append(service.rowsetCalls, fakeStructuredRowsetCall{
		access: access, workspaceID: workspaceID, fragmentID: fragmentID, scope: scope,
	})
	return service.rowset, service.rowsetErr
}

func (service *fakeWorkspaceService) save(call string, access database.AccessContext) error {
	service.call, service.access = call, access
	return service.err
}

func (service *fakeWorkspaceService) Create(_ context.Context, access database.AccessContext, request workspacerepository.CreateRequest) (workspace.Snapshot, error) {
	service.createRequest = request
	return service.snapshot, service.save("create", access)
}
func (service *fakeWorkspaceService) Get(_ context.Context, access database.AccessContext, _ string) (workspace.Snapshot, error) {
	return service.snapshot, service.save("get", access)
}
func (service *fakeWorkspaceService) List(_ context.Context, access database.AccessContext) ([]workspacerepository.Summary, error) {
	err := service.save("list", access)
	return service.list, err
}
func (service *fakeWorkspaceService) Update(_ context.Context, access database.AccessContext, request workspacerepository.UpdateRequest) (workspace.Snapshot, error) {
	service.updateRequest = request
	return service.snapshot, service.save("update", access)
}
func (service *fakeWorkspaceService) Archive(_ context.Context, access database.AccessContext, request workspacerepository.ArchiveRequest) (workspace.Snapshot, error) {
	service.archiveRequest = request
	return service.snapshot, service.save("archive", access)
}
func (service *fakeWorkspaceService) AddMember(_ context.Context, access database.AccessContext, request workspacerepository.AddMemberRequest) (workspace.Snapshot, error) {
	service.addMemberRequest = request
	return service.snapshot, service.save("add_member", access)
}
func (service *fakeWorkspaceService) ChangeMemberRole(_ context.Context, access database.AccessContext, request workspacerepository.ChangeMemberRoleRequest) (workspace.Snapshot, error) {
	service.changeMemberRoleRequest = request
	return service.snapshot, service.save("change_member_role", access)
}
func (service *fakeWorkspaceService) RemoveMember(_ context.Context, access database.AccessContext, request workspacerepository.RemoveMemberRequest) (workspace.Snapshot, error) {
	service.removeMemberRequest = request
	return service.snapshot, service.save("remove_member", access)
}
func (service *fakeWorkspaceService) TransferOwnership(_ context.Context, access database.AccessContext, request workspacerepository.TransferOwnershipRequest) (workspace.Snapshot, error) {
	service.transferRequest = request
	return service.snapshot, service.save("transfer_ownership", access)
}
func (service *fakeWorkspaceService) AddSource(_ context.Context, access database.AccessContext, request workspacerepository.AddSourceRequest) (workspace.Snapshot, error) {
	service.addSourceRequest = request
	return service.snapshot, service.save("add_source", access)
}
func (service *fakeWorkspaceService) RemoveSource(_ context.Context, access database.AccessContext, request workspacerepository.RemoveSourceRequest) (workspace.Snapshot, error) {
	service.removeSourceRequest = request
	return service.snapshot, service.save("remove_source", access)
}
func (service *fakeWorkspaceService) AuditJournal(_ context.Context, access database.AccessContext, workspaceID string) (audit.Journal, error) {
	service.journalWorkspaceID = workspaceID
	err := service.save("audit_journal", access)
	return service.journal, err
}

func testSnapshot(t *testing.T) workspace.Snapshot {
	t.Helper()
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 1, Name: "Alpha", Description: "", Status: workspace.StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []workspace.Member{{PrincipalID: "usr_alice", Role: workspace.RoleOwner, DisplayName: "Alice"}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func testOpaqueToken(label string) string {
	digest := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
