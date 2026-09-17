package postgres_test

// This acceptance proof crosses the authenticated REST and MCP boundaries
// with the same live Question, conversation, workspace and Evidence services
// used by the composition root.  The JSON-path aggregate is replayed through
// both transports over the real PostgreSQL projection; no transport branch
// owns a planner or data fixture.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

type r22SourceService struct {
	registrations *registration.Service
	workspaces    *workspacerepository.Store
}

func (service r22SourceService) Register(ctx context.Context, access database.AccessContext, request registration.RegisterRequest) (registration.RegisterResult, error) {
	return service.registrations.Register(ctx, access, request)
}

func (service r22SourceService) Activate(ctx context.Context, access database.AccessContext, request registration.ActivateRequest) (registration.ActivateResult, error) {
	return service.registrations.Activate(ctx, access, request)
}

func (service r22SourceService) Sync(ctx context.Context, access database.AccessContext, request registration.SyncRequest) (registration.SyncResult, error) {
	return service.registrations.Sync(ctx, access, request)
}

func (service r22SourceService) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	return service.workspaces.ListSources(ctx, access, workspaceID)
}

func (service r22SourceService) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (workspacerepository.ConfirmationContext, error) {
	return service.workspaces.ConfirmationContext(ctx, access, workspaceID)
}

func (service r22SourceService) UploadDocuments(ctx context.Context, access database.AccessContext, request registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return service.registrations.UploadDocuments(ctx, access, request)
}

type r22Digestor struct{}

func (r22Digestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	if purpose != "session_token" && purpose != "csrf" {
		return identity.KeyedDigest{}, errors.New("unsupported digest purpose")
	}
	digest := sha256.Sum256([]byte(purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + hex.EncodeToString(digest[:]))
}

type r22TenantResolver struct{}

func (r22TenantResolver) Resolve(context.Context) (httpauth.TenantSecurityContext, error) {
	return httpauth.TenantSecurityContext{
		OrganizationID: identity.OrganizationID(regOrg),
		Origin:         "https://workspace.example",
		Digestor:       r22Digestor{},
	}, nil
}

type r22SessionResolver struct {
	claims identity.Claims
}

func (resolver r22SessionResolver) ResolveSession(_ context.Context, request identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	return identityrepository.AuthenticatedSession{
		SessionID: "ses_r22_jsonpath",
		Claims:    resolver.claims,
		Access: database.AccessContext{
			OrganizationID: string(request.OrganizationID),
			PrincipalID:    string(resolver.claims.PrincipalID()),
			RequestID:      request.RequestID,
		},
	}, nil
}

func r22Claims(t *testing.T, principal string) identity.Claims {
	t.Helper()
	claims, err := identity.NewClaims(identity.OrganizationID(regOrg), identity.PrincipalID(principal), 1, identity.ProviderID("idp_r22"), 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatalf("r22 claims: %v", err)
	}
	return claims
}

type r22RESTConversationList struct {
	Conversations []r22RESTConversation `json:"conversations"`
}

type r22RESTConversation struct {
	ConversationID    string                    `json:"conversation_id"`
	WorkspaceID       string                    `json:"workspace_id"`
	WorkspaceRevision int64                     `json:"workspace_revision"`
	CreatedBy         string                    `json:"created_by"`
	CreatedAt         time.Time                 `json:"created_at"`
	ArchivedAt        *time.Time                `json:"archived_at,omitempty"`
	Turns             []r22RESTConversationTurn `json:"turns"`
}

type r22RESTConversationTurn struct {
	TurnID        string        `json:"turn_id"`
	QuestionRunID string        `json:"question_run_id"`
	TurnIndex     int64         `json:"turn_index"`
	CreatedAt     time.Time     `json:"created_at"`
	QuestionRun   *question.Run `json:"question_run,omitempty"`
}

type r22MCPResponse struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id"`
	Result  r22MCPResult   `json:"result,omitempty"`
	Error   *r22MCPError   `json:"error,omitempty"`
}

type r22MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type r22MCPResult struct {
	StructuredContent jsontext.Value `json:"structuredContent,omitempty"`
	IsError           bool           `json:"isError,omitempty"`
}

// assertJSONPathRESTMCPParity proves the public adapters are projections over
// one server-owned run. It also proves the safe UNKNOWN terminal shape and a
// real workspace MEMBER request through REST.
func assertJSONPathRESTMCPParity(t *testing.T, ctx context.Context, appStore *database.Store, authority *workspacerepository.Store, registrations *registration.Service, evidenceViewer *evidence.Viewer, questions *question.Service, questionText string, direct question.Run) {
	t.Helper()

	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("r22 audit store: %v", err)
	}
	conversations, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("r22 conversation service: %v", err)
	}
	sources := r22SourceService{registrations: registrations, workspaces: authority}

	newHandler := func(principal string) *workspaceapi.Handler {
		authenticator, authErr := httpauth.New(r22TenantResolver{}, r22SessionResolver{claims: r22Claims(t, principal)})
		if authErr != nil {
			t.Fatalf("r22 authenticator for %s: %v", principal, authErr)
		}
		handler, handlerErr := workspaceapi.NewWithQuestionsAndConversations(authenticator, authority, sources, evidenceViewer, questions, conversations)
		if handlerErr != nil {
			t.Fatalf("r22 workspace handler for %s: %v", principal, handlerErr)
		}
		return handler
	}
	handler := newHandler(regOwner)
	rawToken := make([]byte, sha256.Size)
	for index := range rawToken {
		rawToken[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	digest, err := (r22Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("r22 csrf digest: %v", err)
	}

	rest := func(target *workspaceapi.Handler, method, path, body, idempotencyKey string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "https://workspace.example"+path, strings.NewReader(body))
		request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		if method != http.MethodGet {
			request.Header.Set("Origin", "https://workspace.example")
			request.Header.Set(httpauth.CSRFHeader, digest.Value())
		}
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
		response := httptest.NewRecorder()
		target.ServeHTTP(response, request)
		return response
	}

	mcp := func(target *workspaceapi.Handler, body []byte, idempotencyKey string) r22MCPResponse {
		request := httptest.NewRequest(http.MethodPost, "https://workspace.example/api/v1/mcp", strings.NewReader(string(body)))
		request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://workspace.example")
		request.Header.Set(httpauth.CSRFHeader, digest.Value())
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
		response := httptest.NewRecorder()
		target.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
		}
		var envelope r22MCPResponse
		if err := jsonv2.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode MCP response: %v body=%s", err, response.Body.String())
		}
		if envelope.Error != nil {
			t.Fatalf("MCP error code=%d message=%s", envelope.Error.Code, envelope.Error.Message)
		}
		return envelope
	}
	mcpAllowError := func(target *workspaceapi.Handler, body []byte, idempotencyKey string) r22MCPResponse {
		request := httptest.NewRequest(http.MethodPost, "https://workspace.example/api/v1/mcp", strings.NewReader(string(body)))
		request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "https://workspace.example")
		request.Header.Set(httpauth.CSRFHeader, digest.Value())
		if idempotencyKey != "" {
			request.Header.Set("Idempotency-Key", idempotencyKey)
		}
		response := httptest.NewRecorder()
		target.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
		}
		var envelope r22MCPResponse
		if err := jsonv2.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode MCP response: %v body=%s", err, response.Body.String())
		}
		return envelope
	}

	questionPath := "/api/v1/workspaces/" + regWorkspace + "/questions"
	questionBody, err := jsonv2.Marshal(map[string]any{"question": questionText, "answer_mode": "EXTRACTIVE"})
	if err != nil {
		t.Fatalf("marshal REST question: %v", err)
	}
	replayKey := isolationQuestionKey("json-path-multi-group")
	restResponse := rest(handler, http.MethodPost, questionPath, string(questionBody), replayKey)
	if restResponse.Code != http.StatusOK {
		t.Fatalf("REST question status=%d body=%s", restResponse.Code, restResponse.Body.String())
	}
	var restRun question.Run
	if err := jsonv2.Unmarshal(restResponse.Body.Bytes(), &restRun); err != nil {
		t.Fatalf("decode REST question: %v body=%s", err, restResponse.Body.String())
	}
	if restRun.ID != direct.ID || restRun.ResultStatus != "COMPLETED" || restRun.PlanningOperation != "AGGREGATE" || restRun.Answer != direct.Answer || len(restRun.Citations) != 7 {
		t.Fatalf("REST projection drifted: direct=%+v rest=%+v", direct, restRun)
	}
	for _, citation := range restRun.Citations {
		if citation.EvidenceFragment == "" || citation.DeepLink == "" || citation.SourceVersionID == "" || citation.Anchor == "" || !strings.Contains(citation.Anchor, `"json_path":"/`) {
			t.Fatalf("REST citation is not Evidence-bound: %+v", citation)
		}
	}

	mcpQuestionBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "r22-jsonpath-question", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_question", "arguments": map[string]any{
			"workspace_id": regWorkspace, "question": questionText, "answer_mode": "EXTRACTIVE",
		}},
	})
	if err != nil {
		t.Fatalf("marshal MCP question: %v", err)
	}
	mcpQuestion := mcp(handler, mcpQuestionBody, replayKey)
	if mcpQuestion.Result.IsError || len(mcpQuestion.Result.StructuredContent) == 0 {
		t.Fatalf("MCP question marked error or omitted structured content: %+v", mcpQuestion)
	}
	var mcpRun question.Run
	if err := jsonv2.Unmarshal(mcpQuestion.Result.StructuredContent, &mcpRun); err != nil {
		t.Fatalf("decode MCP question projection: %v", err)
	}
	if !reflect.DeepEqual(restRun, mcpRun) {
		t.Fatalf("REST/MCP question projections differ: rest=%+v mcp=%+v", restRun, mcpRun)
	}

	unknownKey := isolationQuestionKey("json-path-rest-mcp-unknown")
	unknownBody, err := jsonv2.Marshal(map[string]any{"question": "???", "answer_mode": "EXTRACTIVE"})
	if err != nil {
		t.Fatalf("marshal REST unknown question: %v", err)
	}
	unknownResponse := rest(handler, http.MethodPost, questionPath, string(unknownBody), unknownKey)
	if unknownResponse.Code != http.StatusOK {
		t.Fatalf("REST unknown status=%d body=%s", unknownResponse.Code, unknownResponse.Body.String())
	}
	var restUnknown question.Run
	if err := jsonv2.Unmarshal(unknownResponse.Body.Bytes(), &restUnknown); err != nil {
		t.Fatalf("decode REST unknown: %v", err)
	}
	if restUnknown.PlanningStatus != "UNKNOWN" || restUnknown.PlanningOperation != "UNKNOWN" || restUnknown.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(restUnknown.Citations) != 0 || len(restUnknown.Uncertainties) != 1 || restUnknown.Uncertainties[0].Code != question.UncertaintyPlannerUnknown {
		t.Fatalf("REST unknown was not fail-closed: %+v", restUnknown)
	}
	unknownMCPBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "r22-jsonpath-unknown", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_question", "arguments": map[string]any{
			"workspace_id": regWorkspace, "question": "???", "answer_mode": "EXTRACTIVE",
		}},
	})
	if err != nil {
		t.Fatalf("marshal MCP unknown question: %v", err)
	}
	unknownMCP := mcp(handler, unknownMCPBody, unknownKey)
	if !unknownMCP.Result.IsError || len(unknownMCP.Result.StructuredContent) == 0 {
		t.Fatalf("MCP unknown did not expose safe terminal result: %+v", unknownMCP)
	}
	var mcpUnknown question.Run
	if err := jsonv2.Unmarshal(unknownMCP.Result.StructuredContent, &mcpUnknown); err != nil {
		t.Fatalf("decode MCP unknown: %v", err)
	}
	if !reflect.DeepEqual(restUnknown, mcpUnknown) {
		t.Fatalf("REST/MCP UNKNOWN projections differ: rest=%+v mcp=%+v", restUnknown, mcpUnknown)
	}

	conversationResponse := rest(handler, http.MethodGet, "/api/v1/workspaces/"+regWorkspace+"/conversations", "", "")
	if conversationResponse.Code != http.StatusOK {
		t.Fatalf("REST conversation list status=%d body=%s", conversationResponse.Code, conversationResponse.Body.String())
	}
	var restConversations r22RESTConversationList
	if err := jsonv2.Unmarshal(conversationResponse.Body.Bytes(), &restConversations); err != nil {
		t.Fatalf("decode REST conversation list: %v", err)
	}
	if len(restConversations.Conversations) != 2 {
		t.Fatalf("REST conversation list=%d, want direct+UNKNOWN", len(restConversations.Conversations))
	}
	for _, item := range restConversations.Conversations {
		if item.WorkspaceID != regWorkspace || len(item.Turns) != 1 || item.Turns[0].QuestionRun == nil {
			t.Fatalf("REST conversation omitted authorized Question Run: %+v", item)
		}
	}
	mcpConversationsBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "r22-jsonpath-conversations", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_conversations_list", "arguments": map[string]any{"workspace_id": regWorkspace}},
	})
	if err != nil {
		t.Fatalf("marshal MCP conversation list: %v", err)
	}
	mcpConversations := mcp(handler, mcpConversationsBody, "")
	if mcpConversations.Result.IsError || len(mcpConversations.Result.StructuredContent) == 0 {
		t.Fatalf("MCP conversation list failed: %+v", mcpConversations)
	}
	var mcpConversationList r22RESTConversationList
	if err := jsonv2.Unmarshal(mcpConversations.Result.StructuredContent, &mcpConversationList); err != nil {
		t.Fatalf("decode MCP conversation list: %v", err)
	}
	if !reflect.DeepEqual(restConversations, mcpConversationList) {
		t.Fatalf("REST/MCP conversation projections differ: rest=%+v mcp=%+v", restConversations, mcpConversationList)
	}

	// The same production handler and Question authority accept a workspace
	// MEMBER, while the direct isolation proof covers the complementary denial
	// path. This prevents the public adapter from silently requiring OWNER.
	viewerHandler := newHandler(regViewer)
	viewerResponse := rest(viewerHandler, http.MethodPost, questionPath, string(questionBody), isolationQuestionKey("json-path-viewer-rest"))
	if viewerResponse.Code != http.StatusOK {
		t.Fatalf("workspace MEMBER REST question status=%d body=%s", viewerResponse.Code, viewerResponse.Body.String())
	}
	var viewerRun question.Run
	if err := jsonv2.Unmarshal(viewerResponse.Body.Bytes(), &viewerRun); err != nil {
		t.Fatalf("decode workspace MEMBER run: %v", err)
	}
	if viewerRun.ResultStatus != "COMPLETED" || viewerRun.Answer != direct.Answer || len(viewerRun.Citations) != len(direct.Citations) {
		t.Fatalf("workspace MEMBER projection failed: %+v", viewerRun)
	}

	// Revoke the direct conversation through the real purger role. Every public
	// disclosure surface must then collapse to the same not-found/omitted shape:
	// Question GET, conversation GET and both conversation lists. Source Evidence
	// remains independently governed by source retention, not conversation state.
	purger := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
	purgeTx, err := purger.Begin(ctx)
	if err != nil {
		t.Fatalf("r23 open retention transaction: %v", err)
	}
	if _, err := purgeTx.Exec(ctx, `SELECT set_config('app.organization_id',$1,true)`, regOrg); err != nil {
		_ = purgeTx.Rollback(ctx)
		t.Fatalf("r23 set retention tenant: %v", err)
	}
	if _, err := purgeTx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state='PURGING', disclosure_allowed=false, retention_fence=retention_fence+1, purge_started_at=clock_timestamp()
		 WHERE organization_id=$1 AND conversation_id=$2 AND state='ACTIVE'
	`, regOrg, direct.ConversationID); err != nil {
		_ = purgeTx.Rollback(ctx)
		t.Fatalf("r23 revoke conversation retention: %v", err)
	}
	if err := purgeTx.Commit(ctx); err != nil {
		t.Fatalf("r23 commit retention revocation: %v", err)
	}

	revokedQuestion := rest(handler, http.MethodGet, questionPath+"/"+direct.ID, "", "")
	if revokedQuestion.Code != http.StatusNotFound || strings.Contains(revokedQuestion.Body.String(), direct.ID) {
		t.Fatalf("revoked REST Question GET status=%d body=%s", revokedQuestion.Code, revokedQuestion.Body.String())
	}
	revokedConversation := rest(handler, http.MethodGet, "/api/v1/workspaces/"+regWorkspace+"/conversations/"+direct.ConversationID, "", "")
	if revokedConversation.Code != http.StatusNotFound || strings.Contains(revokedConversation.Body.String(), direct.ConversationID) {
		t.Fatalf("revoked REST conversation GET status=%d body=%s", revokedConversation.Code, revokedConversation.Body.String())
	}
	revokedListResponse := rest(handler, http.MethodGet, "/api/v1/workspaces/"+regWorkspace+"/conversations", "", "")
	if revokedListResponse.Code != http.StatusOK {
		t.Fatalf("revoked REST conversation list status=%d body=%s", revokedListResponse.Code, revokedListResponse.Body.String())
	}
	var revokedRESTList r22RESTConversationList
	if err := jsonv2.Unmarshal(revokedListResponse.Body.Bytes(), &revokedRESTList); err != nil {
		t.Fatalf("decode revoked REST conversation list: %v", err)
	}
	for _, item := range revokedRESTList.Conversations {
		if item.ConversationID == direct.ConversationID {
			t.Fatalf("revoked conversation remained in REST list: %+v", item)
		}
	}
	revokedMCPListBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "r23-revoked-conversations", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_conversations_list", "arguments": map[string]any{"workspace_id": regWorkspace}},
	})
	if err != nil {
		t.Fatalf("marshal revoked MCP conversation list: %v", err)
	}
	revokedMCPList := mcp(handler, revokedMCPListBody, "")
	var revokedMCPProjection r22RESTConversationList
	if revokedMCPList.Result.IsError || jsonv2.Unmarshal(revokedMCPList.Result.StructuredContent, &revokedMCPProjection) != nil {
		t.Fatalf("revoked MCP conversation list failed: %+v", revokedMCPList)
	}
	if !reflect.DeepEqual(revokedRESTList, revokedMCPProjection) {
		t.Fatalf("revoked REST/MCP list projections differ: rest=%+v mcp=%+v", revokedRESTList, revokedMCPProjection)
	}
	for _, item := range revokedMCPProjection.Conversations {
		if item.ConversationID == direct.ConversationID {
			t.Fatalf("revoked conversation remained in MCP list: %+v", item)
		}
	}

	// Retention must gate mutation entry points as well as disclosure. A replay
	// of the original idempotency key must not resurrect the revoked Question
	// Run, and a fresh continuation must not append a turn to the PURGING
	// conversation. REST and MCP deliberately expose content-free denial
	// projections through their shared Question authority.
	revokedReplay := rest(handler, http.MethodPost, questionPath, string(questionBody), replayKey)
	if revokedReplay.Code != http.StatusNotFound || strings.Contains(revokedReplay.Body.String(), direct.ID) {
		t.Fatalf("revoked REST idempotency replay status=%d body=%s", revokedReplay.Code, revokedReplay.Body.String())
	}
	continuationBody, err := jsonv2.Marshal(map[string]any{
		"question": questionText, "conversation_id": direct.ConversationID, "answer_mode": "EXTRACTIVE",
	})
	if err != nil {
		t.Fatalf("marshal revoked REST continuation: %v", err)
	}
	revokedContinuation := rest(handler, http.MethodPost, questionPath, string(continuationBody), isolationQuestionKey("r24-revoked-continuation"))
	if revokedContinuation.Code != http.StatusNotFound || strings.Contains(revokedContinuation.Body.String(), direct.ConversationID) {
		t.Fatalf("revoked REST continuation status=%d body=%s", revokedContinuation.Code, revokedContinuation.Body.String())
	}

	revokedMCPReplay := mcpAllowError(handler, mcpQuestionBody, replayKey)
	if revokedMCPReplay.Error == nil || revokedMCPReplay.Result.StructuredContent != nil || strings.Contains(revokedMCPReplay.Error.Message, direct.ID) {
		t.Fatalf("revoked MCP idempotency replay was not content-free: %+v", revokedMCPReplay)
	}
	revokedMCPContinuationBody, err := jsonv2.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": "r24-revoked-continuation", "method": "tools/call",
		"params": map[string]any{"name": "knowvault_question", "arguments": map[string]any{
			"workspace_id": regWorkspace, "conversation_id": direct.ConversationID,
			"question": questionText, "answer_mode": "EXTRACTIVE",
		}},
	})
	if err != nil {
		t.Fatalf("marshal revoked MCP continuation: %v", err)
	}
	revokedMCPContinuation := mcpAllowError(handler, revokedMCPContinuationBody, isolationQuestionKey("r24-revoked-mcp-continuation"))
	if revokedMCPContinuation.Error == nil || revokedMCPContinuation.Result.StructuredContent != nil || strings.Contains(revokedMCPContinuation.Error.Message, direct.ConversationID) {
		t.Fatalf("revoked MCP continuation was not content-free: %+v", revokedMCPContinuation)
	}
}
