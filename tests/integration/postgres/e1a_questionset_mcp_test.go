package postgres_test

// Card D-19: the question-set harness asked a question through the product's
// MCP server the way an outside agent asks it, over the streamable-HTTP MCP
// transport (POST /api/v1/mcp, JSON-RPC 2.0) on a real socket. The client below
// is a real MCP client session: it performs the initialize handshake, reads the
// server identity and tool list, then issues tools/call with the human member's
// bearer session token and the mandatory Idempotency-Key. It never calls the
// product's Go code directly; every question crosses the HTTP MCP boundary.
//
// The product's own record of the run is then read back from the product's
// database: the question.created audit event must carry the MCP request id the
// transport returned, and question.Service.Get must return the same persisted
// answer the MCP projection carried. That is what makes "it arrived through
// MCP" a product record rather than the client's own claim.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/question"

	"knowvault.local/verified-workspace/tests/e2e/questions"
)

// e1aMCPClient is one real MCP client session against the composed product
// handler served on a real HTTP socket.
type e1aMCPClient struct {
	server    *httptest.Server
	token     string
	admin     *pgxpool.Pool
	questions *question.Service
}

type e1aMCPResult struct {
	Content    []map[string]any `json:"content"`
	Structured json.RawMessage  `json:"structuredContent"`
	IsError    bool             `json:"isError"`
}

type e1aMCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type e1aMCPEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *e1aMCPError    `json:"error"`
}

// e1aMCPSessionToken is the fixed, shape-valid bearer session token the
// composed authenticator resolves to the synthetic owner.
func e1aMCPSessionToken() string {
	raw := make([]byte, sha256.Size)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// e1aNewMCPClient starts the composed product handler on a real socket and
// performs the MCP initialize/tools-list handshake, so a later tools/call is a
// request inside a real MCP client session, not a bare function call.
func e1aNewMCPClient(t *testing.T, env *e1aEnvironment) *e1aMCPClient {
	t.Helper()
	server := httptest.NewServer(env.Handler)
	t.Cleanup(server.Close)
	client := &e1aMCPClient{
		server: server, token: e1aMCPSessionToken(),
		admin: env.Admin, questions: env.Questions,
	}
	body, _, envelope := client.rpc(t, context.Background(), "initialize", map[string]any{
		"protocolVersion": "2025-06-18", "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "kv-card-d-19-question-set", "version": "1"},
	}, "")
	if envelope.Error != nil {
		t.Fatalf("MCP initialize refused: %+v body=%s", envelope.Error, body)
	}
	var initResult struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(envelope.Result, &initResult); err != nil {
		t.Fatalf("MCP initialize result decode: %v body=%s", err, body)
	}
	if initResult.ServerInfo.Name != "knowvault" {
		t.Fatalf("MCP initialize serverInfo.name=%q, want knowvault", initResult.ServerInfo.Name)
	}
	body, _, envelope = client.rpc(t, context.Background(), "tools/list", map[string]any{}, "")
	if envelope.Error != nil {
		t.Fatalf("MCP tools/list refused: %+v body=%s", envelope.Error, body)
	}
	var listResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(envelope.Result, &listResult); err != nil {
		t.Fatalf("MCP tools/list result decode: %v body=%s", err, body)
	}
	found := false
	for _, tool := range listResult.Tools {
		if tool.Name == "knowvault_question" {
			found = true
		}
	}
	if !found {
		t.Fatalf("MCP tools/list did not advertise knowvault_question: %s", body)
	}
	return client
}

// rpc issues one JSON-RPC request over the MCP HTTP transport and returns the
// raw body, the response headers and the decoded envelope.
func (client *e1aMCPClient) rpc(t *testing.T, ctx context.Context, method string, params any, idempotencyKey string) (string, http.Header, e1aMCPEnvelope) {
	t.Helper()
	envelope := map[string]any{"jsonrpc": "2.0", "id": "d19-" + method, "method": method}
	if params != nil {
		envelope["params"] = params
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal MCP %s: %v", method, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.server.URL+"/api/v1/mcp", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build MCP %s request: %v", method, err)
	}
	// The bearer session token is the non-browser transport the external MCP
	// probe and a deployment API client use; it never combines with a cookie or
	// CSRF header.
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	response, err := client.server.Client().Do(request)
	if err != nil {
		t.Fatalf("MCP %s call: %v", method, err)
	}
	defer response.Body.Close()
	var buffer bytes.Buffer
	if _, err := buffer.ReadFrom(response.Body); err != nil {
		t.Fatalf("read MCP %s body: %v", method, err)
	}
	body := buffer.String()
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("MCP %s status=%d body=%s", method, response.StatusCode, body)
	}
	var decoded e1aMCPEnvelope
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode MCP %s body: %v body=%s", method, err, body)
	}
	return body, response.Header, decoded
}

// askQuestion issues one MCP tools/call for the question text and returns the
// product's Question Run projection, the MCP transport request id, and whether
// the product's own record ties the run to that request.
func (client *e1aMCPClient) askQuestion(t *testing.T, ctx context.Context, workspaceID, questionText, idempotencyKey string) (question.Run, string, bool, error) {
	t.Helper()
	body, header, envelope := client.rpc(t, ctx, "tools/call", map[string]any{
		"name": "knowvault_question",
		"arguments": map[string]any{
			"workspace_id": workspaceID,
			"question":     questionText,
		},
	}, idempotencyKey)
	requestID := header.Get("X-Request-ID")
	if envelope.Error != nil {
		return question.Run{}, requestID, false, &e1aMCPRefusal{Code: envelope.Error.Code, Message: envelope.Error.Message, Body: body}
	}
	var result e1aMCPResult
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("decode MCP question result: %v body=%s", err, body)
	}
	if len(result.Structured) == 0 {
		t.Fatalf("MCP question returned no structuredContent: %s", body)
	}
	var run question.Run
	if err := json.Unmarshal(result.Structured, &run); err != nil {
		t.Fatalf("decode MCP question run: %v body=%s", err, body)
	}
	return run, requestID, client.productRecordTiesRun(t, ctx, run, requestID), nil
}

// e1aMCPRefusal is one content-free JSON-RPC refusal from the MCP adapter.
type e1aMCPRefusal struct {
	Code    int
	Message string
	Body    string
}

func (refusal *e1aMCPRefusal) Error() string { return refusal.Message }

// productRecordTiesRun reads the product's own durable records: the
// question.created audit event must carry the MCP request id, and the product's
// persisted Question Run must carry the same answer the MCP projection carried.
func (client *e1aMCPClient) productRecordTiesRun(t *testing.T, ctx context.Context, run question.Run, requestID string) bool {
	t.Helper()
	if run.ID == "" || requestID == "" {
		return false
	}
	access := regOwnerAccess("req_d19_mcp_record")
	persisted, err := client.questions.Get(ctx, access, run.WorkspaceID, run.ID)
	if err != nil || persisted.Answer != run.Answer {
		return false
	}
	var recordedRequest string
	err = client.admin.QueryRow(ctx, `SELECT request_id FROM public.audit_event
		WHERE organization_id=$1 AND action='question.created' AND resource_id=$2
		ORDER BY sequence DESC LIMIT 1`, regOrg, run.ID).Scan(&recordedRequest)
	if err != nil {
		return false
	}
	return recordedRequest == requestID
}

// e1aSetNeedsMCP reports whether the set contains a question that must be asked
// through the product's MCP server.
func e1aSetNeedsMCP(set *questions.Set) bool {
	for _, item := range set.Questions {
		if item.Via == "mcp" {
			return true
		}
	}
	return false
}

// e1aMCPRefusalHasNoNumber is the outside-agent denial control: the refusal
// must carry no answer content and its content-free message must state no
// number. The JSON-RPC envelope itself ("jsonrpc":"2.0") is not an answer.
func e1aMCPRefusalHasNoNumber(refusal *e1aMCPRefusal) bool {
	if strings.ContainsAny(refusal.Message, "0123456789") {
		return false
	}
	if strings.Contains(refusal.Body, "structuredContent") || strings.Contains(refusal.Body, `"answer"`) {
		return false
	}
	return true
}

// e1aMCPDeniedWorkspaceQuestion asks one question through MCP against a
// workspace the asking user is not a member of and returns the refusal.
func (client *e1aMCPClient) e1aMCPDeniedWorkspaceQuestion(t *testing.T, ctx context.Context, workspaceID, questionText, idempotencyKey string) *e1aMCPRefusal {
	t.Helper()
	_, _, _, err := client.askQuestion(t, ctx, workspaceID, questionText, idempotencyKey)
	if err == nil {
		t.Fatalf("MCP question against inaccessible workspace %s succeeded, want a refusal", workspaceID)
	}
	refusal, ok := err.(*e1aMCPRefusal)
	if !ok {
		t.Fatalf("MCP refusal is %T, want *e1aMCPRefusal", err)
	}
	if refusal.Code != -32000 || refusal.Message != "question unavailable" {
		t.Fatalf("MCP refusal = %d %q, want the content-free -32000 question unavailable", refusal.Code, refusal.Message)
	}
	if !e1aMCPRefusalHasNoNumber(refusal) {
		t.Fatalf("MCP refusal carries answer content or a number: %s", refusal.Body)
	}
	return refusal
}

// e1aSeedForeignWorkspace creates a real ACTIVE workspace owned by another
// principal, so the synthetic owner is not a member and an MCP question against
// it is an access refusal and not an unknown-id lookup.
func e1aSeedForeignWorkspace(t *testing.T, ctx context.Context, admin *pgxpool.Pool, workspaceID string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin foreign workspace seed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace (id, organization_id, name, status, owner_principal_id, current_revision)
		VALUES ($1, $2, $1, 'ACTIVE', $3, 1) ON CONFLICT DO NOTHING`, workspaceID, regOrg, regViewer); err != nil {
		t.Fatalf("seed foreign workspace: %v", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.workspace_member (id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by)
		VALUES ($1, $2, $3, $4, 'OWNER', 1, $4) ON CONFLICT DO NOTHING`,
		"wm_d19_foreign_owner", regOrg, workspaceID, regViewer); err != nil {
		t.Fatalf("seed foreign workspace owner: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit foreign workspace seed: %v", err)
	}
}

// e1aFormatMCPRefusal renders the refusal for the report's log line.
func e1aFormatMCPRefusal(refusal *e1aMCPRefusal) string {
	return "mcp code=" + strconv.Itoa(refusal.Code) + " message=" + strings.TrimSpace(refusal.Message)
}
