package workspaceapi

// S3 card 2 focused tests for ADR-0097's knowvault_source_sql knowledge tool.
// They prove the MCP tools/call adapter, the REST
// POST /api/v1/workspaces/{workspace_id}/tools/source-sql parity route and the
// chat tool runtime (Handler.Invoke) all compose the identical injected
// SourceSQLProvider and project byte-identical JSON; that the closed refusal
// vocabulary travels to the agent as a tool result on every channel; that a
// foreign source stays the single content-free not-found and an unavailable or
// unauditable provider stays content-free service-unavailable; that the closed
// argument envelope is validated before the provider is touched; and that a
// service principal sees the tool in the registry's SERVICE catalogue.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const testSourceSQLSourceID = "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ"

func testSourceSQLResult() SourceSQLResult {
	count := "3"
	return SourceSQLResult{
		Format: "postgres-text-table-v1", Columns: []string{"count"}, Rows: [][]*string{{&count}}, RowCount: 1,
		AttemptID: "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", SQLHash: "sha256:" + strings.Repeat("a", 64),
		ResultDigest: "sha256:" + strings.Repeat("b", 64), DatabaseIdentity: "pgdb:alpha",
		SourceID: testSourceSQLSourceID, ExposedSchemaRevision: 7,
		ExecutionStartedAt:   time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC),
		ExecutionCompletedAt: time.Date(2026, 9, 24, 10, 0, 1, 0, time.UTC),
	}
}

func newSourceSQLHarness(t *testing.T) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	harness.sources.sqlResult = testSourceSQLResult()
	return harness
}

func callRestSourceSQL(t *testing.T, harness *testHarness, method, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/source-sql", body))
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

func callMCPSourceSQL(t *testing.T, harness *testHarness, arguments string) genericMCPEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"sql","method":"tools/call","params":{"name":"`+mcpToolSourceSQL+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP source_sql status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope genericMCPEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP source_sql did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// TestWorkspaceToolSourceSQLRESTMatchesMCPAndChatProjection proves an authorized
// caller's REST POST, MCP tools/call and chat tool runtime observe
// byte-identical JSON from the identical injected provider call, and that the
// closed argument envelope (source_id, sql, purpose) reaches the provider
// unchanged.
func TestWorkspaceToolSourceSQLRESTMatchesMCPAndChatProjection(t *testing.T) {
	harness := newSourceSQLHarness(t)
	const sqlText = "SELECT count(*) FROM public.contract"
	body := `{"source_id":"` + testSourceSQLSourceID + `","sql":"` + sqlText + `","purpose":"count live contracts"}`

	response, restBody := callRestSourceSQL(t, harness, http.MethodPost, body)
	if response.Code != http.StatusOK {
		t.Fatalf("source-sql REST status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.sqlSourceID != testSourceSQLSourceID || harness.sources.sqlSQL != sqlText ||
		harness.sources.sqlPurpose != "count live contracts" || harness.sources.sqlCalls != 1 {
		t.Fatalf("provider call = source %q sql %q purpose %q calls %d",
			harness.sources.sqlSourceID, harness.sources.sqlSQL, harness.sources.sqlPurpose, harness.sources.sqlCalls)
	}
	wantKeys := []string{"format", "columns", "rows", "row_count", "attempt_id", "sql_hash", "result_digest",
		"database_identity", "source_id", "exposed_schema_revision", "execution_started_at", "execution_completed_at", "complete"}
	if len(restBody) != len(wantKeys) {
		t.Fatalf("REST projection has %d fields, want exactly %d: %#v", len(restBody), len(wantKeys), restBody)
	}
	for _, key := range wantKeys {
		if _, present := restBody[key]; !present {
			t.Fatalf("REST projection is missing %q: %#v", key, restBody)
		}
	}
	if restBody["format"] != "postgres-text-table-v1" || restBody["row_count"] != float64(1) || restBody["complete"] != true {
		t.Fatalf("REST projection shape = %#v", restBody)
	}
	if restBody["sql_hash"] != "sha256:"+strings.Repeat("a", 64) || restBody["result_digest"] != "sha256:"+strings.Repeat("b", 64) {
		t.Fatalf("REST projection hashes = %#v", restBody)
	}
	if restBody["source_id"] != testSourceSQLSourceID || restBody["exposed_schema_revision"] != float64(7) {
		t.Fatalf("REST projection source binding = %#v", restBody)
	}

	mcpEnvelope := callMCPSourceSQL(t, harness, `{"workspace_id":"ws_alpha",`+strings.TrimPrefix(body, "{"))
	if mcpEnvelope.Error != nil || mcpEnvelope.Result.IsError {
		t.Fatalf("MCP source_sql error = %#v isError=%v", mcpEnvelope.Error, mcpEnvelope.Result.IsError)
	}
	mcpStructured, err := json.Marshal(mcpEnvelope.Result.Structured)
	if err != nil {
		t.Fatal(err)
	}
	restStructured, err := json.Marshal(restBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(mcpStructured) != string(restStructured) {
		t.Fatalf("MCP and REST projections differ:\n MCP %s\nREST %s", mcpStructured, restStructured)
	}
	var textBody map[string]any
	if len(mcpEnvelope.Result.Content) != 1 || json.Unmarshal([]byte(mcpEnvelope.Result.Content[0].Text), &textBody) != nil {
		t.Fatalf("MCP text channel = %#v, want one JSON body", mcpEnvelope.Result.Content)
	}
	textJSON, err := json.Marshal(textBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(textJSON) != string(restStructured) {
		t.Fatalf("MCP text channel differs from REST:\n MCP %s\nREST %s", textJSON, restStructured)
	}

	chatResult, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolSourceSQL, json.RawMessage(body))
	if err != nil || chatResult.IsError {
		t.Fatalf("chat source_sql err=%v result=%+v", err, chatResult)
	}
	var chatBody map[string]any
	if json.Unmarshal(chatResult.Structured, &chatBody) != nil {
		t.Fatalf("chat projection did not decode: %s", chatResult.Structured)
	}
	chatJSON, err := json.Marshal(chatBody)
	if err != nil {
		t.Fatal(err)
	}
	if string(chatJSON) != string(restStructured) {
		t.Fatalf("chat and REST projections differ:\nchat %s\nREST %s", chatJSON, restStructured)
	}
}

// TestWorkspaceToolSourceSQLClosedRefusalsReachTheAgent proves every closed
// refusal is a successful tool result carrying its code -- not an opaque
// transport error -- on REST, MCP and chat.
func TestWorkspaceToolSourceSQLClosedRefusalsReachTheAgent(t *testing.T) {
	for _, code := range []string{
		"SQL_REJECTED_STATIC", "RELATION_NOT_IN_SOURCE", "COST_LIMIT", "ROW_LIMIT", "TIMEOUT",
		"DATABASE_REJECTED", "SOURCE_SQL_NOT_CONFIGURED", "SOURCE_SQL_CONCURRENCY_LIMITED",
		"SOURCE_SQL_RATE_LIMITED",
	} {
		t.Run(code, func(t *testing.T) {
			harness := newSourceSQLHarness(t)
			harness.sources.sqlErr = &SourceSQLRefusal{Code: code}
			body := `{"source_id":"` + testSourceSQLSourceID + `","sql":"SELECT 1"}`

			response, decoded := callRestSourceSQL(t, harness, http.MethodPost, body)
			if response.Code != http.StatusOK || decoded["error"] != code {
				t.Fatalf("REST refusal = %d %#v, want 200 {\"error\":%q}", response.Code, decoded, code)
			}
			mcpEnvelope := callMCPSourceSQL(t, harness, `{"workspace_id":"ws_alpha",`+strings.TrimPrefix(body, "{"))
			if mcpEnvelope.Error != nil || !mcpEnvelope.Result.IsError || mcpEnvelope.Result.Structured["error"] != code {
				t.Fatalf("MCP refusal = %#v error=%#v", mcpEnvelope.Result, mcpEnvelope.Error)
			}
			chatResult, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolSourceSQL, json.RawMessage(body))
			if err != nil || !chatResult.IsError || !strings.Contains(chatResult.Text, code) {
				t.Fatalf("chat refusal err=%v result=%+v", err, chatResult)
			}
		})
	}
}

// TestWorkspaceToolSourceSQLForeignSourceIsContentFreeNotFound proves an
// unknown, foreign or disabled source stays the provider's single content-free
// not-found on every channel, with no schema, row or source echo.
func TestWorkspaceToolSourceSQLForeignSourceIsContentFreeNotFound(t *testing.T) {
	harness := newSourceSQLHarness(t)
	harness.sources.sqlErr = workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	body := `{"source_id":"conn_foreign_01H9ABCDEFGHJKMNPQRSTVW","sql":"SELECT 1"}`

	response, _ := callRestSourceSQL(t, harness, http.MethodPost, body)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
		t.Fatalf("REST foreign source = %d %s, want 404 NOT_FOUND", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "conn_foreign") || strings.Contains(response.Body.String(), "SELECT") {
		t.Fatalf("REST not-found echoed content: %s", response.Body.String())
	}
	mcpEnvelope := callMCPSourceSQL(t, harness, `{"workspace_id":"ws_alpha",`+strings.TrimPrefix(body, "{"))
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32004 {
		t.Fatalf("MCP foreign source = %#v, want -32004", mcpEnvelope.Error)
	}
}

// TestWorkspaceToolSourceSQLAuditFailureReturnsNoRows proves a provider that
// cannot record its mandatory attempt is a content-free service-unavailable
// with no rows on every channel.
func TestWorkspaceToolSourceSQLAuditFailureReturnsNoRows(t *testing.T) {
	harness := newSourceSQLHarness(t)
	harness.sources.sqlErr = context.DeadlineExceeded
	body := `{"source_id":"` + testSourceSQLSourceID + `","sql":"SELECT count(*) FROM public.contract"}`

	response, _ := callRestSourceSQL(t, harness, http.MethodPost, body)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("REST audit failure = %d %s, want 503 SERVICE_UNAVAILABLE", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "result_digest") || strings.Contains(response.Body.String(), "rows") {
		t.Fatalf("REST audit failure disclosed rows: %s", response.Body.String())
	}
	mcpEnvelope := callMCPSourceSQL(t, harness, `{"workspace_id":"ws_alpha",`+strings.TrimPrefix(body, "{"))
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32000 || mcpEnvelope.Result.Structured != nil {
		t.Fatalf("MCP audit failure = %#v structured=%#v", mcpEnvelope.Error, mcpEnvelope.Result.Structured)
	}
}

// TestWorkspaceToolSourceSQLFailsClosedWithoutCapability proves a composition
// whose source service does not implement SourceSQLProvider answers 503 over
// REST and -32000 over MCP, before any execution.
func TestWorkspaceToolSourceSQLFailsClosedWithoutCapability(t *testing.T) {
	harness := newSourceSQLHarness(t)
	harness.handler.sources = sourceServiceWithoutSchema{inner: harness.sources}
	response, _ := callRestSourceSQL(t, harness, http.MethodPost, `{"source_id":"`+testSourceSQLSourceID+`","sql":"SELECT 1"}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("source-sql no-capability status=%d body=%s", response.Code, response.Body.String())
	}
	mcpEnvelope := callMCPSourceSQL(t, harness, `{"workspace_id":"ws_alpha","source_id":"`+testSourceSQLSourceID+`","sql":"SELECT 1"}`)
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32000 {
		t.Fatalf("MCP no-capability = %#v, want -32000", mcpEnvelope.Error)
	}
}

// TestWorkspaceToolSourceSQLArgumentEnvelopeIsClosed proves the transport
// refuses an over-long, missing or unknown argument before the provider runs.
func TestWorkspaceToolSourceSQLArgumentEnvelopeIsClosed(t *testing.T) {
	harness := newSourceSQLHarness(t)
	longSQL := strings.Repeat("a", maxSourceSQLBytes+1)
	longPurpose := strings.Repeat("p", maxSourceSQLPurposeChars+1)
	for name, body := range map[string]string{
		"missing sql":       `{"source_id":"` + testSourceSQLSourceID + `"}`,
		"empty sql":         `{"source_id":"` + testSourceSQLSourceID + `","sql":""}`,
		"over-long sql":     `{"source_id":"` + testSourceSQLSourceID + `","sql":"` + longSQL + `"}`,
		"over-long purpose": `{"source_id":"` + testSourceSQLSourceID + `","sql":"SELECT 1","purpose":"` + longPurpose + `"}`,
		"missing source":    `{"sql":"SELECT 1"}`,
		"unknown member":    `{"source_id":"` + testSourceSQLSourceID + `","sql":"SELECT 1","limit":10}`,
	} {
		t.Run(name, func(t *testing.T) {
			response, _ := callRestSourceSQL(t, harness, http.MethodPost, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s status=%d body=%s, want 400", name, response.Code, response.Body.String())
			}
			if harness.sources.sqlCalls != 0 {
				t.Fatalf("%s reached the provider %d times", name, harness.sources.sqlCalls)
			}
		})
	}
	if response, _ := callRestSourceSQL(t, harness, http.MethodGet, ""); response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("source-sql GET status=%d, want 405", response.Code)
	}
}

// TestWorkspaceToolSourceSQLAdvertisedToServicePrincipals proves the tool is in
// the always-present knowledge catalogue, is SERVICE-visible through the
// registry's own allow-list and is invoked under a service principal's own
// access context.
func TestWorkspaceToolSourceSQLAdvertisedToServicePrincipals(t *testing.T) {
	harness := newSourceSQLHarness(t)
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "svcp_agent", RequestID: "req_sql", ActorKind: database.ActorKindService}
	advertised := false
	for _, name := range toolNames(t, harness.handler.mcpTools(access)) {
		if name == mcpToolSourceSQL {
			advertised = true
		}
	}
	if !advertised {
		t.Fatalf("tools/list omitted %s for a service principal", mcpToolSourceSQL)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"sql","method":"tools/call","params":{"name":"`+mcpToolSourceSQL+
			`","arguments":{"workspace_id":"ws_alpha","source_id":"`+testSourceSQLSourceID+`","sql":"SELECT 1"}}}`))
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "-32602") {
		t.Fatalf("service principal call = %d %s", response.Code, response.Body.String())
	}
}
