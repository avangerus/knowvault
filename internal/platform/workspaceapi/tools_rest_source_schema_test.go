package workspaceapi

// S3 card 1 focused tests for ADR-0097's knowvault_source_schema knowledge
// tool. They prove the MCP tools/call adapter, the REST
// POST /api/v1/workspaces/{workspace_id}/tools/source-schema parity route and
// the chat tool runtime (Handler.Invoke) all compose the identical injected
// SourceSchemaProvider read and project byte-identical JSON; that the source
// list, the table/column projection (including the absence of an excluded
// column), pagination and the workspace model context notes are merged as the
// card specifies; and that a foreign source is the single content-free
// not-found while a composition without the capability fails closed.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const testSourceSchemaSourceID = "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ"

// testSourceSchemaResult is the projection the injected provider returns: two
// tables whose columns already reflect the registration-time exclusion (the
// deliberately absent "passport" column is asserted by the tests below).
func testSourceSchemaResult() workspacerepository.SourceSchema {
	return workspacerepository.SourceSchema{
		SourceID: testSourceSchemaSourceID, DatabaseIdentity: "pgdb:alpha",
		Tables: []workspacerepository.SourceSchemaTable{
			{
				Schema: "public", Name: "contract", Kind: "TABLE", RowEstimate: 17030, Note: "catalog comment",
				Columns: []workspacerepository.SourceSchemaColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true, Note: "surrogate key"},
					{Name: "amount", Type: "numeric", Nullable: true, Note: "sum"},
				},
			},
			{
				Schema: "public", Name: "party", Kind: "VIEW", RowEstimate: -1,
				Columns: []workspacerepository.SourceSchemaColumn{
					{Name: "id", Type: "uuid", Nullable: false, PrimaryKey: true},
					{Name: "name", Type: "text", Nullable: true},
				},
			},
		},
	}
}

func newSourceSchemaHarness(t *testing.T) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	harness.sources.schemaResult = testSourceSchemaResult()
	harness.sources.schemaSources = []workspacerepository.SourceSchemaSource{
		{ID: testSourceSchemaSourceID, Name: "Ops database", TableCount: 2},
		{ID: "conn_01H9ABCDEFGHJKMNPQRSTVWXY0", Name: "Billing", TableCount: 1},
	}
	return harness
}

func callRestSourceSchema(t *testing.T, harness *testHarness, method, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/source-schema", body))
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

func callMCPSourceSchema(t *testing.T, harness *testHarness, arguments string) genericMCPEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"schema","method":"tools/call","params":{"name":"`+mcpToolSourceSchema+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP source_schema status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope genericMCPEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP source_schema did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// TestWorkspaceToolSourceSchemaRESTMatchesMCPAndChatProjection proves an
// authorized caller's REST POST, MCP tools/call and chat tool runtime observe
// byte-identical JSON from the identical injected provider read, including the
// stored tables, native types, primary keys, row estimates and the discovery
// comment fallback -- and that the excluded column is absent.
func TestWorkspaceToolSourceSchemaRESTMatchesMCPAndChatProjection(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	response, body := callRestSourceSchema(t, harness, http.MethodPost, `{"source_id":"`+testSourceSchemaSourceID+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("source-schema REST status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.schemaSourceID != testSourceSchemaSourceID || harness.sources.schemaLimit != maxSourceSchemaToolLimit {
		t.Fatalf("provider read = source %q limit %d, want %q and the default %d",
			harness.sources.schemaSourceID, harness.sources.schemaLimit, testSourceSchemaSourceID, maxSourceSchemaToolLimit)
	}
	if body["source_id"] != testSourceSchemaSourceID || body["database_identity"] != "pgdb:alpha" {
		t.Fatalf("source identity = %v/%v", body["source_id"], body["database_identity"])
	}
	if body["has_more"] != false || body["next_offset"] != float64(0) {
		t.Fatalf("page window = has_more %v next_offset %v, want false/0", body["has_more"], body["next_offset"])
	}
	tables, ok := body["tables"].([]any)
	if !ok || len(tables) != 2 {
		t.Fatalf("tables = %#v, want 2", body["tables"])
	}
	contract, ok := tables[0].(map[string]any)
	if !ok || contract["schema"] != "public" || contract["name"] != "contract" || contract["kind"] != "TABLE" ||
		contract["row_estimate"] != float64(17030) || contract["note"] != "catalog comment" {
		t.Fatalf("contract table = %#v", tables[0])
	}
	columns, ok := contract["columns"].([]any)
	if !ok || len(columns) != 2 {
		t.Fatalf("contract columns = %#v, want 2", contract["columns"])
	}
	id, _ := columns[0].(map[string]any)
	if id["name"] != "id" || id["type"] != "uuid" || id["nullable"] != false || id["primary_key"] != true || id["note"] != "surrogate key" {
		t.Fatalf("id column = %#v", columns[0])
	}
	if strings.Contains(response.Body.String(), "passport") {
		t.Fatalf("an excluded column leaked into the schema: %s", response.Body.String())
	}

	mcpEnvelope := callMCPSourceSchema(t, harness, `{"workspace_id":"ws_alpha","source_id":"`+testSourceSchemaSourceID+`"}`)
	if mcpEnvelope.Error != nil {
		t.Fatalf("MCP source_schema error: %#v", mcpEnvelope.Error)
	}
	if !reflect.DeepEqual(body, mcpEnvelope.Result.Structured) {
		t.Fatalf("REST projection != MCP structuredContent\nREST: %#v\nMCP:  %#v", body, mcpEnvelope.Result.Structured)
	}

	result, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolSourceSchema,
		json.RawMessage(`{"source_id":"`+testSourceSchemaSourceID+`"}`))
	if err != nil || result.IsError {
		t.Fatalf("chat source_schema: err=%v result=%s", err, result.Text)
	}
	var chatProjection map[string]any
	if err := json.Unmarshal(result.Structured, &chatProjection); err != nil {
		t.Fatalf("chat source_schema structured did not decode: %v: %s", err, result.Structured)
	}
	if !reflect.DeepEqual(body, chatProjection) {
		t.Fatalf("chat projection != REST projection\nchat: %#v\nREST: %#v", chatProjection, body)
	}
}

// TestWorkspaceToolSourceSchemaListsSourcesWithoutSourceID proves the top of
// the map: without source_id the tool lists the workspace's PostgreSQL sources
// with their id, name and table count, identically over REST and MCP.
func TestWorkspaceToolSourceSchemaListsSourcesWithoutSourceID(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	response, body := callRestSourceSchema(t, harness, http.MethodPost, `{}`)
	if response.Code != http.StatusOK {
		t.Fatalf("source list REST status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.schemaCalls != 0 {
		t.Fatalf("listing sources called SourceSchema %d times, want 0", harness.sources.schemaCalls)
	}
	sources, ok := body["sources"].([]any)
	if !ok || len(sources) != 2 {
		t.Fatalf("sources = %#v, want 2", body["sources"])
	}
	first, _ := sources[0].(map[string]any)
	if first["id"] != testSourceSchemaSourceID || first["name"] != "Ops database" || first["table_count"] != float64(2) {
		t.Fatalf("first source = %#v", sources[0])
	}
	if _, present := body["tables"]; present {
		t.Fatalf("a source list must not carry a tables member: %#v", body)
	}

	mcpEnvelope := callMCPSourceSchema(t, harness, `{"workspace_id":"ws_alpha"}`)
	if mcpEnvelope.Error != nil {
		t.Fatalf("MCP source list error: %#v", mcpEnvelope.Error)
	}
	if !reflect.DeepEqual(body, mcpEnvelope.Result.Structured) {
		t.Fatalf("REST source list != MCP structuredContent\nREST: %#v\nMCP:  %#v", body, mcpEnvelope.Result.Structured)
	}
}

// TestWorkspaceToolSourceSchemaPaginatesTables proves offset/limit reach the
// provider unchanged, the page window is echoed explicitly (no silent
// truncation) and the table filter is forwarded.
func TestWorkspaceToolSourceSchemaPaginatesTables(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	harness.sources.schemaResult.Tables = append(harness.sources.schemaResult.Tables,
		workspacerepository.SourceSchemaTable{Schema: "public", Name: "invoice", Kind: "TABLE", RowEstimate: 4})
	response, body := callRestSourceSchema(t, harness, http.MethodPost,
		`{"source_id":"`+testSourceSchemaSourceID+`","table":"public.contract","offset":1,"limit":1}`)
	if response.Code != http.StatusOK {
		t.Fatalf("paginated source-schema status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.schemaTable != "public.contract" || harness.sources.schemaOffset != 1 || harness.sources.schemaLimit != 1 {
		t.Fatalf("provider args = table %q offset %d limit %d, want public.contract/1/1",
			harness.sources.schemaTable, harness.sources.schemaOffset, harness.sources.schemaLimit)
	}
	if body["has_more"] != true || body["next_offset"] != float64(2) {
		t.Fatalf("page window = has_more %v next_offset %v, want true/2", body["has_more"], body["next_offset"])
	}
	tables, ok := body["tables"].([]any)
	if !ok || len(tables) != 1 || tables[0].(map[string]any)["name"] != "party" {
		t.Fatalf("page tables = %#v, want exactly the second table", body["tables"])
	}
}

// TestWorkspaceToolSourceSchemaMergesWorkspaceContextNotes proves the
// workspace model context's own source/table/column notes are merged into the
// stored schema, that the context version is reported, and that a table or
// column the context does not mention keeps its discovery-time comment.
func TestWorkspaceToolSourceSchemaMergesWorkspaceContextNotes(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	harness.handler.EnableWorkspaceContext(&fakeSourceSchemaNotesReader{notes: workspacecontext.SourceNotes{
		ContextVersion: 4,
		Source: workspacecontext.Source{
			SourceConnectionID: testSourceSchemaSourceID, Description: "Ops database notes",
			Tables: []workspacecontext.Table{{
				Relation: "public.contract", Note: "Договоры",
				Columns: []workspacecontext.Column{{Name: "amount", Note: "Сумма договора"}},
			}},
		},
	}})
	response, body := callRestSourceSchema(t, harness, http.MethodPost, `{"source_id":"`+testSourceSchemaSourceID+`"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("source-schema with notes status=%d body=%s", response.Code, response.Body.String())
	}
	if body["context_version"] != float64(4) || body["source_note"] != "Ops database notes" {
		t.Fatalf("context version/source note = %v/%v", body["context_version"], body["source_note"])
	}
	tables := body["tables"].([]any)
	contract := tables[0].(map[string]any)
	if contract["note"] != "Договоры" {
		t.Fatalf("contract note = %v, want the workspace context note", contract["note"])
	}
	columns := contract["columns"].([]any)
	amount := columns[1].(map[string]any)
	if amount["note"] != "Сумма договора" {
		t.Fatalf("amount note = %v, want the workspace context note", amount["note"])
	}
	// The party table has no context note, so its discovery-time comment is kept.
	party := tables[1].(map[string]any)
	if party["note"] != "" {
		t.Fatalf("party note = %v, want the stored (empty) comment", party["note"])
	}
}

// TestWorkspaceToolSourceSchemaForeignSourceIsContentFree proves an unknown or
// foreign source collapses to the single content-free 404 NOT_FOUND (-32004
// over MCP) with no schema content and no source-id echo.
func TestWorkspaceToolSourceSchemaForeignSourceIsContentFree(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	harness.sources.schemaErr = workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	response, _ := callRestSourceSchema(t, harness, http.MethodPost, `{"source_id":"conn_foreign_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign source REST status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "conn_foreign") || strings.Contains(response.Body.String(), "public") {
		t.Fatalf("foreign source denial leaked content: %s", response.Body.String())
	}
	mcpEnvelope := callMCPSourceSchema(t, harness, `{"workspace_id":"ws_alpha","source_id":"conn_foreign_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32004 {
		t.Fatalf("expected MCP -32004 not-found, got %#v", mcpEnvelope.Error)
	}
}

// TestWorkspaceToolSourceSchemaRejectsInvalidBeforeRead proves an invalid
// argument is refused before the provider is touched: limit over 50, a
// non-"schema.name" table, an unknown member and a malformed body.
func TestWorkspaceToolSourceSchemaRejectsInvalidBeforeRead(t *testing.T) {
	for name, body := range map[string]string{
		"limit_over_max": `{"source_id":"` + testSourceSchemaSourceID + `","limit":51}`,
		"negative_offset": `{"source_id":"` + testSourceSchemaSourceID + `","offset":-1}`,
		"bad_table":       `{"source_id":"` + testSourceSchemaSourceID + `","table":"contract"}`,
		"unknown_field":   `{"source_id":"` + testSourceSchemaSourceID + `","unexpected":true}`,
		"malformed":       `{`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			harness := newSourceSchemaHarness(t)
			response, _ := callRestSourceSchema(t, harness, http.MethodPost, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s: status=%d body=%s, want 400", name, response.Code, response.Body.String())
			}
			if harness.sources.schemaCalls != 0 {
				t.Fatalf("%s: invalid body reached the provider", name)
			}
		})
	}
}

// TestWorkspaceToolSourceSchemaIsPostOnly proves the parity route follows the
// workspace-context shape: POST-only, because its optional arguments travel in
// a JSON body.
func TestWorkspaceToolSourceSchemaIsPostOnly(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	response, _ := callRestSourceSchema(t, harness, http.MethodGet, "")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("source-schema GET status=%d body=%s, want 405", response.Code, response.Body.String())
	}
	if harness.sources.schemaCalls != 0 || harness.sources.call == "list_source_schemas" {
		t.Fatalf("GET reached the provider: call=%q", harness.sources.call)
	}
}

// TestWorkspaceToolSourceSchemaFailsClosedWithoutCapability proves a
// composition whose source service does not implement SourceSchemaProvider
// answers 503 SERVICE_UNAVAILABLE over REST and -32000 over MCP, before any
// read or echo.
func TestWorkspaceToolSourceSchemaFailsClosedWithoutCapability(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	harness.handler.sources = sourceServiceWithoutSchema{inner: harness.sources}
	response, _ := callRestSourceSchema(t, harness, http.MethodPost, "")
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("source-schema no-capability status=%d body=%s", response.Code, response.Body.String())
	}
	mcpEnvelope := callMCPSourceSchema(t, harness, `{"workspace_id":"ws_alpha"}`)
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32000 {
		t.Fatalf("expected MCP -32000 service-unavailable, got %#v", mcpEnvelope.Error)
	}
}

// sourceServiceWithoutSchema satisfies the required SourceService boundary but
// deliberately does not implement SourceSchemaProvider, exactly like a
// composition predating ADR-0097's schema capability.
type sourceServiceWithoutSchema struct{ inner *fakeSourceService }

func (service sourceServiceWithoutSchema) Register(ctx context.Context, access database.AccessContext, request registration.RegisterRequest) (registration.RegisterResult, error) {
	return service.inner.Register(ctx, access, request)
}

func (service sourceServiceWithoutSchema) Activate(ctx context.Context, access database.AccessContext, request registration.ActivateRequest) (registration.ActivateResult, error) {
	return service.inner.Activate(ctx, access, request)
}

func (service sourceServiceWithoutSchema) Sync(ctx context.Context, access database.AccessContext, request registration.SyncRequest) (registration.SyncResult, error) {
	return service.inner.Sync(ctx, access, request)
}

func (service sourceServiceWithoutSchema) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	return service.inner.ListSources(ctx, access, workspaceID)
}

func (service sourceServiceWithoutSchema) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (workspacerepository.ConfirmationContext, error) {
	return service.inner.ConfirmationContext(ctx, access, workspaceID)
}

func (service sourceServiceWithoutSchema) UploadDocuments(ctx context.Context, access database.AccessContext, request registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return service.inner.UploadDocuments(ctx, access, request)
}

var _ SourceService = sourceServiceWithoutSchema{}

// TestWorkspaceToolSourceSchemaAdvertisedToServicePrincipals proves the tool
// is in the always-present knowledge catalogue and therefore visible to an
// external service principal through the registry's own SERVICE allow-list.
func TestWorkspaceToolSourceSchemaAdvertisedToServicePrincipals(t *testing.T) {
	harness := newSourceSchemaHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), mcpToolSourceSchema) {
		t.Fatalf("tools/list omitted %s: %s", mcpToolSourceSchema, response.Body.String())
	}
}

// fakeSourceSchemaNotesReader is the test double for workspacecontext.Reader:
// only SourceNotes is exercised by the source schema tool.
type fakeSourceSchemaNotesReader struct {
	notes workspacecontext.SourceNotes
	err   error
}

func (reader *fakeSourceSchemaNotesReader) Current(_ context.Context, _ workspacecontext.Access, _ string) (workspacecontext.Version, error) {
	return workspacecontext.Version{}, reader.err
}

func (reader *fakeSourceSchemaNotesReader) SourceNotes(_ context.Context, _ workspacecontext.Access, _, _ string) (workspacecontext.SourceNotes, error) {
	return reader.notes, reader.err
}

var _ workspacecontext.Reader = (*fakeSourceSchemaNotesReader)(nil)
var _ SourceSchemaProvider = (*fakeSourceService)(nil)
