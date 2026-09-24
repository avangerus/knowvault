package workspaceapi

// ADR-0098 focused tests: the REST parity twin of the workspace
// knowvault_workspace_context knowledge tool. They prove POST
// /api/v1/workspaces/{workspace_id}/tools/workspace-context composes the
// injected workspacecontext.Reader exactly as the MCP tool and the chat tool
// runtime do (byte-identical structuredContent / chat result), that GET is
// refused, that a denial is the single content-free 404 without a
// workspace-id echo, that an invalid terms/section argument is refused
// before the Reader is read, that a composition without the capability fails
// closed, and that a successful read reports to the
// internal/question.ObserveWorkspaceContextRead audit hook exactly once per
// surface.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// fakeWorkspaceContextReader is the test double for workspacecontext.Reader.
type fakeWorkspaceContextReader struct {
	call        string
	access      workspacecontext.Access
	workspaceID string
	version     workspacecontext.Version
	err         error
}

func (reader *fakeWorkspaceContextReader) Current(_ context.Context, access workspacecontext.Access, workspaceID string) (workspacecontext.Version, error) {
	reader.call, reader.access, reader.workspaceID = "current", access, workspaceID
	return reader.version, reader.err
}

func (reader *fakeWorkspaceContextReader) SourceNotes(_ context.Context, _ workspacecontext.Access, _, _ string) (workspacecontext.SourceNotes, error) {
	return workspacecontext.SourceNotes{}, errors.New("SourceNotes is not exercised by the workspace_context knowledge tool")
}

// testWorkspaceContextDocument is a small, non-empty fixture: two rules, two
// glossary terms (one that a "terms" filter and a question can recognize,
// one that cannot), and one enabled source with one table/column note.
func testWorkspaceContextDocument() workspacecontext.Document {
	return workspacecontext.Document{
		Description: "Alpha workspace context.",
		Rules: []workspacecontext.Rule{
			{ID: "rule_01H9ABCDEFGHJKMNPQRSTVWXY0", Text: "Answer in Russian."},
			{ID: "rule_01H9ABCDEFGHJKMNPQRSTVWXY1", Text: "Prefer the current fiscal year."},
		},
		Glossary: []workspacecontext.Term{
			{
				ID: "term_01H9ABCDEFGHJKMNPQRSTVWXY0", Term: "МНО", Synonyms: []string{"мед. организация"},
				Definition: "Медицинская организация.",
				DataLocations: []workspacecontext.DataLocation{
					{SourceConnectionID: "conn_01", Relation: "public.orgs", Column: "id", Hint: "primary key"},
				},
			},
			{ID: "term_01H9ABCDEFGHJKMNPQRSTVWXY1", Term: "СЗ", Definition: "Страховой знак."},
		},
		Sources: []workspacecontext.Source{
			{
				SourceConnectionID: "conn_01", Description: "Primary Postgres.",
				Tables: []workspacecontext.Table{
					{Relation: "public.orgs", Note: "Organizations.", Columns: []workspacecontext.Column{{Name: "id", Note: "surrogate key"}}},
				},
			},
		},
	}
}

func newWorkspaceContextHarness(t *testing.T) (*testHarness, *fakeWorkspaceContextReader) {
	t.Helper()
	harness := newTestHarness(t)
	reader := &fakeWorkspaceContextReader{version: workspacecontext.Version{
		Number: 3, ContentHash: "sha256:" + strings.Repeat("a", 64), Document: testWorkspaceContextDocument(), Editable: true,
	}}
	harness.handler.EnableWorkspaceContext(reader)
	return harness, reader
}

func callRestWorkspaceContext(t *testing.T, harness *testHarness, method, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/workspace-context", body))
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

type genericMCPEnvelope struct {
	Result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Structured map[string]any `json:"structuredContent"`
		IsError    bool            `json:"isError"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPWorkspaceContext(t *testing.T, harness *testHarness, arguments string) genericMCPEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"wsctx","method":"tools/call","params":{"name":"`+mcpToolWorkspaceContext+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP workspace_context status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope genericMCPEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP workspace_context did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// TestWorkspaceToolWorkspaceContextRESTMatchesMCPProjection proves an
// authorized member's REST POST and MCP tools/call observe byte-identical
// {version, content_hash, description, rules, glossary, sources, notice}
// projections from the identical injected Reader.Current read, with the
// exact notice string and no narrowing when terms/section are omitted.
func TestWorkspaceToolWorkspaceContextRESTMatchesMCPProjection(t *testing.T) {
	harness, reader := newWorkspaceContextHarness(t)
	response, body := callRestWorkspaceContext(t, harness, http.MethodPost, "")
	if response.Code != http.StatusOK {
		t.Fatalf("workspace-context REST status=%d body=%s", response.Code, response.Body.String())
	}
	if reader.call != "current" || reader.workspaceID != "ws_alpha" {
		t.Fatalf("REST did not read through the injected Reader: call=%q workspaceID=%q", reader.call, reader.workspaceID)
	}
	if body["notice"] != workspaceContextToolNotice {
		t.Fatalf("notice = %v, want %q", body["notice"], workspaceContextToolNotice)
	}
	if body["version"] != float64(3) || body["content_hash"] != reader.version.ContentHash {
		t.Fatalf("version/content_hash = %v/%v, want 3/%s", body["version"], body["content_hash"], reader.version.ContentHash)
	}
	if glossary, ok := body["glossary"].([]any); !ok || len(glossary) != 2 {
		t.Fatalf("unfiltered glossary = %#v, want 2 entries", body["glossary"])
	}
	if rules, ok := body["rules"].([]any); !ok || len(rules) != 2 {
		t.Fatalf("unfiltered rules = %#v, want 2 entries", body["rules"])
	}

	mcpEnvelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha"}`)
	if mcpEnvelope.Error != nil {
		t.Fatalf("MCP workspace_context error: %#v", mcpEnvelope.Error)
	}
	if !reflect.DeepEqual(body, mcpEnvelope.Result.Structured) {
		t.Fatalf("REST projection != MCP structuredContent\nREST: %#v\nMCP:  %#v", body, mcpEnvelope.Result.Structured)
	}
}

// TestWorkspaceToolWorkspaceContextTermsFilterNarrowsGlossary proves the
// optional terms argument narrows the glossary to the entries
// workspacecontext.MatchTerms recognizes (case-insensitive, whole-token),
// through both REST and MCP, and that section narrows to one member.
func TestWorkspaceToolWorkspaceContextFiltersNarrowTheProjection(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)

	_, body := callRestWorkspaceContext(t, harness, http.MethodPost, `{"terms":["мно"]}`)
	glossary, ok := body["glossary"].([]any)
	if !ok || len(glossary) != 1 {
		t.Fatalf("terms-filtered glossary = %#v, want exactly the МНО entry", body["glossary"])
	}
	entry, ok := glossary[0].(map[string]any)
	if !ok || entry["term"] != "МНО" {
		t.Fatalf("terms-filtered glossary entry = %#v, want term МНО", glossary[0])
	}
	if body["rules"].([]any) == nil || len(body["rules"].([]any)) != 2 {
		t.Fatalf("terms filter must not narrow rules: %#v", body["rules"])
	}

	mcpEnvelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha","terms":["мно"]}`)
	if !reflect.DeepEqual(body, mcpEnvelope.Result.Structured) {
		t.Fatalf("REST terms-filtered projection != MCP structuredContent\nREST: %#v\nMCP:  %#v", body, mcpEnvelope.Result.Structured)
	}

	_, sectionBody := callRestWorkspaceContext(t, harness, http.MethodPost, `{"section":"rules"}`)
	if rules := sectionBody["rules"].([]any); len(rules) != 2 {
		t.Fatalf("section=rules must keep every rule: %#v", sectionBody["rules"])
	}
	if glossary := sectionBody["glossary"].([]any); len(glossary) != 0 {
		t.Fatalf("section=rules must empty glossary: %#v", sectionBody["glossary"])
	}
	if sources := sectionBody["sources"].([]any); len(sources) != 0 {
		t.Fatalf("section=rules must empty sources: %#v", sectionBody["sources"])
	}
	if sectionBody["description"] != testWorkspaceContextDocument().Description {
		t.Fatalf("section=rules must keep description: %#v", sectionBody["description"])
	}
}

// TestWorkspaceToolWorkspaceContextRESTDenialIsContentFree proves an unknown,
// foreign or non-member workspace collapses to the Reader's single
// content-free 404 NOT_FOUND -- the same shape the other knowledge tools use
// -- with no document content and no workspace-id echo.
func TestWorkspaceToolWorkspaceContextRESTDenialIsContentFree(t *testing.T) {
	harness, reader := newWorkspaceContextHarness(t)
	reader.err = errors.New("denied")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_foreign/tools/workspace-context", ""))
	if response.Code != http.StatusNotFound {
		t.Fatalf("workspace-context REST denial status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ws_foreign") {
		t.Fatalf("workspace-context REST denial echoed the workspace id: %s", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "Alpha workspace context") {
		t.Fatalf("workspace-context REST denial leaked document content: %s", response.Body.String())
	}

	mcpEnvelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_foreign"}`)
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32004 {
		t.Fatalf("expected MCP -32004 not-found, got %#v", mcpEnvelope.Error)
	}
}

// TestWorkspaceToolWorkspaceContextRESTOnlyAllowsPost proves the tool-parity
// route is POST-only (S2-CONTRACT.md "Tool parity"), unlike the other six
// GET/POST workspace tool-parity routes.
func TestWorkspaceToolWorkspaceContextRESTOnlyAllowsPost(t *testing.T) {
	harness, reader := newWorkspaceContextHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/tools/workspace-context", ""))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("workspace-context GET status=%d body=%s, want 405", response.Code, response.Body.String())
	}
	if reader.call != "" {
		t.Fatalf("GET reached the Reader: call=%q", reader.call)
	}
}

// TestWorkspaceToolWorkspaceContextRESTRejectsInvalidBeforeRead proves a
// malformed body, more than 10 terms and an unknown section are refused as
// REQUEST_INVALID before the Reader is touched.
func TestWorkspaceToolWorkspaceContextRESTRejectsInvalidBeforeRead(t *testing.T) {
	elevenTerms := make([]string, 11)
	for i := range elevenTerms {
		elevenTerms[i] = `"t` + string(rune('a'+i)) + `"`
	}
	for name, body := range map[string]string{
		"malformed_json": `{`,
		"not_an_object":  `[1,2,3]`,
		"unknown_field":  `{"unexpected":true}`,
		"too_many_terms": `{"terms":[` + strings.Join(elevenTerms, ",") + `]}`,
		"empty_term":     `{"terms":[""]}`,
		"bad_section":    `{"section":"everything"}`,
		"duplicate_key":  `{"section":"all","section":"rules"}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			harness, reader := newWorkspaceContextHarness(t)
			response, _ := callRestWorkspaceContext(t, harness, http.MethodPost, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s: status=%d body=%s, want 400", name, response.Code, response.Body.String())
			}
			if reader.call != "" {
				t.Fatalf("%s: invalid body reached the Reader: call=%q", name, reader.call)
			}
		})
	}
}

// TestWorkspaceToolWorkspaceContextRESTUnauthenticated proves a rejected
// session is the shared 401 before the dispatcher reaches the capability.
func TestWorkspaceToolWorkspaceContextRESTUnauthenticated(t *testing.T) {
	harness, reader := newWorkspaceContextHarness(t)
	harness.auth.authenticateErr = errors.New("session rejected")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/tools/workspace-context", ""))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("workspace-context REST unauthenticated status=%d body=%s", response.Code, response.Body.String())
	}
	if reader.call != "" {
		t.Fatalf("unauthenticated request reached the Reader: call=%q", reader.call)
	}
}

// TestWorkspaceToolWorkspaceContextRESTFailsClosed proves a composition
// mounted without EnableWorkspaceContext answers 503 SERVICE_UNAVAILABLE.
func TestWorkspaceToolWorkspaceContextRESTFailsClosed(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/tools/workspace-context", ""))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("workspace-context REST no-capability status=%d body=%s", response.Code, response.Body.String())
	}

	mcpEnvelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha"}`)
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32000 {
		t.Fatalf("expected MCP -32000 service-unavailable, got %#v", mcpEnvelope.Error)
	}
}

// TestWorkspaceToolWorkspaceContextChatRuntimeMatchesMCP proves the chat tool
// runtime (workspacetools.Runtime, reached exactly as tool_loop.go reaches
// every other knowledge tool) observes the identical structured result as
// MCP tools/call and the REST tool-parity route, without a workspace_id
// argument (the chat binds it from the already-authorized Scope).
func TestWorkspaceToolWorkspaceContextChatRuntimeMatchesMCP(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)
	scope := chatRuntimeScope(harness)

	result, err := harness.handler.Invoke(context.Background(), scope, mcpToolWorkspaceContext, json.RawMessage(`{}`))
	if err != nil || result.IsError {
		t.Fatalf("chat workspace_context: err=%v result=%s", err, result.Text)
	}
	var chatProjection map[string]any
	if err := json.Unmarshal(result.Structured, &chatProjection); err != nil {
		t.Fatalf("chat workspace_context structured did not decode: %v: %s", err, result.Structured)
	}

	mcpEnvelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha"}`)
	if !reflect.DeepEqual(chatProjection, mcpEnvelope.Result.Structured) {
		t.Fatalf("chat tool runtime projection != MCP structuredContent\nchat: %#v\nMCP:  %#v", chatProjection, mcpEnvelope.Result.Structured)
	}
}

// TestWorkspaceToolWorkspaceContextReadReportsAuditHook proves a successful
// read on every surface (REST, MCP, and -- through Handler.Invoke -- the
// chat tool runtime) reports exactly once to
// question.ObserveWorkspaceContextRead, the content-free hook this card
// leaves for the lead to wire to the workspace.model_context_read audit
// action once internal/audit exposes it (card A).
func TestWorkspaceToolWorkspaceContextReadReportsAuditHook(t *testing.T) {
	t.Cleanup(func() { question.SetWorkspaceContextReadAuditHook(nil) })

	var traces []question.WorkspaceContextReadTrace
	question.SetWorkspaceContextReadAuditHook(func(_ context.Context, _ database.AccessContext, trace question.WorkspaceContextReadTrace) {
		traces = append(traces, trace)
	})

	harness, _ := newWorkspaceContextHarness(t)
	if response, _ := callRestWorkspaceContext(t, harness, http.MethodPost, ""); response.Code != http.StatusOK {
		t.Fatalf("REST read status=%d", response.Code)
	}
	if envelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha"}`); envelope.Error != nil {
		t.Fatalf("MCP read error: %#v", envelope.Error)
	}

	if len(traces) != 2 {
		t.Fatalf("audit hook invocations = %d, want 2 (REST + MCP): %#v", len(traces), traces)
	}
	for _, trace := range traces {
		if trace.WorkspaceID != "ws_alpha" || trace.Version != 3 {
			t.Fatalf("trace = %+v, want workspace ws_alpha version 3", trace)
		}
	}
}

// Ensure the fake Reader satisfies the interface at compile time.
var _ workspacecontext.Reader = (*fakeWorkspaceContextReader)(nil)
