package workspaceapi

// R3a-1 focused tests: the content-free denial mapping of the workspace source
// knowledge tools over both transports.
//
// The production source facade's SourceService.ListSources returns the typed
// workspacerepository CodeNotFound/CodeDenied for a non-member, unknown or
// foreign workspace. These tests inject that exact production error family and
// prove the REST /workspaces/{id}/tools/sources and /tools/refresh routes answer
// the documented 404 NOT_FOUND and the MCP knowvault_sources_list and
// knowvault_refresh tools answer -32004 "source scope not found", with no source
// content, no confirmation_context, no source scope id, no workspace-id echo and
// no confirmation-context read. They also pin the boundary: every
// registration-typed error and every plain error keeps its previous mapping, so
// only the typed workspacerepository denial is recognized.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// mcpToolCallOutcome is the decoded JSON-RPC envelope of one tools/call.
type mcpToolCallOutcome struct {
	Result *json.RawMessage `json:"result"`
	Error  *mcpErrorBody    `json:"error"`
}

func callMCPWorkspaceTool(t *testing.T, harness *testHarness, toolName, arguments string) mcpToolCallOutcome {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"denial","method":"tools/call","params":{"name":"`+toolName+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s transport status=%d body=%s", toolName, response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP %s did not decode: %v: %s", toolName, err, response.Body.String())
	}
	return outcome
}

// TestWorkspaceSourceToolsRESTDenialMapsWorkspacerepositoryCodes proves the
// production workspacerepository CodeNotFound and CodeDenied answer the single
// content-free 404 NOT_FOUND on both methods of both workspace source tools,
// without reading the confirmation context or leaking any source data.
func TestWorkspaceSourceToolsRESTDenialMapsWorkspacerepositoryCodes(t *testing.T) {
	cases := map[string]error{
		"not_found": workspacerepository.NewError(workspacerepository.CodeNotFound, errors.New("absent")),
		"denied":    workspacerepository.NewError(workspacerepository.CodeDenied, errors.New("denied")),
	}
	tools := map[string]string{
		"sources": apiPrefix + "/workspaces/ws_foreign/tools/sources",
		"refresh": apiPrefix + "/workspaces/ws_foreign/tools/refresh",
	}
	for caseName, injected := range cases {
		for toolName, path := range tools {
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				caseName, toolName, injected, path, method := caseName, toolName, injected, path, method
				t.Run(caseName+"/"+toolName+"/"+method, func(t *testing.T) {
					harness := newRestSourcesHarness(t)
					harness.sources.err = injected
					response := httptest.NewRecorder()
					harness.handler.ServeHTTP(response, harness.request(method, path, ""))
					if response.Code != http.StatusNotFound {
						t.Fatalf("%s %s denial status=%d body=%s", toolName, method, response.Code, response.Body.String())
					}
					if !strings.Contains(response.Body.String(), `"NOT_FOUND"`) {
						t.Fatalf("%s %s denial missing NOT_FOUND: %s", toolName, method, response.Body.String())
					}
					for _, leaked := range []string{"ws_foreign", "confirmation_context", testScopeID, "source_scope_id", `"sources"`} {
						if strings.Contains(response.Body.String(), leaked) {
							t.Fatalf("%s %s denial leaked %q: %s", toolName, method, leaked, response.Body.String())
						}
					}
					if harness.sources.confirmationContextCalls != 0 {
						t.Fatalf("%s %s denial read the confirmation context: calls=%d", toolName, method, harness.sources.confirmationContextCalls)
					}
					if harness.sources.syncRequest.SourceScopeID != "" {
						t.Fatalf("%s %s denial reached Sync with %q", toolName, method, harness.sources.syncRequest.SourceScopeID)
					}
				})
			}
		}
	}
}

// TestWorkspaceSourceToolsMCPDenialMapsWorkspacerepositoryCodes proves the same
// production workspacerepository denial answers -32004 "source scope not found"
// on both MCP tools, with no result member, no structuredContent and no content.
func TestWorkspaceSourceToolsMCPDenialMapsWorkspacerepositoryCodes(t *testing.T) {
	cases := map[string]error{
		"not_found": workspacerepository.NewError(workspacerepository.CodeNotFound, errors.New("absent")),
		"denied":    workspacerepository.NewError(workspacerepository.CodeDenied, errors.New("denied")),
	}
	tools := map[string]string{
		mcpToolSourcesList: `{"workspace_id":"ws_foreign"}`,
		mcpToolRefresh:     `{"workspace_id":"ws_foreign"}`,
	}
	for caseName, injected := range cases {
		for toolName, arguments := range tools {
			caseName, toolName, injected, arguments := caseName, toolName, injected, arguments
			t.Run(caseName+"/"+toolName, func(t *testing.T) {
				harness := newRestSourcesHarness(t)
				harness.sources.err = injected
				outcome := callMCPWorkspaceTool(t, harness, toolName, arguments)
				if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "source scope not found" {
					t.Fatalf("MCP %s denial error=%#v", toolName, outcome.Error)
				}
				if outcome.Result != nil {
					t.Fatalf("MCP %s denial carried a result: %s", toolName, string(*outcome.Result))
				}
				if harness.sources.confirmationContextCalls != 0 {
					t.Fatalf("MCP %s denial read the confirmation context: calls=%d", toolName, harness.sources.confirmationContextCalls)
				}
				if harness.sources.syncRequest.SourceScopeID != "" {
					t.Fatalf("MCP %s denial reached Sync with %q", toolName, harness.sources.syncRequest.SourceScopeID)
				}
			})
		}
	}
}

// TestWorkspaceSourceToolsRegistrationMappingUnchanged proves every
// registration-typed error keeps its exact previous REST status/public code and
// MCP JSON-RPC code, and that a plain Go error stays a 503 service-unavailable
// rather than being reclassified as a denial.
func TestWorkspaceSourceToolsRegistrationMappingUnchanged(t *testing.T) {
	restCases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{"invalid", registration.NewRegistrationError(registration.CodeRequestInvalid, nil), http.StatusBadRequest, "REQUEST_INVALID"},
		{"conflict", registration.NewRegistrationError(registration.CodeConflict, nil), http.StatusConflict, "SOURCE_CONFLICT"},
		{"unavailable", registration.NewRegistrationError(registration.CodeUnavailable, nil), http.StatusServiceUnavailable, "SOURCE_UNAVAILABLE"},
		{"unknown_registration", registration.NewRegistrationError(registration.CodePersistence, nil), http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"},
		{"plain_error", errors.New("unexpected dependency failure"), http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"},
	}
	mcpCodes := map[string]int{
		"invalid":              -32602,
		"conflict":             -32009,
		"unavailable":          -32000,
		"unknown_registration": -32000,
		"plain_error":          -32000,
	}
	for _, fixture := range restCases {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			harness := newRestSourcesHarness(t)
			harness.sources.err = fixture.err
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet,
				apiPrefix+"/workspaces/ws_alpha/tools/sources", ""))
			if response.Code != fixture.wantStatus || !strings.Contains(response.Body.String(), `"`+fixture.wantCode+`"`) {
				t.Fatalf("REST %s status=%d body=%s", fixture.name, response.Code, response.Body.String())
			}

			mcpHarness := newRestSourcesHarness(t)
			mcpHarness.sources.err = fixture.err
			outcome := callMCPWorkspaceTool(t, mcpHarness, mcpToolSourcesList, `{"workspace_id":"ws_alpha"}`)
			if outcome.Error == nil || outcome.Error.Code != mcpCodes[fixture.name] {
				t.Fatalf("MCP %s error=%#v", fixture.name, outcome.Error)
			}
			if outcome.Error.Code == -32004 {
				t.Fatalf("MCP %s was reclassified as a content-free denial", fixture.name)
			}
		})
	}
}

// TestWorkspaceSourceToolsAuthorizedMemberProjectionUnchanged proves the typed
// denial normalization does not disturb the successful path: an authorized
// member still observes the identical {sources, confirmation_context} REST/MCP
// projection and the same refresh projection on both transports.
func TestWorkspaceSourceToolsAuthorizedMemberProjectionUnchanged(t *testing.T) {
	harness := newRestSourcesHarness(t)
	harness.sources.syncResult = registration.SyncResult{JobID: "job_01H9ABCDEFGHJKMNPQRSTVWXYZ"}
	restSources := httptest.NewRecorder()
	harness.handler.ServeHTTP(restSources, harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/tools/sources", ""))
	if restSources.Code != http.StatusOK {
		t.Fatalf("authorized REST sources status=%d body=%s", restSources.Code, restSources.Body.String())
	}
	if harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
		t.Fatalf("authorized REST sources reads call=%q confirmation=%d", harness.sources.call, harness.sources.confirmationContextCalls)
	}
	restSourcesBody := decodeJSONObject(t, restSources.Body.String())

	mcpSources := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpSources, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ok","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_alpha"}}}`))
	if mcpSources.Code != http.StatusOK {
		t.Fatalf("authorized MCP sources status=%d body=%s", mcpSources.Code, mcpSources.Body.String())
	}
	mcpStructured := decodeMCPResultStructured(t, mcpSources.Body.String())
	if restSourcesBody["sources"] == nil || restSourcesBody["confirmation_context"] == nil {
		t.Fatalf("authorized REST sources omitted a projection member: %#v", restSourcesBody)
	}
	if mcpStructured["sources"] == nil || mcpStructured["confirmation_context"] == nil {
		t.Fatalf("authorized MCP sources omitted a projection member: %#v", mcpStructured)
	}

	restRefresh := httptest.NewRecorder()
	harness.handler.ServeHTTP(restRefresh, harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/tools/refresh", ""))
	if restRefresh.Code != http.StatusOK {
		t.Fatalf("authorized REST refresh status=%d body=%s", restRefresh.Code, restRefresh.Body.String())
	}
	mcpRefresh := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpRefresh, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ok2","method":"tools/call","params":{"name":"`+mcpToolRefresh+`","arguments":{"workspace_id":"ws_alpha"}}}`))
	if mcpRefresh.Code != http.StatusOK {
		t.Fatalf("authorized MCP refresh status=%d body=%s", mcpRefresh.Code, mcpRefresh.Body.String())
	}
	mcpRefreshStructured := decodeMCPResultStructured(t, mcpRefresh.Body.String())
	restRefreshBody := decodeJSONObject(t, restRefresh.Body.String())
	if restRefreshBody["refreshed"] == nil || mcpRefreshStructured["refreshed"] == nil {
		t.Fatalf("authorized refresh omitted the refreshed projection: REST=%#v MCP=%#v", restRefreshBody, mcpRefreshStructured)
	}
}
