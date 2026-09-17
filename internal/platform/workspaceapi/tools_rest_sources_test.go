package workspaceapi

// R3a-1 focused tests: the REST parity twin of the workspace
// knowvault_sources_list source-inventory/schedule knowledge tool. They prove
// GET and POST /api/v1/workspaces/{workspace_id}/tools/sources compose exactly
// the same injected SourceService.ListSources + ConfirmationContext reads and
// return the byte-identical {sources, confirmation_context} projection the MCP
// tool returns, that a denial is the single content-free not-found without a
// workspace-id echo and without either service read, that an unauthenticated
// request is 401, that no query member is a parameter channel and a non-empty
// POST body is refused before any service read, that a composition without the
// source capability fails closed, and that no MCP tool name or tools/list
// advertisement changes.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// newRestSourcesHarness builds the shared test harness with a rich, non-empty
// source inventory and confirmation context so the parity projection carries
// every status field the MCP tool projects.
func newRestSourcesHarness(t *testing.T) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	started := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	completed := started.Add(2 * time.Minute)
	syncStatus := "SYNCED"
	syncError := "NONE"
	jobID := "job_01H9ABCDEFGHJKMNPQRSTVWXYZ"
	jobStatus := "QUEUED"
	jobError := "NONE"
	objectsSeen, objectsIngested := int64(10), int64(9)
	versionsCreated, evidencePublished := int64(9), int64(9)
	quarantined := int64(1)
	jobAttempts, jobMaxAttempts := int64(0), int64(3)
	harness.sources.statuses = []workspacerepository.SourceStatus{{
		WorkspaceSourceID: "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: testScopeID,
		SourceScopeRevision: 2, AccessMode: "WORKSPACE_MANAGED", Enabled: true, ScopeConfigHash: testHash,
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionName: "Engineering docs",
		ActivationStatus: "READY", TrustVerified: true,
		SyncStatus: &syncStatus, SyncErrorCode: &syncError, SyncStartedAt: &started, SyncCompletedAt: &completed,
		ObjectsSeen: &objectsSeen, ObjectsIngested: &objectsIngested,
		VersionsCreated: &versionsCreated, EvidencePublished: &evidencePublished, Quarantined: &quarantined,
		JobID: &jobID, JobStatus: &jobStatus, JobAttemptCount: &jobAttempts, JobMaxAttempts: &jobMaxAttempts,
		JobAvailableAt: &started, JobLeaseExpiresAt: &completed, JobLastErrorCode: &jobError,
		ContentFreshnessSLASeconds: 3600, LastSuccessfulSyncAt: &completed, FreshnessState: "FRESH",
		SyncIntervalSeconds: 1800, Confirmed: true,
	}}
	harness.sources.confirmationContext = workspacerepository.ConfirmationContext{
		ExpectedPolicyRevision: "policy-acc-0001",
		WarningVersion:         "workspace-managed-risk-v1", WarningContractHash: testHash,
		ViewerPrincipalID: "principal_alpha", CanIssueConfirmationGrant: true, CanVerifyConnectionTrust: true,
		SelfGrant: &workspacerepository.SelfConfirmationGrant{
			GrantID: "grant_01", GrantRevision: 1, GrantHash: testHash, ValidUntil: "2026-09-06T15:00:00Z",
		},
	}
	return harness
}

func callRestSources(t *testing.T, harness *testHarness, method, query, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/sources"+query, body))
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

// TestWorkspaceToolSourcesRESTMatchesMCPProjection proves an authorized member
// GET and POST both observe the exact MCP knowvault_sources_list
// structuredContent projection, composed from the same two SourceService reads.
func TestWorkspaceToolSourcesRESTMatchesMCPProjection(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			harness := newRestSourcesHarness(t)
			response, body := callRestSources(t, harness, method, "", "")
			if response.Code != http.StatusOK {
				t.Fatalf("sources REST %s status=%d body=%s", method, response.Code, response.Body.String())
			}
			if harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
				t.Fatalf("sources REST %s did not compose both SourceService reads: call=%q confirmationContextCalls=%d",
					method, harness.sources.call, harness.sources.confirmationContextCalls)
			}
			if body["sources"] == nil || body["confirmation_context"] == nil {
				t.Fatalf("sources REST %s omitted a projection member: %#v", method, body)
			}

			mcpResponse := httptest.NewRecorder()
			harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
				`{"jsonrpc":"2.0","id":"srcr","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_alpha"}}}`))
			if mcpResponse.Code != http.StatusOK {
				t.Fatalf("MCP sources list status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
			}
			mcpStructured := decodeMCPResultStructured(t, mcpResponse.Body.String())
			if !reflect.DeepEqual(body, mcpStructured) {
				t.Fatalf("sources REST %s projection != MCP structuredContent\nREST: %#v\nMCP:  %#v", method, body, mcpStructured)
			}
			if !strings.Contains(response.Body.String(), testScopeID) ||
				!strings.Contains(response.Body.String(), "policy-acc-0001") {
				t.Fatalf("sources REST %s projection missing inventory fields: %s", method, response.Body.String())
			}
		})
	}
}

// TestWorkspaceToolSourcesRESTDenialIsContentFree proves an unknown workspace
// or a non-member caller collapses to the single content-free 404 NOT_FOUND
// with no source content and no workspace-id echo, without reading the
// confirmation context.
func TestWorkspaceToolSourcesRESTDenialIsContentFree(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.sources.err = registration.NewRegistrationError(registration.CodeDenied, nil)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(method,
				apiPrefix+"/workspaces/ws_foreign/tools/sources", ""))
			if response.Code != http.StatusNotFound {
				t.Fatalf("sources REST %s denial status=%d body=%s", method, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "ws_foreign") {
				t.Fatalf("sources REST %s denial echoed the workspace id: %s", method, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "confirmation_context") ||
				strings.Contains(response.Body.String(), testScopeID) {
				t.Fatalf("sources REST %s denial leaked source content: %s", method, response.Body.String())
			}
			if harness.sources.confirmationContextCalls != 0 {
				t.Fatalf("sources REST denial read the confirmation context: calls=%d", harness.sources.confirmationContextCalls)
			}
		})
	}
}

// TestWorkspaceToolSourcesRESTUnauthenticated proves a rejected session is the
// shared 401 before the dispatcher reaches the source capability.
func TestWorkspaceToolSourcesRESTUnauthenticated(t *testing.T) {
	harness := newTestHarness(t)
	harness.auth.authenticateErr = errors.New("session rejected")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/tools/sources", ""))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("sources REST unauthenticated status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.call != "" || harness.sources.confirmationContextCalls != 0 {
		t.Fatalf("unauthenticated sources REST reached SourceService: call=%q confirmationContextCalls=%d",
			harness.sources.call, harness.sources.confirmationContextCalls)
	}
}

// TestWorkspaceToolSourcesRESTRejectsInvalidBeforeRead proves no query member
// is a parameter channel and a non-empty POST body is refused as
// REQUEST_INVALID before either service read.
func TestWorkspaceToolSourcesRESTRejectsInvalidBeforeRead(t *testing.T) {
	for name, query := range map[string]string{
		"unknown_key":      "?extra=true",
		"limit_key":        "?limit=1",
		"duplicate":        "?limit=1&limit=2",
		"empty_value":      "?limit=",
		"bare_question":    "?",
		"malformed_escape": "?limit=%zz",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			harness := newRestSourcesHarness(t)
			response, _ := callRestSources(t, harness, http.MethodGet, query, "")
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.Code, response.Body.String())
			}
			if harness.sources.call != "" || harness.sources.confirmationContextCalls != 0 {
				t.Fatalf("invalid query reached SourceService: call=%q confirmationContextCalls=%d",
					harness.sources.call, harness.sources.confirmationContextCalls)
			}
		})
	}

	harness := newRestSourcesHarness(t)
	response, _ := callRestSources(t, harness, http.MethodPost, "", `{"workspace_id":"ws_alpha"}`)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unexpected body, got %d body=%s", response.Code, response.Body.String())
	}
	if harness.sources.call != "" || harness.sources.confirmationContextCalls != 0 {
		t.Fatalf("unexpected body reached SourceService: call=%q confirmationContextCalls=%d",
			harness.sources.call, harness.sources.confirmationContextCalls)
	}
}

// TestWorkspaceToolSourcesRESTFailsClosed proves a composition mounted without
// the source capability answers 503 SERVICE_UNAVAILABLE rather than panicking.
func TestWorkspaceToolSourcesRESTFailsClosed(t *testing.T) {
	harness := newTestHarness(t)
	harness.handler.sources = nil
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/tools/sources", ""))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("sources REST no-capability status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestWorkspaceToolSourcesRESTLeavesMCPAdvertisementUnchanged proves the
// canonical MCP name is still advertised and no wiki-rag alias is.
func TestWorkspaceToolSourcesRESTLeavesMCPAdvertisementUnchanged(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", response.Code, response.Body.String())
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatalf("tools/list did not decode: %v: %s", err, response.Body.String())
	}
	advertised := map[string]bool{}
	for _, tool := range list.Result.Tools {
		advertised[tool.Name] = true
	}
	if !advertised[mcpToolSourcesList] {
		t.Fatalf("tools/list omitted the canonical %s: %s", mcpToolSourcesList, response.Body.String())
	}
	for _, removed := range []string{"wiki_search", "wiki_get_page", "wiki_list_pages", "wiki_find_related", "code_search", "code_get_file"} {
		if advertised[removed] {
			t.Fatalf("tools/list still advertises the removed alias %q", removed)
		}
	}
}
