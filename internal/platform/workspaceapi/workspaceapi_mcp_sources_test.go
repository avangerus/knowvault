package workspaceapi

// R3a-1 Outcome 2 focused tests for the read-only knowvault_sources_list MCP
// tool: it must be advertised to a non-SERVICE principal with a closed
// single-field schema, dispatched through the same SourceService reads the REST
// listSources route composes, project the identical JSON, and refuse unbounded
// arguments or unknown workspaces with the same content-free surface REST uses.

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestMCPToolsListAdvertisesSourcesListTool proves a non-SERVICE (human or
// operator) session sees knowvault_sources_list with exactly the closed
// {workspace_id} schema, and a V1-C SERVICE agent principal sees it too: the
// read-only source inventory is a workspace knowledge tool under R3a-1
// Outcome 3, not an administrative one.
func TestMCPToolsListAdvertisesSourcesListTool(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", response.Code, response.Body.String())
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal([]byte(response.Body.String()), &list); err != nil || list.Error != nil {
		t.Fatalf("tools/list did not decode: err=%v error=%#v body=%s", err, list.Error, response.Body.String())
	}
	var schema map[string]any
	for _, tool := range list.Result.Tools {
		if tool.Name == mcpToolSourcesList {
			schema = tool.InputSchema
		}
	}
	if schema == nil {
		t.Fatalf("tools/list omitted %s: %s", mcpToolSourcesList, response.Body.String())
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("sources list inputSchema additionalProperties=%#v", schema["additionalProperties"])
	}
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "workspace_id" {
		t.Fatalf("sources list inputSchema required=%#v", schema["required"])
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok || len(properties) != 1 {
		t.Fatalf("sources list inputSchema properties=%#v", schema["properties"])
	}
	if spec, ok := properties["workspace_id"].(map[string]any); !ok || spec["type"] != "string" {
		t.Fatalf("sources list workspace_id spec=%#v", properties["workspace_id"])
	}

	service := database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "principal_agent",
		RequestID: "req_agent", ActorKind: database.ActorKindService,
	}
	advertised := false
	for _, name := range toolNames(t, mcpToolCatalog(service)) {
		if name == mcpToolSourcesList {
			advertised = true
		}
	}
	if !advertised {
		t.Fatalf("a SERVICE principal must be advertised %s", mcpToolSourcesList)
	}
}

// TestMCPSourcesListMatchesRESTSourcesProjection proves the MCP tool composes
// exactly the two SourceService reads the REST listSources route composes, with
// the authenticated access context, and returns the identical projection for
// the same workspace.
func TestMCPSourcesListMatchesRESTSourcesProjection(t *testing.T) {
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
	postgresqlSchemaName, postgresqlRelationName := "reporting", "waste_daily"
	jobAttempts, jobMaxAttempts := int64(0), int64(3)
	availableAt := started
	harness.sources.statuses = []workspacerepository.SourceStatus{{
		WorkspaceSourceID: "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: testScopeID,
		SourceScopeRevision: 2, AccessMode: "WORKSPACE_MANAGED", Enabled: true, ScopeConfigHash: testHash,
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionName: "Engineering docs",
		SourceType: "POSTGRESQL_QUERY", PostgreSQLSchemaName: &postgresqlSchemaName, PostgreSQLRelationName: &postgresqlRelationName,
		ActivationStatus: "READY", TrustVerified: true,
		SyncStatus: &syncStatus, SyncErrorCode: &syncError, SyncStartedAt: &started, SyncCompletedAt: &completed,
		ObjectsSeen: &objectsSeen, ObjectsIngested: &objectsIngested,
		VersionsCreated: &versionsCreated, EvidencePublished: &evidencePublished, Quarantined: &quarantined,
		JobID: &jobID, JobStatus: &jobStatus, JobAttemptCount: &jobAttempts, JobMaxAttempts: &jobMaxAttempts,
		JobAvailableAt: &availableAt, JobLeaseExpiresAt: &completed, JobLastErrorCode: &jobError,
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

	restResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(restResponse, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", ""))
	if restResponse.Code != http.StatusOK || harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
		t.Fatalf("REST listSources status=%d call=%q confirmationContextCalls=%d body=%s", restResponse.Code, harness.sources.call, harness.sources.confirmationContextCalls, restResponse.Body.String())
	}

	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"src1","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_alpha"}}}`))
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP sources list status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	if harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 2 {
		t.Fatalf("MCP sources list did not dispatch through both SourceService reads: call=%q confirmationContextCalls=%d", harness.sources.call, harness.sources.confirmationContextCalls)
	}
	if harness.sources.access.RequestID != "req_server_001" || harness.sources.confirmationContextAccess.RequestID != "req_server_001" {
		t.Fatalf("sources reads did not receive the authenticated access context: list=%#v confirmation=%#v", harness.sources.access, harness.sources.confirmationContextAccess)
	}

	restProjection := decodeJSONObject(t, restResponse.Body.String())
	mcpStructured := decodeMCPResultStructured(t, mcpResponse.Body.String())
	if !reflect.DeepEqual(restProjection, mcpStructured) {
		t.Fatalf("MCP sources projection != REST listSources projection\nREST: %#v\nMCP:  %#v", restProjection, mcpStructured)
	}
	if !strings.Contains(mcpResponse.Body.String(), testScopeID) || !strings.Contains(mcpResponse.Body.String(), "policy-acc-0001") {
		t.Fatalf("MCP sources projection missing inventory fields: %s", mcpResponse.Body.String())
	}
	if !strings.Contains(mcpResponse.Body.String(), `"source_type":"POSTGRESQL_QUERY"`) ||
		!strings.Contains(mcpResponse.Body.String(), `"postgresql_schema_name":"reporting"`) ||
		!strings.Contains(mcpResponse.Body.String(), `"postgresql_relation_name":"waste_daily"`) {
		t.Fatalf("MCP sources projection missing PostgreSQL identity fields: %s", mcpResponse.Body.String())
	}
}

// TestMCPSourcesListServicePrincipalIsDispatched proves the SERVICE allow-list
// keeps the read-only inventory tool on the call path too: an agent access-code
// principal reaches both SourceService reads and receives the normal
// projection rather than the -32601 an administrative tool gets (R3a-1
// Outcome 3).
func TestMCPSourcesListServicePrincipalIsDispatched(t *testing.T) {
	harness := newTestHarness(t)
	access := database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "principal_agent",
		RequestID: "req_agent", ActorKind: database.ActorKindService,
	}
	request := httptest.NewRequest(http.MethodPost, "https://workspace.example"+apiPrefix+"/mcp", nil)
	envelope := mcpRequest{
		JSONRPC: "2.0", ID: jsontext.Value("1"), Method: "tools/call",
		Params: jsontext.Value(`{"name":"` + mcpToolSourcesList + `","arguments":{"workspace_id":"ws_alpha"}}`),
	}
	response := httptest.NewRecorder()
	harness.handler.mcpToolCall(response, request, access, envelope)
	if harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
		t.Fatalf("SERVICE sources call did not reach both SourceService reads: call=%q confirmationContextCalls=%d body=%s", harness.sources.call, harness.sources.confirmationContextCalls, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"code":-32601`) || !strings.Contains(response.Body.String(), "structuredContent") {
		t.Fatalf("SERVICE sources call was not dispatched to the normal projection: %s", response.Body.String())
	}
}

// TestMCPSourcesListRejectsUnboundedArguments proves the tool honors its closed
// single-field schema: a missing workspace, an empty workspace, a wrong-typed
// member or an unknown member is rejected at the transport boundary and never
// reaches either SourceService read.
func TestMCPSourcesListRejectsUnboundedArguments(t *testing.T) {
	for name, args := range map[string]string{
		"missing_workspace_id": `{}`,
		"empty_workspace_id":   `{"workspace_id":""}`,
		"null_workspace_id":    `{"workspace_id":null}`,
		"wrong_typed_field":    `{"workspace_id":123}`,
		"unknown_member":       `{"workspace_id":"ws_alpha","extra":true}`,
	} {
		name, args := name, args
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
				`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":`+args+`}}`))
			if response.Code != http.StatusOK {
				t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
			}
			if harness.sources.call != "" || harness.sources.confirmationContextCalls != 0 {
				t.Fatalf("unbounded sources arguments reached SourceService: call=%q confirmationContextCalls=%d", harness.sources.call, harness.sources.confirmationContextCalls)
			}
			if !strings.Contains(response.Body.String(), `"code":-32602`) {
				t.Fatalf("expected -32602 invalid-arguments, got: %s", response.Body.String())
			}
		})
	}
}

// TestMCPSourcesListDeniesUnknownWorkspaceIndistinguishably proves an
// unauthorized or unknown workspace produces the same content-free denial the
// REST listSources route produces: a 404 NOT_FOUND there, the matching -32004
// not-found here, with no source content and no workspace echo.
func TestMCPSourcesListDeniesUnknownWorkspaceIndistinguishably(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.err = registration.NewRegistrationError(registration.CodeDenied, nil)

	restResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(restResponse, harness.request(http.MethodGet, workspacesPath+"/ws_foreign/sources", ""))
	if restResponse.Code != http.StatusNotFound {
		t.Fatalf("REST deny status=%d body=%s", restResponse.Code, restResponse.Body.String())
	}
	if strings.Contains(restResponse.Body.String(), "ws_foreign") {
		t.Fatalf("REST denial echoed the workspace: %s", restResponse.Body.String())
	}

	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"src2","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_foreign"}}}`))
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP deny status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	var envelope struct {
		Result map[string]any `json:"result"`
		Error  *mcpErrorBody  `json:"error"`
	}
	if err := json.Unmarshal([]byte(mcpResponse.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP deny did not decode: %v", err)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "source scope not found" {
		t.Fatalf("MCP deny not content-free not-found: %s", mcpResponse.Body.String())
	}
	if envelope.Result != nil || strings.Contains(mcpResponse.Body.String(), "ws_foreign") || strings.Contains(mcpResponse.Body.String(), "structuredContent") {
		t.Fatalf("MCP denial leaked a workspace or content: %s", mcpResponse.Body.String())
	}
}

// sourcesDenialAuditSource records delegation to an injected boundary only.
// These strings are not audit receipts. The production repository's durable
// admission and outcome are covered by source_metadata_audit_test.go in the
// PostgreSQL integration suite, including audit append failures.
type sourcesDenialAuditSource struct {
	*fakeSourceService
	order []string
}

func (service *sourcesDenialAuditSource) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	service.order = append(service.order, "admission")
	statuses, err := service.fakeSourceService.ListSources(ctx, access, workspaceID)
	if err != nil {
		service.order = append(service.order, "denied:"+string(workspacerepository.CodeOf(err)))
		return nil, err
	}
	service.order = append(service.order, "data")
	return statuses, nil
}

// This transport probe verifies content-free denial and delegation parity;
// it does not establish that a production audit event was persisted.
func TestMCPKnowvaultSourcesDenialAdmittedAndAudited(t *testing.T) {
	mcpHarness := newTestHarness(t)
	mcpAudit := &sourcesDenialAuditSource{fakeSourceService: mcpHarness.sources}
	mcpAudit.err = workspacerepository.NewError(workspacerepository.CodeDenied, nil)
	mcpHarness.handler.sources = mcpAudit

	mcpResponse := httptest.NewRecorder()
	mcpHarness.handler.ServeHTTP(mcpResponse, mcpHarness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"src3","method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_foreign"}}}`))
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_sources transport status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(mcpResponse.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP knowvault_sources denial did not decode: %v: %s", err, mcpResponse.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "source scope not found" {
		t.Fatalf("MCP knowvault_sources denial error=%#v body=%s", outcome.Error, mcpResponse.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("MCP knowvault_sources denial carried a result: %s", string(*outcome.Result))
	}
	if mcpHarness.sources.confirmationContextCalls != 0 {
		t.Fatalf("MCP knowvault_sources denial read the confirmation context: calls=%d", mcpHarness.sources.confirmationContextCalls)
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"sources"`, testScopeID} {
		if strings.Contains(mcpResponse.Body.String(), leaked) {
			t.Fatalf("MCP denial leaked %q: %s", leaked, mcpResponse.Body.String())
		}
	}
	if order := strings.Join(mcpAudit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("MCP knowvault_sources denial audit order=%q, want admission before the closed-class denial", order)
	}

	restHarness := newTestHarness(t)
	restAudit := &sourcesDenialAuditSource{fakeSourceService: restHarness.sources}
	restAudit.err = workspacerepository.NewError(workspacerepository.CodeDenied, nil)
	restHarness.handler.sources = restAudit
	restResponse := httptest.NewRecorder()
	restHarness.handler.ServeHTTP(restResponse, restHarness.request(http.MethodGet, apiPrefix+"/workspaces/ws_foreign/tools/sources", ""))
	if restResponse.Code != http.StatusNotFound || !strings.Contains(restResponse.Body.String(), `"NOT_FOUND"`) {
		t.Fatalf("REST tools/sources denial status=%d body=%s", restResponse.Code, restResponse.Body.String())
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"sources"`, testScopeID} {
		if strings.Contains(restResponse.Body.String(), leaked) {
			t.Fatalf("REST tools/sources denial leaked %q: %s", leaked, restResponse.Body.String())
		}
	}
	if order := strings.Join(restAudit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("REST tools/sources denial audit order=%q, want admission before the closed-class denial", order)
	}
}
