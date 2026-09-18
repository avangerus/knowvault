package workspaceapi

import (
	"errors"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func newSourceOnlyHarness(t *testing.T) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	handler, err := newHandlerWithQuestionsAndConversations(
		harness.auth, harness.service, harness.sources, harness.evidence, nil, nil, fixedRequestIDSource("req_server_001"),
	)
	if err != nil {
		t.Fatal(err)
	}
	harness.handler = handler
	harness.questions = nil
	harness.conversations = nil
	return harness
}

func TestMCPTransportServesSourcesWithoutQuestions(t *testing.T) {
	harness := newSourceOnlyHarness(t)
	harness.sources.confirmationContext = confirmedSourceContext()
	harness.sources.statuses = []workspacerepository.SourceStatus{authorizedSourceStatus()}

	outcome := callMCPWorkspaceTool(t, harness, mcpToolSourcesList, `{"workspace_id":"ws_alpha"}`)
	if outcome.Error != nil {
		t.Fatalf("authorized %s without question service must not error: %#v", mcpToolSourcesList, outcome.Error)
	}
	if outcome.Result == nil {
		t.Fatalf("authorized %s returned no result member", mcpToolSourcesList)
	}
	structured := decodeMCPResultStructured(t, `{"jsonrpc":"2.0","id":"x","result":`+string(*outcome.Result)+`}`)
	sources, ok := structured["sources"].([]any)
	if !ok || len(sources) != 1 {
		t.Fatalf("%s structuredContent sources=%#v", mcpToolSourcesList, structured["sources"])
	}
	entry, ok := sources[0].(map[string]any)
	if !ok || entry["source_scope_id"] != testScopeID || entry["source_type"] != "POSTGRESQL_QUERY" {
		t.Fatalf("%s structuredContent entry=%#v", mcpToolSourcesList, sources[0])
	}
	if harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
		t.Fatalf("%s did not compose both SourceService reads: call=%q confirmationContextCalls=%d",
			mcpToolSourcesList, harness.sources.call, harness.sources.confirmationContextCalls)
	}
}

func TestMCPTransportServesRefreshWithoutQuestions(t *testing.T) {
	harness := newSourceOnlyHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{authorizedSourceStatus()}
	harness.sources.syncResult = registration.SyncResult{JobID: "job_01H9ABCDEFGHJKMNPQRSTVWXYZ"}

	outcome := callMCPWorkspaceTool(t, harness, mcpToolRefresh, `{"workspace_id":"ws_alpha"}`)
	if outcome.Error != nil {
		t.Fatalf("authorized %s without question service must not error: %#v", mcpToolRefresh, outcome.Error)
	}
	if outcome.Result == nil {
		t.Fatalf("authorized %s returned no result member", mcpToolRefresh)
	}
	structured := decodeMCPResultStructured(t, `{"jsonrpc":"2.0","id":"x","result":`+string(*outcome.Result)+`}`)
	refreshed, ok := structured["refreshed"].([]any)
	if !ok || len(refreshed) != 1 {
		t.Fatalf("%s structuredContent refreshed=%#v", mcpToolRefresh, structured["refreshed"])
	}
	item, ok := refreshed[0].(map[string]any)
	if !ok || item["source_scope_id"] != testScopeID || item["job_id"] != "job_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("%s structuredContent refreshed entry=%#v", mcpToolRefresh, refreshed[0])
	}
	if harness.sources.syncRequest.SourceScopeID != testScopeID {
		t.Fatalf("%s did not reach the authorized Sync: request=%#v", mcpToolRefresh, harness.sources.syncRequest)
	}
}

func TestMCPTransportForeignWorkspaceStaysContentFreeWithoutQuestions(t *testing.T) {
	for _, toolName := range []string{mcpToolSourcesList, mcpToolRefresh} {
		toolName := toolName
		t.Run(toolName, func(t *testing.T) {
			harness := newSourceOnlyHarness(t)
			harness.sources.err = workspacerepository.NewError(workspacerepository.CodeNotFound, errors.New("absent"))
			outcome := callMCPWorkspaceTool(t, harness, toolName, `{"workspace_id":"ws_foreign"}`)
			if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "source scope not found" {
				t.Fatalf("%s foreign workspace error=%#v", toolName, outcome.Error)
			}
			if outcome.Result != nil {
				t.Fatalf("%s foreign workspace leaked a result: %s", toolName, string(*outcome.Result))
			}
		})
	}
}

func TestMCPTransportQuestionToolFailsClosedWithoutQuestionService(t *testing.T) {
	harness := newSourceOnlyHarness(t)
	outcome := callMCPWorkspaceTool(t, harness, mcpToolQuestion, `{"workspace_id":"ws_alpha","question":"How many?","answer_mode":"EXTRACTIVE"}`)
	if outcome.Error == nil || outcome.Result != nil {
		t.Fatalf("%s with absent question service must fail closed: result=%v error=%#v", mcpToolQuestion, outcome.Result, outcome.Error)
	}
	if outcome.Error.Code != -32602 || outcome.Error.Message != "unsupported answer mode" {
		t.Fatalf("%s absent-service code=%d message=%q", mcpToolQuestion, outcome.Error.Code, outcome.Error.Message)
	}
}

func authorizedSourceStatus() workspacerepository.SourceStatus {
	started := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	syncStatus := "SYNCED"
	schemaName, relationName := "reporting", "waste_daily"
	return workspacerepository.SourceStatus{
		WorkspaceSourceID: "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: testScopeID,
		SourceScopeRevision: 2, AccessMode: "WORKSPACE_MANAGED", Enabled: true, ScopeConfigHash: testHash,
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionName: "Engineering docs",
		SourceType: "POSTGRESQL_QUERY", PostgreSQLSchemaName: &schemaName, PostgreSQLRelationName: &relationName,
		ActivationStatus: "READY", TrustVerified: true,
		SyncStatus: &syncStatus, SyncStartedAt: &started, SyncCompletedAt: &started,
		ContentFreshnessSLASeconds: 3600, LastSuccessfulSyncAt: &started, FreshnessState: "FRESH",
		SyncIntervalSeconds: 1800, Confirmed: true,
	}
}

func confirmedSourceContext() workspacerepository.ConfirmationContext {
	return workspacerepository.ConfirmationContext{
		ExpectedPolicyRevision: "policy-acc-0001",
		WarningVersion:         "workspace-managed-risk-v1", WarningContractHash: testHash,
		ViewerPrincipalID: "principal_alpha", CanIssueConfirmationGrant: true, CanVerifyConnectionTrust: true,
	}
}
