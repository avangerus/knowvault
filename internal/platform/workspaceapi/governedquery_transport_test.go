package workspaceapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

type governedTransportProbe struct {
	workspace, connection, question string
	calls                           int
	result                          governedask.AskResult
	hasPresets                      bool
	presetOnly                      bool
	presetID                        string
	presetCatalog                   governedask.PresetCatalog
	presetResult                    governedask.PresetRunResult
}

func (p *governedTransportProbe) SetLiveQueries(_ context.Context, _ database.AccessContext, w, c string, _ bool) error {
	p.workspace, p.connection = w, c
	p.calls++
	return nil
}
func (p *governedTransportProbe) RegisterExposedSchema(_ context.Context, _ database.AccessContext, w, c string, _ []governedquery.ExposedObject) (int64, error) {
	p.workspace, p.connection = w, c
	p.calls++
	return 1, nil
}
func (p *governedTransportProbe) Ask(_ context.Context, _ database.AccessContext, w, c, q string) (governedask.AskResult, error) {
	p.workspace, p.connection, p.question = w, c, q
	p.calls++
	return p.result, nil
}
func (p *governedTransportProbe) Promote(_ context.Context, _ database.AccessContext, w, c, _, _ string) (governedquery.PromotionResult, error) {
	p.workspace, p.connection = w, c
	p.calls++
	return governedquery.PromotionResult{}, nil
}
func (p *governedTransportProbe) HasPresets() bool { return p.hasPresets }
func (p *governedTransportProbe) PresetOnly() bool { return p.presetOnly }
func (p *governedTransportProbe) ListPresets(_ context.Context, _ database.AccessContext, w, c string) (governedask.PresetCatalog, error) {
	p.workspace, p.connection = w, c
	p.calls++
	return p.presetCatalog, nil
}
func (p *governedTransportProbe) RunPreset(_ context.Context, _ database.AccessContext, w, c, id string) (governedask.PresetRunResult, error) {
	p.workspace, p.connection, p.presetID = w, c, id
	p.calls++
	return p.presetResult, nil
}
func (p *governedTransportProbe) ResolvePresetPhrase(_ context.Context, _ database.AccessContext, _ string, _ string) (governedquery.PresetSummary, bool, error) {
	return governedquery.PresetSummary{}, false, nil
}

func TestGovernedQueryTransportsPreserveConnectionAndCompleteResult(t *testing.T) {
	h := newTestHarness(t)
	number, empty := "9007199254740993.123456789", ""
	p := &governedTransportProbe{result: governedask.AskResult{
		AttemptID: "attempt", SQL: "SELECT amount, missing, empty FROM example", SQLHash: "sha256:sql",
		Columns: []string{"amount", "missing", "empty"}, Rows: [][]*string{{&number, nil, &empty}}, RowCount: 1,
		Answer: "One row", ConnectionID: "conn_requested", DatabaseIdentity: "fixture", ExposedSchemaRevision: 2,
		ResultFormat: "postgres-text-table-v1", ResultDigest: "sha256:result",
		ExecutionStartedAt: time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC), ExecutionCompletedAt: time.Date(2026, 9, 15, 12, 0, 1, 0, time.UTC),
	}}
	h.handler.EnableGovernedQuery(p)
	for _, tc := range []struct{ suffix, body string }{
		{":ask", `{"question":"how many?"}`},
		{":set-live-queries", `{"enabled":true}`},
		{"/exposed-schema", `{"objects":[{"schema_name":"example","table_name":"items","description":"Items","columns":[]}]}`},
		{":promote", `{"attempt_id":"attempt","sql_hash":"sha256:result"}`},
	} {
		req := h.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/governed-query-connections/conn_requested"+tc.suffix, tc.body)
		h.mutationHeaders(req, h.hash)
		req.Header.Del("If-Match")
		rr := httptest.NewRecorder()
		h.handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || p.connection != "conn_requested" || p.workspace != "ws_alpha" {
			t.Fatalf("%s: %d %s, probe %+v", tc.suffix, rr.Code, rr.Body, p)
		}
		if tc.suffix == ":ask" {
			var body struct {
				Result governedask.AskResult `json:"result"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || !reflect.DeepEqual(body.Result, p.result) {
				t.Fatalf("REST changed result: %s", rr.Body)
			}
		}
	}
	p.connection = ""
	req := h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"sql","method":"tools/call","params":{"name":"knowvault_governed_query_ask","arguments":{"workspace_id":"ws_alpha","connection_id":"conn_requested","question":"how many?"}}}`)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	var envelope struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			Structured governedask.AskResult `json:"structuredContent"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil || len(envelope.Result.Content) != 1 || p.connection != "conn_requested" || p.question != "how many?" {
		t.Fatalf("MCP failed: %s", rr.Body)
	}
	var textResult governedask.AskResult
	if err := json.Unmarshal([]byte(envelope.Result.Content[0].Text), &textResult); err != nil || !reflect.DeepEqual(textResult, p.result) || !reflect.DeepEqual(envelope.Result.Structured, p.result) {
		t.Fatalf("MCP lost SQL table/provenance: %s", rr.Body)
	}
}

func TestGovernedPresetMCPIsMountedOnlyWhenConfiguredAndNeverAcceptsSQL(t *testing.T) {
	h := newTestHarness(t)
	unmountedNames := toolNames(t, h.handler.mcpTools(database.AccessContext{OrganizationID: "org_demo", PrincipalID: "agent", RequestID: "req", ActorKind: database.ActorKindService}))
	for _, absent := range []string{mcpToolQueriesList, mcpToolQueryRun} {
		if slices.Contains(unmountedNames, absent) {
			t.Fatalf("unmounted preset tool %q was advertised: %v", absent, unmountedNames)
		}
	}
	unmountedCall := h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"absent","method":"tools/call","params":{"name":"knowvault_query_run","arguments":{"workspace_id":"ws_alpha","connection_id":"conn","preset_id":"contract-count"}}}`)
	unmountedResponse := httptest.NewRecorder()
	h.handler.ServeHTTP(unmountedResponse, unmountedCall)
	if !strings.Contains(unmountedResponse.Body.String(), `"code":-32601`) {
		t.Fatalf("unmounted preset call must be indistinguishable from an unknown method: %s", unmountedResponse.Body)
	}
	p := &governedTransportProbe{
		hasPresets:    true,
		presetCatalog: governedask.PresetCatalog{ConnectionID: "conn", DatabaseIdentity: "gm", Presets: []governedquery.PresetSummary{{ID: "contract-count", Version: "v1", Name: "Contract count", Description: "Current count", Phrases: []string{"check contracts"}, PresetHash: "sha256:preset"}}},
		presetResult:  governedask.PresetRunResult{AttemptID: "attempt", Preset: governedquery.PresetSummary{ID: "contract-count", Version: "v1", PresetHash: "sha256:preset"}, ConnectionID: "conn", DataState: "LIVE_OBSERVATION", ResultDigest: "sha256:result"},
	}
	h.handler.EnableGovernedQuery(p)
	names := toolNames(t, h.handler.mcpTools(database.AccessContext{OrganizationID: "org_demo", PrincipalID: "agent", RequestID: "req", ActorKind: database.ActorKindService}))
	for _, wanted := range []string{mcpToolQueriesList, mcpToolQueryRun} {
		if !slices.Contains(names, wanted) {
			t.Fatalf("configured preset tool %q missing from agent catalogue: %v", wanted, names)
		}
	}

	request := h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"run","method":"tools/call","params":{"name":"knowvault_query_run","arguments":{"workspace_id":"ws_alpha","connection_id":"conn","preset_id":"contract-count"}}}`)
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || p.presetID != "contract-count" || !strings.Contains(response.Body.String(), `"data_state":"LIVE_OBSERVATION"`) {
		t.Fatalf("preset run failed: %d %s probe=%+v", response.Code, response.Body, p)
	}
	previousCalls := p.calls
	request = h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"inject","method":"tools/call","params":{"name":"knowvault_query_run","arguments":{"workspace_id":"ws_alpha","connection_id":"conn","preset_id":"contract-count","sql":"SELECT secret FROM hidden"}}}`)
	response = httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	if p.calls != previousCalls || !strings.Contains(response.Body.String(), `"code":-32602`) || strings.Contains(response.Body.String(), "SELECT secret") {
		t.Fatalf("SQL injection argument reached the service or leaked: %s", response.Body)
	}
}

func TestGovernedPresetOnlyHidesAndRejectsAdHocMCPAsk(t *testing.T) {
	h := newTestHarness(t)
	p := &governedTransportProbe{hasPresets: true}
	h.handler.EnableGovernedQuery(p)
	beforePolicyChange := toolNames(t, h.handler.mcpTools(database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "caller", RequestID: "req", ActorKind: database.ActorKindHuman,
	}))
	if !slices.Contains(beforePolicyChange, mcpToolGovernedQueryAsk) {
		t.Fatalf("ADHOC mode did not advertise ad-hoc ask before policy change: %v", beforePolicyChange)
	}
	p.presetOnly = true

	for _, actorKind := range []database.ActorKind{database.ActorKindHuman, database.ActorKindService} {
		names := toolNames(t, h.handler.mcpTools(database.AccessContext{
			OrganizationID: "org_demo", PrincipalID: "caller", RequestID: "req", ActorKind: actorKind,
		}))
		if slices.Contains(names, mcpToolGovernedQueryAsk) {
			t.Fatalf("PRESET_ONLY advertised ad-hoc ask to %s: %v", actorKind, names)
		}
		for _, wanted := range []string{mcpToolQueriesList, mcpToolQueryRun} {
			if !slices.Contains(names, wanted) {
				t.Fatalf("PRESET_ONLY hid preset tool %q from %s: %v", wanted, actorKind, names)
			}
		}
	}

	before := p.calls
	request := h.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":"closed","method":"tools/call","params":{"name":"knowvault_governed_query_ask","arguments":{"workspace_id":"ws_alpha","connection_id":"conn","question":"show everything"}}}`)
	response := httptest.NewRecorder()
	h.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"code":-32601`) {
		t.Fatalf("PRESET_ONLY direct ask was not hidden as an unknown method: %d %s", response.Code, response.Body)
	}
	if p.calls != before {
		t.Fatalf("PRESET_ONLY direct ask reached governed-query service: calls %d -> %d", before, p.calls)
	}
}

// legacyGovernedQueryService is the pre-PRESET_ONLY capability shape: it
// projects GovernedQueryService and nothing else, so Handler's optional
// GovernedQueryModePolicy stays nil exactly as it does for every service
// double that predates the mounted mode.
type legacyGovernedQueryService struct{ GovernedQueryService }

// TestGovernedPresetOnlyClosesRESTAdHocAskBeforeAnyServiceCall is the REST half
// of the mounted-mode contract the MCP tool already enforces. While the live
// mounted policy reports PRESET_ONLY the human :ask action must not reach
// GovernedQueryService.Ask -- and through it the Model Gateway or the dedicated
// database role -- while the ADHOC, unmounted and legacy (policy-less) shapes
// keep their existing behavior. The refusal is the content-free NOT_FOUND an
// unknown connection already returns.
func TestGovernedPresetOnlyClosesRESTAdHocAskBeforeAnyServiceCall(t *testing.T) {
	ask := func(harness *testHarness, question string) *httptest.ResponseRecorder {
		request := harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/governed-query-connections/conn_requested:ask", `{"question":"`+question+`"}`)
		harness.mutationHeaders(request, harness.hash)
		request.Header.Del("If-Match")
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, request)
		return response
	}

	// Legacy no-mount: the route keeps its capability-absent shape.
	unmounted := ask(newTestHarness(t), "unmounted?")
	if unmounted.Code != http.StatusServiceUnavailable || !strings.Contains(unmounted.Body.String(), `"code":"SERVICE_UNAVAILABLE"`) {
		t.Fatalf("unmounted REST ask changed shape: %d %s", unmounted.Code, unmounted.Body)
	}

	// Legacy service double without the optional policy projection: ad-hoc ask
	// stays callable, exactly as before PRESET_ONLY existed.
	legacy := newTestHarness(t)
	legacyProbe := &governedTransportProbe{}
	legacy.handler.EnableGovernedQuery(legacyGovernedQueryService{GovernedQueryService: legacyProbe})
	if response := ask(legacy, "legacy?"); response.Code != http.StatusOK || legacyProbe.calls != 1 || legacyProbe.question != "legacy?" {
		t.Fatalf("legacy REST ask was closed: %d %s probe=%+v", response.Code, response.Body, legacyProbe)
	}

	// ADHOC (the mounted policy's zero value): the human REST ask reaches the
	// governed service with its connection, workspace and question intact.
	harness := newTestHarness(t)
	probe := &governedTransportProbe{hasPresets: true}
	harness.handler.EnableGovernedQuery(probe)
	if response := ask(harness, "how many?"); response.Code != http.StatusOK || probe.calls != 1 || probe.question != "how many?" {
		t.Fatalf("ADHOC REST ask did not reach the governed service: %d %s probe=%+v", response.Code, response.Body, probe)
	}

	// The decision is read live per request: flipping the mounted policy after
	// the handler was wired closes the already-mounted route before any
	// service, model or database work.
	probe.presetOnly = true
	blocked := ask(harness, "show everything")
	requestID := blocked.Header().Get("X-Request-ID")
	if blocked.Code != http.StatusNotFound || requestID == "" ||
		blocked.Body.String() != `{"error":{"code":"NOT_FOUND","request_id":"`+requestID+`"}}` {
		t.Fatalf("PRESET_ONLY REST ask was not closed content-free: %d %s", blocked.Code, blocked.Body)
	}
	if probe.calls != 1 || probe.question != "how many?" {
		t.Fatalf("PRESET_ONLY REST ask reached the governed service: calls=%d question=%q", probe.calls, probe.question)
	}

	// Only :ask is closed. The operator surfaces that maintain the reviewed
	// catalogue stay reachable in the same mode.
	for _, tc := range []struct{ suffix, body string }{
		{":set-live-queries", `{"enabled":true}`},
		{"/exposed-schema", `{"objects":[{"schema_name":"example","table_name":"items","description":"Items","columns":[]}]}`},
		{":promote", `{"attempt_id":"attempt","sql_hash":"sha256:result"}`},
	} {
		request := harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/governed-query-connections/conn_requested"+tc.suffix, tc.body)
		harness.mutationHeaders(request, harness.hash)
		request.Header.Del("If-Match")
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("PRESET_ONLY closed %s: %d %s", tc.suffix, response.Code, response.Body)
		}
	}
}
