package workspaceapi

// R2 Outcome 1 MCP transport tests. The two metric-definition tools are the
// read-only MCP mirror of the REST list/get routes: they reach the same
// injected, access-re-checked MetricDefinitionCatalog, forward the caller's
// access context and the validated workspace/metric/version, and project
// through the shared projectMetricDefinition so MCP and REST cannot drift. They
// are advertised only to non-SERVICE principals and fail closed without the
// capability; no mutating tool is added.

import (
	"encoding/json"
	"encoding/json/jsontext"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// mcpMetricDefinitionProjectionKeys is the exact published field set both
// transports must expose.
var mcpMetricDefinitionProjectionKeys = []string{
	"id", "version", "status", "name", "source_connection_id",
	"projection_version", "entity_key", "grain", "allowed_filters", "unit",
}

func metricDefinitionUnknownVersionError(t *testing.T) error {
	t.Helper()
	_, err := (metricdef.Series{}).Supersede(metricdef.Spec{})
	if metricdef.CodeOf(err) != metricdef.CodeUnknownVersion {
		t.Fatalf("fixture did not yield CodeUnknownVersion: %v", err)
	}
	return err
}

func metricDefinitionInvalidDefinitionError(t *testing.T) error {
	t.Helper()
	_, err := metricdef.NewSeries("", "ws_alpha", "usr_alice", metricdef.Spec{})
	if metricdef.CodeOf(err) != metricdef.CodeInvalidDefinition {
		t.Fatalf("fixture did not yield CodeInvalidDefinition: %v", err)
	}
	return err
}

func assertMetricDefinitionFieldSet(t *testing.T, entry map[string]any) {
	t.Helper()
	for _, key := range mcpMetricDefinitionProjectionKeys {
		if _, present := entry[key]; !present {
			t.Fatalf("projection missing field %q: %#v", key, entry)
		}
	}
	if len(entry) != len(mcpMetricDefinitionProjectionKeys) {
		t.Fatalf("projection exposed unexpected fields: %#v", entry)
	}
}

func mcpCall(t *testing.T, harness *testHarness, name, arguments string) string {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"md","method":"tools/call","params":{"name":"`+name+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s status=%d body=%s", name, response.Code, response.Body.String())
	}
	return response.Body.String()
}

func decodeMCPErrorBody(t *testing.T, body string) *mcpErrorBody {
	t.Helper()
	var envelope struct {
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("MCP error did not decode: %v: %s", err, body)
	}
	return envelope.Error
}

// TestMCPMetricDefinitionsListMatchesRESTProjection proves the MCP list tool
// dispatches through the same injected catalog the REST route uses, with the
// caller's access context and validated workspace, and returns exactly the REST
// projection (same top-level shape and same per-definition field set).
func TestMCPMetricDefinitionsListMatchesRESTProjection(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definitions: []metricdef.Definition{metricDefinitionTestFixture(t)}}
	harness.handler.EnableMetricDefinitions(catalog)

	rest := httptest.NewRecorder()
	harness.handler.ServeHTTP(rest, harness.request(http.MethodGet, metricDefinitionListPath, ""))
	if rest.Code != http.StatusOK {
		t.Fatalf("REST list status=%d body=%s", rest.Code, rest.Body.String())
	}

	body := mcpCall(t, harness, mcpToolMetricDefinitionsList, `{"workspace_id":"ws_alpha"}`)
	structured := decodeMCPResultStructured(t, body)
	restObject := decodeJSONObject(t, rest.Body.String())
	if !reflect.DeepEqual(structured, restObject) {
		t.Fatalf("MCP list projection != REST list projection\nMCP:  %#v\nREST: %#v", structured, restObject)
	}
	definitions, ok := structured["definitions"].([]any)
	if !ok || len(definitions) != 1 {
		t.Fatalf("MCP list definitions=%#v", structured["definitions"])
	}
	entry, ok := definitions[0].(map[string]any)
	if !ok {
		t.Fatalf("MCP list entry=%#v", definitions[0])
	}
	assertMetricDefinitionFieldSet(t, entry)

	if catalog.workspaceID != "ws_alpha" {
		t.Fatalf("catalog saw workspace=%q", catalog.workspaceID)
	}
	if catalog.access.RequestID != "req_server_001" || catalog.access.PrincipalID != "usr_alice" {
		t.Fatalf("catalog saw access=%+v", catalog.access)
	}
}

// TestMCPMetricDefinitionGetMatchesRESTProjection proves the exact-version tool
// forwards the validated metric id and version and returns the REST object
// projection.
func TestMCPMetricDefinitionGetMatchesRESTProjection(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definition: metricDefinitionTestFixture(t)}
	harness.handler.EnableMetricDefinitions(catalog)

	rest := httptest.NewRecorder()
	harness.handler.ServeHTTP(rest, harness.request(http.MethodGet, metricDefinitionGetPath, ""))
	if rest.Code != http.StatusOK {
		t.Fatalf("REST get status=%d body=%s", rest.Code, rest.Body.String())
	}

	body := mcpCall(t, harness, mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":1}`)
	structured := decodeMCPResultStructured(t, body)
	restObject := decodeJSONObject(t, rest.Body.String())
	if !reflect.DeepEqual(structured, restObject) {
		t.Fatalf("MCP get projection != REST get projection\nMCP:  %#v\nREST: %#v", structured, restObject)
	}
	assertMetricDefinitionFieldSet(t, structured)

	if catalog.workspaceID != "ws_alpha" || catalog.metricID != "md_revenue" || catalog.version != 1 {
		t.Fatalf("catalog saw workspace=%q metric=%q version=%d", catalog.workspaceID, catalog.metricID, catalog.version)
	}
}

// TestMCPMetricDefinitionFailuresCollapse proves the content-free failure
// mapping: denial, a missing definition/version and an unknown version all
// become one identical -32004 not-found (no role or existence oracle), while an
// invalid definition request is -32602.
func TestMCPMetricDefinitionFailuresCollapse(t *testing.T) {
	getArguments := `{"workspace_id":"ws_alpha","metric_id":"md_x","version":9}`
	cases := map[string]struct {
		name      string
		arguments string
		err       error
		wantCode  int
	}{
		"list_denied":         {mcpToolMetricDefinitionsList, `{"workspace_id":"ws_alpha"}`, ErrMetricDefinitionDenied, -32004},
		"get_not_found":       {mcpToolMetricDefinitionGet, getArguments, ErrMetricDefinitionNotFound, -32004},
		"get_unknown_version": {mcpToolMetricDefinitionGet, getArguments, nil, -32004},
		"list_invalid":        {mcpToolMetricDefinitionsList, `{"workspace_id":"ws_alpha"}`, nil, -32602},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			catalogErr := tc.err
			if name == "get_unknown_version" {
				catalogErr = metricDefinitionUnknownVersionError(t)
			}
			if name == "list_invalid" {
				catalogErr = metricDefinitionInvalidDefinitionError(t)
			}
			harness := newTestHarness(t)
			catalog := &fakeMetricDefinitionCatalog{err: catalogErr}
			harness.handler.EnableMetricDefinitions(catalog)
			body := mcpCall(t, harness, tc.name, tc.arguments)
			errBody := decodeMCPErrorBody(t, body)
			if errBody == nil || errBody.Code != tc.wantCode {
				t.Fatalf("MCP failure not mapped to %d: %s", tc.wantCode, body)
			}
			if errBody.Code == -32004 {
				var envelope struct {
					Result map[string]any `json:"result"`
				}
				if err := json.Unmarshal([]byte(body), &envelope); err != nil {
					t.Fatalf("MCP denial did not decode: %v", err)
				}
				if envelope.Result != nil {
					t.Fatalf("MCP denial leaked a result: %s", body)
				}
			}
		})
	}
}

// TestMCPMetricDefinitionToolsFailClosedWithoutCapability proves a handler whose
// service is not composed with the capability answers a content-free -32000
// service unavailable for both tools.
func TestMCPMetricDefinitionToolsFailClosedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	for name, arguments := range map[string]string{
		mcpToolMetricDefinitionsList: `{"workspace_id":"ws_alpha"}`,
		mcpToolMetricDefinitionGet:   `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":1}`,
	} {
		body := mcpCall(t, harness, name, arguments)
		errBody := decodeMCPErrorBody(t, body)
		if errBody == nil || errBody.Code != -32000 {
			t.Fatalf("tool %s not fail-closed: %s", name, body)
		}
	}
}

// TestMCPMetricDefinitionToolsRejectUnboundedArguments proves the closed schema
// is enforced before the catalog is touched: missing members, empty ids, a
// version below one, a fractional version and unknown members are all -32602.
func TestMCPMetricDefinitionToolsRejectUnboundedArguments(t *testing.T) {
	cases := map[string]struct{ name, arguments string }{
		"list_missing_workspace": {mcpToolMetricDefinitionsList, `{}`},
		"list_unknown_member":    {mcpToolMetricDefinitionsList, `{"workspace_id":"ws_alpha","extra":true}`},
		"get_missing_metric":     {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","version":1}`},
		"get_empty_metric":       {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"","version":1}`},
		"get_zero_version":       {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":0}`},
		"get_negative_version":   {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":-1}`},
		"get_fractional_version": {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":1.5}`},
		"get_unknown_member":     {mcpToolMetricDefinitionGet, `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":1,"extra":true}`},
	}
	for name, tc := range cases {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			catalog := &fakeMetricDefinitionCatalog{definition: metricDefinitionTestFixture(t)}
			harness.handler.EnableMetricDefinitions(catalog)
			body := mcpCall(t, harness, tc.name, tc.arguments)
			errBody := decodeMCPErrorBody(t, body)
			if errBody == nil || errBody.Code != -32602 {
				t.Fatalf("arguments not rejected with -32602: %s", body)
			}
			if catalog.listCalls != 0 || catalog.getCalls != 0 {
				t.Fatalf("rejected arguments reached the catalog: list=%d get=%d", catalog.listCalls, catalog.getCalls)
			}
		})
	}
}

// TestMCPMetricDefinitionToolsAdvertisedToHumansOnly proves tools/list carries
// the two tools with their closed schemas for a human session, while a SERVICE
// principal sees only its knowledge tools (never the administrative metric
// definitions) and a direct tools/call by that principal gets the same -32601
// method not found an unknown tool gets, without touching the catalog.
func TestMCPMetricDefinitionToolsAdvertisedToHumansOnly(t *testing.T) {
	humanCatalog := mcpToolCatalog(database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_human"})
	var listSchema, getSchema map[string]any
	for _, entry := range humanCatalog {
		tool, _ := entry.(map[string]any)
		name, _ := tool["name"].(string)
		switch name {
		case mcpToolMetricDefinitionsList:
			listSchema, _ = tool["inputSchema"].(map[string]any)
		case mcpToolMetricDefinitionGet:
			getSchema, _ = tool["inputSchema"].(map[string]any)
		}
	}
	if listSchema == nil || getSchema == nil {
		t.Fatalf("human tools/list omitted a metric-definition tool")
	}
	if additional, _ := listSchema["additionalProperties"].(bool); additional {
		t.Fatalf("list schema allows additional properties: %#v", listSchema)
	}
	listRequired, _ := listSchema["required"].([]string)
	if len(listRequired) != 1 || listRequired[0] != "workspace_id" {
		t.Fatalf("list schema required=%#v", listSchema["required"])
	}
	if additional, _ := getSchema["additionalProperties"].(bool); additional {
		t.Fatalf("get schema allows additional properties: %#v", getSchema)
	}
	getRequired, _ := getSchema["required"].([]string)
	wantRequired := map[string]bool{"workspace_id": false, "metric_id": false, "version": false}
	if len(getRequired) != len(wantRequired) {
		t.Fatalf("get schema required=%#v", getSchema["required"])
	}
	for _, key := range getRequired {
		if _, wanted := wantRequired[key]; !wanted {
			t.Fatalf("get schema unexpected required member %q", key)
		}
		wantRequired[key] = true
	}
	getProperties, _ := getSchema["properties"].(map[string]any)
	versionSpec, _ := getProperties["version"].(map[string]any)
	if versionSpec == nil || versionSpec["type"] != "integer" || versionSpec["minimum"] != 1 {
		t.Fatalf("get schema version spec=%#v", getProperties["version"])
	}

	service := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "principal_agent", RequestID: "req_agent", ActorKind: database.ActorKindService}
	names := toolNames(t, mcpToolCatalog(service))
	found := map[string]bool{}
	for _, name := range names {
		found[name] = true
		if !mcpServiceKnowledgeTool(name) {
			t.Fatalf("tools/list disclosed non-knowledge tool %q to a service principal", name)
		}
		if name == mcpToolMetricDefinitionsList || name == mcpToolMetricDefinitionGet {
			t.Fatalf("tools/list disclosed administrative metric tool %q to a service principal", name)
		}
	}
	if !found[mcpToolQuestion] || !found[mcpToolEvidenceGet] {
		t.Fatalf("the SERVICE knowledge catalogue lost its question tools: %v", names)
	}

	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definition: metricDefinitionTestFixture(t)}
	harness.handler.EnableMetricDefinitions(catalog)
	serviceCalls := map[string]string{
		mcpToolMetricDefinitionsList: `{"workspace_id":"ws_alpha"}`,
		mcpToolMetricDefinitionGet:   `{"workspace_id":"ws_alpha","metric_id":"md_revenue","version":1}`,
	}
	for name, arguments := range serviceCalls {
		recorder := httptest.NewRecorder()
		envelope := mcpRequest{
			JSONRPC: "2.0", ID: jsontext.Value(`1`), Method: "tools/call",
			Params: jsontext.Value(`{"name":"` + name + `","arguments":` + arguments + `}`),
		}
		harness.handler.mcpToolCall(recorder, harness.request(http.MethodPost, apiPrefix+"/mcp", ""), service, envelope)
		errBody := decodeMCPErrorBody(t, recorder.Body.String())
		if errBody == nil || errBody.Code != -32601 {
			t.Fatalf("SERVICE call %s not refused with -32601: %s", name, recorder.Body.String())
		}
	}
	if catalog.listCalls != 0 || catalog.getCalls != 0 {
		t.Fatalf("a SERVICE principal reached the catalog: list=%d get=%d", catalog.listCalls, catalog.getCalls)
	}
}
