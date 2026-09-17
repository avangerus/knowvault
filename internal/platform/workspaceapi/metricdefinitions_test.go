package workspaceapi

// R2 Outcome 1 transport tests. The metric-definition surface is read-only:
// the handler forwards the authenticated access context and the workspace
// named in the path to the injected MetricDefinitionCatalog and projects the
// published fields. It adds no mutator, no query string and no cross-workspace
// path; a handler whose service is not composed with the capability fails
// closed as SERVICE_UNAVAILABLE.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	metricDefinitionListPath = "/api/v1/workspaces/ws_alpha/metric-definitions"
	metricDefinitionGetPath  = "/api/v1/workspaces/ws_alpha/metric-definitions/md_revenue/versions/1"
)

// fakeMetricDefinitionCatalog records what the transport forwarded and returns
// one canned result or one canned failure.
type fakeMetricDefinitionCatalog struct {
	access      database.AccessContext
	workspaceID string
	metricID    string
	version     int64
	listCalls   int
	getCalls    int
	definitions []metricdef.Definition
	definition  metricdef.Definition
	err         error
}

func (catalog *fakeMetricDefinitionCatalog) List(_ context.Context, access database.AccessContext, workspaceID string) ([]metricdef.Definition, error) {
	catalog.listCalls++
	catalog.access, catalog.workspaceID = access, workspaceID
	return catalog.definitions, catalog.err
}

func (catalog *fakeMetricDefinitionCatalog) GetVersion(_ context.Context, access database.AccessContext, workspaceID, metricID string, version int64) (metricdef.Definition, error) {
	catalog.getCalls++
	catalog.access, catalog.workspaceID, catalog.metricID, catalog.version = access, workspaceID, metricID, version
	return catalog.definition, catalog.err
}

type metricDefinitionTestAuditor struct{ approvals int }

func (auditor *metricDefinitionTestAuditor) RecordApproval(event metricdef.ApprovalEvent) error {
	auditor.approvals++
	return nil
}

// metricDefinitionTestFixture builds one real APPROVED version through the
// repository's own metricdef authority, so the projection test exercises the
// exact value the domain package issues rather than a hand-built struct.
func metricDefinitionTestFixture(t *testing.T) metricdef.Definition {
	t.Helper()
	series, err := metricdef.NewSeries("md_revenue", "ws_alpha", "usr_alice", metricdef.Spec{
		Name:           "Revenue",
		Source:         metricdef.SourceConnection{ConnectionID: "conn_orders", ProjectionVersion: 3},
		EntityKey:      "order_id",
		Grain:          metricdef.GrainMonth,
		AllowedFilters: []string{"region", "channel"},
		Unit:           "RUB",
	})
	if err != nil {
		t.Fatal(err)
	}
	auditor := &metricDefinitionTestAuditor{}
	approved, err := series.Approve("usr_alice", auditor, time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if auditor.approvals != 1 {
		t.Fatalf("approval audit events=%d", auditor.approvals)
	}
	definition, ok := approved.Version(1)
	if !ok {
		t.Fatal("approved version 1 missing from series")
	}
	return definition
}

func TestMetricDefinitionListProjectsApprovedVersion(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definitions: []metricdef.Definition{metricDefinitionTestFixture(t)}}
	harness.handler.EnableMetricDefinitions(catalog)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, metricDefinitionListPath, ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"id":"md_revenue"`,
		`"version":1`,
		`"status":"APPROVED"`,
		`"name":"Revenue"`,
		`"source_connection_id":"conn_orders"`,
		`"projection_version":3`,
		`"entity_key":"order_id"`,
		`"grain":"MONTH"`,
		`"allowed_filters":["channel","region"]`,
		`"unit":"RUB"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
	if catalog.workspaceID != "ws_alpha" {
		t.Fatalf("catalog saw workspace=%q", catalog.workspaceID)
	}
	if catalog.access.RequestID != "req_server_001" || catalog.access.PrincipalID != "usr_alice" {
		t.Fatalf("catalog saw access=%+v", catalog.access)
	}
}

func TestMetricDefinitionGetProjectsExactVersion(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definition: metricDefinitionTestFixture(t)}
	harness.handler.EnableMetricDefinitions(catalog)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, metricDefinitionGetPath, ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"id":"md_revenue"`, `"version":1`, `"status":"APPROVED"`, `"unit":"RUB"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
	if catalog.workspaceID != "ws_alpha" || catalog.metricID != "md_revenue" || catalog.version != 1 {
		t.Fatalf("catalog saw workspace=%q metric=%q version=%d", catalog.workspaceID, catalog.metricID, catalog.version)
	}
}

func TestMetricDefinitionDeniedResponseIsTheExistingNotFound(t *testing.T) {
	// A caller whose access context the catalog refuses gets the same
	// content-free 404 every protected read returns; denial never leaks
	// whether the workspace holds any definition.
	denied := ErrMetricDefinitionDenied
	for name, path := range map[string]string{
		"list": metricDefinitionListPath,
		"get":  metricDefinitionGetPath,
	} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			catalog := &fakeMetricDefinitionCatalog{err: denied}
			harness.handler.EnableMetricDefinitions(catalog)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, path, ""))
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), `"code":"NOT_FOUND"`) {
				t.Fatalf("body=%s", response.Body.String())
			}
		})
	}
}

func TestMetricDefinitionUnknownVersionIsNotFound(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{err: ErrMetricDefinitionNotFound}
	harness.handler.EnableMetricDefinitions(catalog)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, metricDefinitionGetPath, ""))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMetricDefinitionGetRejectsMalformedVersionBeforeTheCatalog(t *testing.T) {
	// The version segment is parsed at the transport boundary: a zero, a
	// leading-zero form, a signed value, a non-decimal or an overflowing value
	// names no resource and never reaches the catalog.
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{definition: metricDefinitionTestFixture(t)}
	harness.handler.EnableMetricDefinitions(catalog)
	for _, segment := range []string{"0", "01", "-1", "+1", "1x", "99999999999999999999"} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet,
			"/api/v1/workspaces/ws_alpha/metric-definitions/md_revenue/versions/"+segment, ""))
		if response.Code != http.StatusNotFound {
			t.Fatalf("version=%q status=%d body=%s", segment, response.Code, response.Body.String())
		}
	}
	if catalog.getCalls != 0 {
		t.Fatalf("malformed version reached the catalog %d times", catalog.getCalls)
	}
}

func TestMetricDefinitionRoutesFailClosedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	for _, path := range []string{metricDefinitionListPath, metricDefinitionGetPath} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, path, ""))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
}

func TestMetricDefinitionRoutesAreReadOnly(t *testing.T) {
	harness := newTestHarness(t)
	catalog := &fakeMetricDefinitionCatalog{}
	harness.handler.EnableMetricDefinitions(catalog)
	for _, path := range []string{metricDefinitionListPath, metricDefinitionGetPath} {
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodPost, path, ""))
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
		if response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("path=%s Allow header=%q", path, response.Header().Get("Allow"))
		}
	}
	if catalog.listCalls != 0 || catalog.getCalls != 0 {
		t.Fatalf("mutating method reached the catalog: list=%d get=%d", catalog.listCalls, catalog.getCalls)
	}
}
