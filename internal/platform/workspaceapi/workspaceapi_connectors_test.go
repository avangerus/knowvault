package workspaceapi

// Endpoint tests for the read-only onboarding catalog
// (GET /api/v1/source-connectors). Together with the pure truthfulness test on
// registration.ConnectorCatalogData they exercise the happy path, the
// unauthenticated and the denied (policy) path, and the capability booleans
// that must never invent discovery or a recurring schedule.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/source/registration"
)

// fakeConnectorSource is a SourceService (via the embedded fakeSourceService)
// that additionally exposes the read-only connector catalog, exactly as the
// production sourceServiceFacade does.
type fakeConnectorSource struct {
	*fakeSourceService
	catalog      registration.ConnectorCatalog
	catalogErr   error
	catalogCalls int
}

func (service *fakeConnectorSource) ConnectorCatalog(_ context.Context, _ database.AccessContext) (registration.ConnectorCatalog, error) {
	service.catalogCalls++
	return service.catalog, service.catalogErr
}

// newConnectorHarness builds a handler whose injected source service is the
// connector-capable fake, so the onboarding route type-asserts and serves.
func newConnectorHarness(t *testing.T) (*Handler, *authSpy, *fakeConnectorSource, string) {
	t.Helper()
	token := testOpaqueToken("session")
	digestor := &testDigestor{}
	_, err := digestor.Digest("csrf", token)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := identity.NewClaims("org_alpha", "usr_alice", 1, "idp_alpha", 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := httpauth.New(testTenantResolver{digestor: digestor}, testSessionResolver{claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	spy := &authSpy{delegate: authenticator}
	sources := &fakeConnectorSource{catalog: registration.ConnectorCatalogData()}
	handler, err := newHandlerWithQuestionsAndConversations(spy,
		&fakeWorkspaceService{snapshot: testSnapshot(t)}, sources, &fakeEvidenceService{}, nil, nil,
		fixedRequestIDSource("req_server_001"))
	if err != nil {
		t.Fatal(err)
	}
	return handler, spy, sources, token
}

func connectorsGET(path, token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example"+path, nil)
	if token != "" {
		request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	}
	return request
}

type catalogConnector struct {
	Type         string `json:"type"`
	Capabilities struct {
		AutonomousRecurringSync bool `json:"autonomous_recurring_sync"`
		GeneralDiscovery        bool `json:"general_discovery"`
	} `json:"capabilities"`
}

type catalogEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	Declarations  map[string]any     `json:"declarations"`
	Connectors    []catalogConnector `json:"connectors"`
}

func decodeConnectorEnvelope(t *testing.T, body string) catalogEnvelope {
	t.Helper()
	var envelope catalogEnvelope
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		t.Fatalf("decode catalog body %q: %v", body, err)
	}
	return envelope
}

func connectorCapabilitiesByType(connectors []catalogConnector) map[string]struct {
	autonomous, discovery bool
} {
	result := make(map[string]struct {
		autonomous, discovery bool
	}, len(connectors))
	for _, connector := range connectors {
		result[connector.Type] = struct {
			autonomous, discovery bool
		}{connector.Capabilities.AutonomousRecurringSync, connector.Capabilities.GeneralDiscovery}
	}
	return result
}

func TestSourceConnectorsCatalogHappyPathDeterministic(t *testing.T) {
	handler, _, sources, token := newConnectorHarness(t)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, connectorsGET(sourceConnectorsPath, token))
	if first.Code != http.StatusOK || sources.catalogCalls != 1 {
		t.Fatalf("status=%d catalog_calls=%d body=%s", first.Code, sources.catalogCalls, first.Body.String())
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, connectorsGET(sourceConnectorsPath, token))
	if second.Code != http.StatusOK {
		t.Fatalf("second status=%d body=%s", second.Code, second.Body.String())
	}
	// Two requests over the same handler produce byte-identical bodies: the
	// registry is never mutated by a read, so the catalog is deterministic.
	if first.Body.String() != second.Body.String() {
		t.Fatalf("catalog not deterministic across requests:\nfirst:  %s\nsecond: %s", first.Body.String(), second.Body.String())
	}
	envelope := decodeConnectorEnvelope(t, first.Body.String())
	if envelope.SchemaVersion != registration.ConnectorCatalogSchemaVersion {
		t.Fatalf("schema_version=%q want %q", envelope.SchemaVersion, registration.ConnectorCatalogSchemaVersion)
	}
	capabilities := connectorCapabilitiesByType(envelope.Connectors)
	if len(capabilities) != 3 {
		t.Fatalf("expected exactly 3 connector types, got %d", len(capabilities))
	}
	for _, sourceType := range []string{"FOLDER", "POSTGRESQL_QUERY", "GIT"} {
		if _, present := capabilities[sourceType]; !present {
			t.Fatalf("catalog is missing %s", sourceType)
		}
	}
	if declarations := envelope.Declarations; declarations == nil || declarations["general_discovery_implemented"] != false {
		t.Fatalf("declarations must report general discovery is not implemented: %#v", envelope.Declarations)
	}
}

func TestSourceConnectorsCatalogCapabilityTruthfulness(t *testing.T) {
	_, _, _, _ = newConnectorHarness(t)
	catalog := registration.ConnectorCatalogData()
	if catalog.SchemaVersion != registration.ConnectorCatalogSchemaVersion || len(catalog.Connectors) != 3 {
		t.Fatalf("schema=%q connectors=%d", catalog.SchemaVersion, len(catalog.Connectors))
	}
	if !catalog.Declarations.AutonomousRecurringSyncImplemented ||
		len(catalog.Declarations.AutonomousRecurringSyncSourceTypes) != 2 ||
		catalog.Declarations.AutonomousRecurringSyncSourceTypes[0] != "FOLDER" ||
		catalog.Declarations.AutonomousRecurringSyncSourceTypes[1] != "POSTGRESQL_QUERY" {
		t.Fatalf("declarations must state recurring sync for FOLDER and POSTGRESQL_QUERY: %#v", catalog.Declarations)
	}
	if catalog.Declarations.GeneralDiscoveryImplemented {
		t.Fatal("general discovery must be declared unimplemented")
	}
	for _, connector := range catalog.Connectors {
		if connector.Capabilities.GeneralDiscovery {
			t.Fatalf("%s must not claim general discovery", connector.Type)
		}
	}
	perType := make(map[string]bool, len(catalog.Connectors))
	for _, connector := range catalog.Connectors {
		perType[connector.Type] = connector.Capabilities.AutonomousRecurringSync
	}
	// Both scheduled source types use the existing worker; Git remains explicit.
	if perType["POSTGRESQL_QUERY"] != true || perType["FOLDER"] != true || perType["GIT"] != false {
		t.Fatalf("autonomous_recurring_sync must match the scheduled source types: %#v", perType)
	}
	// Truthful registration-field descriptions: no connector may claim an
	// automatic Git clone/pull or discovery, and field names reflect the real
	// request paths (never business column mappings of configured values).
	hasField := func(connector registration.Connector, name string) bool {
		for _, field := range connector.RegistrationFields {
			if field.Name == name {
				return true
			}
		}
		return false
	}
	for _, connector := range catalog.Connectors {
		switch connector.Type {
		case "FOLDER":
			if !hasField(connector, "root_identity") || !hasField(connector, "relative_root") {
				t.Fatalf("FOLDER registration fields must reflect the mounted-root request path: %#v", connector.RegistrationFields)
			}
		case "POSTGRESQL_QUERY":
			if !hasField(connector, "schema_name") || !hasField(connector, "relation_name") || !hasField(connector, "columns") {
				t.Fatalf("POSTGRESQL_QUERY registration fields must reflect the projection request path: %#v", connector.RegistrationFields)
			}
		case "GIT":
			if !hasField(connector, "repository_id") || !hasField(connector, "branch_name") {
				t.Fatalf("GIT registration fields must reflect the remote request path: %#v", connector.RegistrationFields)
			}
		}
	}
}

func TestSourceConnectorsCatalogUnauthenticatedRejected(t *testing.T) {
	handler, spy, sources, token := newConnectorHarness(t)
	spy.authenticateErr = errors.New("session rejected")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, connectorsGET(sourceConnectorsPath, token))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%s", response.Code, response.Body.String())
	}
	if sources.catalogCalls != 0 {
		t.Fatalf("catalog must not be called for an unauthenticated request")
	}
}

func TestSourceConnectorsCatalogDeniedDoesNotLeak(t *testing.T) {
	handler, _, sources, token := newConnectorHarness(t)
	sources.catalogErr = registration.NewRegistrationError(registration.CodeDenied, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, connectorsGET(sourceConnectorsPath, token))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d want 404 (policy denial follows source read policy) body=%s", response.Code, response.Body.String())
	}
	if sources.catalogCalls != 1 {
		t.Fatalf("catalog must be reached before denial is mapped")
	}
	if body := response.Body.String(); body == "" || strings.Contains(body, `"connectors"`) {
		t.Fatalf("denial must not leak catalog content: %s", body)
	}
}

func TestSourceConnectorsCatalogNotComposedSvcUnavailable(t *testing.T) {
	// newTestHarness wires the plain fakeSourceService, which does not expose
	// the connector catalog capability, so the route must fail closed exactly
	// like every other capability-gated surface.
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	request := harness.request(http.MethodGet, sourceConnectorsPath, "")
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 (capability not composed) body=%s", response.Code, response.Body.String())
	}
}
