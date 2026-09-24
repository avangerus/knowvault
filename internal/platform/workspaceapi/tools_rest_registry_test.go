package workspaceapi

// KV-A05: the REST parity surface of the R3a-1 workspace knowledge tools is
// resolved through the one internal/workspacetools registry. These tests pin
// two facts: (1) an MCP name and its tools/{segment} REST subpath resolve to
// the same registry entry and Kind, and route recognition stores that Kind so
// the dispatcher selects the implementation from the registry rather than from
// the endpoint kind; (2) an unregistered tools/{segment} is refused as the
// existing content-free NOT_FOUND without entering any evidence or source
// capability.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func TestWorkspaceToolRESTAndMCPResolveSameRegistryEntryAndKind(t *testing.T) {
	registry := workspacetools.KnowledgeTools()
	cases := []struct {
		mcpName string
		segment string
		kind    workspacetools.Kind
		route   endpointKind
	}{
		{mcpName: "knowvault_list_objects", segment: "list-objects", kind: workspacetools.KindListObjects, route: endpointWorkspaceToolListObjects},
		{mcpName: "knowvault_search", segment: "search", kind: workspacetools.KindSearch, route: endpointWorkspaceToolSearch},
		{mcpName: "knowvault_grep", segment: "grep", kind: workspacetools.KindGrep, route: endpointWorkspaceToolGrep},
		{mcpName: "knowvault_related", segment: "related", kind: workspacetools.KindRelated, route: endpointWorkspaceToolRelated},
		{mcpName: "knowvault_read", segment: "read", kind: workspacetools.KindRead, route: endpointWorkspaceToolRead},
		{mcpName: "knowvault_sources", segment: "sources", kind: workspacetools.KindSources, route: endpointWorkspaceToolSources},
		{mcpName: "knowvault_refresh", segment: "refresh", kind: workspacetools.KindRefresh, route: endpointWorkspaceToolRefresh},
		{mcpName: "knowvault_source_schema", segment: "source-schema", kind: workspacetools.KindSourceSchema, route: endpointWorkspaceToolSourceSchema},
	}
	for _, testCase := range cases {
		byMCP, mcpOK := registry.Lookup(testCase.mcpName)
		if !mcpOK {
			t.Fatalf("MCP name %s is not registered", testCase.mcpName)
		}
		byREST, restOK := registry.LookupREST(testCase.segment)
		if !restOK {
			t.Fatalf("REST tools/%s is not registered", testCase.segment)
		}
		if byMCP.Kind != byREST.Kind || byMCP.Name != byREST.Name || byMCP.Kind != testCase.kind {
			t.Fatalf("tools/%s resolved to %s/%s, want the %s entry of %s",
				testCase.segment, byREST.Name, byREST.Kind, testCase.kind, testCase.mcpName)
		}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/ws-1/tools/"+testCase.segment, nil)
		resolved, code := parseEndpointPath(request)
		if code != "" {
			t.Fatalf("tools/%s route recognition failed with %s", testCase.segment, code)
		}
		if resolved.kind != testCase.route {
			t.Fatalf("tools/%s resolved endpoint kind %d, want %d", testCase.segment, resolved.kind, testCase.route)
		}
		if resolved.workspaceToolKind != testCase.kind {
			t.Fatalf("tools/%s stored dispatcher kind %s, want %s", testCase.segment, resolved.workspaceToolKind, testCase.kind)
		}
		if resolved.workspaceID != "ws-1" {
			t.Fatalf("tools/%s resolved workspace %q, want ws-1", testCase.segment, resolved.workspaceID)
		}
	}
}

func TestWorkspaceToolRESTUnregisteredSegmentIsNotFoundWithoutCapability(t *testing.T) {
	for _, segment := range []string{"wiki_search", "wiki_get_page", "not-a-tool"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/ws-1/tools/"+segment, nil)
		resolved, code := parseEndpointPath(request)
		if code != "NOT_FOUND" {
			t.Fatalf("unregistered tools/%s was accepted with code %q", segment, code)
		}
		if resolved.workspaceToolKind != "" {
			t.Fatalf("unregistered tools/%s stored a dispatcher kind %q", segment, resolved.workspaceToolKind)
		}
	}
	// A route that carries no registry kind is refused on a Handler with no
	// mounted evidence, source or question capability. Reaching any capability
	// would panic on the nil fields, so a clean 404 NOT_FOUND proves the
	// unrecognised segment never entered one.
	handler := &Handler{}
	recorder := httptest.NewRecorder()
	handler.workspaceToolDispatch(recorder,
		httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/ws-1/tools/wiki_search", nil),
		database.AccessContext{}, "req-1", endpoint{})
	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), "NOT_FOUND") {
		t.Fatalf("unrecognised tool dispatch = %d %s, want 404 NOT_FOUND", recorder.Code, recorder.Body.String())
	}
}
