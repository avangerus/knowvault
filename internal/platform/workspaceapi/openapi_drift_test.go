package workspaceapi

// ARC-007 gate: "OpenAPI is the source of the HTTP contract; CI forbids
// drift." Until this test existed, api/openapi.yaml described 20 of the
// dispatcher's routes and the other 16 were live and undescribed — a client
// generated from the contract simply could not see evidence reads, the audit
// journal, refresh, trust verification, the confirmation authority, agent
// access codes, the search profile or the whole governed-query surface.
//
// The gate is deterministic and needs no YAML dependency: the dispatcher's
// route identity is the closed endpointKind enum, so this test iterates every
// kind from the first to endpointKindSentinel and fails when a kind has no
// entry in the table below, when its path is absent from api/openapi.yaml, or
// when a method the dispatcher accepts for it is not described there. Adding a
// route means adding a kind, which fails this test until the contract is
// written — which is exactly what "CI forbids drift" has to mean.

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/registration"
)

type describedRoute struct {
	// path is the OpenAPI path item, relative to the "/api/v1" server URL.
	path string
	// name is the human label used in failure messages.
	name string
}

// openAPIRoutes maps every dispatcher endpoint kind onto its OpenAPI path
// item. It is intentionally exhaustive rather than generated: an entry is a
// deliberate statement that this route is part of the published contract.
var openAPIRoutes = map[endpointKind]describedRoute{
	endpointCSRF:                          {"/session/csrf", "endpointCSRF"},
	endpointWorkspaceList:                 {"/workspaces", "endpointWorkspaceList"},
	endpointWorkspaceCreate:               {"/workspaces", "endpointWorkspaceCreate"},
	endpointWorkspaceGet:                  {"/workspaces/{workspace_id}", "endpointWorkspaceGet"},
	endpointWorkspaceUpdate:               {"/workspaces/{workspace_id}", "endpointWorkspaceUpdate"},
	endpointWorkspaceArchive:              {"/workspaces/{workspace_id}:archive", "endpointWorkspaceArchive"},
	endpointMemberAdd:                     {"/workspaces/{workspace_id}/members", "endpointMemberAdd"},
	endpointMemberChange:                  {"/workspaces/{workspace_id}/members/{principal_id}", "endpointMemberChange"},
	endpointMemberRemove:                  {"/workspaces/{workspace_id}/members/{principal_id}", "endpointMemberRemove"},
	endpointOwnershipTransfer:             {"/workspaces/{workspace_id}:transfer-ownership", "endpointOwnershipTransfer"},
	endpointSourceRegister:                {"/sources", "endpointSourceRegister"},
	endpointSourceConnectionBootstrap:     {"/sources/connections", "endpointSourceConnectionBootstrap"},
	endpointSourceDiscoveryRequest:        {"/sources/connections/{connection_id}:discover", "endpointSourceDiscoveryRequest"},
	endpointSourceDiscoveryGet:            {"/sources/discovery/{request_id}", "endpointSourceDiscoveryGet"},
	endpointSourceDiscoveryRegister:       {"/sources/discovery/{request_id}/views/{view_id}:register", "endpointSourceDiscoveryRegister"},
	endpointSourceActivate:                {"/sources/{source_scope_id}:activate", "endpointSourceActivate"},
	endpointSourceSync:                    {"/sources/{source_scope_id}:sync", "endpointSourceSync"},
	endpointWorkspaceSources:              {"/workspaces/{workspace_id}/sources", "endpointWorkspaceSources"},
	endpointWorkspaceSourceRemove:         {"/workspaces/{workspace_id}/sources/{source_scope_id}", "endpointWorkspaceSourceRemove"},
	endpointWorkspaceSourceDrafts:         {"/workspaces/{workspace_id}/source-drafts", "endpointWorkspaceSourceDrafts"},
	endpointWorkspaceSourceDraftDiscard:   {"/workspaces/{workspace_id}/source-drafts/{connection_id}", "endpointWorkspaceSourceDraftDiscard"},
	endpointEvidenceGet:                   {"/workspaces/{workspace_id}/evidence/{fragment_id}", "endpointEvidenceGet"},
	endpointWorkspaceAuditEvents:          {"/workspaces/{workspace_id}/audit-events", "endpointWorkspaceAuditEvents"},
	endpointQuestionCreate:                {"/workspaces/{workspace_id}/questions", "endpointQuestionCreate"},
	endpointQuestionGet:                   {"/workspaces/{workspace_id}/questions/{question_run_id}", "endpointQuestionGet"},
	endpointConversationList:              {"/workspaces/{workspace_id}/conversations", "endpointConversationList"},
	endpointConversationGet:               {"/workspaces/{workspace_id}/conversations/{conversation_id}", "endpointConversationGet"},
	endpointConversationArchive:           {"/workspaces/{workspace_id}/conversations/{conversation_id}:archive", "endpointConversationArchive"},
	endpointMCP:                           {"/mcp", "endpointMCP"},
	endpointConfirmGrantIssue:             {"/workspaces/{workspace_id}/confirmation-grants", "endpointConfirmGrantIssue"},
	endpointConfirmGrantRevoke:            {"/workspaces/{workspace_id}/confirmation-grants/{grant_id}:revoke", "endpointConfirmGrantRevoke"},
	endpointManagedSourceConfirm:          {"/workspaces/{workspace_id}/managed-source-confirmations", "endpointManagedSourceConfirm"},
	endpointManagedConfirmationRevoke:     {"/workspaces/{workspace_id}/managed-source-confirmations/{confirmation_id}:revoke", "endpointManagedConfirmationRevoke"},
	endpointSourceConnectionVerifyTrust:   {"/sources/connections/{connection_id}:verify-trust", "endpointSourceConnectionVerifyTrust"},
	endpointAccessCodes:                   {"/workspaces/{workspace_id}/access-codes", "endpointAccessCodes"},
	endpointAccessCodeRevoke:              {"/workspaces/{workspace_id}/access-codes/{credential_id}:revoke", "endpointAccessCodeRevoke"},
	endpointSearchProfile:                 {"/workspaces/{workspace_id}/search-profile", "endpointSearchProfile"},
	endpointSearchProfileRevise:           {"/workspaces/{workspace_id}/search-profile:revise", "endpointSearchProfileRevise"},
	endpointGovernedQuerySetLiveQueries:   {"/workspaces/{workspace_id}/governed-query-connections/{connection_id}:set-live-queries", "endpointGovernedQuerySetLiveQueries"},
	endpointGovernedQueryExposedSchema:    {"/workspaces/{workspace_id}/governed-query-connections/{connection_id}/exposed-schema", "endpointGovernedQueryExposedSchema"},
	endpointGovernedQueryAsk:              {"/workspaces/{workspace_id}/governed-query-connections/{connection_id}:ask", "endpointGovernedQueryAsk"},
	endpointGovernedQueryPromote:          {"/workspaces/{workspace_id}/governed-query-connections/{connection_id}:promote", "endpointGovernedQueryPromote"},
	endpointSourceUploadDocuments:         {"/sources/{source_scope_id}/documents", "endpointSourceUploadDocuments"},
	endpointSourceConnectors:              {"/source-connectors", "endpointSourceConnectors"},
	endpointMemberCandidates:              {"/workspaces/{workspace_id}/member-candidates", "endpointMemberCandidates"},
	endpointMetricDefinitions:             {"/workspaces/{workspace_id}/metric-definitions", "endpointMetricDefinitions"},
	endpointMetricDefinitionGet:           {"/workspaces/{workspace_id}/metric-definitions/{metric_id}/versions/{version}", "endpointMetricDefinitionGet"},
	endpointMetricDefinitionDraft:         {"/workspaces/{workspace_id}/metric-definitions:draft", "endpointMetricDefinitionDraft"},
	endpointMetricDefinitionApprove:       {"/workspaces/{workspace_id}/metric-definitions/{metric_id}:approve", "endpointMetricDefinitionApprove"},
	endpointWorkspaceToolListObjects:      {"/workspaces/{workspace_id}/tools/list-objects", "endpointWorkspaceToolListObjects"},
	endpointWorkspaceToolSearch:           {"/workspaces/{workspace_id}/tools/search", "endpointWorkspaceToolSearch"},
	endpointWorkspaceToolGrep:             {"/workspaces/{workspace_id}/tools/grep", "endpointWorkspaceToolGrep"},
	endpointWorkspaceToolRelated:          {"/workspaces/{workspace_id}/tools/related", "endpointWorkspaceToolRelated"},
	endpointWorkspaceToolRead:             {"/workspaces/{workspace_id}/tools/read", "endpointWorkspaceToolRead"},
	endpointWorkspaceToolSources:          {"/workspaces/{workspace_id}/tools/sources", "endpointWorkspaceToolSources"},
	endpointWorkspaceToolRefresh:          {"/workspaces/{workspace_id}/tools/refresh", "endpointWorkspaceToolRefresh"},
	endpointModelContextGet:               {"/workspaces/{workspace_id}/model-context", "endpointModelContextGet"},
	endpointModelContextSave:              {"/workspaces/{workspace_id}/model-context", "endpointModelContextSave"},
	endpointModelContextVersions:          {"/workspaces/{workspace_id}/model-context/versions", "endpointModelContextVersions"},
	endpointModelContextVersionGet:        {"/workspaces/{workspace_id}/model-context/versions/{version}", "endpointModelContextVersionGet"},
	endpointModelContextRestore:           {"/workspaces/{workspace_id}/model-context/versions/{version}:restore", "endpointModelContextRestore"},
	endpointModelContextProposals:         {"/workspaces/{workspace_id}/model-context/proposals", "endpointModelContextProposals"},
	endpointModelContextProposalAccept:    {"/workspaces/{workspace_id}/model-context/proposals/{proposal_id}:accept", "endpointModelContextProposalAccept"},
	endpointModelContextProposalReject:    {"/workspaces/{workspace_id}/model-context/proposals/{proposal_id}:reject", "endpointModelContextProposalReject"},
	endpointWorkspaceToolWorkspaceContext: {"/workspaces/{workspace_id}/tools/workspace-context", "endpointWorkspaceToolWorkspaceContext"},
	endpointWorkspaceToolSourceSchema:     {"/workspaces/{workspace_id}/tools/source-schema", "endpointWorkspaceToolSourceSchema"},
}

var httpMethodsUnderTest = []string{
	http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch,
}

// readOpenAPIPathItems returns path item -> declared lowercase methods. It is
// a deliberately small structural reader over the two indentation levels the
// contract file uses (a path item at two spaces, an operation at four); a full
// YAML parser would be a new dependency for a gate that only needs to know
// which routes are described.
func readOpenAPIPathItems(t *testing.T) map[string]map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("api/openapi.yaml must be readable by the drift gate: %v", err)
	}
	items := make(map[string]map[string]bool)
	inPaths := false
	current := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "paths:") {
			inPaths = true
			continue
		}
		if !inPaths {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// A key at column zero ends the paths section (components:, etc).
		if !strings.HasPrefix(line, " ") {
			break
		}
		if strings.HasPrefix(line, "  /") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(trimmed, ":") {
			current = strings.TrimSuffix(trimmed, ":")
			if _, exists := items[current]; !exists {
				items[current] = make(map[string]bool)
			}
			continue
		}
		if current == "" || !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "     ") {
			continue
		}
		for _, method := range httpMethodsUnderTest {
			if trimmed == strings.ToLower(method)+":" {
				items[current][method] = true
			}
		}
	}
	if len(items) == 0 {
		t.Fatalf("no path items parsed from api/openapi.yaml: the drift gate would pass vacuously")
	}
	return items
}

func TestEveryDispatcherRouteIsDescribedInOpenAPI(t *testing.T) {
	items := readOpenAPIPathItems(t)
	for kind := endpointCSRF; kind < endpointKindSentinel; kind++ {
		route, described := openAPIRoutes[kind]
		if !described {
			t.Fatalf("endpoint kind %d is routed by the dispatcher but has no OpenAPI entry: "+
				"add it to api/openapi.yaml and to openAPIRoutes (POKA_YOKE ARC-007)", kind)
		}
		methods, present := items[route.path]
		if !present {
			t.Fatalf("%s: api/openapi.yaml has no path item %q", route.name, route.path)
		}
		for _, method := range httpMethodsUnderTest {
			if !methodAllowed(endpoint{kind: kind}, method) {
				continue
			}
			if !methods[method] {
				t.Fatalf("%s: the dispatcher accepts %s %s but api/openapi.yaml does not describe that operation",
					route.name, method, route.path)
			}
		}
	}
}

// The gate must also notice a route that exists in the contract only. A path
// item nobody routes is drift in the other direction: a generated client would
// call something the server answers 404 for.
func TestOpenAPIWorkspacePathItemsAreAllRouted(t *testing.T) {
	items := readOpenAPIPathItems(t)
	routed := make(map[string]bool, len(openAPIRoutes))
	for _, route := range openAPIRoutes {
		routed[route.path] = true
	}
	for path := range items {
		// /system/* is internal/platform/systemapi's contract, not this
		// dispatcher's; it has its own composition and no workspace scope.
		if strings.HasPrefix(path, "/system/") {
			continue
		}
		if !routed[path] {
			t.Fatalf("api/openapi.yaml describes %q but no dispatcher endpoint kind routes it", path)
		}
	}
}

// A source advertised by the live catalog must also be accepted by the
// published response schema. Keep this reader scoped to the one inline enum;
// other connector-type enums must not make a stale declaration pass.
func TestOpenAPIRecurringSyncTypesMatchRuntime(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "api", "openapi.yaml"))
	if err != nil {
		t.Fatalf("read OpenAPI connector declarations: %v", err)
	}
	inSchema, inTypes := false, false
	var declared []string
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if line == "    ConnectorCatalogDeclarations:" {
			inSchema = true
			continue
		}
		if !inSchema || strings.TrimSpace(line) == "" {
			continue
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
			break
		}
		if line == "        autonomous_recurring_sync_source_types:" {
			inTypes = true
			continue
		}
		if inTypes && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         ") {
			break
		}
		if !inTypes || !strings.HasPrefix(line, "            enum: ") {
			continue
		}
		value := strings.TrimPrefix(line, "            enum: ")
		if declared != nil || !strings.HasPrefix(value, "[") || !strings.HasSuffix(value, "]") {
			t.Fatalf("recurring-sync declaration must contain one inline source-type enum: %q", value)
		}
		for _, item := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(value, "["), "]"), ",") {
			declared = append(declared, strings.TrimSpace(item))
		}
	}
	actual := registration.ConnectorCatalogData().Declarations.AutonomousRecurringSyncSourceTypes
	if len(declared) == 0 || len(actual) == 0 || strings.Join(declared, ",") != strings.Join(actual, ",") {
		t.Fatalf("OpenAPI recurring-sync types %v must match the runtime catalog %v", declared, actual)
	}
}
