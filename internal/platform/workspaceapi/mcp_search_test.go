package workspaceapi

// R3a-1 KV-A02b-r2 focused tests: the workspace lexical search tool. They prove
// the canonical tool is advertised only when the mounted evidence service
// implements the search capability, that it dispatches to the authorized
// evidence search with the closed argument envelope forwarded, that every hit
// carries an excerpt, score and immutable address, that paging is explicit,
// that a denial stays content-free, and that the removed `wiki_search` alias is
// neither advertised nor dispatched.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// fakeSearchEvidence is the fakeEvidenceService plus the additive optional
// search capability. Embedding keeps the existing Read harness behavior and
// records, so a test can prove the search tool composes the same authorized
// evidence service without touching the shared fake.
type fakeSearchEvidence struct {
	*fakeEvidenceService
	page        evidence.SearchPage
	searchErr   error
	searchCall  string
	query       string
	allVersions bool
	offset      int64
	limit       int64
}

func (service *fakeSearchEvidence) SearchFragments(_ context.Context, _ database.AccessContext, workspaceID, query string, allVersions bool, offset, limit int64) (evidence.SearchPage, error) {
	service.searchCall = "search"
	service.workspaceID = workspaceID
	service.query = query
	service.allVersions = allVersions
	service.offset = offset
	service.limit = limit
	if service.searchErr != nil {
		return evidence.SearchPage{}, service.searchErr
	}
	return service.page, nil
}

func searchHarness(t *testing.T, service *fakeSearchEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	service.fakeEvidenceService = harness.evidence
	harness.handler.evidence = service
	return harness
}

func testSearchHit(t *testing.T) evidence.SearchHit {
	t.Helper()
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("the alpha project document mentions KnowVault in full")
	fragment.EvidenceTextHash = "sha256:" + strings.Repeat("ef", 32)
	return evidence.SearchHit{Fragment: fragment, Excerpt: "…alpha project document mentions…", Score: 3}
}

type mcpSearchEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured struct {
			Results    []map[string]any `json:"results"`
			Offset     int64            `json:"offset"`
			Limit      int64            `json:"limit"`
			HasMore    bool             `json:"has_more"`
			NextOffset *int64           `json:"next_offset"`
		} `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPSearch(t *testing.T, harness *testHarness, tool, arguments string) mcpSearchEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"`+tool+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s status=%d body=%s", tool, response.Code, response.Body.String())
	}
	var envelope mcpSearchEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP %s did not decode: %v: %s", tool, err, response.Body.String())
	}
	return envelope
}

func listToolSchemas(t *testing.T, harness *testHarness) map[string]map[string]any {
	t.Helper()
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
	schemas := make(map[string]map[string]any, len(list.Result.Tools))
	for _, tool := range list.Result.Tools {
		schemas[tool.Name] = tool.InputSchema
	}
	return schemas
}

// TestMCPSearchAdvertisesCanonicalTool proves the canonical search name is
// listed when the mounted evidence service implements the capability, that it
// requires workspace_id+query, that its schema is closed, and that the removed
// wiki-rag alias is absent.
func TestMCPSearchAdvertisesCanonicalTool(t *testing.T) {
	harness := searchHarness(t, &fakeSearchEvidence{})
	schemas := listToolSchemas(t, harness)

	canonical, ok := schemas[mcpToolSearch]
	if !ok {
		t.Fatalf("tools/list omitted %s: %#v", mcpToolSearch, schemas)
	}
	if required, _ := canonical["required"].([]any); len(required) != 2 {
		t.Fatalf("canonical search required=%#v", canonical["required"])
	}
	if additional, _ := canonical["additionalProperties"].(bool); additional {
		t.Fatalf("canonical search schema is not closed: %#v", canonical)
	}
	if _, ok := schemas["wiki_search"]; ok {
		t.Fatalf("tools/list still advertises the removed wiki_search alias: %#v", schemas)
	}
}

// TestMCPSearchNotAdvertisedWithoutCapability proves a service without the
// search capability never advertises the tool, so tools/list cannot promise a
// call that would fail closed.
func TestMCPSearchNotAdvertisedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	schemas := listToolSchemas(t, harness)
	if _, ok := schemas[mcpToolSearch]; ok {
		t.Fatalf("search tool advertised without the capability: %#v", schemas[mcpToolSearch])
	}
	if _, ok := schemas["wiki_search"]; ok {
		t.Fatalf("wiki alias advertised without the capability: %#v", schemas["wiki_search"])
	}
}

// TestMCPSearchReturnsExcerptScoreAddressAndVersion proves an authorized search
// forwards the closed envelope to the evidence search and returns every required
// field from the canonical result shape.
func TestMCPSearchReturnsExcerptScoreAddressAndVersion(t *testing.T) {
	hit := testSearchHit(t)
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{hit}}}
	harness := searchHarness(t, service)

	envelope := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"alpha KnowVault","limit":5}`)
	if envelope.Error != nil {
		t.Fatalf("search denied unexpectedly: %#v", envelope.Error)
	}
	if service.searchCall != "search" || service.workspaceID != "ws_alpha" || service.query != "alpha KnowVault" {
		t.Fatalf("search capability got call=%q workspace=%q query=%q", service.searchCall, service.workspaceID, service.query)
	}
	if service.limit != 5 || service.offset != 0 || service.allVersions {
		t.Fatalf("search capability got limit=%d offset=%d allVersions=%v", service.limit, service.offset, service.allVersions)
	}
	if len(envelope.Result.Structured.Results) != 1 {
		t.Fatalf("search results=%#v", envelope.Result.Structured.Results)
	}
	result := envelope.Result.Structured.Results[0]
	if result["excerpt"] != hit.Excerpt || result["score"] != float64(hit.Score) {
		t.Fatalf("search hit excerpt/score=%#v", result)
	}
	if result["version_id"] != hit.Fragment.SourceVersionID || result["content_hash"] != hit.Fragment.ContentHash {
		t.Fatalf("search hit version/content hash=%#v", result)
	}
	address, _ := result["address"].(map[string]any)
	if address == nil {
		t.Fatalf("search hit missing address: %#v", result)
	}
	span, _ := address["span"].(map[string]any)
	if span == nil || span["text_hash"] != hit.Fragment.EvidenceTextHash {
		t.Fatalf("search hit address span=%#v", address)
	}
}

// TestMCPSearchAllVersionsAndPaginationAreExplicit proves the all_versions
// switch is forwarded and that a page reports its effective limit, has_more and
// next_offset instead of truncating silently.
func TestMCPSearchAllVersionsAndPaginationAreExplicit(t *testing.T) {
	hit := testSearchHit(t)
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{hit}, HasMore: true, NextOffset: 7}}
	harness := searchHarness(t, service)

	envelope := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"alpha","all_versions":true,"offset":6,"limit":1}`)
	if envelope.Error != nil {
		t.Fatalf("search denied unexpectedly: %#v", envelope.Error)
	}
	if !service.allVersions || service.offset != 6 || service.limit != 1 {
		t.Fatalf("search capability got allVersions=%v offset=%d limit=%d", service.allVersions, service.offset, service.limit)
	}
	if !envelope.Result.Structured.HasMore || envelope.Result.Structured.NextOffset == nil || *envelope.Result.Structured.NextOffset != 7 {
		t.Fatalf("search page lost its cursor: %#v", envelope.Result.Structured)
	}
	if envelope.Result.Structured.Limit != 1 {
		t.Fatalf("search page effective limit=%d", envelope.Result.Structured.Limit)
	}
}

// TestMCPWikiSearchNameIsRefusedAsUnknownTool proves the removed wiki-rag name
// is not dispatched: a tools/call naming `wiki_search` is refused as an unknown
// tool with no evidence search reached, no content returned and the wiki/q/
// project alias arguments no longer decoded.
func TestMCPWikiSearchNameIsRefusedAsUnknownTool(t *testing.T) {
	service := &fakeSearchEvidence{}
	harness := searchHarness(t, service)

	envelope := callMCPSearch(t, harness, "wiki_search", `{"wiki":"ws_alpha","q":"alpha"}`)
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("wiki_search was not refused as an unknown tool: %#v", envelope.Error)
	}
	if service.searchCall != "" {
		t.Fatalf("wiki_search reached the evidence search: %q", service.searchCall)
	}
	if len(envelope.Result.Structured.Results) != 0 || len(envelope.Result.Content) != 0 {
		t.Fatalf("wiki_search leaked content: %#v", envelope.Result)
	}
}

// TestMCPSearchDeniesContentFreeWithoutWorkspaceEcho proves a denied or unknown
// workspace is the viewer's single ErrNotFound, mapped to the existing
// content-free -32004 that carries no result and never echoes the workspace id.
func TestMCPSearchDeniesContentFreeWithoutWorkspaceEcho(t *testing.T) {
	service := &fakeSearchEvidence{searchErr: evidence.ErrNotFound}
	harness := searchHarness(t, service)

	envelope := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_secret","query":"alpha"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("search denial=%#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Results) != 0 || len(envelope.Result.Content) != 0 {
		t.Fatalf("search denial leaked content: %#v", envelope.Result)
	}
}

// TestMCPSearchRejectsUnboundedArguments proves the closed envelope: a missing
// query, a missing workspace on the canonical tool, an unknown member and a
// negative page bound are rejected before the evidence search is touched.
func TestMCPSearchRejectsUnboundedArguments(t *testing.T) {
	for name, arguments := range map[string]string{
		"missing_query":     `{"workspace_id":"ws_alpha"}`,
		"empty_query":       `{"workspace_id":"ws_alpha","query":"  "}`,
		"missing_workspace": `{"query":"alpha"}`,
		"unknown_member":    `{"workspace_id":"ws_alpha","query":"alpha","extra":true}`,
		"negative_offset":   `{"workspace_id":"ws_alpha","query":"alpha","offset":-1}`,
		"alias_q_member":    `{"workspace_id":"ws_alpha","q":"alpha"}`,
	} {
		name, arguments := name, arguments
		t.Run(name, func(t *testing.T) {
			service := &fakeSearchEvidence{}
			harness := searchHarness(t, service)
			envelope := callMCPSearch(t, harness, mcpToolSearch, arguments)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602, got %#v", envelope.Error)
			}
			if service.searchCall != "" {
				t.Fatalf("invalid arguments reached the evidence search: %q", service.searchCall)
			}
		})
	}
}

// TestMCPSearchNeverEchoesQueryOrWorkspaceInError guards the content-free
// contract: an invalid call names neither the query nor the workspace it was
// given.
func TestMCPSearchNeverEchoesQueryOrWorkspaceInError(t *testing.T) {
	service := &fakeSearchEvidence{}
	harness := searchHarness(t, service)
	envelope := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"alpha","extra":true}`)
	encoded := envelope.Error
	if encoded == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(encoded.Message, "alpha") {
		t.Fatalf("error echoed query/workspace content: %q", encoded.Message)
	}
}

// searchDenialAuditSource wraps fakeSearchEvidence to record the
// admission-before-data and terminal outcome sequence of the knowvault_search
// negative control. In production that sequence is the real evidence viewer's
// workspace admission followed by its R1 audit journal record; in this unit
// probe it is the injected EvidenceSearch boundary, so the tool's delegation to
// a search that admits, then records a classed denial, is observable without a
// raw row forgery or a second read path.
type searchDenialAuditSource struct {
	*fakeSearchEvidence
	order []string
}

func (service *searchDenialAuditSource) SearchFragments(ctx context.Context, access database.AccessContext, workspaceID, query string, allVersions bool, offset, limit int64) (evidence.SearchPage, error) {
	service.order = append(service.order, "admission")
	page, err := service.fakeSearchEvidence.SearchFragments(ctx, access, workspaceID, query, allVersions, offset, limit)
	if err != nil {
		service.order = append(service.order, "denied:"+string(workspacerepository.CodeOf(err)))
		return page, err
	}
	service.order = append(service.order, "data")
	return page, nil
}

// TestMCPKnowvaultSearchDenialAdmittedAndAudited is the R3a-1 Outcome 2
// negative control for the canonical knowvault_search tool: a principal without
// the workspace right must receive the existing content-free -32004
// `workspace documents not found` with no result, no structuredContent and no
// workspace-id echo, and the call must record admission before data and its
// classed denial outcome through the same evidence-search boundary the
// production viewer implements. Weakening the denial guard in
// internal/platform/workspaceapi/mcp_search.go to fall through, or weakening
// its -32004 denial mapping to the generic -32000 service-unavailable, turns
// this probe RED.
func TestMCPKnowvaultSearchDenialAdmittedAndAudited(t *testing.T) {
	harness := newTestHarness(t)
	audit := &searchDenialAuditSource{fakeSearchEvidence: &fakeSearchEvidence{searchErr: workspacerepository.NewError(workspacerepository.CodeDenied, nil)}}
	audit.fakeSearchEvidence.fakeEvidenceService = harness.evidence
	harness.handler.evidence = audit

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"s3","method":"tools/call","params":{"name":"`+mcpToolSearch+`","arguments":{"workspace_id":"ws_foreign","query":"alpha"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_search transport status=%d body=%s", response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP knowvault_search denial did not decode: %v: %s", err, response.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "workspace documents not found" {
		t.Fatalf("MCP knowvault_search denial error=%#v body=%s", outcome.Error, response.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("MCP knowvault_search denial carried a result: %s", string(*outcome.Result))
	}
	if audit.searchCall != "search" {
		t.Fatalf("MCP knowvault_search denial never reached the authorized evidence search: %q", audit.searchCall)
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"results"`, `"excerpt"`, testScopeID} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("MCP knowvault_search denial leaked %q: %s", leaked, response.Body.String())
		}
	}
	if order := strings.Join(audit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("MCP knowvault_search denial audit order=%q, want admission before the closed-class denial", order)
	}
}
