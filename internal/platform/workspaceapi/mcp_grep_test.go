package workspaceapi

// R3a-1 KV-A02c focused tests: the workspace exact-regex grep tool. They prove
// the canonical tool is advertised only when the mounted evidence service can
// serve it (directly, or through its inventory + whole-object reads), that it
// dispatches to the authorized grep source with the closed argument envelope
// forwarded, that every hit carries a matched offset/length, a bounded excerpt,
// the version/moment/content hash and an immutable address whose canonical form
// resolves the whole object through knowvault_evidence_read, that paging is
// explicit and lossless, that an invalid pattern and a denial stay content-free,
// and that no wiki-rag alias is advertised.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// fakeGrepEvidence is the fakeEvidenceService plus the additive optional grep
// capability. Embedding keeps the existing Read harness behavior and records, so
// a test can prove the grep tool composes the same authorized evidence service
// without touching the shared fake.
type fakeGrepEvidence struct {
	*fakeEvidenceService
	page        GrepPage
	grepErr     error
	grepCall    string
	pattern     string
	allVersions bool
	offset      int64
	limit       int64
}

func (service *fakeGrepEvidence) GrepFragments(_ context.Context, _ database.AccessContext, workspaceID, pattern string, allVersions bool, offset, limit int64) (GrepPage, error) {
	service.grepCall = "grep"
	service.workspaceID = workspaceID
	service.pattern = pattern
	service.allVersions = allVersions
	service.offset = offset
	service.limit = limit
	if service.grepErr != nil {
		return GrepPage{}, service.grepErr
	}
	return service.page, nil
}

func grepHarness(t *testing.T, service *fakeGrepEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	service.fakeEvidenceService = harness.evidence
	harness.handler.evidence = service
	return harness
}

// fakeGrepInventoryEvidence is a self-contained evidence service that implements
// exactly the capabilities the production *evidence.Viewer exposes: the required
// fragment read, the object inventory and the whole-object read, but NOT the
// grep capability directly. It therefore proves the production capability
// resolver composes grep out of the existing authorized reads.
type fakeGrepInventoryEvidence struct {
	items       []evidence.ObjectInventoryItem
	objects     map[string]evidence.WholeObject
	listErr     error
	objectErr   error
	listCall    string
	objectCalls []string
	allVersions bool
	offset      int64
	limit       int64
}

func (service *fakeGrepInventoryEvidence) Read(_ context.Context, _ database.AccessContext, _ string, fragmentID string) (evidence.Fragment, error) {
	// Match the production viewer's fragment-read behavior so an address emitted
	// by grep can be round-tripped through the ordinary knowvault_read route.
	for _, object := range service.objects {
		if object.Fragment.FragmentID == fragmentID {
			return object.Fragment, nil
		}
	}
	return evidence.Fragment{}, evidence.ErrNotFound
}

func (service *fakeGrepInventoryEvidence) ListObjects(_ context.Context, _ database.AccessContext, _ string, allVersions bool, offset, limit int64) (evidence.ObjectInventoryPage, error) {
	service.listCall = "list"
	service.allVersions = allVersions
	service.offset = offset
	service.limit = limit
	if service.listErr != nil {
		return evidence.ObjectInventoryPage{}, service.listErr
	}
	start := int(offset)
	if start > len(service.items) {
		start = len(service.items)
	}
	end := start + int(limit)
	if end > len(service.items) {
		end = len(service.items)
	}
	page := evidence.ObjectInventoryPage{Items: append([]evidence.ObjectInventoryItem(nil), service.items[start:end]...)}
	if end < len(service.items) {
		page.HasMore = true
		page.NextOffset = int64(end)
	}
	return page, nil
}

func (service *fakeGrepInventoryEvidence) ReadObject(_ context.Context, _ database.AccessContext, _, fragmentID string) (evidence.WholeObject, error) {
	service.objectCalls = append(service.objectCalls, fragmentID)
	if service.objectErr != nil {
		return evidence.WholeObject{}, service.objectErr
	}
	object, ok := service.objects[fragmentID]
	if !ok {
		return evidence.WholeObject{}, evidence.ErrNotFound
	}
	return object, nil
}

func grepInventoryHarness(t *testing.T, service *fakeGrepInventoryEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	harness.handler.evidence = service
	return harness
}

// grepInventoryService builds a one-object workspace whose canonical text is
// "alpha beta alpha".
func grepInventoryService(t *testing.T) (*fakeGrepInventoryEvidence, evidence.WholeObject) {
	t.Helper()
	anchor := testEvidenceFragment(t)
	anchor.FragmentID = "fragment_01H9ABCDEFGHJKMNPQRSTVWX1"
	anchor.Text = []byte("alpha beta alpha")
	anchor.EvidenceTextHash = mcpEvidenceReadTextHash(anchor.Text)
	object := evidence.WholeObject{
		Fragment: anchor, Text: anchor.Text, FragmentCount: 1,
		FirstOrdinal: anchor.Ordinal, LastOrdinal: anchor.Ordinal,
		Fragments: []evidence.ObjectFragmentSpan{{
			FragmentID: anchor.FragmentID, Ordinal: anchor.Ordinal, Offset: 0, Length: len(anchor.Text),
		}},
	}
	service := &fakeGrepInventoryEvidence{
		items: []evidence.ObjectInventoryItem{{
			SourceObjectID: anchor.SourceObjectID, ObjectType: "FILE", ConnectionID: anchor.ConnectionID,
			SourceVersionID: anchor.SourceVersionID, ContentHash: anchor.ContentHash, ObservedAt: anchor.ObservedAt,
			FragmentCount: 1, FirstFragmentID: anchor.FragmentID, FirstOrdinal: anchor.Ordinal, LastOrdinal: anchor.Ordinal,
		}},
		objects: map[string]evidence.WholeObject{anchor.FragmentID: object},
	}
	return service, object
}

type mcpGrepEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured struct {
			Matches    []map[string]any `json:"matches"`
			Offset     int64            `json:"offset"`
			Limit      int64            `json:"limit"`
			HasMore    bool             `json:"has_more"`
			NextOffset *int64           `json:"next_offset"`
		} `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPGrep(t *testing.T, harness *testHarness, arguments string) mcpGrepEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"g","method":"tools/call","params":{"name":"`+mcpToolGrep+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s status=%d body=%s", mcpToolGrep, response.Code, response.Body.String())
	}
	var envelope mcpGrepEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP %s did not decode: %v: %s", mcpToolGrep, err, response.Body.String())
	}
	return envelope
}

// TestMCPGrepAdvertisesCanonicalTool proves the canonical grep name is listed
// with a closed schema and that no wiki-rag name is advertised.
func TestMCPGrepAdvertisesCanonicalTool(t *testing.T) {
	harness := grepHarness(t, &fakeGrepEvidence{})
	schemas := listToolSchemas(t, harness)

	canonical, ok := schemas[mcpToolGrep]
	if !ok {
		t.Fatalf("tools/list omitted %s: %#v", mcpToolGrep, schemas)
	}
	if required, _ := canonical["required"].([]any); len(required) != 2 {
		t.Fatalf("canonical grep required=%#v", canonical["required"])
	}
	if additional, _ := canonical["additionalProperties"].(bool); additional {
		t.Fatalf("canonical grep schema is not closed: %#v", canonical)
	}
	properties, _ := canonical["properties"].(map[string]any)
	if _, ok := properties["address"]; ok {
		t.Fatalf("canonical grep schema advertises address without a whole-object reader: %#v", canonical)
	}
	for _, removed := range []string{"code_search", "code_get_file", "wiki_search", "wiki_get_page"} {
		if _, ok := schemas[removed]; ok {
			t.Fatalf("tools/list advertises removed wiki-rag name %q", removed)
		}
	}
}

func TestMCPGrepAddressRequiresWholeObjectCapability(t *testing.T) {
	hit := testGrepHit(t)
	service := &fakeGrepEvidence{}
	harness := grepHarness(t, service)
	selector := mcpGrepCanonicalAddressKeyed(nil, hit.Object, "")
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, selector)+`}`)
	if envelope.Error == nil || envelope.Error.Code != -32000 {
		t.Fatalf("address grep without whole-object reader error=%#v, want service unavailable", envelope.Error)
	}
	if service.grepCall != "" || service.fakeEvidenceService.call != "" {
		t.Fatalf("unsupported address request fell back to a broader capability: grep=%q read=%q", service.grepCall, service.fakeEvidenceService.call)
	}
}

func TestMCPGrepAddressRejectsNonTextSpanBeforeRead(t *testing.T) {
	service, object := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)
	parsed, err := address.Parse(mcpGrepCanonicalAddressKeyed(nil, object, ""))
	if err != nil {
		t.Fatal(err)
	}
	parsed.SpanKind = address.SpanKindCode
	parsed.File = "README.md"
	parsed.LineStart = 1
	parsed.LineEnd = 1
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, parsed.String())+`}`)
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("non-text address error=%#v, want -32602", envelope.Error)
	}
	if service.listCall != "" || len(service.objectCalls) != 0 {
		t.Fatalf("non-text address touched evidence: list=%q objects=%#v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepNotAdvertisedWithoutCapability proves a service without the
// inventory + whole-object capability never advertises the tool.
func TestMCPGrepNotAdvertisedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	schemas := listToolSchemas(t, harness)
	if _, ok := schemas[mcpToolGrep]; ok {
		t.Fatalf("grep advertised without the capability: %#v", schemas[mcpToolGrep])
	}
}

// TestMCPGrepAdvertisedThroughInventoryAndWholeObject proves the production
// capability resolver advertises grep for a service that only implements the
// existing authorized inventory and whole-object reads, and that the tool is
// served over those reads.
func TestMCPGrepAdvertisedThroughInventoryAndWholeObject(t *testing.T) {
	service, object := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)

	schemas := listToolSchemas(t, harness)
	if _, ok := schemas[mcpToolGrep]; !ok {
		t.Fatalf("grep not advertised through the inventory + whole-object reads")
	}
	properties, _ := schemas[mcpToolGrep]["properties"].(map[string]any)
	if _, ok := properties["address"]; !ok {
		t.Fatalf("exact-address selector not advertised with whole-object reader: %#v", schemas[mcpToolGrep])
	}
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha"}`)
	if envelope.Error != nil {
		t.Fatalf("grep denied unexpectedly: %#v", envelope.Error)
	}
	if len(envelope.Result.Structured.Matches) != 2 {
		t.Fatalf("grep matches=%#v", envelope.Result.Structured.Matches)
	}
	if service.listCall != "list" || service.limit != mcpGrepScanPageSize || service.offset != 0 {
		t.Fatalf("inventory scan got call=%q offset=%d limit=%d", service.listCall, service.offset, service.limit)
	}
	if len(service.objectCalls) != 1 || service.objectCalls[0] != object.Fragment.FragmentID {
		t.Fatalf("whole-object reads=%#v", service.objectCalls)
	}
	first := envelope.Result.Structured.Matches[0]
	if first["offset"] != float64(0) || first["length"] != float64(5) {
		t.Fatalf("match offset/length=%#v", first)
	}
	if first["excerpt"] != "alpha beta alpha" {
		t.Fatalf("match excerpt=%#v", first)
	}
	if first["match_hash"] != address.WholeHash([]byte("alpha")) {
		t.Fatalf("match hash=%#v", first["match_hash"])
	}
	addressObject, _ := first["address"].(map[string]any)
	span, _ := addressObject["span"].(map[string]any)
	if span == nil || span["text_hash"] != address.WholeHash(object.Text) {
		t.Fatalf("match address span=%#v", addressObject)
	}

	// The emitted canonical address resolves the whole object through
	// knowvault_evidence_read, under the same authorized whole-object read.
	canonical, _ := first["canonical_address"].(string)
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatalf("emitted canonical address does not parse: %v (%q)", err, canonical)
	}
	if _, err := address.VerifySpan(object.Text, parsed); err != nil {
		t.Fatalf("emitted canonical address does not verify: %v", err)
	}
	read := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","address":`+jsonString(t, canonical)+`,"cursor":""}`)
	if read.Error != nil {
		t.Fatalf("grep address did not resolve through knowvault_evidence_read: %#v", read.Error)
	}
	if text, _ := read.Result.Structured["text"].(string); text != string(object.Text) {
		t.Fatalf("grep address read text=%q", text)
	}
}

// TestMCPGrepReturnsOffsetsAddressAndVersion proves an authorized grep forwards
// the closed envelope and returns every required field from the canonical result
// shape.
func TestMCPGrepReturnsOffsetsAddressAndVersion(t *testing.T) {
	hit := testGrepHit(t)
	service := &fakeGrepEvidence{page: GrepPage{Hits: []GrepHit{hit}}}
	harness := grepHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha\\s+KnowVault","limit":5}`)
	if envelope.Error != nil {
		t.Fatalf("grep denied unexpectedly: %#v", envelope.Error)
	}
	if service.grepCall != "grep" || service.workspaceID != "ws_alpha" || service.pattern != `alpha\s+KnowVault` {
		t.Fatalf("grep capability got call=%q workspace=%q pattern=%q", service.grepCall, service.workspaceID, service.pattern)
	}
	if service.limit != 5 || service.offset != 0 || service.allVersions {
		t.Fatalf("grep capability got limit=%d offset=%d allVersions=%v", service.limit, service.offset, service.allVersions)
	}
	if len(envelope.Result.Structured.Matches) != 1 {
		t.Fatalf("grep matches=%#v", envelope.Result.Structured.Matches)
	}
	match := envelope.Result.Structured.Matches[0]
	if match["offset"] != float64(hit.Offset) || match["length"] != float64(hit.Length) || match["excerpt"] != hit.Excerpt {
		t.Fatalf("grep match=%#v", match)
	}
	if match["version_id"] != hit.Fragment.SourceVersionID || match["content_hash"] != hit.Fragment.ContentHash {
		t.Fatalf("grep match version/content hash=%#v", match)
	}
	if match["canonical_address"] == "" || match["canonical_address"] == nil {
		t.Fatalf("grep match missing canonical address: %#v", match)
	}
	addressObject, _ := match["address"].(map[string]any)
	span, _ := addressObject["span"].(map[string]any)
	if span == nil || span["text_hash"] != address.WholeHash(hit.Object.Text) {
		t.Fatalf("grep match address span=%#v", addressObject)
	}
	if _, ok := span["total_length"]; !ok {
		t.Fatalf("grep match address span lost total_length: %#v", span)
	}
}

// TestMCPGrepAllVersionsAndPaginationAreExplicit proves the all_versions switch
// is forwarded and that a page reports its effective (capped) limit, has_more
// and next_offset instead of truncating silently.
func TestMCPGrepAllVersionsAndPaginationAreExplicit(t *testing.T) {
	hit := testGrepHit(t)
	service := &fakeGrepEvidence{page: GrepPage{Hits: []GrepHit{hit}, HasMore: true, NextOffset: 7}}
	harness := grepHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","all_versions":true,"offset":6,"limit":100000}`)
	if envelope.Error != nil {
		t.Fatalf("grep denied unexpectedly: %#v", envelope.Error)
	}
	if !service.allVersions || service.offset != 6 || service.limit != mcpGrepMaxLimit {
		t.Fatalf("grep capability got allVersions=%v offset=%d limit=%d", service.allVersions, service.offset, service.limit)
	}
	if !envelope.Result.Structured.HasMore || envelope.Result.Structured.NextOffset == nil || *envelope.Result.Structured.NextOffset != 7 {
		t.Fatalf("grep page lost its cursor: %#v", envelope.Result.Structured)
	}
	if envelope.Result.Structured.Limit != mcpGrepMaxLimit || envelope.Result.Structured.Offset != 6 {
		t.Fatalf("grep page effective window=%#v", envelope.Result.Structured)
	}
}

// TestMCPGrepRejectsInvalidArguments proves the closed envelope: a missing or
// empty pattern, a malformed regex, a missing workspace on the canonical tool, an
// unknown member, a wrong-typed member and a negative page bound are rejected
// before the grep source is touched.
func TestMCPGrepRejectsInvalidArguments(t *testing.T) {
	for name, arguments := range map[string]string{
		"missing_pattern":     `{"workspace_id":"ws_alpha"}`,
		"empty_pattern":       `{"workspace_id":"ws_alpha","pattern":"  "}`,
		"missing_workspace":   `{"pattern":"alpha"}`,
		"malformed_regex":     `{"workspace_id":"ws_alpha","pattern":"("}`,
		"unknown_member":      `{"workspace_id":"ws_alpha","pattern":"alpha","q":"alpha"}`,
		"wrong_typed_bool":    `{"workspace_id":"ws_alpha","pattern":"alpha","all_versions":"yes"}`,
		"negative_offset":     `{"workspace_id":"ws_alpha","pattern":"alpha","offset":-1}`,
		"negative_limit":      `{"workspace_id":"ws_alpha","pattern":"alpha","limit":-1}`,
		"empty_address":       `{"workspace_id":"ws_alpha","pattern":"alpha","address":""}`,
		"null_address":        `{"workspace_id":"ws_alpha","pattern":"alpha","address":null}`,
		"wrong_typed_address": `{"workspace_id":"ws_alpha","pattern":"alpha","address":17}`,
	} {
		name, arguments := name, arguments
		t.Run(name, func(t *testing.T) {
			service := &fakeGrepEvidence{}
			harness := grepHarness(t, service)
			envelope := callMCPGrep(t, harness, arguments)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602, got %#v", envelope.Error)
			}
			if service.grepCall != "" {
				t.Fatalf("invalid arguments reached the grep source: %q", service.grepCall)
			}
		})
	}
}

func TestMCPGrepNullAddressDoesNotFallBackToInventory(t *testing.T) {
	service, _ := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":null}`)
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("explicit null address should be rejected: %#v", envelope.Error)
	}
	if service.listCall != "" || len(service.objectCalls) != 0 {
		t.Fatalf("explicit null address widened into inventory/read: list=%q objectCalls=%v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepDeniesContentFreeWithoutWorkspaceEcho proves a denied or unknown
// workspace is the underlying single denial, mapped to the existing content-free
// -32004 that carries no match, excerpt or address and never echoes the workspace
// id.
func TestMCPGrepDeniesContentFreeWithoutWorkspaceEcho(t *testing.T) {
	service := &fakeGrepEvidence{grepErr: evidence.ErrNotFound}
	harness := grepHarness(t, service)

	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_secret","pattern":"alpha"}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 {
		t.Fatalf("grep denial=%#v", envelope.Error)
	}
	if strings.Contains(envelope.Error.Message, "ws_secret") {
		t.Fatalf("grep denial echoed the workspace id: %q", envelope.Error.Message)
	}
	if len(envelope.Result.Structured.Matches) != 0 || len(envelope.Result.Content) != 0 {
		t.Fatalf("grep denial leaked content: %#v", envelope.Result)
	}
}

// grepDenialAuditSource wraps fakeGrepEvidence to record the admission-before-
// data and terminal outcome sequence of the knowvault_grep negative control. In
// production that sequence is the real evidence viewer's workspace admission
// followed by its R1 audit journal record; in this unit probe it is the injected
// EvidenceGrep boundary, so the tool's delegation to a grep that admits, then
// records a classed denial, is observable without a raw row forgery or a second
// read path.
type grepDenialAuditSource struct {
	*fakeGrepEvidence
	order []string
}

func (service *grepDenialAuditSource) GrepFragments(ctx context.Context, access database.AccessContext, workspaceID, pattern string, allVersions bool, offset, limit int64) (GrepPage, error) {
	service.order = append(service.order, "admission")
	page, err := service.fakeGrepEvidence.GrepFragments(ctx, access, workspaceID, pattern, allVersions, offset, limit)
	if err != nil {
		service.order = append(service.order, "denied:"+string(workspacerepository.CodeOf(err)))
		return page, err
	}
	service.order = append(service.order, "data")
	return page, nil
}

// TestMCPKnowvaultGrepDenialAdmittedAndAudited is the R3a-1 Outcome 2 negative
// control for the canonical knowvault_grep tool: a principal without the
// workspace right must receive the existing content-free -32004 `workspace
// documents not found` with no result, no structuredContent, no match/excerpt/
// address and no workspace-id echo, and the call must record admission before
// data and its classed denial outcome through the same evidence-grep boundary
// the production viewer implements. Weakening the denial guard in
// internal/platform/workspaceapi/mcp_grep.go to fall through, or weakening its
// -32004 denial mapping to the generic -32000 service-unavailable, turns this
// probe RED.
func TestMCPKnowvaultGrepDenialAdmittedAndAudited(t *testing.T) {
	harness := newTestHarness(t)
	audit := &grepDenialAuditSource{fakeGrepEvidence: &fakeGrepEvidence{grepErr: workspacerepository.NewError(workspacerepository.CodeDenied, nil)}}
	audit.fakeGrepEvidence.fakeEvidenceService = harness.evidence
	harness.handler.evidence = audit

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"g1","method":"tools/call","params":{"name":"`+mcpToolGrep+`","arguments":{"workspace_id":"ws_foreign","pattern":"alpha"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_grep transport status=%d body=%s", response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP knowvault_grep denial did not decode: %v: %s", err, response.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "workspace documents not found" {
		t.Fatalf("MCP knowvault_grep denial error=%#v body=%s", outcome.Error, response.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("MCP knowvault_grep denial carried a result: %s", string(*outcome.Result))
	}
	if audit.grepCall != "grep" {
		t.Fatalf("MCP knowvault_grep denial never reached the authorized evidence grep: %q", audit.grepCall)
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"matches"`, `"excerpt"`, `"address"`, testScopeID} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("MCP knowvault_grep denial leaked %q: %s", leaked, response.Body.String())
		}
	}
	if order := strings.Join(audit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("MCP knowvault_grep denial audit order=%q, want admission before the closed-class denial", order)
	}
}

// testGrepHit builds a canonical grep hit over "the alpha project document
// mentions KnowVault in full".
func testGrepHit(t *testing.T) GrepHit {
	t.Helper()
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("the alpha project document mentions KnowVault in full")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	object := evidence.WholeObject{
		Fragment: fragment, Text: fragment.Text, FragmentCount: 1,
		FirstOrdinal: fragment.Ordinal, LastOrdinal: fragment.Ordinal,
		Fragments: []evidence.ObjectFragmentSpan{{
			FragmentID: fragment.FragmentID, Ordinal: fragment.Ordinal, Offset: 0, Length: len(fragment.Text),
		}},
	}
	return GrepHit{Fragment: fragment, Object: object, Offset: 4, Length: 5, Excerpt: "the …alpha… project document mentions KnowVault in full"}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json encode %q: %v", value, err)
	}
	return string(encoded)
}

// TestMCPGrepAddressUsesOneAuthorizedWholeRead proves the bounded exact-object
// path: a canonical address can select a readable historical version, Unicode
// matches keep their byte offsets, pagination is explicit, and no workspace
// inventory call is made.
func TestMCPGrepAddressUsesOneAuthorizedWholeRead(t *testing.T) {
	service, object := grepInventoryService(t)
	object.Fragment.SourceVersionID = "version_history"
	object.Fragment.ObjectType = "FILE"
	object.Fragment.Text = []byte("α alpha β alpha")
	object.Text = object.Fragment.Text
	object.Fragments[0].Length = len(object.Text)
	object.Fragment.EvidenceTextHash = mcpEvidenceReadTextHash(object.Text)
	service.objects[object.Fragment.FragmentID] = object
	harness := grepInventoryHarness(t, service)
	canonical := mcpGrepCanonicalAddressKeyed(nil, object, "")

	first := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, canonical)+`,"limit":1}`)
	if first.Error != nil {
		t.Fatalf("address grep denied unexpectedly: %#v", first.Error)
	}
	if service.listCall != "" {
		t.Fatalf("address grep performed inventory scan: %q", service.listCall)
	}
	if len(service.objectCalls) != 1 || service.objectCalls[0] != object.Fragment.FragmentID {
		t.Fatalf("address grep whole-object calls=%#v", service.objectCalls)
	}
	if len(first.Result.Structured.Matches) != 1 || !first.Result.Structured.HasMore || first.Result.Structured.NextOffset == nil || *first.Result.Structured.NextOffset != 1 {
		t.Fatalf("address grep first page=%#v", first.Result.Structured)
	}
	if got := first.Result.Structured.Matches[0]["offset"]; got != float64(3) {
		t.Fatalf("Unicode match byte offset=%v want 3", got)
	}

	service.objectCalls = nil
	second := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, canonical)+`,"offset":1,"limit":1}`)
	if second.Error != nil || len(second.Result.Structured.Matches) != 1 || second.Result.Structured.HasMore {
		t.Fatalf("address grep second page error=%#v page=%#v", second.Error, second.Result.Structured)
	}
	if got := second.Result.Structured.Matches[0]["offset"]; got != float64(12) {
		t.Fatalf("second Unicode match byte offset=%v want 12", got)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 {
		t.Fatalf("second address page calls list=%q objects=%#v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepAddressRejectsBroadeningAndTampering proves an exact selector
// cannot be combined with workspace-wide version switches, and a changed span
// digest fails after the one authorized read without leaking matches.
func TestMCPGrepAddressRejectsBroadeningAndTampering(t *testing.T) {
	service, object := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)
	canonical := mcpGrepCanonicalAddressKeyed(nil, object, "")
	for name, suffix := range map[string]string{
		"all_versions": `,"all_versions":true`,
		"ref":          `,"ref":"deadbeef"`,
	} {
		name, suffix := name, suffix
		t.Run(name, func(t *testing.T) {
			service.listCall = ""
			service.objectCalls = nil
			envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, canonical)+suffix+`}`)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602, got %#v", envelope.Error)
			}
			if service.listCall != "" || len(service.objectCalls) != 0 {
				t.Fatalf("broadening selector touched evidence list=%q objects=%#v", service.listCall, service.objectCalls)
			}
		})
	}

	tampered := object
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	parsed.SpanHash = strings.Repeat("0", 16)
	service.listCall = ""
	service.objectCalls = nil
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, parsed.String())+`}`)
	if envelope.Error == nil || envelope.Error.Code != -32005 {
		t.Fatalf("expected span mismatch -32005, got %#v", envelope.Error)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 || service.objectCalls[0] != tampered.Fragment.FragmentID {
		t.Fatalf("tampered selector calls list=%q objects=%#v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepAddressAcceptsFragmentAddressFromKnowledgeTools proves a standard
// search/read fragment address is accepted as an exact object selector in
// addition to the whole-object address emitted by grep.
func TestMCPGrepAddressAcceptsFragmentAddressFromKnowledgeTools(t *testing.T) {
	service, object := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)
	fragmentAddress, err := mcpCanonicalEvidenceAddress(object.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, fragmentAddress.String())+`}`)
	if envelope.Error != nil || len(envelope.Result.Structured.Matches) != 2 {
		t.Fatalf("fragment-address grep error=%#v matches=%#v", envelope.Error, envelope.Result.Structured.Matches)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 {
		t.Fatalf("fragment-address grep performed inventory scan: list=%q objects=%#v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepAddressRejectsWrongIdentityAndUnavailableVersion proves a
// canonical envelope cannot retarget a readable fragment to another source or
// version, and a whole-object reader denial remains the content-free not-found.
func TestMCPGrepAddressRejectsWrongIdentityAndUnavailableVersion(t *testing.T) {
	for name, mutate := range map[string]func(*address.Address){
		"wrong_source":  func(parsed *address.Address) { parsed.Source = "object_other" },
		"wrong_version": func(parsed *address.Address) { parsed.Version = "version_stale" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			service, object := grepInventoryService(t)
			harness := grepInventoryHarness(t, service)
			parsed, err := address.Parse(mcpGrepCanonicalAddressKeyed(nil, object, ""))
			if err != nil {
				t.Fatal(err)
			}
			mutate(&parsed)
			envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, parsed.String())+`}`)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("wrong identity error=%#v, want -32602", envelope.Error)
			}
			if service.listCall != "" || len(service.objectCalls) != 1 {
				t.Fatalf("identity rejection calls list=%q objects=%#v", service.listCall, service.objectCalls)
			}
		})
	}

	service, object := grepInventoryService(t)
	service.objectErr = evidence.ErrNotFound
	harness := grepInventoryHarness(t, service)
	canonical := mcpGrepCanonicalAddressKeyed(nil, object, "")
	envelope := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"alpha","address":`+jsonString(t, canonical)+`}`)
	if envelope.Error == nil || envelope.Error.Code != -32004 || len(envelope.Result.Structured.Matches) != 0 {
		t.Fatalf("unavailable exact version was not content-free: %#v", envelope)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 {
		t.Fatalf("unavailable exact version calls list=%q objects=%#v", service.listCall, service.objectCalls)
	}
}

// TestMCPGrepDeepAddressCanReadMatchInOneDirectPage proves an exact grep hit
// beyond the initial fragment-sized read window can be read at its returned
// byte offset in one ordinary knowvault_read call. The caller does not need to
// guess a cursor or page through the beginning of the large object first.
func TestMCPGrepDeepAddressCanReadMatchInOneDirectPage(t *testing.T) {
	service, base := grepInventoryService(t)
	anchor := base.Fragment
	anchor.Text = []byte(strings.Repeat("\u043f", 1500))
	anchor.EvidenceTextHash = mcpEvidenceReadTextHash(anchor.Text)
	prefix := []byte(strings.Repeat("\u043f", 2500))
	whole := append(append([]byte(nil), prefix...), []byte(" target-\u043a\u043b\u044e\u0447 \u043a\u043e\u043d\u0435\u0446")...)
	anchor.Ordinal = 1
	object := evidence.WholeObject{
		Fragment:      anchor,
		Text:          whole,
		FragmentCount: 2,
		FirstOrdinal:  1,
		LastOrdinal:   2,
		Fragments: []evidence.ObjectFragmentSpan{
			{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len(anchor.Text)},
			{FragmentID: "fragment_tail", Ordinal: 2, Offset: len(anchor.Text), Length: len(whole) - len(anchor.Text)},
		},
	}
	service.objects = map[string]evidence.WholeObject{anchor.FragmentID: object}
	harness := grepInventoryHarness(t, service)
	selector := mcpGrepCanonicalAddressKeyed(nil, object, "")
	grep := callMCPGrep(t, harness, "{\"workspace_id\":\"ws_alpha\",\"pattern\":\"\u043a\u043b\u044e\u0447\",\"address\":"+jsonString(t, selector)+`}`)
	if grep.Error != nil || len(grep.Result.Structured.Matches) != 1 {
		t.Fatalf("deep address grep error=%#v matches=%#v", grep.Error, grep.Result.Structured.Matches)
	}
	if len(grep.Result.Content) == 0 || !strings.Contains(grep.Result.Content[0]["text"].(string), "read_hint=knowvault_read(address=canonical_address,offset=offset,limit=4096); omit cursor") {
		t.Fatalf("grep text channel omitted direct-read guidance: %#v", grep.Result.Content)
	}
	match := grep.Result.Structured.Matches[0]
	matchOffset, ok := match["offset"].(float64)
	if !ok || int(matchOffset) != len(prefix)+len([]byte(" target-")) {
		t.Fatalf("deep match offset=%#v want %d", match["offset"], len(prefix)+len([]byte(" target-")))
	}
	returnedAddress, ok := match["canonical_address"].(string)
	if !ok || returnedAddress == "" {
		t.Fatalf("deep grep match has no canonical address: %#v", match)
	}
	service.objectCalls = nil
	read := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{
		"workspace_id": "ws_alpha", "address": returnedAddress,
		"offset": int64(matchOffset), "limit": 64,
	}))
	if read.Error != nil {
		t.Fatalf("direct read of deep match refused: %#v", read.Error)
	}
	if got := read.Result.Structured["text"]; !strings.Contains(got.(string), "\u043a\u043b\u044e\u0447") {
		t.Fatalf("direct read page does not contain matched text: %q", got)
	}
	if got := read.Result.Structured["offset"]; got != matchOffset {
		t.Fatalf("direct read page offset=%#v want %v", got, matchOffset)
	}
	if service.listCall != "" || len(service.objectCalls) != 1 || service.objectCalls[0] != anchor.FragmentID {
		t.Fatalf("deep direct read calls inventory=%q objectReads=%#v", service.listCall, service.objectCalls)
	}
}
