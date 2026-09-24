package workspaceapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const evidenceFragmentID = "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"

// TestMCPToolsListAdvertisesEvidenceGetTool proves the evidence read tool is
// advertised next to the existing question/conversation tools with an
// inputSchema bounded to exactly the two string fields workspace_id and
// fragment_id. Before this slice, tools/list exposed no evidence surface and
// any evidence call answered -32602.
func TestMCPToolsListAdvertisesEvidenceGetTool(t *testing.T) {
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
	var evidenceTool map[string]any
	for _, tool := range list.Result.Tools {
		switch tool.Name {
		case "knowvault_question", "knowvault_conversations_list", "knowvault_conversation_get", "knowvault_conversation_archive",
			"knowvault_confirmation_grant_issue", "knowvault_confirmation_grant_revoke", "knowvault_managed_source_confirm", "knowvault_managed_confirmation_revoke",
			"knowvault_verify_connection_trust", "knowvault_source_enable", "knowvault_source_sync", "knowvault_governed_query_ask",
			"knowvault_metric_definitions_list", "knowvault_metric_definition_get", mcpToolSourcesList, mcpToolEvidenceRead, mcpToolWorkspaceList, mcpToolRefresh, mcpToolWorkspaceContext, mcpToolSourceSchema, mcpToolSourceSQL:
			// existing, ADR-0087 §1 confirmation tools, the ADR-0087 §2
			// verify-trust tool, the ADR-0087 §3 enable/sync tools, the
			// ADR-0089 governed-query ask tool and the R2 Outcome 1
			// read-only metric-definition tools remain advertised (backward
			// compatible surface)
		case "knowvault_evidence_get":
			evidenceTool = tool.InputSchema
		default:
			t.Fatalf("unexpected tool advertised: %q", tool.Name)
		}
	}
	if evidenceTool == nil {
		t.Fatalf("tools/list omitted knowvault_evidence_get: %s", response.Body.String())
	}
	if required, ok := evidenceTool["required"].([]any); !ok || len(required) != 2 {
		t.Fatalf("evidence inputSchema required=%#v", evidenceTool["required"])
	} else {
		for _, want := range []string{"workspace_id", "fragment_id"} {
			found := false
			for _, r := range required {
				if r == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("evidence inputSchema missing required %q: %#v", want, evidenceTool)
			}
		}
	}
	properties, ok := evidenceTool["properties"].(map[string]any)
	if !ok || len(properties) != 2 {
		t.Fatalf("evidence inputSchema properties=%#v", evidenceTool["properties"])
	}
	for _, bound := range []string{"workspace_id", "fragment_id"} {
		spec, ok := properties[bound].(map[string]any)
		if !ok || spec["type"] != "string" {
			t.Fatalf("evidence inputSchema field %q spec=%#v", bound, properties[bound])
		}
	}
}

type mcpErrorBody struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// TestMCPEvidenceGetMatchesRESTEvidenceGetProjection proves an authorized MCP
// evidence read resolves through the same handler.evidence viewer as the REST
// evidenceGet route (harness.evidence.Read with the authenticated access
// context) and discloses exactly the same Fragment projection the REST route
// returns. Because the viewer is the single place that appends the
// citation.opened journal event, routing both surfaces through
// handler.evidence.Read is what makes the MCP read emit the identical audit
// journal entry as a REST read.
func TestMCPEvidenceGetMatchesRESTEvidenceGetProjection(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.result = testEvidenceFragment(t)
	harness.evidence.result.SourcePath = "inbox/\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b/\u0423\u0441\u043b\u043e\u0432\u0438\u044f \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u043d\u0438\u044f.md"
	harness.questions.rowset = &question.RowsetEvidence{
		Columns:     []string{"route_id", "tonnes"},
		Rows:        []map[string]string{{"route_id": "route-1", "tonnes": "10.000"}},
		Total:       1,
		FilterLabel: "route_id = route-1",
		// Snapshot.RowCount is the full source size; the matched rowset may be smaller.
		Snapshot: question.AnswerSnapshot{ID: "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ", RowCount: 2},
	}

	restResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(restResponse, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+evidenceFragmentID, ""))
	if restResponse.Code != http.StatusOK || harness.evidence.call != "read" {
		t.Fatalf("REST evidenceGet status=%d call=%q body=%s", restResponse.Code, harness.evidence.call, restResponse.Body.String())
	}

	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ev1","method":"tools/call","params":{"name":"knowvault_evidence_get","arguments":{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`"}}}`))
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP evidence status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	if harness.evidence.call != "read" {
		t.Fatalf("MCP evidence did not dispatch through handler.evidence viewer: call=%q", harness.evidence.call)
	}
	if harness.evidence.workspaceID != "ws_alpha" || harness.evidence.fragmentID != evidenceFragmentID {
		t.Fatalf("viewer received workspace=%q fragment=%q", harness.evidence.workspaceID, harness.evidence.fragmentID)
	}
	if harness.evidence.access.RequestID != "req_server_001" {
		t.Fatalf("viewer did not receive the authenticated access context the audit event names: %#v", harness.evidence.access)
	}

	restProjection := decodeJSONObject(t, restResponse.Body.String())
	mcpStructured := decodeMCPResultStructured(t, mcpResponse.Body.String())
	if !reflect.DeepEqual(restProjection, mcpStructured) {
		t.Fatalf("MCP evidence projection != REST evidenceGet projection\nREST: %#v\nMCP:  %#v", restProjection, mcpStructured)
	}
	if restProjection["source_path"] != harness.evidence.result.SourcePath {
		t.Fatalf("evidence omitted the viewer-authorized source path: %#v", restProjection)
	}
	if len(harness.questions.rowsetCalls) != 2 {
		t.Fatalf("StructuredRowset calls=%d, want REST and MCP calls", len(harness.questions.rowsetCalls))
	}
	for _, call := range harness.questions.rowsetCalls {
		if call.workspaceID != "ws_alpha" || call.fragmentID != evidenceFragmentID || call.scope != "" {
			t.Fatalf("rowset call=%#v, want authorized matched default", call)
		}
		if call.access.RequestID != "req_server_001" || call.access.OrganizationID != "org_alpha" || call.access.PrincipalID != "usr_alice" {
			t.Fatalf("rowset access=%#v, want authenticated access", call.access)
		}
	}
	if !strings.Contains(mcpResponse.Body.String(), `"fragment_id":"`+evidenceFragmentID+`"`) {
		t.Fatalf("MCP evidence projection missing fragment id: %s", mcpResponse.Body.String())
	}
}

// TestMCPEvidenceGetAndRESTOmitUnavailableRowsetEqually preserves the
// existing fail-safe behavior: a rowset service error does not turn an
// authorized text-fragment read into a transport error, and both adapters
// omit the unavailable optional rowset identically.
func TestMCPEvidenceGetAndRESTOmitUnavailableRowsetEqually(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.result = testEvidenceFragment(t)
	harness.questions.rowsetErr = errors.New("structured rowset unavailable")

	restResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(restResponse, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+evidenceFragmentID, ""))
	if restResponse.Code != http.StatusOK {
		t.Fatalf("REST status=%d body=%s", restResponse.Code, restResponse.Body.String())
	}
	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ev-error","method":"tools/call","params":{"name":"knowvault_evidence_get","arguments":{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`"}}}`))
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP status=%d body=%s", mcpResponse.Code, mcpResponse.Body.String())
	}
	restProjection := decodeJSONObject(t, restResponse.Body.String())
	mcpStructured := decodeMCPResultStructured(t, mcpResponse.Body.String())
	if !reflect.DeepEqual(restProjection, mcpStructured) {
		t.Fatalf("unavailable rowset changed adapter parity\nREST: %#v\nMCP:  %#v", restProjection, mcpStructured)
	}
	if _, ok := restProjection["rowset"]; ok {
		t.Fatalf("REST exposed rowset after StructuredRowset error: %#v", restProjection)
	}
}

// TestMCPEvidenceGetDeniesUnknownFragmentIndistinguishably proves the MCP read
// shows the same fail-closed no-oracle denial as the REST route: an unknown
// fragment dispatches through handler.evidence.Read (whose every denial is one
// ErrNotFound) and the surface answers one content-free not-found that never
// echoes the fragment id. Denials never reach the viewer's citation.opened
// emission, so the MCP surface fabricates no opened audit event either.
func TestMCPEvidenceGetDeniesUnknownFragmentIndistinguishably(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.err = evidence.ErrNotFound

	restResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(restResponse, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/unknown_frag", ""))
	if restResponse.Code != http.StatusNotFound || harness.evidence.call != "read" {
		t.Fatalf("REST deny status=%d call=%q body=%s", restResponse.Code, harness.evidence.call, restResponse.Body.String())
	}
	if strings.Contains(restResponse.Body.String(), "unknown_frag") {
		t.Fatalf("REST denial echoed fragment id: %s", restResponse.Body.String())
	}

	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ev2","method":"tools/call","params":{"name":"knowvault_evidence_get","arguments":{"workspace_id":"ws_alpha","fragment_id":"unknown_frag"}}}`))
	if mcpResponse.Code != http.StatusOK || harness.evidence.call != "read" {
		t.Fatalf("MCP deny status=%d call=%q body=%s", mcpResponse.Code, harness.evidence.call, mcpResponse.Body.String())
	}
	var envelope struct {
		Result map[string]any `json:"result"`
		Error  *mcpErrorBody  `json:"error"`
	}
	if err := json.Unmarshal([]byte(mcpResponse.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP deny did not decode: %v", err)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "evidence not found" {
		t.Fatalf("MCP deny not indistinguishable not-found: %s", mcpResponse.Body.String())
	}
	if envelope.Result != nil || strings.Contains(mcpResponse.Body.String(), "unknown_frag") || strings.Contains(mcpResponse.Body.String(), "structuredContent") {
		t.Fatalf("MCP denial leaked an existence oracle or fragment id: %s", mcpResponse.Body.String())
	}
}

// TestMCPEvidenceGetRejectsUnboundedArguments proves the tool honors its closed
// two-field schema: a missing field, an empty workspace or an unknown member is
// rejected at the transport boundary and never reaches the evidence viewer, so
// the MCP surface cannot be used to probe the authority with extra arguments.
func TestMCPEvidenceGetRejectsUnboundedArguments(t *testing.T) {
	for name, args := range map[string]string{
		"missing_fragment_id":  `{"workspace_id":"ws_alpha"}`,
		"missing_workspace_id": `{"fragment_id":"frag_x"}`,
		"empty_fragment_id":    `{"workspace_id":"ws_alpha","fragment_id":""}`,
		"unknown_member":       `{"workspace_id":"ws_alpha","fragment_id":"frag_x","extra":true}`,
	} {
		name, args := name, args
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
				`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"knowvault_evidence_get","arguments":`+args+`}}`))
			if response.Code != http.StatusOK {
				t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
			}
			if harness.evidence.call != "" {
				t.Fatalf("unbounded evidence arguments reached the viewer: call=%q", harness.evidence.call)
			}
			if !strings.Contains(response.Body.String(), `"code":-32602`) {
				t.Fatalf("expected -32602 invalid-arguments, got: %s", response.Body.String())
			}
		})
	}
}

// --- R3a-1 Outcome 1: knowvault_read (paged address read) ---

type mcpReadEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured map[string]any   `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

// mcpEvidenceRead calls the paged read through the retained compatibility name
// (mcpToolEvidenceReadCompat), so every pagination/address assertion below also
// proves the former name still dispatches to the canonical read core.
func mcpEvidenceRead(t *testing.T, harness *testHarness, arguments string) mcpReadEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"rd","method":"tools/call","params":{"name":"`+mcpToolEvidenceReadCompat+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP evidence read status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpReadEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP evidence read did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// mcpEvidenceReadByName issues a paged read under an explicit tool name.
func mcpEvidenceReadByName(t *testing.T, harness *testHarness, name, arguments string) mcpReadEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"rd","method":"tools/call","params":{"name":"`+name+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP evidence read (%s) status=%d body=%s", name, response.Code, response.Body.String())
	}
	var envelope mcpReadEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP evidence read (%s) did not decode: %v: %s", name, err, response.Body.String())
	}
	return envelope
}

func mcpEvidenceReadTextHash(text []byte) string {
	sum := sha256.Sum256(text)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TestMCPEvidenceReadAdvertisesClosedPagedSchema proves tools/list advertises
// knowvault_read with the closed paged schema: exactly the two
// required selectors plus the optional offset/limit/expected_span_hash members,
// and no further member (additionalProperties:false); the compatibility name is
// not advertised.
func TestMCPEvidenceReadAdvertisesClosedPagedSchema(t *testing.T) {
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
		switch tool.Name {
		case mcpToolEvidenceRead:
			schema = tool.InputSchema
		case mcpToolEvidenceReadCompat:
			t.Fatalf("tools/list advertised the compatibility name %q", tool.Name)
		}
	}
	if schema == nil {
		t.Fatalf("tools/list omitted %s: %s", mcpToolEvidenceRead, response.Body.String())
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("evidence read inputSchema additionalProperties=%#v", schema["additionalProperties"])
	}
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 1 {
		t.Fatalf("evidence read inputSchema required=%#v", schema["required"])
	}
	for _, want := range []string{"workspace_id"} {
		found := false
		for _, r := range required {
			if r == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("evidence read inputSchema missing required %q: %#v", want, required)
		}
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok || len(properties) != 8 {
		t.Fatalf("evidence read inputSchema properties=%#v", schema["properties"])
	}
	for _, bound := range []string{"workspace_id", "fragment_id", "address", "cursor", "offset", "limit", "expected_span_hash", "include_text_base64"} {
		if _, ok := properties[bound].(map[string]any); !ok {
			t.Fatalf("evidence read inputSchema missing property %q: %#v", bound, properties)
		}
	}
	selectors, ok := schema["anyOf"].([]any)
	if !ok || len(selectors) != 2 {
		t.Fatal("read must accept address or fragment_id")
	}
	for i, name := range []string{"address", "fragment_id"} {
		rule := selectors[i].(map[string]any)["required"].([]any)
		if len(rule) != 1 || rule[0] != name {
			t.Fatalf("wrong read selector requirement: %v", rule)
		}
	}
}

// TestMCPEvidenceReadCanonicalAndCompatibilityNamesShareCore proves the
// canonical name knowvault_read and the retained compatibility name
// knowvault_evidence_read both dispatch to the byte-identical read core and
// return the same page projection and pagination. KV-A02d.
func TestMCPEvidenceReadCanonicalAndCompatibilityNamesShareCore(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.result = testEvidenceFragment(t)
	arguments := `{"workspace_id":"ws_alpha","fragment_id":"` + evidenceFragmentID + `","offset":0,"limit":4096}`

	canonical := mcpEvidenceReadByName(t, harness, mcpToolEvidenceRead, arguments)
	compatible := mcpEvidenceReadByName(t, harness, mcpToolEvidenceReadCompat, arguments)
	if canonical.Error != nil || compatible.Error != nil {
		t.Fatalf("read refused: canonical=%#v compatible=%#v", canonical.Error, compatible.Error)
	}
	canonicalJSON, err := json.Marshal(canonical.Result.Structured)
	if err != nil {
		t.Fatalf("marshal canonical page: %v", err)
	}
	compatibleJSON, err := json.Marshal(compatible.Result.Structured)
	if err != nil {
		t.Fatalf("marshal compatibility page: %v", err)
	}
	if string(canonicalJSON) != string(compatibleJSON) {
		t.Fatalf("canonical and compatibility pages differ:\ncanonical=%s\ncompatible=%s", canonicalJSON, compatibleJSON)
	}
}

// TestMCPEvidenceReadPagesReassembleToOriginalHash proves the page contract of
// Outcome 1: every page is an explicit window with offset/length/next_offset/
// has_more, no page splits a UTF-8 rune, concatenating every page's exact bytes
// reproduces the stored canonical text, and the whole-fragment text_hash names
// that original. It also proves the address names source, version, object and
// the exact span.
func TestMCPEvidenceReadPagesReassembleToOriginalHash(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte(strings.Repeat("\u043d\u043e\u0440\u043c\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u043d\u044b\u0439 \u0442\u0435\u043a\u0441\u0442 ", 10))
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	var assembled []byte
	offset := 0
	pages := 0
	for {
		envelope := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","offset":`+strconv.Itoa(offset)+`,"limit":7,"include_text_base64":true}`)
		if envelope.Error != nil {
			t.Fatalf("page at offset %d refused: %#v", offset, envelope.Error)
		}
		structured := envelope.Result.Structured
		if got := structured["offset"]; got != float64(offset) {
			t.Fatalf("page offset=%#v want %d (schema must echo the effective window)", got, offset)
		}
		encoded, ok := structured["text_base64"].(string)
		if !ok {
			t.Fatalf("page missing text_base64: %#v", structured)
		}
		page, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("page text_base64 did not decode: %v", err)
		}
		assembled = append(assembled, page...)
		pages++
		hasMore, _ := structured["has_more"].(bool)
		if !hasMore {
			if structured["next_offset"] != nil {
				t.Fatalf("final page offered a next_offset: %#v", structured)
			}
			break
		}
		next, ok := structured["next_offset"].(float64)
		if !ok || int(next) <= offset {
			t.Fatalf("non-progressing next_offset=%#v at offset=%d", structured["next_offset"], offset)
		}
		offset = int(next)
		if pages > len(fragment.Text) {
			t.Fatalf("pagination did not terminate after %d pages", pages)
		}
	}
	if pages < 2 {
		t.Fatalf("expected a multi-page read, got %d page(s)", pages)
	}
	if string(assembled) != string(fragment.Text) {
		t.Fatalf("reassembled %d bytes != original %d bytes", len(assembled), len(fragment.Text))
	}
	if !utf8.Valid(assembled) {
		t.Fatalf("reassembled pages are not valid UTF-8")
	}

	envelope := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`"}`)
	structured := envelope.Result.Structured
	if structured["text_hash"] != fragment.EvidenceTextHash {
		t.Fatalf("text_hash=%#v want %q", structured["text_hash"], fragment.EvidenceTextHash)
	}
	if structured["total_length"] != float64(len(fragment.Text)) {
		t.Fatalf("total_length=%#v want %d", structured["total_length"], len(fragment.Text))
	}
	if envelope.Result.Content == nil || len(envelope.Result.Content) != 1 {
		t.Fatalf("single authorized page did not return the whole text content: %#v", envelope.Result.Content)
	}
	if pageText, _ := mcpReadTextPage(t, envelope.Result.Content); pageText != string(fragment.Text) {
		t.Fatalf("single authorized page did not return the whole page text: %#v", envelope.Result.Content)
	}
	address, ok := structured["address"].(map[string]any)
	if !ok {
		t.Fatalf("read result missing address: %#v", structured)
	}
	source, _ := address["source"].(map[string]any)
	version, _ := address["version"].(map[string]any)
	object, _ := address["object"].(map[string]any)
	span, _ := address["span"].(map[string]any)
	if source["source_object_id"] != fragment.SourceObjectID || source["connection_id"] != fragment.ConnectionID {
		t.Fatalf("address source=%#v", source)
	}
	if version["source_version_id"] != fragment.SourceVersionID || version["external_version_key"] != fragment.ExternalVersionKey ||
		version["content_hash"] != fragment.ContentHash || version["observed_at"] != "2026-08-13T10:00:00Z" {
		t.Fatalf("address version=%#v", version)
	}
	if object["extraction_id"] != fragment.ExtractionID || object["ordinal"] != float64(fragment.Ordinal) || object["fragment_id"] != fragment.FragmentID {
		t.Fatalf("address object=%#v", object)
	}
	if span["offset"] != float64(0) || span["length"] != float64(len(fragment.Text)) || span["total_length"] != float64(len(fragment.Text)) ||
		span["text_hash"] != fragment.EvidenceTextHash {
		t.Fatalf("address span=%#v", span)
	}
}

// TestMCPEvidenceReadDefaultLimitNeverTruncatesSilently proves a fragment
// longer than one default page is not silently truncated: the default page
// reports has_more and a next_offset, and continuing from it reaches the end.
func TestMCPEvidenceReadDefaultLimitNeverTruncatesSilently(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte(strings.Repeat("abcdefghij", 1000)) // 10000 bytes
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	first := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`"}`)
	if first.Error != nil {
		t.Fatalf("default page refused: %#v", first.Error)
	}
	structured := first.Result.Structured
	if hasMore, _ := structured["has_more"].(bool); !hasMore {
		t.Fatalf("default page silently returned a truncated fragment: %#v", structured)
	}
	next, ok := structured["next_offset"].(float64)
	if !ok || next <= 0 {
		t.Fatalf("default page did not offer next_offset: %#v", structured)
	}
	if structured["limit"] != float64(mcpEvidenceReadDefaultLimit) {
		t.Fatalf("default page limit=%#v want %d", structured["limit"], mcpEvidenceReadDefaultLimit)
	}
	second := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","offset":`+strconv.Itoa(int(next))+`,"limit":10000,"include_text_base64":true}`)
	if second.Error != nil {
		t.Fatalf("second page refused: %#v", second.Error)
	}
	if hasMore, _ := second.Result.Structured["has_more"].(bool); hasMore {
		t.Fatalf("a limit past the end still reports has_more: %#v", second.Result.Structured)
	}
	page2, _ := second.Result.Structured["text_base64"].(string)
	decoded, err := base64.StdEncoding.DecodeString(page2)
	if err != nil {
		t.Fatalf("second page did not decode: %v", err)
	}
	offset := int(structured["length"].(float64))
	if string(decoded) != string(fragment.Text[offset:]) {
		t.Fatalf("second page is not the remaining original text")
	}
}

// TestMCPEvidenceReadRefusesSpanHashMismatch proves the tamper control: a
// caller-supplied expected_span_hash that differs from the stored fragment hash
// is refused with the typed, content-free -32005, returning no page text and no
// address metadata.
func TestMCPEvidenceReadRefusesSpanHashMismatch(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	fragment.Text = []byte("canonical text")
	fragment.EvidenceTextHash = mcpEvidenceReadTextHash(fragment.Text)
	harness.evidence.result = fragment

	envelope := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","expected_span_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}`)
	if harness.evidence.call != "read" {
		t.Fatalf("mismatch check did not resolve through the authorized viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32005 || envelope.Error.Message != "evidence span hash mismatch" {
		t.Fatalf("mismatch not refused with a typed error: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("mismatch leaked content or address: %#v", envelope.Result)
	}
	if strings.Contains(envelope.Error.Message, "canonical") {
		t.Fatalf("mismatch error leaked content: %#v", envelope.Error)
	}

	matching := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_alpha","fragment_id":"`+evidenceFragmentID+`","expected_span_hash":"`+fragment.EvidenceTextHash+`"}`)
	if matching.Error != nil || matching.Result.Structured["text"] != "canonical text" {
		t.Fatalf("matching span hash was not served: %#v / %#v", matching.Error, matching.Result.Structured)
	}
}

// TestMCPEvidenceReadDenialIsContentFree proves the paged read reuses the
// viewer's single no-oracle denial: a denied/cross-workspace fragment yields
// the existing -32004 with no text, no address and no workspace echo.
func TestMCPEvidenceReadDenialIsContentFree(t *testing.T) {
	harness := newTestHarness(t)
	harness.evidence.err = evidence.ErrNotFound

	envelope := mcpEvidenceRead(t, harness, `{"workspace_id":"ws_other","fragment_id":"fragment_secret"}`)
	if harness.evidence.call != "read" {
		t.Fatalf("denial did not dispatch through the authorized viewer: call=%q", harness.evidence.call)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "evidence not found" {
		t.Fatalf("denial not the content-free not-found: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("denial leaked content or address: %#v", envelope.Result)
	}
}

// TestMCPEvidenceReadRejectsUnboundedArguments proves the closed schema and the
// range validation are enforced before any evidence read: a missing selector, a
// negative or wrong-typed offset/limit and an unknown member all answer -32602
// without touching the viewer.
func TestMCPEvidenceReadRejectsUnboundedArguments(t *testing.T) {
	for name, args := range map[string]string{
		"missing_fragment_id":  `{"workspace_id":"ws_alpha"}`,
		"missing_workspace_id": `{"fragment_id":"frag_x"}`,
		"empty_fragment_id":    `{"workspace_id":"ws_alpha","fragment_id":""}`,
		"negative_offset":      `{"workspace_id":"ws_alpha","fragment_id":"frag_x","offset":-1}`,
		"negative_limit":       `{"workspace_id":"ws_alpha","fragment_id":"frag_x","limit":-1}`,
		"wrong_typed_offset":   `{"workspace_id":"ws_alpha","fragment_id":"frag_x","offset":"0"}`,
		"unknown_member":       `{"workspace_id":"ws_alpha","fragment_id":"frag_x","extra":true}`,
	} {
		name, args := name, args
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			envelope := mcpEvidenceRead(t, harness, args)
			if harness.evidence.call != "" {
				t.Fatalf("unbounded evidence read reached the viewer: call=%q", harness.evidence.call)
			}
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602 invalid-arguments, got: %#v", envelope.Error)
			}
		})
	}
}

func decodeJSONObject(t *testing.T, body string) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal([]byte(body), &object); err != nil {
		t.Fatalf("body did not decode as an object: %v: %s", err, body)
	}
	return object
}

func decodeMCPResultStructured(t *testing.T, body string) map[string]any {
	t.Helper()
	var envelope struct {
		Result struct {
			Structured map[string]any `json:"structuredContent"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil || envelope.Error != nil {
		t.Fatalf("MCP result did not decode: err=%v error=%#v body=%s", err, envelope.Error, body)
	}
	if envelope.Result.Structured == nil {
		t.Fatalf("MCP result missing structuredContent: %s", body)
	}
	return envelope.Result.Structured
}

// --- R3a-1 Outcome 2 (KV-A02): knowvault_workspace_list (workspace object inventory) ---

// fakeInventoryEvidence is the fakeEvidenceService plus the additive optional
// inventory capability. Embedding keeps the existing Read harness behavior and
// records, so a test can prove the list tool composes the same authorized
// evidence service without touching the shared fake.
type fakeInventoryEvidence struct {
	*fakeEvidenceService
	items       []evidence.ObjectInventoryItem
	listErr     error
	listCall    string
	allVersions bool
	offset      int64
	limit       int64
}

func (service *fakeInventoryEvidence) ListObjects(_ context.Context, _ database.AccessContext, workspaceID string, allVersions bool, offset, limit int64) (evidence.ObjectInventoryPage, error) {
	service.listCall = "list"
	service.workspaceID = workspaceID
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

func workspaceListHarness(t *testing.T, service *fakeInventoryEvidence) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	service.fakeEvidenceService = harness.evidence
	harness.handler.evidence = service
	return harness
}

func testInventoryItems() []evidence.ObjectInventoryItem {
	moment := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	return []evidence.ObjectInventoryItem{
		{
			SourceObjectID: "object_01", ObjectType: "FILE", ConnectionID: "conn_01", LifecycleState: "ACTIVE",
			SourceVersionID: "version_01", ExternalVersionKey: "native:doc-a", ContentHash: strings.Repeat("ab", 32),
			ObservedAt: moment, VersionState: "CURRENT", Current: true,
			FragmentCount: 3, FirstFragmentID: "fragment_01", FirstOrdinal: 1, LastOrdinal: 3,
		},
		{
			SourceObjectID: "object_02", ObjectType: "FILE", ConnectionID: "conn_01", LifecycleState: "ACTIVE",
			SourceVersionID: "version_02", ExternalVersionKey: "native:doc-b", ContentHash: strings.Repeat("cd", 32),
			ObservedAt: moment, VersionState: "CURRENT", Current: true,
			FragmentCount: 1, FirstFragmentID: "fragment_02", FirstOrdinal: 1, LastOrdinal: 1,
		},
	}
}

type mcpWorkspaceListEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured map[string]any   `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPWorkspaceList(t *testing.T, harness *testHarness, arguments string) mcpWorkspaceListEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"wl","method":"tools/call","params":{"name":"`+mcpToolWorkspaceList+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP workspace list status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpWorkspaceListEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP workspace list did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// TestMCPWorkspaceListAdvertisesClosedInventorySchema proves tools/list
// advertises the new workspace-inventory tool with the closed schema:
// workspace_id required, optional all_versions/offset/limit, and no further
// member (additionalProperties:false).
func TestMCPWorkspaceListAdvertisesClosedInventorySchema(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
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
		if tool.Name == mcpToolWorkspaceList {
			schema = tool.InputSchema
		}
	}
	if schema == nil {
		t.Fatalf("tools/list omitted %s: %s", mcpToolWorkspaceList, response.Body.String())
	}
	if additional, ok := schema["additionalProperties"].(bool); !ok || additional {
		t.Fatalf("workspace list inputSchema additionalProperties=%#v", schema["additionalProperties"])
	}
	required, ok := schema["required"].([]any)
	if !ok || len(required) != 1 || required[0] != "workspace_id" {
		t.Fatalf("workspace list inputSchema required=%#v", schema["required"])
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("workspace list inputSchema properties=%#v", schema["properties"])
	}
	for _, bound := range []string{"workspace_id", "all_versions", "offset", "limit"} {
		if _, ok := properties[bound].(map[string]any); !ok {
			t.Fatalf("workspace list inputSchema missing property %q: %#v", bound, properties)
		}
	}
}

// TestMCPWorkspaceListPagesReassembleCompleteInventory proves the pagination
// contract: the response carries offset/limit/has_more/next_offset, a limit is
// echoed as applied, and concatenating every page reproduces the complete
// inventory with no silent truncation.
func TestMCPWorkspaceListPagesReassembleCompleteInventory(t *testing.T) {
	service := &fakeInventoryEvidence{items: testInventoryItems()}
	harness := workspaceListHarness(t, service)

	var assembled []any
	offset := 0
	for pages := 0; ; pages++ {
		envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha","offset":`+strconv.Itoa(offset)+`,"limit":1}`)
		if envelope.Error != nil {
			t.Fatalf("page at offset %d refused: %#v", offset, envelope.Error)
		}
		structured := envelope.Result.Structured
		if structured["offset"] != float64(offset) || structured["limit"] != float64(1) {
			t.Fatalf("page window not echoed: %#v", structured)
		}
		objects, ok := structured["objects"].([]any)
		if !ok {
			t.Fatalf("page missing objects: %#v", structured)
		}
		assembled = append(assembled, objects...)
		hasMore, _ := structured["has_more"].(bool)
		if !hasMore {
			if structured["next_offset"] != nil {
				t.Fatalf("final page offered next_offset: %#v", structured)
			}
			break
		}
		next, ok := structured["next_offset"].(float64)
		if !ok || int(next) <= offset {
			t.Fatalf("non-progressing next_offset=%#v at offset=%d", structured["next_offset"], offset)
		}
		offset = int(next)
		if pages > len(service.items) {
			t.Fatalf("pagination did not terminate")
		}
	}
	if len(assembled) != len(service.items) {
		t.Fatalf("reassembled %d objects != complete inventory %d", len(assembled), len(service.items))
	}
	first, _ := assembled[0].(map[string]any)
	if first["source_object_id"] != "object_01" || first["source_version_id"] != "version_01" ||
		first["external_version_key"] != "native:doc-a" || first["content_hash"] != strings.Repeat("ab", 32) ||
		first["observed_at"] != "2026-08-13T10:00:00Z" || first["current"] != true {
		t.Fatalf("inventory object projection=%#v", first)
	}
	address, ok := first["address"].(map[string]any)
	if !ok {
		t.Fatalf("inventory object missing address: %#v", first)
	}
	source, _ := address["source"].(map[string]any)
	version, _ := address["version"].(map[string]any)
	span, _ := address["span"].(map[string]any)
	if source["source_object_id"] != "object_01" || source["connection_id"] != "conn_01" ||
		version["source_version_id"] != "version_01" || span["ordinal_start"] != float64(1) || span["ordinal_end"] != float64(3) {
		t.Fatalf("inventory address=%#v", address)
	}
}

// TestMCPWorkspaceListCurrentOnlyByDefault proves the default is current
// versions only and all_versions is forwarded when set.
func TestMCPWorkspaceListCurrentOnlyByDefault(t *testing.T) {
	service := &fakeInventoryEvidence{items: testInventoryItems()}
	harness := workspaceListHarness(t, service)

	if envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha"}`); envelope.Error != nil {
		t.Fatalf("default list refused: %#v", envelope.Error)
	}
	if service.allVersions {
		t.Fatalf("default list did not request current versions only")
	}
	if envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_alpha","all_versions":true}`); envelope.Error != nil {
		t.Fatalf("all_versions list refused: %#v", envelope.Error)
	}
	if !service.allVersions {
		t.Fatalf("all_versions was not forwarded to the inventory read")
	}
	if service.limit != mcpWorkspaceListDefaultLimit {
		t.Fatalf("default limit=%d want %d", service.limit, mcpWorkspaceListDefaultLimit)
	}
}

// TestMCPWorkspaceListDenialIsContentFree proves a denied/unknown/non-member
// workspace reuses the viewer's single content-free not-found: -32004 with no
// objects and no workspace echo.
func TestMCPWorkspaceListDenialIsContentFree(t *testing.T) {
	service := &fakeInventoryEvidence{listErr: evidence.ErrNotFound}
	harness := workspaceListHarness(t, service)

	envelope := callMCPWorkspaceList(t, harness, `{"workspace_id":"ws_other"}`)
	if service.listCall != "list" {
		t.Fatalf("denial did not dispatch through the authorized inventory read: call=%q", service.listCall)
	}
	if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "workspace objects not found" {
		t.Fatalf("denial not the content-free not-found: %#v", envelope.Error)
	}
	if envelope.Result.Structured != nil || envelope.Result.Content != nil {
		t.Fatalf("denial leaked content: %#v", envelope.Result)
	}
}

// listObjectsDenialAuditSource wraps fakeInventoryEvidence to record the
// admission-before-data and terminal outcome sequence of the
// knowvault_list_objects negative control. In production that sequence is the
// real evidence viewer's workspace admission followed by its R1 audit journal
// record; in this unit probe it is the injected EvidenceInventory boundary, so
// the tool's delegation to an inventory read that admits, then records a classed
// denial, is observable without a raw row forgery or a second read path.
type listObjectsDenialAuditSource struct {
	*fakeInventoryEvidence
	order []string
}

func (service *listObjectsDenialAuditSource) ListObjects(ctx context.Context, access database.AccessContext, workspaceID string, allVersions bool, offset, limit int64) (evidence.ObjectInventoryPage, error) {
	service.order = append(service.order, "admission")
	page, err := service.fakeInventoryEvidence.ListObjects(ctx, access, workspaceID, allVersions, offset, limit)
	if err != nil {
		service.order = append(service.order, "denied:"+string(workspacerepository.CodeOf(err)))
		return page, err
	}
	service.order = append(service.order, "data")
	return page, nil
}

// TestMCPKnowvaultListObjectsDenialAdmittedAndAudited is the R3a-1 Outcome 2
// negative control for the canonical knowvault_list_objects tool and its REST
// parity route GET/POST /api/v1/workspaces/{workspace_id}/tools/list-objects: a
// principal without the workspace right must receive the existing content-free
// -32004 `workspace objects not found` (REST: 404 NOT_FOUND) with no rows, no
// skipped items, no address and no workspace-id echo, and the call must record
// admission before data and its classed denial outcome through the same
// authorized inventory boundary the production viewer implements. Weakening the
// denial guard in internal/platform/workspaceapi/mcp_workspace_list.go to fall
// through, or weakening its -32004 denial mapping to the generic -32000
// service-unavailable, turns this probe RED.
func TestMCPKnowvaultListObjectsDenialAdmittedAndAudited(t *testing.T) {
	harness := newTestHarness(t)
	audit := &listObjectsDenialAuditSource{fakeInventoryEvidence: &fakeInventoryEvidence{listErr: workspacerepository.NewError(workspacerepository.CodeDenied, nil)}}
	audit.fakeInventoryEvidence.fakeEvidenceService = harness.evidence
	harness.handler.evidence = audit

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"l1","method":"tools/call","params":{"name":"`+mcpToolWorkspaceList+`","arguments":{"workspace_id":"ws_foreign"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_list_objects transport status=%d body=%s", response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP knowvault_list_objects denial did not decode: %v: %s", err, response.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "workspace objects not found" {
		t.Fatalf("MCP knowvault_list_objects denial error=%#v body=%s", outcome.Error, response.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("MCP knowvault_list_objects denial carried a result: %s", string(*outcome.Result))
	}
	if audit.listCall != "list" {
		t.Fatalf("MCP knowvault_list_objects denial never reached the authorized inventory read: %q", audit.listCall)
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"objects"`, `"skipped"`, `"address"`, testScopeID} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("MCP knowvault_list_objects denial leaked %q: %s", leaked, response.Body.String())
		}
	}
	if order := strings.Join(audit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("MCP knowvault_list_objects denial audit order=%q, want admission before the closed-class denial", order)
	}

	// The REST parity route dispatches through the identical workspaceInventoryPage
	// core, so it records the same admission/classed-denial sequence and answers
	// the documented content-free 404 NOT_FOUND with no row and no workspace echo.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run("rest/"+method, func(t *testing.T) {
			restHarness := newTestHarness(t)
			restAudit := &listObjectsDenialAuditSource{fakeInventoryEvidence: &fakeInventoryEvidence{listErr: workspacerepository.NewError(workspacerepository.CodeDenied, nil)}}
			restAudit.fakeInventoryEvidence.fakeEvidenceService = restHarness.evidence
			restHarness.handler.evidence = restAudit

			restResponse := httptest.NewRecorder()
			restHarness.handler.ServeHTTP(restResponse, restHarness.request(method, apiPrefix+"/workspaces/ws_foreign/tools/list-objects", ""))
			if restResponse.Code != http.StatusNotFound {
				t.Fatalf("REST list-objects %s denial status=%d body=%s", method, restResponse.Code, restResponse.Body.String())
			}
			if restAudit.listCall != "list" {
				t.Fatalf("REST list-objects %s denial never reached the authorized inventory read: %q", method, restAudit.listCall)
			}
			for _, leaked := range []string{"ws_foreign", `"objects"`, `"skipped"`, `"address"`, testScopeID} {
				if strings.Contains(restResponse.Body.String(), leaked) {
					t.Fatalf("REST list-objects %s denial leaked %q: %s", method, leaked, restResponse.Body.String())
				}
			}
			if order := strings.Join(restAudit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
				t.Fatalf("REST list-objects %s denial audit order=%q, want admission before the closed-class denial", method, order)
			}
		})
	}
}

// TestMCPWorkspaceListRejectsUnboundedArguments proves the closed schema and
// range validation run before any inventory read.
func TestMCPWorkspaceListRejectsUnboundedArguments(t *testing.T) {
	for name, args := range map[string]string{
		"missing_workspace_id": `{}`,
		"empty_workspace_id":   `{"workspace_id":""}`,
		"negative_offset":      `{"workspace_id":"ws_alpha","offset":-1}`,
		"negative_limit":       `{"workspace_id":"ws_alpha","limit":-1}`,
		"wrong_typed_offset":   `{"workspace_id":"ws_alpha","offset":"0"}`,
		"wrong_typed_versions": `{"workspace_id":"ws_alpha","all_versions":"yes"}`,
		"unknown_member":       `{"workspace_id":"ws_alpha","extra":true}`,
	} {
		name, args := name, args
		t.Run(name, func(t *testing.T) {
			service := &fakeInventoryEvidence{items: testInventoryItems()}
			harness := workspaceListHarness(t, service)
			envelope := callMCPWorkspaceList(t, harness, args)
			if service.listCall != "" {
				t.Fatalf("unbounded list arguments reached the inventory read: call=%q", service.listCall)
			}
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602 invalid-arguments, got: %#v", envelope.Error)
			}
		})
	}
}
