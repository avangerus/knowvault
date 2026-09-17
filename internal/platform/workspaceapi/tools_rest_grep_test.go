package workspaceapi

// R3a-1 KV-A02c focused tests: the REST parity twin of the workspace
// knowvault_grep tool. They prove GET and POST
// /api/v1/workspaces/{workspace_id}/tools/grep both dispatch through the
// identical authorized EvidenceGrep capability the MCP tool composes, that the
// success projection and explicit page window match the MCP result shape, that a
// denial stays the single content-free not-found without a workspace-id echo,
// that a service without the capability fails closed as SERVICE_UNAVAILABLE, and
// that invalid query members, a malformed pattern and an unexpected body are
// refused before the capability reads anything.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

type restGrepEnvelope struct {
	Matches    []map[string]any `json:"matches"`
	Offset     int64            `json:"offset"`
	Limit      int64            `json:"limit"`
	HasMore    bool             `json:"has_more"`
	NextOffset *int64           `json:"next_offset"`
}

func callRestGrep(t *testing.T, harness *testHarness, method, query string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(method, apiPrefix+"/workspaces/ws_alpha/tools/grep"+query, ""))
	return response
}

// TestWorkspaceToolGrepRESTParity proves both methods route to the same
// authorized capability and return the canonical match projection plus an
// explicit page window.
func TestWorkspaceToolGrepRESTParity(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			hit := testGrepHit(t)
			service := &fakeGrepEvidence{page: GrepPage{Hits: []GrepHit{hit}, HasMore: true, NextOffset: 7}}
			harness := grepHarness(t, service)

			response := callRestGrep(t, harness, method, "?pattern=alpha&offset=6&limit=100000&all_versions=true")
			if response.Code != http.StatusOK {
				t.Fatalf("grep REST status=%d body=%s", response.Code, response.Body.String())
			}
			if service.grepCall != "grep" || service.workspaceID != "ws_alpha" || service.pattern != "alpha" ||
				!service.allVersions || service.offset != 6 || service.limit != mcpGrepMaxLimit {
				t.Fatalf("grep capability got call=%q workspace=%q pattern=%q allVersions=%v offset=%d limit=%d",
					service.grepCall, service.workspaceID, service.pattern, service.allVersions, service.offset, service.limit)
			}
			var envelope restGrepEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("grep REST did not decode: %v: %s", err, response.Body.String())
			}
			if len(envelope.Matches) != 1 {
				t.Fatalf("grep REST matches=%#v", envelope.Matches)
			}
			match := envelope.Matches[0]
			if match["offset"] != float64(hit.Offset) || match["length"] != float64(hit.Length) ||
				match["excerpt"] != hit.Excerpt || match["version_id"] != hit.Fragment.SourceVersionID ||
				match["content_hash"] != hit.Fragment.ContentHash {
				t.Fatalf("grep REST match=%#v", match)
			}
			for _, required := range []string{"match_hash", "observed_at", "address", "canonical_address"} {
				if value, ok := match[required]; !ok || value == nil || value == "" {
					t.Fatalf("grep REST match missing %s: %#v", required, match)
				}
			}
			if !envelope.HasMore || envelope.NextOffset == nil || *envelope.NextOffset != 7 {
				t.Fatalf("grep REST page lost its cursor: %#v", envelope)
			}
			if envelope.Offset != 6 || envelope.Limit != mcpGrepMaxLimit {
				t.Fatalf("grep REST page window=%#v", envelope)
			}
		})
	}
}

// TestWorkspaceToolGrepRESTDeniesContentFree proves a denial is the single
// content-free not-found with no match and no workspace-id echo.
func TestWorkspaceToolGrepRESTDeniesContentFree(t *testing.T) {
	service := &fakeGrepEvidence{grepErr: evidence.ErrNotFound}
	harness := grepHarness(t, service)

	response := callRestGrep(t, harness, http.MethodGet, "?pattern=alpha")
	if response.Code != http.StatusNotFound {
		t.Fatalf("grep REST denial status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("grep REST denial echoed the workspace id: %s", response.Body.String())
	}
	var envelope restGrepEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("grep REST denial did not decode: %v: %s", err, response.Body.String())
	}
	if len(envelope.Matches) != 0 || envelope.HasMore {
		t.Fatalf("grep REST denial leaked content: %#v", envelope)
	}
}

// TestWorkspaceToolGrepRESTServicesUnavailable proves a service mounted without
// the grep capability fails closed as SERVICE_UNAVAILABLE.
func TestWorkspaceToolGrepRESTServicesUnavailable(t *testing.T) {
	harness := newTestHarness(t)
	response := callRestGrep(t, harness, http.MethodGet, "?pattern=alpha")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("grep REST no-capability status=%d body=%s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("grep REST no-capability body=%s", response.Body.String())
	}
}

// TestWorkspaceToolGrepRESTRejectsInvalidBeforeRead proves a malformed pattern,
// invalid or unknown query members and an unexpected body are refused as
// REQUEST_INVALID before the capability is touched.
func TestWorkspaceToolGrepRESTRejectsInvalidBeforeRead(t *testing.T) {
	for name, query := range map[string]string{
		"missing_pattern":   "?offset=1",
		"empty_pattern":     "?pattern=",
		"blank_pattern":     "?pattern=%20%20",
		"malformed_regex":   "?pattern=%28",
		"overlong":          "?pattern=" + strings.Repeat("a", mcpGrepPatternMaxLength+1),
		"negative_offset":   "?pattern=alpha&offset=-1",
		"negative_limit":    "?pattern=alpha&limit=-1",
		"malformed_address": "?pattern=alpha&address=not-a-kv1-address",
		"empty_address":     "?pattern=alpha&address=",
		"unknown_member":    "?pattern=alpha&bogus=1",
		"duplicate":         "?pattern=alpha&pattern=beta",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			service := &fakeGrepEvidence{}
			harness := grepHarness(t, service)
			response := callRestGrep(t, harness, http.MethodGet, query)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.Code, response.Body.String())
			}
			if service.grepCall != "" {
				t.Fatalf("invalid query reached the grep source: %q", service.grepCall)
			}
		})
	}

	// A POST body is not a parameter channel: a non-empty body is refused
	// rather than silently ignored.
	service := &fakeGrepEvidence{}
	harness := grepHarness(t, service)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost,
		apiPrefix+"/workspaces/ws_alpha/tools/grep?pattern=alpha", `{"pattern":"alpha"}`))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an unexpected body, got %d body=%s", response.Code, response.Body.String())
	}
	if service.grepCall != "" {
		t.Fatalf("unexpected body reached the grep source: %q", service.grepCall)
	}
}

// TestWorkspaceToolGrepRESTRefParity proves GET and POST accept the same
// optional `ref` query key and return the identical code-source-scoped
// projection as MCP, reading only the matching code-source version.
func TestWorkspaceToolGrepRESTRefParity(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			service, ids := grepRefService(t)
			harness := grepInventoryHarness(t, service)

			response := callRestGrep(t, harness, method, "?pattern=needle&ref=aaaa")
			if response.Code != http.StatusOK {
				t.Fatalf("ref grep REST status=%d body=%s", response.Code, response.Body.String())
			}
			if len(service.objectCalls) != 1 || service.objectCalls[0] != ids["a"] {
				t.Fatalf("ref grep REST read objects=%#v, want only %q", service.objectCalls, ids["a"])
			}
			var envelope restGrepEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("ref grep REST did not decode: %v: %s", err, response.Body.String())
			}
			if len(envelope.Matches) != 1 {
				t.Fatalf("ref grep REST matches=%#v", envelope.Matches)
			}
			addressObject, _ := envelope.Matches[0]["address"].(map[string]any)
			version, _ := addressObject["version"].(map[string]any)
			if version["ref"] != "aaaa" {
				t.Fatalf("ref grep REST address version=%#v", version)
			}
			parsed, err := address.Parse(envelope.Matches[0]["canonical_address"].(string))
			if err != nil || parsed.Version != "aaaa" {
				t.Fatalf("ref grep REST canonical address=%v version=%q", err, parsed.Version)
			}
			// The code-source file:lines locator is part of the parity shape.
			if envelope.Matches[0]["path"] != "internal/code/main.go" ||
				envelope.Matches[0]["line"] != float64(3) || envelope.Matches[0]["column"] != float64(4) {
				t.Fatalf("ref grep REST hit file:lines=%#v", envelope.Matches[0])
			}
		})
	}
}

// TestWorkspaceToolGrepRESTRefDeniesContentFree proves an unknown or foreign ref
// is the content-free 404 with no fragment read and no workspace-id echo.
func TestWorkspaceToolGrepRESTRefDeniesContentFree(t *testing.T) {
	service, _ := grepRefService(t)
	harness := grepInventoryHarness(t, service)

	response := callRestGrep(t, harness, http.MethodGet, "?pattern=needle&ref=deadbeef")
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown ref REST status=%d body=%s", response.Code, response.Body.String())
	}
	if len(service.objectCalls) != 0 {
		t.Fatalf("unknown ref REST read fragment content: %#v", service.objectCalls)
	}
	if strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("unknown ref REST echoed the workspace id: %s", response.Body.String())
	}
}

// TestWorkspaceToolGrepRESTRefRejectsInvalidBeforeRead proves the closed REST
// key set: a colon-carrying ref, an empty ref value, a duplicate ref and an
// over-long ref are 400 REQUEST_INVALID before the capability is touched.
func TestWorkspaceToolGrepRESTRefRejectsInvalidBeforeRead(t *testing.T) {
	for name, query := range map[string]string{
		"colon_ref":   "?pattern=needle&ref=native%3Acommit%3Aaaaa",
		"empty_ref":   "?pattern=needle&ref=",
		"duplicate":   "?pattern=needle&ref=aaaa&ref=bbbb",
		"overlong":    "?pattern=needle&ref=" + strings.Repeat("a", mcpGrepRefMaxLength+1),
		"unknown_key": "?pattern=needle&ref=aaaa&bogus=1",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			service := &fakeGrepEvidence{}
			harness := grepHarness(t, service)
			response := callRestGrep(t, harness, http.MethodGet, query)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%s", response.Code, response.Body.String())
			}
			if service.grepCall != "" {
				t.Fatalf("invalid ref query reached the grep source: %q", service.grepCall)
			}
		})
	}
}

// TestWorkspaceToolGrepRESTAddressParityUsesNoInventory proves GET and POST
// share the exact-address path, preserve Unicode byte offsets and perform one
// authorized whole-object read without falling back to ListObjects.
func TestWorkspaceToolGrepRESTAddressParityUsesNoInventory(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run(method, func(t *testing.T) {
			service, object := grepInventoryService(t)
			object.Fragment.Text = []byte("α alpha β alpha")
			object.Text = object.Fragment.Text
			object.Fragments[0].Length = len(object.Text)
			object.Fragment.EvidenceTextHash = mcpEvidenceReadTextHash(object.Text)
			service.objects[object.Fragment.FragmentID] = object
			harness := grepInventoryHarness(t, service)
			canonical := mcpGrepCanonicalAddressKeyed(nil, object, "")
			arguments := `{"workspace_id":"ws_alpha","pattern":"alpha","address":` + jsonString(t, canonical) + `,"limit":1}`
			mcpEnvelope := callMCPGrep(t, harness, arguments)
			if mcpEnvelope.Error != nil || len(mcpEnvelope.Result.Structured.Matches) != 1 {
				t.Fatalf("address grep MCP error=%#v matches=%#v", mcpEnvelope.Error, mcpEnvelope.Result.Structured.Matches)
			}
			mcpMatch := mcpEnvelope.Result.Structured.Matches[0]
			service.listCall = ""
			service.objectCalls = nil
			query := "?pattern=alpha&address=" + url.QueryEscape(canonical) + "&limit=1"
			response := callRestGrep(t, harness, method, query)
			if response.Code != http.StatusOK {
				t.Fatalf("address grep REST status=%d body=%s", response.Code, response.Body.String())
			}
			if service.listCall != "" || len(service.objectCalls) != 1 || service.objectCalls[0] != object.Fragment.FragmentID {
				t.Fatalf("address grep REST calls list=%q objects=%#v", service.listCall, service.objectCalls)
			}
			var envelope restGrepEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("address grep REST did not decode: %v: %s", err, response.Body.String())
			}
			if len(envelope.Matches) != 1 || !envelope.HasMore || envelope.NextOffset == nil || *envelope.NextOffset != 1 {
				t.Fatalf("address grep REST page=%#v", envelope)
			}
			if envelope.Matches[0]["offset"] != float64(3) {
				t.Fatalf("address grep REST Unicode offset=%v want 3", envelope.Matches[0]["offset"])
			}
			if !reflect.DeepEqual(envelope.Matches[0], mcpMatch) {
				t.Fatalf("address grep REST/MCP match projections differ:\nREST=%#v\nMCP=%#v", envelope.Matches[0], mcpMatch)
			}
		})
	}
}

// TestWorkspaceToolGrepRESTAddressRejectsBroadening proves the REST parser
// refuses an exact address combined with ref/all_versions before any evidence
// capability is touched.
func TestWorkspaceToolGrepRESTAddressRejectsBroadening(t *testing.T) {
	service, object := grepInventoryService(t)
	harness := grepInventoryHarness(t, service)
	canonical := url.QueryEscape(mcpGrepCanonicalAddressKeyed(nil, object, ""))
	for _, query := range []string{
		"?pattern=alpha&address=" + canonical + "&ref=deadbeef",
		"?pattern=alpha&address=" + canonical + "&all_versions=true",
	} {
		service.listCall = ""
		service.objectCalls = nil
		response := callRestGrep(t, harness, http.MethodGet, query)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 body=%s", response.Body.String())
		}
		if service.listCall != "" || len(service.objectCalls) != 0 {
			t.Fatalf("invalid address query touched evidence list=%q objects=%#v", service.listCall, service.objectCalls)
		}
	}
}
