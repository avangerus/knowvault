package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

func TestMCPMetadataPreservesSearchAndArgumentBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, extensions, arguments string
		invalid                     bool
	}{
		{"plain", "", `{"workspace_id":"ws_alpha","query":"alpha"}`, false},
		{"progress", `,"_meta":{"progressToken":"progress-1"}`, `{"workspace_id":"ws_alpha","query":"alpha"}`, false},
		{"client extensions", `,"_meta":{"progressToken":7},"threadId":"thread-1","itemId":"item-1"`, `{"workspace_id":"ws_alpha","query":"alpha"}`, false},
		{"unknown argument", `,"_meta":{"progressToken":7}`, `{"workspace_id":"ws_alpha","query":"alpha","grant_access":true}`, true},
		{"duplicate name", `,"name":"knowvault_sources"`, `{"workspace_id":"ws_alpha","query":"alpha"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{testSearchHit(t)}}}
			harness := searchHarness(t, service)
			response := httptest.NewRecorder()
			body := `{"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"knowvault_search","arguments":` + tc.arguments + tc.extensions + `}}`
			harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", body))
			var result mcpSearchEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if tc.invalid {
				if result.Error == nil || (result.Error.Code != -32602 && result.Error.Code != -32600) || service.searchCall != "" {
					t.Fatalf("invalid request reached search: %s", response.Body.String())
				}
				return
			}
			if result.Error != nil || service.searchCall != "search" || len(result.Result.Structured.Results) != 1 {
				t.Fatalf("metadata changed tool behavior: %s", response.Body.String())
			}
		})
	}
}
