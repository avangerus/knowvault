package workspaceapi

// R3a-1 KV-A02b-r3 focused tests: KnowVault's MCP tool set is its own canonical
// contract. The wiki-rag tool names `wiki_list_pages` and `wiki_get_page` are
// neither advertised nor dispatched under any capability composition; a
// tools/call naming one is refused through the existing unknown-tool path with
// an error and no result content, and never reaches an inventory or evidence
// read.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type mcpAliasEnvelope struct {
	Result struct {
		Content    []map[string]any `json:"content"`
		Structured map[string]any   `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func callMCPAlias(t *testing.T, harness *testHarness, tool, arguments string) mcpAliasEnvelope {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"`+tool+`","arguments":`+arguments+`}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP %s status=%d body=%s", tool, response.Code, response.Body.String())
	}
	var envelope mcpAliasEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("MCP %s did not decode: %v: %s", tool, err, response.Body.String())
	}
	return envelope
}

// TestMCPWikiToolNamesNotAdvertised proves tools/list advertises only the
// product's `knowvault_*` names, with and without the mounted inventory
// capability, and never the removed wiki-rag names.
func TestMCPWikiToolNamesNotAdvertised(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		harness *testHarness
	}{
		{"with_inventory", workspaceListHarness(t, &fakeInventoryEvidence{})},
		{"without_inventory", newTestHarness(t)},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			schemas := listToolSchemas(t, testCase.harness)
			for name := range schemas {
				if !strings.HasPrefix(name, "knowvault_") {
					t.Fatalf("tools/list advertised a non-product tool name: %q", name)
				}
			}
			for _, removed := range []string{"wiki_list_pages", "wiki_get_page"} {
				if _, ok := schemas[removed]; ok {
					t.Fatalf("tools/list still advertises removed wiki-rag alias %q: %#v", removed, schemas[removed])
				}
			}
		})
	}
}

// TestMCPWikiToolNamesRefusedAsUnknown proves a tools/call naming a removed
// wiki-rag tool is refused through the existing unknown-tool path, with no
// result content and without reaching any inventory or evidence read.
func TestMCPWikiToolNamesRefusedAsUnknown(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		tool      string
		arguments string
	}{
		{"list_pages", "wiki_list_pages", `{"wiki":"ws_alpha"}`},
		{"get_page", "wiki_get_page", `{"wiki":"ws_alpha","page":"fragment_01"}`},
	} {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			service := &fakeInventoryEvidence{items: testInventoryItems()}
			harness := workspaceListHarness(t, service)
			envelope := callMCPAlias(t, harness, testCase.tool, testCase.arguments)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("removed wiki-rag tool %q not refused as unknown: %#v", testCase.tool, envelope.Error)
			}
			if envelope.Result.Structured != nil || envelope.Result.Content != nil {
				t.Fatalf("refusal leaked content: %#v", envelope.Result)
			}
			if service.listCall != "" || harness.evidence.call != "" {
				t.Fatalf("removed alias reached a read: list=%q read=%q", service.listCall, harness.evidence.call)
			}
		})
	}
}
