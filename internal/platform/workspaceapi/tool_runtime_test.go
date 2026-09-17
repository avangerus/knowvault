package workspaceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

func chatRuntimeScope(harness *testHarness) workspacetools.Scope {
	return workspacetools.Scope{
		Access:      database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_chat_search"},
		WorkspaceID: harness.service.snapshot.ID, Revision: harness.service.snapshot.Revision,
	}
}

func TestChatSearchDefaultsPageWithoutChangingMCP(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want int64
	}{
		{"omitted", `{"query":"source facts"}`, 3},
		{"next page", `{"query":"source facts","offset":3}`, 3},
		{"explicit", `{"query":"source facts","limit":9}`, 9},
		{"explicit legacy zero", `{"query":"source facts","limit":0}`, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			search := &fakeSearchEvidence{}
			harness := searchHarness(t, search)
			result, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolSearch, json.RawMessage(tc.args))
			if err != nil || result.IsError || search.limit != tc.want {
				t.Fatalf("chat search: err=%v result=%s limit=%d want=%d", err, result.Text, search.limit, tc.want)
			}
			var page struct {
				Limit int64 `json:"limit"`
			}
			if err := json.Unmarshal(result.Structured, &page); err != nil || page.Limit != tc.want {
				t.Fatalf("effective page limit=%d want=%d err=%v", page.Limit, tc.want, err)
			}
			external := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"source facts"}`)
			if external.Error != nil || search.limit != mcpSearchDefaultLimit {
				t.Fatalf("MCP default changed: limit=%d error=%#v", search.limit, external.Error)
			}
		})
	}
}

func TestChatSearchCatalogAdvertisesItsOwnDefault(t *testing.T) {
	harness := searchHarness(t, &fakeSearchEvidence{})
	mcpBefore, err := json.Marshal(harness.handler.mcpTools(chatRuntimeScope(harness).Access))
	if err != nil {
		t.Fatal(err)
	}
	definitions, err := harness.handler.Catalog(context.Background(), chatRuntimeScope(harness))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, definition := range definitions {
		if definition.Name != mcpToolSearch {
			continue
		}
		found = true
		var schema struct {
			Properties map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(definition.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if schema.Properties["limit"]["default"] != float64(3) || schema.Properties["workspace_id"] != nil {
			t.Fatalf("unexpected chat search schema: %s", definition.Schema)
		}
	}
	if !found {
		t.Fatal("chat search definition missing")
	}
	mcp := listToolSchemas(t, harness)[mcpToolSearch]
	limit := mcp["properties"].(map[string]any)["limit"].(map[string]any)
	if _, present := limit["default"]; present {
		t.Fatalf("chat mutated MCP schema: %#v", limit)
	}
	mcpAfter, err := json.Marshal(harness.handler.mcpTools(chatRuntimeScope(harness).Access))
	if err != nil || !bytes.Equal(mcpBefore, mcpAfter) {
		t.Fatalf("chat guidance changed the external MCP catalogue: err=%v", err)
	}
}

func TestChatInventoryGuidancePreservesPagingDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want int64
	}{
		{"omitted", `{}`, mcpWorkspaceListDefaultLimit},
		{"small explicit page", `{"limit":3}`, 3},
		{"continuation", `{"offset":3,"limit":3}`, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory := &fakeInventoryEvidence{}
			harness := workspaceListHarness(t, inventory)
			scope := chatRuntimeScope(harness)
			definitions, err := harness.handler.Catalog(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, definition := range definitions {
				if definition.Name != mcpToolWorkspaceList {
					continue
				}
				found = true
				var schema struct {
					Properties map[string]map[string]any `json:"properties"`
				}
				if err := json.Unmarshal(definition.Schema, &schema); err != nil {
					t.Fatal(err)
				}
				if _, present := schema.Properties["limit"]["default"]; present || schema.Properties["workspace_id"] != nil {
					t.Fatalf("inventory guidance changed its default or authority schema: %s", definition.Schema)
				}
			}
			if !found {
				t.Fatal("chat inventory definition missing")
			}
			result, err := harness.handler.Invoke(context.Background(), scope, mcpToolWorkspaceList, json.RawMessage(tc.args))
			if err != nil || result.IsError || inventory.limit != tc.want {
				t.Fatalf("inventory paging changed: err=%v limit=%d want=%d", err, inventory.limit, tc.want)
			}
		})
	}
}

func TestChatGrepDefaultsPageWithoutChangingMCP(t *testing.T) {
	for _, tc := range []struct {
		name string
		args string
		want int64
	}{
		{"omitted", `{"pattern":"source facts"}`, 3},
		{"next page", `{"pattern":"source facts","offset":3}`, 3},
		{"explicit", `{"pattern":"source facts","limit":9}`, 9},
		{"explicit legacy zero", `{"pattern":"source facts","limit":0}`, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grep := &fakeGrepEvidence{}
			harness := grepHarness(t, grep)
			result, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolGrep, json.RawMessage(tc.args))
			if err != nil || result.IsError || grep.limit != tc.want {
				t.Fatalf("chat grep: err=%v result=%s limit=%d want=%d", err, result.Text, grep.limit, tc.want)
			}
			external := callMCPGrep(t, harness, `{"workspace_id":"ws_alpha","pattern":"source facts"}`)
			if external.Error != nil || grep.limit != mcpGrepDefaultLimit {
				t.Fatalf("MCP default changed: limit=%d error=%#v", grep.limit, external.Error)
			}
		})
	}
}

func TestChatGrepCatalogAdvertisesItsOwnDefault(t *testing.T) {
	harness := grepHarness(t, &fakeGrepEvidence{})
	definitions, err := harness.handler.Catalog(context.Background(), chatRuntimeScope(harness))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, definition := range definitions {
		if definition.Name != mcpToolGrep {
			continue
		}
		found = true
		var schema struct {
			Properties map[string]map[string]any `json:"properties"`
		}
		if err := json.Unmarshal(definition.Schema, &schema); err != nil {
			t.Fatal(err)
		}
		if schema.Properties["limit"]["default"] != float64(3) {
			t.Fatalf("unexpected chat grep schema: %s", definition.Schema)
		}
	}
	if !found {
		t.Fatal("chat grep definition missing")
	}
	mcp := listToolSchemas(t, harness)[mcpToolGrep]
	limit := mcp["properties"].(map[string]any)["limit"].(map[string]any)
	if _, present := limit["default"]; present {
		t.Fatalf("chat mutated MCP schema: %#v", limit)
	}
}

func TestChatSearchDefaultDoesNotRepairInvalidAuthorityOrArguments(t *testing.T) {
	for _, arguments := range []string{
		`{"query":"source facts","workspace_id":"ws_foreign"}`,
		`{"query":"source facts","limit":1,"limit":2}`,
	} {
		search := &fakeSearchEvidence{}
		harness := searchHarness(t, search)
		_, err := harness.handler.Invoke(context.Background(), chatRuntimeScope(harness), mcpToolSearch, json.RawMessage(arguments))
		if !errors.Is(err, workspacetools.ErrArguments) || search.searchCall != "" {
			t.Fatalf("invalid request reached search: err=%v call=%q", err, search.searchCall)
		}
	}
	search := &fakeSearchEvidence{}
	harness := searchHarness(t, search)
	scope := chatRuntimeScope(harness)
	scope.Revision++
	_, err := harness.handler.Invoke(context.Background(), scope, mcpToolSearch, json.RawMessage(`{"query":"source facts"}`))
	if !errors.Is(err, workspacetools.ErrScopeChanged) || search.searchCall != "" {
		t.Fatalf("changed scope reached search: err=%v call=%q", err, search.searchCall)
	}
}
