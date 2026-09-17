package workspaceapi

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

func TestMCPSearchAddressReadsBackWithOrganizationDigest(t *testing.T) {
	hit := testSearchHit(t)
	hit.Fragment.SourcePath = "projects/alpha/operations.txt"
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{hit}}}
	harness := searchHarness(t, service)
	key := address.NewSpanDigestKey([]byte("search-read-organization-key"), 3)
	harness.handler.EnableSpanDigest(key)
	harness.evidence.result = hit.Fragment
	result := callMCPSearch(t, harness, mcpToolSearch, `{"workspace_id":"ws_alpha","query":"alpha"}`)
	if result.Error != nil || len(result.Result.Structured.Results) != 1 {
		t.Fatalf("search failed: %#v", result)
	}
	canonical, _ := result.Result.Structured.Results[0]["canonical_address"].(string)
	if result.Result.Structured.Results[0]["source_path"] != hit.Fragment.SourcePath ||
		!strings.Contains(mcpContentTextBlock(t, result.Result.Content), hit.Fragment.SourcePath) {
		t.Fatal("search omitted the authorized source path")
	}
	parsed, err := address.Parse(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.VerifySpan(hit.Fragment.Text, parsed); err != nil {
		t.Fatalf("address did not use the organization key: %v", err)
	}
	if !strings.Contains(mcpContentTextBlock(t, result.Result.Content), canonical) {
		t.Fatal("text-only MCP clients cannot copy the address")
	}
	read := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "address": canonical}))
	if read.Error != nil || read.Result.Structured["text"] != string(hit.Fragment.Text) {
		t.Fatalf("search address did not read back: %#v", read)
	}
	if read.Result.Structured["source_path"] != hit.Fragment.SourcePath ||
		!strings.Contains(mcpContentTextBlock(t, read.Result.Content), hit.Fragment.SourcePath) {
		t.Fatal("read omitted the authorized source path")
	}
	parsed.SpanHash = strings.Repeat("0", 16)
	refused := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "address": parsed.String()}))
	if refused.Error == nil || len(refused.Result.Structured) != 0 {
		t.Fatalf("tampered address disclosed a result: %#v", refused)
	}
}
