package workspaceapi

// ADR-0098 focused tests for the MCP surface of knowvault_workspace_context:
// argument validation at the transport boundary, the content-free not-found
// shape, and the `initialize` result's `instructions` member (the static
// rules always, plus -- only with exactly one accessible workspace -- that
// workspace's rendered context through the identical workspacecontext.Render
// the chat's system message uses, with a byte-for-byte parity check).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestMCPWorkspaceContextToolCallRejectsInvalidArguments proves a missing
// workspace_id, more than 10 terms, an unknown section and a duplicate JSON
// key are all refused as -32602 before the Reader is touched.
func TestMCPWorkspaceContextToolCallRejectsInvalidArguments(t *testing.T) {
	for name, arguments := range map[string]string{
		"missing_workspace_id": `{}`,
		"too_many_terms":       `{"workspace_id":"ws_alpha","terms":["a","b","c","d","e","f","g","h","i","j","k"]}`,
		"empty_term":           `{"workspace_id":"ws_alpha","terms":[""]}`,
		"bad_section":          `{"workspace_id":"ws_alpha","section":"everything"}`,
		"unknown_field":        `{"workspace_id":"ws_alpha","unexpected":true}`,
	} {
		name, arguments := name, arguments
		t.Run(name, func(t *testing.T) {
			harness, reader := newWorkspaceContextHarness(t)
			envelope := callMCPWorkspaceContext(t, harness, arguments)
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("%s: expected -32602, got %#v", name, envelope.Error)
			}
			if reader.call != "" {
				t.Fatalf("%s: invalid arguments reached the Reader: call=%q", name, reader.call)
			}
		})
	}
}

// TestMCPWorkspaceContextToolCallCarriesNoticeAndSections proves the exact
// contract projection: version, content_hash, description, rules, glossary,
// sources and the fixed notice "context, not evidence".
func TestMCPWorkspaceContextToolCallCarriesNoticeAndSections(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)
	envelope := callMCPWorkspaceContext(t, harness, `{"workspace_id":"ws_alpha"}`)
	if envelope.Error != nil {
		t.Fatalf("unexpected error: %#v", envelope.Error)
	}
	structured := envelope.Result.Structured
	for _, member := range []string{"version", "content_hash", "description", "rules", "glossary", "sources", "notice"} {
		if _, present := structured[member]; !present {
			t.Fatalf("structuredContent missing %q: %#v", member, structured)
		}
	}
	if structured["notice"] != "context, not evidence" {
		t.Fatalf("notice = %v, want %q", structured["notice"], "context, not evidence")
	}
	if len(envelope.Result.Content) != 1 || envelope.Result.Content[0].Type != "text" || envelope.Result.Content[0].Text == "" {
		t.Fatalf("content channel missing or empty: %#v", envelope.Result.Content)
	}
}

// TestMCPInitializeAlwaysCarriesStaticInstructions proves every initialize
// response -- even with no accessible workspace and no mounted Reader --
// carries the fixed ADR-0098 sentence.
func TestMCPInitializeAlwaysCarriesStaticInstructions(t *testing.T) {
	harness := newTestHarness(t)
	instructions := initializeInstructions(t, harness)
	if !strings.Contains(instructions, mcpWorkspaceContextStaticInstructions) {
		t.Fatalf("initialize instructions missing the static sentence: %q", instructions)
	}
}

// TestMCPInitializeSingleWorkspaceIncludesByteIdenticalRenderedContext proves
// that with exactly one accessible workspace, initialize's instructions carry
// that workspace's context rendered through the identical
// workspacecontext.Render the chat's system message uses -- a parity test
// comparing bytes, per S2-MODEL-CONTEXT-DESIGN.md "MCP".
func TestMCPInitializeSingleWorkspaceIncludesByteIdenticalRenderedContext(t *testing.T) {
	harness, reader := newWorkspaceContextHarness(t)
	harness.service.list = []workspacerepository.Summary{{ID: "ws_alpha", Name: "Alpha"}}

	instructions := initializeInstructions(t, harness)
	wantBlock, _ := workspacecontext.Render(reader.version.Document, reader.version.Number, "", mcpWorkspaceContextInstructionsBudget)
	if !strings.Contains(instructions, wantBlock) {
		t.Fatalf("initialize instructions did not carry the byte-identical rendered block.\nwant substring: %s\ngot: %s", wantBlock, instructions)
	}
	if len(wantBlock) > mcpWorkspaceContextInstructionsBudget {
		t.Fatalf("test fixture itself exceeds the 16 KiB budget: %d bytes", len(wantBlock))
	}
}

// TestMCPInitializeMultipleWorkspacesListsThemInstead proves that with more
// than one accessible workspace, initialize names them and points the client
// at the tool rather than guessing which workspace to render.
func TestMCPInitializeMultipleWorkspacesListsThemInstead(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)
	harness.service.list = []workspacerepository.Summary{{ID: "ws_alpha", Name: "Alpha"}, {ID: "ws_beta", Name: "Beta"}}

	instructions := initializeInstructions(t, harness)
	if !strings.Contains(instructions, "ws_alpha") || !strings.Contains(instructions, "ws_beta") {
		t.Fatalf("initialize instructions did not name both accessible workspaces: %q", instructions)
	}
	if !strings.Contains(instructions, mcpToolWorkspaceContext) {
		t.Fatalf("initialize instructions did not hint the tool name: %q", instructions)
	}
	if strings.Contains(instructions, "WORKSPACE_CONTEXT_JSON (version") {
		t.Fatalf("initialize instructions must not render a block for an ambiguous workspace set: %q", instructions)
	}
}

// TestMCPInitializeZeroWorkspacesOmitsBlock proves a caller with no
// accessible workspace gets the static sentence and no rendered block.
func TestMCPInitializeZeroWorkspacesOmitsBlock(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)
	// harness.service.list defaults to empty.
	instructions := initializeInstructions(t, harness)
	if strings.Contains(instructions, "WORKSPACE_CONTEXT_JSON (version") {
		t.Fatalf("initialize instructions must not render a block with zero accessible workspaces: %q", instructions)
	}
}

// TestMCPInitializeWithoutReaderOmitsBlock proves a composition mounted
// without EnableWorkspaceContext still answers initialize (static sentence
// only), rather than failing the handshake.
func TestMCPInitializeWithoutReaderOmitsBlock(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.list = []workspacerepository.Summary{{ID: "ws_alpha", Name: "Alpha"}}
	instructions := initializeInstructions(t, harness)
	if !strings.Contains(instructions, mcpWorkspaceContextStaticInstructions) {
		t.Fatalf("initialize instructions missing the static sentence: %q", instructions)
	}
	if strings.Contains(instructions, "WORKSPACE_CONTEXT_JSON (version") {
		t.Fatalf("initialize instructions rendered a block without a mounted Reader: %q", instructions)
	}
}

func initializeInstructions(t *testing.T, harness *testHarness) string {
	t.Helper()
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("initialize status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope struct {
		Result struct {
			Instructions string `json:"instructions"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error != nil {
		t.Fatalf("initialize did not decode: err=%v error=%#v body=%s", err, envelope.Error, response.Body.String())
	}
	return envelope.Result.Instructions
}

// TestMCPInstructionsDirectCallMatchesHTTPInitialize proves
// Handler.mcpInstructions (usable directly, e.g. by a future non-HTTP
// transport) matches exactly what the HTTP initialize route returns.
func TestMCPInstructionsDirectCallMatchesHTTPInitialize(t *testing.T) {
	harness, _ := newWorkspaceContextHarness(t)
	harness.service.list = []workspacerepository.Summary{{ID: "ws_alpha", Name: "Alpha"}}
	access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_server_001"}

	direct := harness.handler.mcpInstructions(context.Background(), access)
	viaHTTP := initializeInstructions(t, harness)
	if direct != viaHTTP {
		t.Fatalf("direct mcpInstructions != HTTP initialize instructions\ndirect: %q\nHTTP:   %q", direct, viaHTTP)
	}
}
