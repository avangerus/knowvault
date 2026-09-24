package workspaceapi

// V1-C review remarks: an agent access code must be shown only the tools it
// may invoke, and a partial corpus must be visible to an agent the way it is
// visible to a human.

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
)

func toolNames(t *testing.T, catalog []any) []string {
	t.Helper()
	names := make([]string, 0, len(catalog))
	for _, entry := range catalog {
		tool, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("every tools/list entry must be an object, got %T", entry)
		}
		name, ok := tool["name"].(string)
		if !ok || name == "" {
			t.Fatalf("every tools/list entry must carry a name: %#v", tool)
		}
		names = append(names, name)
	}
	return names
}

func TestToolsListShowsAServicePrincipalOnlyWhatItMayCall(t *testing.T) {
	service := database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "principal_agent",
		RequestID: "req_agent", ActorKind: database.ActorKindService,
	}
	names := toolNames(t, mcpToolCatalog(service))
	// Every name a service principal is shown must be a knowledge tool it may
	// actually invoke, and the canonical knowledge set must be present.
	wanted := map[string]bool{
		mcpToolQuestion: false, mcpToolEvidenceGet: false,
		mcpToolEvidenceRead: false, mcpToolWorkspaceList: false, mcpToolSourcesList: false,
		mcpToolGovernedQueryAsk: false, mcpToolWorkspaceContext: false,
	}
	for _, name := range names {
		if !mcpServiceKnowledgeTool(name) {
			t.Fatalf("tools/list disclosed %q to an agent that can never call it", name)
		}
		if _, tracked := wanted[name]; tracked {
			wanted[name] = true
		}
	}
	for name, present := range wanted {
		if !present {
			t.Fatalf("the SERVICE knowledge catalogue lost %q", name)
		}
	}
	// The administrative tools stay closed to a service principal.
	closed := []string{
		"knowvault_conversations_list", "knowvault_conversation_get", "knowvault_conversation_archive",
		mcpToolConfirmationGrantIssue, mcpToolConfirmationGrantRevoke,
		mcpToolManagedSourceConfirm, mcpToolManagedConfirmationRevoke,
		mcpToolVerifyConnectionTrust, mcpToolSourceEnable, mcpToolSourceSync,
		mcpToolMetricDefinitionsList, mcpToolMetricDefinitionGet,
	}
	for _, name := range names {
		for _, forbidden := range closed {
			if name == forbidden {
				t.Fatalf("tools/list disclosed administrative tool %q to a service principal", name)
			}
		}
	}
}

func TestToolsListShowsAHumanTheWholeCatalogue(t *testing.T) {
	human := database.AccessContext{OrganizationID: "org_demo", PrincipalID: "principal_owner", RequestID: "req_human"}
	names := toolNames(t, mcpToolCatalog(human))
	if len(names) < 10 {
		t.Fatalf("an operator session must keep the full tool catalogue, saw %v", names)
	}
	required := map[string]bool{
		mcpToolQuestion: false, mcpToolEvidenceGet: false,
		mcpToolVerifyConnectionTrust: false, mcpToolGovernedQueryAsk: false,
	}
	for _, name := range names {
		if _, tracked := required[name]; tracked {
			required[name] = true
		}
	}
	for name, present := range required {
		if !present {
			t.Fatalf("the operator catalogue lost %q", name)
		}
	}
}

// The tools/list allow-list and the tools/call allow-list must be the same
// list: showing a tool an agent cannot call, or hiding one it can, is drift
// between two copies of the same rule. tools/call gates SERVICE calls with
// mcpServiceKnowledgeTool, so tools/list must show exactly those names.
func TestServiceToolsListMatchesWhatToolCallAccepts(t *testing.T) {
	service := database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "principal_agent",
		RequestID: "req_agent", ActorKind: database.ActorKindService,
	}
	listed := toolNames(t, mcpToolCatalog(service))
	shown := make(map[string]bool, len(listed))
	for _, name := range listed {
		shown[name] = true
	}
	for _, name := range toolNames(t, mcpToolCatalog(database.AccessContext{OrganizationID: "org_demo", PrincipalID: "p", RequestID: "r"})) {
		if permitted, isShown := mcpServiceKnowledgeTool(name), shown[name]; permitted != isShown {
			t.Fatalf("tool %q: callable by a SERVICE principal=%v but listed to it=%v", name, permitted, isShown)
		}
	}
}

// A mounted optional knowledge capability (lexical search, relations, exact
// grep) must be advertised to a SERVICE principal exactly as it is to a human:
// the allow-list filtering happens after the optional definitions are appended.
func TestServiceToolsListKeepsMountedOptionalKnowledgeCapabilities(t *testing.T) {
	service := database.AccessContext{
		OrganizationID: "org_demo", PrincipalID: "principal_agent",
		RequestID: "req_agent", ActorKind: database.ActorKindService,
	}
	all := mcpToolCatalog(database.AccessContext{OrganizationID: "org_demo", PrincipalID: "p", RequestID: "r"})
	all = append(all, mcpSearchToolDefinitions()...)
	all = append(all, mcpRelatedToolDefinitions()...)
	all = append(all, mcpGrepToolDefinitions(true)...)
	names := make(map[string]bool)
	for _, name := range toolNames(t, mcpToolsForActor(all, service)) {
		names[name] = true
	}
	for _, wanted := range []string{mcpToolSearch, mcpToolRelated, mcpToolGrep} {
		if !names[wanted] {
			t.Fatalf("a mounted knowledge tool %q is hidden from a SERVICE principal", wanted)
		}
	}
}

// QRY-002 on the MCP transport: the corpus status is text an agent reads,
// above the answer, not only a structuredContent field it may ignore.
func TestMCPQuestionContentCarriesTheCorpusWarningAboveTheAnswer(t *testing.T) {
	partial := mcpQuestionContent(question.Run{CorpusStatus: "PARTIAL", Answer: "\u043e\u0442\u0432\u0435\u0442"})
	if len(partial) != 2 {
		t.Fatalf("a PARTIAL run must carry a warning block and the answer, got %#v", partial)
	}
	first, _ := partial[0].(map[string]any)
	warning, _ := first["text"].(string)
	if !strings.Contains(warning, "PARTIAL") {
		t.Fatalf("the first content block must name the corpus status, got %q", warning)
	}
	last, _ := partial[1].(map[string]any)
	if text, _ := last["text"].(string); text != "\u043e\u0442\u0432\u0435\u0442" {
		t.Fatalf("the answer must follow the warning unchanged, got %q", text)
	}

	complete := mcpQuestionContent(question.Run{CorpusStatus: "COMPLETE", Answer: "\u043e\u0442\u0432\u0435\u0442"})
	if len(complete) != 1 {
		t.Fatalf("a COMPLETE run must not invent a warning, got %#v", complete)
	}
}
