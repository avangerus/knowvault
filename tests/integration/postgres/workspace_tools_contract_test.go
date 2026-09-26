package postgres_test

// KV-A03 (R3a-1 Outcome 2): the workspace MCP tool-set catalogue contract,
// proved end to end against real PostgreSQL through the production
// workspaceapi MCP adapter.
//
// The surface under test is the real, unmodified /api/v1/mcp tools/list and
// tools/call dispatch the deployment serves:
//
//  1. tools/list for a workspace member advertises exactly the eight
//     canonical KnowVault knowledge tools (knowvault_search, knowvault_read,
//     knowvault_list_objects, knowvault_related, knowvault_grep,
//     knowvault_sources, knowvault_refresh, knowvault_workspace_context) and
//     no other knowledge name.
//  2. the three compatibility aliases (knowvault_evidence_read,
//     knowvault_workspace_list, knowvault_sources_list) are dispatch-only: they
//     never appear on tools/list, yet a tools/call naming one is still resolved
//     through the single internal/workspacetools registry rather than refused as
//     an unknown tool.
//  3. no wiki-rag tool name (wiki_search, wiki_get_page, wiki_list_pages,
//     wiki_find_related, code_search, code_get_file) is advertised, and a
//     tools/call naming one is refused through the existing unknown-tool path
//     (-32602) with no result content.
//  4. a principal holding no right on the target workspace that calls a
//     registered knowledge tool receives the existing documented content-free
//     -32004 denial with no workspace content and no echo of the requested
//     workspace id.
//
// The handler is the real workspaceapi MCP boundary over a real evidence.Viewer
// bound to the real app-role database. The only test-local wiring is the
// relation capability: the production composition mounts
// internal/platform/composition.relationEvidence over the viewer, whose
// RelatedObjects read is unexported there, so this suite mounts a minimal
// wrapper that embeds the real *evidence.Viewer (keeping Read, ReadObject,
// ListObjects and SearchFragments the production implementations) and adds the
// relation method the catalogue is gated on. QuestionService and
// ConversationService are supplied as non-nil minimal stubs so the adapter's
// "service unavailable" guard does not short-circuit tools/list and tools/call
// before dispatch; a knowledge tools/list or denial call never invokes them. No
// production semantics, route, contract, migration or dependency is changed.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

// kvA03CanonicalTools is the one canonical knowledge name set the workspace
// MCP surface must advertise, in registry order. R3a-1 fixed the first
// seven; knowvault_workspace_context is S2's own addition (ADR-0098,
// S2-CONTRACT.md "MCP") and knowvault_source_schema is S3 card 1's ADR-0097
// addition, as is knowvault_source_sql (S3 card 2) -- member-readable knowledge tools exactly like the other seven
// (Reader.Current's RLS admits OWNER, MANAGER, MEMBER and a scoped SERVICE),
// so they belong in this same closed advertised set, not a separate
// administrative one.
var kvA03CanonicalTools = []string{
	"knowvault_search",
	"knowvault_read",
	"knowvault_list_objects",
	"knowvault_related",
	"knowvault_grep",
	"knowvault_sources",
	"knowvault_refresh",
	"knowvault_workspace_context",
	"knowvault_source_schema",
	"knowvault_source_sql",
}

// kvA03AliasTools are the dispatch-only former names: callable for pinned
// clients, never advertised.
var kvA03AliasTools = []string{
	"knowvault_evidence_read",
	"knowvault_workspace_list",
	"knowvault_sources_list",
}

// kvA03WikiTools are the wiki-rag names the product must neither advertise nor
// dispatch.
var kvA03WikiTools = []string{
	"wiki_search",
	"wiki_get_page",
	"wiki_list_pages",
	"wiki_find_related",
	"code_search",
	"code_get_file",
}

// kvA03RelationViewer mounts the R3a-1 relation capability over the production
// *evidence.Viewer. Embedding the viewer keeps Read/ReadObject/ListObjects and
// SearchFragments the real production reads; only the relation method is
// test-local (the relation tool is what tools/list capability-gates on).
type kvA03RelationViewer struct {
	*evidence.Viewer
}

func (kvA03RelationViewer) RelatedObjects(context.Context, database.AccessContext, string, string, string, int64, int64) (workspaceapi.RelatedPage, error) {
	return workspaceapi.RelatedPage{}, nil
}

type kvA03ToolListEnvelope struct {
	Result struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"result"`
	Error *kvA01MCPError `json:"error"`
}

// kvA03ToolsList issues one authenticated tools/list against the real MCP
// handler and returns the advertised tool names.
func kvA03ToolsList(t *testing.T, handler *workspaceapi.Handler, token, csrf string) []string {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, kvA01Origin+"/api/v1/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":"kva03-list","method":"tools/list","params":{}}`))
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", kvA01Origin)
	request.Header.Set(httpauth.CSRFHeader, csrf)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("kv-a03 tools/list status=%d body=%s", response.Code, response.Body.String())
	}
	var list kvA03ToolListEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &list); err != nil {
		t.Fatalf("kv-a03 tools/list decode: %v body=%s", err, response.Body.String())
	}
	if list.Error != nil {
		t.Fatalf("kv-a03 tools/list refused: %#v body=%s", list.Error, response.Body.String())
	}
	names := make([]string, 0, len(list.Result.Tools))
	for _, tool := range list.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// kvA03Session mints the canonical session cookie token and CSRF proof the
// httpauth OIDC/Keycloak transport the deployment uses requires (the same shape
// the KV-A01 suite presents).
func kvA03Session(t *testing.T) (string, string) {
	t.Helper()
	raw := make([]byte, sha256.Size)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	proof, err := (kvA01Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("kv-a03 csrf proof: %v", err)
	}
	return token, proof.Value()
}

// kvA03QuestionService is a test-local minimal QuestionService. The workspace
// MCP tools/list and the catalogue denial path never call it; a non-nil value
// only satisfies the handler's "service unavailable" guard
// (workspaceapi/mcp_adapter.go:418) so tools/list and tools/call reach the real
// dispatch. Every method returns its zero value.
type kvA03QuestionService struct{}

func (kvA03QuestionService) Create(context.Context, database.AccessContext, question.CreateRequest) (question.Run, error) {
	return question.Run{}, nil
}

func (kvA03QuestionService) Get(context.Context, database.AccessContext, string, string) (question.Run, error) {
	return question.Run{}, nil
}

func (kvA03QuestionService) GetBatch(context.Context, database.AccessContext, string, []string) (map[string]question.Run, error) {
	return nil, nil
}

func (kvA03QuestionService) ProcessingMode(string) (string, string) { return "", "" }

func (kvA03QuestionService) StructuredRowset(context.Context, database.AccessContext, string, string, string) (*question.RowsetEvidence, error) {
	return nil, nil
}

// kvA03ConversationService is a test-local minimal ConversationService with the
// same "guard only" role as kvA03QuestionService.
type kvA03ConversationService struct{}

func (kvA03ConversationService) List(context.Context, database.AccessContext, string) ([]conversation.View, error) {
	return nil, nil
}

func (kvA03ConversationService) Get(context.Context, database.AccessContext, string, string) (conversation.View, error) {
	return conversation.View{}, nil
}

func (kvA03ConversationService) Archive(context.Context, database.AccessContext, conversation.ArchiveRequest) (conversation.View, error) {
	return conversation.View{}, nil
}

// TestKVA03WorkspaceMCPToolSetContract proves the workspace MCP tool-set
// catalogue and denial contract of R3a-1 Outcome 2.
func TestKVA03WorkspaceMCPToolSetContract(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)
	// A real workspace of the same organization the caller s1dViewer is not a
	// member of: the target of the cross-workspace denial below.
	seedKVA01ForeignWorkspace(t, ctx, admin, s1dOrg, kvA01ForeignWorkspace, s1dOwner)

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("kv-a03 evidence viewer: %v", err)
	}

	authenticator, err := httpauth.New(
		kvA01TenantResolver{organizationID: s1dOrg},
		kvA01SessionResolver{organizationID: s1dOrg, principalID: s1dViewer, claims: kvA01Claims(t, s1dOrg, s1dViewer)},
	)
	if err != nil {
		t.Fatalf("kv-a03 authenticator: %v", err)
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(
		authenticator, newAuthorityRuntime(t, ctx), kvA01SourceService{},
		kvA03RelationViewer{Viewer: viewer}, kvA03QuestionService{}, kvA03ConversationService{})
	if err != nil {
		t.Fatalf("kv-a03 workspace handler: %v", err)
	}
	token, csrf := kvA03Session(t)

	t.Run("member tools/list advertises exactly the canonical knowledge tools", func(t *testing.T) {
		names := kvA03ToolsList(t, handler, token, csrf)
		present := make(map[string]bool, len(names))
		for _, name := range names {
			present[name] = true
		}
		for _, want := range kvA03CanonicalTools {
			if !present[want] {
				t.Fatalf("tools/list omitted the canonical knowledge tool %q: %v", want, names)
			}
		}
		for _, alias := range kvA03AliasTools {
			if present[alias] {
				t.Fatalf("tools/list advertised the dispatch-only alias %q: %v", alias, names)
			}
		}
		// No advertised name may resolve to a compatibility alias: an advertised
		// knowledge name is always the canonical name of its registry entry.
		registry := workspacetools.KnowledgeTools()
		advertised := make([]string, 0, len(kvA03CanonicalTools))
		for _, name := range names {
			tool, ok := registry.Lookup(name)
			if !ok {
				continue
			}
			if tool.Name != name {
				t.Fatalf("tools/list advertised the compatibility alias %q (canonical %q)", name, tool.Name)
			}
			advertised = append(advertised, name)
		}
		sort.Strings(advertised)
		want := append([]string(nil), kvA03CanonicalTools...)
		sort.Strings(want)
		if !reflect.DeepEqual(advertised, want) {
			t.Fatalf("advertised knowledge set = %v, want exactly %v", advertised, want)
		}
	})

	t.Run("no wiki-rag name is advertised or dispatched", func(t *testing.T) {
		names := kvA03ToolsList(t, handler, token, csrf)
		present := make(map[string]bool, len(names))
		for _, name := range names {
			present[name] = true
		}
		for _, removed := range kvA03WikiTools {
			if present[removed] {
				t.Fatalf("tools/list advertised the removed wiki-rag tool %q: %v", removed, names)
			}
			body, envelope := kvA01Call(t, handler, token, csrf,
				kvA01ToolCallBody("kva03-wiki", removed, `{"workspace_id":"ws_alpha","query":"alpha"}`))
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("removed wiki-rag tool %q not refused as an unknown tool: %#v body=%s", removed, envelope.Error, body)
			}
			if len(envelope.Result.Content) != 0 || len(envelope.Result.Structured) != 0 {
				t.Fatalf("removed wiki-rag tool %q leaked result content: %s", removed, body)
			}
		}
	})

	t.Run("non-member knowledge call is the documented content-free denial", func(t *testing.T) {
		for _, tool := range []string{"knowvault_list_objects", "knowvault_workspace_list"} {
			body, envelope := kvA01Call(t, handler, token, csrf,
				kvA01ToolCallBody("kva03-denial", tool, `{"workspace_id":"`+kvA01ForeignWorkspace+`"}`))
			if envelope.Error == nil || envelope.Error.Code != -32004 {
				t.Fatalf("non-member %s call = %#v body=%s, want the documented content-free -32004 denial", tool, envelope.Error, body)
			}
			if len(envelope.Result.Content) != 0 || len(envelope.Result.Structured) != 0 {
				t.Fatalf("non-member %s denial leaked content: %s", tool, body)
			}
			if strings.Contains(body, kvA01ForeignWorkspace) {
				t.Fatalf("non-member %s denial echoed the requested workspace: %s", tool, body)
			}
		}
	})
}
