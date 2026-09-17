package workspaceapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// pagingConversationService adds only the narrow bounded-pagination capability
// on top of the shared conversation test double. Every legacy method is
// inherited unchanged, so these tests exercise the real HTTP wiring rather than
// a rewritten fake.
type pagingConversationService struct {
	*fakeConversationService
	pageCalls []conversationPageCall
	page      conversation.Page
	pageErr   error
}

type conversationPageCall struct {
	workspaceID string
	limit       int
	cursor      string
}

func (service *pagingConversationService) ListPage(_ context.Context, access database.AccessContext, workspaceID string, limit int, cursor string) (conversation.Page, error) {
	service.pageCalls = append(service.pageCalls, conversationPageCall{workspaceID: workspaceID, limit: limit, cursor: cursor})
	service.call, service.access = "list_page", access
	return service.page, service.pageErr
}

func newPagingConversationHarness(t *testing.T) (*testHarness, *pagingConversationService) {
	t.Helper()
	harness := newTestHarness(t)
	paging := &pagingConversationService{fakeConversationService: harness.conversations}
	harness.handler.conversations = paging
	return harness, paging
}

func testConversationViews() []conversation.View {
	return []conversation.View{
		{ID: "conv_alpha_1", WorkspaceID: "ws_alpha", WorkspaceRevision: 1, CreatedBy: "usr_alice", Turns: []conversation.Turn{}},
		{ID: "conv_alpha_2", WorkspaceID: "ws_alpha", WorkspaceRevision: 1, CreatedBy: "usr_alice", Turns: []conversation.Turn{}},
	}
}

// TestConversationListQueryReachesBoundedPage proves the read route forwards an
// exactly validated limit/cursor pair to the narrow ListPage capability and
// projects the server cursor unchanged.
func TestConversationListQueryReachesBoundedPage(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.page = conversation.Page{Conversations: testConversationViews(), NextCursor: "conv_alpha_2"}

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?limit=2&cursor=conv_alpha_1", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if paging.call != "list_page" {
		t.Fatalf("call=%q, want the bounded page capability", paging.call)
	}
	if len(paging.pageCalls) != 1 {
		t.Fatalf("page calls=%v, want exactly one", paging.pageCalls)
	}
	call := paging.pageCalls[0]
	if call.workspaceID != "ws_alpha" || call.limit != 2 || call.cursor != "conv_alpha_1" {
		t.Fatalf("page call=%+v, want ws_alpha/2/conv_alpha_1", call)
	}
	body := response.Body.String()
	for _, want := range []string{`"next_cursor":"conv_alpha_2"`, `"conversation_id":"conv_alpha_1"`, `"conversation_id":"conv_alpha_2"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
}

// TestConversationListCursorWithoutLimitIsAccepted proves a cursor may travel
// without limit; the service owns the default-50 bound.
func TestConversationListCursorWithoutLimitIsAccepted(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.page = conversation.Page{Conversations: testConversationViews()}

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?cursor=conv_alpha_1", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(paging.pageCalls) != 1 || paging.pageCalls[0].limit != 0 || paging.pageCalls[0].cursor != "conv_alpha_1" {
		t.Fatalf("page calls=%v, want limit 0 (service default) and cursor conv_alpha_1", paging.pageCalls)
	}
	if strings.Contains(response.Body.String(), "next_cursor") {
		t.Fatalf("last page emitted a cursor: %s", response.Body.String())
	}
}

// TestConversationListNoQueryKeepsLegacyList proves an absent query still reads
// the legacy first screen through List and never reaches the page capability.
func TestConversationListNoQueryKeepsLegacyList(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.fakeConversationService.list = testConversationViews()

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if paging.call != "list" {
		t.Fatalf("call=%q, want the legacy List path", paging.call)
	}
	if len(paging.pageCalls) != 0 {
		t.Fatalf("legacy read reached the page capability: %v", paging.pageCalls)
	}
}

// TestConversationListRejectsInvalidQuery proves only this route accepts a
// query and every unknown, duplicated, empty, malformed or out-of-range shape
// is refused before any service call.
func TestConversationListRejectsInvalidQuery(t *testing.T) {
	cases := [][2]string{
		{"limit_zero", "?limit=0"},
		{"limit_above_max", "?limit=51"},
		{"limit_not_integer", "?limit=abc"},
		{"limit_empty", "?limit="},
		{"limit_duplicate", "?limit=1&limit=2"},
		{"limit_overflow", "?limit=99999999999999999999"},
		{"limit_plus_sign", "?limit=%2B5"},
		{"limit_leading_space", "?limit=%205"},
		{"cursor_empty", "?cursor="},
		{"cursor_duplicate", "?cursor=conv_alpha_1&cursor=conv_alpha_2"},
		{"cursor_not_opaque", "?cursor=ab"},
		{"cursor_with_space", "?cursor=conv%20alpha"},
		{"unknown_key", "?limit=1&unknown=1"},
		{"too_many_keys", "?limit=1&cursor=conv_alpha_1&x=2"},
		{"bare_question_mark", "?"},
		{"bad_escape", "?limit=%zz"},
		{"semicolon", "?limit=1;cursor=conv_alpha_1"},
		{"cursor_key_without_eq", "?cursor"},
	}
	for _, testCase := range cases {
		name, query := testCase[0], testCase[1]
		t.Run(name, func(t *testing.T) {
			harness, paging := newPagingConversationHarness(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations"+query, ""))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "REQUEST_INVALID") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if paging.call != "" || len(paging.pageCalls) != 0 {
				t.Fatalf("invalid query reached the service: call=%q calls=%v", paging.call, paging.pageCalls)
			}
		})
	}
}

// TestConversationListPaginatedWithoutCapabilityIsUnavailable proves a service
// that does not implement ListPage fails closed for a paginated request: the
// route returns a content-free SERVICE_UNAVAILABLE and never slices the legacy
// first-100 List.
func TestConversationListPaginatedWithoutCapabilityIsUnavailable(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?limit=10", ""))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.conversations.call != "" {
		t.Fatalf("missing-capability request reached the legacy service: call=%q", harness.conversations.call)
	}
	if strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("missing-capability refusal echoed the workspace id: %s", response.Body.String())
	}
}

// TestConversationListPageFailureIsContentFree proves a page-capability failure
// maps through the closed conversation error surface without echoing a cursor
// or workspace id.
func TestConversationListPageFailureIsContentFree(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.pageErr = context.DeadlineExceeded

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?cursor=conv_alpha_1", ""))

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "conv_alpha_1") || strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("failure echoed protected data: %s", response.Body.String())
	}
}
