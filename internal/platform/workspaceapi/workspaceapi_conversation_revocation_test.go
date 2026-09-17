package workspaceapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/conversation"
)

// TestConversationListRevokedCursorIsNotFound proves the HTTP boundary of R1:
// once the service reports a cursor whose workspace membership was revoked as
// CONVERSATION_DENIED, the route answers the same content-free 404 NOT_FOUND
// every other conversation denial uses and never leaks the cursor or workspace
// id. The issued cursor must not surface as a 400 REQUEST_INVALID.
func TestConversationListRevokedCursorIsNotFound(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.pageErr = conversation.NewError(conversation.CodeDenied, nil)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?limit=50&cursor=conv_alpha_110", ""))

	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ws_alpha") || strings.Contains(response.Body.String(), "conv_alpha_110") {
		t.Fatalf("denial leaked protected data: %s", response.Body.String())
	}
	if len(paging.pageCalls) != 1 || paging.pageCalls[0].cursor != "conv_alpha_110" {
		t.Fatalf("page calls=%v, want the issued cursor forwarded once", paging.pageCalls)
	}
}

// TestConversationListMissingCursorIsNotFound proves the same content-free 404
// for the NOT_FOUND variant of the R1 denial mapping (wrong workspace/tenant).
func TestConversationListMissingCursorIsNotFound(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.pageErr = conversation.NewError(conversation.CodeNotFound, nil)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?cursor=conv_alpha_110", ""))

	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestConversationListAuthorizedInvalidCursorStaysBadRequest proves that an
// authorized but malformed/foreign cursor still maps to the 400
// REQUEST_INVALID surface the UI treats as a refresh signal, not as an access
// denial. Revocation must not have widened this path.
func TestConversationListAuthorizedInvalidCursorStaysBadRequest(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.pageErr = conversation.NewError(conversation.CodeInvalid, nil)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?limit=50&cursor=conv_alpha_110", ""))

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "REQUEST_INVALID") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestConversationListRevokedCursorTransientUnavailableStaysRetryable proves a
// transient dependency failure (not an access denial) keeps the existing
// SERVICE_UNAVAILABLE retry surface and is never mistaken for a denial.
func TestConversationListRevokedCursorTransientUnavailableStaysRetryable(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.pageErr = conversation.NewError(conversation.CodeUnavailable, nil)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?cursor=conv_alpha_110", ""))

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

// TestConversationListOrdinaryPaginationStillProjectsPage proves the ordinary
// authorized page path (no revocation) still returns the page and the server
// cursor unchanged after the R1 visibility check was added.
func TestConversationListOrdinaryPaginationStillProjectsPage(t *testing.T) {
	harness, paging := newPagingConversationHarness(t)
	paging.page = conversation.Page{Conversations: testConversationViews(), NextCursor: "conv_alpha_2"}

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/conversations?limit=2&cursor=conv_alpha_1", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`"next_cursor":"conv_alpha_2"`, `"conversation_id":"conv_alpha_1"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
	if len(paging.pageCalls) != 1 || paging.pageCalls[0].limit != 2 || paging.pageCalls[0].cursor != "conv_alpha_1" {
		t.Fatalf("page calls=%v, want ws_alpha/2/conv_alpha_1", paging.pageCalls)
	}
}
