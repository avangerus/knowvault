package workspaceapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// pagingWorkspaceService adds only the narrow keyset-continuation capability
// on top of the shared workspace test double. Every legacy method is inherited
// unchanged, so these tests exercise the real HTTP wiring rather than a
// rewritten fake.
type pagingWorkspaceService struct {
	*fakeWorkspaceService
	beforeSequenceCalls []int64
	beforeJournal       audit.Journal
	beforeErr           error
}

func (service *pagingWorkspaceService) AuditJournalBefore(_ context.Context, access database.AccessContext, workspaceID string, beforeSequence int64) (audit.Journal, error) {
	service.beforeSequenceCalls = append(service.beforeSequenceCalls, beforeSequence)
	service.journalWorkspaceID = workspaceID
	service.call = "audit_journal_before"
	service.access = access
	return service.beforeJournal, service.beforeErr
}

func newPagingHarness(t *testing.T) (*testHarness, *pagingWorkspaceService) {
	t.Helper()
	harness := newTestHarness(t)
	paging := &pagingWorkspaceService{fakeWorkspaceService: harness.service}
	harness.handler.service = paging
	return harness, paging
}

// TestAuditJournalBeforeSequenceUsesExactCursorAndProjectsCursor proves the
// continuation route parses exactly one positive decimal cursor, passes it
// verbatim to the narrow repository capability, and projects the server cursor
// as a decimal string rather than a JSON number.
func TestAuditJournalBeforeSequenceUsesExactCursorAndProjectsCursor(t *testing.T) {
	harness, paging := newPagingHarness(t)
	nextCursor := int64(4242)
	journal := testJournal()
	journal.Truncated = true
	journal.NextBeforeSequence = &nextCursor
	paging.beforeJournal = journal

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events?before_sequence=100", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if paging.call != "audit_journal_before" {
		t.Fatalf("call=%q, want the continuation capability", paging.call)
	}
	if len(paging.beforeSequenceCalls) != 1 || paging.beforeSequenceCalls[0] != 100 {
		t.Fatalf("before_sequence calls=%v, want [100]", paging.beforeSequenceCalls)
	}
	if paging.journalWorkspaceID != "ws_alpha" {
		t.Fatalf("workspace=%q", paging.journalWorkspaceID)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"workspace_id":"ws_alpha"`,
		`"head_sequence":2`,
		`"next_before_sequence":"4242"`,
		`"truncated":true`,
		`"event_id":"aud_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, `"next_before_sequence":4242`) {
		t.Fatalf("cursor was projected as a JSON number: %s", body)
	}
}

// TestAuditJournalNoQueryKeepsLegacyPathWithoutCursor proves an absent query
// still reads the legacy first screen through AuditJournal and never emits the
// continuation cursor.
func TestAuditJournalNoQueryKeepsLegacyPathWithoutCursor(t *testing.T) {
	harness, paging := newPagingHarness(t)
	paging.fakeWorkspaceService.journal = testJournal()

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if paging.call != "audit_journal" {
		t.Fatalf("call=%q, want the legacy first screen", paging.call)
	}
	if len(paging.beforeSequenceCalls) != 0 {
		t.Fatalf("legacy read reached the continuation capability: %v", paging.beforeSequenceCalls)
	}
	if strings.Contains(response.Body.String(), "next_before_sequence") {
		t.Fatalf("legacy first screen emitted a continuation cursor: %s", response.Body.String())
	}
}

// TestAuditJournalBeforeSequenceRejectsInvalidQuery proves the route rejects
// every malformed, duplicated, unknown or non-positive query shape before any
// service call, including the pre-existing ?limit=1 refusal.
func TestAuditJournalBeforeSequenceRejectsInvalidQuery(t *testing.T) {
	for name, query := range map[string]string{
		"limit_rejected":      "?limit=1",
		"empty_value":         "?before_sequence=",
		"zero":                "?before_sequence=0",
		"negative":            "?before_sequence=-1",
		"plus_sign":           "?before_sequence=%2B1",
		"non_decimal":         "?before_sequence=1e3",
		"hex":                 "?before_sequence=0x10",
		"leading_space":       "?before_sequence=%201",
		"duplicate":           "?before_sequence=1&before_sequence=2",
		"unknown_key":         "?before_sequence=1&limit=1",
		"overflow":            "?before_sequence=9223372036854775808",
		"bad_escape":          "?before_sequence=%zz",
		"semicolon":           "?before_sequence=1;limit=1",
		"bare_question_mark":  "?",
		"empty_and_valid_key": "?before_sequence",
	} {
		name, query := name, query
		t.Run(name, func(t *testing.T) {
			harness, paging := newPagingHarness(t)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events"+query, ""))
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "REQUEST_INVALID") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if paging.call != "" || len(paging.beforeSequenceCalls) != 0 {
				t.Fatalf("invalid query reached the service: call=%q calls=%v", paging.call, paging.beforeSequenceCalls)
			}
		})
	}
}

// TestAuditJournalBeforeSequenceWithoutCapabilityIsUnavailable proves a
// service that does not implement the continuation capability fails closed:
// the route returns a content-free SERVICE_UNAVAILABLE and never falls back to
// an unauthorized first-page read.
func TestAuditJournalBeforeSequenceWithoutCapabilityIsUnavailable(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events?before_sequence=5", ""))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.service.call != "" {
		t.Fatalf("missing-capability request reached the legacy service: call=%q", harness.service.call)
	}
	if strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("missing-capability refusal echoed the workspace id: %s", response.Body.String())
	}
}

// TestAuditJournalBeforeEmptyTailOmitsCursor proves an empty continuation page
// carries no cursor: there is no next page to ask for.
func TestAuditJournalBeforeEmptyTailOmitsCursor(t *testing.T) {
	harness, paging := newPagingHarness(t)
	paging.beforeJournal = audit.Journal{WorkspaceID: "ws_alpha", HeadHash: "sha256:" + strings.Repeat("ab", 32)}

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events?before_sequence=1", ""))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"events":[]`) || !strings.Contains(body, `"truncated":false`) {
		t.Fatalf("empty tail shape wrong: %s", body)
	}
	if strings.Contains(body, "next_before_sequence") {
		t.Fatalf("empty tail emitted a cursor: %s", body)
	}
}

// TestAuditJournalBeforeSequenceDenialIsContentFree proves the continuation
// read applies the same closed denial mapping as the first page: a repository
// denial is one identical 404 with no workspace echo.
func TestAuditJournalBeforeSequenceDenialIsContentFree(t *testing.T) {
	harness, paging := newPagingHarness(t)
	paging.beforeErr = workspacerepository.NewError(workspacerepository.CodeNotFound, nil)

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_foreign/audit-events?before_sequence=9", ""))

	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "ws_foreign") {
		t.Fatalf("continuation denial echoed the workspace id: %s", response.Body.String())
	}
}
