package workspaceapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

func testJournal() audit.Journal {
	principal := "usr_alice"
	onBehalfOf := "usr_owner"
	policyDecision := "pdec_01"
	reason := "POLICY_ALLOWED"
	deniedCode := string(workspacerepository.CodeDenied)
	return audit.Journal{
		WorkspaceID:  "ws_alpha",
		HeadSequence: 2,
		HeadHash:     "sha256:" + strings.Repeat("ab", 32),
		Truncated:    true,
		Events: []audit.JournalEntry{
			{
				EventID: "aud_01H9ABCDEFGHJKMNPQRSTVWXYZ", Sequence: 2, Action: audit.ActionWorkspaceCreated,
				ResourceType: audit.ResourceWorkspace, ResourceID: "ws_alpha", ActorType: audit.ActorHuman,
				ActorPrincipalID: &principal, OnBehalfOfPrincipalID: &onBehalfOf, RequestID: "req_alpha_01",
				PolicyDecisionID: &policyDecision, Outcome: audit.OutcomeSuccess,
				ReferencedEvidenceIDs: []string{"evd_frag_01"}, Metadata: audit.Metadata{ReasonCodes: []string{reason}},
				PreviousEventHash: "sha256:" + strings.Repeat("cd", 32),
				EventHash:         "sha256:" + strings.Repeat("ef", 32),
				OccurredAt:        time.Date(2026, 8, 15, 9, 30, 0, 0, time.UTC),
			},
			{
				EventID: "aud_01H9ABCDEFGHJKMNPQRSTVWXY0", Sequence: 1, Action: audit.ActionWorkspaceMemberAdded,
				ResourceType: audit.ResourceWorkspaceMember, ResourceID: "mem_01", ActorType: audit.ActorHuman,
				ActorPrincipalID: &principal, RequestID: "req_alpha_02", Outcome: audit.OutcomeDenied,
				ErrorCode:             &deniedCode,
				ReferencedEvidenceIDs: []string{},
				Metadata:              audit.Metadata{ReasonCodes: []string{"POLICY_WORKSPACE_MEMBERSHIP_ABSENT"}},
				PreviousEventHash:     "sha256:" + strings.Repeat("12", 32),
				EventHash:             "sha256:" + strings.Repeat("34", 32),
				OccurredAt:            time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC),
			},
		},
	}
}

// TestAuditJournalReturnsPersistedEvents proves the surface contract of the
// R4 journal: every field in the response body is a value persisted by the
// system (projected through audit.Journal), the chain head is included, and
// no internal chain material such as canonical_bytes appears.
func TestAuditJournalReturnsPersistedEvents(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.journal = testJournal()
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.service.call != "audit_journal" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
	if harness.service.journalWorkspaceID != "ws_alpha" {
		t.Fatalf("service got workspace=%q", harness.service.journalWorkspaceID)
	}
	if harness.service.access.RequestID != "req_server_001" {
		t.Fatalf("service did not receive authenticated access context: %#v", harness.service.access)
	}
	if harness.auth.csrfCalls != 0 {
		t.Fatalf("GET route must not require CSRF, csrf=%d", harness.auth.csrfCalls)
	}
	body := response.Body.String()
	for _, want := range []string{
		`"workspace_id":"ws_alpha"`,
		`"head_sequence":2`,
		`"head_hash":"sha256:` + strings.Repeat("ab", 32) + `"`,
		`"truncated":true`,
		`"event_id":"aud_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		`"on_behalf_of_principal_id":"usr_owner"`,
		`"policy_decision_id":"pdec_01"`,
		`"referenced_evidence_ids":["evd_frag_01"]`,
		`"sequence":2`,
		`"action":"workspace.created"`,
		`"resource_type":"WORKSPACE"`,
		`"resource_id":"ws_alpha"`,
		`"actor_type":"HUMAN"`,
		`"actor_principal_id":"usr_alice"`,
		`"request_id":"req_alpha_01"`,
		`"outcome":"SUCCESS"`,
		`"reason_codes":["POLICY_ALLOWED"]`,
		`"previous_event_hash":"sha256:` + strings.Repeat("cd", 32) + `"`,
		`"event_hash":"sha256:` + strings.Repeat("ef", 32) + `"`,
		`"occurred_at":"2026-08-15T09:30:00Z"`,
		`"outcome":"DENIED"`,
		`"error_code":"WORKSPACE_DENIED"`,
		`"reason_codes":["POLICY_WORKSPACE_MEMBERSHIP_ABSENT"]`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %s: %s", want, body)
		}
	}
	if strings.Contains(body, "canonical_bytes") {
		t.Fatalf("response leaked internal chain material: %s", body)
	}
}

// TestAuditJournalEmptyPageSerializesAsArray proves the surface never emits
// "events":null: an empty journal page is an empty array and the truncation
// flag stays false, so a client reading the length of an empty stream never
// crashes on null.
func TestAuditJournalEmptyPageSerializesAsArray(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.journal = audit.Journal{WorkspaceID: "ws_alpha", HeadHash: "sha256:" + strings.Repeat("ab", 32)}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"events":[]`) {
		t.Fatalf("empty journal page did not serialize as an empty array: %s", body)
	}
	if !strings.Contains(body, `"truncated":false`) {
		t.Fatalf("empty journal page did not serialize the truncation flag: %s", body)
	}
}

// TestAuditJournalDenialsAreIndistinguishable proves the journal has no
// existence oracle: absence and policy denial are one identical 404 NOT_FOUND
// body, and no workspace or event identifier echoes. An infrastructure
// failure stays a typed SERVICE_UNAVAILABLE and never leaks its cause.
func TestAuditJournalDenialsAreIndistinguishable(t *testing.T) {
	for name, err := range map[string]error{
		"not_found": workspacerepository.NewError(workspacerepository.CodeNotFound, nil),
		"denied":    workspacerepository.NewError(workspacerepository.CodeDenied, nil),
	} {
		name, err := name, err
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.service.err = err
			request := harness.request(http.MethodGet, workspacesPath+"/ws_foreign/audit-events", "")
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "ws_foreign") {
				t.Fatalf("denial echoed the workspace id: %s", response.Body.String())
			}
		})
	}
}

func TestAuditJournalInfrastructureFailureIsTypedAndContentFree(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.err = errors.New("database host includes sensitive detail")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events", ""))
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sensitive detail") || strings.Contains(response.Body.String(), "ws_alpha") {
		t.Fatalf("failure leaked a cause or workspace id: %s", response.Body.String())
	}
}

// TestAuditJournalRouteRejectsMalformedIdentifiersAndMethods proves the
// journal is an exact-match GET route: unsafe methods are rejected with an
// Allow header, structurally invalid paths and query strings never reach the
// service, and an invalid opaque workspace id is refused at routing.
func TestAuditJournalRouteRejectsMalformedIdentifiersAndMethods(t *testing.T) {
	t.Run("post_method_not_allowed", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodPost, workspacesPath+"/ws_alpha/audit-events", ""))
		if response.Code != http.StatusMethodNotAllowed || harness.service.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
		}
		if response.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("Allow=%q", response.Header().Get("Allow"))
		}
	})
	t.Run("extra_segment_never_reaches_service", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events/extra", ""))
		if response.Code != http.StatusNotFound || harness.service.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
		}
	})
	t.Run("query_string_rejected", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/audit-events?limit=1", ""))
		if response.Code != http.StatusBadRequest || harness.service.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), "REQUEST_INVALID") {
			t.Fatalf("body=%s", response.Body.String())
		}
	})
	t.Run("invalid_workspace_id_never_reaches_service", func(t *testing.T) {
		harness := newTestHarness(t)
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/not%20an%20id/audit-events", ""))
		if response.Code != http.StatusNotFound || harness.service.call != "" {
			t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
		}
	})
}
