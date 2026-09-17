package workspaceapi

// Unit coverage for the ADR-0087 §2 REST action
// (POST /api/v1/sources/connections/{id}:verify-trust): success, denied
// (collapsed with not-found into one content-free response), idempotency
// conflict / precondition failure mapping, fail-closed composition and strict
// body validation. The real CONNECTOR_ADMIN policy gate, the SECURITY
// DEFINER door and the actual idempotent-replay behaviour are proved against
// real PostgreSQL in tests/integration/postgres; this file proves only that
// the HTTP layer projects the closed body onto the repository command and
// maps its content-free error surface, exactly as the four ADR-0053
// confirmation actions are proved in workspaceapi_sources_test.go.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const testConnectionID = "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ"

// fakeConnectionTrustAuthorityService embeds the existing fake
// WorkspaceService and additionally implements ConnectionTrustAuthority,
// mirroring the production composition where the same workspace repository
// Store satisfies both interfaces.
type fakeConnectionTrustAuthorityService struct {
	*fakeWorkspaceService
	err     error
	call    string
	access  database.AccessContext
	request workspacerepository.VerifyConnectionTrustRequest
	result  workspacerepository.VerifyConnectionTrustResult
}

func (service *fakeConnectionTrustAuthorityService) VerifyConnectionTrust(_ context.Context, access database.AccessContext, request workspacerepository.VerifyConnectionTrustRequest) (workspacerepository.VerifyConnectionTrustResult, error) {
	service.call, service.access, service.request = "verify_trust", access, request
	return service.result, service.err
}

func newConnectionTrustHarness(t *testing.T) (*testHarness, *fakeConnectionTrustAuthorityService, *Handler) {
	t.Helper()
	harness := newTestHarness(t)
	authority := &fakeConnectionTrustAuthorityService{fakeWorkspaceService: harness.service}
	handler, err := newHandlerWithQuestionsAndConversations(harness.auth, authority, harness.sources, harness.evidence, harness.questions, harness.conversations, fixedRequestIDSource("req_server_001"))
	if err != nil {
		t.Fatal(err)
	}
	return harness, authority, handler
}

const verifyTrustBody = `{"attested_connector_identity":"folder-connector-1","attested_by":"security-team","attested_at":"2026-09-06T12:00:00Z"}`

func verifyTrustPath(connectionID string) string {
	return sourcesPath + "/connections/" + connectionID + ":verify-trust"
}

func TestVerifyConnectionTrustDispatchesClosedCommand(t *testing.T) {
	harness, authority, handler := newConnectionTrustHarness(t)
	authority.result = workspacerepository.VerifyConnectionTrustResult{ResultID: "wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultHash: harness.hash}
	request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), verifyTrustBody)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || authority.call != "verify_trust" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
	got := authority.request
	if got.ConnectionID != testConnectionID || got.IdempotencyKey != harness.idempotencyKey ||
		got.AttestedConnectorIdentity != "folder-connector-1" || got.AttestedBy != "security-team" ||
		got.AttestedAt != "2026-09-06T12:00:00Z" {
		t.Fatalf("verify-trust command not projected: %#v", got)
	}
	if authority.access.OrganizationID != "org_alpha" {
		t.Fatalf("organization not server-derived: %#v", authority.access)
	}
	if !strings.Contains(response.Body.String(), `"wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ"`) {
		t.Fatalf("result missing from response: %s", response.Body.String())
	}
}

func TestVerifyConnectionTrustDeniedAndNotFoundCollapseToSameResponse(t *testing.T) {
	// A caller who is not CONNECTOR_ADMIN is denied by the repository as
	// CodeConnectionTrustDenied; a hidden or absent connection is
	// CodeConnectionTrustNotFound. Both must surface as one identical 404 so
	// no caller can distinguish "wrong role" from "no such connection" (no
	// existence or role oracle).
	var deniedBody, notFoundBody string
	for _, code := range []workspacerepository.ErrorCode{workspacerepository.CodeConnectionTrustDenied, workspacerepository.CodeConnectionTrustNotFound} {
		harness, authority, handler := newConnectionTrustHarness(t)
		authority.err = workspacerepository.NewError(code, nil)
		request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), verifyTrustBody)
		request.Header.Set("Idempotency-Key", harness.idempotencyKey)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || authority.call != "verify_trust" {
			t.Fatalf("code=%s status=%d call=%q body=%s", code, response.Code, authority.call, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"NOT_FOUND"`) || strings.Contains(response.Body.String(), testConnectionID) {
			t.Fatalf("code=%s leaked detail in body: %s", code, response.Body.String())
		}
		if code == workspacerepository.CodeConnectionTrustDenied {
			deniedBody = response.Body.String()
		} else {
			notFoundBody = response.Body.String()
		}
	}
	if deniedBody != notFoundBody {
		t.Fatalf("denied and absent are distinguishable: denied=%q absent=%q", deniedBody, notFoundBody)
	}
}

func TestVerifyConnectionTrustPreconditionAndIdempotencyConflictMapping(t *testing.T) {
	for name, fixture := range map[string]struct {
		code       workspacerepository.ErrorCode
		wantStatus int
		wantBody   string
	}{
		"precondition failed (already verified, not a replay)": {
			workspacerepository.CodeConnectionTrustPreconditionFailed, http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED",
		},
		"idempotency key reused with a different request": {
			workspacerepository.CodeConnectionTrustIdempotencyConflict, http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_IDEMPOTENCY_CONFLICT",
		},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newConnectionTrustHarness(t)
			authority.err = workspacerepository.NewError(fixture.code, nil)
			request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), verifyTrustBody)
			request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || !strings.Contains(response.Body.String(), fixture.wantBody) {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestVerifyConnectionTrustReplayReturnsStoredResultUnchanged(t *testing.T) {
	// The transport layer must be transparent to a true replay: calling twice
	// with the same idempotency key against a repository that always answers
	// with its stored SUCCESS result (as a real replay would) returns the
	// identical result both times, with no second distinct command observed.
	harness, authority, handler := newConnectionTrustHarness(t)
	authority.result = workspacerepository.VerifyConnectionTrustResult{ResultID: "wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultHash: harness.hash}

	for attempt := 0; attempt < 2; attempt++ {
		request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), verifyTrustBody)
		request.Header.Set("Idempotency-Key", harness.idempotencyKey)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ"`) {
			t.Fatalf("attempt=%d status=%d body=%s", attempt, response.Code, response.Body.String())
		}
	}
	if authority.request.IdempotencyKey != harness.idempotencyKey {
		t.Fatalf("idempotency key not carried through: %#v", authority.request)
	}
}

func TestVerifyConnectionTrustFailsClosedWhenAuthorityNotComposed(t *testing.T) {
	harness := newTestHarness(t) // plain fakeWorkspaceService has no ConnectionTrustAuthority
	request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), verifyTrustBody)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || harness.service.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
}

func TestVerifyConnectionTrustRequiresIdempotencyAndStrictBody(t *testing.T) {
	for name, fixture := range map[string]struct {
		body       string
		withKey    bool
		wantStatus int
	}{
		"missing idempotency key":  {verifyTrustBody, false, http.StatusBadRequest},
		"unknown body member":      {`{"attested_connector_identity":"x","attested_by":"y","attested_at":"2026-09-06T12:00:00Z","extra":1}`, true, http.StatusBadRequest},
		"missing required member":  {`{"attested_connector_identity":"x"}`, true, http.StatusBadRequest},
		"empty attested_by member": {`{"attested_connector_identity":"x","attested_by":"","attested_at":"2026-09-06T12:00:00Z"}`, true, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newConnectionTrustHarness(t)
			request := harness.request(http.MethodPost, verifyTrustPath(testConnectionID), fixture.body)
			if fixture.withKey {
				request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || authority.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
			}
		})
	}
}

func TestVerifyConnectionTrustMethodNotAllowed(t *testing.T) {
	harness, authority, handler := newConnectionTrustHarness(t)
	request := harness.request(http.MethodGet, verifyTrustPath(testConnectionID), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || authority.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
}

func TestConnectionTrustErrorMapping(t *testing.T) {
	cases := map[workspacerepository.ErrorCode]struct {
		status int
		code   string
	}{
		workspacerepository.CodeConnectionTrustRequestInvalid:      {http.StatusBadRequest, "REQUEST_INVALID"},
		workspacerepository.CodeConnectionTrustIdempotencyConflict: {http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_IDEMPOTENCY_CONFLICT"},
		workspacerepository.CodeConnectionTrustDenied:              {http.StatusNotFound, "NOT_FOUND"},
		workspacerepository.CodeConnectionTrustNotFound:            {http.StatusNotFound, "NOT_FOUND"},
		workspacerepository.CodeConnectionTrustPreconditionFailed:  {http.StatusConflict, "WORKSPACE_CONNECTION_TRUST_PRECONDITION_FAILED"},
		workspacerepository.CodeConnectionTrustPersistence:         {http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE"},
	}
	for inputCode, want := range cases {
		if status, code := connectionTrustErrorResponse(inputCode); status != want.status || code != want.code {
			t.Fatalf("%s: got status=%d code=%q, want status=%d code=%q", inputCode, status, code, want.status, want.code)
		}
	}
}
