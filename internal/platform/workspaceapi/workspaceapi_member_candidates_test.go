package workspaceapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// P10a transport tests. The member-candidate picker is a read-only, bounded
// search over real ACTIVE USER principals of the caller's own organization,
// authorized to the workspace's OWNER/MANAGER by the injected repository
// Store. This transport layer only checks the query shape (exactly one "q"),
// forwards the workspace and term to the capability, projects the bounded
// result, and maps the content-free error surface. A handler whose service
// does not expose the capability fails closed as SERVICE_UNAVAILABLE.

const memberCandidateTestPath = "/api/v1/workspaces/ws_alpha/member-candidates"

// fakeMemberCandidateService embeds the existing WorkspaceService fake and adds
// the P10a capability, so a handler built with it can exercise the route's
// happy path while the plain fakeWorkspaceService exercises its fail-closed
// surface.
type fakeMemberCandidateService struct {
	*fakeWorkspaceService
	result      workspacerepository.MemberCandidateResult
	err         error
	access      database.AccessContext
	workspaceID string
	query       string
}

func (service *fakeMemberCandidateService) MemberCandidates(_ context.Context, access database.AccessContext, workspaceID, query string) (workspacerepository.MemberCandidateResult, error) {
	service.access, service.workspaceID, service.query = access, workspaceID, query
	return service.result, service.err
}

type memberCandidateHarness struct {
	handler *Handler
	fake    *fakeMemberCandidateService
	token   string
}

// newMemberCandidateHarness wires a handler whose service carries the P10a
// capability, authenticated exactly like newTestHarness.
func newMemberCandidateHarness(t *testing.T) *memberCandidateHarness {
	t.Helper()
	token := testOpaqueToken("session")
	digestor := &testDigestor{}
	// The harness's own request() method computes a fresh CSRF proof for an
	// unsafe method, so this digest is only a reachability check for the fake
	// session resolver and its proof is deliberately unused.
	if _, err := digestor.Digest("csrf", token); err != nil {
		t.Fatal(err)
	}
	claims, err := identity.NewClaims("org_alpha", "usr_alice", 1, "idp_alpha", 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	authenticator, err := httpauth.New(testTenantResolver{digestor: digestor}, testSessionResolver{claims: claims})
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeMemberCandidateService{fakeWorkspaceService: &fakeWorkspaceService{snapshot: testSnapshot(t)}}
	spy := &authSpy{delegate: authenticator}
	handler, err := newHandlerWithQuestionsAndConversations(spy, fake, &fakeSourceService{}, &fakeEvidenceService{}, nil, nil, fixedRequestIDSource("req_member_candidate_001"))
	if err != nil {
		t.Fatal(err)
	}
	return &memberCandidateHarness{handler: handler, fake: fake, token: token}
}

func (harness *memberCandidateHarness) request(method, path string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example"+path, nil)
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+harness.token)
	if unsafeMethod(method) {
		proof, _ := (&testDigestor{}).Digest("csrf", harness.token)
		request.Header.Set("Origin", "https://workspace.example")
		request.Header.Set(httpauth.CSRFHeader, proof.Value())
	}
	return request
}

func TestMemberCandidateRouteProjectsAuthorizedResult(t *testing.T) {
	harness := newMemberCandidateHarness(t)
	harness.fake.result = workspacerepository.MemberCandidateResult{
		Candidates: []workspacerepository.MemberCandidate{
			{PrincipalID: "usr_bob", DisplayName: "Bob", AlreadyMember: false},
			{PrincipalID: "usr_alice", DisplayName: "Alice", AlreadyMember: true},
		},
		Truncated: false,
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, memberCandidateTestPath+"?q=Bob"))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if harness.fake.workspaceID != "ws_alpha" || harness.fake.query != "Bob" {
		t.Fatalf("service saw workspace=%q query=%q", harness.fake.workspaceID, harness.fake.query)
	}
	for _, want := range []string{`"principal_id":"usr_bob"`, `"display_name":"Bob"`, `"already_member":false`, `"principal_id":"usr_alice"`, `"already_member":true`, `"truncated":false`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response %s missing %s", body, want)
		}
	}
	if harness.fake.access.RequestID != "req_member_candidate_001" {
		t.Fatalf("service access request id=%q", harness.fake.access.RequestID)
	}
}

func TestMemberCandidateRouteFailsClosedWithoutCapability(t *testing.T) {
	// A handler whose service implements only WorkspaceService (not the P10a
	// capability) must fail the route closed, not degrade.
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, memberCandidateTestPath+"?q=Bob", ""))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMemberCandidateQueryShapeRejectionKeepsOtherRoutesClosed(t *testing.T) {
	harness := newMemberCandidateHarness(t)
	for name, path := range map[string]string{
		"no query":        memberCandidateTestPath,
		"duplicate q":     memberCandidateTestPath + "?q=Bob&q=Alice",
		"extra parameter": memberCandidateTestPath + "?x=1&q=Bob",
	} {
		name, path := name, path
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, path))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if harness.fake.workspaceID != "" {
				t.Fatalf("invalid query reached the service (workspace=%q)", harness.fake.workspaceID)
			}
		})
	}
}

func TestMemberCandidateQueryShapeRejectsMalformedAndUnknown(t *testing.T) {
	// Strict malformed-query rejection at the transport boundary. Each of these
	// must be diagnosed as REQUEST_INVALID (400) before the service capability
	// is reached, so not one MemberCandidates call is made: url.ParseQuery
	// reports a malformed escape and a stray semicolon instead of silently
	// dropping them (URL.Query()'s behavior), and the shape check refuses a
	// duplicate "q" and any unknown extra parameter.
	harness := newMemberCandidateHarness(t)
	cases := []struct {
		name string
		path string
	}{
		{"malformed escape in extra parameter", memberCandidateTestPath + "?q=valid&bad=%ZZ"},
		{"malformed escape in q value", memberCandidateTestPath + "?q=valid%ZZ"},
		{"semicolon separator", memberCandidateTestPath + "?q=valid;bad=x"},
		{"duplicate q", memberCandidateTestPath + "?q=valid&q=other"},
		{"unknown valid parameter", memberCandidateTestPath + "?q=valid&unknown=value"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, tc.path))
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if harness.fake.workspaceID != "" {
				t.Fatalf("malformed query reached the service (workspace=%q)", harness.fake.workspaceID)
			}
		})
	}

	// The accepted single "q" name search must still be a 200 that reaches the
	// service, so strict malformed-query rejection never loosens the legitimate
	// valid-name route.
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, memberCandidateTestPath+"?q=Alice"))
	if response.Code != http.StatusOK {
		t.Fatalf("valid-name status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.fake.workspaceID != "ws_alpha" {
		t.Fatalf("valid query did not reach the service (workspace=%q)", harness.fake.workspaceID)
	}
}

func TestMemberCandidateQueryPolicyDoesNotLoosenOtherRoutes(t *testing.T) {
	harness := newMemberCandidateHarness(t)
	// The evidence scope and the member-candidate "q" are the only two routes
	// that accept a query string; an ordinary workspace-list GET with a query
	// must still be rejected exactly as before.
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, "/api/v1/workspaces?q=Alice"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestMemberCandidateRouteMapsServiceErrorsContentFree(t *testing.T) {
	notFound := workspacerepository.NewError(workspacerepository.CodeNotFound, errors.New("denied"))
	invalid := workspacerepository.NewError(workspacerepository.CodeRequestInvalid, nil)
	for name, fixture := range map[string]struct {
		err    error
		status int
	}{
		"not found": {notFound, http.StatusNotFound},
		"invalid":   {invalid, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newMemberCandidateHarness(t)
			harness.fake.err = fixture.err
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, memberCandidateTestPath+"?q=Bob"))
			if response.Code != fixture.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMemberCandidateRouteIsReadOnly(t *testing.T) {
	harness := newMemberCandidateHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, memberCandidateTestPath+"?q=Bob"))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("Allow header=%q", response.Header().Get("Allow"))
	}
}
