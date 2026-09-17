package oidcweb

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

// fakeHTTPTenantResolver adapts the fixture security context to the httpauth
// boundary so the logout unit tests exercise the real cookie+CSRF verifier.
type fakeHTTPTenantResolver struct {
	security tenantsecurity.Context
	err      error
}

func (resolver fakeHTTPTenantResolver) Resolve(context.Context) (httpauth.TenantSecurityContext, error) {
	if resolver.err != nil {
		return httpauth.TenantSecurityContext{}, resolver.err
	}
	return httpauth.TenantSecurityContext{
		OrganizationID: resolver.security.OrganizationID(),
		Origin:         resolver.security.PublicOrigin(),
		Digestor:       resolver.security.SessionDigestor(),
	}, nil
}

// fakeSessionResolver serves the fixture session to the real httpauth
// Authenticator; setting err models an unknown, foreign or revoked session.
type fakeSessionResolver struct {
	session identityrepository.AuthenticatedSession
	err     error
}

func (resolver *fakeSessionResolver) ResolveSession(_ context.Context, request identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	if resolver.err != nil {
		return identityrepository.AuthenticatedSession{}, resolver.err
	}
	if resolver.session.Access.OrganizationID != string(request.OrganizationID) || resolver.session.Access.RequestID != request.RequestID {
		return identityrepository.AuthenticatedSession{}, errors.New("wrong resolved session scope")
	}
	return resolver.session, nil
}

func authenticatedLogoutRequest(fixture *handlerFixture) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "https://workspace.example/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: httpauth.SessionCookieName, Value: fixture.sessionToken})
	request.Header.Set("Origin", "https://workspace.example")
	request.Header.Set(httpauth.CSRFHeader, fixture.csrfProof)
	return request
}

func assertTerminationFailure(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized || !strings.Contains(responseBody(response), "SESSION_TERMINATION_FAILED") {
		t.Fatalf("status=%d body=%q, want closed 401 SESSION_TERMINATION_FAILED", response.Code, response.Body.String())
	}
	assertStandardResponseHeaders(t, response)
}

// TestLogoutRevokesExactSessionThenExpiresCookie proves the success path:
// the presented session is revoked with the authenticated principal scope,
// the cookie is cleared in the same response and the route answers 204.
func TestLogoutRevokesExactSessionThenExpiresCookie(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, authenticatedLogoutRequest(fixture))

	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	wantOrder := []string{"revoke", "expire"}
	if got := fixture.events; !sameStrings(got, wantOrder) {
		t.Fatalf("order=%v want=%v", got, wantOrder)
	}
	revoke := fixture.store.revokeRequest
	if revoke.OrganizationID != fixture.security.OrganizationID() || revoke.SessionID != "sess_001" ||
		revoke.PrincipalID != "principal_001" || revoke.RequestID != "req_001" || revoke.AuditEventID != "audit_001" {
		t.Fatalf("revoke request=%#v", revoke)
	}
	cookies := response.Header().Values("Set-Cookie")
	if len(cookies) != 1 || !strings.Contains(cookies[0], "session=expired") || !strings.Contains(cookies[0], "Max-Age=0") {
		t.Fatalf("cookies=%v", cookies)
	}
	if len(fixture.store.failureRequests) != 0 {
		t.Fatalf("unexpected failure events: %#v", fixture.store.failureRequests)
	}
	assertStandardResponseHeaders(t, response)
}

// TestLogoutMethodIsClosedToGET proves a plain GET link can never perform a
// logout (ADR-0075 §1.1): the method gate answers 405 without touching the
// session or writing any audit event.
func TestLogoutMethodIsClosedToGET(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/logout", nil))

	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
	if fixture.store.revokeCalls != 0 || fixture.sessions.expireCalls != 0 || len(fixture.store.failureRequests) != 0 {
		t.Fatalf("GET logout reached the session: revoke=%d expire=%d failures=%d", fixture.store.revokeCalls, fixture.sessions.expireCalls, len(fixture.store.failureRequests))
	}
}

// TestLogoutCSRFRejectionIsClosedAndAudited proves a POST without the exact
// CSRF proof answers the shared closed code and records one FAILED event for
// the authenticated principal (ADR-0075 §5).
func TestLogoutCSRFRejectionIsClosedAndAudited(t *testing.T) {
	fixture := newHandlerFixture(t)
	request := httptest.NewRequest(http.MethodPost, "https://workspace.example/auth/logout", nil)
	request.AddCookie(&http.Cookie{Name: httpauth.SessionCookieName, Value: fixture.sessionToken})
	request.Header.Set("Origin", "https://workspace.example")
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, request)

	assertTerminationFailure(t, response)
	if fixture.store.revokeCalls != 0 || fixture.sessions.expireCalls != 0 {
		t.Fatalf("CSRF-rejected logout touched the session: revoke=%d expire=%d", fixture.store.revokeCalls, fixture.sessions.expireCalls)
	}
	if len(fixture.store.failureRequests) != 1 {
		t.Fatalf("failure events=%d", len(fixture.store.failureRequests))
	}
	failure := fixture.store.failureRequests[0]
	if failure.PrincipalID == nil || *failure.PrincipalID != "principal_001" || failure.SessionID == nil || *failure.SessionID != "sess_001" {
		t.Fatalf("failure request=%#v", failure)
	}
}

// TestLogoutUnknownSessionIsClosedAndAuditedWithoutIdentity proves a foreign,
// unknown or revoked session receives exactly the same response and a FAILED
// event that carries no principal or session id (no validity oracle).
func TestLogoutUnknownSessionIsClosedAndAuditedWithoutIdentity(t *testing.T) {
	for name, arrange := range map[string]func(*handlerFixture){
		"unknown session": func(fixture *handlerFixture) { fixture.sessionResolver.err = errors.New("not found") },
		"malformed cookie": func(fixture *handlerFixture) {
			fixture.sessionToken = "not-a-valid-session-token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			arrange(fixture)
			response := httptest.NewRecorder()

			fixture.handler.ServeHTTP(response, authenticatedLogoutRequest(fixture))

			assertTerminationFailure(t, response)
			if fixture.store.revokeCalls != 0 || fixture.sessions.expireCalls != 0 {
				t.Fatalf("unknown-session logout touched the session: revoke=%d expire=%d", fixture.store.revokeCalls, fixture.sessions.expireCalls)
			}
			if len(fixture.store.failureRequests) != 1 {
				t.Fatalf("failure events=%d", len(fixture.store.failureRequests))
			}
			failure := fixture.store.failureRequests[0]
			if failure.PrincipalID != nil || failure.SessionID != nil {
				t.Fatalf("failure request leaked session identity: %#v", failure)
			}
		})
	}
}

// TestLogoutAlreadyRevokedSessionIsClosedWithoutEvents proves the idempotent
// branch (ADR-0075 §6): an already-revoked session answers the shared closed
// code, the state does not change and no event is duplicated.
func TestLogoutAlreadyRevokedSessionIsClosedWithoutEvents(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.store.revokeOutcome = identityrepository.RevocationOutcome{Revoked: false}
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, authenticatedLogoutRequest(fixture))

	assertTerminationFailure(t, response)
	if fixture.sessions.expireCalls != 0 {
		t.Fatalf("cookie expired for an already-revoked session: %d", fixture.sessions.expireCalls)
	}
	if len(fixture.store.failureRequests) != 0 {
		t.Fatalf("already-revoked logout duplicated events: %#v", fixture.store.failureRequests)
	}
}

// TestLogoutRejectsBodyQueryAndBadOrigin proves the route accepts nothing but
// an exact empty POST body without query, and that a wrong Origin answers the
// same closed code as every other failure.
func TestLogoutRejectsBodyQueryAndBadOrigin(t *testing.T) {
	for name, arrange := range map[string]func(*handlerFixture, *http.Request){
		"request body": func(_ *handlerFixture, request *http.Request) {
			request.Body = ioNopCloser("unexpected-body")
			request.ContentLength = int64(len("unexpected-body"))
		},
		"query": func(_ *handlerFixture, request *http.Request) {
			request.URL.RawQuery = "next=/"
		},
		"wrong origin": func(fixture *handlerFixture, request *http.Request) {
			request.Header.Set("Origin", "https://attacker.example")
			request.Header.Set(httpauth.CSRFHeader, fixture.csrfProof)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			request := authenticatedLogoutRequest(fixture)
			arrange(fixture, request)
			response := httptest.NewRecorder()

			fixture.handler.ServeHTTP(response, request)

			assertTerminationFailure(t, response)
			if fixture.store.revokeCalls != 0 || fixture.sessions.expireCalls != 0 {
				t.Fatalf("rejected logout touched the session: revoke=%d expire=%d", fixture.store.revokeCalls, fixture.sessions.expireCalls)
			}
		})
	}
}

// TestLogoutRevocationFailureStaysClosed proves a store failure cannot turn
// into a distinct response shape: the same closed code answers, without an
// audit failure event from the handler itself.
func TestLogoutRevocationFailureStaysClosed(t *testing.T) {
	fixture := newHandlerFixture(t)
	fixture.store.revokeErr = errors.New("database unavailable")
	response := httptest.NewRecorder()

	fixture.handler.ServeHTTP(response, authenticatedLogoutRequest(fixture))

	assertTerminationFailure(t, response)
	if fixture.sessions.expireCalls != 0 {
		t.Fatalf("cookie expired although revocation failed: %d", fixture.sessions.expireCalls)
	}
}
