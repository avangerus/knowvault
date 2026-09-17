package httpauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestAuthenticateRejectsAbsentDuplicateAndMalformedSessionCookies(t *testing.T) {
	for name, prepare := range map[string]func(*http.Request){
		"absent": func(_ *http.Request) {},
		"duplicate cookie": func(request *http.Request) {
			request.Header.Set("Cookie", SessionCookieName+"="+testSessionToken("first")+"; "+SessionCookieName+"="+testSessionToken("second"))
		},
		"duplicate cookie header": func(request *http.Request) {
			request.Header.Set("Cookie", SessionCookieName+"="+testSessionToken("first"))
			request.Header.Add("Cookie", "other=value")
		},
		"case insensitive duplicate cookie header": func(request *http.Request) {
			request.Header.Set("Cookie", SessionCookieName+"="+testSessionToken("first"))
			request.Header["cookie"] = []string{"other=value"}
		},
		"malformed": func(request *http.Request) {
			request.Header.Set("Cookie", SessionCookieName+"=not-a-canonical-token")
		},
	} {
		name, prepare := name, prepare
		t.Run(name, func(t *testing.T) {
			authenticator, resolver, _ := testAuthenticator(t)
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example/api/v1/workspaces", nil)
			prepare(request)
			if _, err := authenticator.Authenticate(request, "req_auth_cookie"); CodeOf(err) != CodeAuthenticationFailed {
				t.Fatalf("authentication code=%q err=%v", CodeOf(err), err)
			}
			if resolver.calls != 0 {
				t.Fatalf("session resolver called for rejected cookie: %d", resolver.calls)
			}
		})
	}
}

func TestAuthenticateAcceptsExplicitBearerSessionForNonBrowserClients(t *testing.T) {
	authenticator, resolver, digestor := testAuthenticator(t)
	request := httptest.NewRequest(http.MethodPost, "https://workspace.example/api/v1/workspaces/ws_001/questions", nil)
	request.Header.Set("Authorization", "Bearer "+testSessionToken("valid"))
	authentication, err := authenticator.Authenticate(request, "req_auth_bearer")
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || authentication.apiBearer != true {
		t.Fatalf("bearer authentication=%#v calls=%d", authentication, resolver.calls)
	}
	if len(digestor.calls) != 2 || digestor.calls[0].raw != digestor.calls[1].raw {
		t.Fatalf("bearer digest calls=%#v", digestor.calls)
	}
	if err := authenticator.VerifyCSRF(request, authentication); err != nil {
		t.Fatalf("bearer request rejected without browser CSRF headers: %v", err)
	}
}

func TestAuthenticateRejectsAmbiguousOrMalformedBearerTransport(t *testing.T) {
	for name, prepare := range map[string]func(*http.Request){
		"cookie plus bearer": func(request *http.Request) {
			request.Header.Set("Authorization", "Bearer "+testSessionToken("valid"))
			request.Header.Set("Cookie", SessionCookieName+"="+testSessionToken("valid"))
		},
		"duplicate bearer": func(request *http.Request) {
			request.Header.Add("Authorization", "Bearer "+testSessionToken("valid"))
			request.Header.Add("Authorization", "Bearer "+testSessionToken("valid"))
		},
		"wrong scheme":          func(request *http.Request) { request.Header.Set("Authorization", "Basic "+testSessionToken("valid")) },
		"non-canonical spacing": func(request *http.Request) { request.Header.Set("Authorization", "Bearer  "+testSessionToken("valid")) },
	} {
		name, prepare := name, prepare
		t.Run(name, func(t *testing.T) {
			authenticator, resolver, _ := testAuthenticator(t)
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example/api/v1/workspaces", nil)
			prepare(request)
			if _, err := authenticator.Authenticate(request, "req_auth_bad_bearer"); CodeOf(err) != CodeAuthenticationFailed {
				t.Fatalf("authentication code=%q err=%v", CodeOf(err), err)
			}
			if resolver.calls != 0 {
				t.Fatalf("session resolver called for rejected bearer: %d", resolver.calls)
			}
		})
	}
}

func TestAuthenticateFailsClosedOnTenantDigestAndSessionErrors(t *testing.T) {
	request := authenticatedRequest(http.MethodGet)

	t.Run("tenant resolver", func(t *testing.T) {
		authenticator, err := New(&fakeTenantResolver{err: errors.New("tenant unavailable")}, &fakeSessionResolver{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authenticator.Authenticate(request, "req_auth_tenant"); CodeOf(err) != CodeAuthenticationFailed {
			t.Fatalf("tenant failure code=%q err=%v", CodeOf(err), err)
		}
	})
	t.Run("digestor", func(t *testing.T) {
		digestor := &recordingDigestor{err: errors.New("digest unavailable")}
		authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", "https://workspace.example", digestor)}, &fakeSessionResolver{})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authenticator.Authenticate(request, "req_auth_digest"); CodeOf(err) != CodeAuthenticationFailed {
			t.Fatalf("digest failure code=%q err=%v", CodeOf(err), err)
		}
	})
	t.Run("session resolver", func(t *testing.T) {
		resolver := &fakeSessionResolver{err: errors.New("session unavailable")}
		authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", "https://workspace.example", &recordingDigestor{})}, resolver)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := authenticator.Authenticate(request, "req_auth_session"); CodeOf(err) != CodeAuthenticationFailed {
			t.Fatalf("session failure code=%q err=%v", CodeOf(err), err)
		}
	})
}

func TestAuthenticateRejectsInconsistentResolvedSession(t *testing.T) {
	for name, session := range map[string]identityrepository.AuthenticatedSession{
		"missing session id": func() identityrepository.AuthenticatedSession {
			result := testAuthenticatedSession(t, "org_alpha", "req_placeholder")
			result.SessionID = ""
			return result
		}(),
		"claims principal differs from access": func() identityrepository.AuthenticatedSession {
			result := testAuthenticatedSession(t, "org_alpha", "req_placeholder")
			claims, err := identity.NewClaims("org_alpha", "usr_bob", 1, "idp_alpha", 1, time.Now().UTC().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			result.Claims = claims
			return result
		}(),
	} {
		name, session := name, session
		t.Run(name, func(t *testing.T) {
			resolver := &fakeSessionResolver{result: session, reflectRequestID: true}
			authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", "https://workspace.example", &recordingDigestor{})}, resolver)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authenticator.Authenticate(authenticatedRequest(http.MethodGet), "req_inconsistent_session"); CodeOf(err) != CodeAuthenticationFailed {
				t.Fatalf("authentication code=%q err=%v", CodeOf(err), err)
			}
		})
	}
}

func TestAuthenticatePropagatesServerRequestIDAndReturnsOnlyDerivedProof(t *testing.T) {
	authenticator, resolver, digestor := testAuthenticator(t)
	request := authenticatedRequest(http.MethodGet)
	authentication, err := authenticator.Authenticate(request, "req_server_generated")
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || resolver.request.OrganizationID != identity.OrganizationID("org_alpha") || resolver.request.RequestID != "req_server_generated" {
		t.Fatalf("resolver request=%#v calls=%d", resolver.request, resolver.calls)
	}
	if authentication.Session().Access.RequestID != "req_server_generated" || authentication.CSRFToken() == "" {
		t.Fatalf("authentication=%#v", authentication)
	}
	if len(digestor.calls) != 2 || digestor.calls[0].purpose != "session_token" || digestor.calls[1].purpose != "csrf" || digestor.calls[0].raw != digestor.calls[1].raw {
		t.Fatalf("digest calls=%#v", digestor.calls)
	}
}

func TestVerifyCSRFFailsClosedAndExemptsSafeMethods(t *testing.T) {
	authenticator, _, _ := testAuthenticator(t)
	authentication, err := authenticator.Authenticate(authenticatedRequest(http.MethodGet), "req_csrf_auth")
	if err != nil {
		t.Fatal(err)
	}

	for name, request := range map[string]*http.Request{
		"safe get without headers": httptest.NewRequest(http.MethodGet, "https://workspace.example/api/v1/workspaces", nil),
		"missing":                  httptest.NewRequest(http.MethodPost, "https://workspace.example/api/v1/workspaces", nil),
		"wrong origin":             csrfRequest(http.MethodPost, "https://other.example", authentication.CSRFToken()),
		"mismatch":                 csrfRequest(http.MethodPost, "https://workspace.example", "hmac-sha256:k1:"+strings.Repeat("0", 64)),
		"duplicate origin":         duplicateHeaderRequest("Origin", "https://workspace.example", "https://workspace.example", authentication.CSRFToken()),
		"case insensitive duplicate origin": func() *http.Request {
			request := csrfRequest(http.MethodPost, "https://workspace.example", authentication.CSRFToken())
			request.Header["origin"] = []string{"https://workspace.example"}
			return request
		}(),
		"duplicate csrf": duplicateHeaderRequest(CSRFHeader, authentication.CSRFToken(), authentication.CSRFToken(), authentication.CSRFToken()),
		"comma csrf":     csrfRequest(http.MethodPost, "https://workspace.example", authentication.CSRFToken()+",ignored"),
	} {
		name, request := name, request
		t.Run(name, func(t *testing.T) {
			err := authenticator.VerifyCSRF(request, authentication)
			if name == "safe get without headers" {
				if err != nil {
					t.Fatalf("safe method rejected: %v", err)
				}
				return
			}
			if CodeOf(err) != CodeCSRFRejected {
				t.Fatalf("csrf rejection code=%q err=%v", CodeOf(err), err)
			}
		})
	}
	if err := authenticator.VerifyCSRF(csrfRequest(http.MethodPatch, "https://workspace.example", authentication.CSRFToken()), authentication); err != nil {
		t.Fatalf("exact csrf proof rejected: %v", err)
	}
}

func TestAuthenticateRejectsInvalidTenantSecurityContext(t *testing.T) {
	for _, origin := range []string{"", "null", "http://workspace.example", "https://user@workspace.example", "https://workspace.example/path", "https://workspace.example?x=1", "https://workspace.example#fragment", "https://workspace.example:443", "https://WORKSPACE.example", "https://workspace.example."} {
		t.Run(origin, func(t *testing.T) {
			authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", origin, &recordingDigestor{})}, &fakeSessionResolver{})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authenticator.Authenticate(authenticatedRequest(http.MethodGet), "req_invalid_tenant_context"); CodeOf(err) != CodeAuthenticationFailed {
				t.Fatalf("origin %q code=%q err=%v", origin, CodeOf(err), err)
			}
		})
	}
	if _, err := New(nil, &fakeSessionResolver{}); CodeOf(err) != CodeConfigInvalid {
		t.Fatalf("nil tenant resolver code=%q err=%v", CodeOf(err), err)
	}
}

func TestVerifyCSRFUsesExactTenantOrigin(t *testing.T) {
	digestor := &recordingDigestor{}
	resolver := &fakeSessionResolver{result: testAuthenticatedSession(t, "org_alpha", "req_placeholder"), reflectRequestID: true}
	authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", "https://workspace.example:8443", digestor)}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := authenticator.Authenticate(authenticatedRequest(http.MethodGet), "req_exact_origin")
	if err != nil {
		t.Fatal(err)
	}
	if err := authenticator.VerifyCSRF(csrfRequest(http.MethodPost, "https://workspace.example:8443", authentication.CSRFToken()), authentication); err != nil {
		t.Fatalf("exact tenant origin rejected: %v", err)
	}
	if CodeOf(authenticator.VerifyCSRF(csrfRequest(http.MethodPost, "https://workspace.example", authentication.CSRFToken()), authentication)) != CodeCSRFRejected {
		t.Fatal("origin alias accepted")
	}
}

type fakeTenantResolver struct {
	security TenantSecurityContext
	err      error
}

func (resolver *fakeTenantResolver) Resolve(context.Context) (TenantSecurityContext, error) {
	return resolver.security, resolver.err
}

type fakeSessionResolver struct {
	request          identityrepository.ResolveSessionRequest
	result           identityrepository.AuthenticatedSession
	err              error
	calls            int
	reflectRequestID bool
}

func (resolver *fakeSessionResolver) ResolveSession(_ context.Context, request identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	resolver.calls++
	resolver.request = request
	if resolver.err != nil {
		return identityrepository.AuthenticatedSession{}, resolver.err
	}
	result := resolver.result
	if resolver.reflectRequestID {
		result.Access.RequestID = request.RequestID
	}
	return result, nil
}

type digestCall struct {
	purpose string
	raw     string
}

type recordingDigestor struct {
	calls []digestCall
	err   error
}

func (digestor *recordingDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	digestor.calls = append(digestor.calls, digestCall{purpose: purpose, raw: raw})
	if digestor.err != nil {
		return identity.KeyedDigest{}, digestor.err
	}
	digest := sha256.Sum256([]byte(purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + fmt.Sprintf("%x", digest[:]))
}

func testAuthenticator(t *testing.T) (*Authenticator, *fakeSessionResolver, *recordingDigestor) {
	t.Helper()
	digestor := &recordingDigestor{}
	resolver := &fakeSessionResolver{result: testAuthenticatedSession(t, "org_alpha", "req_placeholder"), reflectRequestID: true}
	authenticator, err := New(&fakeTenantResolver{security: testTenantSecurityContext("org_alpha", "https://workspace.example", digestor)}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	return authenticator, resolver, digestor
}

func testTenantSecurityContext(organizationID identity.OrganizationID, origin string, digestor Digestor) TenantSecurityContext {
	return TenantSecurityContext{OrganizationID: organizationID, Origin: origin, Digestor: digestor}
}

func testAuthenticatedSession(t *testing.T, organizationID, requestID string) identityrepository.AuthenticatedSession {
	t.Helper()
	claims, err := identity.NewClaims(identity.OrganizationID(organizationID), "usr_alice", 1, "idp_alpha", 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return identityrepository.AuthenticatedSession{
		SessionID: "ses_alpha", Claims: claims,
		Access: database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_alice", RequestID: requestID},
	}
}

func authenticatedRequest(method string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example/api/v1/workspaces", nil)
	request.Header.Set("Cookie", SessionCookieName+"="+testSessionToken("valid"))
	return request
}

func csrfRequest(method, origin, proof string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example/api/v1/workspaces", nil)
	request.Header.Set("Origin", origin)
	request.Header.Set(CSRFHeader, proof)
	return request
}

func duplicateHeaderRequest(name, first, second, proof string) *http.Request {
	request := csrfRequest(http.MethodPost, "https://workspace.example", proof)
	request.Header.Del(name)
	request.Header.Add(name, first)
	request.Header.Add(name, second)
	return request
}

func testSessionToken(label string) string {
	digest := sha256.Sum256([]byte("session-token:" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
