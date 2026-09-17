package oidcweb

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/browserauth"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/oidctransport"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

var handlerTestNow = time.Date(2026, time.July, 15, 11, 30, 0, 0, time.UTC)

func TestLoginOrdersDurableCommitBeforeCookieAndPersistsExactProofs(t *testing.T) {
	fixture := newHandlerFixture(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/login", nil)

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != fixture.client.authorizationURL {
		t.Fatalf("status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	wantOrder := []string{"load", "discover", "attempt", "prepare", "begin", "issue"}
	if got := fixture.events; !sameStrings(got, wantOrder) {
		t.Fatalf("order=%v want=%v", got, wantOrder)
	}
	if fixture.browser.issueBeforeBegin || !fixture.store.beginCalled {
		t.Fatalf("cookie issue occurred before durable BeginLogin: %+v", fixture.browser)
	}
	if len(response.Header().Values("Set-Cookie")) != 1 || !strings.Contains(response.Header().Get("Set-Cookie"), "oidc=issued") {
		t.Fatalf("cookies=%v", response.Header().Values("Set-Cookie"))
	}
	if got, want := response.Header().Get("X-Request-ID"), "req_001"; got != want {
		t.Fatalf("request id=%q want=%q", got, want)
	}
	assertStandardResponseHeaders(t, response)

	requestValue := fixture.store.beginRequest
	if requestValue.OrganizationID != fixture.security.OrganizationID() || requestValue.ProviderID != fixture.security.ProviderID() ||
		requestValue.ProviderRevision != fixture.configuration.Revision || requestValue.LoginAttemptID != "login_001" || requestValue.RequestID != "req_001" ||
		!requestValue.ExpiresAt.Equal(handlerTestNow.Add(loginLifetime)) {
		t.Fatalf("begin request=%#v", requestValue)
	}
	assertAttemptDigests(t, fixture.attempt, requestValue.StateDigest, requestValue.NonceDigest, requestValue.PKCEVerifierDigest, requestValue.BrowserBindingDigest)
	if fixture.browser.preparedRecord.AttemptID() != requestValue.LoginAttemptID || fixture.browser.preparedRecord.ProviderRevision() != requestValue.ProviderRevision {
		t.Fatalf("prepared record does not bind durable attempt: %#v", fixture.browser.preparedRecord)
	}
}

func TestLoginNeverIssuesCookieBeforeBeginSucceeds(t *testing.T) {
	for name, arrange := range map[string]func(*handlerFixture){
		"discovery failure": func(fixture *handlerFixture) { fixture.protocol.discoverErr = errors.New("private discovery failure") },
		"prepare failure":   func(fixture *handlerFixture) { fixture.browser.prepareErr = errors.New("sealed material") },
		"nil prepared capability": func(fixture *handlerFixture) {
			fixture.browser.prepareOverride, fixture.browser.prepared = true, nil
		},
		"typed nil prepared capability": func(fixture *handlerFixture) {
			fixture.browser.prepareOverride, fixture.browser.prepared = true, (*fakePreparedCookie)(nil)
		},
		"begin failure": func(fixture *handlerFixture) { fixture.store.beginErr = errors.New("database unavailable") },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			arrange(fixture)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/login", nil))

			if response.Code != http.StatusServiceUnavailable || !strings.Contains(responseBody(response), "AUTH_UNAVAILABLE") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if fixture.browser.issueCalls != 0 || strings.Contains(response.Header().Get("Set-Cookie"), "oidc=issued") {
				t.Fatalf("issued cookie despite %s: calls=%d headers=%v", name, fixture.browser.issueCalls, response.Header().Values("Set-Cookie"))
			}
			assertStandardResponseHeaders(t, response)
		})
	}
}

func TestCallbackClearsThenCompletesExactRevisionAndOnlyThenIssuesSession(t *testing.T) {
	fixture := newHandlerFixture(t)
	// FIX-7 #3: the OIDC ID token's own exp is deliberately irrelevant to the
	// app session's expiry now (that binding was the root cause of the
	// owner's repeated live mid-shift logout) -- an arbitrary, even
	// far-future, subject.ExpiresAt must not change complete.SessionExpiresAt
	// below at all.
	fixture.client.subject.ExpiresAt = handlerTestNow.Add(48 * time.Hour)
	state, _, _, _, ok := fixture.attempt.TransportMaterial()
	if !ok {
		t.Fatal("test attempt did not release fresh material")
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback?code=callback-code&state="+state, nil)

	fixture.handler.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("status=%d location=%q events=%v", response.Code, response.Header().Get("Location"), fixture.events)
	}
	wantOrder := []string{"clear", "open", "pending", "discover", "secret", "exchange", "complete", "session"}
	if got := fixture.events; !sameStrings(got, wantOrder) {
		t.Fatalf("order=%v want=%v", got, wantOrder)
	}
	if fixture.sessions.issueBeforeComplete || !fixture.store.completeCalled {
		t.Fatalf("session was issued before CompleteLogin: %+v", fixture.sessions)
	}
	if got := response.Header().Values("Set-Cookie"); len(got) != 2 || !strings.Contains(got[0], "oidc=cleared") || !strings.Contains(got[1], "session=issued") {
		t.Fatalf("cookies=%v", got)
	}
	assertStandardResponseHeaders(t, response)
	expectedSecretRequest := ClientSecretRequest{
		OrganizationID: fixture.security.OrganizationID(), ProviderID: fixture.security.ProviderID(), ProviderRevision: fixture.pendingConfiguration.Revision,
		Reference: fixture.pendingConfiguration.ClientSecretReference,
	}
	if fixture.secrets.request != expectedSecretRequest {
		t.Fatalf("secret request=%#v want=%#v", fixture.secrets.request, expectedSecretRequest)
	}

	pending := fixture.store.pendingRequest
	if pending.OrganizationID != fixture.security.OrganizationID() || pending.ProviderID != fixture.security.ProviderID() ||
		pending.ProviderRevision != fixture.record.ProviderRevision() || pending.LoginAttemptID != fixture.record.AttemptID() || pending.RequestID != "req_001" {
		t.Fatalf("pending request=%#v", pending)
	}
	assertAttemptDigests(t, fixture.attempt, pending.StateDigest, pending.NonceDigest, pending.PKCEVerifierDigest, pending.BrowserBindingDigest)
	complete := fixture.store.completeRequest
	if complete.ProviderRevision != fixture.record.ProviderRevision() || complete.LoginAttemptID != fixture.record.AttemptID() || complete.RequestID != "req_001" ||
		complete.SessionID != "sess_001" || complete.AuditEventID != "audit_001" || !complete.SessionExpiresAt.Equal(handlerTestNow.Add(initialSessionLife)) {
		t.Fatalf("complete request=%#v", complete)
	}
	assertAttemptDigests(t, fixture.attempt, complete.StateDigest, complete.NonceDigest, complete.PKCEVerifierDigest, complete.BrowserBindingDigest)
	if complete.ExternalSubjectDigest != fixture.client.subject.Digest || complete.SessionTokenDigest != fixture.sessions.material.Digest() {
		t.Fatalf("complete digests did not bind subject/session")
	}
}

func TestCallbackRejectsMismatchedClientSecretScope(t *testing.T) {
	for name, changeExpected := range map[string]func(*ClientSecretRequest){
		"organization": func(request *ClientSecretRequest) { request.OrganizationID = "org_other" },
		"provider":     func(request *ClientSecretRequest) { request.ProviderID = "provider_other" },
		"revision":     func(request *ClientSecretRequest) { request.ProviderRevision++ },
		"reference":    func(request *ClientSecretRequest) { request.Reference = "secret_ref_other" },
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			changeExpected(&fixture.secrets.expected)
			state, _, _, _, ok := fixture.attempt.TransportMaterial()
			if !ok {
				t.Fatal("test attempt did not release fresh material")
			}
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback?code=code&state="+state, nil))

			if response.Code != http.StatusServiceUnavailable || fixture.sessions.issueCalls != 0 || fixture.store.completeCalled {
				t.Fatalf("status=%d session=%d complete=%t", response.Code, fixture.sessions.issueCalls, fixture.store.completeCalled)
			}
			wantRequest := ClientSecretRequest{
				OrganizationID: fixture.security.OrganizationID(), ProviderID: fixture.security.ProviderID(), ProviderRevision: fixture.pendingConfiguration.Revision,
				Reference: fixture.pendingConfiguration.ClientSecretReference,
			}
			if fixture.secrets.request != wantRequest {
				t.Fatalf("secret request=%#v want=%#v", fixture.secrets.request, wantRequest)
			}
		})
	}
}

func TestCallbackRejectsMalformedStateMismatchAndProtocolDenialWithoutLeaks(t *testing.T) {
	for name, arrange := range map[string]func(*handlerFixture, *http.Request){
		"duplicate query": func(_ *handlerFixture, request *http.Request) {
			request.URL.RawQuery = "code=one&code=two&state=expected"
		},
		"unknown query": func(_ *handlerFixture, request *http.Request) {
			request.URL.RawQuery = "code=one&state=expected&error=access_denied"
		},
		"request body": func(_ *handlerFixture, request *http.Request) {
			request.Body = ioNopCloser("unexpected-body")
			request.ContentLength = int64(len("unexpected-body"))
		},
		"state mismatch": func(fixture *handlerFixture, request *http.Request) {
			request.URL.RawQuery = "code=very-sensitive-code&state=not-the-browser-state"
			fixture.browser.openRecord = fixture.record
		},
		"exchange denial": func(fixture *handlerFixture, _ *http.Request) {
			fixture.client.exchangeErr = errors.New("provider returned secret explanation")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			state, _, _, _, ok := fixture.attempt.TransportMaterial()
			if !ok {
				t.Fatal("test attempt did not release fresh material")
			}
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback?code=very-sensitive-code&state="+state, nil)
			arrange(fixture, request)
			response := httptest.NewRecorder()

			fixture.handler.ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || !strings.Contains(responseBody(response), "AUTH_CALLBACK_FAILED") {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			if fixture.browser.clearCalls != 1 || len(response.Header().Values("Set-Cookie")) == 0 || !strings.Contains(response.Header().Values("Set-Cookie")[0], "oidc=cleared") {
				t.Fatalf("transport cookie was not cleared first: calls=%d cookies=%v", fixture.browser.clearCalls, response.Header().Values("Set-Cookie"))
			}
			if fixture.store.completeCalled || fixture.sessions.issueCalls != 0 {
				t.Fatalf("rejected callback completed a login: complete=%t issue=%d", fixture.store.completeCalled, fixture.sessions.issueCalls)
			}
			for _, raw := range []string{"very-sensitive-code", "not-the-browser-state", "provider returned secret explanation", fixture.secrets.secret} {
				if strings.Contains(response.Body.String(), raw) {
					t.Fatalf("response leaked raw input/error %q: %q", raw, response.Body.String())
				}
			}
			assertStandardResponseHeaders(t, response)
		})
	}
}

func TestCallbackReplayAndUnavailableDependenciesClearTransportCookie(t *testing.T) {
	for name, arrange := range map[string]struct {
		arrange    func(*handlerFixture)
		wantStatus int
	}{
		"replayed browser proof": {
			arrange:    func(fixture *handlerFixture) { fixture.browser.openErr = errors.New("replayed browser envelope") },
			wantStatus: http.StatusBadRequest,
		},
		"pending store unavailable": {
			arrange:    func(fixture *handlerFixture) { fixture.store.pendingErr = errors.New("database dependency") },
			wantStatus: http.StatusServiceUnavailable,
		},
		"secret unavailable": {
			arrange:    func(fixture *handlerFixture) { fixture.secrets.err = errors.New("secret manager failed") },
			wantStatus: http.StatusServiceUnavailable,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newHandlerFixture(t)
			state, _, _, _, ok := fixture.attempt.TransportMaterial()
			if !ok {
				t.Fatal("test attempt did not release fresh material")
			}
			arrange.arrange(fixture)
			response := httptest.NewRecorder()
			fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback?code=code&state="+state, nil))

			if response.Code != arrange.wantStatus || fixture.browser.clearCalls != 1 {
				t.Fatalf("status=%d clear=%d", response.Code, fixture.browser.clearCalls)
			}
			if fixture.sessions.issueCalls != 0 {
				t.Fatal("session issued for failed callback")
			}
		})
	}
}

func TestHandlerRejectsRedirectMismatchAndStrictRoutes(t *testing.T) {
	t.Run("login redirect mismatch", func(t *testing.T) {
		fixture := newHandlerFixture(t)
		fixture.configuration.RedirectURL = "https://attacker.example/auth/callback"
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/login", nil))
		if response.Code != http.StatusServiceUnavailable || fixture.protocol.discoverCalls != 0 || fixture.browser.issueCalls != 0 {
			t.Fatalf("status=%d discover=%d issue=%d", response.Code, fixture.protocol.discoverCalls, fixture.browser.issueCalls)
		}
	})
	t.Run("callback redirect mismatch", func(t *testing.T) {
		fixture := newHandlerFixture(t)
		fixture.pendingConfiguration.RedirectURL = "https://attacker.example/auth/callback"
		state, _, _, _, ok := fixture.attempt.TransportMaterial()
		if !ok {
			t.Fatal("test attempt did not release fresh material")
		}
		response := httptest.NewRecorder()
		fixture.handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback?code=code&state="+state, nil))
		if response.Code != http.StatusServiceUnavailable || fixture.protocol.discoverCalls != 0 || fixture.browser.clearCalls != 1 {
			t.Fatalf("status=%d discover=%d clear=%d", response.Code, fixture.protocol.discoverCalls, fixture.browser.clearCalls)
		}
	})
	t.Run("methods and unknown path", func(t *testing.T) {
		fixture := newHandlerFixture(t)
		for name, request := range map[string]*http.Request{
			"login post":       httptest.NewRequest(http.MethodPost, "https://workspace.example/auth/login", nil),
			"callback post":    httptest.NewRequest(http.MethodPost, "https://workspace.example/auth/callback", nil),
			"unknown":          httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/callback/extra", nil),
			"encoded callback": httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/%63allback", nil),
		} {
			t.Run(name, func(t *testing.T) {
				response := httptest.NewRecorder()
				fixture.handler.ServeHTTP(response, request)
				if strings.Contains(name, "post") {
					if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
						t.Fatalf("status=%d allow=%q", response.Code, response.Header().Get("Allow"))
					}
				} else if response.Code != http.StatusNotFound {
					t.Fatalf("status=%d", response.Code)
				}
			})
		}
		if fixture.browser.clearCalls != 1 { // Only the exact callback POST clears.
			t.Fatalf("clear calls=%d", fixture.browser.clearCalls)
		}
	})
}

func TestHandlerFormattingAndIDGenerationStayRedactedAndBounded(t *testing.T) {
	fixture := newHandlerFixture(t)
	for _, formatted := range []string{fmt.Sprint(fixture.handler), fmt.Sprintf("%#v", fixture.handler)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, fixture.secrets.secret) {
			t.Fatalf("handler formatting leaked dependencies: %q", formatted)
		}
	}

	value, err := (cryptoIDGenerator{entropy: bytes.NewReader(bytes.Repeat([]byte{0x7a}, 24))}).New("audit_")
	if err != nil || !strings.HasPrefix(value, "audit_") || len(value) != len("audit_")+base64RawLength(24) {
		t.Fatalf("id=%q err=%v", value, err)
	}
	if _, err := (cryptoIDGenerator{entropy: bytes.NewReader(nil)}).New("audit_"); err == nil {
		t.Fatal("entropy exhaustion produced an ID")
	}
	if _, err := (cryptoIDGenerator{entropy: bytes.NewReader(bytes.Repeat([]byte{1}, 24))}).New("other_"); err == nil {
		t.Fatal("unexpected ID prefix accepted")
	}
}

type handlerFixture struct {
	handler              *Handler
	security             tenantsecurity.Context
	configuration        identityrepository.ProviderConfiguration
	pendingConfiguration identityrepository.ProviderConfiguration
	attempt              oidc.Attempt
	record               oidctransport.Record
	store                *fakeLoginStore
	protocol             *fakeProtocol
	client               *fakeProtocolClient
	browser              *fakeBrowserTransport
	sessions             *fakeSessionIssuer
	secrets              *fakeSecretResolver
	sessionResolver      *fakeSessionResolver
	sessionToken         string
	csrfProof            string
	events               []string
}

func newHandlerFixture(t *testing.T) *handlerFixture {
	t.Helper()
	security := testSecurity(t)
	if material, materialErr := browserauth.NewSessionMaterial(security); materialErr != nil || material.Digest().Value() == "" {
		t.Fatalf("test session material err=%v value=%#v", materialErr, material)
	}
	attempt, err := oidc.NewSecureAttempt(security.IdentityDigestor())
	if err != nil {
		t.Fatal(err)
	}
	record, err := oidctransport.NewRecord(security.OrganizationID(), security.ProviderID(), 7, "login_001", attempt, handlerTestNow, handlerTestNow.Add(loginLifetime))
	if err != nil {
		t.Fatal(err)
	}
	subjectDigest, err := security.IdentityDigestor().Digest("subject", "subject_001")
	if err != nil {
		t.Fatal(err)
	}
	configuration := identityrepository.ProviderConfiguration{
		OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), Revision: 7,
		IssuerURL: "https://identity.example", ClientID: "client_001", ClientSecretReference: "secret_ref_001",
		RedirectURL: security.PublicOrigin() + callbackPath, SigningAlgorithms: []string{"RS256"},
	}
	fixture := &handlerFixture{security: security, configuration: configuration, pendingConfiguration: configuration, attempt: attempt, record: record}
	fixture.store = &fakeLoginStore{fixture: fixture, revokeOutcome: identityrepository.RevocationOutcome{Revoked: true}}
	fixture.client = &fakeProtocolClient{fixture: fixture, authorizationURL: "https://identity.example/authorize?opaque=1", subject: oidc.Subject{Digest: subjectDigest, ExpiresAt: handlerTestNow.Add(time.Hour)}}
	fixture.protocol = &fakeProtocol{fixture: fixture, attempt: attempt, client: fixture.client}
	fixture.browser = &fakeBrowserTransport{fixture: fixture, openRecord: record}
	fixture.sessions = &fakeSessionIssuer{fixture: fixture}
	fixture.secrets = &fakeSecretResolver{
		fixture: fixture, secret: "provider-super-secret",
		expected: ClientSecretRequest{
			OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), ProviderRevision: configuration.Revision,
			Reference: configuration.ClientSecretReference,
		},
	}
	fixture.sessionToken = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	csrfProof, err := security.SessionDigestor().Digest("csrf", fixture.sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	fixture.csrfProof = csrfProof.Value()
	claims, err := identity.NewClaims(security.OrganizationID(), identity.PrincipalID("principal_001"), 1, security.ProviderID(), configuration.Revision, handlerTestNow.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	fixture.sessionResolver = &fakeSessionResolver{session: identityrepository.AuthenticatedSession{
		SessionID: "sess_001",
		Claims:    claims,
		Access:    database.AccessContext{OrganizationID: "org_001", PrincipalID: "principal_001", RequestID: "req_001"},
	}}
	authenticator, err := httpauth.New(fakeHTTPTenantResolver{security: security}, fixture.sessionResolver)
	if err != nil {
		t.Fatal(err)
	}
	hardened, err := oidc.NewHardenedHTTPClient(&http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Dependencies{TenantResolver: fakeTenantResolver{security: security}, Store: fixture.store, Protocol: fixture.protocol, Secrets: fixture.secrets, Browser: fixture.browser, Sessions: fixture.sessions, Authenticator: authenticator, HTTPClient: hardened})
	if err != nil {
		t.Fatal(err)
	}
	handler.now = func() time.Time { return handlerTestNow }
	handler.ids = &fakeIDGenerator{values: map[string][]string{
		"req_":   {"req_001"},
		"login_": {"login_001"},
		"sess_":  {"sess_001"},
		"audit_": {"audit_001"},
	}}
	handler.newSessionMaterial = func(value tenantsecurity.Context) (browserauth.SessionMaterial, error) {
		material, materialErr := browserauth.NewSessionMaterial(value)
		fixture.sessions.material = material
		return material, materialErr
	}
	fixture.handler = handler
	return fixture
}

func testSecurity(t *testing.T) tenantsecurity.Context {
	t.Helper()
	identityDigestor, err := oidc.NewHMACDigestor(1, bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sessionDigestor, err := oidc.NewHMACDigestor(2, bytes.Repeat([]byte{0x22}, 32))
	if err != nil {
		t.Fatal(err)
	}
	security, err := tenantsecurity.NewContext("org_001", "provider_001", "https://workspace.example", "identity_key_001", identityDigestor, "session_key_001", sessionDigestor)
	if err != nil {
		t.Fatal(err)
	}
	return security
}

type fakeTenantResolver struct {
	security tenantsecurity.Context
	err      error
}

func (resolver fakeTenantResolver) Resolve(context.Context) (tenantsecurity.Context, error) {
	return resolver.security, resolver.err
}

type fakeLoginStore struct {
	fixture *handlerFixture

	beginRequest                      identityrepository.BeginLoginRequest
	pendingRequest                    identityrepository.PendingLoginRequest
	completeRequest                   identityrepository.CompleteLoginRequest
	beginCalled, completeCalled       bool
	beginErr, pendingErr, completeErr error

	revokeRequest   identityrepository.RevokeSessionRequest
	revokeOutcome   identityrepository.RevocationOutcome
	revokeErr       error
	revokeCalls     int
	failureRequests []identityrepository.RecordSessionTerminationFailureRequest
}

func (store *fakeLoginStore) LoadProviderConfiguration(_ context.Context, organizationID identity.OrganizationID, providerID identity.ProviderID, requestID string) (identityrepository.ProviderConfiguration, error) {
	store.fixture.events = append(store.fixture.events, "load")
	if organizationID != store.fixture.security.OrganizationID() || providerID != store.fixture.security.ProviderID() || requestID != "req_001" {
		return identityrepository.ProviderConfiguration{}, errors.New("incorrect trusted input")
	}
	return store.fixture.configuration, nil
}

func (store *fakeLoginStore) BeginLogin(_ context.Context, request identityrepository.BeginLoginRequest) (identityrepository.LoginAttempt, error) {
	store.fixture.events = append(store.fixture.events, "begin")
	store.beginCalled, store.beginRequest = true, request
	if store.beginErr != nil {
		return identityrepository.LoginAttempt{}, store.beginErr
	}
	return identityrepository.LoginAttempt{ID: request.LoginAttemptID, OrganizationID: request.OrganizationID, ProviderID: request.ProviderID, ProviderRevision: request.ProviderRevision, ExpiresAt: request.ExpiresAt}, nil
}

func (store *fakeLoginStore) LoadPendingLoginConfiguration(_ context.Context, request identityrepository.PendingLoginRequest) (identityrepository.ProviderConfiguration, error) {
	store.fixture.events = append(store.fixture.events, "pending")
	store.pendingRequest = request
	if store.pendingErr != nil {
		return identityrepository.ProviderConfiguration{}, store.pendingErr
	}
	return store.fixture.pendingConfiguration, nil
}

func (store *fakeLoginStore) CompleteLogin(_ context.Context, request identityrepository.CompleteLoginRequest) (identityrepository.IssuedSession, error) {
	store.fixture.events = append(store.fixture.events, "complete")
	store.completeCalled, store.completeRequest = true, request
	if store.completeErr != nil {
		return identityrepository.IssuedSession{}, store.completeErr
	}
	return identityrepository.IssuedSession{ID: request.SessionID, OrganizationID: request.OrganizationID, PrincipalID: "principal_001", ProviderID: request.ProviderID, ExpiresAt: request.SessionExpiresAt}, nil
}

func (store *fakeLoginStore) RevokeSession(_ context.Context, request identityrepository.RevokeSessionRequest) (identityrepository.RevocationOutcome, error) {
	store.fixture.events = append(store.fixture.events, "revoke")
	store.revokeCalls++
	store.revokeRequest = request
	if store.revokeErr != nil {
		return identityrepository.RevocationOutcome{}, store.revokeErr
	}
	return store.revokeOutcome, nil
}

func (store *fakeLoginStore) RecordSessionTerminationFailure(_ context.Context, request identityrepository.RecordSessionTerminationFailureRequest) error {
	store.fixture.events = append(store.fixture.events, "failure")
	store.failureRequests = append(store.failureRequests, request)
	return nil
}

type fakeProtocol struct {
	fixture                    *handlerFixture
	attempt                    oidc.Attempt
	client                     ProtocolClient
	discoverErr, newAttemptErr error
	discoverCalls              int
}

func (protocol *fakeProtocol) NewAttempt(digestor oidc.Digestor) (oidc.Attempt, error) {
	protocol.fixture.events = append(protocol.fixture.events, "attempt")
	if digestor != protocol.fixture.security.IdentityDigestor() || protocol.newAttemptErr != nil {
		return oidc.Attempt{}, protocol.newAttemptErr
	}
	return protocol.attempt, nil
}

func (protocol *fakeProtocol) Discover(_ context.Context, _ *oidc.HardenedHTTPClient, configuration oidc.ProviderConfiguration, digestor oidc.Digestor) (ProtocolClient, error) {
	protocol.fixture.events = append(protocol.fixture.events, "discover")
	protocol.discoverCalls++
	if configuration.RedirectURL != protocol.fixture.security.PublicOrigin()+callbackPath || digestor != protocol.fixture.security.IdentityDigestor() || protocol.discoverErr != nil {
		return nil, protocol.discoverErr
	}
	return protocol.client, nil
}

type fakeProtocolClient struct {
	fixture                       *handlerFixture
	authorizationURL              string
	subject                       oidc.Subject
	authorizationErr, exchangeErr error
}

func (client *fakeProtocolClient) AuthorizationURL(attempt oidc.Attempt) (string, error) {
	if attempt != client.fixture.attempt {
		return "", errors.New("wrong login attempt")
	}
	return client.authorizationURL, client.authorizationErr
}

func (client *fakeProtocolClient) ExchangeAndVerify(_ context.Context, code, secret string, attempt oidc.Attempt) (oidc.Subject, error) {
	client.fixture.events = append(client.fixture.events, "exchange")
	if code == "" || secret != client.fixture.secrets.secret || attempt.StateDigest() != client.fixture.attempt.StateDigest() || client.exchangeErr != nil {
		return oidc.Subject{}, client.exchangeErr
	}
	return client.subject, nil
}

type fakeSecretResolver struct {
	fixture  *handlerFixture
	secret   string
	err      error
	expected ClientSecretRequest
	request  ClientSecretRequest
}

func (resolver *fakeSecretResolver) Resolve(_ context.Context, request ClientSecretRequest) (string, error) {
	resolver.fixture.events = append(resolver.fixture.events, "secret")
	resolver.request = request
	if request != resolver.expected {
		return "", errors.New("secret scope rejected")
	}
	if resolver.err != nil {
		return "", resolver.err
	}
	return resolver.secret, nil
}

type fakeBrowserTransport struct {
	fixture                    *handlerFixture
	preparedRecord, openRecord oidctransport.Record
	prepareErr, openErr        error
	prepared                   oidctransport.PreparedCookie
	prepareOverride            bool
	issueCalls, clearCalls     int
	issueBeforeBegin           bool
}

func (transport *fakeBrowserTransport) Prepare(record oidctransport.Record) (oidctransport.PreparedCookie, error) {
	transport.fixture.events = append(transport.fixture.events, "prepare")
	transport.preparedRecord = record
	if transport.prepareOverride {
		return transport.prepared, transport.prepareErr
	}
	return &fakePreparedCookie{transport: transport}, transport.prepareErr
}

type fakePreparedCookie struct{ transport *fakeBrowserTransport }

func (prepared *fakePreparedCookie) WriteOnce(writer http.ResponseWriter) {
	transport := prepared.transport
	transport.fixture.events = append(transport.fixture.events, "issue")
	transport.issueCalls++
	transport.issueBeforeBegin = !transport.fixture.store.beginCalled
	writer.Header().Add("Set-Cookie", "oidc=issued; Secure; HttpOnly")
}

func (transport *fakeBrowserTransport) OpenRequest(*http.Request) (oidctransport.Record, error) {
	transport.fixture.events = append(transport.fixture.events, "open")
	return transport.openRecord, transport.openErr
}

func (transport *fakeBrowserTransport) Clear(writer http.ResponseWriter) {
	transport.fixture.events = append(transport.fixture.events, "clear")
	transport.clearCalls++
	writer.Header().Add("Set-Cookie", "oidc=cleared; Max-Age=0; Secure; HttpOnly")
}

type fakeSessionIssuer struct {
	fixture             *handlerFixture
	material            browserauth.SessionMaterial
	issueErr            error
	issueCalls          int
	issueBeforeComplete bool
	expireErr           error
	expireCalls         int
}

func (issuer *fakeSessionIssuer) Issue(writer http.ResponseWriter, material browserauth.SessionMaterial, _ time.Time) error {
	issuer.fixture.events = append(issuer.fixture.events, "session")
	issuer.issueCalls++
	issuer.issueBeforeComplete = !issuer.fixture.store.completeCalled
	if issuer.issueErr != nil {
		return issuer.issueErr
	}
	if material.Digest() != issuer.material.Digest() {
		return errors.New("wrong session material")
	}
	writer.Header().Add("Set-Cookie", "session=issued; Secure; HttpOnly")
	return nil
}

func (issuer *fakeSessionIssuer) Expire(writer http.ResponseWriter) error {
	issuer.fixture.events = append(issuer.fixture.events, "expire")
	issuer.expireCalls++
	if issuer.expireErr != nil {
		return issuer.expireErr
	}
	writer.Header().Add("Set-Cookie", "session=expired; Max-Age=0; Secure; HttpOnly")
	return nil
}

type fakeIDGenerator struct {
	values map[string][]string
	seen   []string
	err    error
}

func (generator *fakeIDGenerator) New(prefix string) (string, error) {
	generator.seen = append(generator.seen, prefix)
	if generator.err != nil || len(generator.values[prefix]) == 0 {
		return "", generator.err
	}
	value := generator.values[prefix][0]
	generator.values[prefix] = generator.values[prefix][1:]
	if !strings.HasPrefix(value, prefix) {
		return "", errors.New("unexpected generated id prefix")
	}
	return value, nil
}

func assertAttemptDigests(t *testing.T, attempt oidc.Attempt, state, nonce, verifier, browser identity.KeyedDigest) {
	t.Helper()
	if state != attempt.StateDigest() || nonce != attempt.NonceDigest() || verifier != attempt.PKCEVerifierDigest() || browser != attempt.BrowserBindingDigest() {
		t.Fatalf("attempt digests did not exact-match")
	}
}

func assertStandardResponseHeaders(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Request-ID") == "" {
		t.Fatalf("headers=%v", response.Header())
	}
}

func responseBody(response *httptest.ResponseRecorder) string {
	return strings.TrimSpace(response.Body.String())
}

func sameStrings(left, right []string) bool {
	return len(left) == len(right) && strings.Join(left, "\x00") == strings.Join(right, "\x00")
}

func base64RawLength(bytes int) int { return (bytes*8 + 5) / 6 }

type stringReadCloser struct{ *strings.Reader }

func (stringReadCloser) Close() error { return nil }

func ioNopCloser(value string) io.ReadCloser { return stringReadCloser{strings.NewReader(value)} }
