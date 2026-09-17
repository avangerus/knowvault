// Package oidcweb owns the deliberately small browser boundary for a single
// OIDC Authorization Code + PKCE login.  It does not select a tenant from a
// request, expose provider errors, or provide a general authentication API.
package oidcweb

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/browserauth"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/oidc"
	"knowvault.local/verified-workspace/internal/platform/oidctransport"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

const (
	loginPath    = "/auth/login"
	callbackPath = "/auth/callback"
	logoutPath   = "/auth/logout"

	maxCallbackQueryBytes = 8192
	maxAuthorizationCode  = 4096
	maxCallbackState      = 128
	loginLifetime         = 15 * time.Minute
	maximumSessionLife    = 24 * time.Hour
	// initialSessionLife is FIX-7 #3's starting app-session lifetime, matching
	// identityrepository's own sessionRenewalWindow: the session's real
	// duration comes from ResolveSession's sliding renewal on activity
	// thereafter, not from this initial value or from the OIDC token's exp.
	initialSessionLife = 30 * time.Minute
)

// LoginStore is the exact persistence boundary required by the web flow.
// The concrete identity repository fulfils this interface without adapting or
// exposing raw browser/OIDC material.
type LoginStore interface {
	LoadProviderConfiguration(context.Context, identity.OrganizationID, identity.ProviderID, string) (identityrepository.ProviderConfiguration, error)
	BeginLogin(context.Context, identityrepository.BeginLoginRequest) (identityrepository.LoginAttempt, error)
	LoadPendingLoginConfiguration(context.Context, identityrepository.PendingLoginRequest) (identityrepository.ProviderConfiguration, error)
	CompleteLogin(context.Context, identityrepository.CompleteLoginRequest) (identityrepository.IssuedSession, error)
	RevokeSession(context.Context, identityrepository.RevokeSessionRequest) (identityrepository.RevocationOutcome, error)
	RecordSessionTerminationFailure(context.Context, identityrepository.RecordSessionTerminationFailureRequest) error
}

// Protocol deliberately separates discovery from the resulting client.  It
// gives tests a small seam while retaining one reviewed production adapter.
type Protocol interface {
	NewAttempt(oidc.Digestor) (oidc.Attempt, error)
	Discover(context.Context, *oidc.HardenedHTTPClient, oidc.ProviderConfiguration, oidc.Digestor) (ProtocolClient, error)
}

// ProtocolClient is a discovered, revision-bound OIDC client.
type ProtocolClient interface {
	AuthorizationURL(oidc.Attempt) (string, error)
	ExchangeAndVerify(context.Context, string, string, oidc.Attempt) (oidc.Subject, error)
}

// ClientSecretRequest binds a secret lookup to the exact trusted provider
// revision that initiated the callback. A resolver must reject every mismatch
// rather than treating a reference as a tenant-agnostic secret name.
type ClientSecretRequest struct {
	OrganizationID   identity.OrganizationID
	ProviderID       identity.ProviderID
	ProviderRevision int64
	Reference        string
}

func (ClientSecretRequest) String() string   { return "oidcweb.ClientSecretRequest{[REDACTED]}" }
func (ClientSecretRequest) GoString() string { return "oidcweb.ClientSecretRequest{[REDACTED]}" }

// ClientSecretResolver returns a secret only for the short exchange call.
// Implementations must obtain it from a secret manager and never log it.
type ClientSecretResolver interface {
	Resolve(context.Context, ClientSecretRequest) (string, error)
}

// BrowserTransport owns the cookie projection of an authenticated OIDC
// attempt.  The handler can prepare but cannot issue it before BeginLogin has
// durably succeeded; every callback clears it before handling input.
type BrowserTransport interface {
	Prepare(oidctransport.Record) (oidctransport.PreparedCookie, error)
	OpenRequest(*http.Request) (oidctransport.Record, error)
	Clear(http.ResponseWriter)
}

// SessionIssuer emits the reviewed opaque browser-session cookie only after
// CompleteLogin has atomically consumed the durable OIDC attempt, and clears
// it with Max-Age=0 when the server-side session row is already revoked.
type SessionIssuer interface {
	Issue(http.ResponseWriter, browserauth.SessionMaterial, time.Time) error
	Expire(http.ResponseWriter) error
}

// SessionAuthenticator is the reviewed cookie+CSRF boundary (httpauth). Logout
// reuses it so the route enforces exactly the same Origin and CSRF proof as
// every other unsafe API request (ADR-0028).
type SessionAuthenticator interface {
	Authenticate(*http.Request, string) (httpauth.Authentication, error)
	VerifyCSRF(*http.Request, httpauth.Authentication) error
}

// Dependencies are all explicit so the HTTP edge cannot silently create a
// network client, select a tenant, or fall back to an unreviewed store.
type Dependencies struct {
	TenantResolver tenantsecurity.Resolver
	Store          LoginStore
	Protocol       Protocol
	Secrets        ClientSecretResolver
	Browser        BrowserTransport
	Sessions       SessionIssuer
	Authenticator  SessionAuthenticator
	HTTPClient     *oidc.HardenedHTTPClient
}

// Handler is intentionally formatting-redacted: it contains access to
// security and browser transport dependencies, none of which are safe logs.
type Handler struct {
	tenantResolver tenantsecurity.Resolver
	store          LoginStore
	protocol       Protocol
	secrets        ClientSecretResolver
	browser        BrowserTransport
	sessions       SessionIssuer
	authenticator  SessionAuthenticator
	httpClient     *oidc.HardenedHTTPClient

	now                func() time.Time
	ids                idGenerator
	newSessionMaterial func(tenantsecurity.Context) (browserauth.SessionMaterial, error)
}

func (Handler) String() string   { return "oidcweb.Handler{[REDACTED]}" }
func (Handler) GoString() string { return "oidcweb.Handler{[REDACTED]}" }

// New constructs the route handler with the production OIDC protocol
// adapter.  All business dependencies are mandatory; a missing dependency is
// a startup configuration error rather than a runtime fallback.
func New(dependencies Dependencies) (*Handler, error) {
	if unavailable(dependencies.TenantResolver) || unavailable(dependencies.Store) || unavailable(dependencies.Secrets) ||
		unavailable(dependencies.Browser) || unavailable(dependencies.Sessions) || unavailable(dependencies.Authenticator) || dependencies.HTTPClient == nil {
		return nil, errors.New("oidcweb: invalid dependencies")
	}
	protocol := dependencies.Protocol
	if unavailable(protocol) {
		protocol = nativeProtocol{}
	}
	return &Handler{
		tenantResolver:     dependencies.TenantResolver,
		store:              dependencies.Store,
		protocol:           protocol,
		secrets:            dependencies.Secrets,
		browser:            dependencies.Browser,
		sessions:           dependencies.Sessions,
		authenticator:      dependencies.Authenticator,
		httpClient:         dependencies.HTTPClient,
		now:                time.Now,
		ids:                cryptoIDGenerator{entropy: rand.Reader},
		newSessionMaterial: browserauth.NewSessionMaterial,
	}, nil
}

// ServeHTTP accepts exactly two GET routes and one POST route. It
// intentionally has no router parameters, host-based tenant selector,
// query-selected provider, or generic POST endpoint.
func (handler *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || writer == nil || request == nil || handler.ids == nil {
		return
	}
	// Exact callback paths clear the transient browser proof before even an ID
	// generation failure or a method/query validation error can write headers.
	// A non-exact escaped path is deliberately not a callback route.
	isCallback := exactRoute(request, callbackPath)
	if isCallback {
		handler.browser.Clear(writer)
	}

	requestID, err := handler.ids.New("req_")
	if err != nil {
		writeFailure(writer, "", http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	setResponseHeaders(writer, requestID)

	switch {
	case exactRoute(request, loginPath):
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(writer, http.MethodGet)
			return
		}
		handler.login(writer, request, requestID)
	case isCallback:
		if request.Method != http.MethodGet {
			writeMethodNotAllowed(writer, http.MethodGet)
			return
		}
		handler.callback(writer, request, requestID)
	case exactRoute(request, logoutPath):
		if request.Method != http.MethodPost {
			writeMethodNotAllowed(writer, http.MethodPost)
			return
		}
		handler.logout(writer, request, requestID)
	default:
		writeFailure(writer, requestID, http.StatusNotFound, "NOT_FOUND")
	}
}

func (handler *Handler) login(writer http.ResponseWriter, request *http.Request, requestID string) {
	if !emptyRequestBody(request) || request.URL.RawQuery != "" || request.URL.ForceQuery {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}

	security, err := handler.tenantResolver.Resolve(request.Context())
	if err != nil || security.IdentityDigestor() == nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	configuration, err := handler.store.LoadProviderConfiguration(request.Context(), security.OrganizationID(), security.ProviderID(), requestID)
	if err != nil || !matchesSecurity(configuration, security, 0) || !matchesCallbackRedirect(configuration.RedirectURL, security) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}

	client, err := handler.protocol.Discover(request.Context(), handler.httpClient, protocolConfiguration(configuration), security.IdentityDigestor())
	if err != nil || unavailable(client) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	attempt, err := handler.protocol.NewAttempt(security.IdentityDigestor())
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	loginID, err := handler.ids.New("login_")
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	now := handler.currentTime()
	record, err := oidctransport.NewRecord(security.OrganizationID(), security.ProviderID(), configuration.Revision, loginID, attempt, now, now.Add(loginLifetime))
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	authorizationURL, err := client.AuthorizationURL(attempt)
	if err != nil || !validRedirectLocation(authorizationURL) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	prepared, err := handler.browser.Prepare(record)
	if err != nil || unavailable(prepared) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}

	_, err = handler.store.BeginLogin(request.Context(), identityrepository.BeginLoginRequest{
		OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), ProviderRevision: configuration.Revision,
		LoginAttemptID: loginID, RequestID: requestID,
		StateDigest: attempt.StateDigest(), BrowserBindingDigest: attempt.BrowserBindingDigest(),
		NonceDigest: attempt.NonceDigest(), PKCEVerifierDigest: attempt.PKCEVerifierDigest(), ExpiresAt: record.ExpiresAt(),
	})
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	prepared.WriteOnce(writer)
	writer.Header().Set("Location", authorizationURL)
	writer.WriteHeader(http.StatusSeeOther)
}

func (handler *Handler) callback(writer http.ResponseWriter, request *http.Request, requestID string) {
	if !emptyRequestBody(request) {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	security, err := handler.tenantResolver.Resolve(request.Context())
	if err != nil || security.IdentityDigestor() == nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	code, state, responseIssuer, ok := callbackParameters(request.URL)
	if !ok {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	record, err := handler.browser.OpenRequest(request)
	if err != nil || record.OrganizationID() != security.OrganizationID() || record.ProviderID() != security.ProviderID() {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	if !record.MatchesState(state) {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	attempt, err := record.RestoreAttempt(security.IdentityDigestor())
	if err != nil {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}

	configuration, err := handler.store.LoadPendingLoginConfiguration(request.Context(), identityrepository.PendingLoginRequest{
		OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), ProviderRevision: record.ProviderRevision(),
		LoginAttemptID: record.AttemptID(), RequestID: requestID,
		StateDigest: attempt.StateDigest(), BrowserBindingDigest: attempt.BrowserBindingDigest(),
		NonceDigest: attempt.NonceDigest(), PKCEVerifierDigest: attempt.PKCEVerifierDigest(),
	})
	if err != nil {
		writeRepositoryCallbackFailure(writer, requestID, err)
		return
	}
	if !matchesSecurity(configuration, security, record.ProviderRevision()) || !matchesCallbackRedirect(configuration.RedirectURL, security) ||
		(responseIssuer != "" && responseIssuer != configuration.IssuerURL) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	client, err := handler.protocol.Discover(request.Context(), handler.httpClient, protocolConfiguration(configuration), security.IdentityDigestor())
	if err != nil || unavailable(client) {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	secret, err := handler.secrets.Resolve(request.Context(), ClientSecretRequest{
		OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), ProviderRevision: configuration.Revision,
		Reference: configuration.ClientSecretReference,
	})
	if err != nil || secret == "" {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	subject, exchangeErr := client.ExchangeAndVerify(request.Context(), code, secret, attempt)
	secret = "" // Keep the resolved secret out of every later call and error path.
	if exchangeErr != nil || subject.ExpiresAt.IsZero() {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}

	sessionMaterial, err := handler.newSessionMaterial(security)
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	now := handler.currentTime()
	// FIX-7 #3: the app session's own expiry is deliberately NOT
	// subject.ExpiresAt (the OIDC ID token's own short-lived `exp` -- that
	// was the root cause of the owner's repeated live mid-shift logout: the
	// token is verified fresh right above, but its lifetime has nothing to do
	// with how long a local, independently-renewed app session should last).
	// It starts at initialSessionLife and is extended by
	// identityrepository.Store.ResolveSession's sliding renewal on every
	// authenticated request thereafter, capped at maximumSessionLife from
	// this exact issuance -- never here.
	sessionExpiry := now.Add(initialSessionLife)
	maximumExpiry := now.Add(maximumSessionLife)
	if sessionExpiry.After(maximumExpiry) {
		sessionExpiry = maximumExpiry
	}
	if !sessionExpiry.After(now) {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	sessionID, err := handler.ids.New("sess_")
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	auditID, err := handler.ids.New("audit_")
	if err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}

	_, err = handler.store.CompleteLogin(request.Context(), identityrepository.CompleteLoginRequest{
		OrganizationID: security.OrganizationID(), ProviderID: security.ProviderID(), ProviderRevision: configuration.Revision,
		LoginAttemptID: record.AttemptID(), RequestID: requestID, AuditEventID: auditID,
		StateDigest: attempt.StateDigest(), BrowserBindingDigest: attempt.BrowserBindingDigest(),
		NonceDigest: attempt.NonceDigest(), PKCEVerifierDigest: attempt.PKCEVerifierDigest(),
		ExternalSubjectDigest: subject.Digest, SessionID: sessionID, SessionTokenDigest: sessionMaterial.Digest(), SessionExpiresAt: sessionExpiry,
	})
	if err != nil {
		writeRepositoryCallbackFailure(writer, requestID, err)
		return
	}
	if err := handler.sessions.Issue(writer, sessionMaterial, sessionExpiry); err != nil {
		writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
		return
	}
	writer.Header().Set("Location", "/")
	writer.WriteHeader(http.StatusSeeOther)
}

// logout is the single POST session-termination route (ADR-0075). Every
// failure branch shares one closed code so the response cannot reveal whether
// the presented session exists; success revokes the session row and clears
// the cookie in the same response.
func (handler *Handler) logout(writer http.ResponseWriter, request *http.Request, requestID string) {
	if !emptyRequestBody(request) || request.URL.RawQuery != "" || request.URL.ForceQuery {
		handler.writeTerminationFailed(writer, requestID)
		return
	}
	auditID, err := handler.ids.New("audit_")
	if err != nil {
		handler.writeTerminationFailed(writer, requestID)
		return
	}
	security, securityErr := handler.tenantResolver.Resolve(request.Context())
	authentication, err := handler.authenticator.Authenticate(request, requestID)
	if err != nil {
		handler.writeTerminationFailed(writer, requestID)
		if securityErr == nil {
			_ = handler.store.RecordSessionTerminationFailure(request.Context(), identityrepository.RecordSessionTerminationFailureRequest{
				OrganizationID: security.OrganizationID(), RequestID: requestID, AuditEventID: auditID,
			})
		}
		return
	}
	if err := handler.authenticator.VerifyCSRF(request, authentication); err != nil {
		handler.writeTerminationFailed(writer, requestID)
		session := authentication.Session()
		principal := identity.PrincipalID(session.Access.PrincipalID)
		_ = handler.store.RecordSessionTerminationFailure(request.Context(), identityrepository.RecordSessionTerminationFailureRequest{
			OrganizationID: security.OrganizationID(), SessionID: &session.SessionID, PrincipalID: &principal,
			RequestID: requestID, AuditEventID: auditID,
		})
		return
	}
	session := authentication.Session()
	outcome, err := handler.store.RevokeSession(request.Context(), identityrepository.RevokeSessionRequest{
		OrganizationID: security.OrganizationID(), SessionID: session.SessionID,
		PrincipalID: identity.PrincipalID(session.Access.PrincipalID), RequestID: requestID, AuditEventID: auditID,
	})
	if err != nil || !outcome.Revoked {
		handler.writeTerminationFailed(writer, requestID)
		return
	}
	if err := handler.sessions.Expire(writer); err != nil {
		handler.writeTerminationFailed(writer, requestID)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

// writeTerminationFailed is the single closed failure response for every
// logout branch: status and code are identical whether the session was
// unknown, unauthenticated, CSRF-rejected or already revoked.
func (handler *Handler) writeTerminationFailed(writer http.ResponseWriter, requestID string) {
	writeFailure(writer, requestID, http.StatusUnauthorized, string(identityrepository.CodeSessionTerminationFailed))
}

func (handler *Handler) currentTime() time.Time {
	if handler.now == nil {
		return time.Now().UTC()
	}
	return handler.now().UTC()
}

func exactRoute(request *http.Request, path string) bool {
	return request != nil && request.URL != nil && request.URL.Path == path && request.URL.RawPath == "" && request.URL.Opaque == ""
}

func emptyRequestBody(request *http.Request) bool {
	if request == nil || request.ContentLength > 0 || len(request.TransferEncoding) != 0 {
		return false
	}
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	defer request.Body.Close()
	bytes, err := io.ReadAll(io.LimitReader(request.Body, 1))
	return err == nil && len(bytes) == 0
}

// callbackParameters accepts the mandatory authorization-code response pair
// and the two standards-compliant parameters Keycloak and other OIDC
// providers commonly add to a query response.  Unknown parameters remain
// rejected so an error response, duplicate value, or provider-specific
// injection cannot be silently treated as a successful callback.
func callbackParameters(requestURL *url.URL) (code, state, issuer string, ok bool) {
	if requestURL == nil || requestURL.RawQuery == "" || requestURL.ForceQuery || len(requestURL.RawQuery) > maxCallbackQueryBytes {
		return "", "", "", false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil {
		return "", "", "", false
	}
	for key := range values {
		switch key {
		case "code", "state", "iss", "session_state":
		default:
			return "", "", "", false
		}
	}
	codeValues, codeOK := values["code"]
	stateValues, stateOK := values["state"]
	if !codeOK || !stateOK || len(codeValues) != 1 || len(stateValues) != 1 || !validCallbackCode(codeValues[0]) || !validCallbackState(stateValues[0]) {
		return "", "", "", false
	}
	issuerValues, issuerOK := values["iss"]
	if issuerOK {
		if len(issuerValues) != 1 || !validCallbackIssuer(issuerValues[0]) {
			return "", "", "", false
		}
		issuer = issuerValues[0]
	}
	if sessionValues, sessionOK := values["session_state"]; sessionOK {
		if len(sessionValues) != 1 || !validCallbackParameter(sessionValues[0]) {
			return "", "", "", false
		}
	}
	return codeValues[0], stateValues[0], issuer, true
}

func validCallbackIssuer(value string) bool {
	parsed, err := url.Parse(value)
	return len(value) <= 2048 && err == nil && parsed != nil && parsed.Scheme == "https" && parsed.Host != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func validCallbackParameter(value string) bool {
	return value != "" && len(value) <= maxCallbackState && utf8.ValidString(value) && !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validCallbackCode(value string) bool {
	return value != "" && len(value) <= maxAuthorizationCode && utf8.ValidString(value) && !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validCallbackState(value string) bool {
	return value != "" && len(value) <= maxCallbackState && utf8.ValidString(value) && !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func protocolConfiguration(configuration identityrepository.ProviderConfiguration) oidc.ProviderConfiguration {
	return oidc.ProviderConfiguration{
		IssuerURL: configuration.IssuerURL, ClientID: configuration.ClientID, RedirectURL: configuration.RedirectURL,
		SigningAlgorithms: append([]string(nil), configuration.SigningAlgorithms...),
	}
}

func matchesSecurity(configuration identityrepository.ProviderConfiguration, security tenantsecurity.Context, revision int64) bool {
	if configuration.OrganizationID != security.OrganizationID() || configuration.ProviderID != security.ProviderID() || configuration.Revision < 1 {
		return false
	}
	return revision == 0 || configuration.Revision == revision
}

func matchesCallbackRedirect(value string, security tenantsecurity.Context) bool {
	return value == security.PublicOrigin()+callbackPath
}

func validRedirectLocation(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed != nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.Fragment == ""
}

func writeRepositoryCallbackFailure(writer http.ResponseWriter, requestID string, err error) {
	if identityrepository.CodeOf(err) == identityrepository.CodeDenied || identityrepository.CodeOf(err) == identityrepository.CodeRequestInvalid {
		writeFailure(writer, requestID, http.StatusBadRequest, "AUTH_CALLBACK_FAILED")
		return
	}
	writeFailure(writer, requestID, http.StatusServiceUnavailable, "AUTH_UNAVAILABLE")
}

func setResponseHeaders(writer http.ResponseWriter, requestID string) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Referrer-Policy", "no-referrer")
	if requestID != "" {
		writer.Header().Set("X-Request-ID", requestID)
	}
}

func writeMethodNotAllowed(writer http.ResponseWriter, method string) {
	writer.Header().Set("Allow", method)
	writeFailure(writer, writer.Header().Get("X-Request-ID"), http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED")
}

func writeFailure(writer http.ResponseWriter, requestID string, status int, code string) {
	setResponseHeaders(writer, requestID)
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	_, _ = io.WriteString(writer, "{\"error\":\""+code+"\",\"request_id\":\""+requestID+"\"}\n")
}

type nativeProtocol struct{}

func (nativeProtocol) NewAttempt(digestor oidc.Digestor) (oidc.Attempt, error) {
	return oidc.NewSecureAttempt(digestor)
}

func (nativeProtocol) Discover(ctx context.Context, client *oidc.HardenedHTTPClient, configuration oidc.ProviderConfiguration, digestor oidc.Digestor) (ProtocolClient, error) {
	return oidc.Discover(ctx, client, configuration, digestor)
}

type idGenerator interface {
	New(prefix string) (string, error)
}

type cryptoIDGenerator struct{ entropy io.Reader }

func (generator cryptoIDGenerator) New(prefix string) (string, error) {
	if generator.entropy == nil || !validIDPrefix(prefix) {
		return "", errors.New("oidcweb: id generation unavailable")
	}
	raw := make([]byte, 24)
	if _, err := io.ReadFull(generator.entropy, raw); err != nil {
		return "", errors.New("oidcweb: id generation unavailable")
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

func validIDPrefix(prefix string) bool {
	switch prefix {
	case "req_", "login_", "sess_", "audit_":
		return true
	default:
		return false
	}
}

func unavailable(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
