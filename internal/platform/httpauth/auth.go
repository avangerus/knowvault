// Package httpauth authenticates same-origin HTTP requests without owning a
// listener, route, cookie issuer, or tenant selection mechanism.
package httpauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
)

const (
	SessionCookieName = "__Host-knowvault_session"
	CSRFHeader        = "X-KnowVault-CSRF"
)

// ErrorCode is content-free and suitable for HTTP mapping or regular logs.
type ErrorCode string

const (
	CodeConfigInvalid        ErrorCode = "HTTP_AUTH_CONFIG_INVALID"
	CodeAuthenticationFailed ErrorCode = "HTTP_AUTH_AUTHENTICATION_FAILED"
	CodeCSRFRejected         ErrorCode = "HTTP_AUTH_CSRF_REJECTED"
)

// Error is deliberately content-free and never retains a cause that could
// contain a raw cookie token, request header, tenant ID, or provider detail.
type Error struct {
	code ErrorCode
}

func (errorValue *Error) Error() string { return string(errorValue.code) }

// CodeOf maps unexpected errors to the safe authentication failure outcome.
func CodeOf(err error) ErrorCode {
	var authError *Error
	if errors.As(err, &authError) {
		return authError.code
	}
	return CodeAuthenticationFailed
}

// TenantSecurityContext is the deployment-trusted security configuration for
// one tenant. It is resolved on every request, rather than inferred from any
// client-controlled HTTP field. Origin and Digestor are tenant-bound so a
// shared process cannot accidentally authenticate one tenant with another
// tenant's browser policy or HMAC key.
type TenantSecurityContext struct {
	OrganizationID identity.OrganizationID
	Origin         string
	Digestor       Digestor
}

// TenantResolver receives only server-controlled request context. This
// package intentionally gives it no HTTP request, headers, query values, or
// request body, so tenant selection cannot drift into client input.
type TenantResolver interface {
	Resolve(context.Context) (TenantSecurityContext, error)
}

// SessionResolver is implemented by the current identity repository.
type SessionResolver interface {
	ResolveSession(context.Context, identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error)
}

// CookieRenewer reissues the session cookie's Max-Age/Expires when the
// server-side session's own expiry was just extended by ResolveSession's
// sliding renewal (FIX-7 #3), keeping the cookie in the sync ADR-0030
// requires ("Max-Age no later than the server-side session expiry"). It is
// injected, never owned or configured here -- this package still does not
// own a cookie issuer -- and optional: New's default (no renewer) simply
// skips renewal, so Authenticate keeps working exactly as before and a
// session still expires on schedule; only the "lives a whole work shift
// while active" improvement is unavailable without one.
type CookieRenewer interface {
	Renew(writer http.ResponseWriter, rawToken string, expiresAt time.Time) error
}

// Digestor is the domain-separated HMAC adapter already used by the OIDC
// boundary. HTTP auth uses only session_token and csrf purposes.
type Digestor interface {
	Digest(purpose, raw string) (identity.KeyedDigest, error)
}

// Authentication contains only verified identity state and a derived proof.
// It deliberately never retains or returns the raw session cookie token.
type Authentication struct {
	session   identityrepository.AuthenticatedSession
	csrfProof identity.KeyedDigest
	origin    string
	apiBearer bool
}

// Session returns a value copy of the verified session. Callers cannot mutate
// the authentication object that VerifyCSRF subsequently checks.
func (authentication Authentication) Session() identityrepository.AuthenticatedSession {
	return authentication.session
}

// CSRFToken is the tenant-bound derived proof exposed only for the future
// authenticated same-origin CSRF bootstrap response. It is never the raw
// session cookie value.
func (authentication Authentication) CSRFToken() string { return authentication.csrfProof.Value() }

// Authenticator resolves a trusted tenant and validates one opaque session
// cookie on every request. It is safe to construct once and reuse concurrently.
type Authenticator struct {
	tenantResolver  TenantResolver
	sessionResolver SessionResolver
	renewer         CookieRenewer
}

// New validates the transport-neutral dependencies. The tenant resolver must
// return a valid TenantSecurityContext for each request; there is deliberately
// no default tenant, origin, or digestor. It has no cookie renewer (FIX-7 #3
// is simply unavailable); use NewWithRenewer to enable it.
func New(tenantResolver TenantResolver, sessionResolver SessionResolver) (*Authenticator, error) {
	return NewWithRenewer(tenantResolver, sessionResolver, nil)
}

// NewWithRenewer is New plus FIX-7 #3's optional cookie renewer.
func NewWithRenewer(tenantResolver TenantResolver, sessionResolver SessionResolver, renewer CookieRenewer) (*Authenticator, error) {
	if tenantResolver == nil || sessionResolver == nil {
		return nil, &Error{code: CodeConfigInvalid}
	}
	return &Authenticator{
		tenantResolver: tenantResolver, sessionResolver: sessionResolver, renewer: renewer,
	}, nil
}

// Authenticate resolves the trusted tenant, validates exactly one canonical
// session cookie, derives its digest, then asks the identity repository to
// revalidate current session, principal and provider state.
func (authenticator *Authenticator) Authenticate(request *http.Request, serverGeneratedRequestID string) (Authentication, error) {
	if authenticator == nil || authenticator.tenantResolver == nil || authenticator.sessionResolver == nil || request == nil || !validRequestID(serverGeneratedRequestID) {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	tenant, err := authenticator.tenantResolver.Resolve(request.Context())
	if err != nil || !validTenantSecurityContext(tenant) {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	rawToken, apiBearer, err := exactSessionCredential(request)
	if err != nil {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	sessionDigest, err := tenant.Digestor.Digest("session_token", rawToken)
	if err != nil || !validDigest(sessionDigest) {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	session, err := authenticator.sessionResolver.ResolveSession(request.Context(), identityrepository.ResolveSessionRequest{
		OrganizationID: tenant.OrganizationID, RequestID: serverGeneratedRequestID, SessionTokenDigest: sessionDigest,
	})
	if err != nil || !matchesResolvedSession(session, tenant.OrganizationID, serverGeneratedRequestID) {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	csrfProof, err := tenant.Digestor.Digest("csrf", rawToken)
	if err != nil || !validDigest(csrfProof) {
		return Authentication{}, &Error{code: CodeAuthenticationFailed}
	}
	return Authentication{session: session, csrfProof: csrfProof, origin: tenant.Origin, apiBearer: apiBearer}, nil
}

// RefreshCookie reissues the session cookie only when this exact
// authentication's session was just extended by ResolveSession's sliding
// renewal (FIX-7 #3) AND the request presented it as the browser cookie
// transport -- never for the explicit Bearer transport, which has no cookie
// to refresh. It is a separate call from Authenticate so a dispatcher can
// invoke it only after its own method/CSRF checks already succeeded; a
// failure here never fails the request it is refreshing, because the request
// is already validly authenticated against its current, still-valid expiry
// either way -- at worst the next request forces a real re-login sooner than
// it would have otherwise.
func (authenticator *Authenticator) RefreshCookie(writer http.ResponseWriter, request *http.Request, authentication Authentication) error {
	if authenticator == nil || authenticator.renewer == nil || writer == nil || request == nil ||
		authentication.apiBearer || !authentication.session.Renewed {
		return nil
	}
	rawToken, apiBearer, err := exactSessionCredential(request)
	if err != nil || apiBearer {
		return nil
	}
	return authenticator.renewer.Renew(writer, rawToken, authentication.session.Claims.ExpiresAt())
}

// VerifyCSRF accepts safe methods without an Origin or CSRF header. Every
// unsafe request must carry exactly the configured HTTPS Origin and exactly
// one proof equal to the derived session proof.
func (authenticator *Authenticator) VerifyCSRF(request *http.Request, authentication Authentication) error {
	if authenticator == nil || request == nil || !validDigest(authentication.csrfProof) || !validOrigin(authentication.origin) {
		return &Error{code: CodeCSRFRejected}
	}
	if safeMethod(request.Method) {
		return nil
	}
	if authentication.apiBearer {
		// A bearer session is the explicit non-browser API transport. It must
		// not be combined with browser cookies or origin/CSRF headers, which
		// would make the same request ambiguous and reintroduce a cookie CSRF
		// path.
		if len(headerValues(request.Header, "Cookie")) != 0 || len(headerValues(request.Header, "Origin")) != 0 || len(headerValues(request.Header, CSRFHeader)) != 0 {
			return &Error{code: CodeCSRFRejected}
		}
		return nil
	}
	origin, originOK := exactHeader(request.Header, "Origin")
	csrfProof, proofOK := exactHeader(request.Header, CSRFHeader)
	if !originOK || !proofOK || origin != authentication.origin || subtle.ConstantTimeCompare([]byte(csrfProof), []byte(authentication.csrfProof.Value())) != 1 {
		return &Error{code: CodeCSRFRejected}
	}
	return nil
}

func exactSessionToken(request *http.Request) (string, error) {
	if values := headerValues(request.Header, "Cookie"); len(values) != 1 {
		return "", errors.New("ambiguous cookie header")
	}
	var values []string
	for _, cookie := range request.Cookies() {
		if cookie.Name == SessionCookieName {
			values = append(values, cookie.Value)
		}
	}
	if len(values) != 1 || !validSessionToken(values[0]) {
		return "", errors.New("invalid session cookie")
	}
	return values[0], nil
}

// exactSessionCredential accepts either the browser's single transport cookie
// or one explicit Authorization: Bearer session token for non-browser API and
// MCP clients. The bearer form is the same opaque, server-issued session token
// and never creates a second authentication authority.
func exactSessionCredential(request *http.Request) (string, bool, error) {
	if request == nil {
		return "", false, errors.New("missing request")
	}
	authorization := headerValues(request.Header, "Authorization")
	if len(authorization) > 0 {
		if len(authorization) != 1 || len(headerValues(request.Header, "Cookie")) != 0 {
			return "", false, errors.New("ambiguous authorization transport")
		}
		value := authorization[0]
		if !strings.HasPrefix(value, "Bearer ") || strings.TrimSpace(value[7:]) != value[7:] || !validSessionToken(value[7:]) {
			return "", false, errors.New("invalid bearer session")
		}
		return value[7:], true, nil
	}
	token, err := exactSessionToken(request)
	return token, false, err
}

func exactHeader(header http.Header, name string) (string, bool) {
	values := headerValues(header, name)
	if len(values) != 1 || values[0] == "" || strings.ContainsRune(values[0], ',') {
		return "", false
	}
	return values[0], true
}

func headerValues(header http.Header, name string) []string {
	var values []string
	for key, candidates := range header {
		if strings.EqualFold(key, name) {
			values = append(values, candidates...)
		}
	}
	return values
}

func validSessionToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validDigest(value identity.KeyedDigest) bool {
	_, err := identity.NewKeyedDigest(value.Value())
	return err == nil
}

func matchesResolvedSession(session identityrepository.AuthenticatedSession, tenantID identity.OrganizationID, requestID string) bool {
	return session.SessionID != "" && session.Access.OrganizationID == string(tenantID) && session.Access.PrincipalID != "" && session.Access.RequestID == requestID &&
		session.Claims.OrganizationID() == tenantID && session.Claims.PrincipalID() == identity.PrincipalID(session.Access.PrincipalID) && session.Access.Validate() == nil
}

func validOrigin(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed == nil {
		return false
	}
	hostname := parsed.Hostname()
	return parsed.Scheme == "https" && parsed.Host != "" && hostname != "" && hostname == strings.ToLower(hostname) && !strings.HasSuffix(hostname, ".") && parsed.Port() != "443" && parsed.User == nil && parsed.Opaque == "" && parsed.Path == "" && parsed.RawPath == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

func validTenantSecurityContext(tenant TenantSecurityContext) bool {
	return validOpaqueID(string(tenant.OrganizationID)) && validOrigin(tenant.Origin) && tenant.Digestor != nil
}

func validOpaqueID(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validRequestID(value string) bool { return validOpaqueID(value) }

func safeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
