// Package browserauth creates opaque browser-session material and emits the
// exact host-only session cookie. It does not authenticate requests or persist
// raw tokens.
package browserauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

const (
	sessionBytes       = 32
	maximumSessionLife = 24 * time.Hour
)

type ErrorCode string

const (
	CodeConfigurationInvalid ErrorCode = "BROWSER_AUTH_CONFIGURATION_INVALID"
	CodeMaterialFailed       ErrorCode = "BROWSER_AUTH_MATERIAL_FAILED"
	CodeCookieRejected       ErrorCode = "BROWSER_AUTH_COOKIE_REJECTED"
)

type Error struct{ code ErrorCode }

func (value *Error) Error() string { return string(value.code) }

func CodeOf(err error) ErrorCode {
	var value *Error
	if errors.As(err, &value) {
		return value.code
	}
	return CodeCookieRejected
}

// SessionMaterial keeps the raw token private while exposing only the digest
// needed by identityrepository.CompleteLogin. String formatting is redacted.
type SessionMaterial struct {
	rawToken string
	digest   identity.KeyedDigest
}

func (SessionMaterial) String() string                     { return "[REDACTED]" }
func (SessionMaterial) GoString() string                   { return "browserauth.SessionMaterial{[REDACTED]}" }
func (value SessionMaterial) Digest() identity.KeyedDigest { return value.digest }

func NewSessionMaterial(security tenantsecurity.Context) (SessionMaterial, error) {
	return newSessionMaterial(rand.Reader, security)
}

func newSessionMaterial(entropy io.Reader, security tenantsecurity.Context) (SessionMaterial, error) {
	if entropy == nil || security.SessionDigestor() == nil {
		return SessionMaterial{}, &Error{code: CodeConfigurationInvalid}
	}
	raw := make([]byte, sessionBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		return SessionMaterial{}, &Error{code: CodeMaterialFailed}
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest, err := security.SessionDigestor().Digest("session_token", token)
	if err != nil || !validDigest(digest) {
		return SessionMaterial{}, &Error{code: CodeMaterialFailed}
	}
	return SessionMaterial{rawToken: token, digest: digest}, nil
}

// CookieIssuer emits only the reviewed session-cookie profile. SameSite=Lax is
// required for the top-level OIDC callback; unsafe API requests additionally
// require the exact Origin and CSRF proof enforced by httpauth.
type CookieIssuer struct{ now func() time.Time }

func NewCookieIssuer() *CookieIssuer { return &CookieIssuer{now: time.Now} }

func (issuer *CookieIssuer) Issue(writer http.ResponseWriter, material SessionMaterial, expiresAt time.Time) error {
	if issuer == nil || issuer.now == nil || writer == nil || !validMaterial(material) || expiresAt.IsZero() {
		return &Error{code: CodeCookieRejected}
	}
	now := issuer.now().UTC()
	expires := expiresAt.UTC().Truncate(time.Second)
	lifetime := expires.Sub(now)
	if lifetime < time.Second || lifetime > maximumSessionLife {
		return &Error{code: CodeCookieRejected}
	}
	maxAge := int(lifetime / time.Second)
	if maxAge < 1 || time.Duration(maxAge)*time.Second > lifetime {
		return &Error{code: CodeCookieRejected}
	}
	http.SetCookie(writer, &http.Cookie{
		Name: httpauth.SessionCookieName, Value: material.rawToken, Path: "/",
		Expires: expires, MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Renew reissues the same session cookie value with a later Max-Age/Expires
// (FIX-7 #3, httpauth.CookieRenewer): it is the ONLY caller-facing way this
// package writes a Set-Cookie whose Value it did not itself just generate
// with NewSessionMaterial, because it never mints new session material --
// rawToken must be the exact value the request already presented (httpauth
// re-extracts it from the same validated cookie/bearer credential
// Authenticate parsed), keeping the opaque token stable across a renewal. It
// shares the same expiry validation Issue already applies (1s..24h from now),
// so it can never emit a Max-Age that violates ADR-0030 either.
func (issuer *CookieIssuer) Renew(writer http.ResponseWriter, rawToken string, expiresAt time.Time) error {
	if issuer == nil || issuer.now == nil || writer == nil || !validSessionTokenShape(rawToken) || expiresAt.IsZero() {
		return &Error{code: CodeCookieRejected}
	}
	now := issuer.now().UTC()
	expires := expiresAt.UTC().Truncate(time.Second)
	lifetime := expires.Sub(now)
	if lifetime < time.Second || lifetime > maximumSessionLife {
		return &Error{code: CodeCookieRejected}
	}
	maxAge := int(lifetime / time.Second)
	if maxAge < 1 || time.Duration(maxAge)*time.Second > lifetime {
		return &Error{code: CodeCookieRejected}
	}
	http.SetCookie(writer, &http.Cookie{
		Name: httpauth.SessionCookieName, Value: rawToken, Path: "/",
		Expires: expires, MaxAge: maxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// Expire clears the session cookie under the same reviewed profile with
// Max-Age=0. Logout relies on it so the browser cannot keep presenting a
// server-revoked token.
func (issuer *CookieIssuer) Expire(writer http.ResponseWriter) error {
	if issuer == nil || issuer.now == nil || writer == nil {
		return &Error{code: CodeCookieRejected}
	}
	http.SetCookie(writer, &http.Cookie{
		Name: httpauth.SessionCookieName, Value: "", Path: "/",
		Expires: issuer.now().UTC().Add(-24 * time.Hour), MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func validMaterial(value SessionMaterial) bool {
	return validSessionTokenShape(value.rawToken) && validDigest(value.digest)
}

// validSessionTokenShape is the same raw-token shape check validMaterial
// already applies, factored out for Renew (FIX-7 #3): a renewal never mints
// new SessionMaterial, so it has no digest to check alongside the token.
func validSessionTokenShape(rawToken string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(rawToken)
	return err == nil && len(decoded) == sessionBytes && base64.RawURLEncoding.EncodeToString(decoded) == rawToken
}

func validDigest(value identity.KeyedDigest) bool {
	_, err := identity.NewKeyedDigest(value.Value())
	return err == nil
}
