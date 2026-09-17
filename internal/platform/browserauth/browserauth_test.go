package browserauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/tenantsecurity"
)

func TestSessionMaterialUsesOnlySessionSelectionAndRedactsFormatting(t *testing.T) {
	identityDigestor := &purposeDigestor{name: "identity"}
	sessionDigestor := &purposeDigestor{name: "session"}
	security := testSecurity(t, identityDigestor, sessionDigestor)
	material, err := newSessionMaterial(bytes.NewReader(bytes.Repeat([]byte{0x5a}, sessionBytes)), security)
	if err != nil {
		t.Fatal(err)
	}
	if sessionDigestor.purpose != "session_token" || identityDigestor.purpose != "" || material.Digest().Value() == "" {
		t.Fatalf("identity purpose=%q session purpose=%q digest=%q", identityDigestor.purpose, sessionDigestor.purpose, material.Digest().Value())
	}
	for _, formatted := range []string{fmt.Sprint(material), fmt.Sprintf("%#v", material), fmt.Sprintf("%+v", material)} {
		if strings.Contains(formatted, material.rawToken) || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("material formatting leaked token: %q", formatted)
		}
	}
}

func TestCookieIssuerEmitsExactHostOnlyBoundedProfile(t *testing.T) {
	security := testSecurity(t, &purposeDigestor{name: "identity"}, &purposeDigestor{name: "session"})
	material, err := newSessionMaterial(bytes.NewReader(bytes.Repeat([]byte{0x42}, sessionBytes)), security)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	issuer := &CookieIssuer{now: func() time.Time { return now }}
	response := httptest.NewRecorder()
	expires := now.Add(23*time.Hour + 59*time.Second)
	if err := issuer.Issue(response, material, expires); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != httpauth.SessionCookieName || cookie.Value != material.rawToken || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || !cookie.Expires.Equal(expires) || cookie.MaxAge != int(expires.Sub(now)/time.Second) {
		t.Fatalf("cookie=%#v header=%q", cookie, response.Header().Get("Set-Cookie"))
	}
	header := response.Header().Get("Set-Cookie")
	for _, required := range []string{"Path=/", "Expires=", "Max-Age=", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(header, required) {
			t.Fatalf("missing %q in %q", required, header)
		}
	}
	if strings.Contains(strings.ToLower(header), "domain=") {
		t.Fatalf("host-only cookie unexpectedly has Domain: %q", header)
	}
}

func TestCookieIssuerExpireEmitsExactClearingProfile(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	issuer := &CookieIssuer{now: func() time.Time { return now }}
	response := httptest.NewRecorder()
	if err := issuer.Expire(response); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies=%#v", cookies)
	}
	cookie := cookies[0]
	if cookie.Name != httpauth.SessionCookieName || cookie.Value != "" || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != -1 || !cookie.Expires.Before(now) {
		t.Fatalf("cookie=%#v header=%q", cookie, response.Header().Get("Set-Cookie"))
	}
	header := response.Header().Get("Set-Cookie")
	for _, required := range []string{"Path=/", "Expires=", "Max-Age=0", "HttpOnly", "Secure", "SameSite=Lax"} {
		if !strings.Contains(header, required) {
			t.Fatalf("missing %q in %q", required, header)
		}
	}
	if strings.Contains(strings.ToLower(header), "domain=") {
		t.Fatalf("host-only cookie unexpectedly has Domain: %q", header)
	}
	for name, expire := range map[string]func() error{
		"nil issuer": func() error { return (*CookieIssuer)(nil).Expire(response) },
		"nil writer": func() error { return issuer.Expire(nil) },
	} {
		name, expire := name, expire
		t.Run(name, func(t *testing.T) {
			if err := expire(); CodeOf(err) != CodeCookieRejected {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestCookieIssuerFailsClosedWithoutWritingOnInvalidMaterialOrLifetime(t *testing.T) {
	security := testSecurity(t, &purposeDigestor{name: "identity"}, &purposeDigestor{name: "session"})
	material, err := newSessionMaterial(bytes.NewReader(bytes.Repeat([]byte{0x31}, sessionBytes)), security)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	for name, fixture := range map[string]struct {
		material SessionMaterial
		expires  time.Time
	}{
		"zero material": {SessionMaterial{}, now.Add(time.Hour)},
		"expired":       {material, now},
		"subsecond":     {material, now.Add(500 * time.Millisecond)},
		"over maximum":  {material, now.Add(maximumSessionLife + time.Second)},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			issuer := &CookieIssuer{now: func() time.Time { return now }}
			if err := issuer.Issue(response, fixture.material, fixture.expires); CodeOf(err) != CodeCookieRejected || response.Header().Get("Set-Cookie") != "" {
				t.Fatalf("error=%v headers=%#v", err, response.Header())
			}
		})
	}
}

func TestSessionMaterialFailsClosedOnEntropyAndDigestErrors(t *testing.T) {
	valid := testSecurity(t, &purposeDigestor{name: "identity"}, &purposeDigestor{name: "session"})
	if material, err := newSessionMaterial(failingReader{}, valid); CodeOf(err) != CodeMaterialFailed || material.Digest().Value() != "" {
		t.Fatalf("entropy result=%#v error=%v", material, err)
	}
	invalidDigest := testSecurity(t, &purposeDigestor{name: "identity"}, &purposeDigestor{name: "session", err: errors.New("KMS unavailable")})
	if material, err := newSessionMaterial(bytes.NewReader(make([]byte, sessionBytes)), invalidDigest); CodeOf(err) != CodeMaterialFailed || material.Digest().Value() != "" {
		t.Fatalf("digest result=%#v error=%v", material, err)
	}
}

func TestErrorsAreRedactedAndDoNotUnwrap(t *testing.T) {
	err := (&CookieIssuer{}).Issue(httptest.NewRecorder(), SessionMaterial{}, time.Now())
	if err == nil || err.Error() != string(CodeCookieRejected) {
		t.Fatalf("error=%v", err)
	}
	if _, ok := err.(interface{ Unwrap() error }); ok {
		t.Fatal("browser auth error must not retain cause")
	}
}

func testSecurity(t *testing.T, identityDigestor, sessionDigestor tenantsecurity.Digestor) tenantsecurity.Context {
	t.Helper()
	security, err := tenantsecurity.NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", sessionDigestor)
	if err != nil {
		t.Fatal(err)
	}
	return security
}

type purposeDigestor struct {
	name    string
	purpose string
	err     error
}

func (digestor *purposeDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	digestor.purpose = purpose
	if digestor.err != nil {
		return identity.KeyedDigest{}, digestor.err
	}
	hash := fmt.Sprintf("%064x", len(digestor.name+purpose+raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + hash)
}

func (digestor *purposeDigestor) KeyMaterialFingerprint() [32]byte {
	return sha256.Sum256([]byte(digestor.name))
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
