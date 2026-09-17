package apphttp

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/systemapi"
)

func TestSecurityHeadersOnEveryBranch(t *testing.T) {
	for name, requestURL := range map[string]string{
		"login":               "https://workspace.example/auth/login",
		"system health":       "https://workspace.example" + systemapi.HealthPath,
		"system capabilities": "https://workspace.example" + systemapi.CapabilitiesPath,
		"workspace api":       "https://workspace.example/api/v1/workspaces",
		"root ui":             "https://workspace.example/",
		"reserved auth 404":   "https://workspace.example/auth/logout",
	} {
		t.Run(name, func(t *testing.T) {
			calls := make([]string, 0, 1)
			dispatcher := testDispatcher(t, &calls)
			guarded := WithSecurityHeaders(dispatcher)
			response := httptest.NewRecorder()
			guarded.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestURL, nil))
			assertSecurityHeaders(t, response.Header())
		})
	}
}

func TestSecurityHeadersOnImplicitWrite(t *testing.T) {
	// A child that writes a body without an explicit WriteHeader still commits
	// through the middleware, so the header set must be present.
	guarded := WithSecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("body"))
	}))
	response := httptest.NewRecorder()
	guarded.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/", nil))
	if response.Code != http.StatusOK || response.Body.String() != "body" {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	assertSecurityHeaders(t, response.Header())
}

func TestSecurityHeadersSurviveChildRemoval(t *testing.T) {
	// A child that deliberately deletes the header before writing must not
	// publish a response without it.
	guarded := WithSecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Del("Content-Security-Policy")
		writer.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	guarded.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/", nil))
	assertSecurityHeaders(t, response.Header())
}

func TestSecurityHeadersDoNotOverwriteChildValue(t *testing.T) {
	stricter := "default-src 'none'"
	guarded := WithSecurityHeaders(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Security-Policy", stricter)
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
	}))
	response := httptest.NewRecorder()
	guarded.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://workspace.example/", nil))
	if got := response.Header().Get("Content-Security-Policy"); got != stricter {
		t.Fatalf("child CSP=%q was overwritten with %q", stricter, got)
	}
	if got := response.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("child Content-Type=%q was clobbered", got)
	}
}

func TestSecurityHeadersRejectNilHandler(t *testing.T) {
	if WithSecurityHeaders(nil) != nil {
		t.Fatal("nil handler must stay nil")
	}
}

func assertSecurityHeaders(t *testing.T, header http.Header) {
	t.Helper()
	if got := header.Get("Content-Security-Policy"); got != contentSecurityPolicy {
		t.Fatalf("Content-Security-Policy=%q", got)
	}
	if got := header.Get("X-Frame-Options"); got != frameOptions {
		t.Fatalf("X-Frame-Options=%q", got)
	}
	if got := header.Get("Strict-Transport-Security"); got != strictTransportSecurity {
		t.Fatalf("Strict-Transport-Security=%q", got)
	}
}
