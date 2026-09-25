package oidcweb

// Card D-12: the sign-in boundary can answer 503 (AUTH_UNAVAILABLE) on every
// OIDC dependency failure. This test installs the production failure-log
// middleware around the real handler and proves one content-free line names
// the request and the cause, with no secret from the request.

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/failurelog"
)

func captureSignInLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buffer
}

func signInFailureLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := []map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("sign-in log line is not JSON: %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestSignInFailureLeavesOneDiagnosableLineWithoutSecrets(t *testing.T) {
	fixture := newHandlerFixture(t)
	// A private dependency failure that must never surface in the browser and
	// must never be logged verbatim either.
	fixture.protocol.discoverErr = errors.New("private discovery failure must not be logged")
	buffer := captureSignInLogs(t)
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example/auth/login", nil)
	request.Header.Set("Cookie", "session=sign-in-cookie-must-never-be-logged")
	request.Header.Set("Authorization", "Bearer sign-in-bearer-must-never-be-logged")
	response := httptest.NewRecorder()

	failurelog.WithFailureLog(fixture.handler).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(responseBody(response), "AUTH_UNAVAILABLE") {
		t.Fatalf("response changed: status=%d body=%q", response.Code, response.Body.String())
	}
	lines := signInFailureLines(t, buffer)
	if len(lines) != 1 {
		t.Fatalf("want exactly one failure line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if line["method"] != http.MethodGet {
		t.Fatalf("method=%v", line["method"])
	}
	if line["route"] != "/auth/login" {
		t.Fatalf("route=%v", line["route"])
	}
	if line["status"] != float64(http.StatusServiceUnavailable) {
		t.Fatalf("status=%v", line["status"])
	}
	if line["cause"] != "sign-in: AUTH_UNAVAILABLE" {
		t.Fatalf("cause=%v", line["cause"])
	}
	captured := buffer.String()
	for _, secret := range []string{
		"sign-in-cookie-must-never-be-logged",
		"sign-in-bearer-must-never-be-logged",
		"private discovery failure must not be logged",
	} {
		if strings.Contains(captured, secret) {
			t.Fatalf("secret %q leaked into the sign-in failure log: %s", secret, captured)
		}
	}
}
