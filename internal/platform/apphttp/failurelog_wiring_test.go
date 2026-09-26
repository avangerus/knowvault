package apphttp

// Card D-12: the production composition wraps the dispatcher as
// WithSecurityHeaders(failurelog.WithFailureLog(dispatcher)). This test pins
// that exact order: if the failure log ever moves outside the security-header
// wrapper, the handler stops receiving the failure recorder and the cause
// silently degrades to "unclassified".

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/failurelog"
)

func TestProductionWrapperOrderExposesTheFailureCause(t *testing.T) {
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	inner := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		failurelog.Set(writer, "workspace service capability missing: WorkspaceAuthority")
		writer.WriteHeader(http.StatusServiceUnavailable)
	})
	handler := WithSecurityHeaders(failurelog.WithFailureLog(inner))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/workspaces/ws_alpha/member-candidates", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d", response.Code)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"} {
		if response.Header().Get(header) == "" {
			t.Fatalf("security header %s missing", header)
		}
	}
	raw := strings.TrimSpace(buffer.String())
	if raw == "" {
		t.Fatal("no failure line was logged through the production wrapper order")
	}
	var line map[string]any
	if err := json.Unmarshal([]byte(raw), &line); err != nil {
		t.Fatalf("failure line is not JSON: %q: %v", raw, err)
	}
	if line["cause"] != "workspace service capability missing: WorkspaceAuthority" {
		t.Fatalf("cause=%v", line["cause"])
	}
}
