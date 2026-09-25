package webui

// Card D-12: the web UI can answer 503 once its asset root is closed (or was
// never installed). This test installs the production failure-log middleware
// around the real production handler and proves the line names the request
// and the cause with no request secret.

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

func captureUILogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buffer
}

func uiFailureLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := []map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("web UI log line is not JSON: %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestWebUIFailureLeavesOneDiagnosableLineWithoutSecrets(t *testing.T) {
	handler, err := newProduction(http.NotFoundHandler(), writeAssets(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	buffer := captureUILogs(t)
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example/", nil)
	request.Header.Set("Cookie", "session=ui-cookie-must-never-be-logged")
	request.Header.Set("Authorization", "Bearer ui-bearer-must-never-be-logged")
	response := httptest.NewRecorder()

	failurelog.WithFailureLog(handler).ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable || response.Body.Len() != 0 {
		t.Fatalf("response changed: status=%d body=%q", response.Code, response.Body.String())
	}
	lines := uiFailureLines(t, buffer)
	if len(lines) != 1 {
		t.Fatalf("want exactly one failure line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if line["method"] != http.MethodGet {
		t.Fatalf("method=%v", line["method"])
	}
	if line["route"] != "/" {
		t.Fatalf("route=%v", line["route"])
	}
	if line["status"] != float64(http.StatusServiceUnavailable) {
		t.Fatalf("status=%v", line["status"])
	}
	if line["cause"] != "web UI: assets root closed" {
		t.Fatalf("cause=%v", line["cause"])
	}
	captured := buffer.String()
	for _, secret := range []string{"ui-cookie-must-never-be-logged", "ui-bearer-must-never-be-logged"} {
		if strings.Contains(captured, secret) {
			t.Fatalf("secret %q leaked into the web UI failure log: %s", secret, captured)
		}
	}
}
