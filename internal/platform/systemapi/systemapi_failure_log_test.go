package systemapi

// Card D-12: the system endpoints' own writer can answer 500 when a response
// payload cannot be encoded (the only 5xx branch in this boundary). This test
// drives that exact production writer through the failure-log middleware and
// proves one content-free line names the request and the cause, with no
// request secret; the healthy path leaves no failure line.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/buildinfo"
	"knowvault.local/verified-workspace/internal/platform/failurelog"
)

func captureSystemLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	buffer := &bytes.Buffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buffer, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buffer
}

func systemFailureLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()
	lines := []map[string]any{}
	for _, raw := range strings.Split(strings.TrimSpace(buffer.String()), "\n") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal([]byte(raw), &line); err != nil {
			t.Fatalf("system log line is not JSON: %q: %v", raw, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestSystemEndpointEncodingFailureLeavesOneDiagnosableLineWithoutSecrets(t *testing.T) {
	buffer := captureSystemLogs(t)
	// writeJSON is the system boundary's own response writer; an unencodable
	// payload is the one input that reaches its 500 branch.
	unencodable := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, make(chan int))
	})
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example"+BuildInfoPath, nil)
	request.Header.Set("Cookie", "session=system-cookie-must-never-be-logged")
	request.Header.Set("Authorization", "Bearer system-bearer-must-never-be-logged")
	response := httptest.NewRecorder()

	failurelog.WithFailureLog(unencodable).ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "RESPONSE_ENCODING_FAILED") {
		t.Fatalf("response changed: status=%d body=%q", response.Code, response.Body.String())
	}
	lines := systemFailureLines(t, buffer)
	if len(lines) != 1 {
		t.Fatalf("want exactly one failure line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if line["method"] != http.MethodGet {
		t.Fatalf("method=%v", line["method"])
	}
	if line["route"] != BuildInfoPath {
		t.Fatalf("route=%v", line["route"])
	}
	if line["status"] != float64(http.StatusInternalServerError) {
		t.Fatalf("status=%v", line["status"])
	}
	if line["cause"] != "system endpoint: response encoding failed" {
		t.Fatalf("cause=%v", line["cause"])
	}
	captured := buffer.String()
	for _, secret := range []string{"system-cookie-must-never-be-logged", "system-bearer-must-never-be-logged"} {
		if strings.Contains(captured, secret) {
			t.Fatalf("secret %q leaked into the system failure log: %s", secret, captured)
		}
	}
}

func TestHealthySystemEndpointLeavesNoFailureLine(t *testing.T) {
	buffer := captureSystemLogs(t)
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://workspace.example"+HealthPath, nil)

	failurelog.WithFailureLog(New(buildinfo.Info{})).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	if lines := systemFailureLines(t, buffer); len(lines) != 0 {
		t.Fatalf("healthy endpoint logged a failure line: %v", lines)
	}
}
