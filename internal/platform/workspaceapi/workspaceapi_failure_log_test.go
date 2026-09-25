package workspaceapi

// Card D-12: the workspace API is the boundary the demo stand actually hit.
// These tests install the production failure-log middleware around the real
// handler and prove that a 5xx both stays byte-for-byte what it was and leaves
// one content-free server-log line naming method, route, status and cause.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/failurelog"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// workspaceFailureLines returns the attrs of every failure-log record, so a
// test can assert on structured server-log output rather than formatted text.
func workspaceFailureLines(t *testing.T, recorder *recordingLogHandler) []map[string]any {
	t.Helper()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	lines := []map[string]any{}
	for _, record := range recorder.records {
		if record.Message != failurelog.Message {
			continue
		}
		attrs := map[string]any{}
		record.Attrs(func(attr slog.Attr) bool {
			attrs[attr.Key] = attr.Value.Any()
			return true
		})
		lines = append(lines, attrs)
	}
	return lines
}

func TestWorkspaceAPIFailureLeavesOneDiagnosableLine(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	harness.service.err = workspacerepository.NewError(workspacerepository.CodePersistence, errors.New("storage backend is gone"))
	response := httptest.NewRecorder()

	failurelog.WithFailureLog(harness.handler).ServeHTTP(response, harness.request(http.MethodGet, workspacesPath, ""))

	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "SERVICE_UNAVAILABLE") {
		t.Fatalf("response changed: status=%d body=%s", response.Code, response.Body.String())
	}
	lines := workspaceFailureLines(t, recorder)
	if len(lines) != 1 {
		t.Fatalf("want exactly one failure line, got %d: %v", len(lines), lines)
	}
	line := lines[0]
	if line["method"] != http.MethodGet {
		t.Fatalf("method=%v", line["method"])
	}
	if line["route"] != workspacesPath {
		t.Fatalf("route=%v", line["route"])
	}
	if line["status"] != int64(http.StatusServiceUnavailable) {
		t.Fatalf("status=%v", line["status"])
	}
	if line["cause"] != "workspace service: WORKSPACE_PERSISTENCE_FAILED" {
		t.Fatalf("cause=%v", line["cause"])
	}
}

// TestWorkspaceAPIDifferentFailuresNameDifferentCauses is the card's "two
// failures give two lines whose causes differ and each names what actually
// failed": a storage persistence failure and the demo stand's lost capability
// (the injected service no longer satisfying a required interface after a
// rename).
func TestWorkspaceAPIDifferentFailuresNameDifferentCauses(t *testing.T) {
	recorder := withRecordingLog(t)

	persistence := newTestHarness(t)
	persistence.service.err = workspacerepository.NewError(workspacerepository.CodePersistence, errors.New("storage backend is gone"))
	persistenceResponse := httptest.NewRecorder()
	failurelog.WithFailureLog(persistence.handler).ServeHTTP(persistenceResponse, persistence.request(http.MethodGet, workspacesPath, ""))

	missingCapability := newTestHarness(t)
	capabilityResponse := httptest.NewRecorder()
	failurelog.WithFailureLog(missingCapability.handler).ServeHTTP(capabilityResponse, missingCapability.request(http.MethodGet, workspacesPath+"/ws_alpha/member-candidates?q=Bob", ""))

	if persistenceResponse.Code != http.StatusServiceUnavailable || capabilityResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("statuses=%d/%d", persistenceResponse.Code, capabilityResponse.Code)
	}
	lines := workspaceFailureLines(t, recorder)
	if len(lines) != 2 {
		t.Fatalf("want two failure lines, got %d: %v", len(lines), lines)
	}
	causes := map[string]bool{}
	for _, line := range lines {
		causes[line["cause"].(string)] = true
	}
	if len(causes) != 2 {
		t.Fatalf("causes did not differ: %v", causes)
	}
	if !causes["workspace service: WORKSPACE_PERSISTENCE_FAILED"] {
		t.Fatalf("storage failure not named: %v", causes)
	}
	if !causes["workspace service capability missing: WorkspaceMemberCandidateAuthority"] {
		t.Fatalf("lost capability not named: %v", causes)
	}
}

// TestWorkspaceAPIFailureLineCarriesNoRequestSecret runs the same 5xx through
// both credential transports (browser session cookie and explicit bearer
// session) with a password-shaped body secret, and requires none of the
// values in the captured log.
func TestWorkspaceAPIFailureLineCarriesNoRequestSecret(t *testing.T) {
	const bodySecret = "body-password-must-never-be-logged"
	for name, build := range map[string]func(*testHarness) *http.Request{
		"session cookie": func(harness *testHarness) *http.Request {
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example"+workspacesPath, strings.NewReader(`{"password":"`+bodySecret+`"}`))
			request.Header.Set("Cookie", httpauth.SessionCookieName+"="+harness.token)
			return request
		},
		"authorization bearer": func(harness *testHarness) *http.Request {
			request := httptest.NewRequest(http.MethodGet, "https://workspace.example"+workspacesPath, strings.NewReader(`{"password":"`+bodySecret+`"}`))
			request.Header.Set("Authorization", "Bearer "+harness.token)
			return request
		},
	} {
		name, build := name, build
		t.Run(name, func(t *testing.T) {
			recorder := withRecordingLog(t)
			harness := newTestHarness(t)
			harness.service.err = workspacerepository.NewError(workspacerepository.CodePersistence, errors.New("storage backend is gone"))
			response := httptest.NewRecorder()

			failurelog.WithFailureLog(harness.handler).ServeHTTP(response, build(harness))

			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			lines := workspaceFailureLines(t, recorder)
			if len(lines) != 1 {
				t.Fatalf("want one failure line, got %v", lines)
			}
			captured, err := json.Marshal(lines)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{bodySecret, harness.token} {
				if strings.Contains(string(captured), secret) {
					t.Fatalf("secret %q leaked into the failure log: %s", secret, captured)
				}
			}
		})
	}
}
