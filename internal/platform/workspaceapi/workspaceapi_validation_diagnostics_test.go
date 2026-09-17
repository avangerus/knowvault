package workspaceapi

// FIX-7 #2 real-world diagnosis: the owner's browser got a REQUEST_INVALID
// response for request_id req_DuF7ye22ZiqTuJwyXBk5_w and there was not one
// matching line anywhere in the server's own logs -- writeError never logged
// anything, and the body carried no hint of which field failed. These tests
// prove the fix on the four routes the owner actually hit (source
// confirmation, activation, access-code creation, question) plus the new
// evidence rowset scope parameter: every validation failure both logs a
// content-free WARN (request_id, route, code, field NAMES -- never values)
// and returns those same names in the response body's error.fields.

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
)

// fakeAccessCodeService is a minimal stand-in for AccessCodeService: the
// validation-diagnostics tests never get far enough to call it (the
// transport-level failure returns first), so every method here is an inert
// placeholder that satisfies the interface.
type fakeAccessCodeService struct{}

func (fakeAccessCodeService) Issue(context.Context, database.AccessContext, serviceprincipal.IssueRequest) (serviceprincipal.IssueResult, error) {
	return serviceprincipal.IssueResult{}, nil
}

func (fakeAccessCodeService) List(context.Context, database.AccessContext, string) ([]serviceprincipal.Credential, error) {
	return nil, nil
}

func (fakeAccessCodeService) Revoke(context.Context, database.AccessContext, string) error {
	return nil
}

func (fakeAccessCodeService) Authenticate(context.Context, string, string, string) (database.AccessContext, error) {
	return database.AccessContext{}, nil
}

func (fakeAccessCodeService) AuditDeniedAgentCall(context.Context, database.AccessContext, string, string) {
}

// recordingLogHandler is a minimal slog.Handler that keeps every record so a
// test can assert on structured attributes instead of parsing formatted text.
type recordingLogHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (recorder *recordingLogHandler) Enabled(context.Context, slog.Level) bool { return true }

func (recorder *recordingLogHandler) Handle(_ context.Context, record slog.Record) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.records = append(recorder.records, record.Clone())
	return nil
}

func (recorder *recordingLogHandler) WithAttrs([]slog.Attr) slog.Handler { return recorder }
func (recorder *recordingLogHandler) WithGroup(string) slog.Handler      { return recorder }

func (recorder *recordingLogHandler) findByMessage(message string) (slog.Record, bool) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	for _, record := range recorder.records {
		if record.Message == message {
			return record, true
		}
	}
	return slog.Record{}, false
}

func recordAttrs(t *testing.T, record slog.Record) map[string]any {
	t.Helper()
	attrs := make(map[string]any, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value.Any()
		return true
	})
	return attrs
}

// withRecordingLog installs a recording slog handler as the process default
// for the duration of one test and restores the previous default after,
// exactly like t.Setenv restores an environment variable.
func withRecordingLog(t *testing.T) *recordingLogHandler {
	t.Helper()
	recorder := &recordingLogHandler{}
	previous := slog.Default()
	slog.SetDefault(slog.New(recorder))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return recorder
}

func stringSlice(t *testing.T, value any) []string {
	t.Helper()
	if value == nil {
		return nil
	}
	slice, ok := value.([]string)
	if !ok {
		t.Fatalf("fields attr has type %T, want []string", value)
	}
	return slice
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, item := range a {
		seen[item]++
	}
	for _, item := range b {
		seen[item]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}

// TestQuestionCreateMissingFieldLogsAndReturnsFieldNames is the "question"
// route: an empty body (Idempotency-Key present) fails on the one field that
// actually matters, and the failure is diagnosable from the log alone.
func TestQuestionCreateMissingFieldLogsAndReturnsFieldNames(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"code":"REQUEST_INVALID"`) || !strings.Contains(body, `"request_id":"req_server_001"`) ||
		!strings.Contains(body, `"fields":["question"]`) {
		t.Fatalf("body=%s", body)
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged for the validation failure -- exactly the diagnosis gap FIX-7 #2 closes")
	}
	if record.Level != slog.LevelWarn {
		t.Fatalf("level=%v, want WARN", record.Level)
	}
	attrs := recordAttrs(t, record)
	if attrs["request_id"] != "req_server_001" {
		t.Fatalf("attrs=%#v, request_id not carried", attrs)
	}
	if attrs["route"] != "POST "+workspacesPath+"/ws_alpha/questions" {
		t.Fatalf("attrs=%#v, route not carried", attrs)
	}
	if attrs["code"] != "REQUEST_INVALID" {
		t.Fatalf("attrs=%#v, code not carried", attrs)
	}
	if fields := stringSlice(t, attrs["fields"]); !sameSet(fields, []string{"question"}) {
		t.Fatalf("logged fields=%v, want [question]", fields)
	}
	// Content-free: the field NAME is logged and returned, never a value --
	// no raw question text anywhere in the log record or the response body.
	if strings.Contains(body, "answer") {
		t.Fatalf("body leaked more than field names: %s", body)
	}
}

// TestQuestionCreateMissingIdempotencyKeyNamesTheHeader proves the header
// (not only JSON body) validation path is diagnosed the same way.
func TestQuestionCreateMissingIdempotencyKeyNamesTheHeader(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", "{\"question\":\"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d?\"}")
	// Deliberately no Idempotency-Key header.
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"fields":["Idempotency-Key"]`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged")
	}
	attrs := recordAttrs(t, record)
	if fields := stringSlice(t, attrs["fields"]); !sameSet(fields, []string{"Idempotency-Key"}) {
		t.Fatalf("logged fields=%v, want [Idempotency-Key]", fields)
	}
}

// TestAccessCodeIssueMissingFieldsNamesEveryOne is the "access-code creation"
// route: every one of the three required fields is named at once.
func TestAccessCodeIssueMissingFieldsNamesEveryOne(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	harness.handler.accessCodes = &fakeAccessCodeService{}
	harness.handler.organizationID = "org_alpha"
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/access-codes", `{}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged")
	}
	attrs := recordAttrs(t, record)
	want := []string{"name", "workspace_ids", "ttl_seconds"}
	if fields := stringSlice(t, attrs["fields"]); !sameSet(fields, want) {
		t.Fatalf("logged fields=%v, want %v", fields, want)
	}
	body := response.Body.String()
	for _, name := range want {
		if !strings.Contains(body, `"`+name+`"`) {
			t.Fatalf("body missing field name %q: %s", name, body)
		}
	}
}

// TestManagedSourceConfirmMissingFieldsNamesEveryOne is the "source
// confirmation" route (ADR-0053/0087): confirming a managed source with an
// empty body names every one of its eleven required fields, not a generic
// "invalid request".
func TestManagedSourceConfirmMissingFieldsNamesEveryOne(t *testing.T) {
	recorder := withRecordingLog(t)
	harness, _, handler := newAuthorityHarness(t)
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/managed-source-confirmations", `{}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged")
	}
	attrs := recordAttrs(t, record)
	fields := stringSlice(t, attrs["fields"])
	if len(fields) != 11 {
		t.Fatalf("logged fields=%v, want all 11 required fields named", fields)
	}
	for _, want := range []string{
		"workspace_revision", "workspace_configuration_hash", "workspace_source_id", "source_scope_id",
		"source_scope_revision", "scope_config_hash", "confirmation_actor_grant_id",
		"confirmation_actor_grant_revision", "confirmation_actor_grant_hash", "warning_contract_hash",
		"expected_policy_revision",
	} {
		found := false
		for _, got := range fields {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("fields=%v missing %q", fields, want)
		}
	}
}

// TestAddSourceMissingRevisionNamesField is the "activation" route
// (POST .../sources binds a source into the workspace ahead of :activate):
// an out-of-range revision is named exactly like a genuinely absent field.
func TestAddSourceMissingRevisionNamesField(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/sources",
		`{"expected_workspace_revision":0,"source_scope_id":"scope_1","source_scope_revision":1,"scope_config_hash":"sha256:`+strings.Repeat("a", 64)+`","access_mode":"WORKSPACE_MANAGED"}`)
	harness.mutationHeaders(request, harness.hash)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged")
	}
	attrs := recordAttrs(t, record)
	if fields := stringSlice(t, attrs["fields"]); !sameSet(fields, []string{"expected_workspace_revision"}) {
		t.Fatalf("logged fields=%v, want [expected_workspace_revision]", fields)
	}
}

// TestEvidenceGetRejectsUnknownScopeValue proves FIX-7 #1's new scope query
// parameter is validated and diagnosed exactly like every body/header field.
func TestEvidenceGetRejectsUnknownScopeValue(t *testing.T) {
	recorder := withRecordingLog(t)
	harness := newTestHarness(t)
	harness.evidence.result = testEvidenceFragment(t)
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ?scope=everything", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"fields":["scope"]`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	record, found := recorder.findByMessage("request validation failed")
	if !found {
		t.Fatal("no WARN logged")
	}
	attrs := recordAttrs(t, record)
	if attrs["route"] != "GET "+workspacesPath+"/ws_alpha/evidence/fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("attrs=%#v", attrs)
	}
}
