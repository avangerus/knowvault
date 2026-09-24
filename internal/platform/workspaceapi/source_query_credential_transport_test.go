package workspaceapi

// S3 card 2b focused transport tests for the organization-OWNER control over a
// PostgreSQL source connection's SQL query credential. They prove the closed
// set/clear envelope, that a failed check is the capability's exact closed code
// with nothing echoed, that an unauthorized or foreign connection stays the
// single content-free not-found, and that a composition without the capability
// fails closed.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const testQueryCredentialReference = "cred_01H9ABCDEFGHJKMNPQRSTVWXYZ"

func callSetQueryCredential(t *testing.T, harness *testHarness, connectionID, body string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	request := harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/source-connections/"+connectionID+":set-query-credential", body)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

func callClearQueryCredential(t *testing.T, harness *testHarness, connectionID string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	request := harness.request(http.MethodPost, apiPrefix+"/workspaces/ws_alpha/source-connections/"+connectionID+":clear-query-credential", "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	var decoded map[string]any
	if response.Code == http.StatusOK {
		decoded = decodeJSONObject(t, response.Body.String())
	}
	return response, decoded
}

func TestSourceQueryCredentialSetsAndClearsThroughTheOwnerControl(t *testing.T) {
	harness := newTestHarness(t)
	response, decoded := callSetQueryCredential(t, harness, testSourceSQLSourceID,
		`{"credential_reference":"`+testQueryCredentialReference+`"}`)
	if response.Code != http.StatusOK || decoded["connection_id"] != testSourceSQLSourceID || decoded["sql_available"] != true {
		t.Fatalf("set = %d %#v", response.Code, decoded)
	}
	if harness.sources.queryCredentialCalls != 1 || harness.sources.queryCredentialReference != testQueryCredentialReference ||
		harness.sources.access.PrincipalID != "usr_alice" {
		t.Fatalf("provider call = %#v", harness.sources)
	}
	if strings.Contains(response.Body.String(), testQueryCredentialReference) {
		t.Fatalf("response echoed the credential reference: %s", response.Body.String())
	}

	response, decoded = callClearQueryCredential(t, harness, testSourceSQLSourceID)
	if response.Code != http.StatusOK || decoded["sql_available"] != false || harness.sources.queryCredentialCalls != 2 ||
		harness.sources.queryCredentialReference != "" {
		t.Fatalf("clear = %d %#v provider=%#v", response.Code, decoded, harness.sources)
	}
}

func TestSourceQueryCredentialClosedRefusalsReachTheOperator(t *testing.T) {
	for _, code := range []string{
		SourceQueryCredentialUnresolved,
		"SOURCE_QUERY_CREDENTIAL_DATABASE_MISMATCH",
		"SOURCE_QUERY_CREDENTIAL_COLUMN_PRIVILEGE",
		"SOURCE_QUERY_CREDENTIAL_DATABASE_REJECTED",
	} {
		t.Run(code, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.sources.queryCredentialErr = &SourceQueryCredentialRefusal{Code: code}
			response, _ := callSetQueryCredential(t, harness, testSourceSQLSourceID,
				`{"credential_reference":"`+testQueryCredentialReference+`"}`)
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), code) {
				t.Fatalf("refusal = %d %s, want 409 %s", response.Code, response.Body.String(), code)
			}
			if strings.Contains(response.Body.String(), testQueryCredentialReference) ||
				strings.Contains(response.Body.String(), "postgres://") {
				t.Fatalf("refusal disclosed a credential: %s", response.Body.String())
			}
		})
	}
}

func TestSourceQueryCredentialNonOwnerIsContentFreeNotFound(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.queryCredentialErr = workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	response, _ := callSetQueryCredential(t, harness, testSourceSQLSourceID,
		`{"credential_reference":"`+testQueryCredentialReference+`"}`)
	if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), "NOT_FOUND") {
		t.Fatalf("non-owner = %d %s, want 404 NOT_FOUND", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), testQueryCredentialReference) || strings.Contains(response.Body.String(), testSourceSQLSourceID) {
		t.Fatalf("not-found echoed content: %s", response.Body.String())
	}
}

func TestSourceQueryCredentialArgumentEnvelopeIsClosed(t *testing.T) {
	harness := newTestHarness(t)
	for name, body := range map[string]string{
		"missing reference": `{}`,
		"empty reference":   `{"credential_reference":""}`,
		"malformed":         `{"credential_reference":"cred_short"}`,
		"dsn instead":       `{"credential_reference":"postgres://user:pass@db.example/knowvault?sslmode=verify-full"}`,
		"unknown member":    `{"credential_reference":"` + testQueryCredentialReference + `","sql":"SELECT 1"}`,
	} {
		t.Run(name, func(t *testing.T) {
			response, _ := callSetQueryCredential(t, harness, testSourceSQLSourceID, body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("%s = %d %s, want 400", name, response.Code, response.Body.String())
			}
			if harness.sources.queryCredentialCalls != 0 {
				t.Fatalf("%s reached the provider", name)
			}
		})
	}
	request := harness.request(http.MethodGet, apiPrefix+"/workspaces/ws_alpha/source-connections/"+testSourceSQLSourceID+":set-query-credential", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", response.Code)
	}
}

func TestSourceQueryCredentialFailsClosedWithoutCapability(t *testing.T) {
	harness := newTestHarness(t)
	harness.handler.sources = sourceServiceWithoutSchema{inner: harness.sources}
	response, _ := callSetQueryCredential(t, harness, testSourceSQLSourceID,
		`{"credential_reference":"`+testQueryCredentialReference+`"}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("no capability = %d %s, want 503", response.Code, response.Body.String())
	}
	response, _ = callClearQueryCredential(t, harness, testSourceSQLSourceID)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("no capability clear = %d %s, want 503", response.Code, response.Body.String())
	}
}

// The capability is discovered by type assertion, exactly like the other
// optional source capabilities.
var _ SourceQueryCredential = (*fakeSourceService)(nil)

func TestSourceQueryCredentialAccessContextIsTheCaller(t *testing.T) {
	harness := newTestHarness(t)
	_, _ = callSetQueryCredential(t, harness, testSourceSQLSourceID, `{"credential_reference":"`+testQueryCredentialReference+`"}`)
	if harness.sources.access != (database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: "req_server_001"}) {
		t.Fatalf("access = %#v", harness.sources.access)
	}
}
