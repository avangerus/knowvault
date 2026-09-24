package workspaceapi

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const registerBody = `{"name":"Engineering docs","root_alias":"docs-root","root_identity":"vol-1","relative_root":"projects/alpha","kind":"documents","recursive":true,"include_globs":["**/*"],"exclude_globs":[],"max_file_bytes":1048576,"ocr_mode":"OFF","formats":["PDF","DOCX"]}`

const testScopeID = "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ"

// testHash is a well-formed configuration/scope hash literal used to build
// closed authority-command bodies in the unit tests below.
const testHash = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeSourceService struct {
	call                       string
	access                     database.AccessContext
	err                        error
	registerRequest            registration.RegisterRequest
	registerResult             registration.RegisterResult
	bootstrapRequest           registration.PostgreSQLConnectionBootstrapRequest
	bootstrapResult            registration.PostgreSQLConnectionBootstrapResult
	discoveryRequest           registration.DiscoveryRequest
	discoveryResult            registration.DiscoveryResult
	discoveryReadID            string
	discoveryRead              sourcediscovery.ReadResult
	discoveryReadErr           error
	discoveryRegisterRequestID string
	discoveryRegisterViewID    string
	discoveryRegisterExcluded  []int
	discoveryRegisterResult    registration.RegisterResult
	discoveryRegisterErr       error
	activateRequest            registration.ActivateRequest
	activateResult             registration.ActivateResult
	syncRequest                registration.SyncRequest
	syncResult                 registration.SyncResult
	statuses                   []workspacerepository.SourceStatus

	// ConfirmationContext is tracked separately from `call`/`access` above
	// (rather than through the shared `save` helper) so existing assertions
	// that the ListSources dispatch recorded call=="list_sources" stay valid
	// even though listSources now also reads the confirmation context.
	confirmationContext       workspacerepository.ConfirmationContext
	confirmationContextErr    error
	confirmationContextCalls  int
	confirmationContextAccess database.AccessContext

	uploadRequest registration.UploadDocumentsRequest
	uploadResult  registration.UploadDocumentsResult

	// S3 card 1's optional SourceSchemaProvider capability: the stored source
	// schema read behind knowvault_source_schema.
	schemaSources       []workspacerepository.SourceSchemaSource
	schemaSourceListErr error
	schemaResult        workspacerepository.SourceSchema
	schemaErr           error
	schemaSourceID      string
	schemaTable         string
	schemaOffset        int
	schemaLimit         int
	schemaCalls         int

	// S3 card 2's optional SourceSQLProvider capability: the governed
	// agent-authored SQL execution behind knowvault_source_sql.
	sqlResult   SourceSQLResult
	sqlErr      error
	sqlSourceID string
	sqlSQL      string
	sqlPurpose  string
	sqlCalls    int
}

func (service *fakeSourceService) SourceSQL(_ context.Context, access database.AccessContext, _ string, request SourceSQLRequest) (SourceSQLResult, error) {
	service.call, service.access = "source_sql", access
	service.sqlSourceID, service.sqlSQL, service.sqlPurpose = request.SourceID, request.SQL, request.Purpose
	service.sqlCalls++
	if service.sqlErr != nil {
		return SourceSQLResult{}, service.sqlErr
	}
	return service.sqlResult, nil
}

func (service *fakeSourceService) ListSourceSchemas(_ context.Context, access database.AccessContext, _ string) ([]workspacerepository.SourceSchemaSource, error) {
	service.call, service.access = "list_source_schemas", access
	if service.schemaSourceListErr != nil {
		return nil, service.schemaSourceListErr
	}
	return service.schemaSources, nil
}

func (service *fakeSourceService) SourceSchema(_ context.Context, access database.AccessContext, _, sourceID, table string, offset, limit int) (workspacerepository.SourceSchema, error) {
	service.call, service.access = "source_schema", access
	service.schemaSourceID, service.schemaTable, service.schemaOffset, service.schemaLimit = sourceID, table, offset, limit
	service.schemaCalls++
	if service.schemaErr != nil {
		return workspacerepository.SourceSchema{}, service.schemaErr
	}
	// Emulate the repository's own page window so the transport's has_more /
	// next_offset contract is exercised against a provider that really pages.
	result := service.schemaResult
	if offset > len(result.Tables) {
		offset = len(result.Tables)
	}
	end := offset + limit
	if end > len(result.Tables) {
		end = len(result.Tables)
	}
	result.HasMore = end < len(result.Tables)
	result.Tables = result.Tables[offset:end]
	return result, nil
}

func (service *fakeSourceService) save(call string, access database.AccessContext) error {
	service.call, service.access = call, access
	return service.err
}

func (service *fakeSourceService) Register(_ context.Context, access database.AccessContext, request registration.RegisterRequest) (registration.RegisterResult, error) {
	service.registerRequest = request
	return service.registerResult, service.save("register", access)
}

func (service *fakeSourceService) BootstrapPostgreSQLConnection(_ context.Context, access database.AccessContext, request registration.PostgreSQLConnectionBootstrapRequest) (registration.PostgreSQLConnectionBootstrapResult, error) {
	service.bootstrapRequest = request
	return service.bootstrapResult, service.save("bootstrap_postgresql_connection", access)
}

func (service *fakeSourceService) RequestDiscovery(_ context.Context, access database.AccessContext, request registration.DiscoveryRequest) (registration.DiscoveryResult, error) {
	service.discoveryRequest = request
	return service.discoveryResult, service.save("request_discovery", access)
}

func (service *fakeSourceService) GetDiscovery(_ context.Context, access database.AccessContext, requestID string) (sourcediscovery.ReadResult, error) {
	service.discoveryReadID = requestID
	if service.discoveryReadErr != nil {
		return sourcediscovery.ReadResult{}, service.discoveryReadErr
	}
	return service.discoveryRead, service.save("get_discovery", access)
}

func (service *fakeSourceService) RegisterDiscoveredView(_ context.Context, access database.AccessContext, requestID, viewID string, excludedColumns []int) (registration.RegisterResult, error) {
	service.discoveryRegisterRequestID = requestID
	service.discoveryRegisterViewID = viewID
	service.discoveryRegisterExcluded = excludedColumns
	if service.discoveryRegisterErr != nil {
		return registration.RegisterResult{}, service.discoveryRegisterErr
	}
	return service.discoveryRegisterResult, service.save("register_discovered_view", access)
}

func (service *fakeSourceService) Activate(_ context.Context, access database.AccessContext, request registration.ActivateRequest) (registration.ActivateResult, error) {
	service.activateRequest = request
	return service.activateResult, service.save("activate", access)
}

func (service *fakeSourceService) Sync(_ context.Context, access database.AccessContext, request registration.SyncRequest) (registration.SyncResult, error) {
	service.syncRequest = request
	return service.syncResult, service.save("sync", access)
}

func (service *fakeSourceService) ListSources(_ context.Context, access database.AccessContext, _ string) ([]workspacerepository.SourceStatus, error) {
	err := service.save("list_sources", access)
	return service.statuses, err
}

func (service *fakeSourceService) ConfirmationContext(_ context.Context, access database.AccessContext, _ string) (workspacerepository.ConfirmationContext, error) {
	service.confirmationContextAccess = access
	service.confirmationContextCalls++
	return service.confirmationContext, service.confirmationContextErr
}

func (service *fakeSourceService) UploadDocuments(_ context.Context, access database.AccessContext, request registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	service.uploadRequest = request
	return service.uploadResult, service.save("upload_documents", access)
}

func TestSourceRegisterDispatchesWithoutIdempotencyKey(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, sourcesPath, registerBody)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "register" || harness.auth.csrfCalls != 1 {
		t.Fatalf("status=%d call=%q csrf=%d body=%s", response.Code, harness.sources.call, harness.auth.csrfCalls, response.Body.String())
	}
	got := harness.sources.registerRequest
	if got.Name != "Engineering docs" || got.RootAlias != "docs-root" || got.RootIdentity != "vol-1" ||
		got.RelativeRoot != "projects/alpha" || !got.Recursive || len(got.IncludeGlobs) != 1 ||
		got.MaxFileBytes != 1048576 || got.OCRMode != "OFF" || len(got.Formats) != 2 {
		t.Fatalf("register request not projected: %#v", got)
	}
}

func TestPostgreSQLConnectionBootstrapAcceptsNoScopeOrColumnContract(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.bootstrapResult = registration.PostgreSQLConnectionBootstrapResult{
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", ConnectionRevision: 1,
		CredentialReference: "cred_01H9ABCDEFGHJKMNPQRSTVWXYZ", Created: true,
	}
	request := harness.request(http.MethodPost, sourcesPath+"/connections",
		`{"name":"Operations DB","database_identity":"ops-db","lineage_id":"primary","credential_reference":"cred_01H9ABCDEFGHJKMNPQRSTVWXYZ"}`)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "bootstrap_postgresql_connection" || harness.auth.csrfCalls != 1 {
		t.Fatalf("status=%d call=%q csrf=%d body=%s", response.Code, harness.sources.call, harness.auth.csrfCalls, response.Body.String())
	}
	got := harness.sources.bootstrapRequest
	if got.Name != "Operations DB" || got.DatabaseIdentity != "ops-db" || got.LineageID != "primary" ||
		got.CredentialReference != "cred_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("bootstrap request = %#v", got)
	}
	if strings.Contains(response.Body.String(), "trust_profile_hash") || strings.Contains(response.Body.String(), "scope") ||
		strings.Contains(response.Body.String(), "columns") {
		t.Fatalf("bootstrap response disclosed registration-only fields: %s", response.Body.String())
	}
}

func TestPostgreSQLConnectionBootstrapRejectsSelectionAndMutationHeaders(t *testing.T) {
	for name, configure := range map[string]func(*http.Request){
		"scope field":        func(request *http.Request) {},
		"idempotency header": func(request *http.Request) { request.Header.Set("Idempotency-Key", "bootstrap") },
		"etag header":        func(request *http.Request) { request.Header.Set("If-Match", `"1"`) },
	} {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			body := `{"name":"Operations DB","database_identity":"ops-db","lineage_id":"primary"}`
			if name == "scope field" {
				body = `{"name":"Operations DB","database_identity":"ops-db","lineage_id":"primary","schema_name":"public"}`
			}
			request := harness.request(http.MethodPost, sourcesPath+"/connections", body)
			configure(request)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || harness.sources.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
			}
		})
	}
}

func TestSourceDiscoveryRequestAcceptsOnlyConnectionAndIdempotencyKey(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.discoveryResult = registration.DiscoveryResult{
		RequestID: "sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ", JobID: "sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ", Created: true,
	}
	request := harness.request(http.MethodPost,
		sourcesPath+"/connections/conn_01H9ABCDEFGHJKMNPQRSTVWXYZ:discover", "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || harness.sources.call != "request_discovery" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	got := harness.sources.discoveryRequest
	if got.ConnectionID != "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ" || got.IdempotencyKey != harness.idempotencyKey ||
		got.Limits != (postgresqlquery.DiscoveryLimits{}) {
		t.Fatalf("discovery request = %#v", got)
	}
	if strings.Contains(response.Body.String(), "connection_revision") || strings.Contains(response.Body.String(), "trust") {
		t.Fatalf("discovery enqueue disclosed server-owned coordinates: %s", response.Body.String())
	}
}

func TestSourceDiscoveryRequestRejectsCallerMetadata(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost,
		sourcesPath+"/connections/conn_01H9ABCDEFGHJKMNPQRSTVWXYZ:discover", `{"schema_name":"reporting"}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || harness.sources.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
}

func TestSourceDiscoveryGetReturnsBrowserSafeInventory(t *testing.T) {
	harness := newTestHarness(t)
	expiresAt := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	harness.sources.discoveryRead = sourcediscovery.ReadResult{
		RequestID: "sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ", RequestStatus: "SUCCEEDED",
		ResultID: "sdr_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultStatus: "SUCCEEDED",
		ViewCount: 1, PreparedViewCount: 1, ExpiresAt: expiresAt,
		Views: []sourcediscovery.View{{
			Selector:   "sdv_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SchemaName: "reporting", RelationName: "waste_daily", RelationKind: "VIEW",
			Status: postgresqlquery.DiscoveryPrepared,
			Columns: []sourcediscovery.Column{{Ordinal: 1, Name: "period_date", TypeName: "date",
				LogicalType: postgresqlquery.TypeDate, Roles: []postgresqlquery.Role{postgresqlquery.RolePeriod}}},
		}},
	}
	request := harness.request(http.MethodGet,
		sourcesPath+"/discovery/sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "get_discovery" ||
		harness.sources.discoveryReadID != "sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("status=%d call=%q id=%q body=%s", response.Code, harness.sources.call,
			harness.sources.discoveryReadID, response.Body.String())
	}
	body := response.Body.String()
	for _, forbidden := range []string{"relation_oid", "trust_profile_hash", "credential_reference", "database_identity"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("discovery response disclosed %q: %s", forbidden, body)
		}
	}
	for _, required := range []string{`"view_id":"sdv_`, `"period_date"`, `"roles":["PERIOD"]`} {
		if !strings.Contains(body, required) {
			t.Fatalf("discovery response missing %q: %s", required, body)
		}
	}
}

func TestSourceDiscoveryRegisterAcceptsOnlyServerIssuedCoordinates(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.discoveryRegisterResult = registration.RegisterResult{
		ConnectionID:      "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		SourceScopeID:     "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		DiscoveredScopeID: "discovered_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		Revision:          1, ScopeConfigHash: testHash, AccessMode: "WORKSPACE_MANAGED", Created: true,
	}
	viewID := "sdv_" + strings.Repeat("a", 64)
	request := harness.request(http.MethodPost,
		sourcesPath+"/discovery/sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ/views/"+viewID+":register", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "register_discovered_view" ||
		harness.sources.discoveryRegisterRequestID != "sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ" ||
		harness.sources.discoveryRegisterViewID != viewID {
		t.Fatalf("status=%d call=%q request=%q view=%q body=%s", response.Code,
			harness.sources.call, harness.sources.discoveryRegisterRequestID,
			harness.sources.discoveryRegisterViewID, response.Body.String())
	}
	for _, forbidden := range []string{"columns", "schema_name", "relation_name", "trust_profile_hash"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("selected registration disclosed %q: %s", forbidden, response.Body.String())
		}
	}
}

// TestSourceDiscoveryRegisterAcceptsExcludedColumns proves the one caller-
// supplied field this route now accepts (ADR-0097): a well-formed
// excluded_columns list is decoded and handed to the registration service
// unchanged, while every other projection field stays exclusively
// server-derived (TestSourceDiscoveryRegisterAcceptsOnlyServerIssuedCoordinates
// above still proves that half).
func TestSourceDiscoveryRegisterAcceptsExcludedColumns(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.discoveryRegisterResult = registration.RegisterResult{
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", SourceScopeID: "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		DiscoveredScopeID: "discovered_01H9ABCDEFGHJKMNPQRSTVWXYZ", Revision: 1,
		ScopeConfigHash: testHash, AccessMode: "WORKSPACE_MANAGED", Created: true,
	}
	viewID := "sdv_" + strings.Repeat("a", 64)
	request := harness.request(http.MethodPost,
		sourcesPath+"/discovery/sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ/views/"+viewID+":register", `{"excluded_columns":[3,4]}`)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "register_discovered_view" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	if len(harness.sources.discoveryRegisterExcluded) != 2 ||
		harness.sources.discoveryRegisterExcluded[0] != 3 || harness.sources.discoveryRegisterExcluded[1] != 4 {
		t.Fatalf("excluded_columns not projected: %#v", harness.sources.discoveryRegisterExcluded)
	}
}

// TestSourceDiscoveryRegisterRejectsMalformedBodyAndMutationHeaders proves the
// two things this route still refuses even though a well-formed
// excluded_columns body is now accepted (see the excluded-columns test
// above): a body that is not valid JSON (never browser-authored projection
// fields -- there is no such field to smuggle), and the mutation headers this
// idempotent-by-content route has never accepted.
func TestSourceDiscoveryRegisterRejectsMalformedBodyAndMutationHeaders(t *testing.T) {
	viewID := "sdv_" + strings.Repeat("a", 64)
	for name, body := range map[string]string{"malformed_body": `{\"columns\":[]}`, "empty": ""} {
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost,
				sourcesPath+"/discovery/sdrq_01H9ABCDEFGHJKMNPQRSTVWXYZ/views/"+viewID+":register", body)
			if name == "empty" {
				request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || harness.sources.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
			}
		})
	}
}

func TestPostgreSQLQuerySourceRegisterProjectsExactContract(t *testing.T) {
	harness := newTestHarness(t)
	body := `{"source_type":"POSTGRESQL_QUERY","name":"Operations DB","kind":"business-objects","database_identity":"ops-db","lineage_id":"waste-daily","projection_revision":1,"contract_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_name":"reporting","relation_name":"waste_daily","relation_kind":"VIEW","columns":[{"ordinal":1,"name":"route_id","type_fingerprint":"oid:2950","logical_type":"UUID","roles":["IDENTITY"],"nullable":false,"max_bytes":64},{"ordinal":2,"name":"due_at","type_fingerprint":"oid:1184","logical_type":"TIMESTAMPTZ","roles":["PERIOD"],"nullable":false,"max_bytes":64},{"ordinal":3,"name":"state","type_fingerprint":"oid:25","logical_type":"TEXT","roles":["STATUS","EVIDENCE"],"nullable":false,"max_bytes":64},{"ordinal":4,"name":"tonnes","type_fingerprint":"oid:1700:p:12:s:3","logical_type":"NUMERIC","roles":["EVIDENCE"],"nullable":false,"precision":12,"scale":3,"max_bytes":64}],"empty_snapshot_policy":"HELD"}`
	request := harness.request(http.MethodPost, sourcesPath, body)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "register" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	got := harness.sources.registerRequest
	if got.SourceType != "POSTGRESQL_QUERY" || got.DatabaseIdentity != "ops-db" || got.LineageID != "waste-daily" ||
		got.RelationKind != "VIEW" || len(got.Columns) != 4 || got.Columns[1].LogicalType != postgresqlquery.TypeTimestamptz ||
		len(got.Columns[1].Roles) != 1 || got.Columns[1].Roles[0] != postgresqlquery.RolePeriod ||
		len(got.Columns[2].Roles) != 2 || got.Columns[2].Roles[0] != postgresqlquery.RoleStatus {
		t.Fatalf("postgresql request not projected: %#v", got)
	}
}

func TestGitSourceRegisterProjectsRemoteContract(t *testing.T) {
	harness := newTestHarness(t)
	body := `{"source_type":"GIT","name":"Engineering code","kind":"code","provider":"GITHUB","endpoint":"https://api.github.com","web_base_url":"https://github.com","repository_id":"acme/knowledge","branch_name":"main","include_globs":["src/**"],"exclude_globs":["vendor/**"],"text_media_types":["text/plain","application/json"],"max_blob_bytes":1048576}`
	request := harness.request(http.MethodPost, sourcesPath, body)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "register" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	got := harness.sources.registerRequest
	if got.SourceType != "GIT" || got.Provider != "GITHUB" || got.Endpoint != "https://api.github.com" ||
		got.RepositoryID != "acme/knowledge" || got.BranchName != "main" || len(got.IncludeGlobs) != 1 ||
		len(got.TextMediaTypes) != 2 || got.MaxBlobBytes != 1048576 {
		t.Fatalf("Git request not projected: %#v", got)
	}
}

func TestMailSourceRegisterProjectsRemoteContract(t *testing.T) {
	harness := newTestHarness(t)
	body := `{"source_type":"MAIL","provider":"IMAP","name":"Operations mail","kind":"mail","endpoint":"imap.example.test:993","mailbox":"tenant-a","folder":"INBOX","username":"reader@example.test","since":"2026-01-01T00:00:00Z","include_attachments":true,"max_message_bytes":8388608,"max_attachment_bytes":4194304,"attachment_media_types":["text/plain","application/pdf"]}`
	request := harness.request(http.MethodPost, sourcesPath, body)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.sources.call != "register" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	got := harness.sources.registerRequest
	if got.SourceType != "MAIL" || got.Provider != "IMAP" || got.Endpoint != "imap.example.test:993" || got.Mailbox != "tenant-a" ||
		got.Folder != "INBOX" || got.Username != "reader@example.test" || got.Since == nil || !got.IncludeAttachments || len(got.AttachmentMediaTypes) != 2 {
		t.Fatalf("Mail request not projected: %#v", got)
	}
}

func TestRemoteSourceRegisterRejectsIncompleteOrUnknownContract(t *testing.T) {
	for name, body := range map[string]string{
		"unknown source type": `{"source_type":"SITE","name":"site","kind":"site"}`,
		"Git missing branch":  `{"source_type":"GIT","name":"code","kind":"code","provider":"GITHUB","endpoint":"https://api.github.com","repository_id":"acme/repo","include_globs":[],"exclude_globs":[],"text_media_types":["text/plain"],"max_blob_bytes":1024}`,
		"mail bad since":      `{"source_type":"MAIL","name":"mail","kind":"mail","endpoint":"imap.example.test:993","mailbox":"tenant","folder":"INBOX","username":"reader","include_attachments":false,"since":"not-a-time"}`,
	} {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost, sourcesPath, body)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || harness.sources.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
			}
		})
	}
}

func TestWorkspaceSourceRemoveDispatchesExactTuple(t *testing.T) {
	harness := newTestHarness(t)
	body := `{"expected_workspace_revision":3,"workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ","source_scope_id":"` + testScopeID + `","source_scope_revision":1,"scope_config_hash":"` + harness.hash + `","access_mode":"WORKSPACE_MANAGED"}`
	request := harness.request(http.MethodDelete, workspacesPath+"/ws_alpha/sources/"+testScopeID, body)
	harness.mutationHeaders(request, harness.hash)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.service.call != "remove_source" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
	if harness.service.removeSourceRequest.SourceScopeID != testScopeID || harness.service.removeSourceRequest.WorkspaceSourceID == "" {
		t.Fatalf("remove request not projected: %#v", harness.service.removeSourceRequest)
	}
}

func TestWorkspaceSourceAddDispatchesExactTupleForReenable(t *testing.T) {
	harness := newTestHarness(t)
	body := `{"expected_workspace_revision":4,"source_scope_id":"` + testScopeID + `","source_scope_revision":1,"scope_config_hash":"` + harness.hash + `","access_mode":"WORKSPACE_MANAGED"}`
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/sources", body)
	harness.mutationHeaders(request, harness.hash)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.service.call != "add_source" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
	got := harness.service.addSourceRequest
	if got.WorkspaceID != "ws_alpha" || got.ExpectedWorkspaceRevision != 4 ||
		got.SourceScopeID != testScopeID || got.SourceScopeRevision != 1 ||
		got.ScopeConfigHash != harness.hash || got.AccessMode != workspacerepository.SourceAccessMode("WORKSPACE_MANAGED") ||
		got.IdempotencyKey != harness.idempotencyKey {
		t.Fatalf("add request not projected for re-enable: %#v", got)
	}
}

func TestSourceRegisterRejectsMutationHeaders(t *testing.T) {
	for name, configure := range map[string]func(*http.Request, *testHarness){
		"idempotency key": func(request *http.Request, harness *testHarness) {
			request.Header.Set("Idempotency-Key", harness.idempotencyKey)
		},
		"if match": func(request *http.Request, harness *testHarness) {
			request.Header.Set("If-Match", `"`+harness.hash+`"`)
		},
	} {
		name, configure := name, configure
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost, sourcesPath, registerBody)
			configure(request, harness)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || harness.sources.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
			}
		})
	}
}

func TestSourceRegisterStrictBodyFailClosed(t *testing.T) {
	for name, fixture := range map[string]struct {
		body       string
		wantStatus int
	}{
		"unknown member": {`{"name":"Engineering docs","root_alias":"docs-root","root_identity":"vol-1","relative_root":"projects/alpha","kind":"documents","recursive":true,"include_globs":["**/*"],"exclude_globs":[],"max_file_bytes":1048576,"ocr_mode":"OFF","formats":["PDF"],"extra":1}`, http.StatusBadRequest},
		"missing member": {`{"name":"Engineering docs"}`, http.StatusBadRequest},
		"null formats":   {`{"name":"Engineering docs","root_alias":"docs-root","root_identity":"vol-1","relative_root":"projects/alpha","kind":"documents","recursive":true,"include_globs":["**/*"],"exclude_globs":[],"max_file_bytes":1048576,"ocr_mode":"OFF","formats":null}`, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness := newTestHarness(t)
			request := harness.request(http.MethodPost, sourcesPath, fixture.body)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || harness.sources.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
			}
		})
	}
}

func TestSourceActivateRequiresIdempotencyKeyAndDispatches(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.activateResult = registration.ActivateResult{JobID: "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ"}
	request := harness.request(http.MethodPost, sourcesPath+"/"+testScopeID+":activate", "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "activate" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	if harness.sources.activateRequest.SourceScopeID != testScopeID || harness.sources.activateRequest.IdempotencyKey != harness.idempotencyKey {
		t.Fatalf("activate request not projected: %#v", harness.sources.activateRequest)
	}
	if !strings.Contains(response.Body.String(), "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ") {
		t.Fatalf("job id missing in response: %s", response.Body.String())
	}
}

func TestSourceActivateMissingKeyStopsBeforeService(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, sourcesPath+"/"+testScopeID+":activate", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || harness.sources.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
}

func TestSourceSyncRequiresIdempotencyKeyAndDispatches(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.syncResult = registration.SyncResult{JobID: "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ"}
	request := harness.request(http.MethodPost, sourcesPath+"/"+testScopeID+":sync", "")
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "sync" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	if harness.sources.syncRequest.SourceScopeID != testScopeID || harness.sources.syncRequest.IdempotencyKey != harness.idempotencyKey {
		t.Fatalf("sync request not projected: %#v", harness.sources.syncRequest)
	}
	if !strings.Contains(response.Body.String(), "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ") {
		t.Fatalf("job id missing in response: %s", response.Body.String())
	}
}

func TestSourceSyncMissingKeyStopsBeforeService(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.request(http.MethodPost, sourcesPath+"/"+testScopeID+":sync", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || harness.sources.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
}

func TestSourceActivateUnknownPathShapeIsNotFound(t *testing.T) {
	for _, path := range []string{
		sourcesPath + "/" + testScopeID,
		sourcesPath + "/" + testScopeID + ":activate/",
		sourcesPath + "/" + testScopeID + ":sync/",
		sourcesPath + "/" + testScopeID + ":archive",
		sourcesPath + "/" + testScopeID + "/x:activate",
		sourcesPath + "/" + testScopeID + "/x:sync",
	} {
		harness := newTestHarness(t)
		request := harness.request(http.MethodPost, path, "")
		response := httptest.NewRecorder()
		harness.handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || harness.sources.call != "" {
			t.Fatalf("path=%s status=%d call=%q body=%s", path, response.Code, harness.sources.call, response.Body.String())
		}
	}
}

func TestListSourcesDispatchesForWorkspace(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{{SourceScopeID: testScopeID, ActivationStatus: "SYNCING", Enabled: true}}
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "list_sources" || harness.sources.confirmationContextCalls != 1 {
		t.Fatalf("status=%d call=%q confirmationContextCalls=%d body=%s", response.Code, harness.sources.call, harness.sources.confirmationContextCalls, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), testScopeID) || !strings.Contains(response.Body.String(), "SYNCING") {
		t.Fatalf("source status missing in response: %s", response.Body.String())
	}
}

// TestListSourcesConfirmationStateReflectsPendingFacts is ADR-0087 §1's
// operator-visible read (contract A): for each managed source the response
// must expose the exact pending step (grant, confirmation, trust
// verification, or ready-to-activate) derived from facts the repository
// already returns, without any database access of its own. It also proves the
// response carries no secret, credential or connector content — only opaque
// identifiers and hashes.
func TestListSourcesConfirmationStateReflectsPendingFacts(t *testing.T) {
	cases := []struct {
		name          string
		enabled       bool
		confirmed     bool
		trustVerified bool
		activation    string
		selfGrant     bool
		want          string
	}{
		{name: "disabled binding, live confirmation, ready to re-enable", enabled: false, confirmed: true, trustVerified: true, activation: "READY", want: "DISABLED"},
		{name: "disabled binding, no live confirmation, no grant", enabled: false, confirmed: false, trustVerified: false, activation: "DRAFT", selfGrant: false, want: "NEEDS_GRANT"},
		{name: "disabled binding, no live confirmation, grant held", enabled: false, confirmed: false, trustVerified: false, activation: "DRAFT", selfGrant: true, want: "NEEDS_CONFIRMATION"},
		{name: "no grant yet", enabled: true, confirmed: false, trustVerified: false, activation: "DRAFT", selfGrant: false, want: "NEEDS_GRANT"},
		{name: "grant held, not yet confirmed", enabled: true, confirmed: false, trustVerified: false, activation: "DRAFT", selfGrant: true, want: "NEEDS_CONFIRMATION"},
		{name: "ready but not confirmed, no grant", enabled: true, confirmed: false, trustVerified: true, activation: "READY", selfGrant: false, want: "NEEDS_GRANT"},
		{name: "ready but not confirmed, grant held", enabled: true, confirmed: false, trustVerified: true, activation: "READY", selfGrant: true, want: "NEEDS_CONFIRMATION"},
		{name: "confirmed, trust pending", enabled: true, confirmed: true, trustVerified: false, activation: "DRAFT", want: "NEEDS_TRUST_VERIFICATION"},
		{name: "confirmed and trusted, not yet activated", enabled: true, confirmed: true, trustVerified: true, activation: "DRAFT", want: "READY_TO_ACTIVATE"},
		{name: "fully active", enabled: true, confirmed: true, trustVerified: true, activation: "READY", want: "ACTIVE"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newTestHarness(t)
			harness.sources.statuses = []workspacerepository.SourceStatus{{
				SourceScopeID: testScopeID, Enabled: testCase.enabled, Confirmed: testCase.confirmed,
				TrustVerified: testCase.trustVerified, ActivationStatus: testCase.activation,
			}}
			harness.sources.confirmationContext = workspacerepository.ConfirmationContext{
				ExpectedPolicyRevision: "policy-acc-0001",
				WarningVersion:         "workspace-managed-risk-v1", WarningContractHash: testHash,
				ViewerPrincipalID: "principal_alpha",
			}
			if testCase.selfGrant {
				harness.sources.confirmationContext.SelfGrant = &workspacerepository.SelfConfirmationGrant{
					GrantID: "grant_01", GrantRevision: 1, GrantHash: testHash, ValidUntil: "2026-09-06T15:00:00Z",
				}
			}
			request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
			response := httptest.NewRecorder()

			harness.handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var decoded struct {
				Sources []struct {
					ConfirmationState string `json:"confirmation_state"`
					Confirmed         bool   `json:"confirmed"`
				} `json:"sources"`
				ConfirmationContext struct {
					ExpectedPolicyRevision string `json:"expected_policy_revision"`
					ViewerPrincipalID      string `json:"viewer_principal_id"`
					SelfGrant              *struct {
						GrantID string `json:"grant_id"`
					} `json:"self_grant"`
				} `json:"confirmation_context"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
				t.Fatalf("decode: %v body=%s", err, response.Body.String())
			}
			if len(decoded.Sources) != 1 || decoded.Sources[0].ConfirmationState != testCase.want || decoded.Sources[0].Confirmed != testCase.confirmed {
				t.Fatalf("confirmation_state=%q confirmed=%v want=%q body=%s", decoded.Sources[0].ConfirmationState, decoded.Sources[0].Confirmed, testCase.want, response.Body.String())
			}
			if decoded.ConfirmationContext.ExpectedPolicyRevision != "policy-acc-0001" || decoded.ConfirmationContext.ViewerPrincipalID != "principal_alpha" {
				t.Fatalf("confirmation_context not projected: body=%s", response.Body.String())
			}
			if testCase.selfGrant && (decoded.ConfirmationContext.SelfGrant == nil || decoded.ConfirmationContext.SelfGrant.GrantID != "grant_01") {
				t.Fatalf("self_grant not projected: body=%s", response.Body.String())
			}
			if !testCase.selfGrant && decoded.ConfirmationContext.SelfGrant != nil {
				t.Fatalf("self_grant leaked when caller holds none: body=%s", response.Body.String())
			}
			for _, secret := range []string{"credential", "password", "secret", "database_url"} {
				if strings.Contains(strings.ToLower(response.Body.String()), secret) {
					t.Fatalf("response leaks a %q token: %s", secret, response.Body.String())
				}
			}
		})
	}
}

// TestListSourcesConfirmationContextViewerEligibility proves the read
// surfaces the caller's own organization-role eligibility (contract B: "who
// may act, and an explanation when they may not"), computed from the roles
// already loaded for the workspace-metadata policy decision — no separate
// database round trip.
func TestListSourcesConfirmationContextViewerEligibility(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{{SourceScopeID: testScopeID, Enabled: true}}
	harness.sources.confirmationContext = workspacerepository.ConfirmationContext{
		ExpectedPolicyRevision: "policy-acc-0001", CanIssueConfirmationGrant: true, CanVerifyConnectionTrust: false,
	}
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, `"can_issue_confirmation_grant":true`) || !strings.Contains(body, `"can_verify_connection_trust":false`) {
		t.Fatalf("viewer eligibility not projected: %s", body)
	}
}

// TestListSourcesPerSourceCanVerifyConnectionTrustAccountsForSoD proves
// review-opus-s2-6-7.md's remark: confirmation_context.can_verify_connection_
// trust is role-only (CONNECTOR_ADMIN), but the per-source field the UI must
// actually gate the "Verify trust" button on additionally accounts for
// the ADR-0087 §2 verifier/confirmer separation of duty
// (workspacerepository.SourceStatus.ViewerVerifyConflict). A viewer who holds
// the role but has already confirmed a scope of this source's own connection
// sees the workspace-wide context field true and this source's own field
// false — never the reverse, and never both true when the underlying source
// has a conflict.
func TestListSourcesPerSourceCanVerifyConnectionTrustAccountsForSoD(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{
		{SourceScopeID: testScopeID, Enabled: true, ViewerVerifyConflict: true},
	}
	harness.sources.confirmationContext = workspacerepository.ConfirmationContext{
		ExpectedPolicyRevision: "policy-acc-0001", CanVerifyConnectionTrust: true,
	}
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded struct {
		Sources []struct {
			CanVerifyConnectionTrust bool `json:"can_verify_connection_trust"`
		} `json:"sources"`
		ConfirmationContext struct {
			CanVerifyConnectionTrust bool `json:"can_verify_connection_trust"`
		} `json:"confirmation_context"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode: %v body=%s", err, response.Body.String())
	}
	if !decoded.ConfirmationContext.CanVerifyConnectionTrust {
		t.Fatalf("workspace-wide role-only field should stay true: body=%s", response.Body.String())
	}
	if len(decoded.Sources) != 1 || decoded.Sources[0].CanVerifyConnectionTrust {
		t.Fatalf("per-source field should be false when the viewer already confirmed this connection's scope: body=%s", response.Body.String())
	}
}

// TestListSourcesConfirmationContextErrorFailsClosed proves a
// ConfirmationContext failure fails the whole read rather than silently
// returning sources without their pending state — the two reads share the
// exact same visibility gate, so they must not disagree in what a caller sees.
func TestListSourcesConfirmationContextErrorFailsClosed(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{{SourceScopeID: testScopeID, Enabled: true}}
	harness.sources.confirmationContextErr = workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code == http.StatusOK {
		t.Fatalf("expected a non-OK status when ConfirmationContext fails, got 200: %s", response.Body.String())
	}
}

// fakeAuthorityWorkspaceService embeds the existing fake WorkspaceService and
// additionally implements the ADR-0053 WorkspaceAuthority runtime, mirroring the
// production composition where the same workspace repository Store satisfies
// both interfaces (ADR-0087 §1).
type fakeAuthorityWorkspaceService struct {
	*fakeWorkspaceService
	err                       error
	call                      string
	access                    database.AccessContext
	issueRequest              workspacerepository.IssueGrantRequest
	confirmRequest            workspacerepository.ConfirmRequest
	revokeGrantRequest        workspacerepository.RevokeGrantRequest
	revokeConfirmationRequest workspacerepository.RevokeConfirmationRequest
	authorityResult           workspacerepository.AuthorityResult
}

func (service *fakeAuthorityWorkspaceService) IssueConfirmationGrant(_ context.Context, access database.AccessContext, request workspacerepository.IssueGrantRequest) (workspacerepository.AuthorityResult, error) {
	service.call, service.access, service.issueRequest = "issue_grant", access, request
	return service.authorityResult, service.err
}

func (service *fakeAuthorityWorkspaceService) ConfirmManagedSource(_ context.Context, access database.AccessContext, request workspacerepository.ConfirmRequest) (workspacerepository.AuthorityResult, error) {
	service.call, service.access, service.confirmRequest = "confirm", access, request
	return service.authorityResult, service.err
}

func (service *fakeAuthorityWorkspaceService) RevokeConfirmationGrant(_ context.Context, access database.AccessContext, request workspacerepository.RevokeGrantRequest) (workspacerepository.AuthorityResult, error) {
	service.call, service.access, service.revokeGrantRequest = "revoke_grant", access, request
	return service.authorityResult, service.err
}

func (service *fakeAuthorityWorkspaceService) RevokeManagedConfirmation(_ context.Context, access database.AccessContext, request workspacerepository.RevokeConfirmationRequest) (workspacerepository.AuthorityResult, error) {
	service.call, service.access, service.revokeConfirmationRequest = "revoke_confirmation", access, request
	return service.authorityResult, service.err
}

func newAuthorityHarness(t *testing.T) (*testHarness, *fakeAuthorityWorkspaceService, *Handler) {
	t.Helper()
	harness := newTestHarness(t)
	authority := &fakeAuthorityWorkspaceService{fakeWorkspaceService: harness.service}
	handler, err := newHandlerWithQuestionsAndConversations(harness.auth, authority, harness.sources, harness.evidence, harness.questions, harness.conversations, fixedRequestIDSource("req_server_001"))
	if err != nil {
		t.Fatal(err)
	}
	return harness, authority, handler
}

func TestManagedSourceConfirmDispatchesClosedCommandToAuthorityRuntime(t *testing.T) {
	harness, authority, handler := newAuthorityHarness(t)
	authority.authorityResult = workspacerepository.AuthorityResult{
		CommandID: "cmd_01H9ABCDEFGHJKMNPQRSTVWXYZ", Operation: "WORKSPACE_MANAGED_CONFIRM",
		ResultID: "wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultHash: harness.hash,
	}
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/managed-source-confirmations", `{"workspace_revision":3,"workspace_configuration_hash":"`+harness.hash+`","workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ","source_scope_id":"`+testScopeID+`","source_scope_revision":2,"scope_config_hash":"`+harness.hash+`","confirmation_actor_grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_actor_grant_revision":1,"confirmation_actor_grant_hash":"`+harness.hash+`","warning_contract_hash":"`+harness.hash+`","expected_policy_revision":"pol_alpha"}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || authority.call != "confirm" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
	got := authority.confirmRequest
	if got.WorkspaceID != "ws_alpha" || got.OrganizationID != "org_alpha" || got.IdempotencyKey != harness.idempotencyKey {
		t.Fatalf("server-derived workspace/org/idempotency not projected: %#v", got)
	}
	if got.WorkspaceSourceID != "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ" || got.SourceScopeID != testScopeID || got.SourceScopeRevision != 2 ||
		got.ConfirmationActorGrantID != "grant_01H9ABCDEFGHJKMNPQRSTVWXYZ" || got.ConfirmationActorGrantRevision != 1 ||
		got.ExpectedPolicyRevision != "pol_alpha" {
		t.Fatalf("confirm command not projected: %#v", got)
	}
	// The closed access-mode / warning / acknowledgement literals are server
	// constants, never operator-supplied free-form values.
	if got.AccessMode != "WORKSPACE_MANAGED" || got.WarningVersion != "workspace-managed-risk-v1" ||
		got.AcknowledgementCode != "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL" {
		t.Fatalf("closed confirmation literals not server-derived: %#v", got)
	}
	if !strings.Contains(response.Body.String(), `"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ"`) ||
		!strings.Contains(response.Body.String(), `"cmd_01H9ABCDEFGHJKMNPQRSTVWXYZ"`) {
		t.Fatalf("authority result missing from response: %s", response.Body.String())
	}
}

func TestConfirmationRoutesDenyThroughClosedErrorSurface(t *testing.T) {
	confirmPath := workspacesPath + "/ws_alpha/managed-source-confirmations"
	confirmBody := `{"workspace_revision":3,"workspace_configuration_hash":"` + testHash + `","workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ","source_scope_id":"` + testScopeID + `","source_scope_revision":2,"scope_config_hash":"` + testHash + `","confirmation_actor_grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_actor_grant_revision":1,"confirmation_actor_grant_hash":"` + testHash + `","warning_contract_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`

	// A principal without the ADR-0053-required role, or who is also the grant
	// issuer for that scope, is denied by the repository as CodeAuthorityDenied.
	// Absence arrives as CodeAuthorityNotFound. Both must surface as one
	// identical 404 so no caller can distinguish "wrong role" from "no such
	// confirmation/binding" (no existence or role oracle).
	var deniedBody, notFoundBody string
	for _, code := range []workspacerepository.ErrorCode{workspacerepository.CodeAuthorityDenied, workspacerepository.CodeAuthorityNotFound} {
		harness, authority, handler := newAuthorityHarness(t)
		authority.err = workspacerepository.NewError(code, nil)
		request := harness.request(http.MethodPost, confirmPath, confirmBody)
		request.Header.Set("Idempotency-Key", harness.idempotencyKey)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound || authority.call != "confirm" {
			t.Fatalf("code=%s status=%d call=%q body=%s", code, response.Code, authority.call, response.Body.String())
		}
		if !strings.Contains(response.Body.String(), `"NOT_FOUND"`) || strings.Contains(response.Body.String(), "grant_") ||
			strings.Contains(response.Body.String(), "ws_alpha") {
			t.Fatalf("code=%s leaked detail in body: %s", code, response.Body.String())
		}
		if code == workspacerepository.CodeAuthorityDenied {
			deniedBody = response.Body.String()
		} else {
			notFoundBody = response.Body.String()
		}
	}
	if deniedBody != notFoundBody {
		t.Fatalf("denied and absent are distinguishable: denied=%q absent=%q", deniedBody, notFoundBody)
	}
}

func TestConfirmationRoutesFailClosedWhenAuthorityNotComposed(t *testing.T) {
	harness := newTestHarness(t) // plain fakeWorkspaceService has no authority runtime
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/managed-source-confirmations", `{}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || harness.service.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
}

func TestManagedSourceConfirmRequiresIdempotencyAndStrictBody(t *testing.T) {
	confirmPath := workspacesPath + "/ws_alpha/managed-source-confirmations"
	confirmBody := `{"workspace_revision":3,"workspace_configuration_hash":"` + testHash + `","workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ","source_scope_id":"` + testScopeID + `","source_scope_revision":2,"scope_config_hash":"` + testHash + `","confirmation_actor_grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_actor_grant_revision":1,"confirmation_actor_grant_hash":"` + testHash + `","warning_contract_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`
	for name, fixture := range map[string]struct {
		body       string
		withKey    bool
		wantStatus int
	}{
		"missing idempotency key": {confirmBody, false, http.StatusBadRequest},
		"unknown body member":     {`{"workspace_revision":3,"extra":1}`, true, http.StatusBadRequest},
		"missing required member": {`{"workspace_revision":3}`, true, http.StatusBadRequest},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newAuthorityHarness(t)
			request := harness.request(http.MethodPost, confirmPath, fixture.body)
			if fixture.withKey {
				request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != fixture.wantStatus || authority.call != "" {
				t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
			}
		})
	}
}

func TestRevokeAndGrantRoutesDispatchToAuthorityRuntime(t *testing.T) {
	grantIssue := workspacesPath + "/ws_alpha/confirmation-grants"
	grantRevoke := workspacesPath + "/ws_alpha/confirmation-grants/grant_01H9ABCDEFGHJKMNPQRSTVWXYZ:revoke"
	confirmRevoke := workspacesPath + "/ws_alpha/managed-source-confirmations/wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ:revoke"

	issueBody := `{"expected_workspace_revision":3,"expected_workspace_configuration_hash":"` + testHash + `","target_principal_id":"usr_confirmer","ttl_seconds":3600,"expected_policy_revision":"pol_alpha"}`
	grantRevokeBody := `{"grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","grant_revision":1,"grant_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`
	confirmRevokeBody := `{"confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`

	for name, fixture := range map[string]struct {
		path  string
		body  string
		call  string
		check func(*fakeAuthorityWorkspaceService, string) bool
	}{
		"issue grant": {grantIssue, issueBody, "issue_grant", func(s *fakeAuthorityWorkspaceService, idem string) bool {
			return s.issueRequest.WorkspaceID == "ws_alpha" && s.issueRequest.OrganizationID == "org_alpha" &&
				s.issueRequest.TargetPrincipalID == "usr_confirmer" && s.issueRequest.TTLSeconds == 3600 &&
				s.issueRequest.IdempotencyKey == idem
		}},
		"revoke grant": {grantRevoke, grantRevokeBody, "revoke_grant", func(s *fakeAuthorityWorkspaceService, idem string) bool {
			return s.revokeGrantRequest.WorkspaceID == "ws_alpha" && s.revokeGrantRequest.GrantID == "grant_01H9ABCDEFGHJKMNPQRSTVWXYZ" &&
				s.revokeGrantRequest.GrantRevision == 1 && s.revokeGrantRequest.OrganizationID == "org_alpha" &&
				s.revokeGrantRequest.IdempotencyKey == idem
		}},
		"revoke confirmation": {confirmRevoke, confirmRevokeBody, "revoke_confirmation", func(s *fakeAuthorityWorkspaceService, idem string) bool {
			return s.revokeConfirmationRequest.WorkspaceID == "ws_alpha" && s.revokeConfirmationRequest.ConfirmationID == "wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ" &&
				s.revokeConfirmationRequest.ConfirmationHash == testHash && s.revokeConfirmationRequest.OrganizationID == "org_alpha" &&
				s.revokeConfirmationRequest.IdempotencyKey == idem
		}},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newAuthorityHarness(t)
			request := harness.request(http.MethodPost, fixture.path, fixture.body)
			request.Header.Set("Idempotency-Key", harness.idempotencyKey)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || authority.call != fixture.call {
				t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
			}
			if !fixture.check(authority, harness.idempotencyKey) {
				t.Fatalf("request not projected to repository command: issue=%#v revokeGrant=%#v revokeConfirm=%#v", authority.issueRequest, authority.revokeGrantRequest, authority.revokeConfirmationRequest)
			}
		})
	}
}

func TestSourceServiceErrorMapping(t *testing.T) {
	if status, code := sourceServiceErrorResponse(registration.CodeRequestInvalid, false); status != http.StatusBadRequest || code != "REQUEST_INVALID" {
		t.Fatalf("invalid=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeDenied, true); status != http.StatusForbidden || code != "FORBIDDEN" {
		t.Fatalf("create denial=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeDenied, false); status != http.StatusNotFound || code != "NOT_FOUND" {
		t.Fatalf("read denial=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeNotFound, false); status != http.StatusNotFound || code != "NOT_FOUND" {
		t.Fatalf("not found=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeConflict, false); status != http.StatusConflict || code != "SOURCE_CONFLICT" {
		t.Fatalf("conflict=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeUnavailable, false); status != http.StatusServiceUnavailable || code != "SOURCE_UNAVAILABLE" {
		t.Fatalf("unavailable=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodePersistence, false); status != http.StatusServiceUnavailable || code != "SERVICE_UNAVAILABLE" {
		t.Fatalf("persistence=%d/%q", status, code)
	}
	if status, code := sourceServiceErrorResponse(registration.CodeUploadRejected, false); status != http.StatusBadRequest || code != "UPLOAD_REJECTED" {
		t.Fatalf("upload rejected=%d/%q", status, code)
	}
}

// multipartUploadRequest builds a POST to path with one multipart/form-data
// "files" field per (name, content) pair, cookie/CSRF-authenticated exactly
// like harness.request.
func (harness *testHarness) multipartUploadRequest(path string, files map[string][]byte) *http.Request {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, content := range files {
		part, err := writer.CreateFormFile("files", name)
		if err != nil {
			panic(err)
		}
		if _, err := part.Write(content); err != nil {
			panic(err)
		}
	}
	if err := writer.Close(); err != nil {
		panic(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://workspace.example"+path, &body)
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+harness.token)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("Origin", "https://workspace.example")
	request.Header.Set(httpauth.CSRFHeader, harness.csrf)
	return request
}

func TestUploadDocumentsDispatchesValidatedFiles(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.uploadResult = registration.UploadDocumentsResult{
		ConnectionID: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		Uploaded: []registration.UploadedDocument{
			{Name: "notes.txt", ObjectKey: "notes.txt", Version: 1, Format: "TXT", ByteSize: 11},
		},
	}
	request := harness.multipartUploadRequest(sourcesPath+"/"+testScopeID+"/documents", map[string][]byte{
		"notes.txt": []byte("hello world"),
	})
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "upload_documents" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	if harness.sources.uploadRequest.SourceScopeID != testScopeID || len(harness.sources.uploadRequest.Files) != 1 ||
		harness.sources.uploadRequest.Files[0].Name != "notes.txt" || string(harness.sources.uploadRequest.Files[0].Content) != "hello world" {
		t.Fatalf("upload request not projected: %#v", harness.sources.uploadRequest)
	}
	var decoded uploadDocumentsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if decoded.ConnectionID != "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ" || len(decoded.Uploaded) != 1 || decoded.Uploaded[0].Version != 1 {
		t.Fatalf("unexpected response: %#v", decoded)
	}
}

func TestUploadDocumentsRejectsEmptyRequest(t *testing.T) {
	harness := newTestHarness(t)
	request := harness.multipartUploadRequest(sourcesPath+"/"+testScopeID+"/documents", nil)
	response := httptest.NewRecorder()

	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || harness.sources.call != "" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
}
