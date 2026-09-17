package workspaceapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/workspace"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestWorkspaceListAndSnapshotProjectionIsLive proves every list summary and
// snapshot field is a live projection of the repository value, and the snapshot
// ETag is the configuration hash of the very snapshot served. This is the R4
// surface check: a constant substituted for any system value, or a hash
// computed over anything but the served snapshot, turns this test red.
func TestWorkspaceListAndSnapshotProjectionIsLive(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.list = []workspacerepository.Summary{{
		ID: "ws_alpha", Name: "Alpha", Status: workspace.StatusActive, Revision: 7, Role: workspace.RoleOwner,
	}}

	listRequest := harness.request(http.MethodGet, workspacesPath, "")
	listResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK || harness.service.call != "list" {
		t.Fatalf("list status=%d call=%q body=%s", listResponse.Code, harness.service.call, listResponse.Body.String())
	}
	listBody := listResponse.Body.String()
	for _, want := range []string{
		`"id":"ws_alpha"`, `"name":"Alpha"`, `"status":"ACTIVE"`, `"revision":7`, `"role":"OWNER"`,
	} {
		if !strings.Contains(listBody, want) {
			t.Fatalf("list body missing %s: %s", want, listBody)
		}
	}
	harness.service.call = ""

	getRequest := harness.request(http.MethodGet, workspacesPath+"/ws_alpha", "")
	getResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || harness.service.call != "get" {
		t.Fatalf("get status=%d call=%q body=%s", getResponse.Code, harness.service.call, getResponse.Body.String())
	}
	if getResponse.Header().Get("ETag") != `"`+harness.hash+`"` {
		t.Fatalf("ETag=%q, want %q (the hash of the served snapshot)", getResponse.Header().Get("ETag"), harness.hash)
	}
	getBody := getResponse.Body.String()
	for _, want := range []string{
		`"id":"ws_alpha"`, `"name":"Alpha"`, `"description":""`, `"status":"ACTIVE"`, `"revision":1`,
		`"owner_principal_id":"usr_alice"`, `"retention_policy_id":""`,
		`"members":[{"principal_id":"usr_alice","display_name":"Alice","role":"OWNER"}]`,
	} {
		if !strings.Contains(getBody, want) {
			t.Fatalf("snapshot body missing %s: %s", want, getBody)
		}
	}
	for _, forbidden := range []string{`"email"`, `"external_identity"`} {
		if strings.Contains(getBody, forbidden) {
			t.Fatalf("snapshot body leaked member identity field %s: %s", forbidden, getBody)
		}
	}
}

// TestWorkspaceListDegradesOnlyTheStaleHashWorkspace proves the 12.09 acc2
// guard projection: a mixed list where one member workspace carries a stale
// configuration hash still answers 200, that workspace alone exposes the typed
// degraded marker, and every healthy workspace keeps the exact pre-guard
// byte shape. No hash bytes are projected for either workspace.
func TestWorkspaceListDegradesOnlyTheStaleHashWorkspace(t *testing.T) {
	harness := newTestHarness(t)
	harness.service.list = []workspacerepository.Summary{
		{ID: "ws_alpha", Name: "Alpha", Status: workspace.StatusActive, Revision: 7, Role: workspace.RoleOwner},
		{
			ID: "ws_beta", Name: "Beta", Status: workspace.StatusActive, Revision: 3, Role: workspace.RoleManager,
			Degraded: true, DegradedReason: workspacerepository.SummaryDegradedReasonConfigurationHashStale,
		},
	}

	request := harness.request(http.MethodGet, workspacesPath, "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.service.call != "list" {
		t.Fatalf("list status=%d call=%q body=%s", response.Code, harness.service.call, response.Body.String())
	}
	body := response.Body.String()
	// The healthy workspace stays byte-identical: the additive degraded fields
	// are omitted entirely, so the historical projection is unchanged.
	if !strings.Contains(body, `{"id":"ws_alpha","name":"Alpha","status":"ACTIVE","revision":7,"role":"OWNER"}`) {
		t.Fatalf("healthy workspace projection changed: %s", body)
	}
	for _, want := range []string{
		`"id":"ws_beta"`, `"degraded":true`, `"degraded_reason":"WORKSPACE_CONFIGURATION_HASH_STALE"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("degraded workspace body missing %s: %s", want, body)
		}
	}
	for _, forbidden := range []string{"sha256:", harness.hash} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("workspace list leaked configuration hash bytes %q: %s", forbidden, body)
		}
	}
}

// TestListSourcesProjectsEveryStatusField proves the sources surface projects
// every field of the repository status — identifiers, liveness, counters and
// timestamps — so a constant in place of any system value turns this test red.
func TestListSourcesProjectsEveryStatusField(t *testing.T) {
	harness := newTestHarness(t)
	syncStatus := "RUNNING"
	syncErrorCode := "TRANSIENT_BACKOFF"
	startedAt := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	completedAt := time.Date(2026, 8, 14, 10, 5, 0, 0, time.UTC)
	objectsSeen := int64(41)
	objectsIngested := int64(40)
	versionsCreated := int64(3)
	evidencePublished := int64(7)
	quarantined := int64(1)
	jobID := "syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ"
	jobStatus := "RUNNING"
	jobAttemptCount := int64(2)
	jobMaxAttempts := int64(3)
	jobAvailableAt := time.Date(2026, 8, 14, 9, 55, 0, 0, time.UTC)
	jobLeaseExpiresAt := time.Date(2026, 8, 14, 10, 15, 0, 0, time.UTC)
	jobLastErrorCode := "TRANSIENT_BACKOFF"
	contentFreshnessSLASeconds := int64(3600)
	lastSuccessfulSyncAt := time.Date(2026, 8, 14, 10, 5, 0, 0, time.UTC)
	freshnessState := "FRESH"
	postgresqlSchemaName := "reporting"
	postgresqlRelationName := "waste_daily"
	harness.sources.statuses = []workspacerepository.SourceStatus{{
		WorkspaceSourceID:          "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		SourceScopeID:              testScopeID,
		SourceScopeRevision:        5,
		AccessMode:                 "WORKSPACE_MANAGED",
		Enabled:                    true,
		ScopeConfigHash:            "sha256:" + strings.Repeat("ab", 32),
		ConnectionID:               "conn_s1d",
		ConnectionName:             "Engineering docs",
		SourceType:                 "POSTGRESQL_QUERY",
		PostgreSQLSchemaName:       &postgresqlSchemaName,
		PostgreSQLRelationName:     &postgresqlRelationName,
		ActivationStatus:           "SYNCING",
		TrustVerified:              true,
		SyncStatus:                 &syncStatus,
		SyncErrorCode:              &syncErrorCode,
		SyncStartedAt:              &startedAt,
		SyncCompletedAt:            &completedAt,
		ObjectsSeen:                &objectsSeen,
		ObjectsIngested:            &objectsIngested,
		VersionsCreated:            &versionsCreated,
		EvidencePublished:          &evidencePublished,
		Quarantined:                &quarantined,
		JobID:                      &jobID,
		JobStatus:                  &jobStatus,
		JobAttemptCount:            &jobAttemptCount,
		JobMaxAttempts:             &jobMaxAttempts,
		JobAvailableAt:             &jobAvailableAt,
		JobLeaseExpiresAt:          &jobLeaseExpiresAt,
		JobLastErrorCode:           &jobLastErrorCode,
		ContentFreshnessSLASeconds: contentFreshnessSLASeconds,
		LastSuccessfulSyncAt:       &lastSuccessfulSyncAt,
		FreshnessState:             freshnessState,
	}}

	request := harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", "")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || harness.sources.call != "list_sources" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, harness.sources.call, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		`"source_scope_id":"` + testScopeID + `"`,
		`"source_scope_revision":5`,
		`"access_mode":"WORKSPACE_MANAGED"`,
		`"enabled":true`,
		`"scope_config_hash":"sha256:` + strings.Repeat("ab", 32) + `"`,
		`"connection_id":"conn_s1d"`,
		`"connection_name":"Engineering docs"`,
		`"source_type":"POSTGRESQL_QUERY"`,
		`"postgresql_schema_name":"reporting"`,
		`"postgresql_relation_name":"waste_daily"`,
		`"activation_status":"SYNCING"`,
		`"trust_verified":true`,
		`"sync_status":"RUNNING"`,
		`"sync_error_code":"TRANSIENT_BACKOFF"`,
		`"sync_started_at":"2026-08-14T10:00:00Z"`,
		`"sync_completed_at":"2026-08-14T10:05:00Z"`,
		`"objects_seen":41`,
		`"objects_ingested":40`,
		`"versions_created":3`,
		`"evidence_published":7`,
		`"quarantined":1`,
		`"job_id":"syncscope_01H9ABCDEFGHJKMNPQRSTVWXYZ"`,
		`"job_status":"RUNNING"`,
		`"job_attempt_count":2`,
		`"job_max_attempts":3`,
		`"job_available_at":"2026-08-14T09:55:00Z"`,
		`"job_lease_expires_at":"2026-08-14T10:15:00Z"`,
		`"job_last_error_code":"TRANSIENT_BACKOFF"`,
		`"content_freshness_sla_seconds":3600`,
		`"last_successful_sync_at":"2026-08-14T10:05:00Z"`,
		`"freshness_state":"FRESH"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("sources body missing %s: %s", want, body)
		}
	}
}

func TestListSourcesKeepsPostgreSQLMetadataNullForNonPostgreSQLSource(t *testing.T) {
	harness := newTestHarness(t)
	harness.sources.statuses = []workspacerepository.SourceStatus{{
		WorkspaceSourceID: "binding_git_01", SourceScopeID: testScopeID, SourceScopeRevision: 1,
		AccessMode: "WORKSPACE_MANAGED", Enabled: true, ScopeConfigHash: testHash,
		ConnectionID: "conn_git_01", ConnectionName: "Engineering code", SourceType: "GIT",
		ActivationStatus: "READY", TrustVerified: true,
	}}

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/sources", ""))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`"source_type":"GIT"`,
		`"postgresql_schema_name":null`,
		`"postgresql_relation_name":null`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("non-PostgreSQL source body missing %s: %s", want, body)
		}
	}
}
