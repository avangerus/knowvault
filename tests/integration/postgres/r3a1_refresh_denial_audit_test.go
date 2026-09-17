package postgres_test

// R3a-1 Outcome 2 refresh negative control, proved on the real workspaceapi
// MCP/REST dispatch over the real workspacerepository.Store and the real audit
// journal.
//
// knowvault_refresh (MCP) and its REST parity routes GET/POST
// /api/v1/workspaces/{workspace_id}/tools/refresh must answer a principal
// without the workspace right with the existing documented content-free denial
// — no refreshed row, no skip reason and no echo of the requested workspace id
// — and the denial class must land in the R1 audit journal.
//
// The refresh core composes the same injected SourceService.ListSources read
// the REST listSources route composes. That read is the source repository's
// single no-oracle ErrNotFound and, like the fragment read, appends nothing on
// its own (internal/workspace/repository/source_status.go). Exactly as the
// R3a-1 KV-A01 control does for the knowvault_read cross-workspace denial
// (catalog_evidence_controls_test.go), this suite therefore proves the refresh
// denial is content-free at both transports AND proves the R1
// admission-before-data journal record for the same denied membership through
// the workspace-scoped inventory read (knowvault_list_objects and its
// compatibility alias knowvault_workspace_list), which shares the one audit
// journal. The handler, the source repository and the audit store are the real
// production ones; there is no fake SourceService and no raw row forgery.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// r3a1RefreshSourceService exposes the real workspace repository as the
// workspaceapi SourceService boundary: ListSources and ConfirmationContext are
// the production reads, while the administrative commands this negative
// control never reaches fail closed so a stray dispatch is a visible test
// failure rather than a silent no-op.
type r3a1RefreshSourceService struct{ workspaces *workspacerepository.Store }

func (service r3a1RefreshSourceService) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	return service.workspaces.ListSources(ctx, access, workspaceID)
}

func (service r3a1RefreshSourceService) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (workspacerepository.ConfirmationContext, error) {
	return service.workspaces.ConfirmationContext(ctx, access, workspaceID)
}

func (r3a1RefreshSourceService) Register(context.Context, database.AccessContext, registration.RegisterRequest) (registration.RegisterResult, error) {
	return registration.RegisterResult{}, errors.New("r3a1-refresh: source registration not composed for this control")
}

func (r3a1RefreshSourceService) Activate(context.Context, database.AccessContext, registration.ActivateRequest) (registration.ActivateResult, error) {
	return registration.ActivateResult{}, errors.New("r3a1-refresh: source activation not composed for this control")
}

func (r3a1RefreshSourceService) Sync(context.Context, database.AccessContext, registration.SyncRequest) (registration.SyncResult, error) {
	return registration.SyncResult{}, errors.New("r3a1-refresh: source sync not composed for this control")
}

func (r3a1RefreshSourceService) UploadDocuments(context.Context, database.AccessContext, registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return registration.UploadDocumentsResult{}, errors.New("r3a1-refresh: upload not composed for this control")
}

// r3a1RefreshHandler composes the real workspaceapi handler over the real
// workspace repository, the real audit journal and the real evidence viewer,
// authenticated as one principal through the same httpauth OIDC/Keycloak
// transport the deployment uses (a verified session cookie plus the tenant's
// CSRF proof).
func r3a1RefreshHandler(t *testing.T, organizationID, principal string, viewer *evidence.Viewer, authority *workspacerepository.Store) (*workspaceapi.Handler, string, string) {
	t.Helper()
	authenticator, err := httpauth.New(
		kvA01TenantResolver{organizationID: organizationID},
		kvA01SessionResolver{organizationID: organizationID, principalID: principal, claims: kvA01Claims(t, organizationID, principal)},
	)
	if err != nil {
		t.Fatalf("r3a1-refresh authenticator: %v", err)
	}
	handler, err := workspaceapi.NewWithQuestionsAndConversations(authenticator, authority,
		r3a1RefreshSourceService{workspaces: authority}, viewer, nil, nil)
	if err != nil {
		t.Fatalf("r3a1-refresh workspace handler: %v", err)
	}
	rawToken := make([]byte, sha256.Size)
	for index := range rawToken {
		rawToken[index] = byte(index + 1)
	}
	token := base64.RawURLEncoding.EncodeToString(rawToken)
	proof, err := (kvA01Digestor{}).Digest("csrf", token)
	if err != nil {
		t.Fatalf("r3a1-refresh csrf proof: %v", err)
	}
	return handler, token, proof.Value()
}

// TestR3A1RefreshDenialAdmittedAndJournaled drives the real MCP and REST
// refresh surfaces for a principal without the workspace right and pins the
// content-free denial plus its R1 journal record.
func TestR3A1RefreshDenialAdmittedAndJournaled(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_owner", "ws_alpha")
	// A principal of the same organization with no workspace membership: the
	// "principal without the workspace right" of the negative control.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ('usr_outsider', 'org_alpha', 'USER', 'Outsider', 'ACTIVE')`); err != nil {
		t.Fatalf("seed non-member principal: %v", err)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("create audit store: %v", err)
	}
	authority, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("create workspace repository: %v", err)
	}
	viewer, err := evidence.NewViewer(appStore, s1dCodec(t, "org_alpha"))
	if err != nil {
		t.Fatalf("create evidence viewer: %v", err)
	}

	// Positive control: the real OWNER member reaches the authorized refresh
	// projection, so the denial below is a membership decision and not a broken
	// handler.
	memberHandler, memberToken, memberCSRF := r3a1RefreshHandler(t, "org_alpha", "usr_owner", viewer, authority)
	memberBody, memberEnvelope := kvA01Call(t, memberHandler, memberToken, memberCSRF,
		kvA01ToolCallBody("r3a1-refresh-member", "knowvault_refresh", `{"workspace_id":"ws_alpha"}`))
	if memberEnvelope.Error != nil {
		t.Fatalf("authorized member refresh refused: %#v body=%s", memberEnvelope.Error, memberBody)
	}

	handler, token, csrf := r3a1RefreshHandler(t, "org_alpha", "usr_outsider", viewer, authority)

	// MCP: the pre-existing content-free -32004 denial, no result content and
	// no echo of the requested workspace.
	mcpBody, mcpEnvelope := kvA01Call(t, handler, token, csrf,
		kvA01ToolCallBody("r3a1-refresh-denied", "knowvault_refresh", `{"workspace_id":"ws_alpha"}`))
	if mcpEnvelope.Error == nil || mcpEnvelope.Error.Code != -32004 || mcpEnvelope.Error.Message != "source scope not found" {
		t.Fatalf("MCP refresh denial = %#v body=%s", mcpEnvelope.Error, mcpBody)
	}
	if len(mcpEnvelope.Result.Structured) != 0 || len(mcpEnvelope.Result.Content) != 0 {
		t.Fatalf("MCP refresh denial leaked content: %s", mcpBody)
	}
	if strings.Contains(mcpBody, "ws_alpha") {
		t.Fatalf("MCP refresh denial echoed the requested workspace: %s", mcpBody)
	}

	// REST GET and POST parity: the same documented content-free 404 NOT_FOUND.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run("rest/"+method, func(t *testing.T) {
			request := httptest.NewRequest(method, kvA01Origin+"/api/v1/workspaces/ws_alpha/tools/refresh", nil)
			request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
			if method == http.MethodPost {
				request.Header.Set("Origin", kvA01Origin)
				request.Header.Set(httpauth.CSRFHeader, csrf)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"NOT_FOUND"`) {
				t.Fatalf("REST %s refresh denial status=%d body=%s", method, response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "ws_alpha") {
				t.Fatalf("REST %s refresh denial echoed the requested workspace: %s", method, response.Body.String())
			}
		})
	}

	// R1 admission-before-data journal: the refused membership read is the
	// source repository's no-oracle denial and appends nothing itself, so the
	// same denied workspace is read through the workspace-scoped inventory tool.
	// It shares the one audit journal and records a content-free DENIED
	// admission with its closed class and a NULL workspace (never a foreign-key
	// failure and never an existence oracle).
	listBody := kvA01ToolCallBody("r3a1-refresh-list", "knowvault_workspace_list", `{"workspace_id":"ws_alpha"}`)
	rawList, listEnvelope := kvA01Call(t, handler, token, csrf, listBody)
	if listEnvelope.Error == nil || listEnvelope.Error.Code != -32004 || listEnvelope.Error.Message != "workspace objects not found" {
		t.Fatalf("denied inventory not the content-free not-found: %#v body=%s", listEnvelope.Error, rawList)
	}
	var outcome, errorCode string
	var workspaceID *string
	if err := admin.QueryRow(ctx, `
		SELECT outcome, error_code, workspace_id
		FROM public.audit_event
		WHERE organization_id = 'org_alpha'
		  AND action = 'evidence.read.admitted'
		  AND outcome = 'DENIED'
		  AND resource_id = 'ws_alpha'
		ORDER BY occurred_at DESC, id DESC
		LIMIT 1`).Scan(&outcome, &errorCode, &workspaceID); err != nil {
		t.Fatalf("load the denial journal event: %v", err)
	}
	if outcome != "DENIED" || errorCode != "WORKSPACE_OBJECTS_DENIED" {
		t.Fatalf("denial journal event = (%s, %s), want DENIED/WORKSPACE_OBJECTS_DENIED", outcome, errorCode)
	}
	if workspaceID != nil {
		t.Fatalf("denial journal event recorded workspace %q, want NULL", *workspaceID)
	}
}
