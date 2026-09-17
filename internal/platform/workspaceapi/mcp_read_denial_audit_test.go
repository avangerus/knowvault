package workspaceapi

// R3a-1 KV-A02d focused probe: the per-tool denial admission/audit negative
// control for the canonical knowvault_read tool (and its REST tools/read parity
// route). It complements the existing content-free read-denial tests by proving
// the call records admission before any data and a terminal closed denial class,
// which is the R3a-1 Outcome 2 requirement every other KnowVault knowledge tool
// already carries.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// readDenialAuditSource wraps the read EvidenceService boundary to record the
// admission-before-data and terminal outcome sequence of the knowvault_read
// negative control. In production that sequence is the real evidence viewer's
// workspace admission followed by its R1 audit journal record; in this unit
// probe it is the injected EvidenceService boundary, so the tool's delegation to
// a read that admits, then records a classed denial, is observable without a raw
// row forgery or a second read path.
type readDenialAuditSource struct {
	*fakeEvidenceService
	order []string
}

func (service *readDenialAuditSource) Read(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (evidence.Fragment, error) {
	service.order = append(service.order, "admission")
	fragment, err := service.fakeEvidenceService.Read(ctx, access, workspaceID, fragmentID)
	if err != nil {
		service.order = append(service.order, "denied:"+string(workspacerepository.CodeOf(err)))
		return fragment, err
	}
	service.order = append(service.order, "data")
	return fragment, nil
}

// TestMCPKnowvaultReadDenialAdmittedAndAudited is the R3a-1 Outcome 2 negative
// control for the canonical knowvault_read tool and its REST parity route
// GET/POST /api/v1/workspaces/{workspace_id}/tools/read: a principal without the
// workspace right must receive the existing content-free -32004
// `evidence not found` (REST: 404 NOT_FOUND) with no page text, no address, no
// structuredContent and no workspace-id echo, and the call must record admission
// before data and its classed denial outcome through the same authorized
// EvidenceService boundary the production viewer implements. Weakening the read
// denial guard in internal/platform/workspaceapi/mcp_adapter.go to fall through
// turns this probe RED.
func TestMCPKnowvaultReadDenialAdmittedAndAudited(t *testing.T) {
	harness := newTestHarness(t)
	audit := &readDenialAuditSource{fakeEvidenceService: &fakeEvidenceService{
		err: workspacerepository.NewError(workspacerepository.CodeDenied, nil),
	}}
	harness.handler.evidence = audit

	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"r1","method":"tools/call","params":{"name":"`+mcpToolEvidenceRead+`","arguments":{"workspace_id":"ws_foreign","fragment_id":"fragment_denied_01H9ABCDEFGHJKMNPQRSTVWXYZ"}}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_read transport status=%d body=%s", response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("MCP knowvault_read denial did not decode: %v: %s", err, response.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "evidence not found" {
		t.Fatalf("MCP knowvault_read denial error=%#v body=%s", outcome.Error, response.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("MCP knowvault_read denial carried a result: %s", string(*outcome.Result))
	}
	if audit.call != "read" {
		t.Fatalf("MCP knowvault_read denial never reached the authorized evidence read: %q", audit.call)
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"text"`, `"address"`, "fragment_denied", testScopeID} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("MCP knowvault_read denial leaked %q: %s", leaked, response.Body.String())
		}
	}
	if order := strings.Join(audit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
		t.Fatalf("MCP knowvault_read denial audit order=%q, want admission before the closed-class denial", order)
	}

	// The REST parity route dispatches through the identical EvidenceService.Read
	// core, so it records the same admission/classed-denial sequence and answers
	// the documented content-free 404 NOT_FOUND with no page and no workspace echo.
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		method := method
		t.Run("rest/"+method, func(t *testing.T) {
			restHarness := newTestHarness(t)
			restAudit := &readDenialAuditSource{fakeEvidenceService: &fakeEvidenceService{
				err: workspacerepository.NewError(workspacerepository.CodeDenied, nil),
			}}
			restHarness.handler.evidence = restAudit

			restResponse := httptest.NewRecorder()
			restHarness.handler.ServeHTTP(restResponse, restHarness.request(method,
				apiPrefix+"/workspaces/ws_foreign/tools/read?fragment_id=fragment_denied_01H9ABCDEFGHJKMNPQRSTVWXYZ", ""))
			if restResponse.Code != http.StatusNotFound {
				t.Fatalf("REST read %s denial status=%d body=%s", method, restResponse.Code, restResponse.Body.String())
			}
			if restAudit.call != "read" {
				t.Fatalf("REST read %s denial never reached the authorized evidence read: %q", method, restAudit.call)
			}
			for _, leaked := range []string{"ws_foreign", `"text"`, `"address"`, "fragment_denied", testScopeID} {
				if strings.Contains(restResponse.Body.String(), leaked) {
					t.Fatalf("REST read %s denial leaked %q: %s", method, leaked, restResponse.Body.String())
				}
			}
			if order := strings.Join(restAudit.order, ","); order != "admission,denied:WORKSPACE_DENIED" {
				t.Fatalf("REST read %s denial audit order=%q, want admission before the closed-class denial", method, order)
			}
		})
	}
}
