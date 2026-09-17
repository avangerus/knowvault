package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// mcpAuthorityResultBody decodes the MCP success envelope of an ADR-0087 §1
// confirmation tool, which mirrors the REST authorityCommandResponse projection
// exactly: command_id, operation, result_id and result_hash, never canonical
// bytes.
type mcpAuthorityResultBody struct {
	CommandID  string `json:"command_id"`
	Operation  string `json:"operation"`
	ResultID   string `json:"result_id"`
	ResultHash string `json:"result_hash"`
}

type mcpAuthorityEnvelope struct {
	Result struct {
		Structured mcpAuthorityResultBody `json:"structuredContent"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

// mcpAuthorityCall fires one tools/call against /api/v1/mcp with the HTTP
// Idempotency-Key the confirmation commands require, mirroring how the accepted
// REST actions and the question/archive MCP tools enforce the idempotency
// contract at the boundary.
func (harness *testHarness) mcpAuthorityCall(t *testing.T, handler *Handler, toolName, arguments string) *httptest.ResponseRecorder {
	t.Helper()
	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"auth1","method":"tools/call","params":{"name":"`+toolName+`","arguments":`+arguments+`}}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestMCPAuthorityToolsListAdvertisesAllFourConfirmationTools proves tools/list
// names the four ADR-0087 §1 confirmation tools with argument schemas bounded
// to exactly the closed body fields each REST action accepts (no free-form
// member, no bypass surface).
func TestMCPAuthorityToolsListAdvertisesAllFourConfirmationTools(t *testing.T) {
	harness := newTestHarness(t)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	if response.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", response.Code, response.Body.String())
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal([]byte(response.Body.String()), &list); err != nil || list.Error != nil {
		t.Fatalf("tools/list did not decode: err=%v error=%#v body=%s", err, list.Error, response.Body.String())
	}
	expectedRequired := map[string][]string{
		"knowvault_confirmation_grant_issue": {"workspace_id", "expected_workspace_revision", "expected_workspace_configuration_hash", "target_principal_id", "ttl_seconds", "expected_policy_revision"},
		"knowvault_confirmation_grant_revoke": {"workspace_id", "grant_id", "grant_revision", "grant_hash", "expected_policy_revision"},
		"knowvault_managed_source_confirm":    {"workspace_id", "workspace_revision", "workspace_configuration_hash", "workspace_source_id", "source_scope_id", "source_scope_revision", "scope_config_hash", "confirmation_actor_grant_id", "confirmation_actor_grant_revision", "confirmation_actor_grant_hash", "warning_contract_hash", "expected_policy_revision"},
		"knowvault_managed_confirmation_revoke": {"workspace_id", "confirmation_id", "confirmation_hash", "expected_policy_revision"},
	}
	for _, tool := range list.Result.Tools {
		required, ok := expectedRequired[tool.Name]
		if !ok {
			continue // other tools asserted by their own tests
		}
		delete(expectedRequired, tool.Name)
		if additional, ok := tool.InputSchema["additionalProperties"].(bool); !ok || additional {
			t.Fatalf("tool %q is not closed: inputSchema=%#v", tool.Name, tool.InputSchema)
		}
		gotRequired, ok := tool.InputSchema["required"].([]any)
		if !ok || len(gotRequired) != len(required) {
			t.Fatalf("tool %q required=%#v want=%#v", tool.Name, tool.InputSchema["required"], required)
		}
		for _, want := range required {
			found := false
			for _, r := range gotRequired {
				if r == want {
					found = true
				}
			}
			if !found {
				t.Fatalf("tool %q missing required %q: %#v", tool.Name, want, tool.InputSchema)
			}
		}
	}
	for name := range expectedRequired {
		t.Fatalf("tools/list omitted confirmation tool %q", name)
	}
}

// TestMCPConfirmationToolsDispatchMatchesRESTActions proves each confirmation
// tool reaches the same injected WorkspaceAuthority runtime the accepted REST
// action uses, derives organization, workspace and idempotency server-side, and
// returns the identical authorityCommandResponse projection the REST route
// serves.
func TestMCPConfirmationToolsDispatchMatchesRESTActions(t *testing.T) {
	for name, fixture := range map[string]struct {
		tool      string
		arguments string
		call      string
		check     func(*fakeAuthorityWorkspaceService, string) bool
	}{
		"grant issue": {
			tool:      mcpToolConfirmationGrantIssue,
			arguments: `{"workspace_id":"ws_alpha","expected_workspace_revision":3,"expected_workspace_configuration_hash":"` + testHash + `","target_principal_id":"usr_confirmer","ttl_seconds":3600,"expected_policy_revision":"pol_alpha"}`,
			call:      "issue_grant",
			check: func(s *fakeAuthorityWorkspaceService, idem string) bool {
				return s.issueRequest.WorkspaceID == "ws_alpha" && s.issueRequest.OrganizationID == "org_alpha" &&
					s.issueRequest.TargetPrincipalID == "usr_confirmer" && s.issueRequest.TTLSeconds == 3600 &&
					s.issueRequest.ExpectedWorkspaceRevision == 3 && s.issueRequest.ExpectedPolicyRevision == "pol_alpha" &&
					s.issueRequest.IdempotencyKey == idem
			},
		},
		"grant revoke": {
			tool:      mcpToolConfirmationGrantRevoke,
			arguments: `{"workspace_id":"ws_alpha","grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","grant_revision":1,"grant_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`,
			call:      "revoke_grant",
			check: func(s *fakeAuthorityWorkspaceService, idem string) bool {
				return s.revokeGrantRequest.WorkspaceID == "ws_alpha" && s.revokeGrantRequest.OrganizationID == "org_alpha" &&
					s.revokeGrantRequest.GrantID == "grant_01H9ABCDEFGHJKMNPQRSTVWXYZ" && s.revokeGrantRequest.GrantRevision == 1 &&
					s.revokeGrantRequest.IdempotencyKey == idem
			},
		},
		"managed source confirm": {
			tool:      mcpToolManagedSourceConfirm,
			arguments: `{"workspace_id":"ws_alpha","workspace_revision":3,"workspace_configuration_hash":"` + testHash + `","workspace_source_id":"binding_01H9ABCDEFGHJKMNPQRSTVWXYZ","source_scope_id":"` + testScopeID + `","source_scope_revision":2,"scope_config_hash":"` + testHash + `","confirmation_actor_grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_actor_grant_revision":1,"confirmation_actor_grant_hash":"` + testHash + `","warning_contract_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`,
			call:      "confirm",
			check: func(s *fakeAuthorityWorkspaceService, idem string) bool {
				return s.confirmRequest.WorkspaceID == "ws_alpha" && s.confirmRequest.OrganizationID == "org_alpha" &&
					s.confirmRequest.WorkspaceSourceID == "binding_01H9ABCDEFGHJKMNPQRSTVWXYZ" && s.confirmRequest.SourceScopeID == testScopeID &&
					s.confirmRequest.AccessMode == managedAccessMode && s.confirmRequest.WarningVersion == managedWarningVersion &&
					s.confirmRequest.AcknowledgementCode == managedAcknowledgementCode && s.confirmRequest.IdempotencyKey == idem
			},
		},
		"managed confirmation revoke": {
			tool:      mcpToolManagedConfirmationRevoke,
			arguments: `{"workspace_id":"ws_alpha","confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`,
			call:      "revoke_confirmation",
			check: func(s *fakeAuthorityWorkspaceService, idem string) bool {
				return s.revokeConfirmationRequest.WorkspaceID == "ws_alpha" && s.revokeConfirmationRequest.OrganizationID == "org_alpha" &&
					s.revokeConfirmationRequest.ConfirmationID == "wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ" && s.revokeConfirmationRequest.ConfirmationHash == testHash &&
					s.revokeConfirmationRequest.IdempotencyKey == idem
			},
		},
	} {
		name, fixture := name, fixture
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newAuthorityHarness(t)
			authority.authorityResult = workspacerepository.AuthorityResult{
				CommandID: "cmd_01H9ABCDEFGHJKMNPQRSTVWXYZ", Operation: "WORKSPACE_AUTHORITY",
				ResultID: "res_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultHash: harness.hash,
			}
			response := harness.mcpAuthorityCall(t, handler, fixture.tool, fixture.arguments)
			if response.Code != http.StatusOK {
				t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
			}
			if authority.call != fixture.call || authority.access.RequestID != "req_server_001" {
				t.Fatalf("call=%q access=%#v", authority.call, authority.access)
			}
			if !fixture.check(authority, harness.idempotencyKey) {
				t.Fatalf("request not projected to repository command: issue=%#v revokeGrant=%#v confirm=%#v revokeConfirm=%#v",
					authority.issueRequest, authority.revokeGrantRequest, authority.confirmRequest, authority.revokeConfirmationRequest)
			}
			var envelope mcpAuthorityEnvelope
			if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil || envelope.Error != nil {
				t.Fatalf("MCP result did not decode: err=%v error=%#v body=%s", err, envelope.Error, response.Body.String())
			}
			// Same immutable projection the REST action returns (ADR-0053): the
			// identity/hash quartet, never the canonical bytes.
			if envelope.Result.Structured.CommandID != "cmd_01H9ABCDEFGHJKMNPQRSTVWXYZ" ||
				envelope.Result.Structured.ResultID != "res_01H9ABCDEFGHJKMNPQRSTVWXYZ" ||
				envelope.Result.Structured.ResultHash != harness.hash {
				t.Fatalf("result projection mismatch: %s", response.Body.String())
			}
		})
	}
}

// TestMCPConfirmationToolDenialsMapToClosedNotFound proves the MCP surface
// collapses policy denial and a hidden/missing authority row into one identical
// content-free -32004, so a caller cannot distinguish "wrong role" from "no
// such grant/confirmation/binding" (no role or existence oracle), exactly as
// the accepted REST route collapses them into one 404 NOT_FOUND.
func TestMCPConfirmationToolDenialsMapToClosedNotFound(t *testing.T) {
	arguments := `{"workspace_id":"ws_alpha","confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`
	var deniedBody, notFoundBody string
	for _, code := range []workspacerepository.ErrorCode{workspacerepository.CodeAuthorityDenied, workspacerepository.CodeAuthorityNotFound} {
		harness, authority, handler := newAuthorityHarness(t)
		authority.err = workspacerepository.NewError(code, nil)
		response := harness.mcpAuthorityCall(t, handler, mcpToolManagedConfirmationRevoke, arguments)
		if response.Code != http.StatusOK || authority.call != "revoke_confirmation" {
			t.Fatalf("code=%s status=%d call=%q body=%s", code, response.Code, authority.call, response.Body.String())
		}
		var envelope mcpAuthorityEnvelope
		if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
			t.Fatalf("code=%s did not decode: %v", code, err)
		}
		if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "confirmation not found" {
			t.Fatalf("code=%s not closed not-found: %s", code, response.Body.String())
		}
		if strings.Contains(response.Body.String(), "wmc_") || strings.Contains(response.Body.String(), "ws_alpha") || strings.Contains(response.Body.String(), "structuredContent") {
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

// TestMCPConfirmationToolIdempotencyConflictMapsToMCPConflict proves an
// idempotency conflict returned by the authority runtime surfaces as the MCP
// conflict error the REST 409 WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT
// corresponds to, and never reaches the success envelope.
func TestMCPConfirmationToolIdempotencyConflictMapsToMCPConflict(t *testing.T) {
	harness, authority, handler := newAuthorityHarness(t)
	authority.err = workspacerepository.NewError(workspacerepository.CodeAuthorityIdempotencyConflict, nil)
	arguments := `{"workspace_id":"ws_alpha","grant_id":"grant_01H9ABCDEFGHJKMNPQRSTVWXYZ","grant_revision":1,"grant_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`
	response := harness.mcpAuthorityCall(t, handler, mcpToolConfirmationGrantRevoke, arguments)
	if response.Code != http.StatusOK || authority.call != "revoke_grant" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
	var envelope mcpAuthorityEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("did not decode: %v", err)
	}
	if envelope.Error == nil || envelope.Error.Code != -32009 || envelope.Error.Message != "confirmation idempotency conflict" {
		t.Fatalf("expected -32009 idempotency conflict, got: %s", response.Body.String())
	}
}

// TestMCPConfirmationToolsFailClosedWhenAuthorityNotComposed proves a
// composition whose workspace service is not authority-capable fails closed with
// the SERVICE_UNAVAILABLE equivalent before any repository touch, mirroring the
// REST routes' behavior when no WorkspaceAuthority is injected.
func TestMCPConfirmationToolsFailClosedWhenAuthorityNotComposed(t *testing.T) {
	harness := newTestHarness(t) // plain fakeWorkspaceService implements no WorkspaceAuthority
	arguments := `{"workspace_id":"ws_alpha","expected_workspace_revision":3,"expected_workspace_configuration_hash":"` + testHash + `","target_principal_id":"usr_confirmer","ttl_seconds":3600,"expected_policy_revision":"pol_alpha"}`
	response := harness.mcpAuthorityCall(t, harness.handler, mcpToolConfirmationGrantIssue, arguments)
	if response.Code != http.StatusOK {
		t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
	}
	if harness.service.call != "" {
		t.Fatalf("authority call reached an uncomposed service: call=%q", harness.service.call)
	}
	var envelope mcpAuthorityEnvelope
	if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
		t.Fatalf("did not decode: %v", err)
	}
	if envelope.Error == nil || envelope.Error.Code != -32000 || envelope.Error.Message != "service unavailable" {
		t.Fatalf("expected -32000 service unavailable, got: %s", response.Body.String())
	}
}

// TestMCPConfirmationToolRejectsUnboundedArguments proves each tool honors its
// closed schema: an unknown member or a missing workspace is rejected at the
// transport boundary and never reaches the authority runtime.
func TestMCPConfirmationToolRejectsUnboundedArguments(t *testing.T) {
	arguments := `{"workspace_id":"ws_alpha","confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`
	for name, args := range map[string]string{
		"missing_workspace_id": `{"confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha"}`,
		"unknown_member":       `{"workspace_id":"ws_alpha","confirmation_id":"wmc_01H9ABCDEFGHJKMNPQRSTVWXYZ","confirmation_hash":"` + testHash + `","expected_policy_revision":"pol_alpha","extra":true}`,
	} {
		name, args := name, args
		t.Run(name, func(t *testing.T) {
			harness, authority, handler := newAuthorityHarness(t)
			response := harness.mcpAuthorityCall(t, handler, mcpToolManagedConfirmationRevoke, args)
			if response.Code != http.StatusOK {
				t.Fatalf("MCP status=%d body=%s", response.Code, response.Body.String())
			}
			if authority.call != "" {
				t.Fatalf("unbounded arguments reached the authority runtime: call=%q", authority.call)
			}
			var envelope mcpAuthorityEnvelope
			if err := json.Unmarshal([]byte(response.Body.String()), &envelope); err != nil {
				t.Fatalf("did not decode: %v", err)
			}
			if envelope.Error == nil || envelope.Error.Code != -32602 {
				t.Fatalf("expected -32602 invalid-arguments, got: %s", response.Body.String())
			}
		})
	}
	// A well-formed call against the same tool still reaches the runtime, so the
	// rejection above is a schema gate and not a broad unavailability.
	harness, authority, handler := newAuthorityHarness(t)
	authority.authorityResult = workspacerepository.AuthorityResult{CommandID: "cmd_x", Operation: "REVOKE_MANAGED_CONFIRMATION", ResultID: "res_x", ResultHash: harness.hash}
	response := harness.mcpAuthorityCall(t, handler, mcpToolManagedConfirmationRevoke, arguments)
	if response.Code != http.StatusOK || authority.call != "revoke_confirmation" {
		t.Fatalf("well-formed call status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
}
