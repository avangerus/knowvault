package workspaceapi

// R3a-1 Outcome 3 external-agent authorization negative controls.
//
// The streamable-HTTP MCP endpoint is the one surface an external agent reaches
// with its own credential. This file proves the two authorization refusals the
// release names as negative controls, both through the real in-process
// /api/v1/mcp handler and the existing httpauth / access-code wiring:
//
//   - an expired bearer session and a foreign (non-accepted tenant) session get
//     the documented 401 UNAUTHENTICATED with a body that carries no tool name,
//     schema or list content at all: httpauth rejects before the MCP method is
//     ever dispatched;
//   - a SERVICE (agent access-code) principal scoped to ws_alpha is refused a
//     knowledge tool call against ws_foreign with the existing content-free
//     JSON-RPC -32004, while the same principal's tools/list still advertises
//     the knowledge tools of its own workspace, and an administrative tool call
//     is refused -32601 and journaled through the access-code authority with a
//     closed reason class (the R1 denial mechanism).
//
// No production semantics are added: the tests assert the existing refusal,
// audit and no-oracle behaviour. The workspace-membership decision a real
// deployment makes in the source/evidence repositories is modelled by a
// test-local SourceService wrapper that returns the production typed
// workspacerepository denial for the non-member workspace.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
	identityrepository "knowvault.local/verified-workspace/internal/identity/repository"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/serviceprincipal"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// expiredSessionResolver models the identity repository's own refusal to resolve
// a session whose durable expiry has passed. It builds the expired claims and
// rejects exactly where the repository would, so the request reaches the real
// httpauth.Authenticate path and fails there rather than at a pre-seeded spy.
type expiredSessionResolver struct{}

func (expiredSessionResolver) ResolveSession(context.Context, identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	claims, err := identity.NewClaims("org_alpha", "usr_expired", 1, "idp_alpha", 1, time.Now().UTC().Add(-time.Minute))
	if err != nil {
		return identityrepository.AuthenticatedSession{}, err
	}
	if !claims.ExpiresAt().After(time.Now().UTC()) {
		return identityrepository.AuthenticatedSession{}, errors.New("identity session expired")
	}
	return identityrepository.AuthenticatedSession{}, errors.New("identity session unexpectedly live")
}

// foreignSessionResolver returns a resolved session for a different tenant than
// the one the deployment trusts, so httpauth's own tenant/principal cross-check
// refuses it: the documented authorization error for a foreign (non-accepted
// issuer/audience) token.
type foreignSessionResolver struct{}

func (foreignSessionResolver) ResolveSession(context.Context, identityrepository.ResolveSessionRequest) (identityrepository.AuthenticatedSession, error) {
	claims, err := identity.NewClaims("org_foreign", "usr_foreign", 1, "idp_foreign", 1, time.Now().UTC().Add(time.Hour))
	if err != nil {
		return identityrepository.AuthenticatedSession{}, err
	}
	return identityrepository.AuthenticatedSession{
		SessionID: "ses_foreign",
		Claims:    claims,
		Access:    database.AccessContext{OrganizationID: "org_foreign", PrincipalID: "usr_foreign", RequestID: "req_server_001"},
	}, nil
}

// newRejectedAuthHarness re-wires the shared test harness onto a real
// httpauth.Authenticator with the given session resolver, so the MCP endpoint's
// own authentication step is what rejects the token.
func newRejectedAuthHarness(t *testing.T, resolver httpauth.SessionResolver) *testHarness {
	t.Helper()
	harness := newTestHarness(t)
	authenticator, err := httpauth.New(testTenantResolver{digestor: &testDigestor{}}, resolver)
	if err != nil {
		t.Fatalf("httpauth.New: %v", err)
	}
	spy := &authSpy{delegate: authenticator}
	harness.auth = spy
	harness.handler.authenticator = spy
	return harness
}

// bearerMCPRequest is the explicit non-browser bearer transport: exactly one
// Authorization header and no cookie or Origin, the shape httpauth's
// exactSessionCredential accepts alongside the browser cookie.
func bearerMCPRequest(method, path, body, token string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example"+path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", jsonContentType)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	return request
}

// serviceBearerRequest is the V1-C agent access-code transport: the same
// non-browser Bearer form, carrying a kva_ code the MCP endpoint's separate
// access-code authenticator resolves to a SERVICE principal.
func serviceBearerRequest(method, path, body, code string) *http.Request {
	request := httptest.NewRequest(method, "https://workspace.example"+path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", jsonContentType)
	}
	request.Header.Set("Authorization", "Bearer "+code)
	return request
}

func assertMCPAuthorizationRejected(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want %d body=%s", response.Code, http.StatusUnauthorized, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "UNAUTHENTICATED") {
		t.Fatalf("body missing the documented UNAUTHENTICATED error: %s", response.Body.String())
	}
	for _, leaked := range []string{"knowvault_", "inputSchema", `"tools"`, "result"} {
		if strings.Contains(response.Body.String(), leaked) {
			t.Fatalf("rejected token disclosed %q: %s", leaked, response.Body.String())
		}
	}
}

// TestMCPExternalAuthorizationRejectsExpiredAndForeignTokens proves the
// documented outcome of Outcome 3's first negative control: a token the
// deployment cannot accept never reaches tools/list, so the response is the
// existing 401 UNAUTHENTICATED and carries no tool name, schema or list
// content.
func TestMCPExternalAuthorizationRejectsExpiredAndForeignTokens(t *testing.T) {
	for name, resolver := range map[string]httpauth.SessionResolver{
		"expired_session": expiredSessionResolver{},
		"foreign_tenant":  foreignSessionResolver{},
	} {
		name, resolver := name, resolver
		t.Run(name, func(t *testing.T) {
			harness := newRejectedAuthHarness(t, resolver)
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, bearerMCPRequest(http.MethodPost, apiPrefix+"/mcp",
				`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, testOpaqueToken(name)))
			assertMCPAuthorizationRejected(t, response)
			if harness.auth.authenticateCalls != 1 {
				t.Fatalf("authentication attempts=%d want 1", harness.auth.authenticateCalls)
			}
		})
	}
}

// recordedAgentDenial is one content-free refused agent call passed to the
// access-code authority's audit hook: the workspace the agent named and one
// closed reason code.
type recordedAgentDenial struct {
	workspaceID string
	reasonCode  string
}

// staticAccessCodeService is a stateful stand-in for the V1-C access-code
// authority: Authenticate resolves an accepted code to the configured SERVICE
// principal, and AuditDeniedAgentCall records the R1 denial the way the real
// authority does (workspace id and reason class, never arguments or code).
type staticAccessCodeService struct {
	access      database.AccessContext
	authErr     error
	deniedCalls []recordedAgentDenial
}

func (service *staticAccessCodeService) Authenticate(context.Context, string, string, string) (database.AccessContext, error) {
	return service.access, service.authErr
}

func (service *staticAccessCodeService) Issue(context.Context, database.AccessContext, serviceprincipal.IssueRequest) (serviceprincipal.IssueResult, error) {
	return serviceprincipal.IssueResult{}, nil
}

func (service *staticAccessCodeService) List(context.Context, database.AccessContext, string) ([]serviceprincipal.Credential, error) {
	return nil, nil
}

func (service *staticAccessCodeService) Revoke(context.Context, database.AccessContext, string) error {
	return nil
}

func (service *staticAccessCodeService) AuditDeniedAgentCall(_ context.Context, _ database.AccessContext, workspaceID, reasonCode string) {
	service.deniedCalls = append(service.deniedCalls, recordedAgentDenial{workspaceID: workspaceID, reasonCode: reasonCode})
}

// memberScopedSourceService models the workspace-membership decision the
// production source facade makes in the repository: a principal may read the
// inventory of its own workspace, and any other workspace answers the single
// typed workspacerepository denial a non-member sees.
type memberScopedSourceService struct {
	*fakeSourceService
	memberWorkspaceID    string
	requestedWorkspaceID string
}

func (service *memberScopedSourceService) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	service.requestedWorkspaceID = workspaceID
	if workspaceID != service.memberWorkspaceID {
		service.call = "list_sources"
		service.access = access
		return nil, workspacerepository.NewError(workspacerepository.CodeNotFound, errors.New("principal is not a member of the requested workspace"))
	}
	return service.fakeSourceService.ListSources(ctx, access, workspaceID)
}

// newServicePrincipalHarness wires the shared harness with the V1-C access-code
// authority and a member-scoped source service, so a Bearer kva_ code is
// resolved to a SERVICE principal scoped to memberWorkspaceID.
func newServicePrincipalHarness(t *testing.T, memberWorkspaceID string) (*testHarness, *memberScopedSourceService, *staticAccessCodeService) {
	t.Helper()
	harness := newTestHarness(t)
	codes := &staticAccessCodeService{access: database.AccessContext{
		OrganizationID: "org_alpha", PrincipalID: "svcp_agent", RequestID: "req_server_001",
		ActorKind: database.ActorKindService,
	}}
	harness.handler.accessCodes = codes
	harness.handler.organizationID = "org_alpha"
	sources := &memberScopedSourceService{fakeSourceService: harness.sources, memberWorkspaceID: memberWorkspaceID}
	harness.handler.sources = sources
	return harness, sources, codes
}

// testServiceAccessCode builds one canonically-shaped kva_ access code: the same
// prefix, raw byte length and RawURL base64 alphabet ValidCodeShape enforces.
func testServiceAccessCode(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	return serviceprincipal.CodePrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// mcpListToolNames decodes the advertised names of one tools/list response.
func mcpListToolNames(t *testing.T, body string) []string {
	t.Helper()
	var list struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
		Error *mcpErrorBody `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &list); err != nil || list.Error != nil {
		t.Fatalf("tools/list did not decode: err=%v error=%#v body=%s", err, list.Error, body)
	}
	names := make([]string, 0, len(list.Result.Tools))
	for _, tool := range list.Result.Tools {
		names = append(names, tool.Name)
	}
	return names
}

// TestMCPExternalAuthorizationServicePrincipalCrossWorkspaceDenial proves
// Outcome 3's service-principal negative control: an agent scoped to ws_alpha
// still sees the knowledge tools on tools/list, is refused knowvault_sources
// against ws_foreign with the existing content-free -32004 and no workspace
// echo, and succeeds on its own workspace.
func TestMCPExternalAuthorizationServicePrincipalCrossWorkspaceDenial(t *testing.T) {
	harness, sources, _ := newServicePrincipalHarness(t, "ws_alpha")
	code := testServiceAccessCode(t)

	listResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(listResponse, serviceBearerRequest(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`, code))
	if listResponse.Code != http.StatusOK {
		t.Fatalf("tools/list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	advertised := make(map[string]bool)
	for _, name := range mcpListToolNames(t, listResponse.Body.String()) {
		advertised[name] = true
	}
	for _, wanted := range []string{mcpToolSourcesList, mcpToolWorkspaceList, mcpToolEvidenceRead, mcpToolRefresh} {
		if !advertised[wanted] {
			t.Fatalf("tools/list omitted %q for a SERVICE principal: %v", wanted, mcpListToolNames(t, listResponse.Body.String()))
		}
	}

	denied := httptest.NewRecorder()
	harness.handler.ServeHTTP(denied, serviceBearerRequest(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_foreign"}}}`, code))
	if denied.Code != http.StatusOK {
		t.Fatalf("cross-workspace call transport status=%d body=%s", denied.Code, denied.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(denied.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("cross-workspace denial did not decode: %v: %s", err, denied.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32004 || outcome.Error.Message != "source scope not found" {
		t.Fatalf("cross-workspace denial error=%#v body=%s", outcome.Error, denied.Body.String())
	}
	if outcome.Result != nil {
		t.Fatalf("cross-workspace denial carried a result: %s", denied.Body.String())
	}
	for _, leaked := range []string{"ws_foreign", "structuredContent", `"sources"`} {
		if strings.Contains(denied.Body.String(), leaked) {
			t.Fatalf("cross-workspace denial leaked %q: %s", leaked, denied.Body.String())
		}
	}
	if sources.requestedWorkspaceID != "ws_foreign" {
		t.Fatalf("denial did not reach the source read for ws_foreign: %q", sources.requestedWorkspaceID)
	}

	own := httptest.NewRecorder()
	harness.handler.ServeHTTP(own, serviceBearerRequest(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+mcpToolSourcesList+`","arguments":{"workspace_id":"ws_alpha"}}}`, code))
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), "structuredContent") {
		t.Fatalf("member workspace call status=%d body=%s", own.Code, own.Body.String())
	}
	if sources.call != "list_sources" {
		t.Fatalf("member workspace call did not reach the SourceService read: call=%q", sources.call)
	}
}

// TestMCPExternalAuthorizationServicePrincipalAdministrativeDenialIsAudited
// proves the R1 denial mechanism the negative controls rely on stays in place: a
// SERVICE principal asking for an administrative tool is refused -32601 and the
// refusal is journaled through the access-code authority with its closed reason
// class, never the arguments.
func TestMCPExternalAuthorizationServicePrincipalAdministrativeDenialIsAudited(t *testing.T) {
	harness, _, codes := newServicePrincipalHarness(t, "ws_alpha")
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, serviceBearerRequest(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"knowvault_conversation_archive","arguments":{"workspace_id":"ws_alpha","conversation_id":"conv_01H9ABCDEFGHJKMNPQRSTVWXYZ"}}}`, testServiceAccessCode(t)))
	if response.Code != http.StatusOK {
		t.Fatalf("administrative denial transport status=%d body=%s", response.Code, response.Body.String())
	}
	var outcome mcpToolCallOutcome
	if err := json.Unmarshal(response.Body.Bytes(), &outcome); err != nil {
		t.Fatalf("administrative denial did not decode: %v: %s", err, response.Body.String())
	}
	if outcome.Error == nil || outcome.Error.Code != -32601 {
		t.Fatalf("administrative tool was not refused as method-not-found: %s", response.Body.String())
	}
	if len(codes.deniedCalls) != 1 {
		t.Fatalf("denied agent call not journaled: %#v", codes.deniedCalls)
	}
	if codes.deniedCalls[0].reasonCode != "MCP_TOOL_NOT_PERMITTED_FOR_SERVICE" {
		t.Fatalf("denied agent call reason=%q want %q", codes.deniedCalls[0].reasonCode, "MCP_TOOL_NOT_PERMITTED_FOR_SERVICE")
	}
}
