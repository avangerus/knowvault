package workspaceapi

// Unit coverage for the ADR-0087 §2 MCP tool (knowvault_verify_connection_trust):
// it reaches the same injected ConnectionTrustAuthority runtime as the REST
// action and maps the same content-free error surface onto MCP error codes.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

type mcpVerifyTrustResultBody struct {
	ResultID   string `json:"result_id"`
	ResultHash string `json:"result_hash"`
}

type mcpVerifyTrustEnvelope struct {
	Result struct {
		Structured mcpVerifyTrustResultBody `json:"structuredContent"`
		IsError    bool                     `json:"isError"`
	} `json:"result"`
	Error *mcpErrorBody `json:"error"`
}

func TestMCPVerifyConnectionTrustDispatchesToRepository(t *testing.T) {
	harness, authority, handler := newConnectionTrustHarness(t)
	authority.result = workspacerepository.VerifyConnectionTrustResult{ResultID: "wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ", ResultHash: harness.hash}

	response := harness.mcpAuthorityCall(t, handler, mcpToolVerifyConnectionTrust,
		`{"connection_id":"`+testConnectionID+`","attested_connector_identity":"folder-connector-1","attested_by":"security-team","attested_at":"2026-09-06T12:00:00Z"}`)
	if response.Code != http.StatusOK || authority.call != "verify_trust" {
		t.Fatalf("status=%d call=%q body=%s", response.Code, authority.call, response.Body.String())
	}
	var envelope mcpVerifyTrustEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error != nil || envelope.Result.IsError {
		t.Fatalf("mcp verify-trust envelope: err=%v error=%#v body=%s", err, envelope.Error, response.Body.String())
	}
	if envelope.Result.Structured.ResultID != "wctv_01H9ABCDEFGHJKMNPQRSTVWXYZ" {
		t.Fatalf("result not projected: %#v", envelope.Result.Structured)
	}
	if authority.request.ConnectionID != testConnectionID || authority.request.AttestedBy != "security-team" {
		t.Fatalf("verify-trust arguments not projected: %#v", authority.request)
	}
}

func TestMCPVerifyConnectionTrustDeniedAndNotFoundCollapseToSameError(t *testing.T) {
	var deniedError, notFoundError *mcpErrorBody
	for _, code := range []workspacerepository.ErrorCode{workspacerepository.CodeConnectionTrustDenied, workspacerepository.CodeConnectionTrustNotFound} {
		harness, authority, handler := newConnectionTrustHarness(t)
		authority.err = workspacerepository.NewError(code, nil)
		response := harness.mcpAuthorityCall(t, handler, mcpToolVerifyConnectionTrust,
			`{"connection_id":"`+testConnectionID+`","attested_connector_identity":"folder-connector-1","attested_by":"security-team","attested_at":"2026-09-06T12:00:00Z"}`)
		var envelope mcpVerifyTrustEnvelope
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error == nil {
			t.Fatalf("code=%s expected mcp error, body=%s", code, response.Body.String())
		}
		if code == workspacerepository.CodeConnectionTrustDenied {
			deniedError = envelope.Error
		} else {
			notFoundError = envelope.Error
		}
	}
	if *deniedError != *notFoundError {
		t.Fatalf("denied and absent are distinguishable over MCP: denied=%#v absent=%#v", deniedError, notFoundError)
	}
}

func TestMCPVerifyConnectionTrustRequiresIdempotencyKey(t *testing.T) {
	harness, authority, handler := newConnectionTrustHarness(t)
	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"auth1","method":"tools/call","params":{"name":"`+mcpToolVerifyConnectionTrust+`","arguments":{"connection_id":"`+testConnectionID+`","attested_connector_identity":"x","attested_by":"y","attested_at":"2026-09-06T12:00:00Z"}}}`)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var envelope mcpVerifyTrustEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil || envelope.Error == nil || envelope.Error.Code != -32001 {
		t.Fatalf("expected idempotency-key error, body=%s", response.Body.String())
	}
	if authority.call != "" {
		t.Fatalf("repository called without idempotency key: %q", authority.call)
	}
}
