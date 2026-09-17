package workspaceapi

// R2 Outcome 3 transport negative control: the unified AnswerResult must reach
// REST and MCP as the SAME projection, and completeness must never be upgraded.
// The existing internal/question tests marshal the struct in isolation; these
// tests drive the real REST question route (questionCreate -> writeJSON) and the
// real MCP question tool (mcpToolQuestion -> structuredContent) through the
// composed handler, so the surface seam itself is what is under test.
//
// A PARTIAL structured execution stays PARTIAL on both transports, both
// projections are deeply equal, and a legacy run that omits the unified fields
// is not invented into COMPLETE or any other fabricated value.

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/question"
)

const answerResultRunID = "qrun_01ARZ3NDEKTSV4RRFFQ69G5FAV"

const answerResultDigest = "sha256:3f3a2c1b0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a"

// questionRunWithAnswerResult returns the shared run fixture every subtest
// transports. The AnswerResult pointer is exactly what the fake authority hands
// both surfaces, so a missing projection on either route fails the deep-equality
// assertion rather than a string match on one transport.
func questionRunWithAnswerResult(answer *question.AnswerResult) question.Run {
	run := question.Run{}
	run.ID = answerResultRunID
	run.WorkspaceID = "ws_alpha"
	run.Question = "How many?"
	run.AnswerMode = "EXTRACTIVE"
	run.VerificationMethod = "BYTE_EXACT_CITATION"
	run.ResultStatus = "COMPLETED"
	run.Citations = []question.Citation{}
	run.Uncertainties = []question.Uncertainty{}
	run.Conflicts = []question.Conflict{}
	run.AnswerResult = answer
	return run
}

// callRESTQuestion issues a question through the REST route and returns the
// decoded run projection.
func callRESTQuestion(t *testing.T, harness *testHarness) map[string]any {
	t.Helper()
	request := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || harness.questions.call != "create" {
		t.Fatalf("REST question status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}
	return decodeJSONObject(t, response.Body.String())
}

// callMCPQuestion issues the equivalent question through the MCP question tool
// and returns the decoded structuredContent projection.
func callMCPQuestion(t *testing.T, harness *testHarness) map[string]any {
	t.Helper()
	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ar1","method":"tools/call","params":{"name":"knowvault_question","arguments":{"workspace_id":"ws_alpha","question":"How many?"}}}`)
	request.Header.Set("Idempotency-Key", harness.idempotencyKey)
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("MCP question status=%d call=%q body=%s", response.Code, harness.questions.call, response.Body.String())
	}
	return decodeMCPResultStructured(t, response.Body.String())
}

func answerResultObject(t *testing.T, projection map[string]any, surface string) map[string]any {
	t.Helper()
	raw, ok := projection["answer_result"]
	if !ok {
		t.Fatalf("%s omitted answer_result: %#v", surface, projection)
	}
	object, ok := raw.(map[string]any)
	if !ok {
		t.Fatalf("%s answer_result is not an object: %#v", surface, raw)
	}
	return object
}

// TestAnswerResultPartialCompletenessIsIdenticalOnRESTAndMCP is Outcome 3's
// transport negative control: a PARTIAL structured execution is reported PARTIAL
// (never COMPLETE) on the REST question route and the MCP question tool, and the
// two surfaces present the very same AnswerResult projection.
func TestAnswerResultPartialCompletenessIsIdenticalOnRESTAndMCP(t *testing.T) {
	harness := newTestHarness(t)
	answer := &question.AnswerResult{}
	answer.Kind = "CALCULATION"
	answer.Operation = "COUNT"
	answer.Rule = "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a"
	answer.Value = "3"
	answer.Unit = "\u0448\u0442"
	answer.Completeness = "PARTIAL"
	answer.RunID = answerResultRunID
	answer.MetricVersion = "2"
	answer.SnapshotID = "scope-fleet"
	answer.ExecutionID = "exec_01H9ABCDEFGHJKMNPQRSTVWXYZ"
	answer.ResultDigest = answerResultDigest
	answer.Snapshot.ID = "scope-fleet"
	answer.Snapshot.RowCount = 7
	answer.EvidenceRefs = []string{"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"}
	answer.AuditReceipt = []string{"admission_01H9ABCDEFGHJKMNPQRSTVWXYZ", "outcome_01H9ABCDEFGHJKMNPQRSTVWXYZ"}
	harness.questions.run = questionRunWithAnswerResult(answer)

	restResponse := httptest.NewRecorder()
	restRequest := harness.request(http.MethodPost, workspacesPath+"/ws_alpha/questions", `{"question":"How many?"}`)
	restRequest.Header.Set("Idempotency-Key", harness.idempotencyKey)
	harness.handler.ServeHTTP(restResponse, restRequest)
	if restResponse.Code != http.StatusOK || harness.questions.call != "create" {
		t.Fatalf("REST question status=%d call=%q body=%s", restResponse.Code, harness.questions.call, restResponse.Body.String())
	}
	rest := decodeJSONObject(t, restResponse.Body.String())
	restResult := answerResultObject(t, rest, "REST")
	if got := restResult["completeness"]; got != "PARTIAL" {
		t.Fatalf("REST completeness=%#v, want PARTIAL: %#v", got, restResult)
	}
	if strings.Contains(restResponse.Body.String(), `"completeness":"COMPLETE"`) {
		t.Fatalf("REST upgraded a PARTIAL answer to COMPLETE: %s", restResponse.Body.String())
	}

	harness.questions.call = ""
	mcpResponse := httptest.NewRecorder()
	mcpRequest := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"ar1","method":"tools/call","params":{"name":"knowvault_question","arguments":{"workspace_id":"ws_alpha","question":"How many?"}}}`)
	mcpRequest.Header.Set("Idempotency-Key", harness.idempotencyKey)
	harness.handler.ServeHTTP(mcpResponse, mcpRequest)
	if mcpResponse.Code != http.StatusOK {
		t.Fatalf("MCP question status=%d call=%q body=%s", mcpResponse.Code, harness.questions.call, mcpResponse.Body.String())
	}
	mcp := decodeMCPResultStructured(t, mcpResponse.Body.String())
	mcpResult := answerResultObject(t, mcp, "MCP")
	if got := mcpResult["completeness"]; got != "PARTIAL" {
		t.Fatalf("MCP completeness=%#v, want PARTIAL: %#v", got, mcpResult)
	}
	if strings.Contains(mcpResponse.Body.String(), `"completeness":"COMPLETE"`) {
		t.Fatalf("MCP upgraded a PARTIAL answer to COMPLETE: %s", mcpResponse.Body.String())
	}

	if !reflect.DeepEqual(restResult, mcpResult) {
		t.Fatalf("REST answer_result != MCP structuredContent answer_result\nREST: %#v\nMCP:  %#v", restResult, mcpResult)
	}
	if !reflect.DeepEqual(rest, mcp) {
		t.Fatalf("REST run projection != MCP structuredContent projection\nREST: %#v\nMCP:  %#v", rest, mcp)
	}
	// The unified R2 fields must survive both surfaces, not just completeness.
	for _, key := range []string{"run_id", "metric_version", "snapshot_id", "execution_id", "result_digest", "evidence_refs", "audit_receipt"} {
		if _, ok := restResult[key]; !ok {
			t.Fatalf("REST answer_result dropped unified field %q: %#v", key, restResult)
		}
		if _, ok := mcpResult[key]; !ok {
			t.Fatalf("MCP answer_result dropped unified field %q: %#v", key, mcpResult)
		}
	}
	if got := restResult["result_digest"]; got != answerResultDigest {
		t.Fatalf("REST result_digest=%#v, want %q", got, answerResultDigest)
	}
}

// TestAnswerResultMissingCompletenessIsNotInventedOnRESTOrMCP proves a legacy
// answer artifact is never upgraded at the transport surface: when the
// authority holds no AnswerResult at all both routes omit the member, and when
// the AnswerResult carries an empty completeness it stays empty on both routes
// rather than being filled with COMPLETE.
func TestAnswerResultMissingCompletenessIsNotInventedOnRESTOrMCP(t *testing.T) {
	t.Run("no answer result", func(t *testing.T) {
		harness := newTestHarness(t)
		harness.questions.run = questionRunWithAnswerResult(nil)

		rest := callRESTQuestion(t, harness)
		if _, ok := rest["answer_result"]; ok {
			t.Fatalf("REST invented answer_result for a legacy run: %#v", rest["answer_result"])
		}
		harness.questions.call = ""
		mcp := callMCPQuestion(t, harness)
		if _, ok := mcp["answer_result"]; ok {
			t.Fatalf("MCP invented answer_result for a legacy run: %#v", mcp["answer_result"])
		}
		if !reflect.DeepEqual(rest, mcp) {
			t.Fatalf("legacy REST projection != MCP projection\nREST: %#v\nMCP:  %#v", rest, mcp)
		}
	})

	t.Run("empty completeness", func(t *testing.T) {
		harness := newTestHarness(t)
		answer := &question.AnswerResult{}
		answer.Kind = "CALCULATION"
		answer.Operation = "COUNT"
		answer.Rule = "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e \u0441\u0442\u0440\u043e\u043a"
		answer.Value = "3"
		harness.questions.run = questionRunWithAnswerResult(answer)

		rest := callRESTQuestion(t, harness)
		restResult := answerResultObject(t, rest, "REST")
		if got := restResult["completeness"]; got != nil && got != "" {
			t.Fatalf("REST invented completeness=%#v for a legacy answer: %#v", got, restResult)
		}
		harness.questions.call = ""
		mcp := callMCPQuestion(t, harness)
		mcpResult := answerResultObject(t, mcp, "MCP")
		if got := mcpResult["completeness"]; got != nil && got != "" {
			t.Fatalf("MCP invented completeness=%#v for a legacy answer: %#v", got, mcpResult)
		}
		if !reflect.DeepEqual(restResult, mcpResult) {
			t.Fatalf("legacy REST answer_result != MCP answer_result\nREST: %#v\nMCP:  %#v", restResult, mcpResult)
		}
	})
}
