package question

// S3 card 2b: a successful knowvault_source_sql result is retained as the same
// run-scoped live read the governed live-data tool produces, so an answer that
// cites it through submit_answer live_reads passes verification, while a forged
// or foreign receipt is rejected.

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const testSourceSQLRunID = "qrun_current"

func testSourceSQLDigest(columns []string, rows [][]*string) string {
	raw, err := canon.CanonicalJSON(struct {
		Format   string      `json:"format"`
		Columns  []string    `json:"columns"`
		RowCount int         `json:"row_count"`
		Rows     [][]*string `json:"rows"`
	}{"postgres-text-table-v1", columns, len(rows), rows})
	if err != nil {
		return ""
	}
	return canon.Hash(raw)
}

// testSourceSQLToolResult renders the exact JSON projection the workspace API
// emits for a successful knowvault_source_sql call.
func testSourceSQLToolResult(t *testing.T, attemptID, sourceID, resultDigest string) workspacetools.Result {
	t.Helper()
	value := "42"
	projection := map[string]any{
		"format":                  "postgres-text-table-v1",
		"columns":                 []string{"contract_count"},
		"rows":                    [][]*string{{&value}},
		"row_count":               1,
		"attempt_id":              attemptID,
		"sql_hash":                "sha256:" + strings.Repeat("a", 64),
		"result_digest":           resultDigest,
		"database_identity":       "pgdb:alpha",
		"source_id":               sourceID,
		"exposed_schema_revision": 7,
		"execution_started_at":    time.Now().UTC().Add(-2 * time.Second).Format(time.RFC3339Nano),
		"execution_completed_at":  time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano),
		"complete":                true,
	}
	raw, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	return workspacetools.Result{Text: string(raw), Structured: raw}
}

func testSourceSQLCanonicalResult(t *testing.T) workspacetools.Result {
	t.Helper()
	value := "42"
	digest := testSourceSQLDigest([]string{"contract_count"}, [][]*string{{&value}})
	return testSourceSQLToolResult(t, "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", digest)
}

func TestSourceSQLResultIsRetainedAsLiveRead(t *testing.T) {
	retained, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, testSourceSQLCanonicalResult(t), 1<<20)
	if !ok || execution == nil || retained.IsError {
		t.Fatalf("retain ok=%v execution=%#v result=%+v", ok, execution, retained)
	}
	projection := execution.projection
	if projection.SourceID != "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ" || projection.ReceiptDigest == "" ||
		!projection.Complete || projection.ReadWindow != (liveDataReadWindow{Offset: 0, Limit: 1, ReturnedRows: 1, TotalRows: 1, Complete: true}) {
		t.Fatalf("retained projection = %#v", projection)
	}
	if !execution.dependency.validForRun(testSourceSQLRunID) || execution.dependency.connectionID != projection.SourceID {
		t.Fatalf("retained dependency = %#v", execution.dependency)
	}
	recomputed, err := liveDataReceiptDigest(testSourceSQLRunID, projection)
	if err != nil || recomputed != projection.ReceiptDigest {
		t.Fatalf("receipt digest = %q err=%v, want %q", recomputed, err, projection.ReceiptDigest)
	}

	// The model-facing result now carries the receipt and the live read window.
	var wire map[string]any
	if err := json.Unmarshal(retained.Structured, &wire); err != nil {
		t.Fatalf("model-facing projection did not decode: %v", err)
	}
	if wire["receipt_digest"] != projection.ReceiptDigest || wire["source_id"] != projection.SourceID {
		t.Fatalf("model-facing projection = %#v", wire)
	}

	// The answer binds it through the shared live-read reference check, and the
	// server-owned answer result is a LIVE_TABLE bound to the source.
	reference := toolLiveReadReference{ResultID: projection.AttemptID, ReceiptDigest: projection.ReceiptDigest}
	bound, ordinals, boundOK := bindToolLiveReadReferences(testSourceSQLRunID, []toolLiveReadReference{reference}, []liveDataExecution{*execution})
	if !boundOK || len(bound) != 1 || len(ordinals) != 1 || ordinals[0] != 1 {
		t.Fatalf("bound = %#v ordinals = %v ok=%v", bound, ordinals, boundOK)
	}
	answerResult, err := liveDataAnswerResults(testSourceSQLRunID, []liveDataExecution{*execution})
	if err != nil || answerResult.Kind != "LIVE_TABLE" || answerResult.SourceID != projection.SourceID ||
		answerResult.ResultDigest != projection.ResultDigest {
		t.Fatalf("answer result = %#v err=%v", answerResult, err)
	}
}

func TestSourceSQLResultForgedOrForeignReceiptIsRejected(t *testing.T) {
	_, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, testSourceSQLCanonicalResult(t), 1<<20)
	if !ok || execution == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	projection := execution.projection

	for name, reference := range map[string]toolLiveReadReference{
		"forged receipt":  {ResultID: projection.AttemptID, ReceiptDigest: "sha256:" + strings.Repeat("c", 64)},
		"foreign attempt": {ResultID: "gqat_01H9ABCDEFGHJKMNPQRSTVWX0", ReceiptDigest: projection.ReceiptDigest},
	} {
		if _, _, bound := bindToolLiveReadReferences(testSourceSQLRunID, []toolLiveReadReference{reference}, []liveDataExecution{*execution}); bound {
			t.Fatalf("%s was accepted", name)
		}
	}

	// A different run's receipt is also refused: the digest is run-scoped.
	otherRun, err := liveDataReceiptDigest("qrun_other", projection)
	if err == nil && otherRun == projection.ReceiptDigest {
		t.Fatal("the receipt digest is not bound to its question run")
	}
	if _, _, bound := bindToolLiveReadReferences("qrun_other", []toolLiveReadReference{
		{ResultID: projection.AttemptID, ReceiptDigest: projection.ReceiptDigest},
	}, []liveDataExecution{*execution}); bound {
		t.Fatal("a foreign run's receipt was accepted")
	}
}

func TestSourceSQLResultAlteredDigestIsRefused(t *testing.T) {
	// The rows say 42 but the digest covers 43: an unauthenticated result must
	// never become evidence.
	altered := testSourceSQLToolResult(t, "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
		testSourceSQLDigest([]string{"contract_count"}, [][]*string{{strPtr("43")}}))
	result, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, altered, 1<<20)
	if ok || execution != nil || !result.IsError || !strings.Contains(result.Text, "SOURCE_SQL_UNAVAILABLE") {
		t.Fatalf("altered digest result = %+v execution=%#v ok=%v", result, execution, ok)
	}
}

func TestSourceSQLResultWithoutSourceBindingIsRefused(t *testing.T) {
	value := "42"
	digest := testSourceSQLDigest([]string{"contract_count"}, [][]*string{{&value}})
	withoutSource := testSourceSQLToolResult(t, "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ", "", digest)
	result, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, withoutSource, 1<<20)
	if ok || execution != nil || !result.IsError {
		t.Fatalf("unbound result = %+v execution=%#v ok=%v", result, execution, ok)
	}
}

func TestSourceSQLReceiptDigestBindsTheSource(t *testing.T) {
	_, first, ok := sourceSQLRetainResult(testSourceSQLRunID, testSourceSQLCanonicalResult(t), 1<<20)
	if !ok || first == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	other := first.projection
	other.SourceID = "conn_01H9ABCDEFGHJKMNPQRSTVWXZ"
	other.ReceiptDigest = ""
	otherReceipt, err := liveDataReceiptDigest(testSourceSQLRunID, other)
	if err != nil || otherReceipt == first.projection.ReceiptDigest {
		t.Fatalf("two sources produced the same receipt digest: %q vs %q err=%v",
			otherReceipt, first.projection.ReceiptDigest, err)
	}
}

func TestSourceSQLRetainedResultBindsGovernedTrace(t *testing.T) {
	retained, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, testSourceSQLCanonicalResult(t), 1<<20)
	if !ok || execution == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	record := &ToolLoopRecord{
		Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: len(retained.Structured) + 1},
		Calls: []ToolCallRecord{{
			ID: "call-sql", Name: sourceSQLToolName, Outcome: "SUCCEEDED", Result: retained,
		}},
	}
	executions, successful, valid := governedQueryToolExecutions(testSourceSQLRunID, []governedQueryDependency{execution.dependency}, record)
	if !valid || !successful || len(executions) != 1 || executions[0].projection.ReceiptDigest != execution.projection.ReceiptDigest {
		t.Fatalf("governed executions = %#v successful=%v valid=%v", executions, successful, valid)
	}
}

func strPtr(value string) *string { return &value }

func TestSourceSQLStructuredAnswerRoundTrips(t *testing.T) {
	retained, execution, ok := sourceSQLRetainResult(testSourceSQLRunID, testSourceSQLCanonicalResult(t), 1<<20)
	if !ok || execution == nil {
		t.Fatal("the canonical SQL result was not retained")
	}
	const claimText = "The registered contracts table holds 42 rows."
	call := modelgateway.ToolCall{ID: "submit-1", Type: "function"}
	call.Function.Name = submitAnswerToolName
	call.Function.Arguments = `{"no_data":false,"claims":[{"text":"` + claimText + `","live_reads":[{"result_id":"` +
		execution.projection.AttemptID + `","receipt_digest":"` + execution.projection.ReceiptDigest + `"}]}]}`
	record := &ToolLoopRecord{
		Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: len(retained.Structured) + 1},
		Calls:   []ToolCallRecord{{ID: "call-sql", Name: sourceSQLToolName, Outcome: "SUCCEEDED", Result: retained}},
		AllClaimsBound: true, ClaimEvidenceVersion: "v1", StopReason: "ANSWER",
		Messages: []modelgateway.Message{{Role: "assistant", ToolCalls: []modelgateway.ToolCall{call}}},
		ClaimEvidence: []ToolClaimEvidence{{
			TextHash: canon.Hash([]byte(claimText)),
			LiveReads: []toolLiveReadReference{{
				ResultID: execution.projection.AttemptID, ReceiptDigest: execution.projection.ReceiptDigest,
			}},
		}},
	}
	answerResult, err := liveDataAnswerResults(testSourceSQLRunID, []liveDataExecution{*execution})
	if err != nil {
		t.Fatalf("answer result: %v", err)
	}
	raw, err := marshalStructuredAnswerWithDependencyList(testSourceSQLRunID, canon.Hash([]byte(claimText)),
		nil, answerResult, nil, nil, []governedQueryDependency{execution.dependency}, record)
	if err != nil {
		t.Fatalf("marshal structured answer: %v", err)
	}
	decoded, err := decodeStructuredAnswer(testSourceSQLRunID, raw)
	if err != nil {
		t.Fatalf("the SQL live-read answer did not decode: %v (%s)", err, CodeOf(err))
	}
	if decoded.AnswerResult == nil || decoded.AnswerResult.SourceID != execution.projection.SourceID {
		t.Fatalf("decoded answer result = %#v", decoded.AnswerResult)
	}
	if !validateToolLoopClaimEvidence(testSourceSQLRunID, claimText+" [Live result 1]", decoded.ToolLoop, decoded.governedQueryDependencies, nil) {
		t.Fatal("the rendered SQL live-read answer markdown did not validate")
	}
}
