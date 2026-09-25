package question

// source_sql_tool.go is ADR-0097's chat-run bound for the agent-authored SQL
// tool. knowvault_source_sql itself is advertised and dispatched through the
// shared workspace tool runtime, but the card's limit — at most three
// SUCCESSFUL statements per chat run — is a property of one question run, so it
// lives here beside the run-scoped live-data state rather than in the
// transport. A refusal (a closed error result) does not consume the budget: the
// agent may correct a statement and retry.

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"time"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// sourceSQLToolName is the registry name of ADR-0097's agent-authored SQL tool.
const sourceSQLToolName = "knowvault_source_sql"

// sourceSQLMaxSuccessfulCalls is the card's per-run bound. Card 2c tightened
// it from "successful statements" to "attempts that reached execution": a
// statement that ran in the customer database and then timed out, hit the row
// cap or hit the cost cap consumed the same resources as a successful one, so
// it consumes the budget too. A refusal that never reached execution (an
// invalid statement, a scope violation, an unconfigured source, a load-limit
// refusal) stays free so the agent can correct and retry. It is deliberately a
// server-owned constant: no request can widen it.
const sourceSQLMaxSuccessfulCalls = 3

// sourceSQLRunState is the run-local budget. It is retained beside
// liveDataRunState by executeToolLoop and is never persisted or shared between
// runs.
type sourceSQLRunState struct {
	successfulCalls int
}

// allow reports whether one more call may run.
func (state *sourceSQLRunState) allow() bool {
	return state != nil && state.successfulCalls < sourceSQLMaxSuccessfulCalls
}

// record consumes one unit of the budget for a call that reached execution. A
// successful result always counts; a closed refusal counts only when its code
// is one the execution path produced after the statement was sent to the
// database. A refusal that never executed does not consume the budget.
func (state *sourceSQLRunState) record(result workspacetools.Result) {
	if state == nil {
		return
	}
	if !result.IsError {
		state.successfulCalls++
		return
	}
	if sourceSQLReachedExecution(sourceSQLResultCode(result)) {
		state.successfulCalls++
	}
}

// sourceSQLReachedExecution reports whether a closed refusal code means the
// agent's statement reached the customer database. TIMEOUT, ROW_LIMIT and
// COST_LIMIT are the card's named cases; DATABASE_REJECTED covers a statement
// PostgreSQL itself refused (a revoked column, a function the role may not
// call) and is counted conservatively, because a resource limit must never
// under-count an attempt that could have run.
func sourceSQLReachedExecution(code string) bool {
	switch code {
	case "TIMEOUT", "ROW_LIMIT", "COST_LIMIT", "DATABASE_REJECTED", "SOURCE_SQL_RESULT_TOO_LARGE":
		return true
	default:
		return false
	}
}

// sourceSQLResultCode extracts the closed refusal code from a tool result. It
// returns the empty string for a success or a result that is not the closed
// refusal envelope.
func sourceSQLResultCode(result workspacetools.Result) string {
	payload := result.Structured
	if len(payload) == 0 {
		payload = []byte(result.Text)
	}
	var decoded struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}
	return decoded.Error
}

// refused renders the content-free refusal the fourth successful call receives.
func (state *sourceSQLRunState) refused() workspacetools.Result {
	return sourceSQLRefusal("SQL_LIMIT_REACHED")
}

func sourceSQLRefusal(code string) workspacetools.Result {
	payload := `{"error":"` + code + `","advice":"Finish the answer from the SQL results already returned."}`
	return workspacetools.Result{Text: payload, Structured: json.RawMessage(payload), IsError: true}
}

// sourceSQLRetainResult turns one successful knowvault_source_sql tool result
// into the same retained live execution the governed live-data tool produces,
// so a SQL answer cites it through the identical live_reads binding and the UI
// renders it as one LIVE_TABLE result. The provider's projection is already the
// content-free text table; this function adds only the run-scoped receipt
// digest that binds the exact attempt and source to this question run.
//
// It returns the model-facing result, the retained execution, and false when
// the provider's result cannot be authenticated as a complete text table. A
// result too large for the live-table projection is refused with the closed
// SOURCE_SQL_RESULT_TOO_LARGE code rather than silently dropped.
func sourceSQLRetainResult(questionRunID string, result workspacetools.Result, maxResultBytes int) (workspacetools.Result, *liveDataExecution, bool) {
	if len(result.Structured) == 0 || !json.Valid(result.Structured) {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	var projection liveDataProjection
	if err := jsonv2.Unmarshal(result.Structured, &projection,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	if projection.SourceID == "" || projection.ExposedSchemaRevision < 1 {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	// The governed SQL provider returns the complete text table; the live
	// projection's read window is the full result, exactly as the live-data
	// tool sets it.
	projection.ReadWindow = liveDataReadWindow{
		Offset: 0, Limit: projection.RowCount, ReturnedRows: projection.RowCount,
		TotalRows: projection.RowCount, Complete: true,
	}
	projection.Complete = true
	projection.ReceiptDigest = ""
	dependency := governedQueryDependency{
		questionRunID: questionRunID, attemptID: projection.AttemptID, connectionID: projection.SourceID,
		sqlHash: projection.SQLHash, exposedSchemaRevision: projection.ExposedSchemaRevision,
		resultDigest: projection.ResultDigest, kind: governedQueryKindSourceSQL,
	}
	if !dependency.validForRun(questionRunID) || !validLiveDataProjection(projection, time.Now().UTC()) {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	receiptDigest, err := liveDataReceiptDigest(questionRunID, projection)
	if err != nil || !validGovernedSHA256(receiptDigest) {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	projection.ReceiptDigest = receiptDigest
	owned, err := json.Marshal(projection)
	if err != nil {
		return sourceSQLRefusal("SOURCE_SQL_UNAVAILABLE"), nil, false
	}
	if len(owned) > maxResultBytes {
		return workspacetools.Result{
			Text:       `{"error":"SOURCE_SQL_RESULT_TOO_LARGE","advice":"Narrow the statement, add an aggregate, or add a LIMIT of at most 100 rows so the result can be cited."}`,
			Structured: json.RawMessage(`{"error":"SOURCE_SQL_RESULT_TOO_LARGE","advice":"Narrow the statement, add an aggregate, or add a LIMIT of at most 100 rows so the result can be cited."}`),
			IsError:    true,
		}, nil, false
	}
	owned = append(json.RawMessage(nil), owned...)
	return workspacetools.Result{Text: string(owned), Structured: owned},
		&liveDataExecution{projection: projection, dependency: dependency}, true
}
