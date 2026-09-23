package question

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	liveDataToolName           = "knowvault_ask_live_data"
	liveDataMaxRows            = 100
	liveDataMaxColumns         = 64
	liveDataMaxCells           = 4096
	liveDataMaxCellBytes       = 4096
	liveDataMaxColumnBytes     = 128
	liveDataQuestionBytes      = 4000
	liveDataResultFormat       = "postgres-text-table-v1"
	liveDataMaxSuccessfulCalls = 3
)

const liveDataToolSchema = `{"type":"object","additionalProperties":false,"required":["question"],"properties":{"question":{"type":"string"}}}`

func liveDataToolDefinition() modelgateway.ToolDefinition {
	return modelgateway.ToolDefinition{
		Type: "function",
		Function: modelgateway.ToolFunction{
			Name:        liveDataToolName,
			Description: "Answer one natural-language question from the workspace's administrator-governed live company data. Ask a focused question; the workspace and database are selected by the server. For a supported claim, copy this result's attempt_id as live_reads.result_id and copy receipt_digest exactly.",
			Parameters:  json.RawMessage(liveDataToolSchema),
		},
	}
}

func liveDataToolDefinitions(ask GovernedAsk) []modelgateway.ToolDefinition {
	if ask == nil {
		return nil
	}
	return []modelgateway.ToolDefinition{liveDataToolDefinition()}
}

type liveDataReadWindow struct {
	Offset       int  `json:"offset"`
	Limit        int  `json:"limit"`
	ReturnedRows int  `json:"returned_rows"`
	TotalRows    int  `json:"total_rows"`
	Complete     bool `json:"complete"`
}

// liveDataProjection is deliberately a new allow-listed shape. In particular,
// it has no SQL, connection id, cost, credentials or internal error field.
type liveDataProjection struct {
	Format                string             `json:"format"`
	Columns               []string           `json:"columns"`
	Rows                  [][]*string        `json:"rows"`
	RowCount              int                `json:"row_count"`
	AttemptID             string             `json:"attempt_id"`
	SQLHash               string             `json:"sql_hash"`
	ExposedSchemaRevision int64              `json:"exposed_schema_revision"`
	ResultDigest          string             `json:"result_digest"`
	ReadWindow            liveDataReadWindow `json:"read_window"`
	DatabaseIdentity      string             `json:"database_identity"`
	ExecutionStartedAt    string             `json:"execution_started_at"`
	ExecutionCompletedAt  string             `json:"execution_completed_at"`
	ReceiptDigest         string             `json:"receipt_digest,omitempty"`
	Complete              bool               `json:"complete"`
}

func liveDataRefusal(code string) workspacetools.Result {
	payload, _ := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: code})
	return workspacetools.Result{Text: string(payload), Structured: append(json.RawMessage(nil), payload...), IsError: true}
}

func parseLiveDataQuestion(raw json.RawMessage) (string, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || !json.Valid(trimmed) {
		return "", false
	}
	var fields map[string]json.RawMessage
	if jsonv2.Unmarshal(trimmed, &fields, jsontext.AllowDuplicateNames(false)) != nil || fields == nil || len(fields) != 1 {
		return "", false
	}
	questionRaw, ok := fields["question"]
	if !ok {
		return "", false
	}
	var question string
	if jsonv2.Unmarshal(questionRaw, &question) != nil || question == "" || len(question) > liveDataQuestionBytes || !utf8.ValidString(question) {
		return "", false
	}
	return question, true
}

func projectLiveDataResult(result governedask.AskResult, maxBytes int) (liveDataProjection, []byte, bool) {
	projection, payload, ok, _ := projectLiveDataResultDetailed(result, maxBytes)
	return projection, payload, ok
}

func projectLiveDataResultDetailed(result governedask.AskResult, maxBytes int) (liveDataProjection, []byte, bool, string) {
	if maxBytes < 1 || result.RowCount < 0 || result.RowCount > liveDataMaxRows ||
		len(result.Columns) == 0 || len(result.Columns) > liveDataMaxColumns ||
		result.RowCount != len(result.Rows) || len(result.Rows)*len(result.Columns) > liveDataMaxCells {
		return liveDataProjection{}, nil, false, "LIVE_DATA_RESULT_TOO_LARGE"
	}
	startedAt, completedAt, timesOK := liveDataExecutionTimes(result.ExecutionStartedAt, result.ExecutionCompletedAt, time.Now().UTC())
	if !timesOK || result.ResultFormat != liveDataResultFormat || !validLiveDataAttemptID(result.AttemptID) || !validGovernedID(result.ConnectionID) ||
		!validGovernedSHA256(result.SQLHash) || result.ExposedSchemaRevision < 1 || !validGovernedID(result.DatabaseIdentity) {
		return liveDataProjection{}, nil, false, "LIVE_DATA_UNAVAILABLE"
	}
	projection := liveDataProjection{
		Format:                liveDataResultFormat,
		Columns:               append([]string(nil), result.Columns...),
		Rows:                  make([][]*string, len(result.Rows)),
		RowCount:              result.RowCount,
		AttemptID:             result.AttemptID,
		SQLHash:               result.SQLHash,
		ExposedSchemaRevision: result.ExposedSchemaRevision,
		ResultDigest:          result.ResultDigest,
		ReadWindow:            liveDataReadWindow{Offset: 0, Limit: result.RowCount, ReturnedRows: result.RowCount, TotalRows: result.RowCount, Complete: true},
		DatabaseIdentity:      result.DatabaseIdentity,
		ExecutionStartedAt:    startedAt,
		ExecutionCompletedAt:  completedAt,
		Complete:              true,
	}
	for _, column := range projection.Columns {
		if !utf8.ValidString(column) || len(column) == 0 || len(column) > liveDataMaxColumnBytes {
			return liveDataProjection{}, nil, false, "LIVE_DATA_RESULT_TOO_LARGE"
		}
	}
	for rowIndex, row := range result.Rows {
		if len(row) != len(projection.Columns) {
			return liveDataProjection{}, nil, false, "LIVE_DATA_RESULT_TOO_LARGE"
		}
		projection.Rows[rowIndex] = make([]*string, len(row))
		for cellIndex, cell := range row {
			if cell == nil {
				continue
			}
			if !utf8.ValidString(*cell) || len(*cell) > liveDataMaxCellBytes {
				return liveDataProjection{}, nil, false, "LIVE_DATA_RESULT_TOO_LARGE"
			}
			value := *cell
			projection.Rows[rowIndex][cellIndex] = &value
		}
	}
	if !governedask.VerifyTextTableResultDigest(projection.Columns, projection.RowCount, projection.Rows, projection.ResultDigest) {
		return liveDataProjection{}, nil, false, "LIVE_DATA_UNAVAILABLE"
	}
	payload, err := json.Marshal(projection)
	if err != nil || len(payload) > maxBytes {
		return liveDataProjection{}, nil, false, "LIVE_DATA_RESULT_TOO_LARGE"
	}
	return projection, payload, true, ""
}

func liveDataExecutionTimes(started, completed, now time.Time) (string, string, bool) {
	if started.IsZero() || completed.IsZero() || completed.Before(started) || completed.After(now) {
		return "", "", false
	}
	return started.UTC().Format(time.RFC3339Nano), completed.UTC().Format(time.RFC3339Nano), true
}

func validLiveDataAttemptID(value string) bool {
	return strings.HasPrefix(value, "gqat_") && validGovernedID(value)
}

func decodeLiveDataProjection(raw []byte) (liveDataProjection, bool) {
	if len(raw) == 0 || !json.Valid(raw) {
		return liveDataProjection{}, false
	}
	var projection liveDataProjection
	if err := jsonv2.Unmarshal(raw, &projection, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return liveDataProjection{}, false
	}
	if !validLiveDataProjection(projection, time.Now().UTC()) {
		return liveDataProjection{}, false
	}
	return projection, true
}

func validLiveDataProjection(projection liveDataProjection, now time.Time) bool {
	if projection.Format != liveDataResultFormat || !projection.Complete || projection.RowCount < 0 ||
		projection.RowCount > liveDataMaxRows || projection.Columns == nil || len(projection.Columns) == 0 ||
		len(projection.Columns) > liveDataMaxColumns || projection.Rows == nil || projection.RowCount != len(projection.Rows) ||
		projection.RowCount*len(projection.Columns) > liveDataMaxCells || !validLiveDataAttemptID(projection.AttemptID) ||
		!validGovernedSHA256(projection.SQLHash) || projection.ExposedSchemaRevision < 1 ||
		!validGovernedSHA256(projection.ResultDigest) || !validGovernedID(projection.DatabaseIdentity) ||
		(projection.ReceiptDigest != "" && !validGovernedSHA256(projection.ReceiptDigest)) ||
		projection.ReadWindow != (liveDataReadWindow{Offset: 0, Limit: projection.RowCount, ReturnedRows: projection.RowCount, TotalRows: projection.RowCount, Complete: true}) {
		return false
	}
	for _, column := range projection.Columns {
		if !utf8.ValidString(column) || len(column) == 0 || len(column) > liveDataMaxColumnBytes {
			return false
		}
	}
	for _, row := range projection.Rows {
		if len(row) != len(projection.Columns) {
			return false
		}
		for _, cell := range row {
			if cell != nil && (!utf8.ValidString(*cell) || len(*cell) > liveDataMaxCellBytes) {
				return false
			}
		}
	}
	started, err := time.Parse(time.RFC3339Nano, projection.ExecutionStartedAt)
	if err != nil || started.UTC().Format(time.RFC3339Nano) != projection.ExecutionStartedAt {
		return false
	}
	completed, err := time.Parse(time.RFC3339Nano, projection.ExecutionCompletedAt)
	if err != nil || completed.UTC().Format(time.RFC3339Nano) != projection.ExecutionCompletedAt ||
		completed.Before(started) || completed.After(now) {
		return false
	}
	return governedask.VerifyTextTableResultDigest(projection.Columns, projection.RowCount, projection.Rows, projection.ResultDigest)
}

func invokeLiveDataTool(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	ask GovernedAsk,
	raw json.RawMessage,
	maxResultBytes int,
) (workspacetools.Result, error) {
	result, _, err := invokeLiveDataToolRetained(ctx, access, workspaceID, "live_data_unbound", ask, raw, maxResultBytes)
	return result, err
}

func invokeLiveDataToolRetained(
	ctx context.Context,
	access database.AccessContext,
	workspaceID, questionRunID string,
	ask GovernedAsk,
	raw json.RawMessage,
	maxResultBytes int,
) (workspacetools.Result, *liveDataExecution, error) {
	if ctx == nil || ask == nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	if err := ctx.Err(); err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, err
	}
	question, ok := parseLiveDataQuestion(raw)
	if !ok {
		return liveDataRefusal("LIVE_DATA_INVALID_ARGUMENTS"), nil, nil
	}
	result, err := ask.AskWorkspace(ctx, access, workspaceID, question)
	if err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, err
	}
	if err := ctx.Err(); err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, err
	}
	projection, _, ok, refusal := projectLiveDataResultDetailed(result, maxResultBytes)
	if !ok {
		if refusal != "LIVE_DATA_RESULT_TOO_LARGE" {
			return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
		}
		return workspacetools.Result{
			Text:       `{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`,
			Structured: json.RawMessage(`{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`),
			IsError:    true,
		}, nil, nil
	}
	if !validOpaque(questionRunID) {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	dependency := governedQueryDependency{
		questionRunID: questionRunID, attemptID: projection.AttemptID, connectionID: result.ConnectionID,
		sqlHash: projection.SQLHash, exposedSchemaRevision: projection.ExposedSchemaRevision,
		resultDigest: projection.ResultDigest,
	}
	if !dependency.validForRun(questionRunID) {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	projection.ReceiptDigest, err = liveDataReceiptDigest(questionRunID, projection)
	if err != nil || !validGovernedSHA256(projection.ReceiptDigest) {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	owned, err := json.Marshal(projection)
	if err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil, nil
	}
	if len(owned) > maxResultBytes {
		return workspacetools.Result{
			Text:       `{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`,
			Structured: json.RawMessage(`{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`),
			IsError:    true,
		}, nil, nil
	}
	owned = append(json.RawMessage(nil), owned...)
	return workspacetools.Result{Text: string(owned), Structured: owned}, &liveDataExecution{projection: projection, dependency: dependency}, nil
}

type liveDataExecution struct {
	projection liveDataProjection
	dependency governedQueryDependency
}

type liveTableReceiptProjection struct {
	Schema                string                  `json:"schema"`
	RunID                 string                  `json:"run_id"`
	Kind                  string                  `json:"kind"`
	Operation             string                  `json:"operation"`
	Rule                  string                  `json:"rule"`
	Format                string                  `json:"format"`
	AttemptID             string                  `json:"attempt_id"`
	SQLHash               string                  `json:"sql_hash"`
	ExposedSchemaRevision int64                   `json:"exposed_schema_revision"`
	DatabaseIdentity      string                  `json:"database_identity"`
	ResultDigest          string                  `json:"result_digest"`
	RowCount              int                     `json:"row_count"`
	Completeness          string                  `json:"completeness"`
	ObservationWindow     AnswerObservationWindow `json:"observation_window"`
}

func liveDataAnswerResult(questionRunID string, execution liveDataExecution) (*AnswerResult, error) {
	projection := execution.projection
	if !validOpaque(questionRunID) || !validLiveDataProjection(projection, time.Now().UTC()) ||
		!execution.dependency.validForRun(questionRunID) ||
		projection.AttemptID != execution.dependency.attemptID || projection.SQLHash != execution.dependency.sqlHash ||
		projection.ExposedSchemaRevision != execution.dependency.exposedSchemaRevision ||
		projection.ResultDigest != execution.dependency.resultDigest {
		return nil, &Error{code: CodeUnavailable}
	}
	window := AnswerObservationWindow{
		Basis:       "SERVER_GOVERNED_QUERY_EXECUTION",
		StartedAt:   projection.ExecutionStartedAt,
		CompletedAt: projection.ExecutionCompletedAt,
	}
	result := &AnswerResult{
		Kind:              "LIVE_TABLE",
		Operation:         "GOVERNED_READ",
		Rule:              "Complete administrator-governed live table; prose is an interpretation of these returned rows.",
		RunID:             questionRunID,
		Snapshot:          AnswerSnapshot{RowCount: projection.RowCount},
		Completeness:      "COMPLETE",
		ExecutionID:       projection.AttemptID,
		ResultDigest:      projection.ResultDigest,
		ObservationWindow: &window,
	}
	receiptDigest, err := liveDataReceiptDigest(questionRunID, projection)
	if err != nil || receiptDigest == "" || (projection.ReceiptDigest != "" && projection.ReceiptDigest != receiptDigest) {
		return nil, &Error{code: CodeUnavailable}
	}
	result.ReceiptDigest = receiptDigest
	return result, nil
}

func liveDataReceiptDigest(questionRunID string, projection liveDataProjection) (string, error) {
	if !validOpaque(questionRunID) || !validLiveDataProjection(projection, time.Now().UTC()) {
		return "", &Error{code: CodeUnavailable}
	}
	receipt := liveTableReceiptProjection{
		Schema: "knowvault.question.live-table-receipt.v1", RunID: questionRunID,
		Kind: "LIVE_TABLE", Operation: "GOVERNED_READ",
		Rule:   "Complete administrator-governed live table; prose is an interpretation of these returned rows.",
		Format: projection.Format, AttemptID: projection.AttemptID, SQLHash: projection.SQLHash,
		ExposedSchemaRevision: projection.ExposedSchemaRevision, DatabaseIdentity: projection.DatabaseIdentity,
		ResultDigest: projection.ResultDigest, RowCount: projection.RowCount, Completeness: "COMPLETE",
		ObservationWindow: AnswerObservationWindow{
			Basis: "SERVER_GOVERNED_QUERY_EXECUTION", StartedAt: projection.ExecutionStartedAt,
			CompletedAt: projection.ExecutionCompletedAt,
		},
	}
	canonical, err := canon.CanonicalJSON(receipt)
	if err != nil || len(canonical) == 0 {
		return "", &Error{code: CodeUnavailable}
	}
	digest := canon.Hash(canonical)
	if digest == "" {
		return "", &Error{code: CodeUnavailable}
	}
	return digest, nil
}

func liveDataAnswerResults(questionRunID string, executions []liveDataExecution) (*AnswerResult, error) {
	if len(executions) == 0 || len(executions) > liveDataMaxSuccessfulCalls {
		return nil, &Error{code: CodeUnavailable}
	}
	answers := make([]*AnswerResult, 0, len(executions))
	for _, execution := range executions {
		answer, err := liveDataAnswerResult(questionRunID, execution)
		if err != nil {
			return nil, err
		}
		answers = append(answers, answer)
	}
	primary := *answers[0]
	if len(answers) > 1 {
		primary.Receipts = make([]LiveTableReceipt, 0, len(answers))
		for _, answer := range answers {
			window := *answer.ObservationWindow
			primary.Receipts = append(primary.Receipts, LiveTableReceipt{
				ExecutionID: answer.ExecutionID, ResultDigest: answer.ResultDigest,
				ReceiptDigest: answer.ReceiptDigest, RowCount: answer.Snapshot.RowCount,
				Completeness: answer.Completeness, ObservationWindow: &window,
			})
		}
	}
	return &primary, nil
}

// liveDataRunState is local to executeToolLoop. It retains the complete
// validated results and private dependencies from a bounded sequence of
// successful calls.
type liveDataRunState struct {
	successfulCall bool
	retained       *liveDataExecution
	executions     []liveDataExecution
}

func (state *liveDataRunState) invoke(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	questionRunID string,
	ask GovernedAsk,
	raw json.RawMessage,
	maxResultBytes int,
) (workspacetools.Result, error) {
	if state == nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil
	}
	if len(state.executions) >= liveDataMaxSuccessfulCalls {
		return liveDataRefusal("LIVE_DATA_LIMIT_REACHED"), nil
	}
	result, execution, err := invokeLiveDataToolRetained(ctx, access, workspaceID, questionRunID, ask, raw, maxResultBytes)
	if err == nil && !result.IsError && execution != nil {
		state.successfulCall = true
		if state.retained == nil {
			state.retained = execution
		}
		state.executions = append(state.executions, *execution)
	}
	return result, err
}

func (state *liveDataRunState) discardRetainedResult() {
	if state != nil {
		state.retained = nil
		state.executions = nil
	}
}
