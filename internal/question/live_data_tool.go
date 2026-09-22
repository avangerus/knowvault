package question

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	liveDataToolName       = "knowvault_ask_live_data"
	liveDataMaxRows        = 100
	liveDataMaxColumns     = 64
	liveDataMaxCells       = 4096
	liveDataMaxCellBytes   = 4096
	liveDataMaxColumnBytes = 128
	liveDataQuestionBytes  = 4000
)

const liveDataToolSchema = `{"type":"object","additionalProperties":false,"required":["question"],"properties":{"question":{"type":"string"}}}`

func liveDataToolDefinition() modelgateway.ToolDefinition {
	return modelgateway.ToolDefinition{
		Type: "function",
		Function: modelgateway.ToolFunction{
			Name:        liveDataToolName,
			Description: "Answer one natural-language question from the workspace's administrator-governed live company data. Ask a focused question; the workspace and database are selected by the server.",
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
	Columns               []string           `json:"columns"`
	Rows                  [][]*string        `json:"rows"`
	RowCount              int                `json:"row_count"`
	AttemptID             string             `json:"attempt_id,omitempty"`
	SQLHash               string             `json:"sql_hash,omitempty"`
	ExposedSchemaRevision int64              `json:"exposed_schema_revision,omitempty"`
	ResultDigest          string             `json:"result_digest,omitempty"`
	ReadWindow            liveDataReadWindow `json:"read_window"`
	DatabaseIdentity      string             `json:"database_identity,omitempty"`
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
	if maxBytes < 1 || result.RowCount < 0 || result.RowCount > liveDataMaxRows ||
		len(result.Columns) == 0 || len(result.Columns) > liveDataMaxColumns ||
		result.RowCount != len(result.Rows) || len(result.Rows)*len(result.Columns) > liveDataMaxCells {
		return liveDataProjection{}, nil, false
	}
	projection := liveDataProjection{
		Columns:               append([]string(nil), result.Columns...),
		Rows:                  make([][]*string, len(result.Rows)),
		RowCount:              result.RowCount,
		AttemptID:             result.AttemptID,
		SQLHash:               result.SQLHash,
		ExposedSchemaRevision: result.ExposedSchemaRevision,
		ResultDigest:          result.ResultDigest,
		ReadWindow:            liveDataReadWindow{Offset: 0, Limit: result.RowCount, ReturnedRows: result.RowCount, TotalRows: result.RowCount, Complete: true},
		DatabaseIdentity:      result.DatabaseIdentity,
		Complete:              true,
	}
	for _, column := range projection.Columns {
		if !utf8.ValidString(column) || len(column) == 0 || len(column) > liveDataMaxColumnBytes {
			return liveDataProjection{}, nil, false
		}
	}
	for rowIndex, row := range result.Rows {
		if len(row) != len(projection.Columns) {
			return liveDataProjection{}, nil, false
		}
		projection.Rows[rowIndex] = make([]*string, len(row))
		for cellIndex, cell := range row {
			if cell == nil {
				continue
			}
			if !utf8.ValidString(*cell) || len(*cell) > liveDataMaxCellBytes {
				return liveDataProjection{}, nil, false
			}
			value := *cell
			projection.Rows[rowIndex][cellIndex] = &value
		}
	}
	for _, value := range []string{projection.AttemptID, projection.SQLHash, projection.ResultDigest, projection.DatabaseIdentity} {
		if !utf8.ValidString(value) || len(value) > 256 {
			return liveDataProjection{}, nil, false
		}
	}
	if projection.ExposedSchemaRevision < 0 {
		return liveDataProjection{}, nil, false
	}
	payload, err := json.Marshal(projection)
	if err != nil || len(payload) > maxBytes {
		return liveDataProjection{}, nil, false
	}
	return projection, payload, true
}

func invokeLiveDataTool(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	ask GovernedAsk,
	raw json.RawMessage,
	maxResultBytes int,
) (workspacetools.Result, error) {
	if ctx == nil || ask == nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil
	}
	if err := ctx.Err(); err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), err
	}
	question, ok := parseLiveDataQuestion(raw)
	if !ok {
		return liveDataRefusal("LIVE_DATA_INVALID_ARGUMENTS"), nil
	}
	result, err := ask.AskWorkspace(ctx, access, workspaceID, question)
	if err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), err
	}
	if err := ctx.Err(); err != nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), err
	}
	_, payload, ok := projectLiveDataResult(result, maxResultBytes)
	if !ok {
		return workspacetools.Result{
			Text:       `{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`,
			Structured: json.RawMessage(`{"error":"LIVE_DATA_RESULT_TOO_LARGE","advice":"Narrow the question or add filters; no partial rows were returned."}`),
			IsError:    true,
		}, nil
	}
	owned := append(json.RawMessage(nil), payload...)
	return workspacetools.Result{Text: string(owned), Structured: owned}, nil
}

// liveDataRunState is local to executeToolLoop. It prevents a second successful
// live result in one Question run and leaves private dependency persistence to
// the later G3c seam.
type liveDataRunState struct {
	retained bool
}

func (state *liveDataRunState) invoke(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	ask GovernedAsk,
	raw json.RawMessage,
	maxResultBytes int,
) (workspacetools.Result, error) {
	if state == nil {
		return liveDataRefusal("LIVE_DATA_UNAVAILABLE"), nil
	}
	if state.retained {
		return liveDataRefusal("LIVE_DATA_ALREADY_RECORDED"), nil
	}
	result, err := invokeLiveDataTool(ctx, access, workspaceID, ask, raw, maxResultBytes)
	if err == nil && !result.IsError {
		state.retained = true
	}
	return result, err
}
