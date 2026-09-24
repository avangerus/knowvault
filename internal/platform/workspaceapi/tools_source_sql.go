package workspaceapi

// tools_source_sql.go is ADR-0097's knowvault_source_sql knowledge tool (S3
// card 2): the one shared core the MCP tools/call adapter, the REST
// tools/source-sql parity route and the chat tool runtime all dispatch
// through, so the three surfaces cannot drift on the argument envelope, the
// result projection or the closed refusal vocabulary.
//
// The tool accepts exactly one SQL statement written by the agent and one
// source the caller's workspace has enabled. It never executes anything here:
// the injected optional SourceSQLProvider owns the authorization, the source's
// own query credential, the governedquery execution path (static pre-check,
// read-only transaction, statement timeout, EXPLAIN cost cap, row cap, plan
// scope walk) and the audit record. Because the provider returns a closed,
// content-free refusal code, every transport can hand the agent the same
// machine-readable result instead of an opaque transport error.
//
// The tool never accepts a DSN, a credential, a relation list or a schema
// digest from the request; those stay server-owned.

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const (
	// maxSourceSQLBytes is the contract's SQL bound: at most 8192 bytes.
	maxSourceSQLBytes = 8192
	// maxSourceSQLPurposeChars bounds the agent's free-form purpose note.
	maxSourceSQLPurposeChars = 200
	// maxSourceSQLSourceIDChars bounds the source connection id.
	maxSourceSQLSourceIDChars = 128
)

// SourceSQLRequest is the closed, server-owned request the transport hands the
// provider. SQL is the one agent-authored statement; it never reaches a
// request-decoding path other than this tool's own body.
type SourceSQLRequest struct {
	SourceID string
	SQL      string
	Purpose  string
}

// SourceSQLResult is the validated text-table projection the provider returns
// on success. Rows preserve SQL NULL as a nil cell and every value as the
// server's own text rendering, so the digest the provider computed covers
// exactly what the caller is shown.
type SourceSQLResult struct {
	Format string
	// SourceID is the workspace source the statement ran against. It is one
	// half of the chat receipt a citing answer binds to (the other is
	// ResultDigest); it is the same content-free source identifier the caller
	// already named in the request.
	SourceID string
	// ExposedSchemaRevision is the source scope revision the attempt was
	// audited against; it is the read's immutable scope identity, never a
	// request field.
	ExposedSchemaRevision int64
	Columns               []string
	Rows                  [][]*string
	RowCount              int
	AttemptID             string
	SQLHash               string
	ResultDigest          string
	DatabaseIdentity      string
	ExecutionStartedAt    time.Time
	ExecutionCompletedAt  time.Time
}

// SourceSQLProvider is ADR-0097's optional agent-authored SQL capability behind
// the knowvault_source_sql knowledge tool. It is discovered on the injected
// source service exactly like SourceSchemaProvider, so a composition mounted
// without it leaves the tool failing closed instead of widening the required
// SourceService interface. The production implementation owns the source's
// query credential, the single governedquery execution path and the audit
// record; a successful call that could not be audited returns no rows.
type SourceSQLProvider interface {
	SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request SourceSQLRequest) (SourceSQLResult, error)
}

// SourceSQLRefusal is the closed, content-free refusal ADR-0097's tool returns
// to the agent. Code is one of the seven documented codes; the type carries no
// SQL text, relation name, row, credential or driver message.
type SourceSQLRefusal struct{ Code string }

func (refusal *SourceSQLRefusal) Error() string {
	if refusal == nil {
		return ""
	}
	return refusal.Code
}

// SourceSQLRefusalCode reports the closed code of a refusal, or the empty
// string when err is not a refusal.
func SourceSQLRefusalCode(err error) string {
	if refusal, ok := err.(*SourceSQLRefusal); ok && refusal != nil {
		return refusal.Code
	}
	return ""
}

// sourceSQLToolArguments is the closed argument envelope of
// knowvault_source_sql: the source connection id, the one statement and the
// bounded purpose note. There is deliberately no limit/offset/timeout field: a
// caller cannot widen a server-owned bound.
type sourceSQLToolArguments struct {
	SourceID string `json:"source_id"`
	SQL      string `json:"sql"`
	Purpose  string `json:"purpose"`
}

func validSourceSQLToolArguments(arguments sourceSQLToolArguments) bool {
	if arguments.SourceID == "" || len(arguments.SourceID) > maxSourceSQLSourceIDChars ||
		!utf8.ValidString(arguments.SourceID) {
		return false
	}
	if arguments.SQL == "" || len(arguments.SQL) > maxSourceSQLBytes || !utf8.ValidString(arguments.SQL) {
		return false
	}
	if len(arguments.Purpose) > maxSourceSQLPurposeChars || !utf8.ValidString(arguments.Purpose) {
		return false
	}
	for _, character := range arguments.Purpose {
		if character < 0x20 && character != '\n' && character != '\t' {
			return false
		}
	}
	return true
}

// sourceSQLToolResult is the one shared core. available is false only when the
// composition mounted no SourceSQLProvider; a closed refusal is a successful
// tool result carrying its code, so the agent can react to it, while an
// authorization error (the provider's content-free CodeNotFound) is returned as
// an error for the transport's single not-found shape.
func (handler *Handler) sourceSQLToolResult(ctx context.Context, access database.AccessContext, workspaceID string, arguments sourceSQLToolArguments) (map[string]any, bool, error) {
	provider, ok := handler.sources.(SourceSQLProvider)
	if !ok {
		return nil, false, nil
	}
	result, err := provider.SourceSQL(ctx, access, workspaceID, SourceSQLRequest{
		SourceID: arguments.SourceID, SQL: arguments.SQL, Purpose: arguments.Purpose,
	})
	if err != nil {
		if code := SourceSQLRefusalCode(err); code != "" {
			return map[string]any{"error": code}, true, nil
		}
		return nil, true, err
	}
	return sourceSQLProjection(result), true, nil
}

// sourceSQLProjection renders the exact ADR-0097 result shape. It contains no
// SQL text, no connection id and no credential; the attempt id, hashes and
// database identity are the content-free facts the citation receipt binds to.
func sourceSQLProjection(result SourceSQLResult) map[string]any {
	columns := make([]any, 0, len(result.Columns))
	for _, column := range result.Columns {
		columns = append(columns, column)
	}
	rows := make([]any, 0, len(result.Rows))
	for _, row := range result.Rows {
		cells := make([]any, 0, len(row))
		for _, cell := range row {
			if cell == nil {
				cells = append(cells, nil)
				continue
			}
			cells = append(cells, *cell)
		}
		rows = append(rows, cells)
	}
	return map[string]any{
		"format":                  "postgres-text-table-v1",
		"columns":                 columns,
		"rows":                    rows,
		"row_count":               result.RowCount,
		"attempt_id":              result.AttemptID,
		"sql_hash":                result.SQLHash,
		"result_digest":           result.ResultDigest,
		"database_identity":       result.DatabaseIdentity,
		"source_id":               result.SourceID,
		"exposed_schema_revision": result.ExposedSchemaRevision,
		"execution_started_at":    result.ExecutionStartedAt.UTC().Format(time.RFC3339Nano),
		"execution_completed_at":  result.ExecutionCompletedAt.UTC().Format(time.RFC3339Nano),
		"complete":                true,
	}
}

// SourceSQLAttemptReauthority is the optional read-time check behind
// question's source-SQL disclosure gate: it re-verifies that the current
// caller may still read the workspace source a stored agent-authored SQL
// receipt came from. The production facade implements it by pure delegation to
// the same repository boundary the tool itself uses; a source service that does
// not leaves the gate failing closed.
type SourceSQLAttemptReauthority interface {
	ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error
}

// ReauthorizeSourceSQLAttempt is the chat runtime's current-authorization check
// for one stored source-SQL receipt. It is discovered on the injected source
// service exactly like the other optional source capabilities, so no new
// composition install path exists and an unmounted capability fails closed.
func (handler *Handler) ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error {
	if handler == nil || handler.sources == nil {
		return workspacetools.ErrUnavailable
	}
	reauthority, ok := handler.sources.(SourceSQLAttemptReauthority)
	if !ok {
		return workspacetools.ErrUnavailable
	}
	return reauthority.ReauthorizeSourceSQLAttempt(ctx, access, workspaceID, disclosure)
}

// workspaceToolSourceSQL is the REST parity of the MCP knowvault_source_sql
// tool (POST /api/v1/workspaces/{workspace_id}/tools/source-sql). The closed
// argument body carries source_id, sql and purpose. A closed refusal is a 200
// tool result the agent can react to; an unknown, foreign, disabled or
// non-member source is the provider's single content-free 404 NOT_FOUND; a
// composition mounted without the capability fails closed as 503.
func (handler *Handler) workspaceToolSourceSQL(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	var arguments sourceSQLToolArguments
	if code := decodeOptionalJSON(writer, request, &arguments); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	if !validSourceSQLToolArguments(arguments) {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	result, available, err := handler.sourceSQLToolResult(request.Context(), access, workspaceID, arguments)
	if !available {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err != nil {
		if workspacerepository.CodeOf(err) == workspacerepository.CodeNotFound {
			writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
			return
		}
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// mcpSourceSQLArguments is the MCP tools/call envelope of
// knowvault_source_sql: the shared argument set plus the workspace selector
// every MCP tool carries.
type mcpSourceSQLArguments struct {
	WorkspaceID string `json:"workspace_id"`
	SourceID    string `json:"source_id"`
	SQL         string `json:"sql"`
	Purpose     string `json:"purpose"`
}

// mcpSourceSQLToolCall is the MCP dispatch of knowvault_source_sql (ADR-0097).
// It validates the closed envelope at the transport boundary and then delegates
// to the single shared sourceSQLToolResult core the REST tools/source-sql route
// and (through Handler.Invoke -> mcpKnowledgeToolCall) the chat tool runtime
// also compose. A closed refusal travels as a successful tool result with
// isError=true, so an MCP agent sees the same code the REST and chat surfaces
// see; a denied, unknown or foreign workspace is the single content-free
// not-found (-32004).
func (handler *Handler) mcpSourceSQLToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	var arguments mcpSourceSQLArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid source sql arguments")
		return
	}
	shared := sourceSQLToolArguments{SourceID: arguments.SourceID, SQL: arguments.SQL, Purpose: arguments.Purpose}
	if !validSourceSQLToolArguments(shared) {
		writeMCPError(writer, envelope.ID, -32602, "invalid source sql arguments")
		return
	}
	result, available, err := handler.sourceSQLToolResult(request.Context(), access, arguments.WorkspaceID, shared)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		if workspacerepository.CodeOf(err) == workspacerepository.CodeNotFound {
			writeMCPError(writer, envelope.ID, -32004, "source not found")
			return
		}
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	isError := false
	if _, refused := result["error"]; refused {
		// A closed refusal is a tool result the agent reacts to, not a
		// transport failure: content and structuredContent carry the code and
		// isError marks the tool call as unsuccessful.
		isError = true
	}
	text, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(text)}},
		"structuredContent": result,
		"isError":           isError,
	}})
}

// mcpSourceSQLToolCall is the MCP dispatch of knowvault_source_sql (ADR-0097).
