package workspaceapi

// tools_source_schema.go is ADR-0097's knowvault_source_schema knowledge tool
// (S3 card 1): the one shared core the MCP tools/call adapter, the REST
// tools/source-schema parity route and the chat tool runtime all dispatch
// through, so the three surfaces cannot drift on the projection, the page
// window or the content-free denial.
//
// The tool answers from stored data only: the injected SourceSchemaProvider
// (the workspace repository's sourceMetadataRead boundary) resolves the
// enabled source bindings, the exclusion-narrowed immutable projections and
// their discovery catalog, while the optional workspacecontext.Reader supplies
// the administrator-authored source/table/column notes. It opens no external
// database, composes no SQL and never names a column excluded at registration.

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"net/http"
	"regexp"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspacecontext"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// maxSourceSchemaToolLimit is the contract's page bound: limit is at most 50.
// An omitted limit is the same 50, so a first call is a complete page of the
// usual source rather than a silently truncated one.
const maxSourceSchemaToolLimit = 50

// maxSourceSchemaToolTableChars bounds the optional "schema.name" selector.
const maxSourceSchemaToolTableChars = 257

// sourceSchemaIdentifierPattern is the PostgreSQL identifier shape the
// discovered schema uses for both a schema and a relation name.
var sourceSchemaIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// sourceSchemaToolArguments is the closed argument envelope of
// knowvault_source_schema. source_id is the source connection id the
// knowvault_sources tool returns; without it the tool lists the workspace's
// PostgreSQL sources instead of one source's tables. table is an optional
// "schema.name" selector. offset/limit page the table list.
type sourceSchemaToolArguments struct {
	SourceID string `json:"source_id"`
	Table    string `json:"table"`
	Offset   int64  `json:"offset"`
	Limit    int64  `json:"limit"`
}

func validSourceSchemaToolArguments(arguments sourceSchemaToolArguments) bool {
	if len(arguments.SourceID) > 128 || arguments.Offset < 0 || arguments.Limit < 0 ||
		arguments.Limit > maxSourceSchemaToolLimit || len(arguments.Table) > maxSourceSchemaToolTableChars {
		return false
	}
	if arguments.Table == "" {
		return true
	}
	separator := strings.IndexByte(arguments.Table, '.')
	if separator < 0 {
		return false
	}
	return sourceSchemaIdentifierPattern.MatchString(arguments.Table[:separator]) &&
		sourceSchemaIdentifierPattern.MatchString(arguments.Table[separator+1:])
}

// sourceSchemaToolResult is the one shared core. available is false only when
// the composition mounted no SourceSchemaProvider; err is the provider's own
// error, whose CodeNotFound the transports collapse to their single
// content-free not-found (never an existence oracle). A successful read is not
// audited here: the provider's sourceMetadataRead boundary already journals
// the source.metadata.read.* admission and outcome for every surface.
func (handler *Handler) sourceSchemaToolResult(ctx context.Context, access database.AccessContext, workspaceID string, arguments sourceSchemaToolArguments) (map[string]any, bool, error) {
	provider, ok := handler.sources.(SourceSchemaProvider)
	if !ok {
		return nil, false, nil
	}
	if arguments.SourceID == "" {
		sources, err := provider.ListSourceSchemas(ctx, access, workspaceID)
		if err != nil {
			return nil, true, err
		}
		return sourceSchemaSourceListProjection(sources), true, nil
	}
	limit := int(arguments.Limit)
	if limit == 0 {
		limit = maxSourceSchemaToolLimit
	}
	schema, err := provider.SourceSchema(ctx, access, workspaceID, arguments.SourceID, arguments.Table, int(arguments.Offset), limit)
	if err != nil {
		return nil, true, err
	}
	return sourceSchemaProjection(schema, int(arguments.Offset), handler.sourceSchemaNotes(ctx, access, workspaceID, arguments.SourceID)), true, nil
}

// sourceSchemaNotes reads the workspace model context's own notes for one
// source when the Reader is mounted. Notes are context, never evidence: a
// missing reader, a failed read or a source the document does not mention all
// degrade to empty notes rather than failing the schema answer.
func (handler *Handler) sourceSchemaNotes(ctx context.Context, access database.AccessContext, workspaceID, sourceID string) workspacecontext.SourceNotes {
	if handler.workspaceContext == nil {
		return workspacecontext.SourceNotes{}
	}
	notes, err := handler.workspaceContext.SourceNotes(ctx, workspaceContextAccessOf(access), workspaceID, sourceID)
	if err != nil {
		return workspacecontext.SourceNotes{}
	}
	return notes
}

// sourceSchemaSourceListProjection is the answer without source_id: the
// enabled PostgreSQL sources of the workspace with their id, display name and
// registered-relation count (the top of the map).
func sourceSchemaSourceListProjection(sources []workspacerepository.SourceSchemaSource) map[string]any {
	items := make([]any, 0, len(sources))
	for _, source := range sources {
		items = append(items, map[string]any{
			"id": source.ID, "name": source.Name, "table_count": source.TableCount,
		})
	}
	return map[string]any{"sources": items}
}

// sourceSchemaProjection renders the exact
// {source_id, database_identity, context_version, source_note, tables,
// next_offset, has_more} shape of S3 card 1, merging the workspace model
// context notes into the stored schema. A note authored in the workspace model
// context wins; the discovery-time native relation/column comment is the
// fallback display metadata (ADR-0097 "types and comments"), so the field is
// never empty merely because one of the two sources is absent.
func sourceSchemaProjection(schema workspacerepository.SourceSchema, offset int, notes workspacecontext.SourceNotes) map[string]any {
	contextTables := make(map[string]workspacecontext.Table, len(notes.Source.Tables))
	for _, table := range notes.Source.Tables {
		contextTables[table.Relation] = table
	}
	tables := make([]any, 0, len(schema.Tables))
	for _, table := range schema.Tables {
		contextTable, noted := contextTables[table.Schema+"."+table.Name]
		contextColumns := make(map[string]string, len(contextTable.Columns))
		if noted {
			for _, column := range contextTable.Columns {
				contextColumns[column.Name] = column.Note
			}
		}
		columns := make([]any, 0, len(table.Columns))
		for _, column := range table.Columns {
			columnNote := column.Note
			if contextNote, ok := contextColumns[column.Name]; ok && contextNote != "" {
				columnNote = contextNote
			}
			columns = append(columns, map[string]any{
				"name": column.Name, "type": column.Type, "nullable": column.Nullable,
				"primary_key": column.PrimaryKey, "note": columnNote,
			})
		}
		tableNote := table.Note
		if noted && contextTable.Note != "" {
			tableNote = contextTable.Note
		}
		tables = append(tables, map[string]any{
			"schema": table.Schema, "name": table.Name, "kind": table.Kind,
			"row_estimate": table.RowEstimate, "note": tableNote, "columns": columns,
		})
	}
	nextOffset := 0
	if schema.HasMore {
		nextOffset = offset + len(schema.Tables)
	}
	return map[string]any{
		"source_id":         schema.SourceID,
		"database_identity": schema.DatabaseIdentity,
		"context_version":   notes.ContextVersion,
		"source_note":       notes.Source.Description,
		"tables":            tables,
		"next_offset":       nextOffset,
		"has_more":          schema.HasMore,
	}
}

// workspaceToolSourceSchema is the REST parity of the MCP
// knowvault_source_schema tool. It dispatches through the identical shared
// sourceSchemaToolResult core, so a REST client, an MCP client and the chat
// tool runtime observe byte-identical JSON. The optional arguments travel in
// the JSON body (this route is POST-only); an unparsable or over-bound body is
// REQUEST_INVALID before the provider is touched. An unknown, foreign,
// disabled or non-member source is the provider's single content-free 404
// NOT_FOUND with no schema content. A composition mounted without the
// capability fails closed as 503 SERVICE_UNAVAILABLE.
func (handler *Handler) workspaceToolSourceSchema(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID string) {
	var arguments sourceSchemaToolArguments
	if code := decodeOptionalJSON(writer, request, &arguments); code != "" {
		writeError(writer, statusForMutationCode(code), code, requestID)
		return
	}
	if !validSourceSchemaToolArguments(arguments) {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	result, available, err := handler.sourceSchemaToolResult(request.Context(), access, workspaceID, arguments)
	if !available {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if err != nil {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	writeJSON(writer, http.StatusOK, result)
}

// mcpSourceSchemaArguments is the MCP tools/call envelope of
// knowvault_source_schema: the shared argument set plus the workspace
// selector every MCP tool carries.
type mcpSourceSchemaArguments struct {
	WorkspaceID string `json:"workspace_id"`
	SourceID    string `json:"source_id"`
	Table       string `json:"table"`
	Offset      int64  `json:"offset"`
	Limit       int64  `json:"limit"`
}

// mcpSourceSchemaToolCall is the MCP dispatch of knowvault_source_schema
// (ADR-0097). It validates the closed argument envelope at the transport
// boundary and then delegates to the single shared sourceSchemaToolResult
// core the REST tools/source-schema route and (through
// Handler.Invoke -> mcpKnowledgeToolCall) the chat tool runtime also compose.
// A denied, unknown or foreign workspace is the provider's single content-free
// not-found (-32004) with no schema content and no workspace-id echo; a
// composition mounted without the capability fails closed with -32000.
func (handler *Handler) mcpSourceSchemaToolCall(writer http.ResponseWriter, request *http.Request, access database.AccessContext, envelope mcpRequest, params mcpToolCallParams) {
	var arguments mcpSourceSchemaArguments
	if err := jsonv2.Unmarshal(params.Arguments, &arguments,
		jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		arguments.WorkspaceID == "" {
		writeMCPError(writer, envelope.ID, -32602, "invalid source schema arguments")
		return
	}
	shared := sourceSchemaToolArguments{
		SourceID: arguments.SourceID, Table: arguments.Table, Offset: arguments.Offset, Limit: arguments.Limit,
	}
	if !validSourceSchemaToolArguments(shared) {
		writeMCPError(writer, envelope.ID, -32602, "invalid source schema arguments")
		return
	}
	result, available, err := handler.sourceSchemaToolResult(request.Context(), access, arguments.WorkspaceID, shared)
	if !available {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	if err != nil {
		writeMCPError(writer, envelope.ID, -32004, "source schema not found")
		return
	}
	text, marshalErr := jsonv2.Marshal(result)
	if marshalErr != nil {
		writeMCPError(writer, envelope.ID, -32000, "service unavailable")
		return
	}
	writeMCP(writer, mcpResponse{JSONRPC: "2.0", ID: envelope.ID, Result: map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(text)}},
		"structuredContent": result,
		"isError":           false,
	}})
}
