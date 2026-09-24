package workspaceapi

// Wire shapes, header parsing and error mapping for model_context.go. Kept in
// a separate file only for size; it is the same transport, same package.

import (
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// --- Request bodies ---

type modelContextRuleBody struct {
	ID   *string `json:"id"`
	Text *string `json:"text"`
}

type modelContextDataLocationBody struct {
	SourceConnectionID *string `json:"source_connection_id"`
	Relation           *string `json:"relation"`
	Column             *string `json:"column"`
	Hint               *string `json:"hint"`
}

type modelContextTermBody struct {
	ID            *string                        `json:"id"`
	Term          *string                        `json:"term"`
	Synonyms      []string                       `json:"synonyms"`
	Definition    *string                        `json:"definition"`
	DataLocations []modelContextDataLocationBody `json:"data_locations"`
}

type modelContextColumnBody struct {
	Name *string `json:"name"`
	Note *string `json:"note"`
}

type modelContextTableBody struct {
	Relation *string                  `json:"relation"`
	Note     *string                  `json:"note"`
	Columns  []modelContextColumnBody `json:"columns"`
}

type modelContextSourceBody struct {
	SourceConnectionID *string                 `json:"source_connection_id"`
	Description        *string                 `json:"description"`
	Tables             []modelContextTableBody `json:"tables"`
}

type modelContextDocumentBody struct {
	Description *string                  `json:"description"`
	Rules       []modelContextRuleBody   `json:"rules"`
	Glossary    []modelContextTermBody   `json:"glossary"`
	Sources     []modelContextSourceBody `json:"sources"`
}

type modelContextSaveBody struct {
	Document *modelContextDocumentBody `json:"document"`
}

type modelContextProposalAcceptBody struct {
	Term       *string  `json:"term"`
	Synonyms   []string `json:"synonyms"`
	Definition *string  `json:"definition"`
}

// toEdits maps the accept body onto A0's frozen, single-field ProposalEdits
// (file-level deviation note 2): definition wins when present, otherwise
// term; an absent body (nil pointers throughout) keeps the proposal's own
// suggested text (empty SuggestedText).
func (body modelContextProposalAcceptBody) toEdits() workspacecontext.ProposalEdits {
	if body.Definition != nil {
		return workspacecontext.ProposalEdits{SuggestedText: *body.Definition}
	}
	if body.Term != nil {
		return workspacecontext.ProposalEdits{SuggestedText: *body.Term}
	}
	return workspacecontext.ProposalEdits{}
}

func stringValueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// toDocument converts the decoded body into a workspacecontext.Document,
// leaving any id empty for the store to mint (S2-CONTRACT.md "New items are
// sent with \"id\": \"\""). It reports the JSON field names of any absent
// required field (a Rule's text, a Term's term, a Source/Table/Column/
// DataLocation's identity fields) rather than guessing a value for them.
func (body modelContextDocumentBody) toDocument() (workspacecontext.Document, []string) {
	var missing []string
	document := workspacecontext.Document{Description: stringValueOrEmpty(body.Description)}

	document.Rules = make([]workspacecontext.Rule, len(body.Rules))
	for index, rule := range body.Rules {
		if rule.ID == nil {
			missing = append(missing, "rules["+strconv.Itoa(index)+"].id")
		}
		if rule.Text == nil {
			missing = append(missing, "rules["+strconv.Itoa(index)+"].text")
		}
		document.Rules[index] = workspacecontext.Rule{ID: stringValueOrEmpty(rule.ID), Text: stringValueOrEmpty(rule.Text)}
	}

	document.Glossary = make([]workspacecontext.Term, len(body.Glossary))
	for index, term := range body.Glossary {
		if term.ID == nil {
			missing = append(missing, "glossary["+strconv.Itoa(index)+"].id")
		}
		if term.Term == nil {
			missing = append(missing, "glossary["+strconv.Itoa(index)+"].term")
		}
		locations := make([]workspacecontext.DataLocation, len(term.DataLocations))
		for locationIndex, location := range term.DataLocations {
			if location.SourceConnectionID == nil {
				missing = append(missing, "glossary["+strconv.Itoa(index)+"].data_locations["+strconv.Itoa(locationIndex)+"].source_connection_id")
			}
			if location.Relation == nil {
				missing = append(missing, "glossary["+strconv.Itoa(index)+"].data_locations["+strconv.Itoa(locationIndex)+"].relation")
			}
			locations[locationIndex] = workspacecontext.DataLocation{
				SourceConnectionID: stringValueOrEmpty(location.SourceConnectionID), Relation: stringValueOrEmpty(location.Relation),
				Column: stringValueOrEmpty(location.Column), Hint: stringValueOrEmpty(location.Hint),
			}
		}
		document.Glossary[index] = workspacecontext.Term{
			ID: stringValueOrEmpty(term.ID), Term: stringValueOrEmpty(term.Term), Synonyms: term.Synonyms,
			Definition: stringValueOrEmpty(term.Definition), DataLocations: locations,
		}
	}

	document.Sources = make([]workspacecontext.Source, len(body.Sources))
	for index, source := range body.Sources {
		if source.SourceConnectionID == nil {
			missing = append(missing, "sources["+strconv.Itoa(index)+"].source_connection_id")
		}
		tables := make([]workspacecontext.Table, len(source.Tables))
		for tableIndex, table := range source.Tables {
			if table.Relation == nil {
				missing = append(missing, "sources["+strconv.Itoa(index)+"].tables["+strconv.Itoa(tableIndex)+"].relation")
			}
			columns := make([]workspacecontext.Column, len(table.Columns))
			for columnIndex, column := range table.Columns {
				if column.Name == nil {
					missing = append(missing, "sources["+strconv.Itoa(index)+"].tables["+strconv.Itoa(tableIndex)+"].columns["+strconv.Itoa(columnIndex)+"].name")
				}
				columns[columnIndex] = workspacecontext.Column{Name: stringValueOrEmpty(column.Name), Note: stringValueOrEmpty(column.Note)}
			}
			tables[tableIndex] = workspacecontext.Table{Relation: stringValueOrEmpty(table.Relation), Note: stringValueOrEmpty(table.Note), Columns: columns}
		}
		document.Sources[index] = workspacecontext.Source{
			SourceConnectionID: stringValueOrEmpty(source.SourceConnectionID), Description: stringValueOrEmpty(source.Description), Tables: tables,
		}
	}
	return document, missing
}

// --- Responses ---

func modelContextRuleResponse(rule workspacecontext.Rule) map[string]any {
	return map[string]any{"id": rule.ID, "text": rule.Text}
}

func modelContextDataLocationResponse(location workspacecontext.DataLocation) map[string]any {
	item := map[string]any{"source_connection_id": location.SourceConnectionID, "relation": location.Relation}
	if location.Column != "" {
		item["column"] = location.Column
	}
	if location.Hint != "" {
		item["hint"] = location.Hint
	}
	return item
}

func modelContextTermResponse(term workspacecontext.Term) map[string]any {
	locations := make([]map[string]any, len(term.DataLocations))
	for index, location := range term.DataLocations {
		locations[index] = modelContextDataLocationResponse(location)
	}
	return map[string]any{
		"id": term.ID, "term": term.Term, "synonyms": term.Synonyms,
		"definition": term.Definition, "data_locations": locations,
	}
}

func modelContextColumnResponse(column workspacecontext.Column) map[string]any {
	return map[string]any{"name": column.Name, "note": column.Note}
}

func modelContextTableResponse(table workspacecontext.Table) map[string]any {
	columns := make([]map[string]any, len(table.Columns))
	for index, column := range table.Columns {
		columns[index] = modelContextColumnResponse(column)
	}
	return map[string]any{"relation": table.Relation, "note": table.Note, "columns": columns}
}

func modelContextSourceResponse(source workspacecontext.Source) map[string]any {
	tables := make([]map[string]any, len(source.Tables))
	for index, table := range source.Tables {
		tables[index] = modelContextTableResponse(table)
	}
	return map[string]any{"source_connection_id": source.SourceConnectionID, "description": source.Description, "tables": tables}
}

func modelContextDocumentResponse(document workspacecontext.Document) map[string]any {
	rules := make([]map[string]any, len(document.Rules))
	for index, rule := range document.Rules {
		rules[index] = modelContextRuleResponse(rule)
	}
	glossary := make([]map[string]any, len(document.Glossary))
	for index, term := range document.Glossary {
		glossary[index] = modelContextTermResponse(term)
	}
	sources := make([]map[string]any, len(document.Sources))
	for index, source := range document.Sources {
		sources[index] = modelContextSourceResponse(source)
	}
	return map[string]any{
		"description": document.Description, "rules": rules, "glossary": glossary, "sources": sources,
	}
}

// modelContextHashOrSentinel is the ETag/content_hash value for record: a
// version-0 (no context yet) record reports emptyContextSentinelHeader, the
// exact value S2-CONTRACT.md's If-Match also accepts for that state, so a
// client's first PUT never has to special-case "there is no hash yet."
const modelContextEmptySentinel = "sha256:empty"

func modelContextHashOrSentinel(record workspacecontext.VersionRecord) string {
	if record.Number == 0 {
		return modelContextEmptySentinel
	}
	return record.ContentHash
}

func writeModelContextRecord(writer http.ResponseWriter, status int, record workspacecontext.VersionRecord) {
	hash := modelContextHashOrSentinel(record)
	writer.Header().Set("ETag", "\""+hash+"\"")
	body := map[string]any{
		"version": record.Number, "content_hash": hash, "editable": record.Editable,
		"document": modelContextDocumentResponse(record.Document),
	}
	if record.Number > 0 {
		body["updated_at"] = record.CreatedAt.UTC().Format(time.RFC3339)
		body["updated_by"] = record.CreatedBy
	} else {
		body["updated_at"] = ""
		body["updated_by"] = ""
	}
	writeJSON(writer, status, body)
}

// writeModelContextVersion projects a bare workspacecontext.Version (the
// shape workspacecontext.ProposalService.Accept -- A0, frozen -- returns,
// which carries no created_at/created_by). updated_at/updated_by are
// synthesized from the caller's own request: an accept mints its version in
// the same request that is answering it, so "now, by this principal" is
// exact, not an approximation of a fact recorded elsewhere.
func writeModelContextVersion(writer http.ResponseWriter, status int, access database.AccessContext, version workspacecontext.Version) {
	writeModelContextRecord(writer, status, workspacecontext.VersionRecord{
		Version: version, CreatedAt: time.Now().UTC(), CreatedBy: access.PrincipalID,
	})
}

// --- Header parsing ---

// modelContextMutationHeaders is mutationHeaders' If-Match validation widened
// by exactly one literal value, modelContextEmptySentinel
// ("sha256:empty") -- S2-CONTRACT.md's required sentinel for a workspace with
// no context yet, which workspace.IsConfigurationHash (a real 64-hex-digit
// content hash) never accepts. Every other rule (Idempotency-Key format,
// If-Match required/absent, quoting) is unchanged from mutationHeaders.
func modelContextMutationHeaders(request *http.Request) (key, hash, code string, fields []string) {
	key, ok := exactHeader(request.Header, "Idempotency-Key")
	if !ok || !validIdempotencyKey(key) {
		return "", "", "REQUEST_INVALID", []string{"Idempotency-Key"}
	}
	if !headerPresent(request.Header, "If-Match") {
		return "", "", "PRECONDITION_REQUIRED", []string{"If-Match"}
	}
	match, exact := exactHeader(request.Header, "If-Match")
	if !exact {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	if len(match) < 2 || match[0] != '"' || match[len(match)-1] != '"' {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	hash = match[1 : len(match)-1]
	if hash != modelContextEmptySentinel && !workspace.IsConfigurationHash(hash) {
		return "", "", "REQUEST_INVALID", []string{"If-Match"}
	}
	return key, hash, "", nil
}

// --- Query parsing ---

// validModelContextVersionsQuery strictly parses ?limit=&cursor= for
// GET .../model-context/versions, mirroring validConversationListQuery's
// discipline: url.ParseQuery (never URL.Query(), which silently drops a
// malformed component), at most the two known keys, one value each, and a
// canonical decimal cursor (the version to page strictly before).
func validModelContextVersionsQuery(requestURL *url.URL) (limit int, cursor int64, ok bool) {
	if requestURL == nil {
		return 0, 0, false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return 0, 0, true
	}
	if requestURL.ForceQuery {
		return 0, 0, false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 2 {
		return 0, 0, false
	}
	for key, rawValues := range values {
		if (key != "limit" && key != "cursor") || len(rawValues) != 1 || rawValues[0] == "" {
			return 0, 0, false
		}
		if key == "limit" {
			parsed, parseErr := strconv.Atoi(rawValues[0])
			if parseErr != nil || parsed < 1 || parsed > modelContextVersionsPageLimitMax || !canonicalDecimal(rawValues[0]) {
				return 0, 0, false
			}
			limit = parsed
			continue
		}
		parsedCursor, cursorOk := parseCanonicalPositiveInt64(rawValues[0])
		if !cursorOk {
			return 0, 0, false
		}
		cursor = parsedCursor
	}
	return limit, cursor, true
}

// validModelContextProposalsQuery strictly parses ?status=&limit=&cursor=
// for GET .../model-context/proposals. status defaults to PROPOSED (the
// primary review-queue view) when absent; any other value must be one of the
// four closed ProposalStatus values. cursor is an opaque server-assigned
// proposal id (validOpaqueID), never a client-chosen offset.
func validModelContextProposalsQuery(requestURL *url.URL) (status workspacecontext.ProposalStatus, limit int, cursor string, ok bool) {
	status = workspacecontext.ProposalStatusProposed
	limit = defaultVersionPageLimit
	if requestURL == nil {
		return "", 0, "", false
	}
	if requestURL.RawQuery == "" && !requestURL.ForceQuery {
		return status, limit, "", true
	}
	if requestURL.ForceQuery {
		return "", 0, "", false
	}
	values, err := url.ParseQuery(requestURL.RawQuery)
	if err != nil || len(values) == 0 || len(values) > 3 {
		return "", 0, "", false
	}
	for key, rawValues := range values {
		if len(rawValues) != 1 || rawValues[0] == "" {
			return "", 0, "", false
		}
		switch key {
		case "status":
			candidate := workspacecontext.ProposalStatus(rawValues[0])
			if !candidate.Valid() {
				return "", 0, "", false
			}
			status = candidate
		case "limit":
			parsed, parseErr := strconv.Atoi(rawValues[0])
			if parseErr != nil || parsed < 1 || parsed > modelContextVersionsPageLimitMax || !canonicalDecimal(rawValues[0]) {
				return "", 0, "", false
			}
			limit = parsed
		case "cursor":
			if !validOpaqueID(rawValues[0]) {
				return "", 0, "", false
			}
			cursor = rawValues[0]
		default:
			return "", 0, "", false
		}
	}
	return status, limit, cursor, true
}

const defaultVersionPageLimit = 20

func canonicalDecimal(raw string) bool {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return false
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return false
		}
	}
	return true
}

func parseCanonicalPositiveInt64(raw string) (int64, bool) {
	if !canonicalDecimal(raw) || len(raw) > 19 {
		return 0, false
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 1 {
		return 0, false
	}
	return value, true
}

// modelContextVersionSegment parses the {version} path segment shared by
// GET .../versions/{version} and POST .../versions/{version}:restore, an
// exact positive canonical decimal -- the same shape
// parseMetricDefinitionVersion enforces for its own, unrelated route.
func modelContextVersionSegment(raw string) (int64, bool) {
	return parseCanonicalPositiveInt64(raw)
}

// Tool parity (POST /workspaces/{id}/tools/workspace-context) has no wire
// types here: that route is card C's workspaceToolDispatch
// (tools_rest.go), the one kept implementation sharing the
// workspacecontext.Reader/MatchTerms projection with MCP and chat. See
// model_context.go's file-level note.

// --- Error mapping ---

func writeModelContextError(writer http.ResponseWriter, err error, requestID string) {
	code := workspacecontext.CodeOf(err)
	slog.Warn("model context command failed", "component", "knowvault-server",
		"request_id", requestID, "error_code", code, "sql_state", database.SQLStateCode(err))
	switch code {
	case workspacecontext.CodeAccessDenied, workspacecontext.CodeVersionNotFound:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	case workspacecontext.CodeNotEditor:
		writeError(writer, http.StatusForbidden, "FORBIDDEN", requestID)
	case workspacecontext.CodeRevisionConflict:
		writeError(writer, http.StatusPreconditionFailed, "WORKSPACE_CONTEXT_REVISION_CONFLICT", requestID)
	case workspacecontext.CodeIdempotencyConflict:
		writeError(writer, http.StatusConflict, "WORKSPACE_CONTEXT_IDEMPOTENCY_CONFLICT", requestID)
	case workspacecontext.CodeInvalidDocument, workspacecontext.CodeUnknownLocation:
		// S2-CONTRACT.md asks for field paths; see the file-level deviation
		// note 1 in model_context.go for why none is available here.
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	default:
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}

// writeModelContextProposalError maps an error from card E's
// workspacecontext.ProposalService. That interface (A0, frozen) documents no
// error-code contract of its own; this best-effort mapping recognises this
// package's own workspacecontext.Error codes (via the same CodeOf every
// other Store error already uses) when E's implementation reuses them, and
// otherwise fails closed to content-free SERVICE_UNAVAILABLE. Per
// S2-CONTRACT.md "Proposals (OWNER and MANAGER only; others get 404)", a
// denied caller collapses to NOT_FOUND here, not FORBIDDEN -- unlike the
// document routes, where a member's denied write is 403.
func writeModelContextProposalError(writer http.ResponseWriter, err error, requestID string) {
	code := workspacecontext.CodeOf(err)
	slog.Warn("model context proposal command failed", "component", "knowvault-server",
		"request_id", requestID, "error_code", code, "sql_state", database.SQLStateCode(err))
	switch code {
	case workspacecontext.CodeAccessDenied, workspacecontext.CodeNotEditor, workspacecontext.CodeVersionNotFound:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	case workspacecontext.CodeRevisionConflict:
		writeError(writer, http.StatusPreconditionFailed, "WORKSPACE_CONTEXT_REVISION_CONFLICT", requestID)
	case workspacecontext.CodeInvalidDocument, workspacecontext.CodeUnknownLocation:
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	default:
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}
