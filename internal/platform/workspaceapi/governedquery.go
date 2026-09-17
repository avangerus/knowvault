package workspaceapi

// ADR-0089: governed model-authored SQL over an operator-exposed schema.
// These handlers are a thin transport layer only: every policy check,
// database read/write and the sole call into
// internal/source/postgresqlquery/governedquery lives in
// internal/governedask.Service. No SQL, DSN or credential is ever accepted
// as a request field here; the model composes SQL, never a human caller
// (PRODUCT_CONSTITUTION.md §7's carve-out is exactly this ADR's scope).

import (
	"log/slog"
	"net/http"

	"knowvault.local/verified-workspace/internal/governedask"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

type governedQuerySetLiveQueriesBody struct {
	Enabled *bool `json:"enabled"`
}

func (body governedQuerySetLiveQueriesBody) complete() bool { return body.Enabled != nil }

func (handler *Handler) governedQuerySetLiveQueries(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	if handler.governedQuery == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body governedQuerySetLiveQueriesBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if !body.complete() {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"enabled"})
		return
	}
	if err := handler.governedQuery.SetLiveQueries(request.Context(), access, workspaceID, connectionID, *body.Enabled); err != nil {
		handleGovernedAskError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "live_queries_enabled": *body.Enabled})
}

type governedQueryExposedColumnBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Unit        string `json:"unit,omitempty"`
}

type governedQueryExposedObjectBody struct {
	SchemaName  string                           `json:"schema_name"`
	TableName   string                           `json:"table_name"`
	Description string                           `json:"description"`
	Columns     []governedQueryExposedColumnBody `json:"columns"`
}

type governedQueryExposedSchemaBody struct {
	Objects []governedQueryExposedObjectBody `json:"objects"`
}

func (handler *Handler) governedQueryExposedSchema(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	if handler.governedQuery == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body governedQueryExposedSchemaBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if len(body.Objects) == 0 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"objects"})
		return
	}
	objects := make([]governedquery.ExposedObject, 0, len(body.Objects))
	for _, object := range body.Objects {
		columns := make([]governedquery.ExposedColumn, 0, len(object.Columns))
		for _, column := range object.Columns {
			columns = append(columns, governedquery.ExposedColumn{
				Name: column.Name, Description: column.Description, Unit: column.Unit,
			})
		}
		objects = append(objects, governedquery.ExposedObject{
			SchemaName: object.SchemaName, TableName: object.TableName, Description: object.Description, Columns: columns,
		})
	}
	revision, err := handler.governedQuery.RegisterExposedSchema(request.Context(), access, workspaceID, connectionID, objects)
	if err != nil {
		handleGovernedAskError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "revision": revision})
}

type governedQueryAskBody struct {
	Question *string `json:"question"`
}

func (handler *Handler) governedQueryAsk(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	if handler.governedQuery == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body governedQueryAskBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.Question == nil || *body.Question == "" {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"question"})
		return
	}
	result, err := handler.governedQuery.Ask(request.Context(), access, workspaceID, connectionID, *body.Question)
	if err != nil {
		handleGovernedAskError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "result": result})
}

// governedQueryPromoteBody deliberately has NO sql field. ":promote" saves an
// attempt that already ran, named by its server-owned id and confirmed by the
// hash the operator was shown beside it (ADR-0089 §5). Accepting SQL text here
// would have made this route an arbitrary SQL intake on the API surface, which
// PRODUCT_CONSTITUTION.md §7 forbids and ADR-0089's carve-out — the MODEL
// composes, the dedicated role executes — does not cover. Name and schedule
// are the projection's own operator-visible settings and carry no SQL.
type governedQueryPromoteBody struct {
	AttemptID *string `json:"attempt_id"`
	SQLHash   *string `json:"sql_hash"`
	Name      string  `json:"name,omitempty"`
	Schedule  string  `json:"schedule,omitempty"`
}

func (handler *Handler) governedQueryPromote(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	if handler.governedQuery == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body governedQueryPromoteBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.AttemptID == nil || *body.AttemptID == "" || body.SQLHash == nil || *body.SQLHash == "" ||
		len(body.Name) > 200 || len(body.Schedule) > 200 {
		var fields []string
		if body.AttemptID == nil || *body.AttemptID == "" {
			fields = append(fields, "attempt_id")
		}
		if body.SQLHash == nil || *body.SQLHash == "" {
			fields = append(fields, "sql_hash")
		}
		if len(body.Name) > 200 {
			fields = append(fields, "name")
		}
		if len(body.Schedule) > 200 {
			fields = append(fields, "schedule")
		}
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", fields)
		return
	}
	result, err := handler.governedQuery.Promote(request.Context(), access, workspaceID, connectionID, *body.AttemptID, *body.SQLHash)
	if err != nil {
		handleGovernedAskError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"connection_id": connectionID, "status": result.Status,
		"attempt_id": result.AttemptID, "sql_hash": result.SQLHash,
	})
}

// logGovernedAskFailure records the one diagnosis the caller deliberately
// never receives. The response body stays content-free and identical for every
// capability/schema/connection refusal (ADR-0089 §6), so without this line an
// operator seeing 409 GOVERNED_QUERY_UNAVAILABLE cannot tell a disabled live
// query flag from an unreachable dedicated role. Only the request id, the
// typed governed-ask code and governedask.DiagnosticClass are recorded --
// never SQL text, a DSN, a schema/table name, rows or a model answer.
func logGovernedAskFailure(operation string, err error, requestID string) {
	slog.Warn("governed query failed", "component", "knowvault-server", "operation", operation,
		"request_id", requestID, "error_code", governedask.CodeOf(err), "error_class", governedask.DiagnosticClass(err))
}

func handleGovernedAskError(writer http.ResponseWriter, err error, requestID string) {
	logGovernedAskFailure("rest", err, requestID)
	switch governedask.CodeOf(err) {
	case governedask.CodeRequestInvalid:
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	case governedask.CodeDenied:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	case governedask.CodeLiveQueriesOff, governedask.CodeSchemaUnavailable, governedask.CodeConnectionUnavailable:
		writeError(writer, http.StatusConflict, "GOVERNED_QUERY_UNAVAILABLE", requestID)
	case governedask.CodeGenerationFailed, governedask.CodeExecutionFailed:
		writeError(writer, http.StatusUnprocessableEntity, "GOVERNED_QUERY_FAILED", requestID)
	default:
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}
