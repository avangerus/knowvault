package workspaceapi

// R2 Outcome 1: the additive, access-re-checked REST surface for a workspace's
// versioned MetricDefinition projections (POSITION.md §3 "Semantics"). This
// transport holds no metric authority of its own: it forwards the
// authenticated access context and the workspace named in the path to the
// injected capabilities and projects only the fields the definition contract
// publishes.
//
// Reads go through the read-only MetricDefinitionCatalog and stay read-only.
// Drafting and approving go through a separate, optional
// MetricDefinitionAuthoring capability on their own colon paths, so the GET
// routes keep 405-on-POST. The authoring implementation owns the workspace
// access re-check, the owner check, the audited ApprovalEvent and version
// monotonicity (internal/metricdef.Series); this transport never approves a
// version by itself and never accepts a status, version or actor from the
// request.

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"knowvault.local/verified-workspace/internal/metricdef"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// MetricDefinitionCatalog is the narrow, read-only capability this transport
// needs. Both methods receive the caller's access context: the implementation
// re-checks workspace access exactly like every other protected read and is
// solely responsible for refusing a caller who may not read the workspace, so
// one workspace's definitions can never leak into another's. There is no
// Create/Approve/Retire method here by design.
type MetricDefinitionCatalog interface {
	// List returns every issued version of every definition in workspaceID.
	List(ctx context.Context, access database.AccessContext, workspaceID string) ([]metricdef.Definition, error)
	// GetVersion returns the exact version of metricID in workspaceID.
	GetVersion(ctx context.Context, access database.AccessContext, workspaceID, metricID string, version int64) (metricdef.Definition, error)
}

// ErrMetricDefinitionDenied is the content-free refusal a catalog returns when
// the caller's access context may not read the named workspace. The transport
// maps it to the same 404 NOT_FOUND every protected read uses, so denial and
// absence stay indistinguishable.
var ErrMetricDefinitionDenied = errors.New("METRICDEFINITION_ACCESS_DENIED")

// ErrMetricDefinitionNotFound is the content-free refusal for a definition id
// or version the workspace does not hold. Like ErrMetricDefinitionDenied it is
// mapped to 404 NOT_FOUND, never to an existence oracle.
var ErrMetricDefinitionNotFound = errors.New("METRICDEFINITION_NOT_FOUND")

// MetricDefinitionAuthoring is the narrow, owner-only write capability for
// drafting and approving definitions. Like the read catalog, both methods
// receive the caller's access context: the implementation re-checks workspace
// access exactly like every other protected write, maps the authenticated
// principal onto internal/metricdef's owner-only audited approval semantics,
// and owns the audit event, the approved-version immutability and the
// monotonic version number. The transport never chooses an actor, a version, a
// status or an audit time. Implementations return metricdef's typed refusals
// (or ErrMetricDefinitionDenied for a caller without workspace access) so the
// shared error mapping below stays content-free.
type MetricDefinitionAuthoring interface {
	// CreateDraft creates version 1 of definitionID when the workspace holds no
	// such definition, or a new monotonic DRAFT version when the current version
	// is APPROVED (an edited DRAFT stays the same version). It never fabricates
	// an APPROVED version.
	CreateDraft(ctx context.Context, access database.AccessContext, workspaceID, definitionID string, spec metricdef.Spec) (metricdef.Definition, error)
	// Approve flips the current DRAFT version of definitionID to APPROVED
	// through the workspace owner's audited approval boundary.
	Approve(ctx context.Context, access database.AccessContext, workspaceID, definitionID string) (metricdef.Definition, error)
}

// EnableMetricDefinitionAuthoring wires the optional, owner-only write
// capability. Composition calls it only when a real definition store with the
// owner audit boundary is mounted; a nil capability keeps both write routes
// content-free SERVICE_UNAVAILABLE, exactly like the read catalog.
func (handler *Handler) EnableMetricDefinitionAuthoring(authoring MetricDefinitionAuthoring) {
	if handler == nil || authoring == nil {
		return
	}
	handler.metricDefinitionAuthoring = authoring
}

// EnableMetricDefinitions wires the optional, read-only MetricDefinition
// capability. Composition calls it only after a valid definition projection is
// mounted; a nil capability keeps both metric-definition routes content-free
// SERVICE_UNAVAILABLE, exactly like the other optional capabilities.
func (handler *Handler) EnableMetricDefinitions(catalog MetricDefinitionCatalog) {
	if handler == nil || catalog == nil {
		return
	}
	handler.metricDefinitions = catalog
}

// metricDefinitionResponse is the published projection of one definition
// version. Every field is server-owned: none is accepted from a request, and
// no workspace, owner or persistence detail is exposed beyond the pinned
// source connection.
type metricDefinitionResponse struct {
	ID                 string   `json:"id"`
	Version            int64    `json:"version"`
	Status             string   `json:"status"`
	Name               string   `json:"name"`
	SourceConnectionID string   `json:"source_connection_id"`
	ProjectionVersion  int64    `json:"projection_version"`
	EntityKey          string   `json:"entity_key"`
	Grain              string   `json:"grain"`
	AllowedFilters     []string `json:"allowed_filters"`
	Unit               string   `json:"unit"`
}

func projectMetricDefinition(definition metricdef.Definition) metricDefinitionResponse {
	source := definition.Source()
	return metricDefinitionResponse{
		ID:                 definition.ID(),
		Version:            definition.Version(),
		Status:             string(definition.Status()),
		Name:               definition.Name(),
		SourceConnectionID: source.ConnectionID,
		ProjectionVersion:  source.ProjectionVersion,
		EntityKey:          definition.EntityKey(),
		Grain:              string(definition.Grain()),
		AllowedFilters:     definition.AllowedFilters(),
		Unit:               definition.Unit(),
	}
}

// metricDefinitionList answers GET /api/v1/workspaces/{id}/metric-definitions.
func (handler *Handler) metricDefinitionList(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.metricDefinitions == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	definitions, err := handler.metricDefinitions.List(request.Context(), access, workspaceID)
	if err != nil {
		writeMetricDefinitionError(writer, err, requestID)
		return
	}
	items := make([]metricDefinitionResponse, len(definitions))
	for index, definition := range definitions {
		items[index] = projectMetricDefinition(definition)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"definitions": items})
}

// metricDefinitionGet answers GET
// /api/v1/workspaces/{id}/metric-definitions/{metric_id}/versions/{version}.
func (handler *Handler) metricDefinitionGet(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID, metricID string, version int64) {
	if handler.metricDefinitions == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	definition, err := handler.metricDefinitions.GetVersion(request.Context(), access, workspaceID, metricID, version)
	if err != nil {
		writeMetricDefinitionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, projectMetricDefinition(definition))
}

// metricDefinitionDraftBody is the closed create-DRAFT body. Every field is a
// product value the authoring capability normalizes and validates; identity
// (workspace, owner), the version number and the status are never accepted
// from a request.
type metricDefinitionDraftBody struct {
	ID                 *string  `json:"id"`
	Name               *string  `json:"name"`
	SourceConnectionID *string  `json:"source_connection_id"`
	ProjectionVersion  *int64   `json:"projection_version"`
	EntityKey          *string  `json:"entity_key"`
	Grain              *string  `json:"grain"`
	AllowedFilters     []string `json:"allowed_filters"`
	Unit               *string  `json:"unit"`
}

func (body metricDefinitionDraftBody) missingFields() []string {
	return missingFieldNames([]fieldPresence{
		{body.ID != nil, "id"},
		{body.Name != nil, "name"},
		{body.SourceConnectionID != nil, "source_connection_id"},
		{body.ProjectionVersion != nil, "projection_version"},
		{body.EntityKey != nil, "entity_key"},
		{body.Grain != nil, "grain"},
	})
}

// metricDefinitionDraft answers POST
// /api/v1/workspaces/{id}/metric-definitions:draft. It validates the transport
// envelope first, then hands the spec to the owner-only authoring capability;
// the workspace access re-check, the owner check and version monotonicity are
// the capability's, never this handler's.
func (handler *Handler) metricDefinitionDraft(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.metricDefinitionAuthoring == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body metricDefinitionDraftBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if missing := body.missingFields(); len(missing) != 0 {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", missing)
		return
	}
	spec := metricdef.Spec{
		Name:           *body.Name,
		Source:         metricdef.SourceConnection{ConnectionID: *body.SourceConnectionID, ProjectionVersion: *body.ProjectionVersion},
		EntityKey:      *body.EntityKey,
		Grain:          metricdef.PeriodGrain(*body.Grain),
		AllowedFilters: body.AllowedFilters,
	}
	if body.Unit != nil {
		spec.Unit = *body.Unit
	}
	definition, err := handler.metricDefinitionAuthoring.CreateDraft(
		request.Context(), access, workspaceID, *body.ID, spec)
	if err != nil {
		writeMetricDefinitionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, projectMetricDefinition(definition))
}

// metricDefinitionApprove answers POST
// /api/v1/workspaces/{id}/metric-definitions/{metric_id}:approve. The command
// takes no body: the actor is the authenticated session, the version is the
// current DRAFT the capability resolves, and the audit time is the server's.
func (handler *Handler) metricDefinitionApprove(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID, metricID string) {
	if handler.metricDefinitionAuthoring == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	if code, fields := emptyBody(writer, request); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	definition, err := handler.metricDefinitionAuthoring.Approve(
		request.Context(), access, workspaceID, metricID)
	if err != nil {
		writeMetricDefinitionError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, projectMetricDefinition(definition))
}

// writeMetricDefinitionError maps the content-free failure surface. Denial and
// an unknown definition/version collapse to one 404 NOT_FOUND, so a caller
// without workspace access learns nothing about whether the definition exists
// (the same shape search-profile and governed-ask denials already use). An
// invalid definition request is the repository's own REQUEST_INVALID; every
// other failure stays a content-free SERVICE_UNAVAILABLE.
func writeMetricDefinitionError(writer http.ResponseWriter, err error, requestID string) {
	switch {
	case errors.Is(err, ErrMetricDefinitionDenied),
		errors.Is(err, ErrMetricDefinitionNotFound),
		metricdef.CodeOf(err) == metricdef.CodeUnknownVersion,
		// The owner-only refusal collapses to the same content-free 404 as a
		// denial: a caller who is not the workspace owner learns nothing about
		// whether the definition exists or who may approve it.
		metricdef.CodeOf(err) == metricdef.CodeNotWorkspaceOwner:
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	case metricdef.CodeOf(err) == metricdef.CodeInvalidDefinition,
		metricdef.CodeOf(err) == metricdef.CodeNotApprovable,
		metricdef.CodeOf(err) == metricdef.CodeRetiredImmutable:
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	default:
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}

// parseMetricDefinitionVersion parses the version path segment of the
// exact-version read. It accepts exactly one canonical decimal int64 greater
// than zero: no sign, no whitespace, no leading-zero form and no overflow. A
// malformed segment is a NOT_FOUND path, not REQUEST_INVALID, because the path
// itself names no resource.
func parseMetricDefinitionVersion(raw string) (int64, bool) {
	if raw == "" || len(raw) > 19 {
		return 0, false
	}
	if len(raw) > 1 && raw[0] == '0' {
		return 0, false
	}
	for index := 0; index < len(raw); index++ {
		if raw[index] < '0' || raw[index] > '9' {
			return 0, false
		}
	}
	version, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || version <= 0 {
		return 0, false
	}
	return version, true
}
