package workspaceapi

import (
	"context"
	"log/slog"
	"net/http"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/searchprofile"
)

// SearchProfileService is the EMB-1 retrieval profile authority
// (internal/searchprofile.Service satisfies it). Both routes are OWNER-gated
// control-plane actions on the workspace named in the path; this transport
// holds no embedding capability of its own and never accepts a profile,
// generation, alias or model identity from the request.
type SearchProfileService interface {
	Status(context.Context, database.AccessContext, string) (searchprofile.View, error)
	Revise(context.Context, database.AccessContext, string) (searchprofile.View, error)
}

// searchProfileStatus answers GET /api/v1/workspaces/{id}/search-profile.
func (handler *Handler) searchProfileStatus(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.searchProfile == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	view, err := handler.searchProfile.Status(request.Context(), access, workspaceID)
	if err != nil {
		writeSearchProfileError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, searchProfileDocument(view))
}

// searchProfileRevise answers POST /api/v1/workspaces/{id}/search-profile:revise.
// The command takes no body: its only parameter is the deployment's mounted
// embedding channel, which a request may never choose (SRCH-011).
func (handler *Handler) searchProfileRevise(writer http.ResponseWriter, request *http.Request,
	access database.AccessContext, requestID, workspaceID string) {
	if handler.searchProfile == nil {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	view, err := handler.searchProfile.Revise(request.Context(), access, workspaceID)
	if err != nil {
		writeSearchProfileError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusAccepted, searchProfileDocument(view))
}

func searchProfileDocument(view searchprofile.View) map[string]any {
	document := map[string]any{
		"active_profile_id":    view.ActiveProfileID,
		"active_revision":      view.ActiveRevision,
		"active_vector":        view.ActiveVector,
		"mounted_profile_id":   view.MountedProfileID,
		"mounted_available":    view.MountedAvailable,
		"revision_available":   view.RevisionAvailable,
		"reindex_in_progress":  view.ReindexInProgress,
		"staging_profile_id":   view.StagingProfileID,
		"staging_revision":     view.StagingRevision,
		"requested_profile_id": view.RequestedProfileID,
	}
	return document
}

func writeSearchProfileError(writer http.ResponseWriter, err error, requestID string) {
	// Content-free failure diagnosis for the operator command: only the typed
	// code and, when the cause is the database, its SQLSTATE. No identity,
	// profile, statement or corpus content is ever logged.
	slog.Warn("search profile command failed", "component", "knowvault-server",
		"request_id", requestID, "error_code", searchprofile.CodeOf(err),
		"sql_state", database.SQLStateCode(err))
	switch searchprofile.CodeOf(err) {
	case searchprofile.CodeInvalid:
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
	case searchprofile.CodeDenied:
		// Denied and not-found collapse to one response: a caller who is not an
		// OWNER of the workspace learns nothing about whether it exists.
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
	default:
		setServerFailureCause(writer, "search profile service", string(searchprofile.CodeOf(err)))
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
	}
}
