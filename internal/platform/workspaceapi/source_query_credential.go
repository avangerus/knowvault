package workspaceapi

// source_query_credential.go is S3 card 2b's transport for the organization
// OWNER's control over one PostgreSQL source connection's SQL query credential
// (ADR-0097). Like every other optional source capability, it is discovered by
// a type assertion on the injected source service, so a deployment that never
// composed the check leaves both routes content-free SERVICE_UNAVAILABLE
// instead of advertising a control it cannot enforce.
//
// The transport accepts only the opaque 'cred' reference. It never accepts,
// echoes or logs a DSN, a password or any other secret value, and a refusal is
// one closed code so the operator learns what to fix without learning anything
// about the customer database.

import (
	"context"
	"net/http"

	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// SourceQueryCredentialUnresolved is the closed code for a reference that the
// server's mounted credentials do not resolve. The other three codes are the
// governed executor's own vocabulary, reported verbatim.
const SourceQueryCredentialUnresolved = "SOURCE_QUERY_CREDENTIAL_UNRESOLVED"

// SourceQueryCredential is S3 card 2b's optional owner-only capability behind
// the Sources database-card control. The injected implementation owns the
// owner gate, the mounted-credential resolution, the read-only/identity/
// column-privilege checks, the persistence and the audit; this package only
// validates the closed envelope and maps the result.
type SourceQueryCredential interface {
	SetSourceQueryCredential(ctx context.Context, access database.AccessContext, workspaceID, connectionID, credentialReference string) error
}

// SourceQueryCredentialRefusal is the closed, content-free refusal of a
// candidate reference. Code is one of the four documented codes; the type
// carries no DSN, reference, relation or driver message.
type SourceQueryCredentialRefusal struct{ Code string }

func (refusal *SourceQueryCredentialRefusal) Error() string {
	if refusal == nil {
		return ""
	}
	return refusal.Code
}

// SourceQueryCredentialRefusalCode reports the closed code of a refusal, or
// the empty string when err is not a refusal.
func SourceQueryCredentialRefusalCode(err error) string {
	if refusal, ok := err.(*SourceQueryCredentialRefusal); ok && refusal != nil {
		return refusal.Code
	}
	return ""
}

// validSourceQueryCredentialReference is the same opaque 'cred' + ULID shape
// the registration and worker boundaries accept. A reference that does not
// match it is refused before the provider is touched.
func validSourceQueryCredentialReference(value string) bool {
	const (
		prefix   = "cred_"
		alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	)
	if len(value) != len(prefix)+26 || value[:len(prefix)] != prefix {
		return false
	}
	encoded := value[len(prefix):]
	if encoded[0] < '0' || encoded[0] > '7' {
		return false
	}
	for _, symbol := range encoded[1:] {
		found := false
		for _, allowed := range alphabet {
			if symbol == allowed {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

type sourceQueryCredentialBody struct {
	CredentialReference *string `json:"credential_reference"`
}

func (handler *Handler) setSourceQueryCredential(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	provider, ok := handler.sources.(SourceQueryCredential)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body sourceQueryCredentialBody
	if code := decodeJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if body.CredentialReference == nil || !validSourceQueryCredentialReference(*body.CredentialReference) {
		writeValidationError(writer, request, requestID, "REQUEST_INVALID", []string{"credential_reference"})
		return
	}
	if err := provider.SetSourceQueryCredential(request.Context(), access, workspaceID, connectionID, *body.CredentialReference); err != nil {
		writeSourceQueryCredentialError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "sql_available": true})
}

func (handler *Handler) clearSourceQueryCredential(writer http.ResponseWriter, request *http.Request, access database.AccessContext, requestID, workspaceID, connectionID string) {
	provider, ok := handler.sources.(SourceQueryCredential)
	if !ok {
		writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
		return
	}
	if _, _, code, fields := mutationHeaders(request, false); code != "" {
		writeValidationError(writer, request, requestID, code, fields)
		return
	}
	var body struct{}
	if code := decodeOptionalJSON(writer, request, &body); code != "" {
		writeValidationError(writer, request, requestID, code, nil)
		return
	}
	if err := provider.SetSourceQueryCredential(request.Context(), access, workspaceID, connectionID, ""); err != nil {
		writeSourceQueryCredentialError(writer, err, requestID)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"connection_id": connectionID, "sql_available": false})
}

// writeSourceQueryCredentialError maps the capability's closed vocabulary onto
// the transport. Every check failure is a 409 with its exact code (nothing
// changed); an unauthorized, unknown or foreign workspace/connection is the
// single content-free 404 every other source operation returns; a malformed
// reference is 400; an unauditable change is 503.
func writeSourceQueryCredentialError(writer http.ResponseWriter, err error, requestID string) {
	switch code := SourceQueryCredentialRefusalCode(err); code {
	case SourceQueryCredentialUnresolved,
		"SOURCE_QUERY_CREDENTIAL_DATABASE_MISMATCH",
		"SOURCE_QUERY_CREDENTIAL_COLUMN_PRIVILEGE",
		"SOURCE_QUERY_CREDENTIAL_DATABASE_REJECTED":
		writeError(writer, http.StatusConflict, code, requestID)
		return
	default:
		_ = code
	}
	if workspacerepository.CodeOf(err) == workspacerepository.CodeNotFound {
		writeError(writer, http.StatusNotFound, "NOT_FOUND", requestID)
		return
	}
	if workspacerepository.CodeOf(err) == workspacerepository.CodeRequestInvalid {
		writeError(writer, http.StatusBadRequest, "REQUEST_INVALID", requestID)
		return
	}
	writeError(writer, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", requestID)
}
