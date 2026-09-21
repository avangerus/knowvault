package repository

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// authorityAccessModeSourceEnforced is the second legitimate workspace source
// access mode, private to the authority surface. The lookup needs the exact
// spelling so that a legitimate SOURCE_ENFORCED binding — a workspace source
// this execution path cannot serve — stays distinct from an access-mode fact
// the database should never have returned.
const authorityAccessModeSourceEnforced = "SOURCE_ENFORCED"

// PostgreSQLAuthorityLookup names one PostgreSQL source binding a caller
// already knows by its workspace, source scope and connection. It is a closed
// identity triple: it is never SQL, never a credential reference, never a
// workspace revision and never a caller-chosen policy rule.
type PostgreSQLAuthorityLookup struct {
	WorkspaceID   string
	SourceScopeID string
	ConnectionID  string
}

// ResolvePostgreSQLAuthorityRequest resolves the candidate identity of the one
// workspace source binding named by lookup. The result is only a candidate: it
// grants no execution authority and carries no credential, projection, limit,
// workspace revision or workspace configuration hash. Every candidate MUST be
// passed through ResolvePostgreSQLAuthority before any read is authorized.
//
// The result stays in process: it is never cached and never exposed to a
// browser or MCP surface.
//
// Admission is exactly the existing source authority admission, evaluated with
// the same helpers in the same order: an active actor in an active
// organization, the current workspace snapshot and the workspace.ask policy
// decision. A missing or inactive actor, a missing workspace and a denied ask
// all collapse to the same content-free CodeNotFound, so this lookup is not an
// existence oracle.
//
// The single read queries only app.workspace_source_status_v3($1) for the
// exact scope and connection. Zero rows and a legitimate SOURCE_ENFORCED row
// this execution path cannot serve both collapse to CodeNotFound. Any other
// server fact that does not match the requested identity, a revision outside
// the safe positive range, an unparseable scope configuration hash, an access
// mode that is neither of the two legitimate modes, an ambiguous result set
// and every driver/scan/rows error are malformed server facts and fail closed
// with CodePersistence. No error carries a wrapped database cause.
func (store *Store) ResolvePostgreSQLAuthorityRequest(ctx context.Context, access database.AccessContext, lookup PostgreSQLAuthorityLookup) (PostgreSQLAuthorityRequest, error) {
	if store == nil || store.database == nil || ctx == nil || access.Validate() != nil {
		return PostgreSQLAuthorityRequest{}, &Error{code: CodeRequestInvalid}
	}
	if !validID(lookup.WorkspaceID) || !validID(lookup.SourceScopeID) || !validID(lookup.ConnectionID) {
		return PostgreSQLAuthorityRequest{}, &Error{code: CodeRequestInvalid}
	}
	denied := false
	notFound := false
	persistence := false
	resolved := false
	request := PostgreSQLAuthorityRequest{}
	readErr := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, lookup.WorkspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		membership := currentMembership(snapshot, access.PrincipalID)
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceAsk,
			Subject:   subject,
			Workspace: policy.Workspace{
				OrganizationID: snapshot.OrganizationID,
				ID:             snapshot.ID,
				Status:         policy.WorkspaceStatus(snapshot.Status),
			},
			Membership: membership,
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		// Query, never QueryRow: the candidate must be exactly one row, so an
		// ambiguous result set is a server fact to detect rather than a silently
		// dropped duplicate.
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT status.workspace_source_id, status.source_scope_id,
			       status.connection_id, status.source_scope_revision,
			       status.scope_config_hash, status.access_mode
			  FROM app.workspace_source_status_v3($1) AS status
			 WHERE status.source_scope_id = $2
			   AND status.connection_id = $3
			 LIMIT 2
		`, lookup.WorkspaceID, lookup.SourceScopeID, lookup.ConnectionID)
		if queryErr != nil {
			persistence = true
			return nil
		}
		var (
			scannedWorkspaceSourceID string
			scannedSourceScopeID     string
			scannedConnectionID      string
			scannedScopeRevision     int64
			scannedScopeConfigHash   string
			scannedAccessMode        string
		)
		scannedRows := 0
		for rows.Next() {
			if scanErr := rows.Scan(&scannedWorkspaceSourceID, &scannedSourceScopeID,
				&scannedConnectionID, &scannedScopeRevision,
				&scannedScopeConfigHash, &scannedAccessMode); scanErr != nil {
				rows.Close()
				persistence = true
				return nil
			}
			scannedRows++
			if scannedRows > 1 {
				rows.Close()
				persistence = true
				return nil
			}
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			persistence = true
			return nil
		}
		rows.Close()
		if scannedRows == 0 {
			notFound = true
			return nil
		}
		// Exact-check every scanned identity fact before it becomes a candidate.
		// The binding identity is checked in its exact closing form rather than
		// re-derived here: the candidate is not authority, so re-running the
		// lineage derivation would be a second identity rule.
		if !authorityBindingID(scannedWorkspaceSourceID) ||
			scannedSourceScopeID != lookup.SourceScopeID ||
			scannedConnectionID != lookup.ConnectionID ||
			!authoritySafeRevision(scannedScopeRevision) ||
			!authorityHash(scannedScopeConfigHash) {
			persistence = true
			return nil
		}
		// The access mode is a closed server fact, so it is classified only
		// after every identity/revision/hash fact above was exact-checked.
		// WORKSPACE_MANAGED is the one mode this execution path serves. A
		// SOURCE_ENFORCED binding is a legitimate workspace source this path
		// cannot serve, so it is deliberately unavailable rather than corrupt.
		// Every other string — empty, padded, wrong case or unknown — is not a
		// mode at all: it is a malformed server fact that must fail closed
		// instead of borrowing that deliberate unavailability.
		switch scannedAccessMode {
		case authorityAccessModeManaged:
		case authorityAccessModeSourceEnforced:
			notFound = true
			return nil
		default:
			persistence = true
			return nil
		}
		request = PostgreSQLAuthorityRequest{
			WorkspaceID:         lookup.WorkspaceID,
			WorkspaceSourceID:   scannedWorkspaceSourceID,
			SourceScopeID:       scannedSourceScopeID,
			ScopeConfigHash:     scannedScopeConfigHash,
			AccessMode:          scannedAccessMode,
			SourceScopeRevision: scannedScopeRevision,
		}
		resolved = true
		return nil
	})
	if readErr != nil {
		return PostgreSQLAuthorityRequest{}, &Error{code: CodePersistence}
	}
	if persistence {
		return PostgreSQLAuthorityRequest{}, &Error{code: CodePersistence}
	}
	if denied || notFound || !resolved {
		return PostgreSQLAuthorityRequest{}, &Error{code: CodeNotFound}
	}
	return request, nil
}
