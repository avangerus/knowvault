package repository

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace"
)

// PostgreSQLAuthorityRequest carries the immutable identity of one workspace
// source scope revision for which an authority decision is requested.
type PostgreSQLAuthorityRequest struct {
	WorkspaceID         string
	WorkspaceSourceID   string
	SourceScopeID       string
	ScopeConfigHash     string
	AccessMode          string
	SourceScopeRevision int64
}

// PostgreSQLAuthorityResult carries the resolved authority decision. All
// fields are private so that callers can only observe the resolved values
// through the accessor methods.
type PostgreSQLAuthorityResult struct {
	workspaceID         string
	workspaceRevision   int64
	workspaceConfigHash string
	workspaceSourceID   string
	sourceScopeID       string
	sourceScopeRevision int64
	scopeConfigHash     string
	accessMode          string
	projection          postgresqlquery.Projection
	limits              postgresqlquery.Limits
}

func (r PostgreSQLAuthorityResult) WorkspaceID() string { return r.workspaceID }

func (r PostgreSQLAuthorityResult) WorkspaceRevision() int64 { return r.workspaceRevision }

func (r PostgreSQLAuthorityResult) WorkspaceConfigurationHash() string {
	return r.workspaceConfigHash
}

func (r PostgreSQLAuthorityResult) WorkspaceSourceID() string { return r.workspaceSourceID }

func (r PostgreSQLAuthorityResult) SourceScopeID() string { return r.sourceScopeID }

func (r PostgreSQLAuthorityResult) SourceScopeRevision() int64 { return r.sourceScopeRevision }

func (r PostgreSQLAuthorityResult) ScopeConfigHash() string { return r.scopeConfigHash }

func (r PostgreSQLAuthorityResult) AccessMode() string { return r.accessMode }

// Projection returns an independent copy of the resolved projection. The
// Columns slice, every column Roles slice, is newly allocated on every call.
func (r PostgreSQLAuthorityResult) Projection() postgresqlquery.Projection {
	projection := r.projection
	projection.Columns = make([]postgresqlquery.Column, len(r.projection.Columns))
	for i, column := range r.projection.Columns {
		column.Roles = make([]postgresqlquery.Role, len(column.Roles))
		copy(column.Roles, r.projection.Columns[i].Roles)
		projection.Columns[i] = column
	}
	return projection
}

func (r PostgreSQLAuthorityResult) Limits() postgresqlquery.Limits { return r.limits }

// ResolvePostgreSQLAuthority resolves the authority decision for one exact
// workspace source scope revision through the admission boundary only. It
// validates the request and the caller's access context, then performs a single
// read that authenticates the caller, loads the current workspace snapshot,
// authorizes the workspace.ask operation and exact-compares the stored current
// configuration hash against the recomputed one. This card intentionally stops
// at that boundary: a local notFound sentinel keeps the method fail-closed
// until the exact source query is added next, so no path here can admit data.
func (store *Store) ResolvePostgreSQLAuthority(ctx context.Context, access database.AccessContext, request PostgreSQLAuthorityRequest) (PostgreSQLAuthorityResult, error) {
	if store == nil || store.database == nil || ctx == nil || access.Validate() != nil {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeRequestInvalid}
	}
	if !validID(request.WorkspaceID) || !validID(request.WorkspaceSourceID) || !validID(request.SourceScopeID) {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeRequestInvalid}
	}
	if request.SourceScopeRevision <= 0 {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeRequestInvalid}
	}
	if !workspace.IsConfigurationHash(request.ScopeConfigHash) {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeRequestInvalid}
	}
	if request.AccessMode != authorityAccessModeManaged {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeRequestInvalid}
	}
	denied := false
	notFound := false
	persistence := false
	readErr := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, storedHash, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, request.WorkspaceID, false)
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
		recomputedHash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil {
			persistence = true
			return nil
		}
		if recomputedHash != storedHash {
			persistence = true
			return nil
		}
		// The exact source query is added by the next card; until then this
		// method stays fail-closed rather than returning an admitted result.
		notFound = true
		return nil
	})
	if readErr != nil {
		return PostgreSQLAuthorityResult{}, &Error{code: CodePersistence, cause: readErr}
	}
	if persistence {
		return PostgreSQLAuthorityResult{}, &Error{code: CodePersistence}
	}
	if denied || notFound {
		return PostgreSQLAuthorityResult{}, &Error{code: CodeNotFound}
	}
	return PostgreSQLAuthorityResult{}, &Error{code: CodeNotFound}
}
