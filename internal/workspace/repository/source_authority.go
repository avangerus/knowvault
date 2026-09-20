package repository

import "knowvault.local/verified-workspace/internal/source/postgresqlquery"

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
