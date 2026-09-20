package repository

import (
	"context"
	"reflect"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// PostgreSQLProjectionConnector is the narrow external-read capability used
// after workspace admission. Implementations receive only the private target
// resolved by the repository and the server-owned projection and limits.
type PostgreSQLProjectionConnector interface {
	ReadProjection(context.Context, string, string, postgresqlquery.Projection, postgresqlquery.Limits) (postgresqlquery.Snapshot, error)
}

type postgreSQLExecutionAuthorityResolver func(context.Context, database.AccessContext, PostgreSQLAuthorityRequest) (postgreSQLExecutionAuthority, error)

// PostgreSQLAuthorizedReader brackets exactly one bounded external read with
// two current authority resolutions. No caller-provided SQL, credential,
// projection or limit reaches the connector.
type PostgreSQLAuthorizedReader struct {
	resolve   postgreSQLExecutionAuthorityResolver
	connector PostgreSQLProjectionConnector
}

func NewPostgreSQLAuthorizedReader(store *Store, connector PostgreSQLProjectionConnector) (*PostgreSQLAuthorizedReader, error) {
	if store == nil || store.database == nil || connector == nil {
		return nil, &Error{code: CodePersistence}
	}
	return &PostgreSQLAuthorizedReader{
		resolve:   store.resolvePostgreSQLExecutionAuthority,
		connector: connector,
	}, nil
}

// Read resolves authority immediately before and after one connector call.
// Any denial, dependency failure or authority drift returns a strict zero
// snapshot and a content-free repository error with no wrapped cause.
func (reader *PostgreSQLAuthorizedReader) Read(ctx context.Context, access database.AccessContext, request PostgreSQLAuthorityRequest) (postgresqlquery.Snapshot, error) {
	if reader == nil || reader.resolve == nil || reader.connector == nil || ctx == nil {
		return postgresqlquery.Snapshot{}, &Error{code: CodeRequestInvalid}
	}

	before, err := reader.resolve(ctx, access, request)
	if err != nil {
		return postgresqlquery.Snapshot{}, opaqueRepositoryError(err)
	}

	// Projection returns a full deep copy, including every nested Roles slice.
	// The connector can therefore retain or mutate its arguments without
	// changing the authority value used by the post-read comparison.
	projection := before.result.Projection()
	limits := before.result.Limits()
	snapshot, err := reader.connector.ReadProjection(
		ctx,
		before.connectionID,
		before.credentialReference,
		projection,
		limits,
	)
	if err != nil {
		return postgresqlquery.Snapshot{}, &Error{code: CodePersistence}
	}

	after, err := reader.resolve(ctx, access, request)
	if err != nil {
		return postgresqlquery.Snapshot{}, opaqueRepositoryError(err)
	}
	if !samePostgreSQLExecutionAuthority(before, after) {
		return postgresqlquery.Snapshot{}, &Error{code: CodeNotFound}
	}
	return snapshot, nil
}

func opaqueRepositoryError(err error) error {
	if err == nil {
		return &Error{code: CodePersistence}
	}
	return &Error{code: CodeOf(err)}
}

func samePostgreSQLExecutionAuthority(left, right postgreSQLExecutionAuthority) bool {
	return left.connectionID == right.connectionID &&
		left.connectionRevision == right.connectionRevision &&
		left.credentialReference == right.credentialReference &&
		left.result.workspaceID == right.result.workspaceID &&
		left.result.workspaceRevision == right.result.workspaceRevision &&
		left.result.workspaceConfigHash == right.result.workspaceConfigHash &&
		left.result.workspaceSourceID == right.result.workspaceSourceID &&
		left.result.sourceScopeID == right.result.sourceScopeID &&
		left.result.sourceScopeRevision == right.result.sourceScopeRevision &&
		left.result.scopeConfigHash == right.result.scopeConfigHash &&
		left.result.accessMode == right.result.accessMode &&
		reflect.DeepEqual(left.result.projection, right.result.projection) &&
		left.result.limits == right.result.limits
}
