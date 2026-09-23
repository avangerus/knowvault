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
	ReadFilteredProjection(context.Context, string, string, postgresqlquery.FilteredProjectionRequest, postgresqlquery.Limits) (postgresqlquery.Snapshot, error)
}

// PostgreSQLFilteredRead is the public semantic-only description of one
// filtered source read. It names approved projection ordinals and closed typed
// values only: no Projection, SQL, schema, relation, connection target,
// credential or limit can cross this boundary.
type PostgreSQLFilteredRead struct {
	Selection  postgresqlquery.ScalarReadSelection
	Equalities []postgresqlquery.EqualityPredicate
	Period     *postgresqlquery.HalfOpenPeriod
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

// ReadFilteredBound mirrors Read for one bounded filtered projection read: it
// resolves authority immediately before the connector call and requires that
// the fresh result exactly equals the caller-supplied expected authority before
// constructing the private closed source request. The request is built and
// executed only from the fresh authority, never from the expected value. A
// strict zero snapshot with a content-free repository error is returned on any
// denial, dependency failure, binding mismatch or authority drift, and no
// connector call is made when the fresh authority does not match.
func (reader *PostgreSQLAuthorizedReader) ReadFilteredBound(ctx context.Context, access database.AccessContext, authority PostgreSQLAuthorityRequest, expected PostgreSQLAuthorityResult, read PostgreSQLFilteredRead) (postgresqlquery.Snapshot, error) {
	if reader == nil || reader.resolve == nil || reader.connector == nil || ctx == nil {
		return postgresqlquery.Snapshot{}, &Error{code: CodeRequestInvalid}
	}

	before, err := reader.resolve(ctx, access, authority)
	if err != nil {
		return postgresqlquery.Snapshot{}, opaqueRepositoryError(err)
	}
	if !samePostgreSQLAuthorityResult(expected, before.result) {
		return postgresqlquery.Snapshot{}, &Error{code: CodeNotFound}
	}

	request := detachedFilteredProjectionRequest(before.result.Projection(), read)
	snapshot, err := reader.connector.ReadFilteredProjection(
		ctx,
		before.connectionID,
		before.credentialReference,
		request,
		before.result.Limits(),
	)
	if err != nil {
		return postgresqlquery.Snapshot{}, &Error{code: CodePersistence}
	}

	after, err := reader.resolve(ctx, access, authority)
	if err != nil {
		return postgresqlquery.Snapshot{}, opaqueRepositoryError(err)
	}
	if !samePostgreSQLExecutionAuthority(before, after) {
		return postgresqlquery.Snapshot{}, &Error{code: CodeNotFound}
	}
	return snapshot, nil
}

// detachedFilteredProjectionRequest is the single construction point for the
// private closed source request. The authority projection accessor already
// returns a full deep copy; every caller-owned slice and the optional period
// pointer are newly allocated here, so a connector that retains or mutates its
// arguments cannot change retained authority or the caller's PostgreSQLFilteredRead.
func detachedFilteredProjectionRequest(projection postgresqlquery.Projection, read PostgreSQLFilteredRead) postgresqlquery.FilteredProjectionRequest {
	request := postgresqlquery.FilteredProjectionRequest{
		Projection: projection,
		Selection: postgresqlquery.ScalarReadSelection{
			OutputOrdinals:   detachedOrdinals(read.Selection.OutputOrdinals),
			IdentityOrdinals: detachedOrdinals(read.Selection.IdentityOrdinals),
			MeasureOrdinal:   read.Selection.MeasureOrdinal,
		},
	}
	if read.Equalities != nil {
		request.Equalities = make([]postgresqlquery.EqualityPredicate, len(read.Equalities))
		copy(request.Equalities, read.Equalities)
	}
	if read.Period != nil {
		period := *read.Period
		request.Period = &period
	}
	return request
}

func detachedOrdinals(ordinals []int) []int {
	if ordinals == nil {
		return nil
	}
	detached := make([]int, len(ordinals))
	copy(detached, ordinals)
	return detached
}

func opaqueRepositoryError(err error) error {
	if err == nil {
		return &Error{code: CodePersistence}
	}
	return &Error{code: CodeOf(err)}
}

// samePostgreSQLAuthorityResult compares two resolved authority decisions,
// including the authenticated organization and the full nested projection and
// limits, so that binding and drift checks cannot ignore a private field.
func samePostgreSQLAuthorityResult(left, right PostgreSQLAuthorityResult) bool {
	return left.organizationID == right.organizationID &&
		left.workspaceID == right.workspaceID &&
		left.workspaceRevision == right.workspaceRevision &&
		left.workspaceConfigHash == right.workspaceConfigHash &&
		left.workspaceSourceID == right.workspaceSourceID &&
		left.sourceScopeID == right.sourceScopeID &&
		left.sourceScopeRevision == right.sourceScopeRevision &&
		left.scopeConfigHash == right.scopeConfigHash &&
		left.accessMode == right.accessMode &&
		left.connectionRevision == right.connectionRevision &&
		reflect.DeepEqual(left.projection, right.projection) &&
		left.limits == right.limits
}

func samePostgreSQLExecutionAuthority(left, right postgreSQLExecutionAuthority) bool {
	return left.connectionID == right.connectionID &&
		left.credentialReference == right.credentialReference &&
		samePostgreSQLAuthorityResult(left.result, right.result)
}
