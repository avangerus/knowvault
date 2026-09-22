package postgres_test

// B2.4g2a1 — the typed analytics authority fixture and its one positive
// real-PostgreSQL proof.
//
// The fixture admits one workspace-managed POSTGRESQL_QUERY source whose
// registered projection is the four typed analytics columns: a bigint
// identity, a business date, a nullable numeric amount and a zoned
// observation instant. The admission sequence is exactly the existing
// admitted-authority fixture's: reset the database, seed the tenant and the
// PostgreSQL capability profile, register through the production registration
// service, verify isolation trust, seed the workspace binding, issue the
// runtime grant, confirm the managed source, open the worker queue, bootstrap
// the scheduled scope, and prove the admitted request resolves.
//
// The proof asserts facts and adds no behavior: the authority lookup
// (Store.ResolvePostgreSQLAuthorityRequest) returns one candidate that equals
// the admitted request exactly, and the authority resolver
// (Store.ResolvePostgreSQLAuthority) accepts that candidate unchanged and
// returns the exact workspace/source/connection identity with the exact
// ordered projection.
//
// Deliberately not covered here: the analytics catalog, profile JSON, governed
// exposure, analyticsource.Resolver, SQL execution and negative cases.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	// typedAnalyticsDatabaseIdentity is the non-secret database identity the
	// typed analytics projection registers.
	typedAnalyticsDatabaseIdentity = "typed-analytics-cluster"

	typedAnalyticsSchema   = "typed_analytics"
	typedAnalyticsRelation = "operations"
	typedAnalyticsLineage  = "typed-analytics-lineage"
	typedAnalyticsName     = "Typed analytics operations"

	typedAnalyticsProjectionRevision = int64(1)
)

// typedAnalyticsContractHash is the fixed sha256 projection contract hash the
// typed analytics request registers.
func typedAnalyticsContractHash() string { return "sha256:" + strings.Repeat("b", 64) }

// typedAnalyticsColumn is one column of the registered typed analytics
// projection. The registered request and the assertion read this one table, so
// the fingerprint, logical type, roles, nullability, precision and scale the
// resolver returns cannot drift from the ones the fixture admitted.
type typedAnalyticsColumn struct {
	name        string
	fingerprint string
	logicalType postgresqlquery.LogicalType
	roles       []postgresqlquery.Role
	nullable    bool
	precision   int
	scale       int
	maxBytes    int
}

// typedAnalyticsColumns is the fixture's complete column inventory in
// registered ordinal order.
func typedAnalyticsColumns() []typedAnalyticsColumn {
	return []typedAnalyticsColumn{
		{
			name: "operation_id", fingerprint: "oid:20", logicalType: postgresqlquery.TypeInt,
			roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, maxBytes: 32,
		},
		{
			name: "operation_day", fingerprint: "oid:1082", logicalType: postgresqlquery.TypeDate,
			roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, maxBytes: 32,
		},
		{
			name: "amount", fingerprint: "oid:1700:p:12:s:3", logicalType: postgresqlquery.TypeNumeric,
			roles:    []postgresqlquery.Role{postgresqlquery.RoleEvidence},
			nullable: true, precision: 12, scale: 3, maxBytes: 64,
		},
		{
			name: "observed_at", fingerprint: "oid:1184:p:3", logicalType: postgresqlquery.TypeTimestamptz,
			roles:     []postgresqlquery.Role{postgresqlquery.RoleVersionHint, postgresqlquery.RoleEvidence},
			precision: 3, maxBytes: 64,
		},
	}
}

// typedAnalyticsProjectionRequest is the one registration request the typed
// analytics fixture admits: the four columns above, relation kind VIEW and a
// HELD empty-snapshot policy.
func typedAnalyticsProjectionRequest(schema, relation, lineage, name, contractHash string) registration.RegisterRequest {
	columns := make([]postgresqlquery.Column, 0, len(typedAnalyticsColumns()))
	for index, column := range typedAnalyticsColumns() {
		columns = append(columns, postgresqlquery.Column{
			Ordinal: index + 1, Name: column.name, TypeFingerprint: column.fingerprint,
			LogicalType: column.logicalType, Roles: slices.Clone(column.roles), Nullable: column.nullable,
			Precision: column.precision, Scale: column.scale, MaxBytes: column.maxBytes,
		})
	}
	return registration.RegisterRequest{
		SourceType: "POSTGRESQL_QUERY", Name: name, Kind: "business-object",
		DatabaseIdentity: typedAnalyticsDatabaseIdentity, LineageID: lineage,
		ProjectionRevision: typedAnalyticsProjectionRevision, ContractHash: contractHash,
		SchemaName: schema, RelationName: relation, RelationKind: "VIEW",
		EmptySnapshotPolicy: "HELD", Columns: columns,
	}
}

// newTypedAnalyticsAuthorityFixture admits the typed analytics projection
// through the same production chain newAdmittedAuthorityFixture admits its
// projection through, with the same credential sentinel and limits, and
// returns the fixture whose request names the admitted projection exactly.
func newTypedAnalyticsAuthorityFixture(t *testing.T) admittedAuthorityFixture {
	t.Helper()
	ctx := context.Background()
	admin := resetStage1Database(t)
	_, _, service := seedRegistrationTenant(t, ctx, admin)
	seedIsolationPostgreSQLProfile(t, ctx, admin)

	request := typedAnalyticsProjectionRequest(typedAnalyticsSchema, typedAnalyticsRelation,
		typedAnalyticsLineage, typedAnalyticsName, typedAnalyticsContractHash())
	request.CredentialReference = authorityCredentialSentinel
	request.MaxRows = 73
	request.MaxColumns = len(request.Columns)
	request.MaxFieldBytes = 512
	request.MaxRowBytes = 2048
	request.MaxTotalBytes = 8192
	request.StatementTimeoutMS = 2500
	registered, err := service.Register(ctx, regOwnerAccess("req_typed_analytics_register"), request)
	if err != nil {
		t.Fatalf("register typed analytics projection: %v", err)
	}
	verifyIsolationTrust(t, ctx, admin, registered.ConnectionID)
	binding := seedRegistrationWorkspaceBinding(t, ctx, admin,
		registered.SourceScopeID, registered.ScopeConfigHash,
		agg2StableWorkspaceSourceID(regOrg, regWorkspace, registered.SourceScopeID))

	runtime := newAuthorityRuntime(t, ctx)
	grant := issueRuntimeGrant(t, ctx, runtime, binding, "typed-analytics-grant")
	confirmation, err := runtime.ConfirmManagedSource(ctx,
		authorityAccess(binding, regOwner, "req_typed_analytics_confirm"),
		confirmRuntimeRequest(binding, grant, "typed-analytics-confirm"))
	if err != nil {
		t.Fatalf("confirm typed analytics source: %v", err)
	}

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	workerQueue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatalf("create typed analytics worker queue: %v", err)
	}
	bootstrapScheduledScope(t, ctx, admin, workerStore, workerQueue, workerAccess(t, regOrg),
		registered.SourceScopeID, jobs.TypePostgreSQLQuerySync, request.ContractHash)

	store := newAuthorityRuntime(t, ctx)
	authorityRequest := workspacerepository.PostgreSQLAuthorityRequest{
		WorkspaceID:         binding.workspaceID,
		WorkspaceSourceID:   binding.workspaceSourceID,
		SourceScopeID:       registered.SourceScopeID,
		SourceScopeRevision: request.ProjectionRevision,
		ScopeConfigHash:     registered.ScopeConfigHash,
		AccessMode:          authorityAccessMode,
	}
	positive, err := store.ResolvePostgreSQLAuthority(ctx,
		authorityAccess(binding, regOwner, "req_typed_analytics_precondition"), authorityRequest)
	if err != nil {
		t.Fatalf("typed analytics authority precondition resolve: %v", err)
	}
	if err := positive.Projection().Validate(); err != nil {
		t.Fatalf("typed analytics authority projection invalid: %v", err)
	}
	if err := positive.Limits().Validate(); err != nil {
		t.Fatalf("typed analytics authority limits invalid: %v", err)
	}
	return admittedAuthorityFixture{
		admin: admin, store: store,
		access:  authorityAccess(binding, regOwner, "req_typed_analytics_resolve"),
		request: authorityRequest, binding: binding,
		grant: grant, confirmation: confirmation,
	}
}

// TestTypedAnalyticsAuthorityRequestResolvesAdmittedProjection proves the
// lookup candidate is the admitted typed analytics request, that the resolver
// accepts that exact candidate, and that the resolved identity and projection
// are the admitted ones.
func TestTypedAnalyticsAuthorityRequestResolvesAdmittedProjection(t *testing.T) {
	ctx := context.Background()
	fixture := newTypedAnalyticsAuthorityFixture(t)

	// The exact connection identity is one direct-control fact: the lookup is
	// keyed on it, so it is read from the exact scope revision row rather than
	// derived from the fixture. The same row pins the connection revision the
	// resolver reports, so that is read independently here as well.
	var connectionID string
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		FROM public.source_scope_revision
		WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		regOrg, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
		t.Fatalf("direct control read of the typed analytics source connection: %v", err)
	}
	if connectionID == "" || connectionRevision < 1 {
		t.Fatalf("direct control read returned connection id %q at revision %d, want a non-empty id at a positive pinned revision",
			connectionID, connectionRevision)
	}

	candidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access,
		workspacerepository.PostgreSQLAuthorityLookup{
			WorkspaceID:   fixture.request.WorkspaceID,
			SourceScopeID: fixture.request.SourceScopeID,
			ConnectionID:  connectionID,
		})
	if err != nil {
		t.Fatalf("resolve typed analytics authority request: %v", err)
	}
	if candidate != fixture.request {
		t.Fatalf("typed analytics candidate = %#v, want the admitted request %#v", candidate, fixture.request)
	}

	resolved, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, candidate)
	if err != nil {
		t.Fatalf("resolve typed analytics authority: %v", err)
	}
	if resolved.WorkspaceID() != fixture.request.WorkspaceID ||
		resolved.WorkspaceRevision() != fixture.binding.workspaceRevision ||
		resolved.WorkspaceConfigurationHash() != fixture.binding.workspaceConfHash ||
		resolved.WorkspaceSourceID() != fixture.request.WorkspaceSourceID ||
		resolved.SourceScopeID() != fixture.request.SourceScopeID ||
		resolved.SourceScopeRevision() != fixture.request.SourceScopeRevision ||
		resolved.ScopeConfigHash() != fixture.request.ScopeConfigHash ||
		resolved.AccessMode() != fixture.request.AccessMode {
		t.Fatalf("typed analytics authority identity drifted: workspace=%q revision=%d hash=%q source=%q scope=%q scope_revision=%d scope_hash=%q mode=%q connection_revision=%d",
			resolved.WorkspaceID(), resolved.WorkspaceRevision(), resolved.WorkspaceConfigurationHash(),
			resolved.WorkspaceSourceID(), resolved.SourceScopeID(), resolved.SourceScopeRevision(),
			resolved.ScopeConfigHash(), resolved.AccessMode(), resolved.ConnectionRevision())
	}
	if resolved.ConnectionRevision() != connectionRevision {
		t.Fatalf("typed analytics authority connection revision = %d, want the pinned %d",
			resolved.ConnectionRevision(), connectionRevision)
	}
	projection := resolved.Projection()
	if err := projection.Validate(); err != nil {
		t.Fatalf("typed analytics authority projection invalid: %v", err)
	}
	if err := resolved.Limits().Validate(); err != nil {
		t.Fatalf("typed analytics authority limits invalid: %v", err)
	}
	if projection.ConnectionID != connectionID ||
		projection.DatabaseIdentity != typedAnalyticsDatabaseIdentity ||
		projection.LineageID != typedAnalyticsLineage ||
		projection.Revision != typedAnalyticsProjectionRevision ||
		projection.ContractHash != typedAnalyticsContractHash() ||
		projection.SchemaName != typedAnalyticsSchema ||
		projection.RelationName != typedAnalyticsRelation ||
		projection.RelationKind != "VIEW" ||
		projection.EmptySnapshotPolicy != "HELD" {
		t.Fatalf("typed analytics authority projection identity = %#v", projection)
	}

	columns := typedAnalyticsColumns()
	if len(projection.Columns) != len(columns) {
		t.Fatalf("typed analytics authority projection holds %d columns, want %d",
			len(projection.Columns), len(columns))
	}
	for index, column := range columns {
		resolvedColumn := projection.Columns[index]
		if resolvedColumn.Ordinal != index+1 || resolvedColumn.Name != column.name ||
			resolvedColumn.TypeFingerprint != column.fingerprint ||
			resolvedColumn.LogicalType != column.logicalType ||
			!slices.Equal(resolvedColumn.Roles, column.roles) ||
			resolvedColumn.Nullable != column.nullable ||
			resolvedColumn.Precision != column.precision || resolvedColumn.Scale != column.scale {
			t.Fatalf("typed analytics projection column %d = %#v, want %#v", index+1, resolvedColumn, column)
		}
	}
}
