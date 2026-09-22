package postgres_test

// B2.4g2a2a — the typed governed-exposure fixture and its one positive
// real-PostgreSQL proof.
//
// The fixture starts from newTypedAnalyticsAuthorityFixture's fully admitted
// typed analytics POSTGRESQL_QUERY source and seeds only the governed read
// surface the loader rebinds: the governed_query_connection for the exact
// connection the fixture's current scope revision pinned, this workspace's
// enabled governed_query_workspace_binding, and exposure revision 1 holding the
// caller's one typed analytics object. It reuses the existing
// seedGovernedExposureRevision, so the canonical JSON and hash the loader
// re-derives are the ones production registration persists.
//
// The proof asserts facts and adds no behavior: the exact lookup resolves
// through Store.ResolveGovernedExposure to the fixture's workspace, source
// scope and connection identities, the independently read connection revision,
// the supplied database identity, the enabled live-query flag, exposure
// revision 1 with the expected full-artifact hash, and exactly the four ordered
// typed analytics column names.
//
// Deliberately not covered here: the analytics catalog, profile JSON,
// analyticsource.Resolver, source-authority changes, SQL execution against an
// external database and negative cases.

import (
	"context"
	"slices"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// seedTypedGovernedExposureReadSurface seeds the governed read surface for the
// typed analytics fixture's exact pinned connection — the governed connection
// carrying databaseIdentity, this workspace's binding with live queries enabled,
// and exposure revision 1 holding objects — through the same canonical JSON and
// hash pair the existing seedGovernedExposureRevision writes. It returns the
// lookup naming the fixture workspace, source scope, connection and the single
// supplied object's schema/relation, so the caller supplies the exposed
// inventory while every other bound identity stays a fact of the fixture.
func seedTypedGovernedExposureReadSurface(
	t *testing.T,
	ctx context.Context,
	fixture admittedAuthorityFixture,
	databaseIdentity string,
	objects []governedquery.ExposedObject,
) workspacerepository.GovernedExposureLookup {
	t.Helper()
	if len(objects) != 1 {
		t.Fatalf("typed governed exposure fixture holds %d exposed objects, want exactly one", len(objects))
	}

	// The pinned connection is a fact of the fixture's exact current scope
	// chain, not of the lookup: read the same source_scope_revision row the
	// loader rebinds.
	var connectionID string
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionID, &connectionRevision); err != nil {
		t.Fatalf("load pinned typed analytics source connection: %v", err)
	}
	if connectionID == "" || connectionRevision < 1 {
		t.Fatalf("pinned typed analytics source connection = %q revision %d, want a non-empty id at a positive revision",
			connectionID, connectionRevision)
	}

	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_connection
		    (organization_id, id, workspace_id, database_identity, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $5)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		databaseIdentity, fixture.binding.ownerID); err != nil {
		t.Fatalf("seed typed analytics governed query connection: %v", err)
	}
	if _, err := fixture.admin.Exec(ctx, `
		INSERT INTO public.governed_query_workspace_binding
		    (organization_id, connection_id, workspace_id, live_queries_enabled, created_by, updated_by)
		VALUES ($1, $2, $3, true, $4, $4)`,
		fixture.binding.organizationID, connectionID, fixture.binding.workspaceID,
		fixture.binding.ownerID); err != nil {
		t.Fatalf("seed typed analytics governed query workspace binding: %v", err)
	}
	seedGovernedExposureRevision(t, ctx, fixture, connectionID, 1, objects)

	return workspacerepository.GovernedExposureLookup{
		WorkspaceID:   fixture.binding.workspaceID,
		SourceScopeID: fixture.request.SourceScopeID,
		ConnectionID:  connectionID,
		SchemaName:    objects[0].SchemaName,
		RelationName:  objects[0].TableName,
	}
}

// typedAnalyticsExposedObject is the one exposed object the typed analytics
// governed-exposure proof seeds: the registered typed analytics relation with
// its four canonical data-type columns in registered ordinal order.
func typedAnalyticsExposedObject() governedquery.ExposedObject {
	return governedquery.ExposedObject{
		SchemaName:  typedAnalyticsSchema,
		TableName:   typedAnalyticsRelation,
		Description: "Typed analytics operations exposed for governed queries.",
		Columns: []governedquery.ExposedColumn{
			{Name: "operation_id", DataType: "bigint", Description: "Operation identifier."},
			{Name: "operation_day", DataType: "date", Description: "Business day of the operation."},
			{Name: "amount", DataType: "numeric", Description: "Signed operation amount."},
			{Name: "observed_at", DataType: "timestamptz", Description: "Instant the operation was observed."},
		},
	}
}

// TestTypedAnalyticsGovernedExposureResolvesExactReadSurface proves the typed
// analytics fixture resolves through the governed-exposure loader: the lookup
// seeded over the fixture's pinned connection returns the fixture's exact
// workspace, source scope and connection facts, the independently read
// connection revision, the supplied database identity, exposure revision 1 with
// the full-artifact hash of the seeded object, and exactly the four ordered
// column names.
func TestTypedAnalyticsGovernedExposureResolvesExactReadSurface(t *testing.T) {
	ctx := context.Background()
	fixture := newTypedAnalyticsAuthorityFixture(t)

	// The expected artifact hash covers the whole inventory the helper seeds,
	// so it is computed from that same slice before the canonical JSON and hash
	// pair is persisted.
	objects := []governedquery.ExposedObject{typedAnalyticsExposedObject()}
	canonicalBytes, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatalf("canonicalize typed analytics governed exposure artifact: %v", err)
	}
	wantArtifactHash := canon.Hash(canonicalBytes)

	lookup := seedTypedGovernedExposureReadSurface(t, ctx, fixture,
		typedAnalyticsDatabaseIdentity, objects)

	// The resolver reports the connection revision the scope revision pinned,
	// so it is read independently from that exact row rather than inferred from
	// the fixture or from the seeded exposure artifact.
	var connectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&connectionRevision); err != nil {
		t.Fatalf("direct control read of the typed analytics connection revision: %v", err)
	}
	if connectionRevision < 1 {
		t.Fatalf("direct control read returned connection revision %d, want a positive pinned revision",
			connectionRevision)
	}

	result, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, lookup)
	if err != nil {
		t.Fatalf("resolve typed analytics governed exposure: %v (code=%s)",
			err, workspacerepository.CodeOf(err))
	}
	if !result.Valid() {
		t.Fatal("resolved typed analytics governed exposure result is not valid")
	}

	for _, scalar := range []struct {
		name string
		got  string
		want string
	}{
		{"workspace id", result.WorkspaceID(), fixture.binding.workspaceID},
		{"workspace configuration hash", result.WorkspaceConfigurationHash(), fixture.binding.workspaceConfHash},
		{"workspace source id", result.WorkspaceSourceID(), fixture.binding.workspaceSourceID},
		{"source scope id", result.SourceScopeID(), fixture.request.SourceScopeID},
		{"source scope configuration hash", result.SourceScopeConfigurationHash(), fixture.request.ScopeConfigHash},
		{"connection id", result.ConnectionID(), lookup.ConnectionID},
		{"database identity", result.DatabaseIdentity(), typedAnalyticsDatabaseIdentity},
		{"exposure artifact hash", result.ExposureArtifactHash(), wantArtifactHash},
		{"schema", result.SchemaName(), typedAnalyticsSchema},
		{"relation", result.RelationName(), typedAnalyticsRelation},
	} {
		if scalar.got != scalar.want {
			t.Fatalf("%s = %q, want %q", scalar.name, scalar.got, scalar.want)
		}
	}
	for _, revision := range []struct {
		name string
		got  int64
		want int64
	}{
		{"workspace revision", result.WorkspaceRevision(), fixture.binding.workspaceRevision},
		{"source scope revision", result.SourceScopeRevision(), fixture.request.SourceScopeRevision},
		{"connection revision", result.ConnectionRevision(), connectionRevision},
		{"exposure revision", result.ExposureRevision(), 1},
	} {
		if revision.got != revision.want {
			t.Fatalf("%s = %d, want %d", revision.name, revision.got, revision.want)
		}
	}
	if !result.LiveQueryEnabled() {
		t.Fatal("live query flag = false, want this workspace's enabled binding")
	}
	wantColumns := []string{"operation_id", "operation_day", "amount", "observed_at"}
	if columns := result.Columns(); !slices.Equal(columns, wantColumns) {
		t.Fatalf("columns = %v, want %v", columns, wantColumns)
	}
}
