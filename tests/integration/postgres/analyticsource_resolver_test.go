package postgres_test

// B2.4g2b — the callable analytics source resolver and its one positive
// real-PostgreSQL proof.
//
// The proof starts from newTypedAnalyticsAuthorityFixture's fully admitted typed
// analytics POSTGRESQL_QUERY source and seeds the exact typed governed exposure
// for that source through seedTypedGovernedExposureReadSurface. It then mounts
// the one active typed analytics catalog over the independently controlled
// facts of the same source: the connection identity read directly from the
// fixture's exact current scope revision row, the full-artifact hash of the
// seeded inventory, the registered database, lineage, revision and contract
// identity, and the registered schema, relation and VIEW kind. The catalog is
// sealed by newTypedAnalyticsCatalogFixture and loaded only through the
// production mount loader, and the request names the fixture workspace plus that
// loaded catalog's own identity and its one resolved active profile.
//
// The production path under proof is exactly one call:
// analyticsource.Resolver.Resolve performs all three separately authorized
// reads itself, so this test calls no authority or exposure method directly;
// existing fixture setup may perform its own precondition check. The production
// resolution itself passes only through Resolver.Resolve and must return no
// error and a valid opaque Resolution for an admitted, exposed, actively mounted
// source.
//
// Deliberately not covered here: the authority and exposure facts themselves
// (the prior fixture proofs own them), SQL execution against the pinned
// connection, runtime freshness, an atomic-snapshot claim, mount provenance, a
// negative matrix and Question/MCP/UI wiring.

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
)

// TestTypedAnalyticsResolverResolvesAdmittedExposedMountedSource proves one
// accepted request resolves the fixture's admitted, exposed and mounted source
// through Resolver.Resolve alone: the mounted catalog declares exactly the fact
// set the three reads return, so the sealed binding is produced, and Resolve
// reports no error and one valid opaque Resolution.
func TestTypedAnalyticsResolverResolvesAdmittedExposedMountedSource(t *testing.T) {
	ctx := context.Background()
	fixture := newTypedAnalyticsAuthorityFixture(t)

	// The expected artifact hash covers the whole inventory the helper seeds, so
	// it is computed from that same slice before the canonical JSON and hash
	// pair is persisted.
	objects := []governedquery.ExposedObject{typedAnalyticsExposedObject()}
	canonicalBytes, err := canon.CanonicalJSON(objects)
	if err != nil {
		t.Fatalf("canonicalize typed analytics governed exposure artifact: %v", err)
	}
	artifactHash := canon.Hash(canonicalBytes)
	const exposureRevision = int64(1)

	seededExposure := seedTypedGovernedExposureReadSurface(t, ctx, fixture,
		typedAnalyticsDatabaseIdentity, objects)

	// The pinned connection is a direct-control fact of the fixture's exact
	// current scope revision row, so it is read here rather than derived from
	// the fixture, the mount document or the seeded exposure lookup.
	var pinnedConnectionID string
	var pinnedConnectionRevision int64
	if err := fixture.admin.QueryRow(ctx, `
		SELECT connection_id, connection_revision
		  FROM public.source_scope_revision
		 WHERE organization_id = $1 AND source_scope_id = $2 AND revision = $3`,
		fixture.binding.organizationID, fixture.request.SourceScopeID,
		fixture.request.SourceScopeRevision).Scan(&pinnedConnectionID, &pinnedConnectionRevision); err != nil {
		t.Fatalf("direct control read of the typed analytics source connection: %v", err)
	}
	if pinnedConnectionID == "" || pinnedConnectionRevision < 1 {
		t.Fatalf("direct control read returned connection id %q at revision %d, want a non-empty id at a positive pinned revision",
			pinnedConnectionID, pinnedConnectionRevision)
	}
	if seededExposure.ConnectionID != pinnedConnectionID {
		t.Fatalf("seeded governed exposure lookup connection = %q, want the independently pinned %q",
			seededExposure.ConnectionID, pinnedConnectionID)
	}

	// Every member of the source input is one independently controlled fact:
	// the admitted scope, the directly read pinned connection, the registered
	// database/lineage/revision/contract identity, the exposure revision and
	// full-artifact hash of the seeded inventory, and the registered schema,
	// relation and VIEW kind.
	sourceInput := analytic.SourceProjectionInput{
		SourceScopeID:          fixture.request.SourceScopeID,
		ConnectionID:           pinnedConnectionID,
		DatabaseIdentity:       typedAnalyticsDatabaseIdentity,
		ProjectionLineageID:    typedAnalyticsLineage,
		ProjectionRevision:     typedAnalyticsProjectionRevision,
		ProjectionContractHash: typedAnalyticsContractHash(),
		ExposedSchemaRevision:  exposureRevision,
		ExposedSchemaHash:      artifactHash,
		SchemaName:             typedAnalyticsSchema,
		RelationName:           typedAnalyticsRelation,
		RelationKind:           analytic.RelationView,
	}
	catalogFixture := newTypedAnalyticsCatalogFixture(t, sourceInput)
	loadedCatalog := catalogFixture.mountedCatalog(t)
	if !loadedCatalog.Valid() {
		t.Fatal("loaded typed analytics catalog is not valid")
	}
	profile, resolved := loadedCatalog.ResolveActive(catalogFixture.profile.Key(), catalogFixture.profile.Hash())
	if !resolved || !profile.Valid() {
		t.Fatalf("loaded typed analytics catalog resolved = %v for key %v hash %q, want the one valid active profile",
			resolved, catalogFixture.profile.Key(), catalogFixture.profile.Hash())
	}

	resolver, err := analyticsource.NewResolver(fixture.store, loadedCatalog)
	if err != nil {
		t.Fatalf("construct typed analytics resolver over the retained store and loaded catalog: %v", err)
	}
	request := analyticsource.ResolveRequest{
		WorkspaceID:     fixture.binding.workspaceID,
		CatalogID:       loadedCatalog.ID(),
		CatalogRevision: loadedCatalog.Revision(),
		CatalogHash:     loadedCatalog.Hash(),
		ProfileKey:      profile.Key(),
		ProfileHash:     profile.Hash(),
	}

	resolution, err := resolver.Resolve(ctx, fixture.access, request)
	if err != nil {
		t.Fatalf("resolve typed analytics source: %v", err)
	}
	if !resolution.Valid() {
		t.Fatal("resolved typed analytics source is not valid")
	}
}
