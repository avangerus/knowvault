package postgres_test

// B2.4g2a2b2 — the mounted typed analytics profile joined to real authority and
// exposure facts.
//
// The proof starts from newTypedAnalyticsAuthorityFixture's fully admitted typed
// analytics POSTGRESQL_QUERY source, seeds the governed read surface with the
// fixture's one exposed object, reads the connection identity the fixture's
// exact scope revision pinned directly from public.source_scope_revision, and
// builds the one analytic.SourceProjectionInput from those independently
// controlled facts alone. The catalog is then sealed by
// newTypedAnalyticsCatalogFixture, mounted through the production mount loader
// and resolved once; every later lookup and assertion reads that one retained
// loaded catalog and profile.
//
// Both lookups are derived from the loaded profile's source DTO with only the
// fixture workspace id added, so a mounted catalog whose approved projection
// drifted from the seeded read surface cannot resolve: the profile-derived
// governed exposure lookup must equal the seeded one, the authority lookup must
// select exactly the admitted request, and the resolved authority and exposure
// results must agree on the workspace, source scope, connection and database
// identities, the independently pinned connection revision, the exposure
// revision and the full-artifact hash computed from the seeded inventory.
//
// The proof asserts facts and adds no behavior. The loaded source DTO must
// equal the independent input and match the authority projection's lineage,
// revision, contract hash, schema, relation and kind plus the exposure
// revision, artifact hash, database identity and connection id; exposure must
// be live-enabled and retain exactly the four ordered column names; the loaded
// profile must hold exactly four fields in source ordinal order matching the
// fixed catalog fixture; and the registered authority projection must hold
// exactly four columns in ordinal order with the exact existing fingerprints,
// PostgreSQL logical types and nullability, carrying the numeric and temporal
// precision and scale that belong to the registered projection alone. The run
// finishes by constructing analyticsource.NewResolver over the fixture store
// and the one loaded catalog.
//
// Deliberately not covered here: Resolver.Resolve, SQL execution against the
// pinned connection, runtime freshness, an atomic-snapshot claim, mount
// provenance, a negative matrix and Question/MCP/UI wiring.

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestMountedTypedAnalyticsProfileMatchesRepositoryFacts proves the mounted
// typed analytics catalog profile resolves the real authority and governed
// exposure facts of the fixture's admitted source: both lookups come from the
// loaded profile's source DTO, the authority candidate is the admitted request
// exactly, the resolved authority projection and exposure result agree on every
// shared identity, and the loaded profile, the four-field catalog fixture and
// the registered projection carry exactly the same typed analytics columns.
func TestMountedTypedAnalyticsProfileMatchesRepositoryFacts(t *testing.T) {
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
	artifactHash := canon.Hash(canonicalBytes)
	const exposureRevision = int64(1)

	seededLookup := seedTypedGovernedExposureReadSurface(t, ctx, fixture,
		typedAnalyticsDatabaseIdentity, objects)

	// The pinned connection is a direct-control fact of the fixture's exact
	// current scope revision row, so it is read here rather than derived from
	// the fixture, the mount document or the seeded lookup.
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
	if seededLookup.ConnectionID != pinnedConnectionID {
		t.Fatalf("seeded governed exposure lookup connection = %q, want the independently pinned %q",
			seededLookup.ConnectionID, pinnedConnectionID)
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

	loadedSource := profile.Source().Values()
	if loadedSource != sourceInput {
		t.Fatalf("loaded typed analytics source DTO = %#v, want the independent input %#v", loadedSource, sourceInput)
	}

	// The caller cannot name a source scope, connection, schema or relation:
	// both lookups are the loaded source DTO plus the fixture workspace id.
	authorityLookup := workspacerepository.PostgreSQLAuthorityLookup{
		WorkspaceID:   fixture.binding.workspaceID,
		SourceScopeID: loadedSource.SourceScopeID,
		ConnectionID:  loadedSource.ConnectionID,
	}
	exposureLookup := workspacerepository.GovernedExposureLookup{
		WorkspaceID:   fixture.binding.workspaceID,
		SourceScopeID: loadedSource.SourceScopeID,
		ConnectionID:  loadedSource.ConnectionID,
		SchemaName:    loadedSource.SchemaName,
		RelationName:  loadedSource.RelationName,
	}
	if exposureLookup != seededLookup {
		t.Fatalf("profile-derived governed exposure lookup = %#v, want the seeded read surface %#v",
			exposureLookup, seededLookup)
	}

	candidate, err := fixture.store.ResolvePostgreSQLAuthorityRequest(ctx, fixture.access, authorityLookup)
	if err != nil {
		t.Fatalf("resolve typed analytics authority request from the mounted profile: %v (code=%s)",
			err, workspacerepository.CodeOf(err))
	}
	if candidate != fixture.request {
		t.Fatalf("mounted typed analytics authority candidate = %#v, want the admitted request %#v",
			candidate, fixture.request)
	}

	authority, err := fixture.store.ResolvePostgreSQLAuthority(ctx, fixture.access, candidate)
	if err != nil {
		t.Fatalf("resolve typed analytics authority from the mounted profile: %v (code=%s)",
			err, workspacerepository.CodeOf(err))
	}
	exposure, err := fixture.store.ResolveGovernedExposure(ctx, fixture.access, exposureLookup)
	if err != nil {
		t.Fatalf("resolve typed analytics governed exposure from the mounted profile: %v (code=%s)",
			err, workspacerepository.CodeOf(err))
	}

	if !exposure.Valid() {
		t.Fatal("resolved typed analytics governed exposure result is not valid")
	}
	projection := authority.Projection()
	if err := projection.Validate(); err != nil {
		t.Fatalf("resolved typed analytics authority projection invalid: %v", err)
	}
	if err := authority.Limits().Validate(); err != nil {
		t.Fatalf("resolved typed analytics authority limits invalid: %v", err)
	}

	// Authority and governed exposure describe the same source scope revision,
	// so each shared identity must be the fixture fact in both results.
	for _, scalar := range []struct {
		name      string
		authority string
		exposure  string
		want      string
	}{
		{"workspace id", authority.WorkspaceID(), exposure.WorkspaceID(), fixture.binding.workspaceID},
		{"workspace configuration hash", authority.WorkspaceConfigurationHash(), exposure.WorkspaceConfigurationHash(), fixture.binding.workspaceConfHash},
		{"workspace source id", authority.WorkspaceSourceID(), exposure.WorkspaceSourceID(), fixture.binding.workspaceSourceID},
		{"source scope id", authority.SourceScopeID(), exposure.SourceScopeID(), fixture.request.SourceScopeID},
		{"source scope configuration hash", authority.ScopeConfigHash(), exposure.SourceScopeConfigurationHash(), fixture.request.ScopeConfigHash},
		{"connection id", projection.ConnectionID, exposure.ConnectionID(), pinnedConnectionID},
		{"database identity", projection.DatabaseIdentity, exposure.DatabaseIdentity(), typedAnalyticsDatabaseIdentity},
	} {
		if scalar.authority != scalar.want || scalar.exposure != scalar.want {
			t.Fatalf("%s = authority %q exposure %q, want %q in both",
				scalar.name, scalar.authority, scalar.exposure, scalar.want)
		}
	}
	for _, revision := range []struct {
		name      string
		authority int64
		exposure  int64
		want      int64
	}{
		{"workspace revision", authority.WorkspaceRevision(), exposure.WorkspaceRevision(), fixture.binding.workspaceRevision},
		{"source scope revision", authority.SourceScopeRevision(), exposure.SourceScopeRevision(), fixture.request.SourceScopeRevision},
		{"connection revision", authority.ConnectionRevision(), exposure.ConnectionRevision(), pinnedConnectionRevision},
	} {
		if revision.authority != revision.want || revision.exposure != revision.want {
			t.Fatalf("%s = authority %d exposure %d, want the independently pinned %d in both",
				revision.name, revision.authority, revision.exposure, revision.want)
		}
	}
	// The loaded profile must approve exactly the projection the authority
	// read returned and exactly the exposure revision the loader re-derived.
	if loadedSource.ProjectionLineageID != projection.LineageID ||
		loadedSource.ProjectionRevision != projection.Revision ||
		loadedSource.ProjectionContractHash != projection.ContractHash ||
		loadedSource.SchemaName != projection.SchemaName ||
		loadedSource.RelationName != projection.RelationName ||
		loadedSource.RelationKind != analytic.RelationKind(projection.RelationKind) {
		t.Fatalf("loaded typed analytics source projection = %#v, want lineage %q revision %d contract %q schema %q relation %q kind %q",
			loadedSource, projection.LineageID, projection.Revision, projection.ContractHash,
			projection.SchemaName, projection.RelationName, projection.RelationKind)
	}
	if loadedSource.SourceScopeID != exposure.SourceScopeID() ||
		loadedSource.ConnectionID != exposure.ConnectionID() ||
		loadedSource.DatabaseIdentity != exposure.DatabaseIdentity() ||
		loadedSource.ExposedSchemaRevision != exposure.ExposureRevision() ||
		loadedSource.ExposedSchemaHash != exposure.ExposureArtifactHash() {
		t.Fatalf("loaded typed analytics source read surface = %#v, want scope %q connection %q database %q exposure revision %d artifact hash %q",
			loadedSource, exposure.SourceScopeID(), exposure.ConnectionID(),
			exposure.DatabaseIdentity(), exposure.ExposureRevision(), exposure.ExposureArtifactHash())
	}

	if !exposure.LiveQueryEnabled() {
		t.Fatal("live query flag = false, want this workspace's enabled binding")
	}
	wantColumns := make([]string, 0, len(objects[0].Columns))
	for _, column := range objects[0].Columns {
		wantColumns = append(wantColumns, column.Name)
	}
	if len(wantColumns) != 4 {
		t.Fatalf("seeded typed analytics object holds %d columns, want exactly four", len(wantColumns))
	}
	if columns := exposure.Columns(); !slices.Equal(columns, wantColumns) {
		t.Fatalf("exposure columns = %v, want the seeded object's ordered names %v", columns, wantColumns)
	}

	// The loaded profile is the fixed four-column catalog fixture: one field
	// per source ordinal, with the exact field DTO the constructors sealed.
	fields := profile.Fields()
	if len(fields) != len(catalogFixture.columns) || len(catalogFixture.columns) != 4 {
		t.Fatalf("loaded profile holds %d fields, want the %d fixed catalog columns",
			len(fields), len(catalogFixture.columns))
	}
	for index, column := range catalogFixture.columns {
		got := fields[index].Values()
		if got.Token != column.token || got.PhysicalName != column.physicalName ||
			got.LogicalType != column.logicalType || got.PhysicalType != column.physicalType ||
			got.Nullable != column.nullable {
			t.Fatalf("loaded field %d identity = %#v, want token %q physical name %q logical %q physical %q nullable %v",
				index+1, got, column.token, column.physicalName,
				column.logicalType, column.physicalType, column.nullable)
		}
		if want := catalogFixture.profile.Fields()[index].Values(); !reflect.DeepEqual(got, want) {
			t.Fatalf("loaded field %d DTO = %#v, want %#v", index+1, got, want)
		}
	}
	if profile.Key() != catalogFixture.profile.Key() || profile.Hash() != catalogFixture.profile.Hash() {
		t.Fatalf("loaded profile = key %v hash %q, want key %v hash %q",
			profile.Key(), profile.Hash(), catalogFixture.profile.Key(), catalogFixture.profile.Hash())
	}

	// The numeric and temporal precision and scale belong to the registered
	// authority projection alone; the profile stores only the logical and
	// physical type families asserted above.
	authorityColumns := typedAnalyticsColumns()
	if len(projection.Columns) != len(authorityColumns) || len(authorityColumns) != 4 {
		t.Fatalf("resolved authority projection holds %d columns, want the %d registered columns",
			len(projection.Columns), len(authorityColumns))
	}
	for index, column := range authorityColumns {
		got := projection.Columns[index]
		if got.Ordinal != index+1 || got.Name != column.name ||
			got.TypeFingerprint != column.fingerprint ||
			got.LogicalType != column.logicalType ||
			!slices.Equal(got.Roles, column.roles) ||
			got.Nullable != column.nullable ||
			got.Precision != column.precision || got.Scale != column.scale {
			t.Fatalf("resolved authority projection column %d = %#v, want %#v", index+1, got, column)
		}
	}

	resolver, err := analyticsource.NewResolver(fixture.store, loadedCatalog)
	if err != nil {
		t.Fatalf("construct typed analytics resolver over the retained store and loaded catalog: %v", err)
	}
	if resolver == nil {
		t.Fatal("constructed typed analytics resolver is nil")
	}
}
