package analyticsource

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	repositoryCatalogID             = "fixture_catalog"
	repositoryCatalogRevision int64 = 4
)

// bindRepositoryResultsConcreteSignature pins the public wrapper to exactly the
// two concrete repository result types. A repository accessor type change breaks
// this file's build instead of silently relaxing what the adapter accepts.
var bindRepositoryResultsConcreteSignature func(
	repositoryBindingExpectation,
	analytic.DatasetProfileCatalog,
	repository.PostgreSQLAuthorityResult,
	repository.GovernedExposureResult,
) (eligibilityBinding, error) = bindRepositoryResults

// fakeRepositorySource is the compact in-memory stand-in for one concrete
// PostgreSQL authority result. Every getter mirrors the real result: scalars are
// returned as stored and Projection hands back a detached copy.
type fakeRepositorySource struct {
	workspaceID                string
	workspaceRevision          int64
	workspaceConfigurationHash string
	workspaceSourceID          string
	sourceScopeID              string
	sourceScopeRevision        int64
	scopeConfigHash            string
	accessMode                 string
	connectionRevision         int64
	projection                 postgresqlquery.Projection
}

func (view fakeRepositorySource) WorkspaceID() string { return view.workspaceID }

func (view fakeRepositorySource) WorkspaceRevision() int64 { return view.workspaceRevision }

func (view fakeRepositorySource) WorkspaceConfigurationHash() string {
	return view.workspaceConfigurationHash
}

func (view fakeRepositorySource) WorkspaceSourceID() string { return view.workspaceSourceID }

func (view fakeRepositorySource) SourceScopeID() string { return view.sourceScopeID }

func (view fakeRepositorySource) SourceScopeRevision() int64 { return view.sourceScopeRevision }

func (view fakeRepositorySource) ScopeConfigHash() string { return view.scopeConfigHash }

func (view fakeRepositorySource) AccessMode() string { return view.accessMode }

func (view fakeRepositorySource) ConnectionRevision() int64 { return view.connectionRevision }

func (view fakeRepositorySource) Projection() postgresqlquery.Projection {
	projection := view.projection
	projection.Columns = append([]postgresqlquery.Column(nil), view.projection.Columns...)
	return projection
}

// fakeRepositoryExposure is the compact in-memory stand-in for one concrete
// governed exposure result. Valid reports only the resolved bit and Columns
// hands back a detached copy, exactly as the real result does.
type fakeRepositoryExposure struct {
	resolved                     bool
	workspaceID                  string
	workspaceRevision            int64
	workspaceConfigurationHash   string
	workspaceSourceID            string
	sourceScopeID                string
	sourceScopeRevision          int64
	sourceScopeConfigurationHash string
	connectionID                 string
	connectionRevision           int64
	databaseIdentity             string
	liveQueryEnabled             bool
	exposureRevision             int64
	exposureArtifactHash         string
	schemaName                   string
	relationName                 string
	columns                      []string
}

func (view fakeRepositoryExposure) Valid() bool { return view.resolved }

func (view fakeRepositoryExposure) WorkspaceID() string { return view.workspaceID }

func (view fakeRepositoryExposure) WorkspaceRevision() int64 { return view.workspaceRevision }

func (view fakeRepositoryExposure) WorkspaceConfigurationHash() string {
	return view.workspaceConfigurationHash
}

func (view fakeRepositoryExposure) WorkspaceSourceID() string { return view.workspaceSourceID }

func (view fakeRepositoryExposure) SourceScopeID() string { return view.sourceScopeID }

func (view fakeRepositoryExposure) SourceScopeRevision() int64 { return view.sourceScopeRevision }

func (view fakeRepositoryExposure) SourceScopeConfigurationHash() string {
	return view.sourceScopeConfigurationHash
}

func (view fakeRepositoryExposure) ConnectionID() string { return view.connectionID }

func (view fakeRepositoryExposure) ConnectionRevision() int64 { return view.connectionRevision }

func (view fakeRepositoryExposure) DatabaseIdentity() string { return view.databaseIdentity }

func (view fakeRepositoryExposure) LiveQueryEnabled() bool { return view.liveQueryEnabled }

func (view fakeRepositoryExposure) ExposureRevision() int64 { return view.exposureRevision }

func (view fakeRepositoryExposure) ExposureArtifactHash() string { return view.exposureArtifactHash }

func (view fakeRepositoryExposure) SchemaName() string { return view.schemaName }

func (view fakeRepositoryExposure) RelationName() string { return view.relationName }

func (view fakeRepositoryExposure) Columns() []string {
	if view.columns == nil {
		return nil
	}
	columns := make([]string, len(view.columns))
	copy(columns, view.columns)
	return columns
}

// repositoryFixture pairs one frozen catalog selection and the expectation that
// names it with the two fake views that report matching concrete results.
type repositoryFixture struct {
	expectation repositoryBindingExpectation
	catalog     analytic.DatasetProfileCatalog
	profile     analytic.DatasetProfile
	binding     bindingFacts
	source      fakeRepositorySource
	exposure    fakeRepositoryExposure
}

// repositoryFixtureFor derives the expectation, the catalog, the exact common
// tuple, the source projection and both inventories from one sealed profile. It
// reuses the matcher's own governed fixture, so the adapter fixture cannot drift
// from the facts the matcher already accepts.
func repositoryFixtureFor(t *testing.T, profile analytic.DatasetProfile) repositoryFixture {
	t.Helper()
	columns, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("fixture inventory refused: %v", err)
	}
	facts := governedMatchFixture(t, profile, columns)
	catalog := repositoryCatalog(t, profile, analytic.ProfileActive)
	binding := facts.source.binding
	return repositoryFixture{
		expectation: repositoryBindingExpectation{
			workspaceID: binding.workspaceID, workspaceRevision: binding.workspaceRevision,
			workspaceConfigurationHash: binding.workspaceConfigurationHash,
			catalogID:                  catalog.ID(), catalogRevision: catalog.Revision(), catalogHash: catalog.Hash(),
			profileKey: profile.Key(), profileHash: profile.Hash(),
		},
		catalog: catalog,
		profile: profile,
		binding: binding,
		source: fakeRepositorySource{
			workspaceID: binding.workspaceID, workspaceRevision: binding.workspaceRevision,
			workspaceConfigurationHash: binding.workspaceConfigurationHash,
			workspaceSourceID:          binding.workspaceSourceID, sourceScopeID: binding.sourceScopeID,
			sourceScopeRevision: binding.sourceScopeRevision, scopeConfigHash: binding.sourceScopeConfigurationHash,
			accessMode: repositoryManagedAccessMode, connectionRevision: binding.connectionRevision,
			projection: repositoryProjection(t, profile, columns),
		},
		exposure: fakeRepositoryExposure{
			resolved:    true,
			workspaceID: binding.workspaceID, workspaceRevision: binding.workspaceRevision,
			workspaceConfigurationHash: binding.workspaceConfigurationHash,
			workspaceSourceID:          binding.workspaceSourceID, sourceScopeID: binding.sourceScopeID,
			sourceScopeRevision:          binding.sourceScopeRevision,
			sourceScopeConfigurationHash: binding.sourceScopeConfigurationHash,
			connectionID:                 binding.connectionID, connectionRevision: binding.connectionRevision,
			databaseIdentity: binding.databaseIdentity, liveQueryEnabled: true,
			exposureRevision:     facts.exposure.exposedSchemaRevision,
			exposureArtifactHash: facts.exposure.exposedSchemaHash,
			schemaName:           binding.schemaName, relationName: binding.relationName,
			columns: append([]string(nil), columns...),
		},
	}
}

// repositoryCatalog seals one profile into a single-entry catalog, so an active
// or retired selection can be exercised without a second profile.
func repositoryCatalog(t *testing.T, profile analytic.DatasetProfile, state analytic.ProfileState) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog(repositoryCatalogID, repositoryCatalogRevision,
		[]analytic.CatalogEntryInput{{Profile: profile, State: state}})
	if err != nil {
		t.Fatalf("fixture catalog rejected: %v", err)
	}
	return catalog
}

// repositoryProjection builds the exact valid projection the fake source
// reports: the approved source identity and the complete physical inventory in
// canonical order, with the first column carrying the identity role.
func repositoryProjection(t *testing.T, profile analytic.DatasetProfile, columns []string) postgresqlquery.Projection {
	t.Helper()
	approved := profile.Source().Values()
	projectionColumns := make([]postgresqlquery.Column, len(columns))
	for index, name := range columns {
		column := postgresqlquery.Column{
			Ordinal: index + 1, Name: name, TypeFingerprint: "text",
			LogicalType: postgresqlquery.TypeText,
			Roles:       []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024,
		}
		if index == 0 {
			column.TypeFingerprint = "int8"
			column.LogicalType = postgresqlquery.TypeInt
			column.Roles = []postgresqlquery.Role{postgresqlquery.RoleIdentity}
		}
		projectionColumns[index] = column
	}
	projection := postgresqlquery.Projection{
		ConnectionID: approved.ConnectionID, DatabaseIdentity: approved.DatabaseIdentity,
		LineageID: approved.ProjectionLineageID, Revision: approved.ProjectionRevision,
		ContractHash: approved.ProjectionContractHash, SchemaName: approved.SchemaName,
		RelationName: approved.RelationName, RelationKind: string(approved.RelationKind),
		Columns: projectionColumns, EmptySnapshotPolicy: "AUTHORITATIVE",
	}
	if err := projection.Validate(); err != nil {
		t.Fatalf("fixture projection rejected: %v", err)
	}
	return projection
}

// withoutProjectionColumn removes one column and renumbers the rest, so the
// projection stays valid and only the reported inventory changes.
func withoutProjectionColumn(columns []postgresqlquery.Column, name string) []postgresqlquery.Column {
	kept := make([]postgresqlquery.Column, 0, len(columns))
	for _, column := range columns {
		if column.Name == name {
			continue
		}
		column.Ordinal = len(kept) + 1
		kept = append(kept, column)
	}
	return kept
}

// reorderedProjectionColumns returns the inventory in the opposite order with
// ordinals renumbered, so the projection stays valid and only the order changes.
func reorderedProjectionColumns(columns []postgresqlquery.Column) []postgresqlquery.Column {
	flipped := make([]postgresqlquery.Column, 0, len(columns))
	for index := len(columns) - 1; index >= 0; index-- {
		column := columns[index]
		column.Ordinal = len(flipped) + 1
		flipped = append(flipped, column)
	}
	return flipped
}

// repositoryRefusal applies one mutation, binds the mutated fixture, and
// requires the exact zero binding and the one content-free sentinel.
func repositoryRefusal(t *testing.T, mutate func(*repositoryFixture)) error {
	t.Helper()
	fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	mutate(&fixture)
	value, err := bindRepositoryViews(fixture.expectation, fixture.catalog, fixture.source, fixture.exposure)
	assertEligibilityRefusal(t, value, err)
	return err
}

// repositoryBinding runs the exact fixture through bindRepositoryViews and
// returns the constructed binding.
func repositoryBinding(t *testing.T, fixture repositoryFixture) eligibilityBinding {
	t.Helper()
	value, err := bindRepositoryViews(fixture.expectation, fixture.catalog, fixture.source, fixture.exposure)
	if err != nil {
		t.Fatalf("exact repository results refused: %v", err)
	}
	return value
}

// repositoryDisclosures lists every value this adapter's fixture adds beyond the
// sealed profile's own disclosures: the expectation identities and hashes, the
// workspace source, the scope configuration hash, and every reported column.
func repositoryDisclosures(fixture repositoryFixture) []string {
	values := []string{
		fixture.expectation.workspaceID, fixture.expectation.workspaceConfigurationHash,
		fixture.expectation.catalogID, fixture.expectation.catalogHash, fixture.expectation.profileHash,
		fixture.source.workspaceSourceID, fixture.source.scopeConfigHash,
		alternateIdentity, alternateIdentifier, validHash("9"), "SOURCE_ENFORCED",
	}
	for _, column := range fixture.source.projection.Columns {
		values = append(values, column.Name)
	}
	return values
}

func TestBindRepositoryViewsConstructsExactBinding(t *testing.T) {
	fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	value := repositoryBinding(t, fixture)
	if !value.valid() {
		t.Fatal("constructed binding does not validate")
	}
	if value.profile.Key() != fixture.profile.Key() || value.profile.Hash() != fixture.profile.Hash() {
		t.Fatal("stored profile key or hash differs from the frozen selection")
	}
	if value.binding != fixture.binding {
		t.Fatalf("binding = %+v, want the exact twelve-field tuple", value.binding)
	}
	if value.seal == ([32]byte{}) {
		t.Fatal("constructed binding carries a zero seal")
	}
	approved := fixture.profile.Source().Values()
	if value.binding.sourceScopeID != approved.SourceScopeID || value.binding.connectionID != approved.ConnectionID ||
		value.binding.databaseIdentity != approved.DatabaseIdentity ||
		value.binding.schemaName != approved.SchemaName ||
		value.binding.relationName != approved.RelationName {
		t.Fatal("binding tuple does not carry the approved projection identity")
	}
}

func TestBindRepositoryViewsRefusesInvalidExpectations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*repositoryBindingExpectation)
	}{
		{"zero expectation", func(e *repositoryBindingExpectation) { *e = repositoryBindingExpectation{} }},
		{"workspace id", func(e *repositoryBindingExpectation) { e.workspaceID = "" }},
		{"workspace revision", func(e *repositoryBindingExpectation) { e.workspaceRevision = 0 }},
		{"workspace configuration hash", func(e *repositoryBindingExpectation) { e.workspaceConfigurationHash = "" }},
		{"catalog id", func(e *repositoryBindingExpectation) { e.catalogID = "" }},
		{"catalog revision", func(e *repositoryBindingExpectation) { e.catalogRevision = 0 }},
		{"catalog hash", func(e *repositoryBindingExpectation) { e.catalogHash = "" }},
		{"profile key", func(e *repositoryBindingExpectation) { e.profileKey = analytic.ProfileKey{} }},
		{"profile hash", func(e *repositoryBindingExpectation) { e.profileHash = "" }},
		{"untrimmed workspace id", func(e *repositoryBindingExpectation) { e.workspaceID = " fixture_workspace" }},
		{"control character catalog id", func(e *repositoryBindingExpectation) { e.catalogID += "\x00" }},
		{"workspace revision above max", func(e *repositoryBindingExpectation) { e.workspaceRevision = maxBindingRevision + 1 }},
		{"catalog revision negative", func(e *repositoryBindingExpectation) { e.catalogRevision = -1 }},
		{"uppercase catalog hash", func(e *repositoryBindingExpectation) { e.catalogHash = strings.ToUpper(e.catalogHash) }},
		{"short profile hash", func(e *repositoryBindingExpectation) { e.profileHash = validHash("a")[:len("sha256:")+63] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRefusal(t, func(fixture *repositoryFixture) { test.mutate(&fixture.expectation) })
		})
	}
}

func TestBindRepositoryViewsRefusesCatalogAndProfileDrift(t *testing.T) {
	otherKey, err := analytic.NewProfileKey("other_dataset", 1)
	if err != nil {
		t.Fatalf("alternate profile key rejected: %v", err)
	}
	retired := repositoryCatalog(t, sealedFixtureProfile(t, false), analytic.ProfileRetired)
	tests := []struct {
		name   string
		mutate func(*repositoryFixture)
	}{
		{"zero catalog", func(f *repositoryFixture) { f.catalog = analytic.DatasetProfileCatalog{} }},
		{"retired profile", func(f *repositoryFixture) { f.catalog = retired }},
		{"catalog id drift", func(f *repositoryFixture) { f.expectation.catalogID = "other_catalog" }},
		{"catalog revision drift", func(f *repositoryFixture) { f.expectation.catalogRevision++ }},
		{"catalog hash drift", func(f *repositoryFixture) { f.expectation.catalogHash = validHash("9") }},
		{"missing profile", func(f *repositoryFixture) { f.expectation.profileKey = otherKey }},
		{"wrong profile hash", func(f *repositoryFixture) { f.expectation.profileHash = validHash("9") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRefusal(t, test.mutate)
		})
	}
}

func TestBindRepositoryViewsRefusesUnusableViews(t *testing.T) {
	t.Run("nil source view", func(t *testing.T) {
		fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
		value, err := bindRepositoryViews(fixture.expectation, fixture.catalog, nil, fixture.exposure)
		assertEligibilityRefusal(t, value, err)
	})
	t.Run("nil exposure view", func(t *testing.T) {
		fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
		value, err := bindRepositoryViews(fixture.expectation, fixture.catalog, fixture.source, nil)
		assertEligibilityRefusal(t, value, err)
	})
	t.Run("zero concrete results", func(t *testing.T) {
		fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
		value, err := bindRepositoryResults(fixture.expectation, fixture.catalog,
			repository.PostgreSQLAuthorityResult{}, repository.GovernedExposureResult{})
		assertEligibilityRefusal(t, value, err)
	})
	tests := []struct {
		name   string
		mutate func(*repositoryFixture)
	}{
		{"non-managed access mode", func(f *repositoryFixture) { f.source.accessMode = "SOURCE_ENFORCED" }},
		{"unlowered access mode", func(f *repositoryFixture) { f.source.accessMode = "workspace_managed" }},
		{"empty access mode", func(f *repositoryFixture) { f.source.accessMode = "" }},
		{"zero projection", func(f *repositoryFixture) { f.source.projection = postgresqlquery.Projection{} }},
		{"invalid contract hash", func(f *repositoryFixture) { f.source.projection.ContractHash = "sha256:0" }},
		{"empty projection columns", func(f *repositoryFixture) { f.source.projection.Columns = nil }},
		{"unresolved exposure", func(f *repositoryFixture) { f.exposure.resolved = false }},
		{"disabled exposure", func(f *repositoryFixture) { f.exposure.liveQueryEnabled = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRefusal(t, test.mutate)
		})
	}
}

func TestBindRepositoryViewsRefusesWrongWorkspaceAndCommonBindingDrift(t *testing.T) {
	// Two results that agree with each other on the wrong workspace are still
	// refused: the expectation, not the pair, owns the workspace identity.
	wrongWorkspace := []struct {
		name   string
		mutate func(*repositoryFixture)
	}{
		{"workspace id", func(f *repositoryFixture) {
			f.source.workspaceID, f.exposure.workspaceID = alternateIdentity, alternateIdentity
		}},
		{"workspace revision", func(f *repositoryFixture) {
			f.source.workspaceRevision, f.exposure.workspaceRevision = alternateRevision, alternateRevision
		}},
		{"workspace configuration hash", func(f *repositoryFixture) {
			f.source.workspaceConfigurationHash, f.exposure.workspaceConfigurationHash = validHash("9"), validHash("9")
		}},
	}
	for _, test := range wrongWorkspace {
		t.Run("agreeing on "+test.name, func(t *testing.T) {
			repositoryRefusal(t, test.mutate)
		})
	}

	// Every common binding component drifts on one side alone, so the two mapped
	// tuples stop matching each other rather than the expectation.
	components := []struct {
		name     string
		source   func(*repositoryFixture)
		exposure func(*repositoryFixture)
	}{
		{"workspace id",
			func(f *repositoryFixture) { f.source.workspaceID = alternateIdentity },
			func(f *repositoryFixture) { f.exposure.workspaceID = alternateIdentity }},
		{"workspace revision",
			func(f *repositoryFixture) { f.source.workspaceRevision = alternateRevision },
			func(f *repositoryFixture) { f.exposure.workspaceRevision = alternateRevision }},
		{"workspace configuration hash",
			func(f *repositoryFixture) { f.source.workspaceConfigurationHash = validHash("9") },
			func(f *repositoryFixture) { f.exposure.workspaceConfigurationHash = validHash("9") }},
		{"workspace source id",
			func(f *repositoryFixture) { f.source.workspaceSourceID = alternateIdentity },
			func(f *repositoryFixture) { f.exposure.workspaceSourceID = alternateIdentity }},
		{"source scope id",
			func(f *repositoryFixture) { f.source.sourceScopeID = alternateIdentity },
			func(f *repositoryFixture) { f.exposure.sourceScopeID = alternateIdentity }},
		{"source scope revision",
			func(f *repositoryFixture) { f.source.sourceScopeRevision = alternateRevision },
			func(f *repositoryFixture) { f.exposure.sourceScopeRevision = alternateRevision }},
		{"source scope configuration hash",
			func(f *repositoryFixture) { f.source.scopeConfigHash = validHash("9") },
			func(f *repositoryFixture) { f.exposure.sourceScopeConfigurationHash = validHash("9") }},
		{"connection id",
			func(f *repositoryFixture) { f.source.projection.ConnectionID = alternateIdentity },
			func(f *repositoryFixture) { f.exposure.connectionID = alternateIdentity }},
		{"connection revision",
			func(f *repositoryFixture) { f.source.connectionRevision = alternateRevision },
			func(f *repositoryFixture) { f.exposure.connectionRevision = alternateRevision }},
		{"database identity",
			func(f *repositoryFixture) { f.source.projection.DatabaseIdentity = alternateIdentity },
			func(f *repositoryFixture) { f.exposure.databaseIdentity = alternateIdentity }},
		{"schema",
			func(f *repositoryFixture) { f.source.projection.SchemaName = alternateIdentifier },
			func(f *repositoryFixture) { f.exposure.schemaName = alternateIdentifier }},
		{"relation",
			func(f *repositoryFixture) { f.source.projection.RelationName = alternateIdentifier },
			func(f *repositoryFixture) { f.exposure.relationName = alternateIdentifier }},
	}
	if len(components) != bindingFieldCount {
		t.Fatalf("common binding component table has %d entries, want %d", len(components), bindingFieldCount)
	}
	for _, component := range components {
		sides := []struct {
			name   string
			mutate func(*repositoryFixture)
		}{
			{"source", component.source},
			{"exposure", component.exposure},
		}
		for _, side := range sides {
			t.Run(component.name+"/"+side.name, func(t *testing.T) {
				repositoryRefusal(t, side.mutate)
			})
		}
	}
}

func TestBindRepositoryViewsRefusesProjectionExposureAndColumnDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*repositoryFixture)
	}{
		{"projection lineage", func(f *repositoryFixture) { f.source.projection.LineageID = "other_lineage" }},
		{"projection revision", func(f *repositoryFixture) { f.source.projection.Revision++ }},
		{"projection contract hash", func(f *repositoryFixture) { f.source.projection.ContractHash = validHash("9") }},
		{"relation kind drift", func(f *repositoryFixture) {
			f.source.projection.RelationKind = string(analytic.RelationMaterializedView)
		}},
		{"relation kind unknown", func(f *repositoryFixture) { f.source.projection.RelationKind = "TABLE" }},
		{"exposure revision", func(f *repositoryFixture) { f.exposure.exposureRevision++ }},
		{"exposure hash", func(f *repositoryFixture) { f.exposure.exposureArtifactHash = validHash("9") }},
		{"missing source column", func(f *repositoryFixture) {
			f.source.projection.Columns = withoutProjectionColumn(f.source.projection.Columns, "grain_two_column")
		}},
		{"missing exposure column", func(f *repositoryFixture) {
			f.exposure.columns = withoutColumn(f.exposure.columns, "numerator_column")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repositoryRefusal(t, test.mutate)
		})
	}
}

// The relation-kind mapping is a closed union of its own, so it is exercised
// directly: an unknown spelling refuses even without projection validation, and
// the one approved alternative maps to its exact analytic kind.
func TestRepositorySourceFactsMapsClosedRelationKinds(t *testing.T) {
	fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	projection := fixture.source.Projection()
	if facts, ok := repositorySourceFacts(fixture.source, projection); !ok ||
		facts.relationKind != analytic.RelationView {
		t.Fatal("the approved VIEW relation kind was not mapped exactly")
	}
	projection.RelationKind = string(analytic.RelationMaterializedView)
	if facts, ok := repositorySourceFacts(fixture.source, projection); !ok ||
		facts.relationKind != analytic.RelationMaterializedView {
		t.Fatal("MATERIALIZED_VIEW was not mapped exactly")
	}
	for _, kind := range []string{"", "TABLE", "view", "materialized_view", "MATERIALIZED_VIEW "} {
		projection.RelationKind = kind
		if _, ok := repositorySourceFacts(fixture.source, projection); ok {
			t.Fatalf("relation kind %q was accepted", kind)
		}
	}
}

func TestBindRepositoryViewsAcceptsExtraColumnsAndInventoryOrder(t *testing.T) {
	reference := repositoryBinding(t, repositoryFixtureFor(t, sealedFixtureProfile(t, false)))

	extended := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	extended.source.projection.Columns = append(extended.source.projection.Columns, postgresqlquery.Column{
		Ordinal: len(extended.source.projection.Columns) + 1, Name: "internal_note",
		TypeFingerprint: "text", LogicalType: postgresqlquery.TypeText,
		Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024,
	})
	extended.exposure.columns = append(extended.exposure.columns, "internal_note", "unapproved_extra")
	extraValue := repositoryBinding(t, extended)
	if !extraValue.equal(reference) {
		t.Fatal("extra valid columns changed the binding")
	}

	reordered := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	reordered.source.projection.Columns = reorderedProjectionColumns(reordered.source.projection.Columns)
	reordered.exposure.columns = reversedColumns(reordered.exposure.columns)
	reorderedValue := repositoryBinding(t, reordered)
	if !reorderedValue.equal(reference) {
		t.Fatal("inventory order changed the binding")
	}
}

func TestBindRepositoryViewsRetainsNoCallerSlices(t *testing.T) {
	// Mutating the fake inputs after binding cannot reach the binding.
	mutated := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	value := repositoryBinding(t, mutated)
	seal, binding, hash := value.seal, value.binding, value.profile.Hash()
	mutated.source.projection.Columns[0].Name = "mutated_column"
	mutated.exposure.columns[0] = "mutated_column"
	if value.seal != seal || value.binding != binding || value.profile.Hash() != hash || !value.valid() {
		t.Fatal("mutating the fake inputs changed the constructed binding")
	}

	// The accessors hand back detached copies, so mutating what they return
	// cannot reach the views or a later binding.
	detached := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	first := repositoryBinding(t, detached)
	projection := detached.source.Projection()
	projection.Columns[0].Name = "mutated_column"
	columns := detached.exposure.Columns()
	columns[0] = "mutated_column"
	second, err := bindRepositoryViews(detached.expectation, detached.catalog, detached.source, detached.exposure)
	if err != nil {
		t.Fatalf("binding after mutating returned slices refused: %v", err)
	}
	if !second.equal(first) || !first.equal(second) {
		t.Fatal("returned slice mutation changed a later binding")
	}
}

func TestBindRepositoryViewsRefusalsAreOneContentFreeSentinel(t *testing.T) {
	fixture := repositoryFixtureFor(t, sealedFixtureProfile(t, false))
	zeroResults, zeroErr := bindRepositoryResults(fixture.expectation, fixture.catalog,
		repository.PostgreSQLAuthorityResult{}, repository.GovernedExposureResult{})
	assertEligibilityRefusal(t, zeroResults, zeroErr)
	refusals := []error{
		zeroErr,
		repositoryRefusal(t, func(f *repositoryFixture) { *f = repositoryFixture{} }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.catalog = analytic.DatasetProfileCatalog{} }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.expectation.catalogHash = validHash("9") }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.expectation.profileHash = validHash("9") }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.expectation.workspaceID = "refusal_workspace" }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.source.accessMode = "SOURCE_ENFORCED" }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.source.projection = postgresqlquery.Projection{} }),
		repositoryRefusal(t, func(f *repositoryFixture) { f.exposure.resolved = false }),
		repositoryRefusal(t, func(f *repositoryFixture) {
			f.exposure.columns = withoutColumn(f.exposure.columns, "numerator_column")
		}),
	}
	disclosures := append(fixtureDisclosures(fixture.profile), repositoryDisclosures(fixture)...)
	if errMismatch == nil || errMismatch.Error() == "" {
		t.Fatal("sentinel error is empty")
	}
	for index, refusal := range refusals {
		if refusal != errMismatch || !errors.Is(refusal, errMismatch) {
			t.Fatalf("refusal %d is not the sentinel: %v", index, refusal)
		}
		if refusal.Error() != errMismatch.Error() {
			t.Fatalf("refusal %d has a distinct message: %q", index, refusal.Error())
		}
		for _, disclosure := range disclosures {
			if strings.Contains(refusal.Error(), disclosure) {
				t.Fatalf("refusal %d discloses %q", index, disclosure)
			}
		}
	}
}

func TestRepositoryAdapterViewsAreImplementedByConcreteResults(t *testing.T) {
	if bindRepositoryResultsConcreteSignature == nil {
		t.Fatal("the concrete wrapper signature assertion is missing")
	}
	views := map[string]reflect.Type{
		"repositorySourceView":   reflect.TypeOf((*repositorySourceView)(nil)).Elem(),
		"repositoryExposureView": reflect.TypeOf((*repositoryExposureView)(nil)).Elem(),
	}
	if !reflect.TypeOf(repository.PostgreSQLAuthorityResult{}).Implements(views["repositorySourceView"]) {
		t.Fatal("the concrete PostgreSQL authority result does not implement the source view")
	}
	if !reflect.TypeOf(repository.GovernedExposureResult{}).Implements(views["repositoryExposureView"]) {
		t.Fatal("the concrete governed exposure result does not implement the exposure view")
	}
	for name, view := range views {
		for index := 0; index < view.NumMethod(); index++ {
			method := view.Method(index)
			// A read-only getter takes no argument and returns exactly one value.
			if method.Type.NumIn() != 0 || method.Type.NumOut() != 1 {
				t.Fatalf("%s.%s is not a read-only getter: %s", name, method.Name, method.Type)
			}
			lowered := strings.ToLower(method.Name)
			for _, forbidden := range []string{"credential", "secret", "dsn", "sql", "exec", "token", "password", "row"} {
				if strings.Contains(lowered, forbidden) {
					t.Fatalf("%s.%s carries a forbidden member: %s", name, method.Name, forbidden)
				}
			}
		}
	}
}

func TestRepositoryAdapterProductionSurfaceIsPrivateAndClosed(t *testing.T) {
	const filename = "repository_adapter.go"
	raw, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	files := token.NewFileSet()
	parsed, err := parser.ParseFile(files, filename, raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	if parsed.Name.Name != "analyticsource" {
		t.Fatalf("package = %q, want analyticsource", parsed.Name.Name)
	}

	// Imports are pinned to exactly the three packages the mapping needs.
	allowedImports := map[string]bool{
		"knowvault.local/verified-workspace/internal/analytic":               true,
		"knowvault.local/verified-workspace/internal/source/postgresqlquery": true,
		"knowvault.local/verified-workspace/internal/workspace/repository":   true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the adapter: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	wantViews := map[string][]string{
		"repositorySourceView": {
			"WorkspaceID", "WorkspaceRevision", "WorkspaceConfigurationHash", "WorkspaceSourceID",
			"SourceScopeID", "SourceScopeRevision", "ScopeConfigHash", "AccessMode",
			"ConnectionRevision", "Projection",
		},
		"repositoryExposureView": {
			"Valid", "WorkspaceID", "WorkspaceRevision", "WorkspaceConfigurationHash", "WorkspaceSourceID",
			"SourceScopeID", "SourceScopeRevision", "SourceScopeConfigurationHash", "ConnectionID",
			"ConnectionRevision", "DatabaseIdentity", "LiveQueryEnabled", "ExposureRevision",
			"ExposureArtifactHash", "SchemaName", "RelationName", "Columns",
		},
	}
	assertions := map[string]string{}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			for _, specification := range typed.Specs {
				switch value := specification.(type) {
				case *ast.ValueSpec:
					for index, name := range value.Names {
						if name.IsExported() {
							t.Fatalf("exported package-level identifier %s", name.Name)
						}
						if typed.Tok != token.VAR {
							continue
						}
						// The only package-level vars are the two blank
						// compile-time interface assertions.
						if name.Name != "_" {
							t.Fatalf("package-level var %s: the adapter holds no state", name.Name)
						}
						literal, ok := value.Values[index].(*ast.CompositeLit)
						if !ok {
							t.Fatalf("compile-time assertion for %s is not a composite literal", astTypeName(value.Type))
						}
						assertions[astTypeName(value.Type)] = astTypeName(literal.Type)
					}
				case *ast.TypeSpec:
					if value.Name.IsExported() {
						t.Fatalf("exported type %s", value.Name.Name)
					}
					switch inner := value.Type.(type) {
					case *ast.InterfaceType:
						want, known := wantViews[value.Name.Name]
						if !known {
							t.Fatalf("unexpected interface %s", value.Name.Name)
						}
						names := []string{}
						for _, member := range inner.Methods.List {
							if len(member.Names) != 1 {
								t.Fatalf("%s embeds an interface at %s", value.Name.Name, files.Position(member.Pos()))
							}
							names = append(names, member.Names[0].Name)
						}
						if !slices.Equal(names, want) {
							t.Fatalf("%s methods = %v, want %v", value.Name.Name, names, want)
						}
					case *ast.StructType:
						for _, field := range inner.Fields.List {
							for _, name := range field.Names {
								if name.IsExported() {
									t.Fatalf("exported field %s.%s", value.Name.Name, name.Name)
								}
							}
							if identifier, ok := field.Type.(*ast.Ident); ok {
								if _, stored := wantViews[identifier.Name]; stored {
									t.Fatalf("struct %s stores the %s view", value.Name.Name, identifier.Name)
								}
							}
						}
					default:
						t.Fatalf("unexpected type declaration %s", value.Name.Name)
					}
				default:
					t.Fatalf("unexpected declaration spec in the adapter")
				}
			}
		case *ast.FuncDecl:
			if typed.Recv != nil {
				t.Fatalf("unexpected method %s", typed.Name.Name)
			}
			if typed.Name.IsExported() {
				t.Fatalf("exported top-level function %s", typed.Name.Name)
			}
			functions[typed.Name.Name] = typed
		}
	}

	wantAssertions := map[string]string{
		"repositorySourceView":   "repository.PostgreSQLAuthorityResult",
		"repositoryExposureView": "repository.GovernedExposureResult",
	}
	if !reflect.DeepEqual(assertions, wantAssertions) {
		t.Fatalf("compile-time assertions = %v, want %v", assertions, wantAssertions)
	}

	wantFunctions := []string{
		"bindRepositoryResults", "bindRepositoryViews", "validRepositoryBindingExpectation",
		"reportsExpectedWorkspace", "repositorySourceFacts", "repositoryRelationKind", "repositoryExposureFacts",
	}
	declared := make([]string, 0, len(functions))
	for name := range functions {
		declared = append(declared, name)
	}
	slices.Sort(declared)
	expected := slices.Clone(wantFunctions)
	slices.Sort(expected)
	if !slices.Equal(declared, expected) {
		t.Fatalf("declared functions = %v, want %v", declared, expected)
	}

	wrapper := functions["bindRepositoryResults"]
	wantParams := [][2]string{
		{"expected", "repositoryBindingExpectation"},
		{"catalog", "analytic.DatasetProfileCatalog"},
		{"source", "repository.PostgreSQLAuthorityResult"},
		{"exposure", "repository.GovernedExposureResult"},
	}
	if parameters := astParameters(wrapper.Type.Params); !slices.Equal(parameters, wantParams) {
		t.Fatalf("bindRepositoryResults parameters = %v, want %v", parameters, wantParams)
	}
	wantResults := [][2]string{{"", "eligibilityBinding"}, {"", "error"}}
	if results := astParameters(wrapper.Type.Results); !slices.Equal(results, wantResults) {
		t.Fatalf("bindRepositoryResults results = %v, want %v", results, wantResults)
	}
	// The wrapper is exactly one delegation to the view helper.
	if len(wrapper.Body.List) != 1 {
		t.Fatal("bindRepositoryResults must be exactly one statement")
	}
	returned, ok := wrapper.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(returned.Results) != 1 {
		t.Fatal("bindRepositoryResults must be exactly one return statement")
	}
	call, ok := returned.Results[0].(*ast.CallExpr)
	if !ok {
		t.Fatal("bindRepositoryResults must return one call")
	}
	callee, ok := call.Fun.(*ast.Ident)
	if !ok || callee.Name != "bindRepositoryViews" {
		t.Fatalf("bindRepositoryResults delegates to %v, want bindRepositoryViews", call.Fun)
	}
	if len(call.Args) != len(wantParams) {
		t.Fatalf("bindRepositoryViews call has %d arguments, want %d", len(call.Args), len(wantParams))
	}
	for index, want := range wantParams {
		identifier, ok := call.Args[index].(*ast.Ident)
		if !ok || identifier.Name != want[0] {
			t.Fatalf("bindRepositoryViews argument %d = %v, want %s", index, call.Args[index], want[0])
		}
	}
}

// astTypeName renders one declared type expression exactly as it is written.
func astTypeName(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return astTypeName(typed.X) + "." + typed.Sel.Name
	default:
		return ""
	}
}

// astParameters returns the declared name and type of every parameter, with an
// empty name for an unnamed one.
func astParameters(list *ast.FieldList) [][2]string {
	parameters := [][2]string{}
	if list == nil {
		return parameters
	}
	for _, field := range list.List {
		name := ""
		if len(field.Names) == 1 {
			name = field.Names[0].Name
		}
		parameters = append(parameters, [2]string{name, astTypeName(field.Type)})
	}
	return parameters
}
