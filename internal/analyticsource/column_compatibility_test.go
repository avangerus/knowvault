package analyticsource

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// compatibilityFieldPlan extends the shared complete-field fixture with one
// field of every supported pair that fixture omits, so one sealed profile
// carries all seven logical/physical pairs and both nullability values on top of
// the hidden measure operands, grain keys, and time field.
func compatibilityFieldPlan() []fixtureField {
	return append(fixtureFieldPlan(),
		fixtureField{token: "flag_token", physical: "flag_column", logical: analytic.ScalarBool, nullable: true},
		fixtureField{token: "party_size_token", physical: "party_size_column", logical: analytic.ScalarInt},
		fixtureField{token: "observed_at_token", physical: "observed_at_column", logical: analytic.ScalarTimestamp, nullable: true},
		fixtureField{token: "recorded_at_token", physical: "recorded_at_column", logical: analytic.ScalarTimestamptz},
	)
}

// compatibilityProfile seals the extended inventory with semantics, measures,
// grain, and time covering the whole inventory.
func compatibilityProfile(t *testing.T) analytic.DatasetProfile {
	t.Helper()
	plan := compatibilityFieldPlan()
	fields := make([]analytic.FieldSpec, len(plan))
	semanticFields := make([]analytic.FieldSemanticsInput, len(plan))
	for index, field := range plan {
		fields[index] = fixtureFieldSpec(t, field, index+1)
		semanticFields[index] = analytic.FieldSemanticsInput{
			Token: field.token, Label: "Compatibility field label",
			Description: "Compatibility field description", NullMeaning: "Compatibility null meaning",
		}
	}
	inputs := fixtureMeasureInputs()
	semanticMeasures := make([]analytic.MeasureSemanticsInput, len(inputs))
	for index, measure := range inputs {
		semanticMeasures[index] = analytic.MeasureSemanticsInput{
			ID: measure.ID, Label: "Compatibility measure label", Description: "Compatibility measure description",
		}
	}
	semantics, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel: "Compatibility dataset", DatasetDescription: "Compatibility dataset description",
		Fields: semanticFields, Measures: semanticMeasures,
	})
	if err != nil {
		t.Fatalf("compatibility semantics rejected: %v", err)
	}
	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: fixtureKey(t), Mode: analytic.ExecutionLive, Source: fixtureSource(t),
		Fields: fields, Measures: fixtureMeasures(t), Semantics: semantics,
		Grain: fixtureGrain(t), Time: fixtureTime(t),
		Coverage: analytic.CoverageUnknown, Limits: fixtureLimits(t),
	})
	if err != nil {
		t.Fatalf("compatibility profile rejected: %v", err)
	}
	if !profile.Valid() {
		t.Fatal("compatibility profile did not seal")
	}
	return profile
}

// compatibilityNullabilityProfile reseals the compatibility inventory with the
// nullability of one nullable and one required field inverted, so acceptance
// follows the sealed profile rather than one fixed value per column.
func compatibilityNullabilityProfile(t *testing.T) analytic.DatasetProfile {
	t.Helper()
	spec := compatibilityProfile(t).Spec()
	inverted := map[string]bool{"flag_token": false, "inert_token": true}
	fields := make([]analytic.FieldSpec, len(spec.Fields))
	for index, field := range spec.Fields {
		value := field.Values()
		if nullable, found := inverted[value.Token]; found {
			value.Nullable = nullable
		}
		rebuilt, err := analytic.NewFieldSpec(value)
		if err != nil {
			t.Fatalf("inverted field %q rejected: %v", value.Token, err)
		}
		fields[index] = rebuilt
	}
	spec.Fields = fields
	profile, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("inverted profile rejected: %v", err)
	}
	return profile
}

// compatibilityFixture returns the sealed all-pairs profile with the
// discovery-shaped projection the adapter fixture builder reports for its
// complete inventory.
func compatibilityFixture(t *testing.T) (analytic.DatasetProfile, postgresqlquery.Projection) {
	t.Helper()
	profile := compatibilityProfile(t)
	columns, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("compatibility inventory refused: %v", err)
	}
	return profile, repositoryProjection(t, profile, columns)
}

// withCompatibilityColumn applies one rewrite to the projection column named
// name and returns the resulting projection, which shares no backing array with
// the input.
func withCompatibilityColumn(t *testing.T, projection postgresqlquery.Projection, name string, mutate func(*postgresqlquery.Column)) postgresqlquery.Projection {
	t.Helper()
	for index, column := range projection.Columns {
		if column.Name != name {
			continue
		}
		projection.Columns = slices.Clone(projection.Columns)
		mutate(&projection.Columns[index])
		return projection
	}
	t.Fatalf("projection has no column %q", name)
	return postgresqlquery.Projection{}
}

// assertColumnCompatibilityRefusal requires the one content-free sentinel.
func assertColumnCompatibilityRefusal(t *testing.T, err error) {
	t.Helper()
	if err != errMismatch || !errors.Is(err, errMismatch) {
		t.Fatalf("refused compatibility returned %v, want errMismatch", err)
	}
	if err.Error() != errMismatch.Error() {
		t.Fatalf("refusal has a distinct message: %q", err.Error())
	}
}

func TestRepositoryColumnCompatibilityAcceptsCompleteProfileInventory(t *testing.T) {
	profile, projection := compatibilityFixture(t)
	pairs := map[analytic.PhysicalType]bool{}
	nullability := map[bool]bool{}
	for _, field := range profile.Fields() {
		value := field.Values()
		pairs[value.PhysicalType] = true
		nullability[value.Nullable] = true
	}
	if len(pairs) != 7 || !nullability[true] || !nullability[false] {
		t.Fatalf("fixture covers %d physical types with nullability %v, want all seven and both values", len(pairs), nullability)
	}
	if len(projection.Columns) != len(profile.Fields()) {
		t.Fatalf("projection has %d columns for %d fields", len(projection.Columns), len(profile.Fields()))
	}
	present := map[string]bool{}
	for _, column := range projection.Columns {
		present[column.Name] = true
	}
	for _, hidden := range []string{"numerator_column", "denominator_column", "grain_one_column", "grain_two_column", "time_column"} {
		if !present[hidden] {
			t.Fatalf("fixture inventory omits %q", hidden)
		}
	}
	if err := repositoryColumnCompatibility(profile, projection); err != nil {
		t.Fatalf("complete discovery-shaped inventory refused: %v", err)
	}

	// Extra valid columns and inventory order change nothing.
	extended := projection
	extended.Columns = append(slices.Clone(projection.Columns), postgresqlquery.Column{
		Ordinal: len(projection.Columns) + 1, Name: "internal_note",
		TypeFingerprint: "oid:25", LogicalType: postgresqlquery.TypeText,
		Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, MaxBytes: 1024,
	})
	if err := repositoryColumnCompatibility(profile, extended); err != nil {
		t.Fatalf("extra valid column refused: %v", err)
	}
	reordered := extended
	reordered.Columns = reorderedProjectionColumns(extended.Columns)
	if err := repositoryColumnCompatibility(profile, reordered); err != nil {
		t.Fatalf("reordered inventory refused: %v", err)
	}

	// The adapter binds the same complete inventory.
	if value := repositoryBinding(t, repositoryFixtureFor(t, profile)); !value.valid() {
		t.Fatal("all-pairs profile did not bind")
	}
}

func TestRepositoryColumnCompatibilityAcceptsBoundaryMetadata(t *testing.T) {
	tests := []struct {
		name   string
		column string
		mutate func(*postgresqlquery.Column)
	}{
		{"numeric precision lower bound", "numerator_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 1, 0, "oid:1700:p:1:s:0"
		}},
		{"numeric precision upper bound", "numerator_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 1000, 1000, "oid:1700:p:1000:s:1000"
		}},
		{"numeric scale equals precision", "denominator_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 12, 12, "oid:1700:p:12:s:12"
		}},
		{"timestamp precision lower bound", "observed_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 0, 0, "oid:1114:p:0"
		}},
		{"timestamp precision upper bound", "observed_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 6, 0, "oid:1114:p:6"
		}},
		{"timestamptz precision lower bound", "recorded_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 0, 0, "oid:1184:p:0"
		}},
		{"timestamptz precision upper bound", "recorded_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.Scale, c.TypeFingerprint = 6, 0, "oid:1184:p:6"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, projection := compatibilityFixture(t)
			mutated := withCompatibilityColumn(t, projection, test.column, test.mutate)
			if err := repositoryColumnCompatibility(profile, mutated); err != nil {
				t.Fatalf("boundary metadata refused: %v", err)
			}
		})
	}
}

// Nullability is accepted in both directions and refused on drift, because it
// follows the sealed profile rather than one fixed value per column.
func TestRepositoryColumnCompatibilityTracksSealedNullability(t *testing.T) {
	_, projection := compatibilityFixture(t)
	assertNullability(t, projection, map[string]bool{"flag_column": true, "inert_column": false})

	inverted := compatibilityNullabilityProfile(t)
	columns, err := requiredColumns(inverted)
	if err != nil {
		t.Fatalf("inverted inventory refused: %v", err)
	}
	invertedProjection := repositoryProjection(t, inverted, columns)
	if err := repositoryColumnCompatibility(inverted, invertedProjection); err != nil {
		t.Fatalf("inverted nullability refused: %v", err)
	}
	assertNullability(t, invertedProjection, map[string]bool{"flag_column": false, "inert_column": true})
	if err := repositoryColumnCompatibility(inverted, projection); err != errMismatch {
		t.Fatalf("stale nullability accepted: err=%v", err)
	}
}

// assertNullability requires the named projection columns to report exactly the
// stated nullability.
func assertNullability(t *testing.T, projection postgresqlquery.Projection, want map[string]bool) {
	t.Helper()
	for _, column := range projection.Columns {
		nullable, tracked := want[column.Name]
		if tracked && column.Nullable != nullable {
			t.Fatalf("column %q nullability = %v, want %v", column.Name, column.Nullable, nullable)
		}
	}
}

func TestRepositoryColumnCompatibilityRefusesColumnDrift(t *testing.T) {
	tests := []struct {
		name   string
		column string
		mutate func(*postgresqlquery.Column)
	}{
		{"logical type", "visible_column", func(c *postgresqlquery.Column) { c.LogicalType = postgresqlquery.TypeInt }},
		{"base oid", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:23" }},
		{"fingerprint case", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "OID:25" }},
		{"fingerprint leading zero", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:025" }},
		{"fingerprint padding", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = " oid:25" }},
		{"fingerprint length suffix", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:25:len:10" }},
		{"text varchar alias", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1043" }},
		{"text bpchar alias", "visible_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1042" }},
		{"text varchar length alias", "inert_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1043:len:10" }},
		{"int8 alias int4", "party_size_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:23" }},
		{"int8 alias int2", "party_size_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:21" }},
		{"int8 domain oid", "party_size_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:16385" }},
		{"bool unknown oid", "flag_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:99999" }},
		{"bool precision", "flag_column", func(c *postgresqlquery.Column) { c.Precision = 1 }},
		{"int8 precision", "party_size_column", func(c *postgresqlquery.Column) { c.Precision = 32 }},
		{"date precision", "time_column", func(c *postgresqlquery.Column) { c.Precision = 1 }},
		{"numeric precision drift", "numerator_column", func(c *postgresqlquery.Column) { c.Precision = 11 }},
		{"numeric scale drift", "numerator_column", func(c *postgresqlquery.Column) { c.Scale = 2 }},
		{"numeric fingerprint precision drift", "numerator_column", func(c *postgresqlquery.Column) {
			c.TypeFingerprint = "oid:1700:p:11:s:3"
		}},
		{"numeric fingerprint scale drift", "numerator_column", func(c *postgresqlquery.Column) {
			c.TypeFingerprint = "oid:1700:p:12:s:2"
		}},
		{"numeric fingerprint without metadata", "numerator_column", func(c *postgresqlquery.Column) {
			c.TypeFingerprint = "oid:1700"
		}},
		{"timestamp fingerprint drift", "observed_at_column", func(c *postgresqlquery.Column) { c.Precision = 6 }},
		{"timestamp bare oid", "observed_at_column", func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1114" }},
		{"timestamp bare oid at default precision", "observed_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.TypeFingerprint = 6, "oid:1114"
		}},
		{"timestamptz bare oid at default precision", "recorded_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.TypeFingerprint = 6, "oid:1184"
		}},
		{"timestamp as timestamptz", "observed_at_column", func(c *postgresqlquery.Column) {
			c.LogicalType, c.TypeFingerprint = postgresqlquery.TypeTimestamptz, "oid:1184:p:3"
		}},
		{"timestamp scale", "observed_at_column", func(c *postgresqlquery.Column) { c.Scale = 1 }},
		{"timestamp precision above canonical", "observed_at_column", func(c *postgresqlquery.Column) {
			c.Precision, c.TypeFingerprint = 7, "oid:1114:p:7"
		}},
		{"nullable field made required", "flag_column", func(c *postgresqlquery.Column) { c.Nullable = false }},
		{"required field made nullable", "inert_column", func(c *postgresqlquery.Column) { c.Nullable = true }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile, projection := compatibilityFixture(t)
			mutated := withCompatibilityColumn(t, projection, test.column, test.mutate)
			assertColumnCompatibilityRefusal(t, repositoryColumnCompatibility(profile, mutated))
		})
	}
}

func TestRepositoryColumnCompatibilityRefusesIncompleteAndInvalidInputs(t *testing.T) {
	profile, projection := compatibilityFixture(t)
	missing := projection
	missing.Columns = withoutProjectionColumn(projection.Columns, "grain_two_column")
	assertColumnCompatibilityRefusal(t, repositoryColumnCompatibility(profile, missing))

	unhashed := projection
	unhashed.ContractHash = "sha256:0"
	assertColumnCompatibilityRefusal(t, repositoryColumnCompatibility(profile, unhashed))

	assertColumnCompatibilityRefusal(t, repositoryColumnCompatibility(analytic.DatasetProfile{}, projection))
	assertColumnCompatibilityRefusal(t, repositoryColumnCompatibility(profile, postgresqlquery.Projection{}))
}

// The adapter refuses the same discovered drift, so the gate is not a pure check
// whose result the binding path ignores.
func TestBindRepositoryViewsRefusesDiscoveryShapedColumnDrift(t *testing.T) {
	tests := []struct {
		name   string
		column string
		mutate func(*postgresqlquery.Column)
		remove string
	}{
		{name: "logical type", column: "visible_column",
			mutate: func(c *postgresqlquery.Column) { c.LogicalType = postgresqlquery.TypeInt }},
		{name: "base oid", column: "inert_column",
			mutate: func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:23" }},
		{name: "fingerprint spelling", column: "inert_column",
			mutate: func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:025" }},
		{name: "precision", column: "numerator_column",
			mutate: func(c *postgresqlquery.Column) { c.Precision = 11 }},
		{name: "scale", column: "numerator_column",
			mutate: func(c *postgresqlquery.Column) { c.Scale = 2 }},
		{name: "bare temporal oid", column: "recorded_at_column",
			mutate: func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1184" }},
		{name: "nullability", column: "inert_column",
			mutate: func(c *postgresqlquery.Column) { c.Nullable = true }},
		{name: "missing required field", remove: "time_column"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := repositoryFixtureFor(t, compatibilityProfile(t))
			if test.remove != "" {
				fixture.source.projection.Columns = withoutProjectionColumn(fixture.source.projection.Columns, test.remove)
			} else {
				fixture.source.projection = withCompatibilityColumn(t, fixture.source.projection, test.column, test.mutate)
			}
			value, err := bindRepositoryViews(fixture.expectation, fixture.catalog, fixture.source, fixture.exposure)
			assertEligibilityRefusal(t, value, err)
		})
	}
}

func TestRepositoryColumnCompatibilityRefusalsAreOneContentFreeSentinel(t *testing.T) {
	profile, projection := compatibilityFixture(t)
	logicalType := withCompatibilityColumn(t, projection, "visible_column",
		func(c *postgresqlquery.Column) { c.LogicalType = postgresqlquery.TypeInt })
	fingerprint := withCompatibilityColumn(t, projection, "numerator_column",
		func(c *postgresqlquery.Column) { c.TypeFingerprint = "oid:1700:p:11:s:3" })
	nullability := withCompatibilityColumn(t, projection, "flag_column",
		func(c *postgresqlquery.Column) { c.Nullable = false })
	missing := projection
	missing.Columns = withoutProjectionColumn(projection.Columns, "time_column")
	refusals := []error{
		repositoryColumnCompatibility(analytic.DatasetProfile{}, projection),
		repositoryColumnCompatibility(profile, postgresqlquery.Projection{}),
		repositoryColumnCompatibility(profile, logicalType),
		repositoryColumnCompatibility(profile, fingerprint),
		repositoryColumnCompatibility(profile, nullability),
		repositoryColumnCompatibility(profile, missing),
	}
	disclosures := append(fixtureDisclosures(profile),
		"oid:16", "oid:20", "oid:25", "oid:1082", "oid:1114", "oid:1184", "oid:1700",
		"BOOL", "INT", "TEXT", "DATE", "TIMESTAMP", "TIMESTAMPTZ", "NUMERIC", "true", "false")
	if errMismatch == nil || errMismatch.Error() == "" {
		t.Fatal("sentinel error is empty")
	}
	for index, refusal := range refusals {
		assertColumnCompatibilityRefusal(t, refusal)
		for _, disclosure := range disclosures {
			if strings.Contains(refusal.Error(), disclosure) {
				t.Fatalf("refusal %d discloses %q", index, disclosure)
			}
		}
	}
}

func TestColumnCompatibilityProductionSurfaceIsPrivateAndClosed(t *testing.T) {
	const filename = "column_compatibility.go"
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

	allowedImports := map[string]bool{
		"strconv": true,
		"knowvault.local/verified-workspace/internal/analytic":               true,
		"knowvault.local/verified-workspace/internal/source/postgresqlquery": true,
	}
	imported := map[string]bool{}
	for _, specification := range parsed.Imports {
		path, unquoteErr := strconv.Unquote(specification.Path.Value)
		if unquoteErr != nil || !allowedImports[path] {
			t.Fatalf("unexpected import in the compatibility gate: %v", specification.Path.Value)
		}
		imported[path] = true
	}
	for path := range allowedImports {
		if !imported[path] {
			t.Fatalf("required import %q is missing", path)
		}
	}

	functions := map[string]*ast.FuncDecl{}
	declared := []string{}
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.GenDecl:
			if typed.Tok == token.IMPORT {
				continue
			}
			t.Fatalf("package-level declaration at %s: the gate holds no state or type", files.Position(typed.Pos()))
		case *ast.FuncDecl:
			if typed.Recv != nil {
				t.Fatalf("unexpected method %s", typed.Name.Name)
			}
			if typed.Name.IsExported() {
				t.Fatalf("exported top-level function %s", typed.Name.Name)
			}
			functions[typed.Name.Name] = typed
			declared = append(declared, typed.Name.Name)
		}
	}
	wantFunctions := []string{"repositoryColumnCompatibility", "repositoryColumnExpectation", "repositoryProjectionColumn"}
	expected := slices.Clone(wantFunctions)
	slices.Sort(declared)
	slices.Sort(expected)
	if !slices.Equal(declared, expected) {
		t.Fatalf("declared functions = %v, want %v", declared, expected)
	}

	// The gate takes the sealed profile and the detached projection and returns
	// one error, so no caller can receive a partial value.
	gate := functions["repositoryColumnCompatibility"]
	wantParams := [][2]string{{"profile", "analytic.DatasetProfile"}, {"projection", "postgresqlquery.Projection"}}
	if parameters := astParameters(gate.Type.Params); !slices.Equal(parameters, wantParams) {
		t.Fatalf("gate parameters = %v, want %v", parameters, wantParams)
	}
	wantResults := [][2]string{{"", "error"}}
	if results := astParameters(gate.Type.Results); !slices.Equal(results, wantResults) {
		t.Fatalf("gate results = %v, want %v", results, wantResults)
	}
}
