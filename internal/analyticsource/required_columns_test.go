package analyticsource

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// fixtureField is one row of the fixture's approved field inventory.
type fixtureField struct {
	token     string
	physical  string
	logical   analytic.ScalarType
	nullable  bool
	output    bool
	groupable bool
	sortable  bool
	operators []analytic.PredicateOperator
}

// fixtureFieldPlan is the fixture's field inventory in canonical SourceOrdinal
// order. Logical tokens differ from physical projection columns so a derivation
// that confuses the two is visible, and every dependency family the inventory
// must keep appears once: a visible output column, a hidden ratio numerator and
// denominator, a hidden distinct operand, two hidden composite grain keys, a
// hidden time field, a filter-only field, a group-only field, a sort-only field,
// and a field with every user-facing capability flag false.
func fixtureFieldPlan() []fixtureField {
	return []fixtureField{
		{token: "visible_token", physical: "visible_column", logical: analytic.ScalarText, output: true},
		{token: "numerator_token", physical: "numerator_column", logical: analytic.ScalarNumeric},
		{token: "denominator_token", physical: "denominator_column", logical: analytic.ScalarNumeric},
		{token: "distinct_token", physical: "distinct_column", logical: analytic.ScalarText},
		{token: "grain_one_token", physical: "grain_one_column", logical: analytic.ScalarText},
		{token: "grain_two_token", physical: "grain_two_column", logical: analytic.ScalarText},
		{token: "time_token", physical: "time_column", logical: analytic.ScalarDate},
		{token: "filter_only_token", physical: "filter_only_column", logical: analytic.ScalarText,
			operators: []analytic.PredicateOperator{analytic.PredicateEQ, analytic.PredicateIN}},
		{token: "group_only_token", physical: "group_only_column", logical: analytic.ScalarText, groupable: true},
		{token: "sort_only_token", physical: "sort_only_column", logical: analytic.ScalarText, sortable: true},
		{token: "inert_token", physical: "inert_column", logical: analytic.ScalarText},
	}
}

// fixtureMeasureInputs is the fixture measure inventory: a ratio of hidden sums
// and a hidden distinct count, so every operand family is a dependency.
func fixtureMeasureInputs() []analytic.MeasureSpecInput {
	return []analytic.MeasureSpecInput{
		{ID: "distinct_measure", Reducer: analytic.ReducerCountDistinct, DistinctField: "distinct_token",
			Unit: "fixture_items", NullPolicy: analytic.NullExcludeAndReport, Eligibility: analytic.EligibilityAllRows},
		{ID: "ratio_measure", Reducer: analytic.ReducerRatioOfSums, NumeratorField: "numerator_token",
			DenominatorField: "denominator_token", Unit: "fixture_ratio",
			NullPolicy: analytic.NullRequireComplete, Eligibility: analytic.EligibilityAllRows},
	}
}

// canonicalFixtureColumns is the fixture's complete physical inventory in
// canonical SourceOrdinal order, declared from the field plan instead of read
// back from a sealed profile.
func canonicalFixtureColumns() []string {
	plan := fixtureFieldPlan()
	columns := make([]string, len(plan))
	for index, field := range plan {
		columns[index] = field.physical
	}
	return columns
}

// sealedFixtureProfile seals the fixture specification. A reversed request
// supplies the field slice in the reverse of canonical order, so sealing alone
// has to restore SourceOrdinal order.
func sealedFixtureProfile(t *testing.T, reversed bool) analytic.DatasetProfile {
	t.Helper()
	plan := fixtureFieldPlan()
	fields := make([]analytic.FieldSpec, len(plan))
	for index, field := range plan {
		fields[index] = fixtureFieldSpec(t, field, index+1)
	}
	if reversed {
		slices.Reverse(fields)
	}
	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: fixtureKey(t), Mode: analytic.ExecutionLive, Source: fixtureSource(t),
		Fields: fields, Measures: fixtureMeasures(t), Semantics: fixtureSemantics(t),
		Grain: fixtureGrain(t), Time: fixtureTime(t),
		Coverage: analytic.CoverageUnknown, Limits: fixtureLimits(t),
	})
	if err != nil {
		t.Fatalf("fixture profile rejected: %v", err)
	}
	if !profile.Valid() {
		t.Fatal("fixture profile did not seal")
	}
	return profile
}

func fixtureFieldSpec(t *testing.T, field fixtureField, ordinal int) analytic.FieldSpec {
	t.Helper()
	value, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: field.token, SourceOrdinal: ordinal, PhysicalName: field.physical,
		LogicalType: field.logical, PhysicalType: fixturePhysicalType(field.logical), Nullable: field.nullable,
		Filterable: len(field.operators) > 0, Groupable: field.groupable, Sortable: field.sortable,
		OutputAllowed: field.output, AllowedOps: field.operators,
	})
	if err != nil {
		t.Fatalf("fixture field %q rejected: %v", field.token, err)
	}
	return value
}

// fixturePhysicalType maps one logical fixture type to its compatible physical
// type; an unmapped type yields the zero value, which field construction rejects.
func fixturePhysicalType(logical analytic.ScalarType) analytic.PhysicalType {
	types := map[analytic.ScalarType]analytic.PhysicalType{
		analytic.ScalarBool: analytic.PhysicalPGBool, analytic.ScalarInt: analytic.PhysicalPGInt8,
		analytic.ScalarNumeric: analytic.PhysicalPGNumeric, analytic.ScalarText: analytic.PhysicalPGText,
		analytic.ScalarDate: analytic.PhysicalPGDate, analytic.ScalarTimestamp: analytic.PhysicalPGTimestamp,
		analytic.ScalarTimestamptz: analytic.PhysicalPGTimestamptz,
	}
	return types[logical]
}

func fixtureMeasures(t *testing.T) []analytic.MeasureSpec {
	t.Helper()
	inputs := fixtureMeasureInputs()
	measures := make([]analytic.MeasureSpec, len(inputs))
	for index, input := range inputs {
		value, err := analytic.NewMeasureSpec(input)
		if err != nil {
			t.Fatalf("fixture measure %q rejected: %v", input.ID, err)
		}
		measures[index] = value
	}
	return measures
}

func fixtureSemantics(t *testing.T) analytic.ProfileSemantics {
	t.Helper()
	plan := fixtureFieldPlan()
	fields := make([]analytic.FieldSemanticsInput, len(plan))
	for index, field := range plan {
		fields[index] = analytic.FieldSemanticsInput{
			Token: field.token, Label: "Fixture field label",
			Description: "Fixture field description", NullMeaning: "Fixture field null meaning",
		}
	}
	inputs := fixtureMeasureInputs()
	measures := make([]analytic.MeasureSemanticsInput, len(inputs))
	for index, measure := range inputs {
		measures[index] = analytic.MeasureSemanticsInput{
			ID: measure.ID, Label: "Fixture measure label", Description: "Fixture measure description",
		}
	}
	value, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel: "Fixture dataset", DatasetDescription: "Fixture dataset description",
		Fields: fields, Measures: measures,
	})
	if err != nil {
		t.Fatalf("fixture semantics rejected: %v", err)
	}
	return value
}

func fixtureGrain(t *testing.T) analytic.DatasetGrain {
	t.Helper()
	value, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description: "Fixture grain over two hidden keys",
		KeyFields:   []string{"grain_one_token", "grain_two_token"}, DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatalf("fixture grain rejected: %v", err)
	}
	return value
}

func fixtureTime(t *testing.T) analytic.TimePolicy {
	t.Helper()
	value, err := analytic.NewTimePolicy(analytic.TimePolicyInput{
		Kind: analytic.TimeBusinessDate, FieldToken: "time_token",
		ReportingTimezone: "UTC", Calendar: analytic.CalendarGregorian,
	})
	if err != nil {
		t.Fatalf("fixture time policy rejected: %v", err)
	}
	return value
}

func fixtureKey(t *testing.T) analytic.ProfileKey {
	t.Helper()
	key, err := analytic.NewProfileKey("fixture_dataset", 1)
	if err != nil {
		t.Fatalf("fixture key rejected: %v", err)
	}
	return key
}

func fixtureSource(t *testing.T) analytic.SourceProjectionSpec {
	t.Helper()
	source, err := analytic.NewSourceProjectionSpec(analytic.SourceProjectionInput{
		SourceScopeID: "fixture_scope", ConnectionID: "fixture_connection",
		DatabaseIdentity: "fixture_database", ProjectionLineageID: "fixture_lineage",
		ProjectionRevision: 1, ProjectionContractHash: validHash("1"),
		ExposedSchemaRevision: 2, ExposedSchemaHash: validHash("2"),
		SchemaName: "fixture_schema", RelationName: "fixture_relation", RelationKind: analytic.RelationView,
	})
	if err != nil {
		t.Fatalf("fixture projection rejected: %v", err)
	}
	return source
}

func fixtureLimits(t *testing.T) analytic.ProfileLimits {
	t.Helper()
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: 1000, MaxOutputGroups: 20, MaxPeriodDays: 31,
		MaxResultBytes: 1048576, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("fixture limits rejected: %v", err)
	}
	return limits
}

// governedMatchFixture pairs the fixture profile's approved projection with
// trusted source and exposure facts that carry exactly columns on both sides.
func governedMatchFixture(t *testing.T, profile analytic.DatasetProfile, columns []string) matchFixture {
	t.Helper()
	input := profile.Source().Values()
	binding := bindingFacts{
		workspaceID: "fixture_workspace", workspaceRevision: 3,
		workspaceConfigurationHash: validHash("c"), workspaceSourceID: "fixture_workspace_source",
		sourceScopeID: input.SourceScopeID, sourceScopeRevision: 5,
		sourceScopeConfigurationHash: validHash("d"),
		connectionID:                 input.ConnectionID, connectionRevision: 7,
		databaseIdentity: input.DatabaseIdentity, schemaName: input.SchemaName,
		relationName: input.RelationName,
	}
	return matchFixture{
		expected: profile.Source(),
		source: sourceFacts{
			binding: binding, projectionLineageID: input.ProjectionLineageID,
			projectionRevision:     input.ProjectionRevision,
			projectionContractHash: input.ProjectionContractHash, relationKind: input.RelationKind,
			columns: append([]string(nil), columns...),
		},
		exposure: exposureFacts{
			binding: binding, liveEnabled: true,
			exposedSchemaRevision: input.ExposedSchemaRevision,
			exposedSchemaHash:     input.ExposedSchemaHash,
			columns:               append([]string(nil), columns...),
		},
		required: append([]string(nil), columns...),
	}
}

// factSide names one trusted fact inventory that carries physical columns.
type factSide struct {
	name    string
	columns func(*matchFixture) *[]string
}

// factSides lists the two trusted sides the matcher checks columns against.
func factSides() []factSide {
	return []factSide{
		{"source", func(fixture *matchFixture) *[]string { return &fixture.source.columns }},
		{"exposure", func(fixture *matchFixture) *[]string { return &fixture.exposure.columns }},
	}
}

// withoutColumn returns columns with every occurrence of column removed.
func withoutColumn(columns []string, column string) []string {
	kept := make([]string, 0, len(columns))
	for _, candidate := range columns {
		if candidate != column {
			kept = append(kept, candidate)
		}
	}
	return kept
}

// fixtureDisclosures lists every identity, logical token, measure id, and
// physical name the sealed fixture carries; no refusal may reveal one.
func fixtureDisclosures(profile analytic.DatasetProfile) []string {
	source := profile.Source().Values()
	values := []string{
		profile.Key().DatasetID(), source.SourceScopeID, source.ConnectionID,
		source.DatabaseIdentity, source.ProjectionLineageID, source.ProjectionContractHash,
		source.ExposedSchemaHash, source.SchemaName, source.RelationName,
	}
	for _, field := range profile.Fields() {
		input := field.Values()
		values = append(values, input.Token, input.PhysicalName)
	}
	for _, measure := range profile.Measures() {
		values = append(values, measure.Values().ID)
	}
	return values
}

func TestRequiredColumnsReturnsExactCanonicalInventory(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	columns, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("sealed fixture profile refused: %v", err)
	}
	if want := canonicalFixtureColumns(); !slices.Equal(columns, want) {
		t.Fatalf("columns = %q, want %q", columns, want)
	}
	seen := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		if _, duplicate := seen[column]; duplicate {
			t.Fatalf("column %q returned twice", column)
		}
		seen[column] = struct{}{}
	}
}

func TestRequiredColumnsIgnoresCallerFieldOrder(t *testing.T) {
	profile := sealedFixtureProfile(t, true)
	columns, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("reordered fixture profile refused: %v", err)
	}
	if want := canonicalFixtureColumns(); !slices.Equal(columns, want) {
		t.Fatalf("columns = %q, want canonical order %q", columns, want)
	}
}

func TestRequiredColumnsReturnsDetachedResults(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	hash := profile.Hash()
	first, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("sealed fixture profile refused: %v", err)
	}
	if first == nil {
		t.Fatal("successful call returned a nil slice")
	}
	second, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("repeated call refused: %v", err)
	}
	if !slices.Equal(first, second) {
		t.Fatalf("repeated calls differ: %q, %q", first, second)
	}

	// Mutating one result must not reach the profile or a later result.
	first[0] = "mutated_column"
	third, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("call after slice mutation refused: %v", err)
	}
	if !slices.Equal(third, second) {
		t.Fatalf("slice mutation changed a later result: %q, %q", third, second)
	}
	if second[0] == "mutated_column" {
		t.Fatal("separate results share one backing array")
	}

	// A detached field DTO and a detached profile DTO must not be a route back
	// into the sealed profile.
	detached := profile.Fields()
	detached[0] = detached[len(detached)-1]
	field := detached[0].Values()
	field.Token, field.PhysicalName = "mutated_token", "mutated_column"
	spec := profile.Spec()
	spec.Fields[0], spec.Measures[0] = spec.Fields[1], spec.Measures[1]
	fourth, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("call after DTO mutation refused: %v", err)
	}
	if !slices.Equal(fourth, second) {
		t.Fatalf("DTO mutation changed a later result: %q, %q", fourth, second)
	}
	if profile.Hash() != hash || !profile.Valid() {
		t.Fatal("DTO mutation changed the sealed profile")
	}
}

func TestRequiredColumnsRefusesZeroProfile(t *testing.T) {
	columns, err := requiredColumns(analytic.DatasetProfile{})
	if columns != nil {
		t.Fatalf("zero profile returned columns %q", columns)
	}
	if err != errMismatch {
		t.Fatalf("zero profile returned %v, want errMismatch", err)
	}
}

func TestRequiredColumnsInventorySatisfiesMatch(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	derived, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("sealed fixture profile refused: %v", err)
	}

	exact := governedMatchFixture(t, profile, derived)
	if err := match(exact.expected, exact.required, exact.source, exact.exposure); err != nil {
		t.Fatalf("exact derived inventory refused: %v", err)
	}

	extra := governedMatchFixture(t, profile, derived)
	extra.source.columns = append(extra.source.columns, "internal_note", "_audit$1")
	extra.exposure.columns = append(extra.exposure.columns, "internal_note", "unapproved_extra")
	if err := match(extra.expected, extra.required, extra.source, extra.exposure); err != nil {
		t.Fatalf("extra valid fact columns refused: %v", err)
	}

	for _, side := range factSides() {
		for _, column := range derived {
			t.Run(side.name+"/"+column, func(t *testing.T) {
				fixture := governedMatchFixture(t, profile, derived)
				inventory := side.columns(&fixture)
				*inventory = withoutColumn(*inventory, column)
				if err := match(fixture.expected, fixture.required, fixture.source, fixture.exposure); err != errMismatch {
					t.Fatalf("inventory without %q accepted: err=%v", column, err)
				}
			})
		}
	}
}

func TestRequiredColumnsRefusalsDiscloseNoFixtureMetadata(t *testing.T) {
	profile := sealedFixtureProfile(t, false)
	derived, err := requiredColumns(profile)
	if err != nil {
		t.Fatalf("sealed fixture profile refused: %v", err)
	}
	zeroColumns, zeroErr := requiredColumns(analytic.DatasetProfile{})
	if zeroColumns != nil {
		t.Fatalf("zero profile returned columns %q", zeroColumns)
	}
	incomplete := governedMatchFixture(t, profile, derived)
	inventory := factSides()[0].columns(&incomplete)
	*inventory = withoutColumn(*inventory, derived[0])
	refusals := []error{
		zeroErr,
		match(incomplete.expected, incomplete.required, incomplete.source, incomplete.exposure),
	}
	for index, refusal := range refusals {
		if refusal != errMismatch || !errors.Is(refusal, errMismatch) {
			t.Fatalf("refusal %d is not the sentinel: %v", index, refusal)
		}
		if refusal.Error() != errMismatch.Error() {
			t.Fatalf("refusal %d has a distinct message: %q", index, refusal.Error())
		}
		for _, disclosure := range fixtureDisclosures(profile) {
			if strings.Contains(refusal.Error(), disclosure) {
				t.Fatalf("refusal %d discloses %q", index, disclosure)
			}
		}
	}
}
