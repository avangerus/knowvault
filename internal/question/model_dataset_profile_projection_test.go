package question

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// TestProjectModelDatasetProfileMapsSafeBusinessContract is the first RED
// vertical slice for the model-facing dataset profile projection. It builds
// one small live profile through the public analytic constructors and asserts
// only that the safe business contract is projected and that no source,
// schema, relation, physical, or SQL identity survives into the JSON.
func TestProjectModelDatasetProfileMapsSafeBusinessContract(t *testing.T) {
	profile := newProjectionFixtureProfile(t)

	got, err := projectModelDatasetProfile(profile)
	if err != nil {
		t.Fatalf("projectModelDatasetProfile returned error: %v", err)
	}

	if got.SchemaVersion != "knowvault-model-dataset-profile-v1" {
		t.Fatalf("schema version = %q", got.SchemaVersion)
	}
	if got.Capability != "READ_ONLY_ANALYTIC" {
		t.Fatalf("capability = %q", got.Capability)
	}
	if got.DatasetID != "projection_fixture" {
		t.Fatalf("dataset id = %q", got.DatasetID)
	}
	if got.ProfileVersion != 7 {
		t.Fatalf("profile version = %d", got.ProfileVersion)
	}
	if got.ProfileHash != profile.Hash() || got.ProfileHash == "" {
		t.Fatalf("profile hash = %q want %q", got.ProfileHash, profile.Hash())
	}
	if got.DatasetLabel != "Projection fixture" {
		t.Fatalf("dataset label = %q", got.DatasetLabel)
	}
	if got.DatasetDescription != "Projection fixture business records" {
		t.Fatalf("dataset description = %q", got.DatasetDescription)
	}
	if got.GrainDescription != "One row per order" {
		t.Fatalf("grain description = %q", got.GrainDescription)
	}

	if len(got.Fields) != 3 {
		t.Fatalf("projected fields = %d want 3", len(got.Fields))
	}
	assertProjectedField(t, got.Fields, "order_id", "Order id", "TEXT", true, true, true)
	assertProjectedField(t, got.Fields, "order_total", "Order total", "NUMERIC", true, true, true)
	assertProjectedField(t, got.Fields, "unit_cost", "Unit cost", "NUMERIC", false, false, false)

	if len(got.Measures) != 1 {
		t.Fatalf("projected measures = %d want 1", len(got.Measures))
	}
	measure := got.Measures[0]
	if measure.ID != "net_revenue" || measure.Label != "Net revenue" ||
		measure.Reducer != "SUM" || measure.Unit != "currency" ||
		measure.NullPolicy != "EXCLUDE_AND_REPORT" {
		t.Fatalf("projected measure = %+v", measure)
	}

	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}
	text := string(raw)
	for _, sentinel := range []string{
		"src_scope_9f", "conn_9f", "db_9f", "lineage_9f", "fixture_schema", "fixture_relation",
		"order_id_phys", "order_total_phys", "unit_cost_phys",
	} {
		if strings.Contains(text, sentinel) {
			t.Fatalf("projection leaked sentinel %q in %s", sentinel, text)
		}
	}
	for _, key := range []string{
		"physical_name", "physical_type", "source_ordinal", "numerator_field",
		"denominator_field", "distinct_field", "key_fields", "source_timezone", "sql",
	} {
		if strings.Contains(text, key) {
			t.Fatalf("projection leaked forbidden key %q in %s", key, text)
		}
	}

	if got.ProjectionDigest == "" {
		t.Fatal("projection digest is empty")
	}
}

func assertProjectedField(t *testing.T, fields []modelDatasetProfileField, token, label, logicalType string, filterable, groupable, output bool) {
	t.Helper()
	for _, field := range fields {
		if field.Token != token {
			continue
		}
		if field.Label != label || field.LogicalType != logicalType ||
			field.Filterable != filterable || field.Groupable != groupable || field.OutputAllowed != output {
			t.Fatalf("projected field %q = %+v", token, field)
		}
		return
	}
	t.Fatalf("projected field %q missing from %+v", token, fields)
}

// newProjectionFixtureProfile builds one small valid live profile from the
// public analytic constructors. Every source/schema/relation/physical value is
// a unique sentinel so the projection test can prove none of them survive.
func newProjectionFixtureProfile(t *testing.T) analytic.DatasetProfile {
	t.Helper()

	key, err := analytic.NewProfileKey("projection_fixture", 7)
	if err != nil {
		t.Fatal(err)
	}
	source, err := analytic.NewSourceProjectionSpec(analytic.SourceProjectionInput{
		SourceScopeID: "src_scope_9f", ConnectionID: "conn_9f", DatabaseIdentity: "db_9f",
		ProjectionLineageID: "lineage_9f", ProjectionRevision: 3,
		ProjectionContractHash: "sha256:" + strings.Repeat("a", 64), ExposedSchemaRevision: 4,
		ExposedSchemaHash: "sha256:" + strings.Repeat("b", 64), SchemaName: "fixture_schema",
		RelationName: "fixture_relation", RelationKind: analytic.RelationView,
	})
	if err != nil {
		t.Fatal(err)
	}

	orderID := newProjectionFixtureField(t, "order_id", "order_id_phys", 1, analytic.ScalarText, analytic.PhysicalPGText, false, true, true, true)
	orderTotal := newProjectionFixtureField(t, "order_total", "order_total_phys", 2, analytic.ScalarNumeric, analytic.PhysicalPGNumeric, true, true, true, true)
	unitCost := newProjectionFixtureField(t, "unit_cost", "unit_cost_phys", 3, analytic.ScalarNumeric, analytic.PhysicalPGNumeric, true, false, false, false)

	measure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: "net_revenue", Reducer: analytic.ReducerSum, NumeratorField: "unit_cost",
		Unit: "currency", NullPolicy: analytic.NullExcludeAndReport, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatal(err)
	}

	semantics, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel:       "Projection fixture",
		DatasetDescription: "Projection fixture business records",
		Fields: []analytic.FieldSemanticsInput{
			{Token: "order_id", Label: "Order id", Description: "Order identifier", NullMeaning: "Not assigned", Aliases: []string{"order"}},
			{Token: "order_total", Label: "Order total", Description: "Total order value", NullMeaning: "Not measured", Aliases: []string{"total"}},
			{Token: "unit_cost", Label: "Unit cost", Description: "Hidden unit cost operand", NullMeaning: "Not measured"},
		},
		Measures: []analytic.MeasureSemanticsInput{
			{ID: "net_revenue", Label: "Net revenue", Description: "Sum of net revenue", Aliases: []string{"revenue"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description: "One row per order", KeyFields: []string{"order_id"}, DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatal(err)
	}

	timePolicy, err := analytic.NewTimePolicy(analytic.TimePolicyInput{Kind: analytic.TimeNone})
	if err != nil {
		t.Fatal(err)
	}
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: 1000, MaxOutputGroups: 20, MaxPeriodDays: 31, MaxResultBytes: 1048576, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}

	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source,
		Fields:    []analytic.FieldSpec{orderID, orderTotal, unitCost},
		Measures:  []analytic.MeasureSpec{measure},
		Semantics: semantics, Grain: grain, Time: timePolicy,
		Coverage: analytic.CoverageUnknown, Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func newProjectionFixtureField(t *testing.T, token, physical string, ordinal int, logical analytic.ScalarType, physicalType analytic.PhysicalType, nullable, filterable, groupable, output bool) analytic.FieldSpec {
	t.Helper()
	field, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: physical,
		LogicalType: logical, PhysicalType: physicalType, Nullable: nullable,
		Filterable: filterable, Groupable: groupable, Sortable: true, OutputAllowed: output,
		AllowedOps: func() []analytic.PredicateOperator {
			if filterable {
				return []analytic.PredicateOperator{analytic.PredicateEQ, analytic.PredicateIN}
			}
			return []analytic.PredicateOperator{}
		}(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return field
}

// TestProjectModelDatasetProfileRejectsZeroContentFree proves a zero
// analytic.DatasetProfile is rejected with the invalid code and no wrapped
// cause, and that no projection value is produced.
func TestProjectModelDatasetProfileRejectsZeroContentFree(t *testing.T) {
	profile := analytic.DatasetProfile{}
	got, err := projectModelDatasetProfile(profile)
	if !reflect.DeepEqual(got, modelDatasetProfile{}) {
		t.Fatalf("projection for zero profile = %+v, want zero value", got)
	}
	if err == nil {
		t.Fatal("projectModelDatasetProfile(zero) returned nil error")
	}
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("CodeOf(err) = %q, want %q", CodeOf(err), CodeInvalid)
	}
	if err.Error() != string(CodeInvalid) {
		t.Fatalf("err.Error() = %q, want %q", err.Error(), string(CodeInvalid))
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}
