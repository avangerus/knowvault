package analytic

import (
	"reflect"
	"strings"
	"testing"
)

func TestDatasetProfileMeasureEnumsAreClosed(t *testing.T) {
	for _, value := range []Reducer{ReducerCountRows, ReducerCountDistinct, ReducerSum, ReducerRatioOfSums} {
		if !value.Valid() || Reducer(strings.ToLower(string(value))).Valid() {
			t.Fatalf("reducer set is not closed: %q", value)
		}
	}
	for _, value := range []NullPolicy{NullNotApplicable, NullExcludeAndReport, NullRequireComplete} {
		if !value.Valid() || NullPolicy(strings.ToLower(string(value))).Valid() {
			t.Fatalf("null policy set is not closed: %q", value)
		}
	}
	if Reducer("").Valid() || Reducer("AVG").Valid() || NullPolicy("").Valid() || NullPolicy("MISSING_AS_ZERO").Valid() ||
		!EligibilityAllRows.Valid() || Eligibility("").Valid() || Eligibility("FILTERED").Valid() {
		t.Fatal("unknown enum accepted")
	}
}

func TestDatasetProfileMeasureHappyPathsAndRoundTrip(t *testing.T) {
	cases := []MeasureSpecInput{
		{ID: "rows", Reducer: ReducerCountRows, Unit: "rows", NullPolicy: NullNotApplicable, Eligibility: EligibilityAllRows},
		{ID: "objects", Reducer: ReducerCountDistinct, DistinctField: "object_id", Unit: "objects", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows},
		{ID: "mass", Reducer: ReducerSum, NumeratorField: "mass_kg", Unit: "kg", NullPolicy: NullRequireComplete, Eligibility: EligibilityAllRows},
		{ID: "completion", Reducer: ReducerRatioOfSums, NumeratorField: "done", DenominatorField: "planned", Unit: "ratio", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows},
	}
	for _, input := range cases {
		spec, err := NewMeasureSpec(input)
		if err != nil || !spec.Valid() || spec.Values() != input {
			t.Fatalf("valid measure rejected: %+v err=%v", input, err)
		}
		copy := spec.Values()
		copy.ID = "changed"
		if spec.Values() != input {
			t.Fatal("returned DTO changed immutable spec")
		}
	}
	if (MeasureSpec{}).Valid() {
		t.Fatal("zero measure is valid")
	}
}

func TestDatasetProfileMeasureOperandArity(t *testing.T) {
	rows := MeasureSpecInput{ID: "measure", Reducer: ReducerCountRows, Unit: "items", NullPolicy: NullNotApplicable, Eligibility: EligibilityAllRows}
	distinct := MeasureSpecInput{ID: "measure", Reducer: ReducerCountDistinct, DistinctField: "object_id", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows}
	sum := MeasureSpecInput{ID: "measure", Reducer: ReducerSum, NumeratorField: "amount", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows}
	ratio := MeasureSpecInput{ID: "measure", Reducer: ReducerRatioOfSums, NumeratorField: "amount", DenominatorField: "total", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows}
	invalid := []MeasureSpecInput{
		{ID: rows.ID, Reducer: rows.Reducer, DistinctField: "id", Unit: rows.Unit, NullPolicy: rows.NullPolicy, Eligibility: rows.Eligibility},
		{ID: rows.ID, Reducer: rows.Reducer, NumeratorField: "amount", Unit: rows.Unit, NullPolicy: rows.NullPolicy, Eligibility: rows.Eligibility},
		{ID: rows.ID, Reducer: rows.Reducer, DenominatorField: "total", Unit: rows.Unit, NullPolicy: rows.NullPolicy, Eligibility: rows.Eligibility},
		{ID: distinct.ID, Reducer: distinct.Reducer, Unit: distinct.Unit, NullPolicy: distinct.NullPolicy, Eligibility: distinct.Eligibility},
		{ID: distinct.ID, Reducer: distinct.Reducer, DistinctField: distinct.DistinctField, NumeratorField: "amount", Unit: distinct.Unit, NullPolicy: distinct.NullPolicy, Eligibility: distinct.Eligibility},
		{ID: distinct.ID, Reducer: distinct.Reducer, DistinctField: distinct.DistinctField, DenominatorField: "total", Unit: distinct.Unit, NullPolicy: distinct.NullPolicy, Eligibility: distinct.Eligibility},
		{ID: sum.ID, Reducer: sum.Reducer, Unit: sum.Unit, NullPolicy: sum.NullPolicy, Eligibility: sum.Eligibility},
		{ID: sum.ID, Reducer: sum.Reducer, DistinctField: "id", NumeratorField: sum.NumeratorField, Unit: sum.Unit, NullPolicy: sum.NullPolicy, Eligibility: sum.Eligibility},
		{ID: sum.ID, Reducer: sum.Reducer, NumeratorField: sum.NumeratorField, DenominatorField: "total", Unit: sum.Unit, NullPolicy: sum.NullPolicy, Eligibility: sum.Eligibility},
		{ID: ratio.ID, Reducer: ratio.Reducer, DenominatorField: ratio.DenominatorField, Unit: ratio.Unit, NullPolicy: ratio.NullPolicy, Eligibility: ratio.Eligibility},
		{ID: ratio.ID, Reducer: ratio.Reducer, NumeratorField: ratio.NumeratorField, Unit: ratio.Unit, NullPolicy: ratio.NullPolicy, Eligibility: ratio.Eligibility},
		{ID: ratio.ID, Reducer: ratio.Reducer, DistinctField: "id", NumeratorField: ratio.NumeratorField, DenominatorField: ratio.DenominatorField, Unit: ratio.Unit, NullPolicy: ratio.NullPolicy, Eligibility: ratio.Eligibility},
	}
	for index, input := range invalid {
		assertInvalidMeasure(t, index, input)
	}
}

func TestDatasetProfileMeasureIdentifiersAndUnitBoundaries(t *testing.T) {
	for _, id := range []string{"measure", strings.Repeat("a", 256), strings.Repeat("é", 128)} {
		input := validMeasureInput()
		input.ID = id
		if _, err := NewMeasureSpec(input); err != nil {
			t.Fatalf("valid ID rejected: bytes=%d", len(id))
		}
	}
	for index, id := range []string{"", " measure", "measure ", "me\nasure", "me\u0085asure", strings.Repeat("a", 257), strings.Repeat("é", 129), string([]byte{0xff})} {
		input := validMeasureInput()
		input.ID = id
		assertInvalidMeasure(t, index, input)
	}
	for _, unit := range []string{"x", strings.Repeat("a", 64), strings.Repeat("é", 32)} {
		input := validMeasureInput()
		input.Unit = unit
		if _, err := NewMeasureSpec(input); err != nil {
			t.Fatalf("valid unit rejected: bytes=%d", len(unit))
		}
	}
	for index, unit := range []string{"", " kg", "kg ", "k\ng", "k\u0085g", strings.Repeat("a", 65), strings.Repeat("é", 33), string([]byte{0xff})} {
		input := validMeasureInput()
		input.Unit = unit
		assertInvalidMeasure(t, index, input)
	}
	for index, field := range []string{"9field", "field.name", "field$", strings.Repeat("a", 129), "é"} {
		input := validMeasureInput()
		input.NumeratorField = field
		assertInvalidMeasure(t, index, input)
	}
}

func TestDatasetProfileMeasureNullPolicyAndEligibilityMatrix(t *testing.T) {
	for index, policy := range []NullPolicy{NullExcludeAndReport, NullRequireComplete, "MISSING_AS_ZERO", NullNotApplicable, ""} {
		input := validMeasureInput()
		input.NullPolicy = policy
		if index < 2 {
			if _, err := NewMeasureSpec(input); err != nil {
				t.Fatalf("valid policy rejected: %s", policy)
			}
			continue
		}
		assertInvalidMeasure(t, index, input)
	}
	input := validMeasureInput()
	input.Reducer, input.NumeratorField, input.NullPolicy = ReducerCountRows, "", NullExcludeAndReport
	assertInvalidMeasure(t, 10, input)
	input = validMeasureInput()
	input.Eligibility = "FILTERED"
	assertInvalidMeasure(t, 11, input)
}

func TestDatasetProfileMeasureInputSurfaceIsClosed(t *testing.T) {
	typeOf := reflect.TypeOf(MeasureSpecInput{})
	want := []string{"ID", "Reducer", "DistinctField", "NumeratorField", "DenominatorField", "Unit", "NullPolicy", "Eligibility"}
	if typeOf.NumField() != len(want) {
		t.Fatalf("field count=%d", typeOf.NumField())
	}
	for index, name := range want {
		if typeOf.Field(index).Name != name {
			t.Fatalf("field %d=%s want=%s", index, typeOf.Field(index).Name, name)
		}
	}
	for _, forbidden := range []string{"Formula", "Expression", "SQL", "Map", "Function"} {
		if _, ok := typeOf.FieldByName(forbidden); ok {
			t.Fatalf("escape hatch present: %s", forbidden)
		}
	}
}

func validMeasureInput() MeasureSpecInput {
	return MeasureSpecInput{ID: "mass", Reducer: ReducerSum, NumeratorField: "mass_kg", Unit: "kg", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows}
}

func assertInvalidMeasure(t *testing.T, index int, input MeasureSpecInput) {
	t.Helper()
	if spec, err := NewMeasureSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest || spec.Valid() {
		t.Fatalf("invalid measure %d accepted: %+v", index, input)
	}
}
