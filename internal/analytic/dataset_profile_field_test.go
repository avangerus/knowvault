package analytic

import (
	"reflect"
	"strings"
	"testing"
)

func TestDatasetProfileFieldEnumsAreClosed(t *testing.T) {
	logical := []ScalarType{ScalarBool, ScalarInt, ScalarNumeric, ScalarText, ScalarDate, ScalarTimestamp, ScalarTimestamptz}
	physical := []PhysicalType{PhysicalPGBool, PhysicalPGInt8, PhysicalPGNumeric, PhysicalPGText, PhysicalPGDate, PhysicalPGTimestamp, PhysicalPGTimestamptz}
	operators := []PredicateOperator{PredicateEQ, PredicateIN, PredicateGTE, PredicateLTE, PredicateISNull}
	for _, value := range logical {
		if !value.Valid() || ScalarType(strings.ToLower(string(value))).Valid() {
			t.Fatalf("logical type set is not closed: %q", value)
		}
	}
	for _, value := range physical {
		if !value.Valid() || PhysicalType(strings.ToLower(string(value))).Valid() {
			t.Fatalf("physical type set is not closed: %q", value)
		}
	}
	for _, value := range operators {
		if !value.Valid() || PredicateOperator(strings.ToLower(string(value))).Valid() {
			t.Fatalf("operator set is not closed: %q", value)
		}
	}
	if ScalarType("").Valid() || ScalarType("INTEGER").Valid() || PhysicalType("").Valid() ||
		PhysicalType("PG_INT4").Valid() || PredicateOperator("").Valid() || PredicateOperator("NE").Valid() {
		t.Fatal("unknown enum value accepted")
	}
}

func TestDatasetProfileFieldExactTypeCompatibility(t *testing.T) {
	pairs := []struct {
		logical  ScalarType
		physical PhysicalType
	}{
		{ScalarBool, PhysicalPGBool}, {ScalarInt, PhysicalPGInt8}, {ScalarNumeric, PhysicalPGNumeric},
		{ScalarText, PhysicalPGText}, {ScalarDate, PhysicalPGDate}, {ScalarTimestamp, PhysicalPGTimestamp},
		{ScalarTimestamptz, PhysicalPGTimestamptz},
	}
	for index, pair := range pairs {
		input := validFieldSpecInput()
		input.LogicalType, input.PhysicalType = pair.logical, pair.physical
		if spec, err := NewFieldSpec(input); err != nil || !spec.Valid() {
			t.Fatalf("exact pair rejected: %s/%s: %v", pair.logical, pair.physical, err)
		}
		input.PhysicalType = pairs[(index+1)%len(pairs)].physical
		if _, err := NewFieldSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest {
			t.Fatalf("mismatched pair accepted: %s/%s", input.LogicalType, input.PhysicalType)
		}
	}
}

func TestDatasetProfileFieldIdentifiersAndOrdinal(t *testing.T) {
	for _, token := range []string{"field", "_field9", strings.Repeat("a", 128)} {
		input := validFieldSpecInput()
		input.Token = token
		if _, err := NewFieldSpec(input); err != nil {
			t.Fatalf("valid token rejected: %q: %v", token, err)
		}
	}
	for _, token := range []string{"", "9field", "field.name", "field$", "field;drop", "é", strings.Repeat("a", 129)} {
		input := validFieldSpecInput()
		input.Token = token
		assertInvalidField(t, input)
	}
	for _, name := range []string{"column", "_column$9", strings.Repeat("a", 63)} {
		input := validFieldSpecInput()
		input.PhysicalName = name
		if _, err := NewFieldSpec(input); err != nil {
			t.Fatalf("valid physical name rejected: %q: %v", name, err)
		}
	}
	for _, name := range []string{"", "9column", "column.name", "column;drop", "é", strings.Repeat("a", 64)} {
		input := validFieldSpecInput()
		input.PhysicalName = name
		assertInvalidField(t, input)
	}
	for _, ordinal := range []int{0, -1} {
		input := validFieldSpecInput()
		input.SourceOrdinal = ordinal
		assertInvalidField(t, input)
	}
}

func TestDatasetProfileFieldFilterableOperatorMatrix(t *testing.T) {
	input := validFieldSpecInput()
	input.Filterable = true
	assertInvalidField(t, input)
	input.Filterable = false
	input.AllowedOps = []PredicateOperator{PredicateEQ}
	assertInvalidField(t, input)
	for _, operations := range [][]PredicateOperator{
		{PredicateEQ, PredicateEQ}, {PredicateOperator("NE")},
		{PredicateEQ, PredicateIN, PredicateGTE, PredicateLTE, PredicateISNull, PredicateEQ},
	} {
		input := validFieldSpecInput()
		input.Filterable, input.Nullable, input.AllowedOps = true, true, operations
		assertInvalidField(t, input)
	}
	for _, kind := range []ScalarType{ScalarBool, ScalarText} {
		for _, operator := range []PredicateOperator{PredicateGTE, PredicateLTE} {
			input := inputForLogicalType(kind)
			input.Filterable, input.AllowedOps = true, []PredicateOperator{operator}
			assertInvalidField(t, input)
		}
	}
	for _, kind := range []ScalarType{ScalarInt, ScalarNumeric, ScalarDate, ScalarTimestamp, ScalarTimestamptz} {
		input := inputForLogicalType(kind)
		input.Filterable, input.AllowedOps = true, []PredicateOperator{PredicateGTE, PredicateLTE}
		if _, err := NewFieldSpec(input); err != nil {
			t.Fatalf("ordered type rejected: %s: %v", kind, err)
		}
	}
	input = validFieldSpecInput()
	input.Filterable, input.AllowedOps = true, []PredicateOperator{PredicateISNull}
	assertInvalidField(t, input)
	input.Nullable = true
	if _, err := NewFieldSpec(input); err != nil {
		t.Fatalf("IS_NULL rejected for nullable field: %v", err)
	}
	for _, kind := range []ScalarType{ScalarBool, ScalarInt, ScalarNumeric, ScalarText, ScalarDate, ScalarTimestamp, ScalarTimestamptz} {
		input := inputForLogicalType(kind)
		input.Filterable, input.AllowedOps = true, []PredicateOperator{PredicateEQ, PredicateIN}
		if _, err := NewFieldSpec(input); err != nil {
			t.Fatalf("EQ/IN rejected for %s: %v", kind, err)
		}
	}
}

func TestDatasetProfileFieldCanonicalOrderAndHiddenOperand(t *testing.T) {
	input := validFieldSpecInput()
	input.Nullable, input.Filterable = true, true
	input.AllowedOps = []PredicateOperator{PredicateISNull, PredicateLTE, PredicateIN, PredicateGTE, PredicateEQ}
	spec, err := NewFieldSpec(input)
	want := []PredicateOperator{PredicateEQ, PredicateIN, PredicateGTE, PredicateLTE, PredicateISNull}
	if err != nil || !reflect.DeepEqual(spec.Values().AllowedOps, want) {
		t.Fatalf("operators not canonicalized: got=%v err=%v", spec.Values().AllowedOps, err)
	}
	hidden := validFieldSpecInput()
	hidden.Nullable, hidden.Filterable, hidden.Groupable, hidden.Sortable, hidden.OutputAllowed = false, false, false, false, false
	if spec, err := NewFieldSpec(hidden); err != nil || !spec.Valid() {
		t.Fatalf("hidden measure operand rejected: %v", err)
	}
	if (FieldSpec{}).Valid() {
		t.Fatal("zero field spec is valid")
	}
}

func TestDatasetProfileFieldInputAndOutputSlicesAreDetached(t *testing.T) {
	input := validFieldSpecInput()
	input.Filterable, input.AllowedOps = true, []PredicateOperator{PredicateEQ, PredicateIN}
	spec, err := NewFieldSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	input.AllowedOps[0] = PredicateISNull
	first := spec.Values()
	if !reflect.DeepEqual(first.AllowedOps, []PredicateOperator{PredicateEQ, PredicateIN}) {
		t.Fatalf("caller mutation changed spec: %v", first.AllowedOps)
	}
	first.AllowedOps[0] = PredicateLTE
	if !reflect.DeepEqual(spec.Values().AllowedOps, []PredicateOperator{PredicateEQ, PredicateIN}) {
		t.Fatal("returned slice mutation changed spec")
	}
}

func inputForLogicalType(kind ScalarType) FieldSpecInput {
	physical := map[ScalarType]PhysicalType{
		ScalarBool: PhysicalPGBool, ScalarInt: PhysicalPGInt8, ScalarNumeric: PhysicalPGNumeric,
		ScalarText: PhysicalPGText, ScalarDate: PhysicalPGDate, ScalarTimestamp: PhysicalPGTimestamp,
		ScalarTimestamptz: PhysicalPGTimestamptz,
	}
	input := validFieldSpecInput()
	input.LogicalType, input.PhysicalType = kind, physical[kind]
	return input
}

func validFieldSpecInput() FieldSpecInput {
	return FieldSpecInput{Token: "amount", SourceOrdinal: 1, PhysicalName: "amount_value", LogicalType: ScalarNumeric, PhysicalType: PhysicalPGNumeric}
}

func assertInvalidField(t *testing.T, input FieldSpecInput) {
	t.Helper()
	if spec, err := NewFieldSpec(input); err == nil || CodeOf(err) != CodeInvalidRequest || spec.Valid() {
		t.Fatalf("invalid field accepted: %+v", input)
	}
}
