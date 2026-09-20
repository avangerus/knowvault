package analytic

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func validDatasetGrainInput() DatasetGrainInput {
	return DatasetGrainInput{
		Description:     "Stable removal grain keyed by vehicle and operation time.",
		KeyFields:       []string{"vehicle_id", "event_at"},
		DuplicatePolicy: DuplicateReject,
	}
}

func TestDatasetGrainNormalizesSortsAndPreservesCase(t *testing.T) {
	input := DatasetGrainInput{
		Description:     "Grain with mixed-case tokens.",
		KeyFields:       []string{"zeta", "Alpha", "beta"},
		DuplicatePolicy: DuplicateReject,
	}
	value, err := NewDatasetGrain(input)
	if err != nil || !value.Valid() {
		t.Fatalf("valid grain rejected: valid=%v err=%v", value.Valid(), err)
	}
	got := value.Values()
	want := []string{"Alpha", "beta", "zeta"}
	if !reflect.DeepEqual(got.KeyFields, want) {
		t.Fatalf("key tokens not sorted case-preserving: %#v", got.KeyFields)
	}
	if got.Description != input.Description || got.DuplicatePolicy != DuplicateReject {
		t.Fatalf("grain values not preserved: %#v", got)
	}
	for _, token := range got.KeyFields {
		if !sort.StringsAreSorted(got.KeyFields) {
			t.Fatalf("key tokens not lexicographically sorted: %#v", got.KeyFields)
		}
		_ = token
	}
}

func TestDatasetGrainPermutationsProduceEqualValues(t *testing.T) {
	base := DatasetGrainInput{
		Description:     "Permutation invariance.",
		KeyFields:       []string{"alpha", "bravo", "charlie"},
		DuplicatePolicy: DuplicateReject,
	}
	reference, err := NewDatasetGrain(base)
	if err != nil {
		t.Fatal(err)
	}
	permutations := [][]string{
		{"alpha", "bravo", "charlie"},
		{"alpha", "charlie", "bravo"},
		{"bravo", "alpha", "charlie"},
		{"bravo", "charlie", "alpha"},
		{"charlie", "alpha", "bravo"},
		{"charlie", "bravo", "alpha"},
	}
	for _, permutation := range permutations {
		input := base
		input.KeyFields = permutation
		value, err := NewDatasetGrain(input)
		if err != nil || !value.Valid() {
			t.Fatalf("permutation rejected: %#v err=%v", permutation, err)
		}
		if !reflect.DeepEqual(value.Values(), reference.Values()) {
			t.Fatalf("permutation produced unequal values: %#v vs %#v", value.Values(), reference.Values())
		}
	}
}

func TestDatasetGrainDetachesSlices(t *testing.T) {
	input := validDatasetGrainInput()
	value, err := NewDatasetGrain(input)
	if err != nil {
		t.Fatal(err)
	}
	want := value.Values()
	input.KeyFields[0] = "mutated"
	input.KeyFields = append(input.KeyFields, "extra")
	if !value.Valid() || !reflect.DeepEqual(value.Values(), want) {
		t.Fatalf("caller mutation changed grain: %#v", value.Values())
	}
	got := value.Values()
	got.KeyFields[0] = "changed"
	got.KeyFields = append(got.KeyFields, "changed")
	if !value.Valid() || !reflect.DeepEqual(value.Values(), want) {
		t.Fatalf("Values() leaked aliased slice: %#v", value.Values())
	}
}

func TestDatasetGrainRejectsInvalidInputsContentFree(t *testing.T) {
	cases := map[string]func(*DatasetGrainInput){
		"missing description":       func(v *DatasetGrainInput) { v.Description = "" },
		"leading whitespace":        func(v *DatasetGrainInput) { v.Description = " leading" },
		"trailing whitespace":       func(v *DatasetGrainInput) { v.Description = "trailing " },
		"c0 control":                func(v *DatasetGrainInput) { v.Description = "bad\u0001description" },
		"c1 control":                func(v *DatasetGrainInput) { v.Description = "bad\u0085description" },
		"invalid utf8":              func(v *DatasetGrainInput) { v.Description = string([]byte{0xff}) },
		"description over bytes":    func(v *DatasetGrainInput) { v.Description = strings.Repeat("x", 1025) },
		"no key fields":             func(v *DatasetGrainInput) { v.KeyFields = nil },
		"empty key fields":          func(v *DatasetGrainInput) { v.KeyFields = []string{} },
		"too many key fields":       func(v *DatasetGrainInput) { v.KeyFields = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} },
		"empty field token":         func(v *DatasetGrainInput) { v.KeyFields = []string{""} },
		"field token bad char":      func(v *DatasetGrainInput) { v.KeyFields = []string{"bad.token"} },
		"field token leading digit": func(v *DatasetGrainInput) { v.KeyFields = []string{"9bad"} },
		"field token over bytes":    func(v *DatasetGrainInput) { v.KeyFields = []string{strings.Repeat("a", 129)} },
		"duplicate key fields":      func(v *DatasetGrainInput) { v.KeyFields = []string{"same", "same"} },
		"empty duplicate policy":    func(v *DatasetGrainInput) { v.DuplicatePolicy = "" },
		"unknown duplicate policy":  func(v *DatasetGrainInput) { v.DuplicatePolicy = DuplicatePolicy("FIRST") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validDatasetGrainInput()
			mutate(&input)
			assertInvalidDatasetGrain(t, input)
		})
	}
}

func TestDatasetGrainAcceptsExactUTF8ByteBounds(t *testing.T) {
	input := validDatasetGrainInput()
	input.Description = strings.Repeat("я", 512)
	if len(input.Description) != 1024 {
		t.Fatalf("cyrillic description not 1024 bytes: %d", len(input.Description))
	}
	if value, err := NewDatasetGrain(input); err != nil || !value.Valid() {
		t.Fatalf("exact 1024-byte description rejected: valid=%v err=%v", value.Valid(), err)
	}
	input.Description = strings.Repeat("x", 1024)
	if value, err := NewDatasetGrain(input); err != nil || !value.Valid() {
		t.Fatalf("exact 1024-byte ascii description rejected: valid=%v err=%v", value.Valid(), err)
	}
	input.Description = strings.Repeat("x", 1)
	if value, err := NewDatasetGrain(input); err != nil || !value.Valid() {
		t.Fatalf("1-byte description rejected: valid=%v err=%v", value.Valid(), err)
	}
	input.KeyFields = []string{strings.Repeat("a", 128)}
	if value, err := NewDatasetGrain(input); err != nil || !value.Valid() {
		t.Fatalf("128-byte field token rejected: valid=%v err=%v", value.Valid(), err)
	}
	input.KeyFields = []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	if value, err := NewDatasetGrain(input); err != nil || !value.Valid() {
		t.Fatalf("8 key fields rejected: valid=%v err=%v", value.Valid(), err)
	}
}

func TestDatasetGrainZeroAndForgedValuesAreInvalid(t *testing.T) {
	if (DatasetGrain{}).Valid() {
		t.Fatal("zero grain is valid")
	}
	original, err := NewDatasetGrain(validDatasetGrainInput())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*DatasetGrain){
		"description": func(v *DatasetGrain) { v.description = "" },
		"empty keys":  func(v *DatasetGrain) { v.keyFields = nil },
		"key token":   func(v *DatasetGrain) { v.keyFields = []string{"bad.token"} },
		"duplicate":   func(v *DatasetGrain) { v.keyFields = []string{"same", "same"} },
		"order":       func(v *DatasetGrain) { v.keyFields = []string{"z", "a"} },
		"policy":      func(v *DatasetGrain) { v.duplicatePolicy = "" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			forged := original
			forged.keyFields = append([]string(nil), original.keyFields...)
			mutate(&forged)
			if forged.Valid() {
				t.Fatal("forged grain is valid")
			}
		})
	}
}

func TestDatasetGrainReconstructionFromValuesPreservesValue(t *testing.T) {
	original, err := NewDatasetGrain(validDatasetGrainInput())
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := NewDatasetGrain(original.Values())
	if err != nil || !rebuilt.Valid() {
		t.Fatalf("reconstruction rejected: valid=%v err=%v", rebuilt.Valid(), err)
	}
	if !reflect.DeepEqual(original.Values(), rebuilt.Values()) {
		t.Fatalf("reconstruction changed value: %#v vs %#v", original.Values(), rebuilt.Values())
	}
	if !reflect.DeepEqual(original.Values(), rebuilt.Values()) {
		t.Fatal("reconstruction not idempotent")
	}
}

func TestDatasetGrainErrorsCarryNoSubmittedContent(t *testing.T) {
	secretDescription := "secret-description-marker"
	secretToken := "secret_token_marker"
	input := DatasetGrainInput{
		Description:     secretDescription,
		KeyFields:       []string{secretToken, secretToken},
		DuplicatePolicy: DuplicateReject,
	}
	value, err := NewDatasetGrain(input)
	if err == nil || value.Valid() {
		t.Fatalf("invalid grain accepted: valid=%v err=%v", value.Valid(), err)
	}
	if CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("grain error not content-free invalid request: %v", err)
	}
	if strings.Contains(err.Error(), secretDescription) || strings.Contains(err.Error(), secretToken) {
		t.Fatalf("grain error leaked submitted content: %v", err)
	}
}

func assertInvalidDatasetGrain(t *testing.T, input DatasetGrainInput) {
	t.Helper()
	value, err := NewDatasetGrain(input)
	if err == nil || value.Valid() || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid grain accepted or leaked detail: valid=%v err=%v", value.Valid(), err)
	}
	for _, token := range input.KeyFields {
		if token != "" && strings.Contains(err.Error(), token) {
			t.Fatalf("grain error leaked field token: %v", err)
		}
	}
	if input.Description != "" && strings.Contains(err.Error(), input.Description) {
		t.Fatalf("grain error leaked description: %v", err)
	}
}
