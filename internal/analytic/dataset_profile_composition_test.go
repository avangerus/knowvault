package analytic

import "testing"

// TestDatasetProfileCompositionNormalizes proves a spec whose semantics and
// grain agree exactly with the structural fields and measures is accepted.
func TestDatasetProfileCompositionNormalizes(t *testing.T) {
	spec := validDatasetProfileSpec(t)
	if _, err := normalizeDatasetProfileSpec(spec); err != nil {
		t.Fatalf("valid composed spec rejected: %v", err)
	}
}

// TestDatasetProfileCompositionRejectsSemanticFieldSetMismatch proves the
// semantic field token set must exactly equal the structural field token set.
func TestDatasetProfileCompositionRejectsSemanticFieldSetMismatch(t *testing.T) {
	cases := map[string]func(*ProfileSemanticsInput){
		"missing": func(s *ProfileSemanticsInput) {
			keep := s.Fields[:len(s.Fields)-1]
			s.Fields = append([]FieldSemanticsInput(nil), keep...)
		},
		"extra": func(s *ProfileSemanticsInput) {
			s.Fields = append(s.Fields, FieldSemanticsInput{
				Token: "extra", Label: "Extra", Description: "Extra field", NullMeaning: "Not recorded",
			})
		},
		"same count mismatch": func(s *ProfileSemanticsInput) {
			s.Fields[len(s.Fields)-1].Token = "other"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			input := spec.Semantics.Values()
			mutate(&input)
			spec.Semantics = mustProfileSemantics(t, input)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
}

// TestDatasetProfileCompositionRejectsSemanticMeasureSetMismatch proves the
// semantic measure ID set must exactly equal the structural measure ID set.
func TestDatasetProfileCompositionRejectsSemanticMeasureSetMismatch(t *testing.T) {
	cases := map[string]func(*ProfileSemanticsInput){
		"missing": func(s *ProfileSemanticsInput) {
			keep := s.Measures[:len(s.Measures)-1]
			s.Measures = append([]MeasureSemanticsInput(nil), keep...)
		},
		"extra": func(s *ProfileSemanticsInput) {
			s.Measures = append(s.Measures, MeasureSemanticsInput{
				ID: "extra", Label: "Extra", Description: "Extra measure",
			})
		},
		"same count mismatch": func(s *ProfileSemanticsInput) {
			s.Measures[len(s.Measures)-1].ID = "other"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			input := spec.Semantics.Values()
			mutate(&input)
			spec.Semantics = mustProfileSemantics(t, input)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
}

// TestDatasetProfileCompositionRejectsGrainKeyFailures proves every grain key
// must exist and be non-null, while a non-output key stays valid because grain
// grants no output, filter, or group permission.
func TestDatasetProfileCompositionRejectsGrainKeyFailures(t *testing.T) {
	cases := map[string]func(*DatasetGrainInput){
		"absent key": func(s *DatasetGrainInput) {
			s.KeyFields = []string{"absent"}
		},
		"null key": func(s *DatasetGrainInput) {
			s.KeyFields = []string{"object_id", "null_col"}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			if name == "null key" {
				spec.Fields = append(spec.Fields, profileField(t, "null_col", "null_col", 6, ScalarText, false))
				spec.Semantics = mustProfileSemantics(t, profileSemanticsInputWithField(t, spec.Semantics.Values(), "null_col"))
				// The structural field is nullable-only if the constructor was told so.
				// Rebuild the appended field as nullable.
				nullable := normalizedNullableField(t, "null_col", "null_col", 6)
				spec.Fields[len(spec.Fields)-1] = nullable
			}
			input := spec.Grain.Values()
			mutate(&input)
			spec.Grain = mustDatasetGrain(t, input)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}

	t.Run("non-output key valid", func(t *testing.T) {
		// business_day is an existing structural field with OutputAllowed false.
		spec := validDatasetProfileSpec(t)
		grain := spec.Grain.Values()
		grain.KeyFields = []string{"business_day"}
		spec.Grain = mustDatasetGrain(t, grain)
		if _, err := normalizeDatasetProfileSpec(spec); err != nil {
			t.Fatalf("non-output grain key rejected: %v", err)
		}
	})
}

// TestDatasetProfileCompositionRejectsZeroAndInvalidValues proves zero and
// invalid Semantics and Grain fail with a content-free CodeInvalidRequest.
func TestDatasetProfileCompositionRejectsZeroAndInvalidValues(t *testing.T) {
	cases := map[string]func(*DatasetProfileSpec){
		"zero semantics": func(s *DatasetProfileSpec) { s.Semantics = ProfileSemantics{} },
		"zero grain":     func(s *DatasetProfileSpec) { s.Grain = DatasetGrain{} },
		"invalid semantics": func(s *DatasetProfileSpec) {
			forged := s.Semantics
			forged.measures = append([]storedMeasureSemantics(nil), forged.measures...)
			forged.measures[0].id = "bad id"
			s.Semantics = forged
		},
		"invalid grain": func(s *DatasetProfileSpec) {
			forged := s.Grain
			forged.duplicatePolicy = DuplicatePolicy("ALLOW")
			s.Grain = forged
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			mutate(&spec)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
}

func mustProfileSemantics(t *testing.T, input ProfileSemanticsInput) ProfileSemantics {
	t.Helper()
	value, err := NewProfileSemantics(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustDatasetGrain(t *testing.T, input DatasetGrainInput) DatasetGrain {
	t.Helper()
	value, err := NewDatasetGrain(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func profileSemanticsInputWithField(t *testing.T, input ProfileSemanticsInput, token string) ProfileSemanticsInput {
	t.Helper()
	input.Fields = append(input.Fields, FieldSemanticsInput{
		Token: token, Label: token, Description: token, NullMeaning: "Not recorded",
	})
	return input
}

func normalizedNullableField(t *testing.T, token, physical string, ordinal int) FieldSpec {
	t.Helper()
	value, err := NewFieldSpec(FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: physical,
		LogicalType: ScalarText, PhysicalType: PhysicalPGText,
		Nullable: true, OutputAllowed: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
