package analytic

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func validProfileSemanticsInput() ProfileSemanticsInput {
	return ProfileSemanticsInput{
		DatasetLabel:       "Removal operations",
		DatasetDescription: "One approved projection of removal operations.",
		Fields: []FieldSemanticsInput{
			{Token: "vehicle_id", Label: "Vehicle", Description: "Vehicle business identifier.", NullMeaning: "Not applicable; this field is required.", Aliases: []string{"truck"}},
			{Token: "event_at", Label: "Event time", Description: "Time of the operation.", NullMeaning: "The source did not report the event time.", Aliases: []string{"operation time"}},
		},
		Measures: []MeasureSemanticsInput{
			{ID: "vehicles", Label: "Vehicles", Description: "Distinct vehicles.", Aliases: []string{"truck count"}},
			{ID: "rows", Label: "Operations", Description: "Number of operation rows.", Aliases: []string{"removals"}},
		},
	}
}

func TestProfileSemanticsNormalizesAndDetaches(t *testing.T) {
	input := validProfileSemanticsInput()
	value, err := NewProfileSemantics(input)
	if err != nil || !value.Valid() {
		t.Fatalf("valid semantics rejected: valid=%v err=%v", value.Valid(), err)
	}
	want := value.Values()
	if want.Fields[0].Token != "event_at" || want.Fields[1].Token != "vehicle_id" || want.Measures[0].ID != "rows" || want.Measures[1].ID != "vehicles" {
		t.Fatalf("semantics not deterministically ordered: %#v", want)
	}
	input.DatasetLabel = "changed"
	input.Fields[0].Label = "changed"
	input.Fields[0].Aliases[0] = "changed"
	input.Measures[0].Aliases[0] = "changed"
	got := value.Values()
	got.DatasetLabel = "changed again"
	got.Fields[0].Label = "changed again"
	got.Fields[0].Aliases[0] = "changed again"
	got.Measures[0].Aliases[0] = "changed again"
	if !value.Valid() || !reflect.DeepEqual(value.Values(), want) {
		t.Fatalf("caller mutation changed semantics: %#v", value.Values())
	}
}

func TestProfileSemanticsRejectsInvalidInputsContentFree(t *testing.T) {
	cases := map[string]func(*ProfileSemanticsInput){
		"dataset label missing":       func(v *ProfileSemanticsInput) { v.DatasetLabel = "" },
		"dataset description missing": func(v *ProfileSemanticsInput) { v.DatasetDescription = "" },
		"field token invalid":         func(v *ProfileSemanticsInput) { v.Fields[0].Token = "bad.token" },
		"field label missing":         func(v *ProfileSemanticsInput) { v.Fields[0].Label = "" },
		"field description missing":   func(v *ProfileSemanticsInput) { v.Fields[0].Description = "" },
		"field null meaning missing":  func(v *ProfileSemanticsInput) { v.Fields[0].NullMeaning = "" },
		"measure id missing":          func(v *ProfileSemanticsInput) { v.Measures[0].ID = "" },
		"measure label missing":       func(v *ProfileSemanticsInput) { v.Measures[0].Label = "" },
		"measure description missing": func(v *ProfileSemanticsInput) { v.Measures[0].Description = "" },
		"duplicate field":             func(v *ProfileSemanticsInput) { v.Fields[1].Token = v.Fields[0].Token },
		"duplicate measure":           func(v *ProfileSemanticsInput) { v.Measures[1].ID = v.Measures[0].ID },
		"empty fields":                func(v *ProfileSemanticsInput) { v.Fields = nil },
		"too many fields":             func(v *ProfileSemanticsInput) { v.Fields = make([]FieldSemanticsInput, 257) },
		"empty measures":              func(v *ProfileSemanticsInput) { v.Measures = nil },
		"too many measures":           func(v *ProfileSemanticsInput) { v.Measures = make([]MeasureSemanticsInput, 129) },
		"too many aliases": func(v *ProfileSemanticsInput) {
			v.Fields[0].Aliases = []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}
		},
		"alias equals label":           func(v *ProfileSemanticsInput) { v.Fields[0].Aliases = []string{"vEhIcLe"} },
		"duplicate aliases":            func(v *ProfileSemanticsInput) { v.Measures[0].Aliases = []string{"Count", "cOuNt"} },
		"leading whitespace":           func(v *ProfileSemanticsInput) { v.DatasetLabel = " leading" },
		"trailing whitespace":          func(v *ProfileSemanticsInput) { v.Fields[0].Description = "trailing " },
		"control":                      func(v *ProfileSemanticsInput) { v.Measures[0].Label = "bad\u0085label" },
		"invalid utf8":                 func(v *ProfileSemanticsInput) { v.Fields[0].NullMeaning = string([]byte{0xff}) },
		"label over byte limit":        func(v *ProfileSemanticsInput) { v.Fields[0].Label = strings.Repeat("я", 81) },
		"alias over byte limit":        func(v *ProfileSemanticsInput) { v.Measures[0].Aliases = []string{strings.Repeat("я", 81)} },
		"description over byte limit":  func(v *ProfileSemanticsInput) { v.DatasetDescription = strings.Repeat("x", 1025) },
		"null meaning over byte limit": func(v *ProfileSemanticsInput) { v.Fields[0].NullMeaning = strings.Repeat("x", 1025) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validProfileSemanticsInput()
			mutate(&input)
			assertInvalidProfileSemantics(t, input)
		})
	}
}

func TestProfileSemanticsAcceptsExactUTF8ByteBounds(t *testing.T) {
	input := validProfileSemanticsInput()
	input.DatasetLabel = strings.Repeat("я", 80)
	input.DatasetDescription = strings.Repeat("я", 512)
	input.Fields[0].Aliases = []string{strings.Repeat("я", 80)}
	input.Fields[0].NullMeaning = strings.Repeat("я", 512)
	if value, err := NewProfileSemantics(input); err != nil || !value.Valid() {
		t.Fatalf("exact UTF-8 byte bounds rejected: valid=%v err=%v", value.Valid(), err)
	}
}

func TestProfileSemanticsZeroAndForgeryAreInvalid(t *testing.T) {
	if (ProfileSemantics{}).Valid() {
		t.Fatal("zero semantics is valid")
	}
	original, err := NewProfileSemantics(validProfileSemanticsInput())
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ProfileSemantics){
		"dataset":       func(v *ProfileSemantics) { v.datasetLabel = "" },
		"field token":   func(v *ProfileSemantics) { v.fields[0].token = "bad.token" },
		"field null":    func(v *ProfileSemantics) { v.fields[0].nullMeaning = "" },
		"field alias":   func(v *ProfileSemantics) { v.fields[0].aliases = []string{v.fields[0].label} },
		"measure id":    func(v *ProfileSemantics) { v.measures[0].id = "" },
		"measure alias": func(v *ProfileSemantics) { v.measures[0].aliases = []string{"same", "SAME"} },
		"field order":   func(v *ProfileSemantics) { v.fields[0], v.fields[1] = v.fields[1], v.fields[0] },
		"measure order": func(v *ProfileSemantics) { v.measures[0], v.measures[1] = v.measures[1], v.measures[0] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			forged := original
			forged.fields = append([]storedFieldSemantics(nil), original.fields...)
			forged.measures = append([]storedMeasureSemantics(nil), original.measures...)
			mutate(&forged)
			if forged.Valid() {
				t.Fatal("forged semantics is valid")
			}
		})
	}
}

func TestProfileSemanticsStoredTypesExposeNoFields(t *testing.T) {
	for _, value := range []any{ProfileSemantics{}, storedFieldSemantics{}, storedMeasureSemantics{}} {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			if typ.Field(index).IsExported() {
				t.Fatalf("%s exposes field %q", typ, typ.Field(index).Name)
			}
		}
	}
}

func assertInvalidProfileSemantics(t *testing.T, input ProfileSemanticsInput) {
	t.Helper()
	value, err := NewProfileSemantics(input)
	if err == nil || value.Valid() || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid semantics accepted or leaked detail: valid=%v err=%v", value.Valid(), err)
	}
}
