package analytic

import (
	"errors"
	"reflect"
	"testing"
)

func TestDatasetProfileSealNormalizesAndExposesDetachedValues(t *testing.T) {
	spec := validDatasetProfileSpec(t)
	_, expectedHash := canonicalProfileForTest(t, spec)
	profile, err := NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Valid() || profile.Hash() != expectedHash {
		t.Fatalf("profile did not seal canonical identity: valid=%v hash=%q", profile.Valid(), profile.Hash())
	}
	if profile.Key() != spec.Key || profile.Mode() != spec.Mode || profile.Source() != spec.Source ||
		profile.Time() != spec.Time || profile.Coverage() != spec.Coverage || profile.Limits() != spec.Limits {
		t.Fatal("scalar accessors did not round trip")
	}
	fields, measures := profile.Fields(), profile.Measures()
	if len(fields) != len(spec.Fields) || fields[0].Values().Token != "object_id" ||
		len(measures) != len(spec.Measures) || measures[0].Values().ID != "amount" {
		t.Fatalf("members not normalized: fields=%v measures=%v", fields, measures)
	}
	field, found := profile.Field("amount")
	if !found || field.Values().Token != "amount" {
		t.Fatal("field lookup failed")
	}
	measure, found := profile.Measure("rows")
	if !found || measure.Values().ID != "rows" {
		t.Fatal("measure lookup failed")
	}
	if _, found := profile.Field("missing"); found {
		t.Fatal("unknown field found")
	}
	if _, found := profile.Measure("missing"); found {
		t.Fatal("unknown measure found")
	}
}

func TestDatasetProfileSealDefensivelyCopiesAllSlices(t *testing.T) {
	spec := validDatasetProfileSpec(t)
	profile, err := NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	hash := profile.Hash()
	spec.Fields[0] = FieldSpec{}
	spec.Measures[0] = MeasureSpec{}

	fields := profile.Fields()
	measures := profile.Measures()
	fields[0] = FieldSpec{}
	measures[0] = MeasureSpec{}
	detached := profile.Spec()
	detached.Fields[0] = FieldSpec{}
	detached.Measures[0] = MeasureSpec{}

	field, hasField := profile.Field("object_id")
	measure, hasMeasure := profile.Measure("amount")
	if !profile.Valid() || profile.Hash() != hash || !hasField || !field.Valid() || !hasMeasure || !measure.Valid() {
		t.Fatal("caller mutation changed sealed profile")
	}
}

func TestDatasetProfileSealRejectsZeroForgeryAndInvalidInput(t *testing.T) {
	if (DatasetProfile{}).Valid() {
		t.Fatal("zero profile is valid")
	}
	profile, err := NewDatasetProfile(validDatasetProfileSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	forgedHash := profile
	forgedHash.hash = "sha256:" + profile.Hash()[len("sha256:")+1:] + "0"
	if forgedHash.Valid() {
		t.Fatal("forged hash is valid")
	}
	forgedMember := profile
	forgedMember.coverage = CoverageSourceGuaranteed
	if forgedMember.Valid() {
		t.Fatal("forged member is valid")
	}

	invalid := validDatasetProfileSpec(t)
	invalid.Key = ProfileKey{}
	got, err := NewDatasetProfile(invalid)
	if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) ||
		errors.Unwrap(err) != nil || got.Valid() {
		t.Fatalf("invalid profile accepted or leaked detail: profile=%v err=%v", got.Valid(), err)
	}
}

func TestDatasetProfileSealHasNoExportedFields(t *testing.T) {
	typeOf := reflect.TypeOf(DatasetProfile{})
	for index := 0; index < typeOf.NumField(); index++ {
		if typeOf.Field(index).IsExported() {
			t.Fatalf("DatasetProfile exposes field %q", typeOf.Field(index).Name)
		}
	}
}
