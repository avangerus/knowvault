package analytic

import (
	"errors"
	"reflect"
	"testing"
)

func TestDatasetProfileRegistryOrdersAndLooksUpExactVersions(t *testing.T) {
	alphaV1 := datasetProfileRegistryFixture(t, "alpha", 1, CoverageUnknown)
	alphaV2 := datasetProfileRegistryFixture(t, "alpha", 2, CoverageUnknown)
	betaV1 := datasetProfileRegistryFixture(t, "beta", 1, CoverageUnknown)
	registry, err := NewDatasetProfileRegistry(betaV1, alphaV2, alphaV1)
	if err != nil || !registry.Valid() {
		t.Fatalf("valid registry rejected: valid=%v err=%v", registry.Valid(), err)
	}
	listed := registry.Profiles()
	want := []ProfileKey{alphaV1.Key(), alphaV2.Key(), betaV1.Key()}
	if len(listed) != len(want) {
		t.Fatalf("profile count=%d want=%d", len(listed), len(want))
	}
	for index, key := range want {
		if listed[index].Key() != key {
			t.Fatalf("profile[%d] key=%v want=%v", index, listed[index].Key(), key)
		}
		byKey, found := registry.Lookup(key)
		if !found || !byKey.Valid() || byKey.Hash() != listed[index].Hash() {
			t.Fatalf("key lookup failed for %v", key)
		}
		byVersion, found := registry.LookupVersion(key.DatasetID(), key.Version())
		if !found || byVersion.Hash() != listed[index].Hash() {
			t.Fatalf("version lookup failed for %v", key)
		}
	}
	missing, _ := NewProfileKey("missing", 1)
	if _, found := registry.Lookup(missing); found {
		t.Fatal("unknown key found")
	}
	if _, found := registry.LookupVersion("alpha", 3); found {
		t.Fatal("unknown version found")
	}
	if _, found := registry.LookupVersion("", 0); found {
		t.Fatal("invalid identity found")
	}
}

func TestDatasetProfileRegistryRejectsInvalidDuplicatesAndAmbiguity(t *testing.T) {
	valid := datasetProfileRegistryFixture(t, "alpha", 1, CoverageUnknown)
	forged := valid
	forged.hash = "forged"
	ambiguous := datasetProfileRegistryFixture(t, "alpha", 1, CoverageSourceGuaranteed)

	cases := map[string][]DatasetProfile{
		"empty":           nil,
		"zero":            {{}},
		"forged hash":     {forged},
		"duplicate exact": {valid, valid},
		"ambiguous key":   {valid, ambiguous},
	}
	for name, profiles := range cases {
		t.Run(name, func(t *testing.T) {
			registry, err := NewDatasetProfileRegistry(profiles...)
			if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) ||
				errors.Unwrap(err) != nil || registry.Valid() {
				t.Fatalf("invalid registry accepted or leaked detail: valid=%v err=%v", registry.Valid(), err)
			}
		})
	}
}

func TestDatasetProfileRegistryDetachesInputsAndReturnedProfiles(t *testing.T) {
	original := datasetProfileRegistryFixture(t, "alpha", 1, CoverageUnknown)
	expectedHash := original.Hash()
	input := []DatasetProfile{original}
	registry, err := NewDatasetProfileRegistry(input...)
	if err != nil {
		t.Fatal(err)
	}
	input[0].fields[0] = FieldSpec{}
	input[0].measures[0] = MeasureSpec{}

	listed := registry.Profiles()
	listed[0].fields[0] = FieldSpec{}
	listed[0].measures[0] = MeasureSpec{}
	listed[0].coverage = CoverageSourceGuaranteed
	byKey, found := registry.Lookup(original.Key())
	if !found {
		t.Fatal("profile disappeared after caller mutation")
	}
	byKey.fields[0] = FieldSpec{}
	byKey.measures[0] = MeasureSpec{}

	again, found := registry.LookupVersion("alpha", 1)
	if !registry.Valid() || !found || !again.Valid() || again.Hash() != expectedHash {
		t.Fatal("caller mutation changed the registry")
	}
}

func TestDatasetProfileRegistryHasNoExportedFields(t *testing.T) {
	typeOf := reflect.TypeOf(DatasetProfileRegistry{})
	for index := 0; index < typeOf.NumField(); index++ {
		if typeOf.Field(index).IsExported() {
			t.Fatalf("DatasetProfileRegistry exposes field %q", typeOf.Field(index).Name)
		}
	}
}

func datasetProfileRegistryFixture(t *testing.T, datasetID string, version int64, coverage CoveragePolicy) DatasetProfile {
	t.Helper()
	spec := validDatasetProfileSpec(t)
	key, err := NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatal(err)
	}
	spec.Key = key
	spec.Coverage = coverage
	profile, err := NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}
