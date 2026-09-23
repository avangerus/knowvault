package analytic

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// datasetProfileCatalogFixture seals one valid profile under the given identity
// so a catalog test can attach it to an entry with an explicit profile state.
func datasetProfileCatalogFixture(t *testing.T, datasetID string, version int64) DatasetProfile {
	t.Helper()
	return datasetProfileRegistryFixture(t, datasetID, version, CoverageUnknown)
}

func catalogEntry(profile DatasetProfile, state ProfileState) CatalogEntryInput {
	return CatalogEntryInput{Profile: profile, State: state}
}

func TestDatasetProfileCatalogAcceptsMixedAndAllRetiredInKeyOrder(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	mixed, err := NewDatasetProfileCatalog("catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(betaV1, ProfileActive),
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(alphaV2, ProfileActive),
	})
	if err != nil || !mixed.Valid() {
		t.Fatalf("valid mixed catalog rejected: valid=%v err=%v", mixed.Valid(), err)
	}
	if mixed.ID() != "catalog.operations" || mixed.Revision() != 7 {
		t.Fatalf("catalog identity id=%q revision=%d", mixed.ID(), mixed.Revision())
	}
	entries := mixed.Entries()
	wantOrder := []ProfileKey{alphaV1.Key(), alphaV2.Key(), betaV1.Key()}
	if len(entries) != len(wantOrder) {
		t.Fatalf("entry count=%d want=%d", len(entries), len(wantOrder))
	}
	wantState := []ProfileState{ProfileRetired, ProfileActive, ProfileActive}
	wantHash := []string{alphaV1.Hash(), alphaV2.Hash(), betaV1.Hash()}
	for index, key := range wantOrder {
		if entries[index].Profile.Key() != key || entries[index].State != wantState[index] ||
			entries[index].Profile.Hash() != wantHash[index] {
			t.Fatalf("entry[%d]=%v/%v want=%v/%v", index,
				entries[index].Profile.Key(), entries[index].State, key, wantState[index])
		}
	}

	allRetired, err := NewDatasetProfileCatalog("catalog.operations", 1, []CatalogEntryInput{
		catalogEntry(alphaV2, ProfileRetired),
		catalogEntry(alphaV1, ProfileRetired),
	})
	if err != nil || !allRetired.Valid() {
		t.Fatalf("all-retired catalog rejected: valid=%v err=%v", allRetired.Valid(), err)
	}
	if _, found := allRetired.ResolveActive(alphaV1.Key(), alphaV1.Hash()); found {
		t.Fatal("all-retired catalog resolved an active profile")
	}
}

func TestDatasetProfileCatalogInspectReturnsExactActiveOrRetiredVersion(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	catalog, err := NewDatasetProfileCatalog("catalog.operations", 3, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(alphaV2, ProfileActive),
	})
	if err != nil {
		t.Fatal(err)
	}

	retired, found := catalog.Inspect(alphaV1.Key())
	if !found || retired.State != ProfileRetired || retired.Profile.Hash() != alphaV1.Hash() {
		t.Fatalf("retired inspect=%v/%v found=%v", retired.Profile.Key(), retired.State, found)
	}
	active, found := catalog.Inspect(alphaV2.Key())
	if !found || active.State != ProfileActive || active.Profile.Hash() != alphaV2.Hash() {
		t.Fatalf("active inspect=%v/%v found=%v", active.Profile.Key(), active.State, found)
	}

	unknown, _ := NewProfileKey("alpha", 9)
	if _, found := catalog.Inspect(unknown); found {
		t.Fatal("inspect resolved an unknown version")
	}
	if _, found := catalog.Inspect(ProfileKey{}); found {
		t.Fatal("inspect resolved an invalid key")
	}
}

func TestDatasetProfileCatalogResolveActiveRequiresExactMatch(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	retiredBeta := datasetProfileCatalogFixture(t, "beta", 1)
	activeBeta := datasetProfileRegistryFixture(t, "beta", 1, CoverageSourceGuaranteed)
	catalog, err := NewDatasetProfileCatalog("catalog.operations", 4, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileRetired),
		catalogEntry(retiredBeta, ProfileActive),
	})
	if err != nil {
		t.Fatal(err)
	}

	resolved, found := catalog.ResolveActive(alphaV1.Key(), alphaV1.Hash())
	if !found || !resolved.Valid() || resolved.Hash() != alphaV1.Hash() {
		t.Fatalf("exact active resolve failed: found=%v hash=%q", found, resolved.Hash())
	}

	unknown, _ := NewProfileKey("alpha", 9)
	cases := map[string]struct {
		key      ProfileKey
		hash     string
		wantHash string
	}{
		"retired":         {alphaV2.Key(), alphaV2.Hash(), ""},
		"unknown key":     {unknown, alphaV1.Hash(), ""},
		"wrong hash":      {alphaV1.Key(), alphaV2.Hash(), ""},
		"neighbor active": {retiredBeta.Key(), activeBeta.Hash(), ""},
		"invalid key":     {ProfileKey{}, alphaV1.Hash(), ""},
		"empty hash":      {alphaV1.Key(), "", ""},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			got, ok := catalog.ResolveActive(testCase.key, testCase.hash)
			if ok || got.Valid() || got.Hash() != testCase.wantHash {
				t.Fatalf("resolve fell back: ok=%v valid=%v hash=%q", ok, got.Valid(), got.Hash())
			}
		})
	}
}

func TestDatasetProfileCatalogRejectsInvalidConstruction(t *testing.T) {
	valid := datasetProfileCatalogFixture(t, "alpha", 1)
	forged := valid
	forged.hash = "forged"
	sameKeyOtherHash := datasetProfileRegistryFixture(t, "alpha", 1, CoverageSourceGuaranteed)

	cases := map[string]struct {
		id      string
		rev     int64
		entries []CatalogEntryInput
	}{
		"empty id":        {"", 1, []CatalogEntryInput{catalogEntry(valid, ProfileActive)}},
		"oversized id":    {strings.Repeat("a", 257), 1, []CatalogEntryInput{catalogEntry(valid, ProfileActive)}},
		"zero revision":   {"catalog.operations", 0, []CatalogEntryInput{catalogEntry(valid, ProfileActive)}},
		"negative rev":    {"catalog.operations", -1, []CatalogEntryInput{catalogEntry(valid, ProfileActive)}},
		"empty entries":   {"catalog.operations", 1, nil},
		"invalid profile": {"catalog.operations", 1, []CatalogEntryInput{catalogEntry(DatasetProfile{}, ProfileActive)}},
		"forged profile":  {"catalog.operations", 1, []CatalogEntryInput{catalogEntry(forged, ProfileActive)}},
		"empty state":     {"catalog.operations", 1, []CatalogEntryInput{catalogEntry(valid, "")}},
		"unknown state":   {"catalog.operations", 1, []CatalogEntryInput{catalogEntry(valid, ProfileState("PENDING"))}},
		"duplicate exact": {"catalog.operations", 1, []CatalogEntryInput{
			catalogEntry(valid, ProfileActive), catalogEntry(valid, ProfileRetired),
		}},
		"duplicate same key": {"catalog.operations", 1, []CatalogEntryInput{
			catalogEntry(valid, ProfileActive), catalogEntry(sameKeyOtherHash, ProfileActive),
		}},
	}
	tooMany := make([]CatalogEntryInput, 65)
	for index := range tooMany {
		profile := datasetProfileCatalogFixture(t, fmt.Sprintf("dataset_%02d", index), 1)
		tooMany[index] = catalogEntry(profile, ProfileActive)
	}
	cases["too many entries"] = struct {
		id      string
		rev     int64
		entries []CatalogEntryInput
	}{"catalog.operations", 1, tooMany}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			catalog, err := NewDatasetProfileCatalog(testCase.id, testCase.rev, testCase.entries)
			assertContentFreeInvalidCatalog(t, catalog, err)
		})
	}
}

func TestDatasetProfileCatalogDetachesEntriesAndProfiles(t *testing.T) {
	original := datasetProfileCatalogFixture(t, "alpha", 1)
	expectedHash := original.Hash()
	entries := []CatalogEntryInput{catalogEntry(original, ProfileActive)}
	catalog, err := NewDatasetProfileCatalog("catalog.operations", 5, entries)
	if err != nil {
		t.Fatal(err)
	}

	entries[0].State = ProfileRetired
	entries[0].Profile.fields[0] = FieldSpec{}
	entries[0].Profile.measures[0] = MeasureSpec{}
	entries[0].Profile.coverage = CoverageSourceGuaranteed

	returned := catalog.Entries()
	returned[0].State = ProfileRetired
	returned[0].Profile.fields[0] = FieldSpec{}
	returned[0].Profile.measures[0] = MeasureSpec{}

	inspected, found := catalog.Inspect(original.Key())
	if !found {
		t.Fatal("entry disappeared after caller mutation")
	}
	inspected.Profile.fields[0] = FieldSpec{}
	inspected.Profile.measures[0] = MeasureSpec{}
	inspected.Profile.coverage = CoverageSourceGuaranteed

	again, found := catalog.ResolveActive(original.Key(), expectedHash)
	if !catalog.Valid() || !found || !again.Valid() || again.Hash() != expectedHash {
		t.Fatal("caller mutation changed the catalog")
	}
}

func TestDatasetProfileCatalogValidRejectsForgedValues(t *testing.T) {
	valid := datasetProfileCatalogFixture(t, "alpha", 1)
	catalog, err := NewDatasetProfileCatalog("catalog.operations", 1, []CatalogEntryInput{
		catalogEntry(valid, ProfileActive),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.Valid() {
		t.Fatal("valid catalog reported invalid")
	}

	forgeries := map[string]func(DatasetProfileCatalog) DatasetProfileCatalog{
		"empty id":      func(value DatasetProfileCatalog) DatasetProfileCatalog { value.id = ""; return value },
		"zero revision": func(value DatasetProfileCatalog) DatasetProfileCatalog { value.revision = 0; return value },
		"empty entries": func(value DatasetProfileCatalog) DatasetProfileCatalog { value.entries = nil; return value },
		"forged state": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].State = ProfileState("PENDING")
			return value
		},
		"empty state": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].State = ""
			return value
		},
		"forged profile": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].Profile = DatasetProfile{}
			return value
		},
		"forged profile hash": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].Profile = forgedCatalogProfile(valid)
			return value
		},
		"forged seal": func(value DatasetProfileCatalog) DatasetProfileCatalog { value.hash = "deadbeef"; return value },
	}
	if (DatasetProfileCatalog{}).Valid() {
		t.Fatal("zero catalog reported valid")
	}
	for name, forge := range forgeries {
		t.Run(name, func(t *testing.T) {
			value := forge(catalog)
			if value.Valid() {
				t.Fatalf("forged catalog %q reported valid", name)
			}
		})
	}
}

func TestDatasetProfileCatalogAcceptsExactBounds(t *testing.T) {
	entries := make([]CatalogEntryInput, 64)
	for index := range entries {
		profile := datasetProfileCatalogFixture(t, fmt.Sprintf("bounded_%02d", index), 1)
		entries[index] = catalogEntry(profile, ProfileRetired)
	}
	catalog, err := NewDatasetProfileCatalog(strings.Repeat("a", 256), 1, entries)
	if err != nil || !catalog.Valid() || len(catalog.Entries()) != 64 {
		t.Fatalf("exact catalog bounds rejected: valid=%v entries=%d err=%v", catalog.Valid(), len(catalog.Entries()), err)
	}
}

func TestDatasetProfileCatalogConstructorErrorsAreContentFree(t *testing.T) {
	valid := datasetProfileCatalogFixture(t, "alpha", 1)
	_, err := NewDatasetProfileCatalog("", 0, nil)
	if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) ||
		errors.Unwrap(err) != nil {
		t.Fatalf("constructor error not content free: %v", err)
	}
	catalog, err := NewDatasetProfileCatalog("catalog.operations", 1, []CatalogEntryInput{
		catalogEntry(valid, ProfileActive),
	})
	if err != nil || !catalog.Valid() {
		t.Fatalf("valid construction failed: valid=%v err=%v", catalog.Valid(), err)
	}
}

func TestDatasetProfileCatalogHasNoExportedFields(t *testing.T) {
	typeOf := reflect.TypeOf(DatasetProfileCatalog{})
	for index := 0; index < typeOf.NumField(); index++ {
		if typeOf.Field(index).IsExported() {
			t.Fatalf("DatasetProfileCatalog exposes field %q", typeOf.Field(index).Name)
		}
	}
}

func forgedCatalogProfile(profile DatasetProfile) DatasetProfile {
	profile.hash = "forged"
	return profile
}

func assertContentFreeInvalidCatalog(t *testing.T, catalog DatasetProfileCatalog, err error) {
	t.Helper()
	if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) ||
		errors.Unwrap(err) != nil || catalog.Valid() {
		t.Fatalf("invalid catalog accepted or leaked detail: valid=%v err=%v", catalog.Valid(), err)
	}
}
