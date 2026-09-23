package analytic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDatasetProfileCanonicalV2ProjectsNestedIdentity(t *testing.T) {
	canonical, hash := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	for _, member := range []string{
		`"schema_version":"knowvault-dataset-profile-v2"`,
		`"dataset_description":"Business operations records"`,
		`"dataset_label":"Operations"`,
		`"aliases":[]`,
		`"description":"Measured amount"`,
		`"null_meaning":"Not measured"`,
		`"description":"Sum of amount"`,
		`"description":"One row per object per business day"`,
		`"duplicate_policy":"REJECT"`,
		`"key_fields":["business_day","object_id"]`,
	} {
		if !bytes.Contains(canonical, []byte(member)) {
			t.Fatalf("canonical v2 missing %s: %s", member, canonical)
		}
	}
	digest := sha256.Sum256(canonical)
	if want := "sha256:" + hex.EncodeToString(digest[:]); hash != want {
		t.Fatalf("hash = %q, want independently computed %q", hash, want)
	}
}

func TestDatasetProfileCanonicalNestedOrderIsNormalized(t *testing.T) {
	left := validDatasetProfileSpec(t)
	right := validDatasetProfileSpec(t)
	semantics := right.Semantics.Values()
	for leftIndex, rightIndex := 0, len(semantics.Fields)-1; leftIndex < rightIndex; leftIndex, rightIndex = leftIndex+1, rightIndex-1 {
		semantics.Fields[leftIndex], semantics.Fields[rightIndex] = semantics.Fields[rightIndex], semantics.Fields[leftIndex]
	}
	for leftIndex, rightIndex := 0, len(semantics.Measures)-1; leftIndex < rightIndex; leftIndex, rightIndex = leftIndex+1, rightIndex-1 {
		semantics.Measures[leftIndex], semantics.Measures[rightIndex] = semantics.Measures[rightIndex], semantics.Measures[leftIndex]
	}
	right.Semantics = mustCanonicalSemantics(t, semantics)
	grain := right.Grain.Values()
	grain.KeyFields[0], grain.KeyFields[1] = grain.KeyFields[1], grain.KeyFields[0]
	right.Grain = mustCanonicalGrain(t, grain)

	leftBytes, leftHash := canonicalProfileForTest(t, left)
	rightBytes, rightHash := canonicalProfileForTest(t, right)
	if !bytes.Equal(leftBytes, rightBytes) || leftHash != rightHash {
		t.Fatal("normalized nested order changed canonical identity")
	}
}

func TestDatasetProfileCanonicalEveryNestedMemberChangesHash(t *testing.T) {
	semanticCases := map[string]func(*ProfileSemanticsInput){
		"dataset label":       func(v *ProfileSemanticsInput) { v.DatasetLabel = "Business operations" },
		"dataset description": func(v *ProfileSemanticsInput) { v.DatasetDescription = "Approved business operations records" },
		"field label":         func(v *ProfileSemanticsInput) { v.Fields[0].Label = "Total amount" },
		"field description":   func(v *ProfileSemanticsInput) { v.Fields[0].Description = "Approved measured amount" },
		"field null meaning":  func(v *ProfileSemanticsInput) { v.Fields[0].NullMeaning = "Source did not measure it" },
		"field aliases":       func(v *ProfileSemanticsInput) { v.Fields[0].Aliases = []string{"Total"} },
		"measure label":       func(v *ProfileSemanticsInput) { v.Measures[0].Label = "Total amount" },
		"measure description": func(v *ProfileSemanticsInput) { v.Measures[0].Description = "Approved sum of amount" },
		"measure aliases":     func(v *ProfileSemanticsInput) { v.Measures[0].Aliases = []string{"Total"} },
	}
	_, baselineHash := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	for name, mutate := range semanticCases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			value := spec.Semantics.Values()
			mutate(&value)
			spec.Semantics = mustCanonicalSemantics(t, value)
			_, changedHash := canonicalProfileForTest(t, spec)
			if changedHash == baselineHash {
				t.Fatal("semantic identity mutation did not change hash")
			}
		})
	}
	grainCases := map[string]func(*DatasetGrainInput){
		"grain description": func(v *DatasetGrainInput) { v.Description = "One approved row per object and business day" },
		"grain key":         func(v *DatasetGrainInput) { v.KeyFields = []string{"local_at"} },
	}
	for name, mutate := range grainCases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			value := spec.Grain.Values()
			mutate(&value)
			spec.Grain = mustCanonicalGrain(t, value)
			_, changedHash := canonicalProfileForTest(t, spec)
			if changedHash == baselineHash {
				t.Fatal("grain identity mutation did not change hash")
			}
		})
	}
}

func TestDatasetProfileCanonicalDuplicatePolicyIsProjected(t *testing.T) {
	normalized, err := normalizeDatasetProfileSpec(validDatasetProfileSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	_, baselineHash, err := canonicalDatasetProfile(normalized)
	if err != nil {
		t.Fatal(err)
	}
	forged := normalized
	forged.grain.duplicatePolicy = DuplicatePolicy("OTHER")
	_, changedHash, err := canonicalDatasetProfile(forged)
	if err != nil {
		t.Fatal(err)
	}
	if changedHash == baselineHash {
		t.Fatal("duplicate policy was omitted from canonical identity")
	}
}

func mustCanonicalGrain(t *testing.T, value DatasetGrainInput) DatasetGrain {
	t.Helper()
	result, err := NewDatasetGrain(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
