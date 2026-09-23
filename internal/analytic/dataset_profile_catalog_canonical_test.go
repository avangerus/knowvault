package analytic

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDatasetProfileCatalogCanonicalEnvelope(t *testing.T) {
	alpha := datasetProfileCatalogFixture(t, "alpha", 1)
	beta := datasetProfileCatalogFixture(t, "beta", 1)

	left := mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(beta, ProfileActive),
		catalogEntry(alpha, ProfileRetired),
	})
	right := mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(alpha, ProfileRetired),
		catalogEntry(beta, ProfileActive),
	})

	leftBytes, leftHash := canonicalDatasetProfileCatalogForTest(t, left)
	rightBytes, rightHash := canonicalDatasetProfileCatalogForTest(t, right)
	if !bytes.Equal(leftBytes, rightBytes) || leftHash != rightHash ||
		left.Hash() != right.Hash() || left.Hash() != leftHash {
		t.Fatal("catalog input order changed canonical identity")
	}

	digest := sha256.Sum256(leftBytes)
	if want := "sha256:" + hex.EncodeToString(digest[:]); leftHash != want {
		t.Fatalf("hash=%q want independently computed %q", leftHash, want)
	}

	want := `{"catalog_id":"catalog.operations","entries":[{"key":{"dataset_id":"alpha","version":1},"profile_hash":"` +
		alpha.Hash() + `","state":"RETIRED"},{"key":{"dataset_id":"beta","version":1},"profile_hash":"` +
		beta.Hash() + `","state":"ACTIVE"}],"revision":7,"schema_version":"knowvault-dataset-profile-catalog-v1"}`
	if string(leftBytes) != want {
		t.Fatalf("canonical bytes=%s want=%s", leftBytes, want)
	}
	if bytes.Contains(leftBytes, []byte(":null")) {
		t.Fatalf("canonical catalog contains null: %s", leftBytes)
	}
	for _, forbidden := range []string{
		`"description"`, `"fields"`, `"measures"`, `"source"`,
		`"physical_name"`, `"schema_name"`, `"relation_name"`,
		`"connection_id"`, `"time"`, `"credentials"`, `"semantics"`,
		`"grain"`, `"coverage"`, `"limits"`, `"mode"`,
	} {
		if bytes.Contains(leftBytes, []byte(forbidden)) {
			t.Fatalf("canonical catalog embedded %s: %s", forbidden, leftBytes)
		}
	}
}

func TestDatasetProfileCatalogCanonicalHashBindsIdentity(t *testing.T) {
	alpha := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaOtherHash := datasetProfileRegistryFixture(t, "alpha", 1, CoverageSourceGuaranteed)
	beta := datasetProfileCatalogFixture(t, "beta", 1)
	if alphaOtherHash.Key() != alpha.Key() || alphaOtherHash.Hash() == alpha.Hash() {
		t.Fatal("fixture did not produce a valid same-key profile with another hash")
	}

	baseline := mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(alpha, ProfileActive),
	})
	cases := map[string]DatasetProfileCatalog{
		"catalog id": mustDatasetProfileCatalogCanonicalTest(t, "catalog.reporting", 7, []CatalogEntryInput{
			catalogEntry(alpha, ProfileActive),
		}),
		"revision": mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 8, []CatalogEntryInput{
			catalogEntry(alpha, ProfileActive),
		}),
		"membership": mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
			catalogEntry(alpha, ProfileActive),
			catalogEntry(beta, ProfileActive),
		}),
		"valid profile hash": mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
			catalogEntry(alphaOtherHash, ProfileActive),
		}),
		"state": mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
			catalogEntry(alpha, ProfileRetired),
		}),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) {
			if !candidate.Valid() {
				t.Fatal("candidate catalog is invalid")
			}
			if candidate.Hash() == baseline.Hash() {
				t.Fatal("catalog identity mutation did not change hash")
			}
		})
	}
}

func TestDatasetProfileCatalogCanonicalRejectsOldSealMutations(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	beta := datasetProfileCatalogFixture(t, "beta", 1)
	gamma := datasetProfileCatalogFixture(t, "gamma", 1)
	alphaOtherHash := datasetProfileRegistryFixture(t, "alpha", 1, CoverageSourceGuaranteed)

	catalog := mustDatasetProfileCatalogCanonicalTest(t, "catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileRetired),
		catalogEntry(beta, ProfileActive),
	})

	cases := map[string]func(DatasetProfileCatalog) DatasetProfileCatalog{
		"reorder": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0], value.entries[1] = value.entries[1], value.entries[0]
			return value
		},
		"member substitution": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[2].Profile = gamma
			return value
		},
		"profile substitution": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].Profile = alphaOtherHash
			return value
		},
		"state mutation": func(value DatasetProfileCatalog) DatasetProfileCatalog {
			value.entries = cloneCatalogEntries(value.entries)
			value.entries[0].State = ProfileRetired
			return value
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if mutate(catalog).Valid() {
				t.Fatal("old catalog seal accepted a mutated catalog")
			}
		})
	}
}

func mustDatasetProfileCatalogCanonicalTest(t *testing.T, id string, revision int64, entries []CatalogEntryInput) DatasetProfileCatalog {
	t.Helper()
	value, err := NewDatasetProfileCatalog(id, revision, entries)
	if err != nil || !value.Valid() {
		t.Fatalf("catalog construction failed: valid=%v err=%v", value.Valid(), err)
	}
	return value
}

func canonicalDatasetProfileCatalogForTest(t *testing.T, value DatasetProfileCatalog) ([]byte, string) {
	t.Helper()
	normalized, err := normalizeDatasetProfileCatalog(value.id, value.revision, value.entries)
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, err := canonicalDatasetProfileCatalog(normalized)
	if err != nil {
		t.Fatal(err)
	}
	return raw, hash
}
