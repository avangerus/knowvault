package analytic

import (
	"errors"
	"testing"
)

// datasetProfileCatalogTransitionFixture seals one immutable catalog snapshot.
func datasetProfileCatalogTransitionFixture(t *testing.T, id string, revision int64, entries []CatalogEntryInput) DatasetProfileCatalog {
	t.Helper()
	catalog, err := NewDatasetProfileCatalog(id, revision, entries)
	if err != nil || !catalog.Valid() {
		t.Fatalf("transition fixture invalid: valid=%v err=%v", catalog.Valid(), err)
	}
	return catalog
}

// datasetProfileCatalogTransitionFixtureForged seals a snapshot that did not go
// through the constructor; it must never pass Valid or the transition check.
func datasetProfileCatalogTransitionFixtureForged(t *testing.T, id string, revision int64, entries []CatalogEntryInput) DatasetProfileCatalog {
	t.Helper()
	catalog, err := NewDatasetProfileCatalog(id, revision, entries)
	if err != nil {
		t.Fatal(err)
	}
	catalog.hash = "forged"
	return catalog
}

func assertDatasetProfileCatalogTransitionAccepted(t *testing.T, previous, next DatasetProfileCatalog) {
	t.Helper()
	if err := ValidateDatasetProfileCatalogTransition(previous, next); err != nil {
		t.Fatalf("valid transition rejected: %v", err)
	}
}

func assertDatasetProfileCatalogTransitionRefused(t *testing.T, previous, next DatasetProfileCatalog) {
	t.Helper()
	err := ValidateDatasetProfileCatalogTransition(previous, next)
	if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) ||
		errors.Unwrap(err) != nil {
		t.Fatalf("forbidden transition accepted or leaked detail: %v", err)
	}
}

func TestValidateDatasetProfileCatalogTransitionAllowsStateAndAdditionRules(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)

	const catalogID = "catalog.operations"

	allActive := datasetProfileCatalogTransitionFixture(t, catalogID, 10, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})
	activeToActive := datasetProfileCatalogTransitionFixture(t, catalogID, 11, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileActive),
	})
	// New entry is ACTIVE; for an existing dataset its version must exceed the
	// previous maximum version for that dataset (alpha v2 > v1).
	assertDatasetProfileCatalogTransitionAccepted(t, allActive, activeToActive)

	// ACTIVE->RETIRED and RETIRED->RETIRED are allowed; version is untouched.
	allRetiredPrevious := datasetProfileCatalogTransitionFixture(t, catalogID, 20, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileRetired),
	})
	allRetiredNext := datasetProfileCatalogTransitionFixture(t, catalogID, 21, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(alphaV2, ProfileRetired),
	})
	assertDatasetProfileCatalogTransitionAccepted(t, allRetiredPrevious, allRetiredNext)

}

func TestValidateDatasetProfileCatalogTransitionAllActiveToAllRetired(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 31, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(betaV1, ProfileActive),
	})
	// Atomic batch retirement: every entry ACTIVE->RETIRED in one transition.
	next := datasetProfileCatalogTransitionFixture(t, catalogID, 32, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(betaV1, ProfileRetired),
	})
	assertDatasetProfileCatalogTransitionAccepted(t, previous, next)
	if _, found := next.ResolveActive(alphaV1.Key(), alphaV1.Hash()); found {
		t.Fatal("all-retired successor resolved an active profile")
	}
}

func TestValidateDatasetProfileCatalogTransitionForbidsReactivationAndDeletion(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	const catalogID = "catalog.operations"

	retiredPrevious := datasetProfileCatalogTransitionFixture(t, catalogID, 40, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(betaV1, ProfileActive),
	})

	t.Run("retired to active", func(t *testing.T) {
		reactivated := datasetProfileCatalogTransitionFixture(t, catalogID, 41, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(betaV1, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, retiredPrevious, reactivated)
	})

	t.Run("retired deletion", func(t *testing.T) {
		deleted := datasetProfileCatalogTransitionFixture(t, catalogID, 41, []CatalogEntryInput{
			catalogEntry(betaV1, ProfileActive),
		})
		if _, found := deleted.Inspect(alphaV1.Key()); found {
			t.Fatal("deletion fixture still carries the retired entry")
		}
		assertDatasetProfileCatalogTransitionRefused(t, retiredPrevious, deleted)
	})

	t.Run("active deletion", func(t *testing.T) {
		deleted := datasetProfileCatalogTransitionFixture(t, catalogID, 41, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileRetired),
		})
		assertDatasetProfileCatalogTransitionRefused(t, retiredPrevious, deleted)
	})
}

func TestValidateDatasetProfileCatalogTransitionForbidsSameKeyHashReplacement(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV1OtherHash := datasetProfileRegistryFixture(t, "alpha", 1, CoverageSourceGuaranteed)

	if alphaV1.Hash() == alphaV1OtherHash.Hash() {
		t.Fatal("replacement fixture shares the original hash")
	}

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 50, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})
	// Same key (dataset, version) with a different profile hash is a
	// mutation of an immutable entry, so the snapshot itself is forged.
	next := datasetProfileCatalogTransitionFixture(t, catalogID, 51, []CatalogEntryInput{
		catalogEntry(alphaV1OtherHash, ProfileActive),
	})
	assertDatasetProfileCatalogTransitionRefused(t, previous, next)
}

func TestValidateDatasetProfileCatalogTransitionEnforcesPerDatasetVersionMaxima(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV3 := datasetProfileCatalogFixture(t, "alpha", 3)
	alphaV4 := datasetProfileCatalogFixture(t, "alpha", 4)
	alphaV7 := datasetProfileCatalogFixture(t, "alpha", 7)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 60, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(alphaV4, ProfileActive),
	})

	t.Run("new dataset any positive version", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 61, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileRetired),
			catalogEntry(alphaV4, ProfileActive),
			catalogEntry(betaV1, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionAccepted(t, previous, next)
	})

	t.Run("existing dataset version above maximum", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 61, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileRetired),
			catalogEntry(alphaV4, ProfileActive),
			catalogEntry(alphaV7, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionAccepted(t, previous, next)
	})

	t.Run("existing dataset version below maximum", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 61, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileRetired),
			catalogEntry(alphaV3, ProfileActive),
			catalogEntry(alphaV4, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

}

func TestValidateDatasetProfileCatalogTransitionAdditionDoesNotAutoRetire(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 70, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})
	// alpha v2 is added while alpha v1 stays ACTIVE: the new version does not
	// implicitly retire the old one, and beta v1 is a brand-new dataset.
	next := datasetProfileCatalogTransitionFixture(t, catalogID, 71, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileActive),
		catalogEntry(betaV1, ProfileActive),
	})
	assertDatasetProfileCatalogTransitionAccepted(t, previous, next)

	alphaV1After, found := next.Inspect(alphaV1.Key())
	if !found || alphaV1After.State != ProfileActive {
		t.Fatal("adding a version auto-retired the previous one")
	}
	if _, found := next.ResolveActive(alphaV1.Key(), alphaV1.Hash()); !found {
		t.Fatal("previous active version no longer resolves after addition")
	}
}

func TestValidateDatasetProfileCatalogTransitionForbidsRetiredAdditionAndNoOp(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	alphaV3 := datasetProfileCatalogFixture(t, "alpha", 3)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 80, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})

	t.Run("new entry must be active", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 81, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(betaV1, ProfileRetired),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

	t.Run("revision only no-op", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 81, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

	t.Run("revision only no-op over multiple entries", func(t *testing.T) {
		widePrevious := datasetProfileCatalogTransitionFixture(t, catalogID, 82, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileRetired),
			catalogEntry(alphaV3, ProfileActive),
		})
		wideNext := datasetProfileCatalogTransitionFixture(t, catalogID, 83, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileRetired),
			catalogEntry(alphaV3, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, widePrevious, wideNext)
	})
}

func TestValidateDatasetProfileCatalogTransitionEnforcesExactRevisionStep(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 90, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})

	t.Run("equal revision", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 90, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

	t.Run("decreasing revision", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 89, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

	t.Run("skipped revision", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, catalogID, 92, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})

	t.Run("maxint64 overflow", func(t *testing.T) {
		maxPrevious := datasetProfileCatalogTransitionFixture(t, catalogID, 1<<63-1, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
		})
		// The successor cannot carry revision MaxInt64+1; the largest legal
		// snapshot therefore has no representable successor.
		overflowNext := datasetProfileCatalogTransitionFixture(t, catalogID, 1<<63-1, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, maxPrevious, overflowNext)
	})

	t.Run("different catalog id", func(t *testing.T) {
		next := datasetProfileCatalogTransitionFixture(t, "catalog.other", 91, []CatalogEntryInput{
			catalogEntry(alphaV1, ProfileActive),
			catalogEntry(alphaV2, ProfileActive),
		})
		assertDatasetProfileCatalogTransitionRefused(t, previous, next)
	})
}

func TestValidateDatasetProfileCatalogTransitionMixedTransitionWithOneViolation(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)
	betaV1 := datasetProfileCatalogFixture(t, "beta", 1)
	gammaV1 := datasetProfileCatalogFixture(t, "gamma", 1)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 100, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(betaV1, ProfileActive),
		catalogEntry(gammaV1, ProfileRetired),
	})

	// alpha: ACTIVE->RETIRED (legal). beta: ACTIVE->ACTIVE with a new higher
	// version (legal). gamma: the only violating change a RETIRED->ACTIVE
	// reactivation, so the whole atomic transition must be refused.
	next := datasetProfileCatalogTransitionFixture(t, catalogID, 101, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileRetired),
		catalogEntry(alphaV2, ProfileActive),
		catalogEntry(betaV1, ProfileActive),
		catalogEntry(gammaV1, ProfileActive),
	})
	assertDatasetProfileCatalogTransitionRefused(t, previous, next)
}

func TestValidateDatasetProfileCatalogTransitionRefusesInvalidOrForgedSnapshots(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)

	const catalogID = "catalog.operations"

	valid := datasetProfileCatalogTransitionFixture(t, catalogID, 110, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})
	validSuccessor := datasetProfileCatalogTransitionFixture(t, catalogID, 111, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileActive),
	})
	forgedHash := datasetProfileCatalogTransitionFixtureForged(t, catalogID, 111, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileActive),
	})

	cases := map[string]struct {
		previous DatasetProfileCatalog
		next     DatasetProfileCatalog
	}{
		"zero previous":           {DatasetProfileCatalog{}, validSuccessor},
		"zero next":               {valid, DatasetProfileCatalog{}},
		"both zero":               {DatasetProfileCatalog{}, DatasetProfileCatalog{}},
		"forged hash previous":    {forgedHash, validSuccessor},
		"forged hash next":        {valid, forgedHash},
		"forged state previous":   {forgedCatalogState(valid), validSuccessor},
		"forged state next":       {valid, forgedCatalogState(validSuccessor)},
		"forged profile previous": {forgedCatalogEntryProfile(valid), validSuccessor},
		"forged profile next":     {valid, forgedCatalogEntryProfile(validSuccessor)},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			assertDatasetProfileCatalogTransitionRefused(t, testCase.previous, testCase.next)
		})
	}
}

// forgedCatalogState keeps the frozen hash but plants an unknown profile state,
// so the snapshot must fail Valid and be refused by the transition check.
func forgedCatalogState(catalog DatasetProfileCatalog) DatasetProfileCatalog {
	catalog.entries = cloneCatalogEntries(catalog.entries)
	catalog.entries[0].State = ProfileState("PENDING")
	return catalog
}

// forgedCatalogEntryProfile swaps an entry profile without recomputing the hash.
func forgedCatalogEntryProfile(catalog DatasetProfileCatalog) DatasetProfileCatalog {
	catalog.entries = cloneCatalogEntries(catalog.entries)
	catalog.entries[0].Profile = DatasetProfile{}
	return catalog
}

func TestValidateDatasetProfileCatalogTransitionDoesNotMutateInputs(t *testing.T) {
	alphaV1 := datasetProfileCatalogFixture(t, "alpha", 1)
	alphaV2 := datasetProfileCatalogFixture(t, "alpha", 2)

	const catalogID = "catalog.operations"

	previous := datasetProfileCatalogTransitionFixture(t, catalogID, 120, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
	})
	next := datasetProfileCatalogTransitionFixture(t, catalogID, 121, []CatalogEntryInput{
		catalogEntry(alphaV1, ProfileActive),
		catalogEntry(alphaV2, ProfileActive),
	})
	previousEntries := previous.Entries()
	nextEntries := next.Entries()
	previousHash, previousRevision := previous.Hash(), previous.Revision()
	nextHash, nextRevision := next.Hash(), next.Revision()

	assertDatasetProfileCatalogTransitionAccepted(t, previous, next)

	if !previous.Valid() || !next.Valid() ||
		previous.Hash() != previousHash || next.Hash() != nextHash ||
		previous.Revision() != previousRevision || next.Revision() != nextRevision {
		t.Fatal("transition mutated the input snapshots")
	}
	afterPrevious := previous.Entries()
	afterNext := next.Entries()
	if !equalCatalogEntries(previousEntries, afterPrevious) || !equalCatalogEntries(nextEntries, afterNext) {
		t.Fatal("transition mutated or reordered input entries")
	}
}

func equalCatalogEntries(left, right []CatalogEntryInput) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].State != right[index].State ||
			left[index].Profile.Key() != right[index].Profile.Key() ||
			left[index].Profile.Hash() != right[index].Profile.Hash() {
			return false
		}
	}
	return true
}
