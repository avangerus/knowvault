package analytic

import "math"

// ValidateDatasetProfileCatalogTransition accepts one immutable, adjacent
// catalog snapshot transition. It performs no mutation or external lookup.
func ValidateDatasetProfileCatalogTransition(previous, next DatasetProfileCatalog) error {
	if !previous.Valid() || !next.Valid() ||
		previous.ID() != next.ID() ||
		previous.Revision() == math.MaxInt64 ||
		next.Revision() != previous.Revision()+1 {
		return invalidDatasetProfileCatalogTransition()
	}

	previousEntries := previous.Entries()
	nextEntries := next.Entries()
	previousByKey := make(map[ProfileKey]CatalogEntryInput, len(previousEntries))
	nextByKey := make(map[ProfileKey]CatalogEntryInput, len(nextEntries))
	previousMaxByDataset := make(map[string]int64)

	for _, entry := range previousEntries {
		key := entry.Profile.Key()
		previousByKey[key] = entry
		if maximum, found := previousMaxByDataset[key.DatasetID()]; !found || key.Version() > maximum {
			previousMaxByDataset[key.DatasetID()] = key.Version()
		}
	}
	for _, entry := range nextEntries {
		nextByKey[entry.Profile.Key()] = entry
	}

	changed := false
	for _, previousEntry := range previousEntries {
		key := previousEntry.Profile.Key()
		nextEntry, found := nextByKey[key]
		if !found || nextEntry.Profile.Hash() != previousEntry.Profile.Hash() {
			return invalidDatasetProfileCatalogTransition()
		}
		if previousEntry.State == ProfileRetired && nextEntry.State == ProfileActive {
			return invalidDatasetProfileCatalogTransition()
		}
		if previousEntry.State == ProfileActive && nextEntry.State == ProfileRetired {
			changed = true
		}
	}

	for _, nextEntry := range nextEntries {
		key := nextEntry.Profile.Key()
		if _, existed := previousByKey[key]; existed {
			continue
		}
		if nextEntry.State != ProfileActive {
			return invalidDatasetProfileCatalogTransition()
		}
		if maximum, existed := previousMaxByDataset[key.DatasetID()]; existed && key.Version() <= maximum {
			return invalidDatasetProfileCatalogTransition()
		}
		changed = true
	}

	if !changed {
		return invalidDatasetProfileCatalogTransition()
	}
	return nil
}

func invalidDatasetProfileCatalogTransition() error {
	return &Error{code: CodeInvalidRequest}
}
