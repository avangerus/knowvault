package analytic

import "math"

// ValidateDatasetProfileCatalogTransition proves that next is the only legal
// immediate successor of previous: same catalog identity, exactly one revision
// step, no entry removed or mutated, no retired entry revived, every new entry
// active, and at least one addition or ACTIVE->RETIRED change.
func ValidateDatasetProfileCatalogTransition(previous, next DatasetProfileCatalog) error {
	if !previous.Valid() || !next.Valid() {
		return invalidDatasetProfileCatalogTransition()
	}
	if previous.id != next.id {
		return invalidDatasetProfileCatalogTransition()
	}
	if previous.revision == math.MaxInt64 || next.revision != previous.revision+1 {
		return invalidDatasetProfileCatalogTransition()
	}

	previousMaxVersion := make(map[string]int64, len(previous.entries))
	for _, entry := range previous.entries {
		previousMaxVersion[entry.Profile.Key().DatasetID()] = entry.Profile.Key().Version()
	}

	changed := false
	seen := make(map[ProfileKey]struct{}, len(next.entries))
	for _, entry := range next.entries {
		key := entry.Profile.Key()
		seen[key] = struct{}{}
		prior, existed := previous.Inspect(key)
		if !existed {
			if entry.State != ProfileActive {
				return invalidDatasetProfileCatalogTransition()
			}
			if maximum, present := previousMaxVersion[key.DatasetID()]; present && key.Version() <= maximum {
				return invalidDatasetProfileCatalogTransition()
			}
			changed = true
			continue
		}
		if entry.Profile.Hash() != prior.Profile.Hash() {
			return invalidDatasetProfileCatalogTransition()
		}
		switch {
		case prior.State == ProfileActive && entry.State == ProfileActive:
		case prior.State == ProfileActive && entry.State == ProfileRetired:
			changed = true
		case prior.State == ProfileRetired && entry.State == ProfileRetired:
		default:
			return invalidDatasetProfileCatalogTransition()
		}
	}

	for _, entry := range previous.entries {
		if _, present := seen[entry.Profile.Key()]; !present {
			return invalidDatasetProfileCatalogTransition()
		}
	}

	if !changed {
		return invalidDatasetProfileCatalogTransition()
	}
	return nil
}

func invalidDatasetProfileCatalogTransition() error { return &Error{code: CodeInvalidRequest} }
