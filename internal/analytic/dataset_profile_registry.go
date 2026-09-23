package analytic

import "sort"

// DatasetProfileRegistry is an immutable, deterministically ordered set of
// sealed dataset profiles. A dataset id and profile version identify exactly
// one profile within a registry.
type DatasetProfileRegistry struct {
	profiles []DatasetProfile
}

func NewDatasetProfileRegistry(profiles ...DatasetProfile) (DatasetProfileRegistry, error) {
	if len(profiles) == 0 {
		return DatasetProfileRegistry{}, invalidDatasetProfileRegistry()
	}
	values := make([]DatasetProfile, len(profiles))
	for index, profile := range profiles {
		if !profile.Valid() {
			return DatasetProfileRegistry{}, invalidDatasetProfileRegistry()
		}
		values[index] = cloneDatasetProfile(profile)
	}
	sort.Slice(values, func(left, right int) bool {
		return profileKeyLess(values[left].key, values[right].key)
	})
	for index := 1; index < len(values); index++ {
		if values[index-1].key == values[index].key {
			return DatasetProfileRegistry{}, invalidDatasetProfileRegistry()
		}
	}
	return DatasetProfileRegistry{profiles: values}, nil
}

func (registry DatasetProfileRegistry) Valid() bool {
	if len(registry.profiles) == 0 {
		return false
	}
	for index, profile := range registry.profiles {
		if !profile.Valid() {
			return false
		}
		if index > 0 && !profileKeyLess(registry.profiles[index-1].key, profile.key) {
			return false
		}
	}
	return true
}

// Profiles returns detached profiles ordered by dataset id, then version.
func (registry DatasetProfileRegistry) Profiles() []DatasetProfile {
	if !registry.Valid() {
		return nil
	}
	profiles := make([]DatasetProfile, len(registry.profiles))
	for index, profile := range registry.profiles {
		profiles[index] = cloneDatasetProfile(profile)
	}
	return profiles
}

// Lookup returns the profile identified by an exact validated key.
func (registry DatasetProfileRegistry) Lookup(key ProfileKey) (DatasetProfile, bool) {
	if !key.Valid() || !registry.Valid() {
		return DatasetProfile{}, false
	}
	index := sort.Search(len(registry.profiles), func(index int) bool {
		return !profileKeyLess(registry.profiles[index].key, key)
	})
	if index == len(registry.profiles) || registry.profiles[index].key != key {
		return DatasetProfile{}, false
	}
	return cloneDatasetProfile(registry.profiles[index]), true
}

// LookupVersion resolves the same exact identity from its public components.
func (registry DatasetProfileRegistry) LookupVersion(datasetID string, profileVersion int64) (DatasetProfile, bool) {
	key, err := NewProfileKey(datasetID, profileVersion)
	if err != nil {
		return DatasetProfile{}, false
	}
	return registry.Lookup(key)
}

func cloneDatasetProfile(profile DatasetProfile) DatasetProfile {
	profile.fields = append([]FieldSpec(nil), profile.fields...)
	profile.measures = append([]MeasureSpec(nil), profile.measures...)
	return profile
}

func profileKeyLess(left, right ProfileKey) bool {
	return left.datasetID < right.datasetID || left.datasetID == right.datasetID && left.version < right.version
}

func invalidDatasetProfileRegistry() error { return &Error{code: CodeInvalidRequest} }
