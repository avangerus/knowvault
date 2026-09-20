package analytic

import "sort"

const datasetProfileCatalogMaxEntries = 64

type ProfileState string

const (
	ProfileActive  ProfileState = "ACTIVE"
	ProfileRetired ProfileState = "RETIRED"
)

func (value ProfileState) Valid() bool {
	return value == ProfileActive || value == ProfileRetired
}

type CatalogEntryInput struct {
	Profile DatasetProfile
	State   ProfileState
}

// DatasetProfileCatalog is an immutable historical snapshot. ResolveActive
// proves activity only inside this exact snapshot; runtime must separately
// verify that the snapshot is still current and authorized.
type DatasetProfileCatalog struct {
	id       string
	revision int64
	entries  []CatalogEntryInput
	hash     string
}

type normalizedDatasetProfileCatalog struct {
	id       string
	revision int64
	entries  []CatalogEntryInput
}

func NewDatasetProfileCatalog(id string, revision int64, entries []CatalogEntryInput) (DatasetProfileCatalog, error) {
	normalized, err := normalizeDatasetProfileCatalog(id, revision, entries)
	if err != nil {
		return DatasetProfileCatalog{}, err
	}
	_, hash, err := canonicalDatasetProfileCatalog(normalized)
	if err != nil {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalog()
	}
	return DatasetProfileCatalog{
		id: normalized.id, revision: normalized.revision,
		entries: normalized.entries, hash: hash,
	}, nil
}

func normalizeDatasetProfileCatalog(id string, revision int64, entries []CatalogEntryInput) (normalizedDatasetProfileCatalog, error) {
	if !validProfileIdentity(id) || revision <= 0 ||
		len(entries) < 1 || len(entries) > datasetProfileCatalogMaxEntries {
		return normalizedDatasetProfileCatalog{}, invalidDatasetProfileCatalog()
	}
	values := cloneCatalogEntries(entries)
	for _, entry := range values {
		if !entry.Profile.Valid() || !entry.State.Valid() {
			return normalizedDatasetProfileCatalog{}, invalidDatasetProfileCatalog()
		}
	}
	sort.Slice(values, func(left, right int) bool {
		return profileKeyLess(values[left].Profile.Key(), values[right].Profile.Key())
	})
	for index := 1; index < len(values); index++ {
		if values[index-1].Profile.Key() == values[index].Profile.Key() {
			return normalizedDatasetProfileCatalog{}, invalidDatasetProfileCatalog()
		}
	}
	return normalizedDatasetProfileCatalog{id: id, revision: revision, entries: values}, nil
}

func (value DatasetProfileCatalog) Valid() bool {
	if !validProfileHash(value.hash) {
		return false
	}
	normalized, err := normalizeDatasetProfileCatalog(value.id, value.revision, value.entries)
	if err != nil || !catalogEntriesEqual(value.entries, normalized.entries) {
		return false
	}
	_, hash, err := canonicalDatasetProfileCatalog(normalized)
	return err == nil && hash == value.hash
}

func catalogEntriesEqual(left, right []CatalogEntryInput) bool {
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

func (value DatasetProfileCatalog) ID() string      { return value.id }
func (value DatasetProfileCatalog) Revision() int64 { return value.revision }
func (value DatasetProfileCatalog) Hash() string    { return value.hash }

func (value DatasetProfileCatalog) Entries() []CatalogEntryInput {
	if !value.Valid() {
		return nil
	}
	return cloneCatalogEntries(value.entries)
}

func (value DatasetProfileCatalog) Inspect(key ProfileKey) (CatalogEntryInput, bool) {
	if !key.Valid() || !value.Valid() {
		return CatalogEntryInput{}, false
	}
	index := sort.Search(len(value.entries), func(index int) bool {
		return !profileKeyLess(value.entries[index].Profile.Key(), key)
	})
	if index == len(value.entries) || value.entries[index].Profile.Key() != key {
		return CatalogEntryInput{}, false
	}
	return cloneCatalogEntry(value.entries[index]), true
}

func (value DatasetProfileCatalog) ResolveActive(key ProfileKey, expectedProfileHash string) (DatasetProfile, bool) {
	if !key.Valid() || !validProfileHash(expectedProfileHash) || !value.Valid() {
		return DatasetProfile{}, false
	}
	entry, found := value.Inspect(key)
	if !found || entry.State != ProfileActive ||
		entry.Profile.Hash() != expectedProfileHash || !entry.Profile.Valid() {
		return DatasetProfile{}, false
	}
	return cloneDatasetProfile(entry.Profile), true
}

func cloneCatalogEntry(value CatalogEntryInput) CatalogEntryInput {
	value.Profile = cloneDatasetProfile(value.Profile)
	return value
}

func cloneCatalogEntries(values []CatalogEntryInput) []CatalogEntryInput {
	cloned := make([]CatalogEntryInput, len(values))
	for index, value := range values {
		cloned[index] = cloneCatalogEntry(value)
	}
	return cloned
}

func invalidDatasetProfileCatalog() error { return &Error{code: CodeInvalidRequest} }
