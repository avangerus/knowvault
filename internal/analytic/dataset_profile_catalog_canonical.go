package analytic

import "knowvault.local/verified-workspace/internal/source/canon"

const datasetProfileCatalogSchemaVersion = "knowvault-dataset-profile-catalog-v1"

type canonicalDatasetProfileCatalogKey struct {
	DatasetID string `json:"dataset_id"`
	Version   int64  `json:"version"`
}

type canonicalDatasetProfileCatalogEntry struct {
	Key         canonicalDatasetProfileCatalogKey `json:"key"`
	ProfileHash string                            `json:"profile_hash"`
	State       ProfileState                      `json:"state"`
}

type canonicalDatasetProfileCatalogEnvelope struct {
	SchemaVersion string                                `json:"schema_version"`
	CatalogID     string                                `json:"catalog_id"`
	Revision      int64                                 `json:"revision"`
	Entries       []canonicalDatasetProfileCatalogEntry `json:"entries"`
}

func canonicalDatasetProfileCatalog(value normalizedDatasetProfileCatalog) ([]byte, string, error) {
	entries := make([]canonicalDatasetProfileCatalogEntry, len(value.entries))
	for index, entry := range value.entries {
		key := entry.Profile.Key()
		entries[index] = canonicalDatasetProfileCatalogEntry{
			Key: canonicalDatasetProfileCatalogKey{
				DatasetID: key.DatasetID(),
				Version:   key.Version(),
			},
			ProfileHash: entry.Profile.Hash(),
			State:       entry.State,
		}
	}
	raw, err := canon.CanonicalJSON(canonicalDatasetProfileCatalogEnvelope{
		SchemaVersion: datasetProfileCatalogSchemaVersion,
		CatalogID:     value.id,
		Revision:      value.revision,
		Entries:       entries,
	})
	if err != nil {
		return nil, "", &Error{code: CodeInvalidRequest}
	}
	return raw, canon.Hash(raw), nil
}
