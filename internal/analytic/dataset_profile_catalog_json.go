package analytic

import (
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
)

const datasetProfileCatalogMountSchemaVersion = "knowvault-dataset-profile-catalog-mount-v1"

// maxDatasetProfileCatalogJSONBytes bounds the whole trusted, server-owned
// catalog mount document before decoding can allocate any nested representation.
const maxDatasetProfileCatalogJSONBytes = 1 << 20

// DecodeDatasetProfileCatalogJSON strictly decodes one server-owned catalog
// mount document. The wire embeds the exact trusted profile object accepted by
// DecodeDatasetProfileJSON and deliberately has no place for a caller-supplied
// catalog or profile hash, SQL text, endpoint, credential, DSN, or relation
// override. The sealed catalog computes its own deterministic hash.
func DecodeDatasetProfileCatalogJSON(raw []byte) (DatasetProfileCatalog, error) {
	if len(raw) == 0 || len(raw) > maxDatasetProfileCatalogJSONBytes {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
	}
	var wire datasetProfileCatalogJSON
	if err := jsonv2.Unmarshal(raw, &wire,
		jsonv2.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false)); err != nil {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
	}
	catalog, err := wire.catalog()
	if err != nil {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
	}
	return catalog, nil
}

type datasetProfileCatalogJSON struct {
	SchemaVersion *string                           `json:"schema_version"`
	CatalogID     *string                           `json:"catalog_id"`
	Revision      *int64                            `json:"revision"`
	Entries       *[]datasetProfileCatalogEntryJSON `json:"entries"`
}

type datasetProfileCatalogEntryJSON struct {
	State   *ProfileState       `json:"state"`
	Profile *datasetProfileJSON `json:"profile"`
}

func (wire datasetProfileCatalogJSON) catalog() (DatasetProfileCatalog, error) {
	if wire.SchemaVersion == nil || *wire.SchemaVersion != datasetProfileCatalogMountSchemaVersion ||
		wire.CatalogID == nil || wire.Revision == nil || wire.Entries == nil {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
	}
	entries := make([]CatalogEntryInput, len(*wire.Entries))
	for index, item := range *wire.Entries {
		if item.State == nil || !item.State.Valid() || item.Profile == nil {
			return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
		}
		profile, err := item.Profile.profile()
		if err != nil {
			return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
		}
		entries[index] = CatalogEntryInput{Profile: profile, State: *item.State}
	}
	catalog, err := NewDatasetProfileCatalog(*wire.CatalogID, *wire.Revision, entries)
	if err != nil {
		return DatasetProfileCatalog{}, invalidDatasetProfileCatalogJSON()
	}
	return catalog, nil
}

func invalidDatasetProfileCatalogJSON() error { return &Error{code: CodeInvalidRequest} }
