package postgresqlquery

import (
	"strings"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// Registration modes. A relation is registered either as an indexed source,
// whose rows become ordinary addressable Evidence, or as query-only, which is
// registered and addressable through knowvault_source_sql but never copied
// into the search index (S3 card 4).
const (
	ProjectionModeIndexed   = "INDEXED"
	ProjectionModeQueryOnly = "QUERY_ONLY"
)

// ValidProjectionMode reports whether value is the empty string (the indexed
// default) or one of the two closed registration modes.
func ValidProjectionMode(value string) bool {
	switch value {
	case "", ProjectionModeIndexed, ProjectionModeQueryOnly:
		return true
	default:
		return false
	}
}

// WithQueryOnly derives the immutable query-only projection of an already
// built indexed projection. The mode is part of the content contract, so the
// returned ContractHash and LineageID are freshly derived from it: a
// query-only relation is a distinct immutable lineage, never a silent flag on
// the indexed one. Calling it with false -- or on a projection that already
// has the requested mode -- returns the input unchanged, so an indexed
// registration keeps the exact hashes discovery produced.
func WithQueryOnly(projection Projection, queryOnly bool) (Projection, error) {
	if err := projection.Validate(); err != nil {
		return Projection{}, err
	}
	if !queryOnly || projection.QueryOnly {
		return projection, nil
	}
	hashBytes, err := canon.CanonicalJSON(struct {
		ValueFormat      string               `json:"value_format"`
		BaseContractHash string               `json:"base_contract_hash"`
		SchemaName       string               `json:"schema_name"`
		RelationName     string               `json:"relation_name"`
		RelationKind     string               `json:"relation_kind"`
		QueryOnly        bool                 `json:"query_only"`
		Columns          []narrowedHashColumn `json:"columns"`
	}{
		ValueFormat: ValueContractVersion, BaseContractHash: projection.ContractHash,
		SchemaName: projection.SchemaName, RelationName: projection.RelationName,
		RelationKind: projection.RelationKind, QueryOnly: true,
		Columns: narrowedHashColumns(projection.Columns),
	})
	if err != nil {
		return Projection{}, &Error{code: CodeInvalidProjection, cause: err}
	}
	contractHash := canon.Hash(hashBytes)
	lineageBytes, err := canon.CanonicalJSON(struct {
		BaseLineageID string `json:"base_lineage_id"`
		ContractHash  string `json:"contract_hash"`
	}{BaseLineageID: projection.LineageID, ContractHash: contractHash})
	if err != nil {
		return Projection{}, &Error{code: CodeInvalidProjection, cause: err}
	}
	modeOnly := projection
	modeOnly.QueryOnly = true
	modeOnly.ContractHash = contractHash
	modeOnly.LineageID = "projection-lineage:" + strings.TrimPrefix(canon.Hash(lineageBytes), "sha256:")
	if err := modeOnly.Validate(); err != nil {
		return Projection{}, err
	}
	return modeOnly, nil
}
