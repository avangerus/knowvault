package postgresqlquery

import (
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// NarrowProjection derives a new immutable Projection that drops the given
// column ordinals from an already-built projection (ADR-0097). It is used
// only for the administrator's registration-time column exclusion over a
// base/partitioned-table discovery; the sealed discovery result itself is
// always the complete, unnarrowed projection.
//
// Excluding an IDENTITY column is refused: an exclusion may only narrow the
// EVIDENCE set, never remove the primary key the server derived identity
// from. The surviving columns are renumbered 1..N in their original relative
// order, and because the column set is part of the content contract, the
// returned ContractHash and LineageID are freshly derived from it -- a
// narrowed table is a distinct immutable lineage, never a silent subset of
// the original one.
func NarrowProjection(projection Projection, excludedOrdinals map[int]bool) (Projection, error) {
	if err := projection.Validate(); err != nil {
		return Projection{}, err
	}
	if len(excludedOrdinals) == 0 {
		return projection, nil
	}
	source := append([]Column(nil), projection.Columns...)
	sort.Slice(source, func(i, j int) bool { return source[i].Ordinal < source[j].Ordinal })
	columns := make([]Column, 0, len(source))
	matched := make(map[int]bool, len(excludedOrdinals))
	for _, column := range source {
		if excludedOrdinals[column.Ordinal] {
			if columnHasRole(column, RoleIdentity) {
				return Projection{}, &Error{code: CodeInvalidProjection}
			}
			matched[column.Ordinal] = true
			continue
		}
		copied := column
		copied.Roles = append([]Role(nil), column.Roles...)
		copied.Ordinal = len(columns) + 1
		columns = append(columns, copied)
	}
	if len(matched) != len(excludedOrdinals) {
		// A caller named an ordinal that is not a real column of this
		// projection: never silently ignored.
		return Projection{}, &Error{code: CodeInvalidProjection}
	}
	hashBytes, err := canon.CanonicalJSON(struct {
		ValueFormat      string               `json:"value_format"`
		BaseContractHash string               `json:"base_contract_hash"`
		SchemaName       string               `json:"schema_name"`
		RelationName     string               `json:"relation_name"`
		RelationKind     string               `json:"relation_kind"`
		Columns          []narrowedHashColumn `json:"columns"`
	}{
		ValueFormat: ValueContractVersion, BaseContractHash: projection.ContractHash,
		SchemaName: projection.SchemaName, RelationName: projection.RelationName,
		RelationKind: projection.RelationKind, Columns: narrowedHashColumns(columns),
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
	lineageID := "projection-lineage:" + strings.TrimPrefix(canon.Hash(lineageBytes), "sha256:")
	narrowed := projection
	narrowed.Columns = columns
	narrowed.ContractHash = contractHash
	narrowed.LineageID = lineageID
	if err := narrowed.Validate(); err != nil {
		return Projection{}, err
	}
	return narrowed, nil
}

type narrowedHashColumn struct {
	Ordinal         int         `json:"ordinal"`
	Name            string      `json:"name"`
	TypeFingerprint string      `json:"type_fingerprint"`
	LogicalType     LogicalType `json:"logical_type"`
	Roles           []Role      `json:"roles"`
	Nullable        bool        `json:"nullable"`
	Precision       int         `json:"precision"`
	Scale           int         `json:"scale"`
	MaxBytes        int         `json:"max_bytes"`
}

func narrowedHashColumns(columns []Column) []narrowedHashColumn {
	result := make([]narrowedHashColumn, 0, len(columns))
	for _, column := range columns {
		result = append(result, narrowedHashColumn{
			Ordinal: column.Ordinal, Name: column.Name, TypeFingerprint: column.TypeFingerprint,
			LogicalType: column.LogicalType, Roles: append([]Role(nil), column.Roles...), Nullable: column.Nullable,
			Precision: column.Precision, Scale: column.Scale, MaxBytes: column.MaxBytes,
		})
	}
	return result
}
