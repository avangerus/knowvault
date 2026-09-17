package postgresqlquery

import (
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// RenderedCell is one immutable Evidence candidate produced from a declared
// projection column. JSON payloads can yield multiple cells, one per bounded
// JSON Pointer leaf; scalar columns yield exactly one cell with an empty path.
type RenderedCell struct {
	Path      string
	Text      []byte
	Anchor    []byte
	ValueHash string
}

// CanonicalValueHash returns the immutable hash of a typed value entry.  The
// type fingerprint and value tag are deliberately included: the same display
// text under a different PostgreSQL type must not silently retain identity.
func CanonicalValueHash(value ValueEntry) (string, error) {
	if value.Ordinal < 1 || value.TypeFingerprint == "" || value.LogicalType == "" || value.ValueTag == "" {
		return "", &Error{code: CodeInvalidValue}
	}
	raw, err := canon.CanonicalJSON(value)
	if err != nil {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	return canon.Hash(raw), nil
}

// RenderCell produces the only text representation that may become Evidence
// for a PostgreSQL projection cell. It contains the declared column label and
// one canonical value; no row, SQL, identity tuple or unselected column is
// included. The result is text-v1 canonical UTF-8.
func RenderCell(column Column, value ValueEntry) ([]byte, error) {
	if column.Ordinal < 1 || value.Ordinal != column.Ordinal || value.TypeFingerprint != column.TypeFingerprint ||
		value.LogicalType != column.LogicalType || !validRoleForCell(column.Roles) {
		return nil, &Error{code: CodeInvalidValue}
	}
	if value.ValueTag != "NULL" && value.ValueTag != expectedValueTag(column.LogicalType) {
		return nil, &Error{code: CodeInvalidValue}
	}
	var rendered string
	switch value.ValueTag {
	case "NULL":
		if !column.Nullable || value.Value != nil {
			return nil, &Error{code: CodeInvalidValue}
		}
		rendered = "NULL"
	case "BOOL":
		v, ok := value.Value.(bool)
		if !ok || column.LogicalType != TypeBool {
			return nil, &Error{code: CodeInvalidValue}
		}
		if v {
			rendered = "true"
		} else {
			rendered = "false"
		}
	case "INT", "NUMERIC", "UUID", "DATE", "TIMESTAMP_LOCAL", "TIMESTAMPTZ_UTC", "TEXT":
		v, ok := value.Value.(string)
		if !ok || v == "" && value.ValueTag != "TEXT" || !utf8.ValidString(v) {
			return nil, &Error{code: CodeInvalidValue}
		}
		rendered = v
	case "JSON", "JSONB":
		if column.LogicalType == TypeJSON && value.ValueTag != "JSON" || column.LogicalType == TypeJSONB && value.ValueTag != "JSONB" {
			return nil, &Error{code: CodeInvalidValue}
		}
		v, ok := value.Value.(jsontext.Value)
		if !ok || len(v) == 0 {
			return nil, &Error{code: CodeInvalidValue}
		}
		canonical := jsontext.Value(append([]byte(nil), v...))
		if err := canonical.Canonicalize(); err != nil {
			return nil, &Error{code: CodeInvalidValue, cause: err}
		}
		rendered = string(canonical)
	default:
		return nil, &Error{code: CodeInvalidValue}
	}
	// A column label is a trusted identifier from the projection; the value is
	// canonicalized again so an Evidence resolver can compare exact bytes.
	result, err := canon.Canonicalize([]byte(column.Name + " = " + rendered))
	if err != nil || len(result) == 0 || !utf8.Valid(result) {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	if column.MaxBytes > 0 && len(result) > column.MaxBytes+len(column.Name)+3 {
		return nil, &Error{code: CodeLimitExceeded}
	}
	return result, nil
}

func expectedValueTag(logicalType LogicalType) string {
	switch logicalType {
	case TypeBool:
		return "BOOL"
	case TypeInt:
		return "INT"
	case TypeNumeric:
		return "NUMERIC"
	case TypeUUID:
		return "UUID"
	case TypeDate:
		return "DATE"
	case TypeTimestamp:
		return "TIMESTAMP_LOCAL"
	case TypeTimestamptz:
		return "TIMESTAMPTZ_UTC"
	case TypeText:
		return "TEXT"
	case TypeJSON, TypeJSONB:
		return string(logicalType)
	default:
		return ""
	}
}

func validRoleForCell(roles []Role) bool {
	for _, role := range roles {
		if role == RoleEvidence {
			return true
		}
	}
	return false
}

// CellAnchorBytes builds an exact anchor whose byte range covers the complete
// rendered cell. It is a thin typed wrapper around canon's anchor authority.
func CellAnchorBytes(projection Projection, entityDigest, rowHash string, column Column, value ValueEntry) ([]byte, error) {
	if err := projection.Validate(); err != nil {
		return nil, &Error{code: CodeInvalidValue}
	}
	text, err := RenderCell(column, value)
	if err != nil {
		return nil, err
	}
	valueHash, err := CanonicalValueHash(value)
	if err != nil {
		return nil, err
	}
	anchor, err := canon.PostgreSQLQueryCellAnchorBytes(projection.ConnectionID, projection.LineageID,
		projection.Revision, projection.ContractHash, entityDigest, rowHash, column.Ordinal, column.Name,
		valueHash, 0, len(text))
	if err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	return anchor, nil
}

// RenderedCellAnchor is the publication-friendly helper: it validates a real
// typed entry, renders it, hashes the entry and creates its exact anchor.
func RenderedCellAnchor(projection Projection, entityDigest string, row Row, column Column, value ValueEntry) (text, anchor []byte, valueHash string, err error) {
	if err = projection.Validate(); err != nil || len(row.Canonical) == 0 || row.Hash == "" {
		return nil, nil, "", &Error{code: CodeInvalidValue}
	}
	text, err = RenderCell(column, value)
	if err != nil {
		return nil, nil, "", err
	}
	valueHash, err = CanonicalValueHash(value)
	if err != nil {
		return nil, nil, "", err
	}
	anchor, err = canon.PostgreSQLQueryCellAnchorBytes(projection.ConnectionID, projection.LineageID,
		projection.Revision, projection.ContractHash, entityDigest, row.Hash, column.Ordinal, column.Name,
		valueHash, 0, len(text))
	if err != nil {
		return nil, nil, "", &Error{code: CodeInvalidValue, cause: err}
	}
	return text, anchor, valueHash, nil
}

// RenderedEvidenceCells expands structured JSON/JSONB values into exact
// path-addressable Evidence cells. The original RenderCell contract remains
// unchanged for scalar values and for callers that need the complete payload.
func RenderedEvidenceCells(projection Projection, entityDigest string, row Row, column Column, value ValueEntry) ([]RenderedCell, error) {
	if err := projection.Validate(); err != nil || len(row.Canonical) == 0 || row.Hash == "" || !validRoleForCell(column.Roles) {
		return nil, &Error{code: CodeInvalidValue}
	}
	if column.LogicalType != TypeJSON && column.LogicalType != TypeJSONB {
		text, anchor, valueHash, err := RenderedCellAnchor(projection, entityDigest, row, column, value)
		if err != nil {
			return nil, err
		}
		return []RenderedCell{{Text: text, Anchor: anchor, ValueHash: valueHash}}, nil
	}
	if value.ValueTag != string(column.LogicalType) {
		return nil, &Error{code: CodeInvalidValue}
	}
	raw, ok := value.Value.(jsontext.Value)
	if !ok {
		return nil, &Error{code: CodeInvalidValue}
	}
	leaves, err := JSONLeaves(raw)
	if err != nil {
		return nil, err
	}
	result := make([]RenderedCell, 0, len(leaves))
	for _, leaf := range leaves {
		valueHash, err := JSONLeafValueHash(column, leaf)
		if err != nil {
			return nil, err
		}
		text, err := renderJSONLeaf(column.Name, leaf)
		if err != nil {
			return nil, err
		}
		anchor, err := canon.PostgreSQLQueryCellAnchorBytesWithPath(projection.ConnectionID,
			projection.LineageID, projection.Revision, projection.ContractHash, entityDigest,
			row.Hash, column.Ordinal, column.Name, valueHash, 0, len(text), leaf.Path)
		if err != nil {
			return nil, &Error{code: CodeInvalidValue, cause: err}
		}
		result = append(result, RenderedCell{Path: leaf.Path, Text: text, Anchor: anchor, ValueHash: valueHash})
	}
	return result, nil
}

func renderJSONLeaf(columnName string, leaf JSONLeaf) ([]byte, error) {
	if err := ValidateJSONPath(leaf.Path); err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	canonical := leaf.Raw.Clone()
	if err := canonical.Canonicalize(); err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	label := columnName
	if leaf.Path != "" {
		label += "[" + leaf.Path + "]"
	}
	result, err := canon.Canonicalize([]byte(fmt.Sprintf("%s = %s", label, strings.TrimSpace(string(canonical)))))
	if err != nil || len(result) == 0 || !utf8.Valid(result) {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	return result, nil
}
