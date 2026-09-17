package canon

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// PostgreSQLQueryCellAnchorBytes builds the sole canonical anchor for a
// structured PostgreSQL business-object cell.  The function lives in canon so
// connector and resolver code cannot quietly invent a second JSON shape.
// Offsets are UTF-8 byte offsets into the normalized cell text.
func PostgreSQLQueryCellAnchorBytes(connectionID, lineageID string, projectionRevision int64,
	projectionContractHash, entityIdentityDigest, rowVersionHash string,
	columnOrdinal int, columnName, canonicalValueHash string, textStart, textEnd int) ([]byte, error) {
	return PostgreSQLQueryCellAnchorBytesWithPath(connectionID, lineageID, projectionRevision,
		projectionContractHash, entityIdentityDigest, rowVersionHash, columnOrdinal,
		columnName, canonicalValueHash, textStart, textEnd, "")
}

// PostgreSQLQueryCellAnchorBytesWithPath extends the structured-cell anchor
// with an optional RFC 6901 JSON Pointer. Keeping the legacy function above
// preserves scalar-cell callers while JSON leaf Evidence gets an exact path.
func PostgreSQLQueryCellAnchorBytesWithPath(connectionID, lineageID string, projectionRevision int64,
	projectionContractHash, entityIdentityDigest, rowVersionHash string,
	columnOrdinal int, columnName, canonicalValueHash string, textStart, textEnd int,
	jsonPath string) ([]byte, error) {
	if !validOpaqueAnchorID(connectionID) || !validOpaqueAnchorID(lineageID) ||
		projectionRevision < 1 || !validSHA256Anchor(projectionContractHash) ||
		!validHMACAnchor(entityIdentityDigest) || !validSHA256Anchor(rowVersionHash) ||
		columnOrdinal < 1 || columnOrdinal > 256 || !validColumnName(columnName) ||
		!validSHA256Anchor(canonicalValueHash) || textStart < 0 || textEnd <= textStart ||
		!validJSONPointerAnchor(jsonPath) {
		return nil, ErrCanonical
	}
	return canonicalJSON(struct {
		Kind                   string `json:"kind"`
		ConnectionID           string `json:"connection_id"`
		ProjectionLineageID    string `json:"projection_lineage_id"`
		ProjectionRevision     int64  `json:"projection_revision"`
		ProjectionContractHash string `json:"projection_contract_hash"`
		EntityIdentityDigest   string `json:"entity_identity_digest"`
		RowVersionHash         string `json:"row_version_hash"`
		ColumnOrdinal          int    `json:"column_ordinal"`
		ColumnName             string `json:"column_name"`
		CanonicalValueHash     string `json:"canonical_value_hash"`
		JSONPath               string `json:"json_path,omitempty"`
		TextStart              int    `json:"text_start"`
		TextEnd                int    `json:"text_end"`
		OffsetUnit             string `json:"offset_unit"`
		RangeSemantics         string `json:"range_semantics"`
		NormalizationVersion   string `json:"normalization_version"`
	}{
		Kind: "POSTGRESQL_QUERY_CELL", ConnectionID: connectionID,
		ProjectionLineageID: lineageID, ProjectionRevision: projectionRevision,
		ProjectionContractHash: projectionContractHash, EntityIdentityDigest: entityIdentityDigest,
		RowVersionHash: rowVersionHash, ColumnOrdinal: columnOrdinal, ColumnName: columnName,
		CanonicalValueHash: canonicalValueHash, JSONPath: jsonPath, TextStart: textStart, TextEnd: textEnd,
		OffsetUnit: "UTF8_BYTE", RangeSemantics: "START_INCLUSIVE_END_EXCLUSIVE",
		NormalizationVersion: NormalizationVersion,
	})
}

var anchorIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var anchorSHA256Pattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var anchorHMACPattern = regexp.MustCompile(`^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$`)
var anchorColumnPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

func validOpaqueAnchorID(value string) bool { return anchorIDPattern.MatchString(value) }
func validSHA256Anchor(value string) bool   { return anchorSHA256Pattern.MatchString(value) }
func validHMACAnchor(value string) bool     { return anchorHMACPattern.MatchString(value) }
func validColumnName(value string) bool {
	return anchorColumnPattern.MatchString(value) && strings.TrimSpace(value) == value
}

func validJSONPointerAnchor(value string) bool {
	if len(value) > 4096 || strings.IndexAny(value, "\x00\r\n") >= 0 {
		return false
	}
	if value == "" {
		return true
	}
	if value[0] != '/' {
		return false
	}
	for index := 0; index < len(value); {
		r, size := utf8.DecodeRuneInString(value[index:])
		if r == utf8.RuneError && size == 1 {
			return false
		}
		if r == '~' {
			if index+1 >= len(value) || (value[index+1] != '0' && value[index+1] != '1') {
				return false
			}
			index += 2
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
		index += size
	}
	return true
}
