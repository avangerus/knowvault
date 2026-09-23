package analyticsource

import (
	"strconv"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// repositoryColumnCompatibility proves that every field of the resolved sealed
// profile has one persisted projection column carrying the approved logical
// type, the supported PostgreSQL base OID family, the canonical discovery
// fingerprint that column's own precision metadata reproduces, and the approved
// nullability. The sealed field inventory is the complete requirement, so
// capability flags, measures, grain, and time select nothing away, while extra
// projection columns and inventory order change nothing.
//
// It reads the already-detached projection value, performs no I/O, retains no
// slice, and returns nil only for a complete match; every refusal is
// errMismatch, and the profile and projection are both re-proved valid so a
// direct caller cannot skip that check.
func repositoryColumnCompatibility(profile analytic.DatasetProfile, projection postgresqlquery.Projection) error {
	if !profile.Valid() {
		return errMismatch
	}
	if err := projection.Validate(); err != nil {
		return errMismatch
	}
	for _, field := range profile.Fields() {
		approved := field.Values()
		column, found := repositoryProjectionColumn(projection.Columns, approved.PhysicalName)
		if !found || column.Nullable != approved.Nullable {
			return errMismatch
		}
		logicalType, fingerprint, ok := repositoryColumnExpectation(
			approved.LogicalType, approved.PhysicalType,
			column.Precision, column.Scale, column.MaxBytes,
		)
		if !ok || column.LogicalType != logicalType || column.TypeFingerprint != fingerprint {
			return errMismatch
		}
	}
	return nil
}

// repositoryProjectionColumn locates one projection column by byte-exact
// physical name. Projection validation owns column-name uniqueness, so the first
// match is the only match.
func repositoryProjectionColumn(columns []postgresqlquery.Column, name string) (postgresqlquery.Column, bool) {
	for _, column := range columns {
		if column.Name == name {
			return column, true
		}
	}
	return postgresqlquery.Column{}, false
}

// repositoryColumnExpectation maps one sealed analytic logical/physical pair and
// the matched column's own precision metadata onto the single supported
// projection logical type, the canonical discovery fingerprint that
// internal/source/postgresqlquery/catalogType reports for the same base OID and
// typmod, and whether the pair and metadata are supported exactly as received.
// The fingerprint is rebuilt from the column's Precision and Scale and compared
// as one exact string, so an alias, domain, alternate spelling, padding, leading
// zero, or length-suffixed text OID never matches. Both temporal fingerprints
// are precision-suffixed: discovery reports precision 6 for the default typmod,
// so a bare temporal OID is never canonical.
func repositoryColumnExpectation(logical analytic.ScalarType, physical analytic.PhysicalType, precision, scale, maxBytes int) (postgresqlquery.LogicalType, string, bool) {
	switch physical {
	case analytic.PhysicalPGBool:
		return postgresqlquery.TypeBool, "oid:16", logical == analytic.ScalarBool && precision == 0 && scale == 0
	case analytic.PhysicalPGInt8:
		return postgresqlquery.TypeInt, "oid:20", logical == analytic.ScalarInt && precision == 0 && scale == 0
	case analytic.PhysicalPGText:
		return postgresqlquery.TypeText, "oid:25", logical == analytic.ScalarText && precision == 0 && scale == 0
	case analytic.PhysicalPGVarchar:
		// PostgreSQL discovery reports varchar(n) as oid:1043:len:n and
		// reserves four UTF-8 bytes per declared character in MaxBytes. Bind
		// both facts so a bare varchar, bpchar, domain, malformed length, or a
		// fingerprint whose length disagrees with the persisted byte bound
		// cannot alias the approved physical type. PostgreSQL bounds n at
		// 10,485,760 characters, so the capped discovery representation is
		// never ambiguous for a real varchar(n).
		if logical != analytic.ScalarText || precision != 0 || scale != 0 ||
			maxBytes < 4 || maxBytes%4 != 0 || maxBytes/4 > 10485760 {
			return "", "", false
		}
		return postgresqlquery.TypeText, "oid:1043:len:" + strconv.Itoa(maxBytes/4), true
	case analytic.PhysicalPGDate:
		return postgresqlquery.TypeDate, "oid:1082", logical == analytic.ScalarDate && precision == 0 && scale == 0
	case analytic.PhysicalPGNumeric:
		return postgresqlquery.TypeNumeric, "oid:1700:p:" + strconv.Itoa(precision) + ":s:" + strconv.Itoa(scale),
			logical == analytic.ScalarNumeric && precision >= 1 && precision <= 1000 && scale >= 0 && scale <= precision
	case analytic.PhysicalPGTimestamp:
		return postgresqlquery.TypeTimestamp, "oid:1114:p:" + strconv.Itoa(precision),
			logical == analytic.ScalarTimestamp && precision >= 0 && precision <= 6 && scale == 0
	case analytic.PhysicalPGTimestamptz:
		return postgresqlquery.TypeTimestamptz, "oid:1184:p:" + strconv.Itoa(precision),
			logical == analytic.ScalarTimestamptz && precision >= 0 && precision <= 6 && scale == 0
	default:
		return "", "", false
	}
}
