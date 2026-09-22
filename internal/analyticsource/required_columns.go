package analyticsource

import "knowvault.local/verified-workspace/internal/analytic"

// requiredColumns derives the complete physical column inventory one sealed
// profile depends on: every approved field's projection column, once, in the
// profile's canonical SourceOrdinal order. Capability flags, output permission,
// measure operands, grain keys, the time field, and any caller request select
// nothing away, because the sealed profile is the sole source of truth. A zero,
// invalid, or forged profile is refused as errMismatch.
func requiredColumns(profile analytic.DatasetProfile) ([]string, error) {
	if !profile.Valid() {
		return nil, errMismatch
	}
	fields := profile.Fields()
	columns := make([]string, 0, len(fields))
	for _, field := range fields {
		columns = append(columns, field.Values().PhysicalName)
	}
	return columns, nil
}
