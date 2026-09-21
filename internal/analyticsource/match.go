// Package analyticsource holds pure, fail-closed metadata matching between an
// approved analytic projection and trusted source and exposure facts. It grants
// no authority: it performs no I/O and returns no diagnostics.
package analyticsource

import (
	"errors"
	"regexp"

	"knowvault.local/verified-workspace/internal/analytic"
)

// errMismatch is the single content-free refusal returned for every invalid or
// mismatched input; it carries no identity, value, or diagnostic.
var errMismatch = errors.New("analyticsource: facts do not match approved projection")

// columnPattern mirrors the approved projection identifier shape: an ASCII,
// unquoted PostgreSQL identifier of at most 63 bytes, with no case folding.
var columnPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

// sourceFacts is the trusted repository view of source-side projection metadata.
type sourceFacts struct {
	sourceScopeID, connectionID, databaseIdentity, projectionLineageID string
	projectionContractHash, schemaName, relationName                   string
	projectionRevision                                                 int64
	relationKind                                                       analytic.RelationKind
	columns                                                            []string
}

// exposureFacts is the trusted view of exposure-side live metadata.
type exposureFacts struct {
	liveEnabled                                 bool
	exposedSchemaRevision                       int64
	exposedSchemaHash, schemaName, relationName string
	columns                                     []string
}

// match reports whether the facts exactly equal the approved projection, the
// exposure is live on the approved schema revision, and every required column
// exists in both column sets. Every refusal is errMismatch.
func match(expected analytic.SourceProjectionSpec, requiredColumns []string, source sourceFacts, exposure exposureFacts) error {
	if !expected.Valid() {
		return errMismatch
	}
	if _, ok := columnSet(requiredColumns); !ok {
		return errMismatch
	}
	sourceColumns, ok := columnSet(source.columns)
	if !ok {
		return errMismatch
	}
	exposureColumns, ok := columnSet(exposure.columns)
	if !ok {
		return errMismatch
	}
	approved := expected.Values()
	if source.sourceScopeID != approved.SourceScopeID || source.connectionID != approved.ConnectionID ||
		source.databaseIdentity != approved.DatabaseIdentity ||
		source.projectionLineageID != approved.ProjectionLineageID ||
		source.projectionRevision != approved.ProjectionRevision ||
		source.projectionContractHash != approved.ProjectionContractHash ||
		source.schemaName != approved.SchemaName || source.relationName != approved.RelationName ||
		source.relationKind != approved.RelationKind {
		return errMismatch
	}
	if !exposure.liveEnabled || exposure.exposedSchemaRevision != approved.ExposedSchemaRevision ||
		exposure.exposedSchemaHash != approved.ExposedSchemaHash ||
		exposure.schemaName != approved.SchemaName || exposure.relationName != approved.RelationName {
		return errMismatch
	}
	for _, column := range requiredColumns {
		if _, present := sourceColumns[column]; !present {
			return errMismatch
		}
		if _, present := exposureColumns[column]; !present {
			return errMismatch
		}
	}
	return nil
}

// columnSet validates that columns are a non-empty, unique list of unquoted
// PostgreSQL identifiers and returns them as a set. Extra columns are allowed
// because this matcher does not authorize selecting them.
func columnSet(columns []string) (map[string]struct{}, bool) {
	if len(columns) == 0 {
		return nil, false
	}
	set := make(map[string]struct{}, len(columns))
	for _, column := range columns {
		if !columnPattern.MatchString(column) {
			return nil, false
		}
		if _, duplicate := set[column]; duplicate {
			return nil, false
		}
		set[column] = struct{}{}
	}
	return set, true
}
