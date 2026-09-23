// Package analyticsource holds fail-closed metadata matching between an
// approved analytic projection and trusted source and exposure facts, and the
// resolver that reads those facts from the concrete repository under the
// caller's access context. Matching is pure and returns no diagnostics; the
// resolver returns one opaque sealed binding or the one content-free refusal.
// Neither grants authority beyond the exact facts it matched: a sealed binding
// is not execution, disclosure, freshness or still-mounted permission.
package analyticsource

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/analytic"
)

// errMismatch is the single content-free refusal returned for every invalid or
// mismatched input; it carries no identity, value, or diagnostic.
var errMismatch = errors.New("analyticsource: facts do not match approved projection")

// maxBindingRevision is the largest revision a common binding value may carry:
// every revision must survive a round trip through an IEEE-754 double.
const maxBindingRevision int64 = 9007199254740991

// identifierPattern mirrors the approved projection identifier shape used by
// schema, relation and column names: an ASCII, unquoted PostgreSQL identifier of
// at most 63 bytes, with no case folding.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

// bindingFacts is the comparable common binding identity one trusted side
// reports. Both sourceFacts and exposureFacts hold exactly one such value; it is
// validated for shape and must be byte-exact equal across the two sides. The
// workspace fields are not part of the approved projection, so this matcher
// proves only that both sides agree on one valid tuple, never that the workspace
// is the one the caller may read; that authority belongs to the future trusted
// adapters and resolver.
type bindingFacts struct {
	workspaceID                string
	workspaceRevision          int64
	workspaceConfigurationHash string
	workspaceSourceID          string

	sourceScopeID                string
	sourceScopeRevision          int64
	sourceScopeConfigurationHash string

	connectionID       string
	connectionRevision int64

	databaseIdentity string
	schemaName       string
	relationName     string
}

// valid reports whether every value is well formed exactly as received: no
// value is trimmed, case folded, or otherwise normalized before validation.
func (value bindingFacts) valid() bool {
	return validBindingIdentity(value.workspaceID) && validBindingRevision(value.workspaceRevision) &&
		validBindingHash(value.workspaceConfigurationHash) && validBindingIdentity(value.workspaceSourceID) &&
		validBindingIdentity(value.sourceScopeID) && validBindingRevision(value.sourceScopeRevision) &&
		validBindingHash(value.sourceScopeConfigurationHash) && validBindingIdentity(value.connectionID) &&
		validBindingRevision(value.connectionRevision) && validBindingIdentity(value.databaseIdentity) &&
		identifierPattern.MatchString(value.schemaName) && identifierPattern.MatchString(value.relationName)
}

// validBindingIdentity reports whether an opaque identity is valid UTF-8, 1..256
// bytes, already trimmed, and free of C0 and C1 control characters.
func validBindingIdentity(value string) bool {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

// validBindingRevision reports whether a revision is positive and within the
// range an IEEE-754 double represents exactly.
func validBindingRevision(value int64) bool { return value >= 1 && value <= maxBindingRevision }

// validBindingHash reports whether a hash is exactly the lowercase "sha256:"
// prefix followed by 64 lowercase hexadecimal digits.
func validBindingHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// sourceFacts is the trusted repository view of source-side projection metadata.
// Projection lineage, revision, contract hash and relation kind stay source-only.
type sourceFacts struct {
	binding                bindingFacts
	projectionLineageID    string
	projectionRevision     int64
	projectionContractHash string
	relationKind           analytic.RelationKind
	columns                []string
}

// exposureFacts is the trusted view of exposure-side live metadata. Live state
// and the exposed schema revision and hash stay exposure-only.
type exposureFacts struct {
	binding               bindingFacts
	liveEnabled           bool
	exposedSchemaRevision int64
	exposedSchemaHash     string
	columns               []string
}

// match reports whether both common binding values are well formed and
// byte-exact equal, the common and source-only facts equal the approved
// projection exactly, the exposure is live on the approved schema revision and
// hash, and every required column exists in both column sets. Every refusal is
// errMismatch.
func match(expected analytic.SourceProjectionSpec, requiredColumns []string, source sourceFacts, exposure exposureFacts) error {
	if !expected.Valid() {
		return errMismatch
	}
	if _, ok := columnSet(requiredColumns); !ok {
		return errMismatch
	}
	if !source.binding.valid() || !exposure.binding.valid() {
		return errMismatch
	}
	if source.binding != exposure.binding {
		return errMismatch
	}
	approved := expected.Values()
	if source.binding.sourceScopeID != approved.SourceScopeID || source.binding.connectionID != approved.ConnectionID ||
		source.binding.databaseIdentity != approved.DatabaseIdentity ||
		source.binding.schemaName != approved.SchemaName || source.binding.relationName != approved.RelationName ||
		source.projectionLineageID != approved.ProjectionLineageID ||
		source.projectionRevision != approved.ProjectionRevision ||
		source.projectionContractHash != approved.ProjectionContractHash ||
		source.relationKind != approved.RelationKind {
		return errMismatch
	}
	if !exposure.liveEnabled || exposure.exposedSchemaRevision != approved.ExposedSchemaRevision ||
		exposure.exposedSchemaHash != approved.ExposedSchemaHash {
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
		if !identifierPattern.MatchString(column) {
			return nil, false
		}
		if _, duplicate := set[column]; duplicate {
			return nil, false
		}
		set[column] = struct{}{}
	}
	return set, true
}
