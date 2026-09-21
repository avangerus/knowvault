package repository

// B2.3b1a: the neutral immutable data shape of one resolved governed-exposure
// lookup. B2.3b1b adds the private validation and construction boundary below.
// This file owns no database read, no policy decision, no SQL, no authorization
// grant, no transport DTO and no exported constructor: it adds only the shape
// and the private boundary that fills it.
//
// GovernedExposureLookup is the closed identity a caller already knows: the
// workspace, the source scope, the connection, and the one schema/relation pair
// whose exposed columns the caller wants projected. Every field is a plain
// exported string, so a zero value names nothing at all.
//
// GovernedExposureResult carries one resolved lookup. Every field is private so
// that a caller can only observe the resolved values through the scalar
// read-only accessors beside it, Columns hands back a detached copy, Valid
// reports only the private resolved bit and MarshalJSON renders the whole value
// as an opaque empty JSON object. There is deliberately no public constructor
// and no String/GoString: nothing here can be built, formatted or serialized
// into a value that claims more than the caller already holds, and the shape
// carries no secret material, no connection string, no SQL, no policy decision
// and no authorization grant.
//
// governedExposureResultInput and newGovernedExposureResult are the private
// boundary between already-read facts and an observable result: the constructor
// validates every fact with this package's existing identifier, revision and
// hash semantics and either returns the exact zero result or a result whose
// resolved bit is set and whose values are exactly the ones it was given.

import (
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/workspace"
)

// GovernedExposureLookup names the exact governed-exposure relation a caller
// already knows by workspace, source scope, connection, schema and relation. It
// is a closed identity: it is never SQL, never a secret reference, never a
// workspace revision and never a caller-chosen policy rule.
type GovernedExposureLookup struct {
	WorkspaceID   string
	SourceScopeID string
	ConnectionID  string
	SchemaName    string
	RelationName  string
}

// GovernedExposureResult carries the resolved values of one governed-exposure
// lookup. All fields are private so that a result can only be observed through
// the accessor methods below.
type GovernedExposureResult struct {
	workspaceID                  string
	workspaceRevision            int64
	workspaceConfigurationHash   string
	workspaceSourceID            string
	sourceScopeID                string
	sourceScopeRevision          int64
	sourceScopeConfigurationHash string
	connectionID                 string
	connectionRevision           int64
	databaseIdentity             string
	liveQueryEnabled             bool
	exposureRevision             int64
	exposureArtifactHash         string
	schemaName                   string
	relationName                 string
	columns                      []string
	resolved                     bool
}

func (r GovernedExposureResult) WorkspaceID() string { return r.workspaceID }

func (r GovernedExposureResult) WorkspaceRevision() int64 { return r.workspaceRevision }

func (r GovernedExposureResult) WorkspaceConfigurationHash() string {
	return r.workspaceConfigurationHash
}

func (r GovernedExposureResult) WorkspaceSourceID() string { return r.workspaceSourceID }

func (r GovernedExposureResult) SourceScopeID() string { return r.sourceScopeID }

func (r GovernedExposureResult) SourceScopeRevision() int64 { return r.sourceScopeRevision }

func (r GovernedExposureResult) SourceScopeConfigurationHash() string {
	return r.sourceScopeConfigurationHash
}

func (r GovernedExposureResult) ConnectionID() string { return r.connectionID }

func (r GovernedExposureResult) ConnectionRevision() int64 { return r.connectionRevision }

func (r GovernedExposureResult) DatabaseIdentity() string { return r.databaseIdentity }

func (r GovernedExposureResult) LiveQueryEnabled() bool { return r.liveQueryEnabled }

func (r GovernedExposureResult) ExposureRevision() int64 { return r.exposureRevision }

func (r GovernedExposureResult) ExposureArtifactHash() string { return r.exposureArtifactHash }

func (r GovernedExposureResult) SchemaName() string { return r.schemaName }

func (r GovernedExposureResult) RelationName() string { return r.relationName }

// Columns returns an independent copy of the resolved column names in their
// exact selected order. A nil slice is preserved as the true zero value so that
// an unresolved result stays strictly zero; a non-nil slice is newly allocated
// on every call, so no caller can reach the result through the returned slice.
func (r GovernedExposureResult) Columns() []string {
	if r.columns == nil {
		return nil
	}
	columns := make([]string, len(r.columns))
	copy(columns, r.columns)
	return columns
}

// Valid reports only the private resolved bit. A zero result is never valid, and
// no combination of the other private fields can make it valid.
func (r GovernedExposureResult) Valid() bool { return r.resolved }

// MarshalJSON renders the resolved exposure result as an opaque empty JSON
// object so that no private exposure value can leak through generic JSON
// logging.
func (GovernedExposureResult) MarshalJSON() ([]byte, error) {
	return []byte("{}"), nil
}

// governedExposureResultInput mirrors every fact of GovernedExposureResult
// except the private resolved bit, which only newGovernedExposureResult may
// set. It is private and carries no validation of its own: it exists only so
// that the construction boundary can refuse a malformed fact before any caller
// can observe a result that claims it.
type governedExposureResultInput struct {
	workspaceID                  string
	workspaceRevision            int64
	workspaceConfigurationHash   string
	workspaceSourceID            string
	sourceScopeID                string
	sourceScopeRevision          int64
	sourceScopeConfigurationHash string
	connectionID                 string
	connectionRevision           int64
	databaseIdentity             string
	liveQueryEnabled             bool
	exposureRevision             int64
	exposureArtifactHash         string
	schemaName                   string
	relationName                 string
	columns                      []string
}

// newGovernedExposureResult validates one set of already-resolved facts and
// returns the neutral result. Every failure returns the exact zero result,
// never a partial or best-effort value, so an invalid input is indistinguishable
// from no result at all.
//
// The boundary performs no I/O and no policy decision: it validates the four
// identifiers with validID, the four revisions with the package's safe-revision
// semantics, the three configuration/artifact hashes with
// workspace.IsConfigurationHash, the database identity with the existing
// PostgreSQL value semantics, the live-query flag, the schema, relation and
// every column with validGovernedExposureIdentifier, and the column count and
// exact case-sensitive uniqueness. A valid input is copied exactly: nothing is
// trimmed, normalized, case-folded, sorted, rewritten or deduplicated, and the
// columns are deep-copied so that the caller's slice can never reach the result.
func newGovernedExposureResult(input governedExposureResultInput) GovernedExposureResult {
	if !validID(input.workspaceID) || !validID(input.workspaceSourceID) ||
		!validID(input.sourceScopeID) || !validID(input.connectionID) {
		return GovernedExposureResult{}
	}
	if !validGovernedExposureRevision(input.workspaceRevision) ||
		!validGovernedExposureRevision(input.sourceScopeRevision) ||
		!validGovernedExposureRevision(input.connectionRevision) ||
		!validGovernedExposureRevision(input.exposureRevision) {
		return GovernedExposureResult{}
	}
	if !workspace.IsConfigurationHash(input.workspaceConfigurationHash) ||
		!workspace.IsConfigurationHash(input.sourceScopeConfigurationHash) ||
		!workspace.IsConfigurationHash(input.exposureArtifactHash) {
		return GovernedExposureResult{}
	}
	if !validGovernedExposureDatabaseIdentity(input.databaseIdentity) || !input.liveQueryEnabled {
		return GovernedExposureResult{}
	}
	if !validGovernedExposureIdentifier(input.schemaName) || !validGovernedExposureIdentifier(input.relationName) {
		return GovernedExposureResult{}
	}
	if len(input.columns) == 0 || len(input.columns) > maxGovernedExposureColumns {
		return GovernedExposureResult{}
	}
	seen := make(map[string]struct{}, len(input.columns))
	for _, column := range input.columns {
		if !validGovernedExposureIdentifier(column) {
			return GovernedExposureResult{}
		}
		// Uniqueness is exact and case-sensitive: "ID" and "id" are two
		// distinct columns, never one folded duplicate.
		if _, duplicate := seen[column]; duplicate {
			return GovernedExposureResult{}
		}
		seen[column] = struct{}{}
	}

	// Detach: the result owns its own slice, so no later mutation of the
	// caller's slice can reach the resolved value.
	columns := make([]string, len(input.columns))
	copy(columns, input.columns)
	return GovernedExposureResult{
		workspaceID:                  input.workspaceID,
		workspaceRevision:            input.workspaceRevision,
		workspaceConfigurationHash:   input.workspaceConfigurationHash,
		workspaceSourceID:            input.workspaceSourceID,
		sourceScopeID:                input.sourceScopeID,
		sourceScopeRevision:          input.sourceScopeRevision,
		sourceScopeConfigurationHash: input.sourceScopeConfigurationHash,
		connectionID:                 input.connectionID,
		connectionRevision:           input.connectionRevision,
		databaseIdentity:             input.databaseIdentity,
		liveQueryEnabled:             input.liveQueryEnabled,
		exposureRevision:             input.exposureRevision,
		exposureArtifactHash:         input.exposureArtifactHash,
		schemaName:                   input.schemaName,
		relationName:                 input.relationName,
		columns:                      columns,
		resolved:                     true,
	}
}

// validGovernedExposureRevision is the safe-revision semantics every other
// revision precondition in this package uses: a revision is an ordinal in
// 1..maxSafeInteger, so zero, a negative value and one past the exact-integer
// bound are all refused.
func validGovernedExposureRevision(value int64) bool {
	return value >= 1 && value <= maxSafeInteger
}

// validGovernedExposureDatabaseIdentity mirrors the existing PostgreSQL-safe
// value semantics: 1..128 bytes, valid UTF-8, no leading or trailing Unicode
// whitespace, and only ASCII letters, digits, '_', '-', '.', ':'. Nothing is
// trimmed, case-folded or repaired, and a database identity is never a DSN, a
// host name or a secret reference.
func validGovernedExposureDatabaseIdentity(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'a' && character <= 'z', character >= 'A' && character <= 'Z',
			character >= '0' && character <= '9', strings.ContainsRune("_-.:", character):
			continue
		default:
			return false
		}
	}
	return true
}
