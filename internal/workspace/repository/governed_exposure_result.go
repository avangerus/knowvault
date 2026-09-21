package repository

// B2.3b1a: the neutral immutable data shape of one resolved governed-exposure
// lookup. This file owns no validation, no database read, no policy decision,
// no SQL, no authorization grant, no transport DTO and no constructor: it adds
// only the shape the later lookup card fills in.
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
