package analytic

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// ExecutionMode is the closed set of ways an approved dataset may be read.
type ExecutionMode string

const ExecutionLive ExecutionMode = "LIVE"

func (value ExecutionMode) Valid() bool { return value == ExecutionLive }

// RelationKind identifies the approved PostgreSQL projection type.
type RelationKind string

const (
	RelationView             RelationKind = "VIEW"
	RelationMaterializedView RelationKind = "MATERIALIZED_VIEW"
)

func (value RelationKind) Valid() bool {
	return value == RelationView || value == RelationMaterializedView
}

// ProfileKey identifies one immutable version of a server-owned dataset profile.
type ProfileKey struct {
	datasetID string
	version   int64
}

func NewProfileKey(datasetID string, version int64) (ProfileKey, error) {
	value := ProfileKey{datasetID: datasetID, version: version}
	if !value.Valid() {
		return ProfileKey{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value ProfileKey) Valid() bool {
	return validProfileIdentity(value.datasetID) && value.version > 0
}
func (value ProfileKey) DatasetID() string { return value.datasetID }
func (value ProfileKey) Version() int64    { return value.version }

// SourceProjectionInput is the construction and detached read DTO for an
// approved projection. It deliberately carries no endpoint, credentials, or SQL.
type SourceProjectionInput struct {
	SourceScopeID          string
	ConnectionID           string
	DatabaseIdentity       string
	ProjectionLineageID    string
	ProjectionRevision     int64
	ProjectionContractHash string
	ExposedSchemaRevision  int64
	ExposedSchemaHash      string
	SchemaName             string
	RelationName           string
	RelationKind           RelationKind
}

// SourceProjectionSpec is an immutable, validated projection identity.
type SourceProjectionSpec struct {
	sourceScopeID          string
	connectionID           string
	databaseIdentity       string
	projectionLineageID    string
	projectionRevision     int64
	projectionContractHash string
	exposedSchemaRevision  int64
	exposedSchemaHash      string
	schemaName             string
	relationName           string
	relationKind           RelationKind
}

func NewSourceProjectionSpec(input SourceProjectionInput) (SourceProjectionSpec, error) {
	value := SourceProjectionSpec{
		sourceScopeID: input.SourceScopeID, connectionID: input.ConnectionID,
		databaseIdentity: input.DatabaseIdentity, projectionLineageID: input.ProjectionLineageID,
		projectionRevision: input.ProjectionRevision, projectionContractHash: input.ProjectionContractHash,
		exposedSchemaRevision: input.ExposedSchemaRevision, exposedSchemaHash: input.ExposedSchemaHash,
		schemaName: input.SchemaName, relationName: input.RelationName, relationKind: input.RelationKind,
	}
	if !value.Valid() {
		return SourceProjectionSpec{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value SourceProjectionSpec) Valid() bool {
	return validProfileIdentity(value.sourceScopeID) &&
		validProfileIdentity(value.connectionID) &&
		validProfileIdentity(value.databaseIdentity) &&
		validProfileIdentity(value.projectionLineageID) &&
		value.projectionRevision > 0 && validProfileHash(value.projectionContractHash) &&
		value.exposedSchemaRevision > 0 && validProfileHash(value.exposedSchemaHash) &&
		projectionIdentifierPattern.MatchString(value.schemaName) &&
		projectionIdentifierPattern.MatchString(value.relationName) && value.relationKind.Valid()
}

func (value SourceProjectionSpec) Values() SourceProjectionInput {
	return SourceProjectionInput{
		SourceScopeID: value.sourceScopeID, ConnectionID: value.connectionID,
		DatabaseIdentity: value.databaseIdentity, ProjectionLineageID: value.projectionLineageID,
		ProjectionRevision: value.projectionRevision, ProjectionContractHash: value.projectionContractHash,
		ExposedSchemaRevision: value.exposedSchemaRevision, ExposedSchemaHash: value.exposedSchemaHash,
		SchemaName: value.schemaName, RelationName: value.relationName, RelationKind: value.relationKind,
	}
}

var projectionIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)

func validProfileIdentity(value string) bool {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validProfileHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}
