package analyticsource

import (
	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// repositoryManagedAccessMode is the one source access mode this adapter maps:
// WORKSPACE_MANAGED is the binding the governed analytics path serves, so every
// other mode is refused before any source fact is read.
const repositoryManagedAccessMode = "WORKSPACE_MANAGED"

// repositoryBindingExpectation is the exact workspace identity and frozen
// catalog selection a caller already resolved and now asks this adapter to bind
// concrete repository results against. It is a private comparable value that
// carries no credential, no SQL, and no evidence that any member is still
// current: every member is an expectation this adapter can refuse.
type repositoryBindingExpectation struct {
	workspaceID                string
	workspaceRevision          int64
	workspaceConfigurationHash string
	catalogID                  string
	catalogRevision            int64
	catalogHash                string
	profileKey                 analytic.ProfileKey
	profileHash                string
}

// repositorySourceView is the read-only getter view of one already-resolved
// PostgreSQL authority result. It exposes scalar facts, the exact connection
// revision, and a detached projection copy; no connection string, credential,
// row, limit, or execution handle is reachable through it. It is used only by
// bindRepositoryViews and same-package tests, is never stored in a struct, and
// has exactly one production implementation.
type repositorySourceView interface {
	WorkspaceID() string
	WorkspaceRevision() int64
	WorkspaceConfigurationHash() string
	WorkspaceSourceID() string
	SourceScopeID() string
	SourceScopeRevision() int64
	ScopeConfigHash() string
	AccessMode() string
	ConnectionRevision() int64
	Projection() postgresqlquery.Projection
}

// repositoryExposureView is the read-only getter view of one already-resolved
// governed exposure result. Like the source view it exposes scalar facts and
// detached column names only, is used only by bindRepositoryViews and
// same-package tests, is never stored in a struct, and has exactly one
// production implementation.
type repositoryExposureView interface {
	Valid() bool
	WorkspaceID() string
	WorkspaceRevision() int64
	WorkspaceConfigurationHash() string
	WorkspaceSourceID() string
	SourceScopeID() string
	SourceScopeRevision() int64
	SourceScopeConfigurationHash() string
	ConnectionID() string
	ConnectionRevision() int64
	DatabaseIdentity() string
	LiveQueryEnabled() bool
	ExposureRevision() int64
	ExposureArtifactHash() string
	SchemaName() string
	RelationName() string
	Columns() []string
}

// The two concrete repository results are the only production sources of these
// views, so their compatibility is proved at compile time: an accessor rename or
// type change breaks this package's build instead of silently weakening the
// mapping.
var (
	_ repositorySourceView   = repository.PostgreSQLAuthorityResult{}
	_ repositoryExposureView = repository.GovernedExposureResult{}
)

// bindRepositoryResults maps one already-resolved PostgreSQL authority result and
// one already-resolved governed exposure result into the eligibility binding for
// one exact frozen active catalog selection. It is pure delegation: the whole
// validation and mapping order lives in bindRepositoryViews.
func bindRepositoryResults(
	expected repositoryBindingExpectation,
	catalog analytic.DatasetProfileCatalog,
	source repository.PostgreSQLAuthorityResult,
	exposure repository.GovernedExposureResult,
) (eligibilityBinding, error) {
	return bindRepositoryViews(expected, catalog, source, exposure)
}

// bindRepositoryViews validates the expectation, the frozen catalog selection,
// both repository views, and every mapped fact in one fail-closed order, then
// seals the resulting binding. It performs no I/O and grants nothing: it proves
// neither current workspace authority, nor a shared database snapshot, nor
// execution, type, or disclosure permission.
//
// The order is fixed: the expectation shape, the catalog identity and activity,
// the exact resolved active profile, both non-nil views reporting the expected
// workspace identity independently, the source access mode, the exposure's
// resolved and live state, the detached source projection, and finally the
// independently mapped source and exposure facts. Every refusal returns the
// exact zero eligibilityBinding and errMismatch.
func bindRepositoryViews(
	expected repositoryBindingExpectation,
	catalog analytic.DatasetProfileCatalog,
	source repositorySourceView,
	exposure repositoryExposureView,
) (eligibilityBinding, error) {
	if !validRepositoryBindingExpectation(expected) {
		return eligibilityBinding{}, errMismatch
	}
	if !catalog.Valid() || catalog.ID() != expected.catalogID ||
		catalog.Revision() != expected.catalogRevision || catalog.Hash() != expected.catalogHash {
		return eligibilityBinding{}, errMismatch
	}
	profile, resolved := catalog.ResolveActive(expected.profileKey, expected.profileHash)
	if !resolved || !profile.Valid() {
		return eligibilityBinding{}, errMismatch
	}
	if source == nil || exposure == nil {
		return eligibilityBinding{}, errMismatch
	}
	if !reportsExpectedWorkspace(source.WorkspaceID(), source.WorkspaceRevision(),
		source.WorkspaceConfigurationHash(), expected) ||
		!reportsExpectedWorkspace(exposure.WorkspaceID(), exposure.WorkspaceRevision(),
			exposure.WorkspaceConfigurationHash(), expected) {
		return eligibilityBinding{}, errMismatch
	}
	if source.AccessMode() != repositoryManagedAccessMode {
		return eligibilityBinding{}, errMismatch
	}
	if !exposure.Valid() || !exposure.LiveQueryEnabled() {
		return eligibilityBinding{}, errMismatch
	}
	projection := source.Projection()
	if err := projection.Validate(); err != nil {
		return eligibilityBinding{}, errMismatch
	}
	sourceView, ok := repositorySourceFacts(source, projection)
	if !ok {
		return eligibilityBinding{}, errMismatch
	}
	return newEligibilityBinding(profile, sourceView, repositoryExposureFacts(exposure))
}

// validRepositoryBindingExpectation reports whether every expectation member is
// well formed exactly as received: canonical workspace and catalog identities,
// positive safe revisions, canonical lowercase SHA-256 hashes, and a valid
// profile key. Nothing is trimmed, case folded, or repaired. Catalog and profile
// validity remain owned by analytic.
func validRepositoryBindingExpectation(value repositoryBindingExpectation) bool {
	return validBindingIdentity(value.workspaceID) && validBindingRevision(value.workspaceRevision) &&
		validBindingHash(value.workspaceConfigurationHash) && validBindingIdentity(value.catalogID) &&
		validBindingRevision(value.catalogRevision) && validBindingHash(value.catalogHash) &&
		value.profileKey.Valid() && validBindingHash(value.profileHash)
}

// reportsExpectedWorkspace reports whether one repository result independently
// reports the workspace identity the expectation names.
func reportsExpectedWorkspace(workspaceID string, revision int64, configurationHash string, expected repositoryBindingExpectation) bool {
	return workspaceID == expected.workspaceID && revision == expected.workspaceRevision &&
		configurationHash == expected.workspaceConfigurationHash
}

// repositorySourceFacts maps one validated source view and its already-read
// projection into the source-only fact set. The workspace, source scope, and
// connection revision come from the view's own accessors; the connection
// identity, database identity, schema, relation, projection lineage, revision,
// contract hash, and relation kind come from the projection; and every column
// name is copied in its exact spelling, so no caller slice reaches the facts.
// The projection is never re-read and no missing value is synthesized from the
// profile. An unapproved relation kind refuses.
func repositorySourceFacts(view repositorySourceView, projection postgresqlquery.Projection) (sourceFacts, bool) {
	relationKind, ok := repositoryRelationKind(projection.RelationKind)
	if !ok {
		return sourceFacts{}, false
	}
	columns := make([]string, len(projection.Columns))
	for index, column := range projection.Columns {
		columns[index] = column.Name
	}
	return sourceFacts{
		binding: bindingFacts{
			workspaceID:                  view.WorkspaceID(),
			workspaceRevision:            view.WorkspaceRevision(),
			workspaceConfigurationHash:   view.WorkspaceConfigurationHash(),
			workspaceSourceID:            view.WorkspaceSourceID(),
			sourceScopeID:                view.SourceScopeID(),
			sourceScopeRevision:          view.SourceScopeRevision(),
			sourceScopeConfigurationHash: view.ScopeConfigHash(),
			connectionID:                 projection.ConnectionID,
			connectionRevision:           view.ConnectionRevision(),
			databaseIdentity:             projection.DatabaseIdentity,
			schemaName:                   projection.SchemaName,
			relationName:                 projection.RelationName,
		},
		projectionLineageID:    projection.LineageID,
		projectionRevision:     projection.Revision,
		projectionContractHash: projection.ContractHash,
		relationKind:           relationKind,
		columns:                columns,
	}, true
}

// repositoryRelationKind maps the PostgreSQL relation kind the projection
// reports onto the approved analytic relation kind through an explicit closed
// switch. Every other spelling refuses; nothing is case folded or inferred.
func repositoryRelationKind(value string) (analytic.RelationKind, bool) {
	switch value {
	case string(analytic.RelationView):
		return analytic.RelationView, true
	case string(analytic.RelationMaterializedView):
		return analytic.RelationMaterializedView, true
	default:
		return "", false
	}
}

// repositoryExposureFacts maps one resolved exposure view into the
// exposure-only fact set. All twelve common binding fields come from the view's
// own accessors, the live flag and the exposed schema revision and hash come
// from the exposure, and the exposure columns are copied in their exact
// received order, so no caller slice reaches the facts.
func repositoryExposureFacts(view repositoryExposureView) exposureFacts {
	columns := view.Columns()
	detached := make([]string, len(columns))
	copy(detached, columns)
	return exposureFacts{
		binding: bindingFacts{
			workspaceID:                  view.WorkspaceID(),
			workspaceRevision:            view.WorkspaceRevision(),
			workspaceConfigurationHash:   view.WorkspaceConfigurationHash(),
			workspaceSourceID:            view.WorkspaceSourceID(),
			sourceScopeID:                view.SourceScopeID(),
			sourceScopeRevision:          view.SourceScopeRevision(),
			sourceScopeConfigurationHash: view.SourceScopeConfigurationHash(),
			connectionID:                 view.ConnectionID(),
			connectionRevision:           view.ConnectionRevision(),
			databaseIdentity:             view.DatabaseIdentity(),
			schemaName:                   view.SchemaName(),
			relationName:                 view.RelationName(),
		},
		liveEnabled:           view.LiveQueryEnabled(),
		exposedSchemaRevision: view.ExposureRevision(),
		exposedSchemaHash:     view.ExposureArtifactHash(),
		columns:               detached,
	}
}
