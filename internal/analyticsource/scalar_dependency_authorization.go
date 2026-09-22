package analyticsource

import (
	"context"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// ReauthorizeScalarDependency decides whether one previously saved live scalar
// may be disclosed to the current caller right now.
//
// It re-proves current authorization by freshly resolving the exact governed
// workspace, catalog, profile and exposure the dependency retained, under the
// current caller's own access context, and then comparing the fresh resolution
// against every retained neutral authority fact. The old principal, request and
// actor are never reused and are never read from the dependency: the dependency
// carries none of them.
//
// The method is fail closed and deliberately non-atomic. It proves authorization
// at this one instant only: it is not an atomic revocation fence, does not mutate
// or return the dependency, performs no source execution, retries nothing, caches
// nothing and discloses nothing. It calls the one concrete
// resolver.Resolve(ctx, currentAccess, request) exactly once, with a request
// derived only from the dependency's private payload; no caller-supplied source
// identity enters the request. A nil context is refused before any preparation
// or repository I/O. Every local refusal, repository refusal or fresh mismatch
// returns the exact unwrapped content-free errMismatch.
func (resolver *Resolver) ReauthorizeScalarDependency(
	ctx context.Context,
	currentAccess database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency ScalarDependency,
) error {
	if ctx == nil {
		return errMismatch
	}
	request, err := resolver.prepareScalarDependencyReauthorization(
		currentAccess, workspaceID, questionRunID, dependency)
	if err != nil {
		return errMismatch
	}
	resolution, err := resolver.Resolve(ctx, currentAccess, request)
	if err != nil {
		return errMismatch
	}
	if !scalarDependencyResolutionMatches(dependency.payload, resolver.catalog, resolution) {
		return errMismatch
	}
	return nil
}

// prepareScalarDependencyReauthorization performs every pre-I/O local check and
// derives the one ResolveRequest this reauthorization may make.
//
// It refuses a nil resolver or store, an invalid retained catalog, an invalid
// current access context, a malformed workspace or Question Run id, a zero or
// invalid dependency, and any mismatch of the exact run id, organization id or
// workspace id the current caller names. It then builds the request from the
// dependency's private payload alone — workspace id, catalog id/revision/hash,
// profile key from dataset id and profile version, and profile hash — so no
// caller-supplied source identity can enter it. Every refusal returns the exact
// zero ResolveRequest and the exact unwrapped errMismatch. It reads no
// repository and grants nothing.
func (resolver *Resolver) prepareScalarDependencyReauthorization(
	currentAccess database.AccessContext,
	workspaceID string,
	questionRunID string,
	dependency ScalarDependency,
) (ResolveRequest, error) {
	if resolver == nil || resolver.store == nil || !resolver.catalog.Valid() {
		return ResolveRequest{}, errMismatch
	}
	if currentAccess.Validate() != nil || !validBindingIdentity(workspaceID) ||
		!validBindingIdentity(questionRunID) {
		return ResolveRequest{}, errMismatch
	}
	payload := dependency.payload
	if !payload.valid() {
		return ResolveRequest{}, errMismatch
	}
	if payload.QuestionRunID != questionRunID || payload.OrganizationID != currentAccess.OrganizationID ||
		payload.WorkspaceID != workspaceID {
		return ResolveRequest{}, errMismatch
	}
	profileKey, err := analytic.NewProfileKey(payload.DatasetID, payload.ProfileVersion)
	if err != nil {
		return ResolveRequest{}, errMismatch
	}
	return ResolveRequest{
		WorkspaceID:     payload.WorkspaceID,
		CatalogID:       payload.CatalogID,
		CatalogRevision: payload.CatalogRevision,
		CatalogHash:     payload.CatalogHash,
		ProfileKey:      profileKey,
		ProfileHash:     payload.ProfileHash,
	}, nil
}

// scalarDependencyResolutionMatches compares one fresh private Resolution and the
// exact mounted catalog the concrete Resolve accepted it against, member by
// member, with every neutral authority fact the dependency retained.
//
// The workspace id/revision/configuration hash/source id, dataset id/profile
// version/profile hash, source-scope id/revision/configuration hash, connection
// id/revision, database identity, projection lineage/revision/contract hash and
// exposed schema revision/hash come from the Resolution's own sealed binding and
// profile. The catalog id/revision/hash are not fields of a Resolution: the
// concrete Resolve proves the derived request's catalog equals this mounted
// catalog, and this helper re-checks the mounted catalog against the dependency,
// so it never pretends Resolve returned a catalog fact. The receipt schema,
// receipt digest and Question Run id are binding facts validated locally, not
// facts Resolve reproduces, and are deliberately not compared here.
//
// It is pure, reads no repository, performs no source execution and is
// fail-closed: a zero or invalid dependency, an invalid catalog, a zero or
// invalid Resolution binding, or any single differing or malformed member
// returns false without disclosing which member failed.
func scalarDependencyResolutionMatches(
	dependency scalarDependencyPayload,
	mounted analytic.DatasetProfileCatalog,
	resolution Resolution,
) bool {
	if !dependency.valid() || !mounted.Valid() || !resolution.binding.valid() {
		return false
	}
	binding := resolution.binding
	facts := binding.binding
	execution := binding.execution
	profile := binding.profile
	return mounted.ID() == dependency.CatalogID &&
		mounted.Revision() == dependency.CatalogRevision &&
		mounted.Hash() == dependency.CatalogHash &&
		dependency.WorkspaceID == facts.workspaceID &&
		dependency.WorkspaceRevision == facts.workspaceRevision &&
		dependency.WorkspaceConfigurationHash == facts.workspaceConfigurationHash &&
		dependency.WorkspaceSourceID == facts.workspaceSourceID &&
		dependency.DatasetID == profile.Key().DatasetID() &&
		dependency.ProfileVersion == profile.Key().Version() &&
		dependency.ProfileHash == profile.Hash() &&
		dependency.SourceScopeID == facts.sourceScopeID &&
		dependency.SourceScopeRevision == facts.sourceScopeRevision &&
		dependency.SourceScopeConfigurationHash == facts.sourceScopeConfigurationHash &&
		dependency.ConnectionID == facts.connectionID &&
		dependency.ConnectionRevision == facts.connectionRevision &&
		dependency.DatabaseIdentity == facts.databaseIdentity &&
		dependency.ProjectionLineageID == execution.projectionLineageID &&
		dependency.ProjectionRevision == execution.projectionRevision &&
		dependency.ProjectionContractHash == execution.projectionContractHash &&
		dependency.ExposedSchemaRevision == execution.exposedSchemaRevision &&
		dependency.ExposedSchemaHash == execution.exposedSchemaHash
}
