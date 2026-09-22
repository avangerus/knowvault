package analyticsource

import (
	"context"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// Resolver owns the immutable mounted catalog selection and the concrete
// repository store one caller reads fresh authority and exposure facts through.
// Retaining a store is not a repository result, and retaining a valid catalog
// is not proof that the catalog is still the mounted one, so the resolver holds
// no resolved fact and every call re-reads the repository.
type Resolver struct {
	store   *repository.Store
	catalog analytic.DatasetProfileCatalog
}

// ResolveRequest is the one caller-named selection a resolver accepts: the
// workspace it asks about and the exact mounted catalog revision, catalog hash
// and active profile version it already knows. It cannot name a source scope,
// connection, database, schema or relation, so every source value can only come
// from the retained sealed profile.
type ResolveRequest struct {
	WorkspaceID     string
	CatalogID       string
	CatalogRevision int64
	CatalogHash     string
	ProfileKey      analytic.ProfileKey
	ProfileHash     string
}

// NewResolver binds one concrete repository store and one valid immutable
// catalog to a resolver. It performs no I/O and calls neither the store nor the
// database. A nil store and a zero or invalid catalog both return nil plus the
// exact unwrapped errMismatch, so no caller can hold a resolver that is missing
// either half.
//
// The catalog is retained exactly as received: the constructor does not claim
// the value came from a mount, and later composition must supply the same
// mounted value the Question service uses.
func NewResolver(store *repository.Store, catalog analytic.DatasetProfileCatalog) (*Resolver, error) {
	if store == nil || !catalog.Valid() {
		return nil, errMismatch
	}
	return &Resolver{store: store, catalog: catalog}, nil
}

// Resolve executes the frozen plan against the concrete repository and returns
// the one sealed eligibility binding as an opaque Resolution, or the exact zero
// Resolution and the exact unwrapped errMismatch.
//
// The sequence is fail closed. The plan is prepared before any repository I/O,
// so a malformed or drifting request reads nothing. The three reads that follow
// are separately authorized current reads — the authority candidate lookup, the
// authority resolution of that exact returned candidate, and the governed
// exposure lookup — and they do not form one atomic snapshot: no fact read
// earlier is assumed to still hold in a later read, and the binding is sealed
// only after the fresh authority and exposure facts matched the retained active
// profile exactly.
//
// Nothing is retried, cached or parallelized, no repository cause, code or fact
// is exposed or wrapped, and no source scope, connection, schema or relation is
// caller-chosen. Every refusal — the plan, a repository read, the binding —
// returns the same content-free value, so Resolve is neither an existence nor
// an authorization oracle.
func (resolver *Resolver) Resolve(
	ctx context.Context,
	access database.AccessContext,
	request ResolveRequest,
) (Resolution, error) {
	plan, err := resolver.plan(request)
	if err != nil {
		return Resolution{}, errMismatch
	}
	candidate, err := resolver.store.ResolvePostgreSQLAuthorityRequest(ctx, access, plan.authority)
	if err != nil {
		return Resolution{}, errMismatch
	}
	authority, err := resolver.store.ResolvePostgreSQLAuthority(ctx, access, candidate)
	if err != nil {
		return Resolution{}, errMismatch
	}
	exposure, err := resolver.store.ResolveGovernedExposure(ctx, access, plan.exposure)
	if err != nil {
		return Resolution{}, errMismatch
	}
	binding, err := bindRepositoryResults(repositoryBindingExpectation{
		workspaceID:                request.WorkspaceID,
		workspaceRevision:          authority.WorkspaceRevision(),
		workspaceConfigurationHash: authority.WorkspaceConfigurationHash(),
		catalogID:                  request.CatalogID,
		catalogRevision:            request.CatalogRevision,
		catalogHash:                request.CatalogHash,
		profileKey:                 request.ProfileKey,
		profileHash:                request.ProfileHash,
	}, resolver.catalog, authority, exposure)
	if err != nil {
		return Resolution{}, errMismatch
	}
	return Resolution{binding: binding}, nil
}

// resolutionPlan is the exact read plan one accepted ResolveRequest prepares:
// the active sealed profile, the source authority lookup, and the governed
// exposure lookup. It is preparation only, performs no I/O, grants nothing, and
// is never current authority.
type resolutionPlan struct {
	profile   analytic.DatasetProfile
	authority repository.PostgreSQLAuthorityLookup
	exposure  repository.GovernedExposureLookup
}

// plan prepares the resolutionPlan for one request without reading the
// repository. It refuses a nil resolver, a nil retained store, an invalid
// retained catalog, a malformed request member, any catalog identity drift, and
// any profile the retained catalog cannot resolve as active with the exact
// requested hash. Every refusal returns the exact zero resolutionPlan and the
// exact unwrapped errMismatch, which discloses none of the request, catalog or
// profile values.
//
// The accepted plan names the workspace from the request and every source
// identity from the resolved profile alone: the caller cannot select a source
// scope, connection, schema or relation, and no missing profile value is
// repaired, defaulted, case folded or trimmed.
func (resolver *Resolver) plan(request ResolveRequest) (resolutionPlan, error) {
	if resolver == nil || resolver.store == nil || !resolver.catalog.Valid() {
		return resolutionPlan{}, errMismatch
	}
	if !validBindingIdentity(request.WorkspaceID) || !validBindingIdentity(request.CatalogID) ||
		!validBindingRevision(request.CatalogRevision) || !validBindingHash(request.CatalogHash) ||
		!request.ProfileKey.Valid() || !validBindingHash(request.ProfileHash) {
		return resolutionPlan{}, errMismatch
	}
	if resolver.catalog.ID() != request.CatalogID ||
		resolver.catalog.Revision() != request.CatalogRevision ||
		resolver.catalog.Hash() != request.CatalogHash {
		return resolutionPlan{}, errMismatch
	}
	profile, resolved := resolver.catalog.ResolveActive(request.ProfileKey, request.ProfileHash)
	if !resolved || !profile.Valid() {
		return resolutionPlan{}, errMismatch
	}
	approved := profile.Source().Values()
	return resolutionPlan{
		profile: profile,
		authority: repository.PostgreSQLAuthorityLookup{
			WorkspaceID:   request.WorkspaceID,
			SourceScopeID: approved.SourceScopeID,
			ConnectionID:  approved.ConnectionID,
		},
		exposure: repository.GovernedExposureLookup{
			WorkspaceID:   request.WorkspaceID,
			SourceScopeID: approved.SourceScopeID,
			ConnectionID:  approved.ConnectionID,
			SchemaName:    approved.SchemaName,
			RelationName:  approved.RelationName,
		},
	}, nil
}
