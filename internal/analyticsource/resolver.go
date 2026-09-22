package analyticsource

import (
	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// Resolver owns the immutable mounted catalog selection and the concrete
// repository store one caller will later read fresh authority and exposure
// facts through. It performs no I/O itself and grants nothing: retaining a
// store is not a repository result, and retaining a valid catalog is not proof
// that the catalog is still the mounted one.
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
