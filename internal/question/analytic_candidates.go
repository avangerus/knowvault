package question

import (
	"reflect"

	"knowvault.local/verified-workspace/internal/analytic"
)

// maxAnalyticCandidateLimit bounds how many ACTIVE catalog profiles one plan may
// describe. It equals the sealed catalog maximum, which analytic refuses to
// exceed, so an accepted snapshot never needs a larger budget.
const maxAnalyticCandidateLimit = 64

// analyticCandidate names one catalog profile version that is ACTIVE inside the
// retained immutable catalog snapshot. It carries the sealed profile identity
// only: no workspace or access identity, source scope, connection, database,
// schema, relation, SQL, physical field, business prose, semantic projection,
// repository result, resolution, or execution handle.
type analyticCandidate struct {
	profileKey  analytic.ProfileKey
	profileHash string
}

// analyticCandidatePlan describes which exact catalog profile versions are
// ACTIVE in one retained immutable catalog snapshot. It is a server-owned
// description for a future Question Run, never authority, execution permission,
// evidence, a model payload, or a durable artifact: no transport or model picks
// its limit, and nothing persists or caches it. ACTIVE here means only membership
// in the retained snapshot.
type analyticCandidatePlan struct {
	catalogID       string
	catalogRevision int64
	catalogHash     string
	candidates      []analyticCandidate
}

// planAnalyticCandidates describes the ACTIVE members of the retained catalog
// snapshot within a server-owned limit. It reads the two installed slots only:
// no I/O, no resolver call, no persistence, and no mutation of either slot.
//
// EnableDatasetProfileCatalog is the only production writer of those slots: it
// constructs the resolver from the exact catalog it is about to retain and
// assigns both slots only after that constructor succeeded, so every pair a
// production service holds is that installer's catalog with the resolver built
// from it. This method does not re-establish that installer invariant and must
// not be read as proving it. The resolver keeps its retained catalog private, so
// resolver-internal catalog equality is not observable here, and any non-nil
// resolver beside a valid non-zero catalog is accepted as received, including a
// pair a package test assigned to both slots directly.
//
// What this method does verify is the observable slot shape: the exact zero
// catalog beside a nil resolver is the absent capability and returns the exact
// zero plan and a nil error; exactly one occupied slot is invalid; and a
// non-zero catalog must be Valid with a non-nil resolver. A valid installed
// catalog then succeeds with a plan bound to its exact ID, revision and hash,
// whose candidates carry each ACTIVE entry's sealed profile key and hash in the
// catalog's canonical order. A catalog whose entries are all RETIRED still
// succeeds, with a non-nil, zero-length candidate slice that keeps an installed
// catalog distinguishable from an absent capability.
//
// A nil Service, a limit outside [1, maxAnalyticCandidateLimit], an invalid
// slot shape, or more ACTIVE entries than limit fails closed with the exact zero
// plan and the content-free CodeInvalid refusal, and returns no truncated
// candidate list.
func (service *Service) planAnalyticCandidates(limit int) (analyticCandidatePlan, error) {
	if service == nil || limit < 1 || limit > maxAnalyticCandidateLimit {
		return analyticCandidatePlan{}, &Error{code: CodeInvalid}
	}
	// The retained catalog carries a sealed entry slice, so it is not
	// Go-comparable and its emptiness is an explicit comparison against the
	// exact zero value, the same test EnableDatasetProfileCatalog uses to decide
	// occupancy. A non-zero invalid value therefore stays an occupied slot. The
	// resolver is checked for nil only, never for the catalog it was built from.
	catalog := service.datasetProfileCatalog
	resolver := service.analyticSourceResolver
	if reflect.DeepEqual(catalog, analytic.DatasetProfileCatalog{}) {
		if resolver != nil {
			return analyticCandidatePlan{}, &Error{code: CodeInvalid}
		}
		return analyticCandidatePlan{}, nil
	}
	if resolver == nil || !catalog.Valid() {
		return analyticCandidatePlan{}, &Error{code: CodeInvalid}
	}

	entries := catalog.Entries()
	candidates := make([]analyticCandidate, 0, len(entries))
	for _, entry := range entries {
		if entry.State != analytic.ProfileActive {
			continue
		}
		if len(candidates) == limit {
			return analyticCandidatePlan{}, &Error{code: CodeInvalid}
		}
		candidates = append(candidates, analyticCandidate{
			profileKey:  entry.Profile.Key(),
			profileHash: entry.Profile.Hash(),
		})
	}
	return analyticCandidatePlan{
		catalogID:       catalog.ID(),
		catalogRevision: catalog.Revision(),
		catalogHash:     catalog.Hash(),
		candidates:      candidates,
	}, nil
}
