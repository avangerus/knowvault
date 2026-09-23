package question

import (
	"reflect"

	"knowvault.local/verified-workspace/internal/analyticsource"
)

// analyticResolveRequest binds one selected analytic candidate from an exact
// retained candidate plan to the analyticsource.ResolveRequest that names it.
// It performs no resolution and no I/O: it calls no resolver, repository or
// database, and it produces no audit record, persistence, model projection,
// disclosure, authority or execution permission.
//
// The workspace ID is validated with validOpaque and is never trimmed or
// normalized. The supplied plan must be exactly the plan this service retains:
// the method recomputes it with planAnalyticCandidates at the sealed maximum
// limit and requires the catalog ID, revision and hash, the candidate count and
// canonical order, and every candidate key and hash to match. The generating
// budget is not part of a plan, so a complete plan generated under any
// sufficient lower limit is accepted, while a missing, added, duplicated,
// reordered, mutated, stale or fabricated plan is refused. The selected
// candidate's exact profile key and profile hash must then occur in that plan.
//
// An absent analytic capability is refused: the exact zero plan carries no
// catalog identity to bind. An installed catalog whose entries are all RETIRED
// is installed and keeps its catalog identity, but has no selectable member, so
// every attempted selection is refused.
//
// On success the request carries only the workspace ID, the plan's catalog
// identity, and the selected candidate's profile identity. Every refusal
// returns the exact zero analyticsource.ResolveRequest and &Error{code:
// CodeInvalid} with no cause, clarification, wrapped error, field-specific
// reason, logging, partial result, identity or existence-specific outcome.
// Neither outcome mutates the service slots, the supplied plan, or its
// candidate slice.
//
// This proves correspondence to the service's retained immutable catalog only.
// It does not claim freshness, authority, source access, execution permission,
// resolver-internal catalog equality or evidence. The resolver keeps its
// retained catalog private, so this method adds no resolver accessor and cannot
// detect a resolver that was privately built from another catalog by a package
// test assigning the fields directly.
func (service *Service) analyticResolveRequest(
	workspaceID string,
	plan analyticCandidatePlan,
	candidate analyticCandidate,
) (analyticsource.ResolveRequest, error) {
	if !validOpaque(workspaceID) {
		return analyticsource.ResolveRequest{}, &Error{code: CodeInvalid}
	}
	retained, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		return analyticsource.ResolveRequest{}, &Error{code: CodeInvalid}
	}
	// The exact zero plan is the absent analytic capability, which has no
	// catalog identity to bind. An installed all-RETIRED catalog instead keeps
	// its catalog identity and a non-nil zero-length candidate slice, so it
	// stays distinguishable here and refuses through the exact plan equality
	// and the missing selected member below.
	if reflect.DeepEqual(retained, analyticCandidatePlan{}) {
		return analyticsource.ResolveRequest{}, &Error{code: CodeInvalid}
	}
	if !reflect.DeepEqual(plan, retained) {
		return analyticsource.ResolveRequest{}, &Error{code: CodeInvalid}
	}
	selected := false
	for _, member := range retained.candidates {
		if member == candidate {
			selected = true
			break
		}
	}
	if !selected {
		return analyticsource.ResolveRequest{}, &Error{code: CodeInvalid}
	}
	return analyticsource.ResolveRequest{
		WorkspaceID:     workspaceID,
		CatalogID:       retained.catalogID,
		CatalogRevision: retained.catalogRevision,
		CatalogHash:     retained.catalogHash,
		ProfileKey:      candidate.profileKey,
		ProfileHash:     candidate.profileHash,
	}, nil
}
