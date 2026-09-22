package question

import (
	"context"
	"errors"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// authorizeScalarDisclosureBatch is the deterministic batch reauthorization of
// already-saved scalar pairs. It is pure up to the per-pair single
// authorizeScalarDisclosure call and returns only the denied Question Run ids.
//
// The candidate ids are deduplicated and sorted before any work, so one id is
// processed exactly once and the outcome does not depend on caller ordering or
// repetition. Every candidate id is validated locally before any authority call:
// an empty or invalid candidate id is never treated as a legacy run and returns
// the exact content-free CodeUnavailable with a nil denied list before any I/O.
//
// A missing or nil pair for a candidate is the legacy state: it makes zero
// authority call, is never denied, and is simply skipped. A present pair is
// delegated unchanged to authorizeScalarDisclosure, so the one existing local
// validation, binding verification and single reauthorizer call apply per run.
// Pair-map entries for ids outside the candidate list are ignored entirely.
//
// A CodeNotFound outcome collects that whole run id as denied and processing
// continues. Any other error aborts immediately with a nil denied list and the
// exact bare error, even after earlier denials, so a partial prefix is never
// reported as a complete decision. On success the denied ids are the sorted,
// duplicate-free subset of the candidate ids whose pair was present and refused.
func authorizeScalarDisclosureBatch(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	pairs map[string]*analyticScalarPair,
	reauthorizer scalarDependencyReauthorizer,
) ([]string, error) {
	unique := make(map[string]struct{}, len(candidateRunIDs))
	for _, runID := range candidateRunIDs {
		unique[runID] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for runID := range unique {
		ordered = append(ordered, runID)
	}
	sort.Strings(ordered)

	for _, runID := range ordered {
		if !validOpaque(runID) {
			return nil, &Error{code: CodeUnavailable}
		}
	}

	var denied []string
	for _, runID := range ordered {
		pair := pairs[runID]
		if pair == nil {
			continue
		}
		err := authorizeScalarDisclosure(ctx, access, workspaceID, runID, pair, reauthorizer)
		if err == nil {
			continue
		}
		var refusal *Error
		if errors.As(err, &refusal) && refusal.code == CodeNotFound {
			denied = append(denied, runID)
			continue
		}
		return nil, err
	}
	return denied, nil
}

// authorizeAnalyticScalarDisclosureBatch is the Service wrapper of the batch
// gate. It requires the installed valid catalog and resolver only when at least
// one candidate id carries a present pair; an all-legacy batch succeeds without
// any installation, and pair-map entries outside the candidate list never force
// an install. It adds no setter, second install path or mutable state, and it
// never mutates the installed slots.
//
// When the install is required but absent, invalid or incomplete, it returns the
// content-free CodeUnavailable with a nil denied list before any authority call.
// Otherwise it delegates to the interface-taking helper with the installed
// concrete resolver, or with a nil reauthorizer for an all-legacy batch where no
// reauthorization call can occur.
func (service *Service) authorizeAnalyticScalarDisclosureBatch(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	pairs map[string]*analyticScalarPair,
) ([]string, error) {
	requiresResolver := false
	for _, runID := range candidateRunIDs {
		if pairs[runID] != nil {
			requiresResolver = true
			break
		}
	}
	if !requiresResolver {
		return authorizeScalarDisclosureBatch(ctx, access, workspaceID, candidateRunIDs, pairs, nil)
	}
	if service == nil || !service.datasetProfileCatalog.Valid() || service.analyticSourceResolver == nil {
		return nil, &Error{code: CodeUnavailable}
	}
	return authorizeScalarDisclosureBatch(ctx, access, workspaceID, candidateRunIDs, pairs, service.analyticSourceResolver)
}
