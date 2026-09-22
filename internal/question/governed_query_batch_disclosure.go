package question

import (
	"context"
	"errors"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// authorizeGovernedQueryDisclosureBatch reauthorizes the present saved live
// dependencies for a deterministic set of candidate runs. A denied dependency
// contributes only its Question Run id; any unavailable/local failure aborts
// with a nil denied list so callers never act on a partial prefix.
func authorizeGovernedQueryDisclosureBatch(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	dependencies map[string]*governedQueryDependency,
	reauthorizer governedAttemptReauthorizer,
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
		dependency := dependencies[runID]
		if dependency == nil {
			continue
		}
		err := authorizeGovernedQueryDisclosure(ctx, access, workspaceID, runID, dependency, reauthorizer)
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

// authorizeGovernedQueryDisclosureBatchForService uses only the governed ask
// installed through EnableGovernedAsk. Nil dependencies are skipped by the
// helper, so legacy batches require no installation or authority call.
func (service *Service) authorizeGovernedQueryDisclosureBatch(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	dependencies map[string]*governedQueryDependency,
) ([]string, error) {
	var reauthorizer governedAttemptReauthorizer
	if service != nil {
		reauthorizer, _ = service.liveDataAsk.(governedAttemptReauthorizer)
	}
	return authorizeGovernedQueryDisclosureBatch(ctx, access, workspaceID, candidateRunIDs, dependencies, reauthorizer)
}
