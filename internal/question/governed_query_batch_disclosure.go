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
	sourceReauthorizer sourceSQLAttemptReauthorizer,
) ([]string, error) {
	multiple := make(map[string][]governedQueryDependency, len(dependencies))
	for runID, dependency := range dependencies {
		if dependency != nil {
			multiple[runID] = []governedQueryDependency{*dependency}
		}
	}
	return authorizeGovernedQueryDisclosureBatchMany(ctx, access, workspaceID, candidateRunIDs, multiple, reauthorizer, sourceReauthorizer)
}

func authorizeGovernedQueryDisclosureBatchMany(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	dependencies map[string][]governedQueryDependency,
	reauthorizer governedAttemptReauthorizer,
	sourceReauthorizer sourceSQLAttemptReauthorizer,
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
		dependencyList := dependencies[runID]
		if len(dependencyList) == 0 {
			continue
		}
		err := authorizeGovernedQueryDisclosuresByKind(ctx, access, workspaceID, runID, dependencyList, reauthorizer, sourceReauthorizer)
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
	return authorizeGovernedQueryDisclosureBatch(ctx, access, workspaceID, candidateRunIDs, dependencies,
		service.liveDataReauthorizer(), service.sourceSQLReauthorizer())
}

func (service *Service) authorizeGovernedQueryDisclosureBatchMany(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	candidateRunIDs []string,
	dependencies map[string][]governedQueryDependency,
) ([]string, error) {
	return authorizeGovernedQueryDisclosureBatchMany(ctx, access, workspaceID, candidateRunIDs, dependencies,
		service.liveDataReauthorizer(), service.sourceSQLReauthorizer())
}
