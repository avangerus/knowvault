package governedask

import (
	"context"
	"sort"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// ComparisonSummary contains only the operator-approved human description of
// a metric. Physical table names, columns, filters and SQL stay server-side.
type ComparisonSummary struct {
	MetricID    string `json:"metric_id"`
	Unit        string `json:"unit"`
	Description string `json:"description"`
}

// ComparisonCatalog lists metrics available to an authorized workspace. The
// same live-query opt-in used for execution gates discovery as well.
func (service *Service) ComparisonCatalog(ctx context.Context, access database.AccessContext, workspaceID string) ([]ComparisonSummary, error) {
	return service.comparisonCatalogWith(ctx, access, workspaceID, service.authorize, service.liveQueriesEnabled)
}

// comparisonCatalogWith keeps the production authorization and opt-in order
// testable without a live database. Production always supplies those exact
// service methods and no callback is stored on Service.
func (service *Service) comparisonCatalogWith(ctx context.Context, access database.AccessContext, workspaceID string,
	authorize func(context.Context, database.AccessContext, string, policy.Operation) error,
	liveEnabled func(context.Context, database.AccessContext, string) (bool, error),
) ([]ComparisonSummary, error) {
	if service == nil || !service.enabled {
		return nil, &Error{code: CodeUnavailable}
	}
	if ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) || authorize == nil || liveEnabled == nil {
		return nil, &Error{code: CodeRequestInvalid}
	}
	if err := authorize(ctx, access, workspaceID, policy.OperationWorkspaceAsk); err != nil {
		return nil, err
	}
	enabled, err := liveEnabled(ctx, access, workspaceID)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, &Error{code: CodeLiveQueriesOff}
	}
	service.comparisonMu.RLock()
	defer service.comparisonMu.RUnlock()
	summaries := make([]ComparisonSummary, 0, len(service.comparisonProfiles[workspaceID]))
	for _, binding := range service.comparisonProfiles[workspaceID] {
		if binding.connectionID != service.config.ConnectionID || binding.databaseIdentity != service.config.DatabaseIdentity {
			continue
		}
		summaries = append(summaries, ComparisonSummary{
			MetricID: binding.profile.MetricID(), Unit: binding.profile.Unit(), Description: binding.profile.Description(),
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].MetricID < summaries[j].MetricID })
	return summaries, nil
}
