package registration

// Batch discovery registration (card S3.4b). A discovery result can carry
// hundreds of prepared relations; the wizard registers them with one server
// request per batch instead of one request per table. This file owns the
// bounded batch: it accepts only server-issued view selectors (never browser
// schema, columns, hashes or SQL), delegates every per-view registration to the
// unchanged single-table RegisterDiscoveredView path, and returns one closed
// per-view outcome. A table the discovery worker could not prepare (for example
// one without a declared primary key) gets its own interpretation reason and
// never blocks the others.

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

// MaxBatchRegisterViews is the hard bound on one batch registration request.
// A larger request is refused as a whole before any selector is resolved.
const MaxBatchRegisterViews = 200

// BatchRegisterItem is one selector of a batch registration: the server-issued
// view id plus the same two caller-owned narrowing choices the single-table
// route accepts (ADR-0097 excluded ordinals and the S3 card 4 mode).
type BatchRegisterItem struct {
	ViewID                 string
	ExcludedColumnOrdinals []int
	Mode                   string
}

// BatchRegisterOutcome is the per-view result. On success Registered is true
// and Result carries the created DRAFT identity; on refusal Registered is false
// and ReasonCode is one closed, content-free code.
type BatchRegisterOutcome struct {
	ViewID     string
	Registered bool
	ReasonCode string
	Result     RegisterResult
}

// BatchRegisterResult is the ordered per-view outcome of one batch request.
type BatchRegisterResult struct {
	Outcomes        []BatchRegisterOutcome
	RegisteredCount int
	RefusedCount    int
}

// DiscoveredViewResolver resolves server-issued selectors against one live
// discovery result. It is satisfied by internal/source/discovery.Reader.
type DiscoveredViewResolver interface {
	SelectMany(ctx context.Context, access database.AccessContext, requestID string, selectors []string) ([]discovery.SelectedViewResolution, error)
}

// RegisterDiscoveredViewBatch registers a bounded batch of discovered views
// through the one discovery resolver and the unchanged single-view
// registration. A per-view business refusal (an unprepared relation, an unknown
// selector, a lineage conflict or an invalid narrowing) is reported in that
// view's outcome and the loop continues; an authorization or infrastructure
// failure aborts the whole request, exactly like the single-table route.
func RegisterDiscoveredViewBatch(ctx context.Context, service *Service, resolver DiscoveredViewResolver,
	access database.AccessContext, requestID string, items []BatchRegisterItem) (BatchRegisterResult, error) {
	if service == nil || resolver == nil || access.Validate() != nil || requestID == "" ||
		len(items) < 1 || len(items) > MaxBatchRegisterViews {
		return BatchRegisterResult{}, &Error{code: CodeRequestInvalid}
	}
	selectors := make([]string, len(items))
	for index, item := range items {
		if item.ViewID == "" || !postgresqlquery.ValidProjectionMode(item.Mode) {
			return BatchRegisterResult{}, &Error{code: CodeRequestInvalid}
		}
		selectors[index] = item.ViewID
	}
	resolutions, err := resolver.SelectMany(ctx, access, requestID, selectors)
	if err != nil {
		return BatchRegisterResult{}, err
	}
	if len(resolutions) != len(items) {
		return BatchRegisterResult{}, &Error{code: CodePersistence}
	}

	result := BatchRegisterResult{Outcomes: make([]BatchRegisterOutcome, 0, len(items))}
	for index, item := range items {
		outcome := BatchRegisterOutcome{ViewID: item.ViewID}
		resolution := resolutions[index]
		if resolution.Selected == nil {
			outcome.ReasonCode = resolution.Reason
			if outcome.ReasonCode == "" {
				outcome.ReasonCode = "NOT_FOUND"
			}
			result.RefusedCount++
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		registered, registerErr := service.RegisterDiscoveredView(ctx, access, *resolution.Selected,
			item.ExcludedColumnOrdinals, item.Mode)
		if registerErr == nil {
			outcome.Registered = true
			outcome.Result = registered
			result.RegisteredCount++
			result.Outcomes = append(result.Outcomes, outcome)
			continue
		}
		code := CodeOf(registerErr)
		switch code {
		case CodePersistence, CodeUnavailable, CodeDenied:
			return BatchRegisterResult{}, registerErr
		}
		outcome.ReasonCode = string(code)
		result.RefusedCount++
		result.Outcomes = append(result.Outcomes, outcome)
	}
	return result, nil
}
