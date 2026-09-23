package question

import (
	"context"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// analyticResolutionCheck is the private callback one sequential candidate check
// invokes for a single matched request. It reports whether that exact request
// resolved to a valid resolution for the supplied access context, and returns a
// nonnil error when the attempt failed. It is a callback seam only: it holds no
// resolver, service, store, connection or state between calls, and any
// repository read, audit record or resolution value behind an answer belongs to
// the caller that supplies the callback.
type analyticResolutionCheck func(
	context.Context,
	database.AccessContext,
	analyticsource.ResolveRequest,
) (validResolution bool, err error)

// checkAnalyticCandidateRequests attempts each matched candidate/request pair
// exactly once through check and returns the candidates whose attempt reported a
// valid resolution, in input order.
//
// Every argument refusal is decided before the first callback: a nil ctx, an
// access context that fails Validate, a nil check, unequal candidate and request
// lengths, or any index whose request ProfileKey or ProfileHash differs from the
// candidate key or hash at that index returns a nil candidate slice and
// &Error{code: CodeInvalid} with no cause, clarification, wrap or logging.
// Matched slices are matched index by index; nothing is reordered, added,
// dropped, deduplicated or compared beyond that exact key and hash.
//
// An empty matched pair returns a non-nil, zero-length candidate slice and a nil
// error: no deadline is required and no callback runs. A non-empty pair
// otherwise requires a live context with a deadline, so an already failed ctx
// returns a nil candidate slice and &Error{code: CodeUnavailable}, while a live
// context without a Deadline returns a nil candidate slice and
// &Error{code: CodeInvalid}. Both refusals precede the first callback.
//
// The requests are then attempted sequentially, with no concurrency, retry,
// batching or timeout construction. The helper reads ctx.Err immediately before
// and immediately after each call, and a failed context at either point returns
// a nil candidate slice and &Error{code: CodeUnavailable}, discarding every
// candidate accepted so far and making no later call. A nonnil callback error
// excludes that request and continues with the next one: the error is never
// inspected, compared, wrapped, logged, counted or exposed, even when the
// callback also reported a valid resolution. A nil callback error with a false
// resolution is a broken callback contract and stops the run with a nil
// candidate slice and &Error{code: CodeUnavailable}, again discarding the
// accepted prefix.
//
// The accepted slice is always freshly allocated, so it shares no storage with
// the candidates argument, and it stays non-nil when every callback errored.
// This helper performs no I/O, persistence, audit or model projection of its
// own.
func checkAnalyticCandidateRequests(
	ctx context.Context,
	access database.AccessContext,
	candidates []analyticCandidate,
	requests []analyticsource.ResolveRequest,
	check analyticResolutionCheck,
) ([]analyticCandidate, error) {
	if ctx == nil || access.Validate() != nil || check == nil || len(candidates) != len(requests) {
		return nil, &Error{code: CodeInvalid}
	}
	for index, request := range requests {
		if request.ProfileKey != candidates[index].profileKey || request.ProfileHash != candidates[index].profileHash {
			return nil, &Error{code: CodeInvalid}
		}
	}
	if len(requests) == 0 {
		return []analyticCandidate{}, nil
	}
	if ctx.Err() != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, &Error{code: CodeInvalid}
	}
	accepted := make([]analyticCandidate, 0, len(requests))
	for index, request := range requests {
		if ctx.Err() != nil {
			return nil, &Error{code: CodeUnavailable}
		}
		valid, err := check(ctx, access, request)
		if ctx.Err() != nil {
			return nil, &Error{code: CodeUnavailable}
		}
		if err != nil {
			continue
		}
		if !valid {
			return nil, &Error{code: CodeUnavailable}
		}
		accepted = append(accepted, candidates[index])
	}
	return accepted, nil
}
