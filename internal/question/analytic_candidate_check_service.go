package question

import (
	"context"
	"reflect"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// checkAnalyticCandidates attempts one complete analytic candidate check for
// the workspace and returns the candidates whose opaque check completed in this
// invocation, in the retained catalog's canonical order.
//
// It is an adapter over three existing private helpers and adds no authority of
// its own: planAnalyticCandidates describes the ACTIVE members of the retained
// immutable catalog snapshot, analyticResolveRequest binds each planned
// candidate to the exact request naming it, and checkAnalyticCandidateRequests
// attempts those requests sequentially through a private closure over the
// installed concrete service.analyticSourceResolver.Resolve.
//
// A nil Service, a nil ctx, an access context that fails Validate, or a
// workspace ID that fails validOpaque returns a nil candidate slice and the
// content-free &Error{code: CodeInvalid}. An already canceled or expired ctx
// returns a nil candidate slice and &Error{code: CodeUnavailable} before either
// retained slot is read.
//
// The plan is recomputed at the sealed maximum limit, so an invalid or partial
// slot pair, or more ACTIVE entries than that limit, returns a nil candidate
// slice and &Error{code: CodeInvalid}. The exact zero plan is the absent
// analytic capability: it returns a nil candidate slice and a nil error without
// reading a context Deadline or calling any resolver. An installed catalog
// stays distinguishable — an all-RETIRED catalog succeeds with the non-nil,
// zero-length accepted slice and a nil error, again with no resolver call.
//
// A nonempty plan requires a live context that already carries a Deadline
// before any request is built or any resolver runs; a live context without one
// returns a nil candidate slice and &Error{code: CodeInvalid}. Every request is
// then constructed in candidate order, before the first resolver call, and any
// request refusal returns a nil candidate slice and &Error{code: CodeInvalid}
// rather than a hand-built, repaired, truncated or partially executed request
// set.
//
// The resolver closure never inspects or retains resolution internals: it
// reports valid only for a nil-error call whose Valid() holds, and hands a
// resolver error to the sequential helper unchanged, which uniformly skips
// that candidate. No
// resolver cause, code or fact, and no Resolution value, is retained, returned
// or exposed. The helper's result is returned unchanged, so the returned subset
// says only which opaque checks completed in this invocation: it is not current
// authority, execution permission, evidence, source coverage or disclosure
// permission. Nothing is cached, persisted, logged, counted, serialized,
// model-projected or stored on the Service.
func (service *Service) checkAnalyticCandidates(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
) ([]analyticCandidate, error) {
	if service == nil || ctx == nil || access.Validate() != nil || !validOpaque(workspaceID) {
		return nil, &Error{code: CodeInvalid}
	}
	if ctx.Err() != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	// The exact zero plan is the absent analytic capability, which has no
	// catalog identity and no member to check. An installed all-RETIRED catalog
	// instead carries a non-nil, zero-length candidate slice, so it still
	// reaches the empty sequential fast path below and stays distinguishable.
	if reflect.DeepEqual(plan, analyticCandidatePlan{}) {
		return nil, nil
	}
	resolve := func(callbackContext context.Context, callbackAccess database.AccessContext, request analyticsource.ResolveRequest) (bool, error) {
		resolution, err := service.analyticSourceResolver.Resolve(callbackContext, callbackAccess, request)
		if err != nil {
			return false, err
		}
		return resolution.Valid(), nil
	}
	requests := make([]analyticsource.ResolveRequest, 0, len(plan.candidates))
	if len(plan.candidates) > 0 {
		if _, ok := ctx.Deadline(); !ok {
			return nil, &Error{code: CodeInvalid}
		}
		for _, candidate := range plan.candidates {
			request, err := service.analyticResolveRequest(workspaceID, plan, candidate)
			if err != nil {
				return nil, &Error{code: CodeInvalid}
			}
			requests = append(requests, request)
		}
	}
	return checkAnalyticCandidateRequests(ctx, access, plan.candidates, requests, resolve)
}
