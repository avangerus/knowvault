package question

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// errAnalyticCandidateCheckAttempt is the sentinel a scripted failing callback
// returns. The helper may neither inspect, compare, wrap, log, count nor expose
// it, so every test that scripts it also proves the returned error is not it.
var errAnalyticCandidateCheckAttempt = errors.New("injected: analytic candidate attempt failed")

// TestCheckAnalyticCandidateRequestsEmptyMatchReturnsNonNilEmpty proves an empty
// matched pair is the fast path: a non-nil, zero-length candidate slice and a
// nil error, with no deadline on the context and no callback.
func TestCheckAnalyticCandidateRequestsEmptyMatchReturnsNonNilEmpty(t *testing.T) {
	access := questionAccess(database.ActorKindHuman)

	for _, testCase := range []struct {
		name       string
		candidates []analyticCandidate
		requests   []analyticsource.ResolveRequest
	}{
		{"nil slices", nil, nil},
		{"empty slices", []analyticCandidate{}, []analyticsource.ResolveRequest{}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &analyticCandidateCheckRecorder{}

			accepted, err := checkAnalyticCandidateRequests(context.Background(), access, testCase.candidates, testCase.requests, recorder.check)
			if err != nil {
				t.Fatalf("empty match refused: %v", err)
			}
			if accepted == nil {
				t.Fatal("empty match returned a nil candidate slice")
			}
			if len(accepted) != 0 {
				t.Fatalf("empty match accepted = %+v want none", accepted)
			}
			if len(recorder.calls) != 0 {
				t.Fatalf("empty match made %d calls want none", len(recorder.calls))
			}
		})
	}
}

// TestCheckAnalyticCandidateRequestsForwardsEachMatchedRequestInOrder proves one
// callback per candidate, in input order, receiving the exact context, access
// context and request the helper was given.
func TestCheckAnalyticCandidateRequestsForwardsEachMatchedRequestInOrder(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta", "gamma")
	access := questionAccess(database.ActorKindService)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}

	accepted, err := checkAnalyticCandidateRequests(ctx, access, candidates, requests, recorder.check)
	if err != nil {
		t.Fatalf("check matched candidates: %v", err)
	}
	if !reflect.DeepEqual(accepted, candidates) {
		t.Fatalf("accepted = %+v want %+v", accepted, candidates)
	}
	if len(recorder.calls) != len(requests) {
		t.Fatalf("calls = %d want %d", len(recorder.calls), len(requests))
	}
	wantDatasets := []string{"alpha", "beta", "gamma"}
	for index, call := range recorder.calls {
		if call.ctx != ctx {
			t.Fatalf("call %d context = %v want the exact supplied context", index, call.ctx)
		}
		if call.access != access {
			t.Fatalf("call %d access = %+v want %+v", index, call.access, access)
		}
		if call.request != requests[index] {
			t.Fatalf("call %d request = %+v want %+v", index, call.request, requests[index])
		}
		if call.request.ProfileKey != candidates[index].profileKey || call.request.ProfileHash != candidates[index].profileHash {
			t.Fatalf("call %d request = %+v does not name candidate %d", index, call.request, index)
		}
		if datasetID := call.request.ProfileKey.DatasetID(); datasetID != wantDatasets[index] {
			t.Fatalf("call %d dataset = %q want %q", index, datasetID, wantDatasets[index])
		}
	}
}

// TestCheckAnalyticCandidateRequestsKeepsValidAndSkipsFailedAttempts proves a
// valid, error-free attempt is accepted, an errored attempt is skipped whether
// or not it also reported a valid resolution, and the accepted candidates keep
// the input order of the requests that produced them.
func TestCheckAnalyticCandidateRequestsKeepsValidAndSkipsFailedAttempts(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta", "gamma", "delta")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	recorder := &analyticCandidateCheckRecorder{results: []analyticCandidateCheckResult{
		{valid: true},
		{err: errAnalyticCandidateCheckAttempt},
		{valid: true, err: errAnalyticCandidateCheckAttempt},
		{valid: true},
	}}

	accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
	if err != nil {
		t.Fatalf("mixed attempts refused: %v", err)
	}
	want := []analyticCandidate{candidates[0], candidates[3]}
	if !reflect.DeepEqual(accepted, want) {
		t.Fatalf("accepted = %+v want %+v", accepted, want)
	}
	if len(recorder.calls) != len(candidates) {
		t.Fatalf("calls = %d want one per candidate (%d)", len(recorder.calls), len(candidates))
	}
}

// TestCheckAnalyticCandidateRequestsAllFailedAttemptsReturnEmptySuccess proves a
// run whose every callback errored still succeeds, with a non-nil, zero-length
// candidate slice and no exposed callback error.
func TestCheckAnalyticCandidateRequestsAllFailedAttemptsReturnEmptySuccess(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	recorder := &analyticCandidateCheckRecorder{results: []analyticCandidateCheckResult{
		{err: errAnalyticCandidateCheckAttempt},
		{valid: true, err: errAnalyticCandidateCheckAttempt},
	}}

	accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
	if err != nil {
		t.Fatalf("all failed attempts refused: %v", err)
	}
	if accepted == nil {
		t.Fatal("all failed attempts returned a nil candidate slice")
	}
	if len(accepted) != 0 {
		t.Fatalf("all failed attempts accepted = %+v want none", accepted)
	}
	if len(recorder.calls) != len(candidates) {
		t.Fatalf("calls = %d want one per candidate (%d)", len(recorder.calls), len(candidates))
	}
}

// TestCheckAnalyticCandidateRequestsFalseWithoutErrorStops proves a nil callback
// error with a false resolution is the broken callback contract: the run stops
// with CodeUnavailable, discards the candidate accepted before it, and makes no
// later call.
func TestCheckAnalyticCandidateRequestsFalseWithoutErrorStops(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta", "gamma")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	recorder := &analyticCandidateCheckRecorder{results: []analyticCandidateCheckResult{
		{valid: true},
		{},
		{valid: true},
	}}

	accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
	assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeUnavailable)
	if len(recorder.calls) != 2 {
		t.Fatalf("calls = %d want exactly the two calls before the broken contract", len(recorder.calls))
	}
}

// TestCheckAnalyticCandidateRequestsRefusesInvalidInputsBeforeAnyCallback proves
// every argument refusal returns the exact nil candidate slice and the
// content-free CodeInvalid error without calling the callback once.
func TestCheckAnalyticCandidateRequestsRefusesInvalidInputsBeforeAnyCallback(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta")
	access := questionAccess(database.ActorKindHuman)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	keyDrift := analyticCandidateCheckRequestForEntry(t, analyticCandidateFixtureEntry(t, "delta", 1, analytic.ProfileActive))
	hashDrift := analyticCandidateCheckRequestForEntry(t, analyticResolveRequestHashDriftEntry(t, "alpha", 1))
	if keyDrift.ProfileKey == candidates[0].profileKey {
		t.Fatalf("key-drift request = %+v shares the candidate key %+v", keyDrift, candidates[0].profileKey)
	}
	if hashDrift.ProfileKey != candidates[0].profileKey || hashDrift.ProfileHash == candidates[0].profileHash {
		t.Fatalf("hash-drift request = %+v want the candidate key %+v with another hash", hashDrift, candidates[0].profileKey)
	}

	for _, testCase := range []struct {
		name       string
		ctx        context.Context
		access     database.AccessContext
		candidates []analyticCandidate
		requests   []analyticsource.ResolveRequest
		useCheck   bool
	}{
		{"nil context", nil, access, candidates, requests, true},
		{"invalid access", ctx, database.AccessContext{}, candidates, requests, true},
		{"nil check", ctx, access, candidates, requests, false},
		{"candidates longer", ctx, access, candidates, requests[:1], true},
		{"requests longer", ctx, access, candidates[:1], requests, true},
		{"profile key mismatch", ctx, access, candidates, []analyticsource.ResolveRequest{keyDrift, requests[1]}, true},
		{"profile hash mismatch", ctx, access, candidates, []analyticsource.ResolveRequest{hashDrift, requests[1]}, true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(candidates))}
			var check analyticResolutionCheck
			if testCase.useCheck {
				check = recorder.check
			}

			accepted, err := checkAnalyticCandidateRequests(testCase.ctx, testCase.access, testCase.candidates, testCase.requests, check)
			assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeInvalid)
			if len(recorder.calls) != 0 {
				t.Fatalf("refusal made %d calls want none", len(recorder.calls))
			}
		})
	}
}

// TestCheckAnalyticCandidateRequestsRefusesLiveContextWithoutDeadline proves a
// live context carrying no Deadline is refused as invalid before any callback.
func TestCheckAnalyticCandidateRequestsRefusesLiveContextWithoutDeadline(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha")
	recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}

	accepted, err := checkAnalyticCandidateRequests(context.Background(), questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
	assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeInvalid)
	if len(recorder.calls) != 0 {
		t.Fatalf("refusal made %d calls want none", len(recorder.calls))
	}
}

// TestCheckAnalyticCandidateRequestsRefusesCanceledContexts proves a context
// that is already canceled, canceled during a call, or canceled once the next
// call is due returns CodeUnavailable with no accepted prefix and no later call.
func TestCheckAnalyticCandidateRequestsRefusesCanceledContexts(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta", "gamma")

	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		cancel()
		recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}

		accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
		assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeUnavailable)
		if len(recorder.calls) != 0 {
			t.Fatalf("canceled context made %d calls want none", len(recorder.calls))
		}
	})

	t.Run("canceled during a call", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}
		recorder.onCall = func(index int) {
			if index == 0 {
				cancel()
			}
		}

		accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
		assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeUnavailable)
		if len(recorder.calls) != 1 {
			t.Fatalf("calls = %d want exactly the one call the cancellation followed", len(recorder.calls))
		}
	})

	t.Run("canceled between calls", func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		ctx := &analyticCandidateCheckLateCancelContext{Context: parent}
		recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}
		recorder.onCall = func(index int) {
			if index == 0 {
				cancel()
				ctx.suppressErrOnce = true
			}
		}

		accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
		assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeUnavailable)
		if len(recorder.calls) != 1 {
			t.Fatalf("calls = %d want exactly the one call whose accepted prefix was discarded", len(recorder.calls))
		}
	})
}

// TestCheckAnalyticCandidateRequestsCallsOncePerAttemptWithoutConcurrency proves
// the run is strictly sequential and never retried: one callback per attempted
// request in input order, and never two callbacks active at once.
func TestCheckAnalyticCandidateRequestsCallsOncePerAttemptWithoutConcurrency(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta", "gamma", "delta")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}

	accepted, err := checkAnalyticCandidateRequests(ctx, questionAccess(database.ActorKindHuman), candidates, requests, recorder.check)
	if err != nil {
		t.Fatalf("check matched candidates: %v", err)
	}
	if len(accepted) != len(candidates) {
		t.Fatalf("accepted = %d want %d", len(accepted), len(candidates))
	}
	if len(recorder.calls) != len(requests) {
		t.Fatalf("calls = %d want exactly one per attempted request (%d)", len(recorder.calls), len(requests))
	}
	if recorder.maxActive != 1 {
		t.Fatalf("max overlapping callbacks = %d want 1", recorder.maxActive)
	}
	for index, call := range recorder.calls {
		if call.request != requests[index] {
			t.Fatalf("call %d request = %+v want %+v, so a call was retried or reordered", index, call.request, requests[index])
		}
	}
}

// TestCheckAnalyticCandidateRequestsReturnsDetachedCandidates proves the
// accepted slice shares no storage with the candidates argument: mutating it
// reaches neither the inputs nor a repeated call.
func TestCheckAnalyticCandidateRequestsReturnsDetachedCandidates(t *testing.T) {
	candidates, requests := analyticCandidateCheckFixture(t, "alpha", "beta")
	access := questionAccess(database.ActorKindHuman)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	heldCandidates := append([]analyticCandidate(nil), candidates...)
	heldRequests := append([]analyticsource.ResolveRequest(nil), requests...)
	recorder := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}

	first, err := checkAnalyticCandidateRequests(ctx, access, candidates, requests, recorder.check)
	if err != nil {
		t.Fatalf("check matched candidates: %v", err)
	}
	if len(first) != len(candidates) {
		t.Fatalf("accepted = %d want %d", len(first), len(candidates))
	}
	other := analyticCandidateFromEntry(analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive))
	first[0] = analyticCandidate{}
	first[1] = other

	if !reflect.DeepEqual(candidates, heldCandidates) {
		t.Fatalf("accepted mutation reached the candidates argument: %+v want %+v", candidates, heldCandidates)
	}
	if !reflect.DeepEqual(requests, heldRequests) {
		t.Fatalf("accepted mutation reached the requests argument: %+v want %+v", requests, heldRequests)
	}
	if &first[0] == &candidates[0] {
		t.Fatal("accepted slice reused the candidate argument storage")
	}

	repeated := &analyticCandidateCheckRecorder{results: analyticCandidateCheckValidResults(len(requests))}
	second, err := checkAnalyticCandidateRequests(ctx, access, candidates, requests, repeated.check)
	if err != nil {
		t.Fatalf("repeat matched candidates: %v", err)
	}
	if !reflect.DeepEqual(second, heldCandidates) {
		t.Fatalf("repeated call accepted = %+v want %+v", second, heldCandidates)
	}
	if &second[0] == &first[0] {
		t.Fatal("repeated call reused the mutated accepted storage")
	}
}

// analyticCandidateCheckFixture seals one ACTIVE profile per dataset at version
// 1 and binds every planned candidate through the production request builder, so
// each returned request names the exact profile key and hash of the candidate at
// the same index.
func analyticCandidateCheckFixture(t *testing.T, datasetIDs ...string) ([]analyticCandidate, []analyticsource.ResolveRequest) {
	t.Helper()
	entries := make([]analytic.CatalogEntryInput, 0, len(datasetIDs))
	for _, datasetID := range datasetIDs {
		entries = append(entries, analyticCandidateFixtureEntry(t, datasetID, 1, analytic.ProfileActive))
	}
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 200, entries)
	service := analyticCandidateFixtureService(t, catalog)
	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan candidate check fixture: %v", err)
	}
	requests := make([]analyticsource.ResolveRequest, 0, len(plan.candidates))
	for _, candidate := range plan.candidates {
		request, err := service.analyticResolveRequest("ws_operations", plan, candidate)
		if err != nil {
			t.Fatalf("bind candidate check fixture request: %v", err)
		}
		requests = append(requests, request)
	}
	return plan.candidates, requests
}

// analyticCandidateCheckRequestForEntry returns the exact production-built
// request that names one sealed profile, so a mismatch fixture pairs a real
// request with a candidate built from another sealed profile.
func analyticCandidateCheckRequestForEntry(t *testing.T, entry analytic.CatalogEntryInput) analyticsource.ResolveRequest {
	t.Helper()
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 201, []analytic.CatalogEntryInput{entry})
	service := analyticCandidateFixtureService(t, catalog)
	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan single-entry request fixture: %v", err)
	}
	request, err := service.analyticResolveRequest("ws_operations", plan, analyticCandidateFromEntry(entry))
	if err != nil {
		t.Fatalf("bind single-entry request fixture: %v", err)
	}
	return request
}

// analyticCandidateCheckResult is one scripted callback answer: the resolution
// it reports and the error it returns.
type analyticCandidateCheckResult struct {
	valid bool
	err   error
}

// analyticCandidateCheckCall records one callback invocation with the exact
// context, access context and request the helper forwarded.
type analyticCandidateCheckCall struct {
	ctx     context.Context
	access  database.AccessContext
	request analyticsource.ResolveRequest
}

// analyticCandidateCheckRecorder answers one scripted result per call, in call
// order, and records every invocation. It counts overlapping invocations, so a
// concurrently running callback would raise the recorded maximum above one, and
// it records every call, so a retry would appear as an extra entry. A call with
// no scripted result answers a valid resolution with a nil error, so an
// unexpected call shows up as an extra recorded call instead of silently
// stopping the helper at the broken-contract branch.
type analyticCandidateCheckRecorder struct {
	calls     []analyticCandidateCheckCall
	results   []analyticCandidateCheckResult
	active    int
	maxActive int
	// onCall runs inside the callback before it answers, so a test can cancel
	// the context of the call it observes.
	onCall func(index int)
}

// check records one invocation and answers the result scripted for its index.
func (recorder *analyticCandidateCheckRecorder) check(
	ctx context.Context,
	access database.AccessContext,
	request analyticsource.ResolveRequest,
) (bool, error) {
	index := len(recorder.calls)
	recorder.calls = append(recorder.calls, analyticCandidateCheckCall{ctx: ctx, access: access, request: request})
	recorder.active++
	if recorder.active > recorder.maxActive {
		recorder.maxActive = recorder.active
	}
	if recorder.onCall != nil {
		recorder.onCall(index)
	}
	result := analyticCandidateCheckResult{valid: true}
	if index < len(recorder.results) {
		result = recorder.results[index]
	}
	recorder.active--
	return result.valid, result.err
}

// analyticCandidateCheckValidResults scripts one valid, error-free answer for
// each of count calls.
func analyticCandidateCheckValidResults(count int) []analyticCandidateCheckResult {
	results := make([]analyticCandidateCheckResult, count)
	for index := range results {
		results[index] = analyticCandidateCheckResult{valid: true}
	}
	return results
}

// analyticCandidateCheckLateCancelContext is a live context with a deadline whose
// cancellation becomes observable one Err observation later. Arming it from
// inside one callback makes a cancellation land between two calls: the helper
// finishes the call and its post-call check as if the context were still live,
// then observes the failure on the next iteration's pre-call check.
type analyticCandidateCheckLateCancelContext struct {
	context.Context
	suppressErrOnce bool
}

// Err suppresses exactly one observation after the context was canceled.
func (ctx *analyticCandidateCheckLateCancelContext) Err() error {
	if ctx.suppressErrOnce {
		ctx.suppressErrOnce = false
		return nil
	}
	return ctx.Context.Err()
}

// assertAnalyticCandidateCheckRefusal proves one refusal returns the exact nil
// candidate slice plus the content-free error carrying only the wanted code.
func assertAnalyticCandidateCheckRefusal(t *testing.T, accepted []analyticCandidate, err error, code ErrorCode) {
	t.Helper()
	if accepted != nil {
		t.Fatalf("refused candidates = %+v want the exact nil slice", accepted)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != code || typed.cause != nil || typed.clarification != "" {
		t.Fatalf("refusal = %v, want content-free %s", err, code)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}
