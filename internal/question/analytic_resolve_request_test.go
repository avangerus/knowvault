package question

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestAnalyticResolveRequestBindsEachActiveVersion proves one accepted call
// returns exactly the six request fields for each ACTIVE catalog version: the
// workspace, the retained catalog identity, and the selected profile key and
// hash. The service is built by the production installer over the shared inert
// concrete store, which cannot serve a resolution, so an accepted call also
// proves the helper reads no database and calls no resolver I/O.
func TestAnalyticResolveRequestBindsEachActiveVersion(t *testing.T) {
	alphaV1 := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	alphaV2 := analyticCandidateFixtureEntry(t, "alpha", 2, analytic.ProfileActive)
	alphaV3 := analyticCandidateFixtureEntry(t, "alpha", 3, analytic.ProfileRetired)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 100,
		[]analytic.CatalogEntryInput{alphaV2, alphaV3, alphaV1})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}

	for _, entry := range []analytic.CatalogEntryInput{alphaV1, alphaV2} {
		request, err := service.analyticResolveRequest("ws_operations", plan, analyticCandidateFromEntry(entry))
		if err != nil {
			t.Fatalf("bind %q/%d: %v", entry.Profile.Key().DatasetID(), entry.Profile.Key().Version(), err)
		}
		want := analyticsource.ResolveRequest{
			WorkspaceID:     "ws_operations",
			CatalogID:       catalog.ID(),
			CatalogRevision: catalog.Revision(),
			CatalogHash:     catalog.Hash(),
			ProfileKey:      entry.Profile.Key(),
			ProfileHash:     entry.Profile.Hash(),
		}
		if request != want {
			t.Fatalf("request = %+v want %+v", request, want)
		}
	}
}

// TestAnalyticResolveRequestAcceptsCompletePlanMadeUnderLowerBudget proves the
// generating limit is not part of a plan: a complete plan built with a
// sufficient lower budget still matches the recomputation at the sealed
// maximum.
func TestAnalyticResolveRequestAcceptsCompletePlanMadeUnderLowerBudget(t *testing.T) {
	active := []analytic.CatalogEntryInput{
		analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive),
		analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive),
		analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive),
	}
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 101, active)
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(len(active))
	if err != nil {
		t.Fatalf("plan at the exact active count: %v", err)
	}
	request, err := service.analyticResolveRequest("ws_operations", plan, analyticCandidateFromEntry(active[2]))
	if err != nil {
		t.Fatalf("bind candidate from a lower-budget plan: %v", err)
	}
	if request.CatalogRevision != catalog.Revision() || request.ProfileKey != active[2].Profile.Key() ||
		request.ProfileHash != active[2].Profile.Hash() {
		t.Fatalf("request = %+v want catalog revision %d and profile %+v/%q", request, catalog.Revision(),
			active[2].Profile.Key(), active[2].Profile.Hash())
	}
}

// TestAnalyticResolveRequestRefusesInvalidWorkspaceID proves the helper applies
// validOpaque unchanged: an empty, padded, whitespace-bearing, punctuated or
// oversized workspace ID refuses with no trimming or normalization.
func TestAnalyticResolveRequestRefusesInvalidWorkspaceID(t *testing.T) {
	active := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 102,
		[]analytic.CatalogEntryInput{active}))

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	candidate := analyticCandidateFromEntry(active)

	for _, testCase := range []struct {
		name        string
		workspaceID string
	}{
		{"empty", ""},
		{"leading pad", " ws_operations"},
		{"trailing pad", "ws_operations "},
		{"inner space", "ws operations"},
		{"punctuation", "ws/operations"},
		{"oversized", strings.Repeat("a", 129)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := service.analyticResolveRequest(testCase.workspaceID, plan, candidate)
			assertAnalyticResolveRequestRefusal(t, request, err)
		})
	}
}

// TestAnalyticResolveRequestRefusesNilAbsentAndPartialServices proves the
// helper refuses a nil receiver, an absent analytic mount, and each invalid
// one-slot retained state instead of panicking or repairing the pair.
func TestAnalyticResolveRequestRefusesNilAbsentAndPartialServices(t *testing.T) {
	active := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 103, []analytic.CatalogEntryInput{active})
	candidate := analyticCandidateFromEntry(active)

	t.Run("nil service", func(t *testing.T) {
		var service *Service

		request, err := service.analyticResolveRequest("ws_operations", analyticCandidatePlan{}, candidate)
		assertAnalyticResolveRequestRefusal(t, request, err)
	})

	t.Run("absent mount", func(t *testing.T) {
		service := &Service{}

		request, err := service.analyticResolveRequest("ws_operations", analyticCandidatePlan{}, candidate)
		assertAnalyticResolveRequestRefusal(t, request, err)
	})

	t.Run("catalog only", func(t *testing.T) {
		service := &Service{datasetProfileCatalog: catalog}

		request, err := service.analyticResolveRequest("ws_operations", analyticCandidatePlan{}, candidate)
		assertAnalyticResolveRequestRefusal(t, request, err)
	})

	t.Run("resolver only", func(t *testing.T) {
		resolver, err := analyticsource.NewResolver(&workspacerepository.Store{}, catalog)
		if err != nil {
			t.Fatalf("build held resolver: %v", err)
		}
		service := &Service{analyticSourceResolver: resolver}

		request, refuseErr := service.analyticResolveRequest("ws_operations", analyticCandidatePlan{}, candidate)
		assertAnalyticResolveRequestRefusal(t, request, refuseErr)
	})
}

// TestAnalyticResolveRequestRefusesAllRetiredSelection proves an installed
// all-RETIRED catalog is not the absent capability: its plan is installed and
// comparable, but it holds no selectable member, so a candidate built from the
// retired entry refuses.
func TestAnalyticResolveRequestRefusesAllRetiredSelection(t *testing.T) {
	retired := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 104, []analytic.CatalogEntryInput{retired})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan all-retired catalog: %v", err)
	}
	request, refuseErr := service.analyticResolveRequest("ws_operations", plan, analyticCandidateFromEntry(retired))
	assertAnalyticResolveRequestRefusal(t, request, refuseErr)
}

// TestAnalyticResolveRequestRefusesCatalogIdentityDrift proves a plan whose
// catalog ID, revision or hash differs from the retained catalog refuses, as
// does a stale plan produced by another service over a different catalog
// revision.
func TestAnalyticResolveRequestRefusesCatalogIdentityDrift(t *testing.T) {
	active := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 105,
		[]analytic.CatalogEntryInput{active}))

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	candidate := analyticCandidateFromEntry(active)

	for _, testCase := range []struct {
		name   string
		mutate func(*analyticCandidatePlan)
	}{
		{"catalog id drift", func(altered *analyticCandidatePlan) { altered.catalogID = "catalog.other" }},
		{"catalog revision drift", func(altered *analyticCandidatePlan) { altered.catalogRevision++ }},
		{"catalog hash drift", func(altered *analyticCandidatePlan) {
			altered.catalogHash = "sha256:" + strings.Repeat("f", 64)
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			altered := analyticResolveRequestPlanSnapshot(plan)
			testCase.mutate(&altered)

			request, err := service.analyticResolveRequest("ws_operations", altered, candidate)
			assertAnalyticResolveRequestRefusal(t, request, err)
		})
	}

	t.Run("stale plan from another service", func(t *testing.T) {
		other := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 106,
			[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)}))
		stale, err := other.planAnalyticCandidates(maxAnalyticCandidateLimit)
		if err != nil {
			t.Fatalf("plan second service: %v", err)
		}

		request, refuseErr := service.analyticResolveRequest("ws_operations", stale, candidate)
		assertAnalyticResolveRequestRefusal(t, request, refuseErr)
	})
}

// TestAnalyticResolveRequestRefusesPlanMemberDrift proves a plan that is not
// exactly the retained plan refuses when a member is removed, added,
// duplicated, reordered, or has its key or hash mutated.
func TestAnalyticResolveRequestRefusesPlanMemberDrift(t *testing.T) {
	alpha := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	beta := analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive)
	gamma := analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive)
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 107,
		[]analytic.CatalogEntryInput{alpha, beta, gamma}))

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	if len(plan.candidates) != 3 {
		t.Fatalf("retained candidates = %d want 3", len(plan.candidates))
	}
	candidate := analyticCandidateFromEntry(alpha)

	for _, testCase := range []struct {
		name   string
		mutate func(*analyticCandidatePlan)
	}{
		{"member removed", func(altered *analyticCandidatePlan) { altered.candidates = altered.candidates[:2] }},
		{"all members removed", func(altered *analyticCandidatePlan) { altered.candidates = nil }},
		{"member added", func(altered *analyticCandidatePlan) {
			added := analyticCandidateFromEntry(analyticCandidateFixtureEntry(t, "delta", 1, analytic.ProfileActive))
			altered.candidates = append(altered.candidates, added)
		}},
		{"member duplicated", func(altered *analyticCandidatePlan) {
			altered.candidates = append(altered.candidates, altered.candidates[0])
		}},
		{"members reordered", func(altered *analyticCandidatePlan) {
			altered.candidates[0], altered.candidates[1] = altered.candidates[1], altered.candidates[0]
		}},
		{"member key mutated", func(altered *analyticCandidatePlan) {
			altered.candidates[1].profileKey = altered.candidates[0].profileKey
		}},
		{"member hash mutated", func(altered *analyticCandidatePlan) {
			altered.candidates[1].profileHash = altered.candidates[0].profileHash
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			altered := analyticResolveRequestPlanSnapshot(plan)
			testCase.mutate(&altered)

			request, err := service.analyticResolveRequest("ws_operations", altered, candidate)
			assertAnalyticResolveRequestRefusal(t, request, err)
		})
	}
}

// TestAnalyticResolveRequestRefusesCandidateDrift proves the selected candidate
// must occur in the retained plan: a zero candidate, a different version of the
// same dataset, a dataset outside the plan, a different hash for the retained
// key, and a RETIRED member all refuse.
func TestAnalyticResolveRequestRefusesCandidateDrift(t *testing.T) {
	alpha := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	retired := analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileRetired)
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 108,
		[]analytic.CatalogEntryInput{alpha, retired}))

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	versionDrift := analyticCandidateFixtureEntry(t, "alpha", 2, analytic.ProfileActive)
	keyDrift := analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive)
	hashDrift := analyticResolveRequestHashDriftEntry(t, "alpha", 1)
	if hashDrift.Profile.Hash() == alpha.Profile.Hash() {
		t.Fatalf("hash-drift fixture carries the retained profile hash %q", alpha.Profile.Hash())
	}

	for _, testCase := range []struct {
		name      string
		candidate analyticCandidate
	}{
		{"zero candidate", analyticCandidate{}},
		{"version drift", analyticCandidateFromEntry(versionDrift)},
		{"key drift", analyticCandidateFromEntry(keyDrift)},
		{"hash drift", analyticCandidateFromEntry(hashDrift)},
		{"retired member", analyticCandidateFromEntry(retired)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			request, err := service.analyticResolveRequest("ws_operations", plan, testCase.candidate)
			assertAnalyticResolveRequestRefusal(t, request, err)
		})
	}
}

// TestAnalyticResolveRequestPreservesServiceAndInputs proves neither an
// accepted nor a refused call changes the two installed slots, the supplied
// plan, or the supplied plan's candidate slice.
func TestAnalyticResolveRequestPreservesServiceAndInputs(t *testing.T) {
	alpha := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	beta := analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 109,
		[]analytic.CatalogEntryInput{alpha, beta})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	heldCatalog := service.datasetProfileCatalog
	heldResolver := service.analyticSourceResolver
	heldPlan := analyticResolveRequestPlanSnapshot(plan)

	if _, err := service.analyticResolveRequest("ws_operations", plan, analyticCandidateFromEntry(alpha)); err != nil {
		t.Fatalf("accepted call refused: %v", err)
	}
	assertAnalyticResolveRequestStateIntact(t, service, heldCatalog, heldResolver, plan, heldPlan)

	request, refuseErr := service.analyticResolveRequest("ws_operations", plan, analyticCandidate{})
	assertAnalyticResolveRequestRefusal(t, request, refuseErr)
	assertAnalyticResolveRequestStateIntact(t, service, heldCatalog, heldResolver, plan, heldPlan)
}

// TestAnalyticResolveRequestReturnsDetachedRequest proves the returned request
// shares no storage with the service, the plan or the candidate: mutating every
// field of the returned value cannot change the request a later call rebuilds.
func TestAnalyticResolveRequestReturnsDetachedRequest(t *testing.T) {
	alpha := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 110, []analytic.CatalogEntryInput{alpha})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	candidate := analyticCandidateFromEntry(alpha)

	first, err := service.analyticResolveRequest("ws_operations", plan, candidate)
	if err != nil {
		t.Fatalf("bind selected candidate: %v", err)
	}
	driftedKey, err := analytic.NewProfileKey("delta", 9)
	if err != nil {
		t.Fatalf("build drifted profile key: %v", err)
	}
	first.WorkspaceID = "ws_other"
	first.CatalogID = "catalog.other"
	first.CatalogRevision++
	first.CatalogHash = "sha256:" + strings.Repeat("0", 64)
	first.ProfileKey = driftedKey
	first.ProfileHash = "sha256:" + strings.Repeat("0", 64)

	second, err := service.analyticResolveRequest("ws_operations", plan, candidate)
	if err != nil {
		t.Fatalf("rebind selected candidate: %v", err)
	}
	want := analyticsource.ResolveRequest{
		WorkspaceID:     "ws_operations",
		CatalogID:       catalog.ID(),
		CatalogRevision: catalog.Revision(),
		CatalogHash:     catalog.Hash(),
		ProfileKey:      alpha.Profile.Key(),
		ProfileHash:     alpha.Profile.Hash(),
	}
	if second != want {
		t.Fatalf("rebuilt request = %+v want %+v", second, want)
	}
}

// analyticResolveRequestPlanSnapshot returns a detached copy of one plan, so a
// test can detect in-place mutation of the caller's candidate slice. A nil
// candidate slice stays nil and a non-nil empty slice stays non-nil, because
// the plan comparison treats those as different values.
func analyticResolveRequestPlanSnapshot(plan analyticCandidatePlan) analyticCandidatePlan {
	held := plan
	if plan.candidates == nil {
		return held
	}
	held.candidates = append([]analyticCandidate{}, plan.candidates...)
	return held
}

// analyticResolveRequestHashDriftEntry seals one valid profile under the given
// key with a coverage policy the shared candidate fixture does not use, so the
// returned entry carries a different hash for the same profile key.
func analyticResolveRequestHashDriftEntry(t *testing.T, datasetID string, version int64) analytic.CatalogEntryInput {
	t.Helper()
	key, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatalf("build hash-drift profile key %q/%d: %v", datasetID, version, err)
	}
	spec := newProjectionFixtureProfile(t).Spec()
	spec.Key = key
	spec.Coverage = analytic.CoverageSourceGuaranteed
	profile, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("seal hash-drift profile %q/%d: %v", datasetID, version, err)
	}
	return analytic.CatalogEntryInput{Profile: profile, State: analytic.ProfileActive}
}

// assertAnalyticResolveRequestRefusal proves one refusal returns the exact zero
// request plus the content-free CodeInvalid error, whose unwrap chain is empty.
func assertAnalyticResolveRequestRefusal(t *testing.T, request analyticsource.ResolveRequest, err error) {
	t.Helper()
	if !reflect.DeepEqual(request, analyticsource.ResolveRequest{}) {
		t.Fatalf("refused request = %+v want the exact zero value", request)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}

// assertAnalyticResolveRequestStateIntact proves the two installed slots and
// the supplied plan still hold exactly the values captured before the call.
func assertAnalyticResolveRequestStateIntact(
	t *testing.T,
	service *Service,
	catalog analytic.DatasetProfileCatalog,
	resolver *analyticsource.Resolver,
	plan analyticCandidatePlan,
	heldPlan analyticCandidatePlan,
) {
	t.Helper()
	if !reflect.DeepEqual(service.datasetProfileCatalog, catalog) {
		t.Fatalf("service catalog changed: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision(), catalog.ID(), catalog.Revision())
	}
	if service.analyticSourceResolver != resolver {
		t.Fatalf("service resolver changed: %p want %p", service.analyticSourceResolver, resolver)
	}
	if !reflect.DeepEqual(plan, heldPlan) {
		t.Fatalf("supplied plan changed: %+v want %+v", plan, heldPlan)
	}
}
