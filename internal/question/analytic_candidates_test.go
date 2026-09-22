package question

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestPlanAnalyticCandidatesDescribesInstalledCatalog proves a valid installed
// pair returns the exact retained catalog identity together with the exact
// ACTIVE profile key and hash.
func TestPlanAnalyticCandidatesDescribesInstalledCatalog(t *testing.T) {
	active := analyticCandidateFixtureEntry(t, "orders", 3, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 11, []analytic.CatalogEntryInput{active})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(1)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	if plan.catalogID != catalog.ID() || plan.catalogRevision != catalog.Revision() || plan.catalogHash != catalog.Hash() {
		t.Fatalf("plan identity = %q/%d/%q want %q/%d/%q", plan.catalogID, plan.catalogRevision, plan.catalogHash,
			catalog.ID(), catalog.Revision(), catalog.Hash())
	}
	want := []analyticCandidate{analyticCandidateFromEntry(active)}
	if !reflect.DeepEqual(plan.candidates, want) {
		t.Fatalf("candidates = %+v want %+v", plan.candidates, want)
	}
	if candidate := plan.candidates[0]; candidate.profileKey != active.Profile.Key() || candidate.profileHash != active.Profile.Hash() {
		t.Fatalf("candidate = %+v want key %+v hash %q", candidate, active.Profile.Key(), active.Profile.Hash())
	}
}

// TestPlanAnalyticCandidatesKeepsOnlyActiveEntriesInCanonicalOrder proves the
// plan drops every RETIRED entry and follows the catalog's canonical key order,
// whatever state mix and input order the constructor received.
func TestPlanAnalyticCandidatesKeepsOnlyActiveEntriesInCanonicalOrder(t *testing.T) {
	zetaV1 := analyticCandidateFixtureEntry(t, "zeta", 1, analytic.ProfileActive)
	alphaV2 := analyticCandidateFixtureEntry(t, "alpha", 2, analytic.ProfileRetired)
	alphaV1 := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	betaV5 := analyticCandidateFixtureEntry(t, "beta", 5, analytic.ProfileActive)
	betaV4 := analyticCandidateFixtureEntry(t, "beta", 4, analytic.ProfileRetired)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 12,
		[]analytic.CatalogEntryInput{zetaV1, alphaV2, alphaV1, betaV5, betaV4})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(3)
	if err != nil {
		t.Fatalf("plan mixed-state catalog: %v", err)
	}
	want := []analyticCandidate{
		analyticCandidateFromEntry(alphaV1),
		analyticCandidateFromEntry(betaV5),
		analyticCandidateFromEntry(zetaV1),
	}
	if !reflect.DeepEqual(plan.candidates, want) {
		t.Fatalf("candidates = %+v want %+v", plan.candidates, want)
	}
}

// TestPlanAnalyticCandidatesKeepsEveryActiveVersionOfOneDataset proves the plan
// never collapses a dataset to one entry: two ACTIVE versions of the same dataset
// are both retained in canonical version order, with no latest-version choice,
// dataset-level deduplication, or ranking.
func TestPlanAnalyticCandidatesKeepsEveryActiveVersionOfOneDataset(t *testing.T) {
	alphaV2 := analyticCandidateFixtureEntry(t, "alpha", 2, analytic.ProfileActive)
	alphaV3 := analyticCandidateFixtureEntry(t, "alpha", 3, analytic.ProfileRetired)
	alphaV1 := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 13,
		[]analytic.CatalogEntryInput{alphaV2, alphaV3, alphaV1})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(2)
	if err != nil {
		t.Fatalf("plan two active versions of one dataset: %v", err)
	}
	want := []analyticCandidate{
		analyticCandidateFromEntry(alphaV1),
		analyticCandidateFromEntry(alphaV2),
	}
	if !reflect.DeepEqual(plan.candidates, want) {
		t.Fatalf("candidates = %+v want both active versions in canonical order %+v", plan.candidates, want)
	}
}

// TestPlanAnalyticCandidatesSucceedsAtLimitAndRefusesBeyondIt proves the budget
// is exact: a catalog with exactly limit ACTIVE entries succeeds, and one more
// ACTIVE entry than limit refuses the entire plan without a truncated prefix,
// including at the sealed catalog maximum.
func TestPlanAnalyticCandidatesSucceedsAtLimitAndRefusesBeyondIt(t *testing.T) {
	t.Run("three active entries", func(t *testing.T) {
		entries := []analytic.CatalogEntryInput{
			analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive),
			analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive),
			analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive),
		}
		service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 20, entries))

		plan, err := service.planAnalyticCandidates(len(entries))
		if err != nil {
			t.Fatalf("plan exactly limit candidates: %v", err)
		}
		if len(plan.candidates) != len(entries) {
			t.Fatalf("candidates = %d want exactly the %d active entries", len(plan.candidates), len(entries))
		}
		refused, refuseErr := service.planAnalyticCandidates(len(entries) - 1)
		assertAnalyticCandidateRefusal(t, refused, refuseErr)
	})

	t.Run("sealed catalog maximum", func(t *testing.T) {
		entries := make([]analytic.CatalogEntryInput, 0, maxAnalyticCandidateLimit)
		for index := 0; index < maxAnalyticCandidateLimit; index++ {
			entries = append(entries, analyticCandidateFixtureEntry(t, fmt.Sprintf("dataset_%02d", index), 1, analytic.ProfileActive))
		}
		service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 21, entries))

		plan, err := service.planAnalyticCandidates(maxAnalyticCandidateLimit)
		if err != nil {
			t.Fatalf("plan the sealed catalog maximum: %v", err)
		}
		if len(plan.candidates) != maxAnalyticCandidateLimit {
			t.Fatalf("candidates = %d want %d", len(plan.candidates), maxAnalyticCandidateLimit)
		}
		refused, refuseErr := service.planAnalyticCandidates(maxAnalyticCandidateLimit - 1)
		assertAnalyticCandidateRefusal(t, refused, refuseErr)
	})
}

// TestPlanAnalyticCandidatesRefusesLimitsOutsideBudget proves the server-owned
// budget fails closed for a zero, negative, or oversized limit even on a valid
// installed pair.
func TestPlanAnalyticCandidatesRefusesLimitsOutsideBudget(t *testing.T) {
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 30,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "orders", 1, analytic.ProfileActive)}))

	for _, limit := range []int{0, -1, maxAnalyticCandidateLimit + 1} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			plan, err := service.planAnalyticCandidates(limit)
			assertAnalyticCandidateRefusal(t, plan, err)
		})
	}
}

// TestPlanAnalyticCandidatesRefusesNilService proves a nil receiver is a
// content-free refusal rather than a panic.
func TestPlanAnalyticCandidatesRefusesNilService(t *testing.T) {
	var service *Service

	plan, err := service.planAnalyticCandidates(1)
	assertAnalyticCandidateRefusal(t, plan, err)
}

// TestPlanAnalyticCandidatesAbsentCapabilityReturnsZeroPlan proves the exact
// empty pair means the optional analytic capability is absent: the exact zero
// plan and a nil error, not a refusal.
func TestPlanAnalyticCandidatesAbsentCapabilityReturnsZeroPlan(t *testing.T) {
	plan, err := (&Service{}).planAnalyticCandidates(1)
	if err != nil {
		t.Fatalf("absent analytic capability refused: %v", err)
	}
	if !reflect.DeepEqual(plan, analyticCandidatePlan{}) {
		t.Fatalf("absent capability plan = %+v want the exact zero value", plan)
	}
}

// TestPlanAnalyticCandidatesRefusesPartialPairsAndPreservesSlots proves an
// inconsistent retained pair is never repaired: one occupied slot refuses
// content-free and both slots stay exactly as they were.
func TestPlanAnalyticCandidatesRefusesPartialPairsAndPreservesSlots(t *testing.T) {
	t.Run("catalog only", func(t *testing.T) {
		catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 40,
			[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "orders", 1, analytic.ProfileActive)})
		service := &Service{datasetProfileCatalog: catalog}

		plan, err := service.planAnalyticCandidates(1)
		assertAnalyticCandidateRefusal(t, plan, err)
		if !reflect.DeepEqual(service.datasetProfileCatalog, catalog) {
			t.Fatalf("refusal changed the catalog slot: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision(), catalog.ID(), catalog.Revision())
		}
		if service.analyticSourceResolver != nil {
			t.Fatalf("refusal completed the pair: resolver = %p", service.analyticSourceResolver)
		}
	})

	t.Run("resolver only", func(t *testing.T) {
		catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 41,
			[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "orders", 1, analytic.ProfileActive)})
		resolver, err := analyticsource.NewResolver(&workspacerepository.Store{}, catalog)
		if err != nil {
			t.Fatalf("build held resolver: %v", err)
		}
		service := &Service{analyticSourceResolver: resolver}

		plan, refuseErr := service.planAnalyticCandidates(1)
		assertAnalyticCandidateRefusal(t, plan, refuseErr)
		if service.analyticSourceResolver != resolver {
			t.Fatalf("refusal changed the resolver slot: %p want %p", service.analyticSourceResolver, resolver)
		}
		if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
			t.Fatalf("refusal completed the pair: catalog = %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision())
		}
	})
}

// TestPlanAnalyticCandidatesAllRetiredCatalogReturnsEmptySlice proves an
// installed valid catalog stays distinguishable from an absent capability: an
// all-RETIRED catalog succeeds with its catalog identity and a non-nil,
// zero-length candidate slice.
func TestPlanAnalyticCandidatesAllRetiredCatalogReturnsEmptySlice(t *testing.T) {
	retired := analyticCandidateFixtureEntry(t, "orders", 1, analytic.ProfileRetired)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 50, []analytic.CatalogEntryInput{retired})
	service := analyticCandidateFixtureService(t, catalog)

	plan, err := service.planAnalyticCandidates(1)
	if err != nil {
		t.Fatalf("plan all-retired catalog: %v", err)
	}
	if plan.catalogID != catalog.ID() || plan.catalogRevision != catalog.Revision() || plan.catalogHash != catalog.Hash() {
		t.Fatalf("plan identity = %q/%d/%q want %q/%d/%q", plan.catalogID, plan.catalogRevision, plan.catalogHash,
			catalog.ID(), catalog.Revision(), catalog.Hash())
	}
	if plan.candidates == nil {
		t.Fatal("all-retired plan carries a nil candidate slice")
	}
	if len(plan.candidates) != 0 {
		t.Fatalf("all-retired candidates = %+v want none", plan.candidates)
	}
	absent, err := (&Service{}).planAnalyticCandidates(1)
	if err != nil {
		t.Fatalf("absent analytic capability refused: %v", err)
	}
	if reflect.DeepEqual(plan, absent) {
		t.Fatal("all-retired plan equals the absent-capability plan")
	}
}

// TestPlanAnalyticCandidatesReturnsDetachedCandidates proves mutating a returned
// candidate slice reaches neither the installed catalog nor the next plan.
func TestPlanAnalyticCandidatesReturnsDetachedCandidates(t *testing.T) {
	active := analyticCandidateFixtureEntry(t, "orders", 2, analytic.ProfileActive)
	other := analyticCandidateFixtureEntry(t, "invoices", 1, analytic.ProfileActive)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 60,
		[]analytic.CatalogEntryInput{active, other})
	service := analyticCandidateFixtureService(t, catalog)

	first, err := service.planAnalyticCandidates(2)
	if err != nil {
		t.Fatalf("plan installed catalog: %v", err)
	}
	held := append([]analyticCandidate(nil), first.candidates...)
	first.candidates[0] = analyticCandidate{}
	first.candidates[1] = analyticCandidate{profileKey: active.Profile.Key(), profileHash: active.Profile.Hash()}

	second, err := service.planAnalyticCandidates(2)
	if err != nil {
		t.Fatalf("re-plan installed catalog: %v", err)
	}
	if !reflect.DeepEqual(second.candidates, held) {
		t.Fatalf("re-plan candidates = %+v want %+v", second.candidates, held)
	}
	if &first.candidates[0] == &second.candidates[0] {
		t.Fatal("re-plan reused the mutated candidate storage")
	}
	if !reflect.DeepEqual(service.datasetProfileCatalog.Entries(), catalog.Entries()) {
		t.Fatal("candidate mutation reached the installed catalog entries")
	}
}

// analyticCandidateFixtureEntry seals one valid profile for a dataset version
// through the public analytic constructors and pairs it with a catalog state.
// The shared projection fixture supplies the profile body; only the sealed key
// varies, so every entry stays a real sealed profile.
func analyticCandidateFixtureEntry(t *testing.T, datasetID string, version int64, state analytic.ProfileState) analytic.CatalogEntryInput {
	t.Helper()
	key, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatalf("build candidate profile key %q/%d: %v", datasetID, version, err)
	}
	spec := newProjectionFixtureProfile(t).Spec()
	spec.Key = key
	profile, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("seal candidate profile %q/%d: %v", datasetID, version, err)
	}
	return analytic.CatalogEntryInput{Profile: profile, State: state}
}

// analyticCandidateFixtureCatalog seals one immutable catalog over the given
// entries.
func analyticCandidateFixtureCatalog(t *testing.T, catalogID string, revision int64, entries []analytic.CatalogEntryInput) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog(catalogID, revision, entries)
	if err != nil {
		t.Fatalf("build candidate catalog %q/%d: %v", catalogID, revision, err)
	}
	return catalog
}

// analyticCandidateFixtureService installs one valid catalog/resolver pair
// through the production one-shot install.
func analyticCandidateFixtureService(t *testing.T, catalog analytic.DatasetProfileCatalog) *Service {
	t.Helper()
	service := &Service{}
	if err := service.EnableDatasetProfileCatalog(catalog, &workspacerepository.Store{}); err != nil {
		t.Fatalf("install candidate catalog: %v", err)
	}
	return service
}

// analyticCandidateFromEntry returns the candidate a plan must carry for one
// catalog entry.
func analyticCandidateFromEntry(entry analytic.CatalogEntryInput) analyticCandidate {
	return analyticCandidate{profileKey: entry.Profile.Key(), profileHash: entry.Profile.Hash()}
}

// assertAnalyticCandidateRefusal proves one refusal is the exact zero plan plus
// the content-free CodeInvalid error, whose unwrap chain is empty.
func assertAnalyticCandidateRefusal(t *testing.T, plan analyticCandidatePlan, err error) {
	t.Helper()
	if !reflect.DeepEqual(plan, analyticCandidatePlan{}) {
		t.Fatalf("refused plan = %+v want the exact zero value", plan)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}
