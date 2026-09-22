package question

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/platform/database"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestCheckAnalyticCandidatesRefusesInvalidArguments proves a nil receiver, a
// nil context, an access context that fails Validate, and every invalid
// workspace ID shape are the same content-free CodeInvalid refusal, before any
// slot is read or any resolver runs.
func TestCheckAnalyticCandidatesRefusesInvalidArguments(t *testing.T) {
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 300,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	access := questionAccess(database.ActorKindHuman)

	for _, testCase := range []struct {
		name        string
		service     *Service
		ctx         context.Context
		access      database.AccessContext
		workspaceID string
	}{
		{"nil service", nil, ctx, access, "ws_operations"},
		{"nil context", service, nil, access, "ws_operations"},
		{"invalid access", service, ctx, database.AccessContext{}, "ws_operations"},
		{"empty workspace", service, ctx, access, ""},
		{"padded workspace", service, ctx, access, " ws_operations"},
		{"punctuated workspace", service, ctx, access, "ws/operations"},
		{"oversized workspace", service, ctx, access, strings.Repeat("a", 129)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			accepted, err := testCase.service.checkAnalyticCandidates(testCase.ctx, testCase.access, testCase.workspaceID)
			assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeInvalid)
		})
	}
}

// TestCheckAnalyticCandidatesRefusesFailedContexts proves an already canceled or
// expired context is CodeUnavailable even beside an installed catalog and even
// beside the absent capability, so the refusal precedes the plan and the
// capability fast path.
func TestCheckAnalyticCandidatesRefusesFailedContexts(t *testing.T) {
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 301,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)}))
	access := questionAccess(database.ActorKindHuman)
	canceled, cancel := context.WithTimeout(context.Background(), time.Minute)
	cancel()
	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Minute))
	defer expire()
	if expired.Err() == nil {
		t.Fatal("expired fixture context is still live")
	}

	for _, testCase := range []struct {
		name    string
		service *Service
		ctx     context.Context
	}{
		{"canceled with mounted catalog", service, canceled},
		{"expired with mounted catalog", service, expired},
		{"canceled with absent mount", &Service{}, canceled},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			accepted, err := testCase.service.checkAnalyticCandidates(testCase.ctx, access, "ws_operations")
			assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeUnavailable)
		})
	}
}

// TestCheckAnalyticCandidatesAbsentMountReturnsNil proves the absent analytic
// capability is not a refusal: a live context without a Deadline returns the
// exact nil candidate slice and a nil error, with no resolver and no Deadline
// requirement.
func TestCheckAnalyticCandidatesAbsentMountReturnsNil(t *testing.T) {
	accepted, err := (&Service{}).checkAnalyticCandidates(context.Background(),
		questionAccess(database.ActorKindHuman), "ws_operations")
	if err != nil {
		t.Fatalf("absent analytic mount refused: %v", err)
	}
	if accepted != nil {
		t.Fatalf("absent analytic mount accepted = %+v want the exact nil slice", accepted)
	}
}

// TestCheckAnalyticCandidatesAllRetiredCatalogReturnsNonNilEmpty proves an
// installed catalog whose entries are all RETIRED succeeds with a non-nil,
// zero-length accepted slice and a nil error, without requiring a Deadline and
// without changing either installed slot.
func TestCheckAnalyticCandidatesAllRetiredCatalogReturnsNonNilEmpty(t *testing.T) {
	retired := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 302, []analytic.CatalogEntryInput{retired})
	service := analyticCandidateFixtureService(t, catalog)
	heldCatalog := service.datasetProfileCatalog
	heldResolver := service.analyticSourceResolver

	accepted, err := service.checkAnalyticCandidates(context.Background(),
		questionAccess(database.ActorKindHuman), "ws_operations")
	if err != nil {
		t.Fatalf("all-RETIRED catalog refused: %v", err)
	}
	if accepted == nil {
		t.Fatal("all-RETIRED catalog accepted a nil slice, which is the absent-capability result")
	}
	if len(accepted) != 0 {
		t.Fatalf("all-RETIRED catalog accepted = %+v want none", accepted)
	}
	assertAnalyticCandidateCheckSlotsIntact(t, service, heldCatalog, heldResolver)
}

// TestCheckAnalyticCandidatesKeepsInstalledEmptyApartFromAbsentCapability proves
// the two empty outcomes stay distinct: the installed all-RETIRED catalog
// returns a non-nil empty slice while the absent capability returns the exact
// nil slice, both with a nil error and neither requiring a Deadline.
func TestCheckAnalyticCandidatesKeepsInstalledEmptyApartFromAbsentCapability(t *testing.T) {
	retired := analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileRetired)
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 303,
		[]analytic.CatalogEntryInput{retired}))
	access := questionAccess(database.ActorKindHuman)

	installed, err := service.checkAnalyticCandidates(context.Background(), access, "ws_operations")
	if err != nil {
		t.Fatalf("installed all-RETIRED catalog refused: %v", err)
	}
	absent, err := (&Service{}).checkAnalyticCandidates(context.Background(), access, "ws_operations")
	if err != nil {
		t.Fatalf("absent analytic mount refused: %v", err)
	}
	if installed == nil {
		t.Fatal("installed all-RETIRED catalog returned the absent-capability nil slice")
	}
	if len(installed) != 0 {
		t.Fatalf("installed all-RETIRED catalog accepted = %+v want none", installed)
	}
	if absent != nil {
		t.Fatalf("absent analytic mount accepted = %+v want the exact nil slice", absent)
	}
}

// TestCheckAnalyticCandidatesRefusesPartialSlots proves neither inconsistent
// retained pair is repaired: a catalog-only and a resolver-only Service both
// refuse content-free and keep the slots exactly as they were.
func TestCheckAnalyticCandidatesRefusesPartialSlots(t *testing.T) {
	catalog := analyticCandidateFixtureCatalog(t, "catalog.operations", 304,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)})
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	access := questionAccess(database.ActorKindHuman)

	t.Run("catalog only", func(t *testing.T) {
		service := &Service{datasetProfileCatalog: catalog}

		accepted, err := service.checkAnalyticCandidates(ctx, access, "ws_operations")
		assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeInvalid)
		if !reflect.DeepEqual(service.datasetProfileCatalog, catalog) {
			t.Fatalf("refusal changed the catalog slot: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision(), catalog.ID(), catalog.Revision())
		}
		if service.analyticSourceResolver != nil {
			t.Fatalf("refusal completed the pair: resolver = %p", service.analyticSourceResolver)
		}
	})

	t.Run("resolver only", func(t *testing.T) {
		resolver, err := analyticsource.NewResolver(&workspacerepository.Store{}, catalog)
		if err != nil {
			t.Fatalf("build held resolver: %v", err)
		}
		service := &Service{analyticSourceResolver: resolver}

		accepted, refuseErr := service.checkAnalyticCandidates(ctx, access, "ws_operations")
		assertAnalyticCandidateCheckRefusal(t, accepted, refuseErr, CodeInvalid)
		if service.analyticSourceResolver != resolver {
			t.Fatalf("refusal changed the resolver slot: %p want %p", service.analyticSourceResolver, resolver)
		}
		if !reflect.DeepEqual(service.datasetProfileCatalog, analytic.DatasetProfileCatalog{}) {
			t.Fatalf("refusal completed the pair: catalog = %q/%d", service.datasetProfileCatalog.ID(),
				service.datasetProfileCatalog.Revision())
		}
	})
}

// TestCheckAnalyticCandidatesRefusesLiveContextWithoutDeadline proves a
// nonempty installed catalog over a live context carrying no Deadline refuses
// CodeInvalid. The shared inert concrete store cannot serve a resolution, so
// this refusal is the missing-Deadline gate rather than the non-nil empty
// success every hidden resolver refusal produces.
func TestCheckAnalyticCandidatesRefusesLiveContextWithoutDeadline(t *testing.T) {
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 305,
		[]analytic.CatalogEntryInput{analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive)}))

	accepted, err := service.checkAnalyticCandidates(context.Background(),
		questionAccess(database.ActorKindHuman), "ws_operations")
	assertAnalyticCandidateCheckRefusal(t, accepted, err, CodeInvalid)
}

// TestCheckAnalyticCandidatesHidesConcreteResolverRefusals proves every
// concrete resolver refusal is hidden behind the non-nil empty success: each
// ACTIVE candidate resolves against the shared inert concrete repository store,
// which cannot serve a resolution, yet the invocation reports no error and
// retains nothing on the Service.
func TestCheckAnalyticCandidatesHidesConcreteResolverRefusals(t *testing.T) {
	entries := []analytic.CatalogEntryInput{
		analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive),
		analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive),
		analyticCandidateFixtureEntry(t, "gamma", 1, analytic.ProfileActive),
	}
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 306, entries))
	heldCatalog := service.datasetProfileCatalog
	heldResolver := service.analyticSourceResolver
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	accepted, err := service.checkAnalyticCandidates(ctx, questionAccess(database.ActorKindHuman), "ws_operations")
	if err != nil {
		t.Fatalf("concrete resolver refusal was exposed: %v", err)
	}
	if accepted == nil {
		t.Fatal("every concrete resolver refusal returned a nil slice instead of the non-nil empty success")
	}
	if len(accepted) != 0 {
		t.Fatalf("concrete resolver refusals accepted = %+v want none", accepted)
	}
	assertAnalyticCandidateCheckSlotsIntact(t, service, heldCatalog, heldResolver)
}

// TestCheckAnalyticCandidatesRetainsNoStateAcrossInvocations proves a repeated
// bounded top-level invocation reports the same fresh successful empty
// semantics and leaves both installed slots exactly as they were, so no result,
// cache or state is retained between calls.
func TestCheckAnalyticCandidatesRetainsNoStateAcrossInvocations(t *testing.T) {
	entries := []analytic.CatalogEntryInput{
		analyticCandidateFixtureEntry(t, "alpha", 1, analytic.ProfileActive),
		analyticCandidateFixtureEntry(t, "beta", 1, analytic.ProfileActive),
	}
	service := analyticCandidateFixtureService(t, analyticCandidateFixtureCatalog(t, "catalog.operations", 307, entries))
	heldCatalog := service.datasetProfileCatalog
	heldResolver := service.analyticSourceResolver
	access := questionAccess(database.ActorKindHuman)

	for attempt := 1; attempt <= 2; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		accepted, err := service.checkAnalyticCandidates(ctx, access, "ws_operations")
		cancel()
		if err != nil {
			t.Fatalf("attempt %d refused: %v", attempt, err)
		}
		if accepted == nil {
			t.Fatalf("attempt %d returned a nil slice want the non-nil empty success", attempt)
		}
		if len(accepted) != 0 {
			t.Fatalf("attempt %d accepted = %+v want none", attempt, accepted)
		}
		assertAnalyticCandidateCheckSlotsIntact(t, service, heldCatalog, heldResolver)
	}
}

// assertAnalyticCandidateCheckSlotsIntact proves the two installed slots still
// hold exactly the values captured before the call.
func assertAnalyticCandidateCheckSlotsIntact(
	t *testing.T,
	service *Service,
	catalog analytic.DatasetProfileCatalog,
	resolver *analyticsource.Resolver,
) {
	t.Helper()
	if !reflect.DeepEqual(service.datasetProfileCatalog, catalog) {
		t.Fatalf("service catalog changed: %q/%d want %q/%d", service.datasetProfileCatalog.ID(),
			service.datasetProfileCatalog.Revision(), catalog.ID(), catalog.Revision())
	}
	if service.analyticSourceResolver != resolver {
		t.Fatalf("service resolver changed: %p want %p", service.analyticSourceResolver, resolver)
	}
}
