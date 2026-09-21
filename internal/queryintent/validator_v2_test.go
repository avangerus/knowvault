package queryintent

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// v2Binding builds the exact binding of one installed catalog snapshot.
func v2Binding(t *testing.T, catalog analytic.DatasetProfileCatalog) CatalogBindingV2 {
	t.Helper()
	binding, err := NewCatalogBindingV2(catalog.ID(), catalog.Revision(), catalog.Hash())
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func v2Validator(t *testing.T, catalog analytic.DatasetProfileCatalog) ValidatorV2 {
	t.Helper()
	validator, err := NewValidatorV2(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

// v2ContentFreeV2 pins one generic refusal: the exact typed code, the generic
// clarification for that code, no unwrapping, and no echoed fixture content.
func v2ContentFreeV2(t *testing.T, name string, code ErrorCode, err error) {
	t.Helper()
	clarification := ClarificationOf(err)
	if err == nil || CodeOf(err) != code || err.Error() != string(code) || clarification == "" ||
		clarification != clarificationFor(code) || errors.Unwrap(err) != nil {
		t.Fatalf("%s: code=%q clarification=%q err=%v", name, CodeOf(err), clarification, err)
	}
	for _, leaked := range []string{"alpha", "beta", "gamma", "catalog.operations", "catalog.other", "sha256:", "amount", "region"} {
		if strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked) {
			t.Fatalf("%s: refusal leaked %q in %q", name, leaked, clarification)
		}
	}
}

// v2RefusalV2 additionally requires a refusal to return the zero sealed value.
func v2RefusalV2(t *testing.T, name string, code ErrorCode, sealed ValidatedIntentV2, err error) {
	t.Helper()
	v2ContentFreeV2(t, name, code, err)
	if !reflect.DeepEqual(sealed, ValidatedIntentV2{}) {
		t.Fatalf("%s: refusal returned %v", name, sealed)
	}
}

// v2ValidatorFilters replaces the R1.2f baseline filter set with the one the
// R1.2g filter policy allows the v2Base profile: business_day is not filterable,
// so these baselines filter on the filterable region field instead.
func v2ValidatorFilters(t *testing.T) Predicates {
	t.Helper()
	return v2Predicates(t, v2Predicate(t, "region", OpEQ, v2Text(t, "north")))
}

func TestValidatorV2ValidAggregateAndLookup(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	proposal := v2SealAggregate(t, parts)

	sealed, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("aggregate refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if id, ok := sealed.CatalogID(); !ok || id != catalog.ID() {
		t.Fatalf("catalog id=%q ok=%v", id, ok)
	}
	if revision, ok := sealed.CatalogRevision(); !ok || revision != catalog.Revision() {
		t.Fatalf("catalog revision=%d ok=%v", revision, ok)
	}
	if hash, ok := sealed.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("catalog hash=%q ok=%v", hash, ok)
	}
	if limits, ok := sealed.Limits(); !ok || limits != profile.Limits() {
		t.Fatalf("limits=%v ok=%v", limits, ok)
	}
	if coverage, ok := sealed.Coverage(); !ok || coverage != profile.Coverage() {
		t.Fatalf("coverage=%q ok=%v", coverage, ok)
	}
	direct := v2Seal(t, catalog, profile, proposal)
	if !reflect.DeepEqual(sealed, direct) || v2Digest(t, sealed) != v2Digest(t, direct) {
		t.Fatal("the validator sealed a different value than the direct seal")
	}

	lookupParts := v2LookupPartsFor(t, profile)
	lookupParts.Filters = v2ValidatorFilters(t)
	lookup, err := validator.ValidateProposalV2(v2SealLookup(t, lookupParts), binding)
	if err != nil || !lookup.Valid() {
		t.Fatalf("lookup refused: valid=%v err=%v", lookup.Valid(), err)
	}
	if _, ok := lookup.Measure(); ok {
		t.Fatal("LOOKUP sealed an AGGREGATE measure")
	}
	if hash, ok := lookup.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("lookup catalog hash=%q ok=%v", hash, ok)
	}
	if v2Digest(t, lookup) == v2Digest(t, sealed) {
		t.Fatal("LOOKUP and AGGREGATE sealed the same digest")
	}
}

func TestValidatorV2RefusesInvalidProposalFirst(t *testing.T) {
	catalog, profile := v2Base(t)
	validator := v2Validator(t, catalog)
	mixed := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	mixed.operation = OperationLOOKUP
	cases := map[string]ProposalV2{"zero proposal": {}, "mixed shape": mixed}
	for name, proposal := range cases {
		sealed, err := validator.ValidateProposalV2(proposal, v2Binding(t, catalog))
		v2RefusalV2(t, name, CodeInvalidProposal, sealed, err)
	}
	sealed, err := ValidatorV2{}.ValidateProposalV2(ProposalV2{}, CatalogBindingV2{})
	v2RefusalV2(t, "proposal before the invalid validator", CodeInvalidProposal, sealed, err)
}

func TestValidatorV2ConstructorRefusesInvalidCatalog(t *testing.T) {
	validator, err := NewValidatorV2(analytic.DatasetProfileCatalog{})
	if !reflect.DeepEqual(validator, ValidatorV2{}) {
		t.Fatalf("invalid catalog produced %v", validator)
	}
	v2ContentFreeV2(t, "invalid catalog", CodeCatalogUnavailable, err)

	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	sealed, err := ValidatorV2{}.ValidateProposalV2(proposal, v2Binding(t, catalog))
	v2RefusalV2(t, "zero validator", CodeCatalogUnavailable, sealed, err)
}

func TestCatalogBindingV2ShapeAndImmutability(t *testing.T) {
	zero := CatalogBindingV2{}
	if zero.Valid() {
		t.Fatal("zero binding reported valid")
	}
	if id, ok := zero.ID(); ok || id != "" {
		t.Fatalf("zero ID=%q ok=%v", id, ok)
	}
	if revision, ok := zero.Revision(); ok || revision != 0 {
		t.Fatalf("zero Revision=%d ok=%v", revision, ok)
	}
	if hash, ok := zero.Hash(); ok || hash != "" {
		t.Fatalf("zero Hash=%q ok=%v", hash, ok)
	}

	catalog, _ := v2Base(t)
	bad := []struct {
		name     string
		id       string
		revision int64
		hash     string
	}{
		{"empty id", "", 7, catalog.Hash()},
		{"untrimmed id", " catalog.operations", 7, catalog.Hash()},
		{"control id", "catalog\noperations", 7, catalog.Hash()},
		{"zero revision", catalog.ID(), 0, catalog.Hash()},
		{"negative revision", catalog.ID(), -1, catalog.Hash()},
		{"empty hash", catalog.ID(), 7, ""},
		{"untagged hash", catalog.ID(), 7, strings.Repeat("0", 64)},
		{"uppercase hash", catalog.ID(), 7, "sha256:" + strings.Repeat("A", 64)},
	}
	for _, test := range bad {
		binding, err := NewCatalogBindingV2(test.id, test.revision, test.hash)
		if !reflect.DeepEqual(binding, CatalogBindingV2{}) {
			t.Fatalf("%s produced %v", test.name, binding)
		}
		v2ContentFreeV2(t, test.name, CodeInvalidProposal, err)
	}

	binding := v2Binding(t, catalog)
	if id, ok := binding.ID(); !ok || id != catalog.ID() {
		t.Fatalf("ID=%q ok=%v", id, ok)
	}
	if revision, ok := binding.Revision(); !ok || revision != catalog.Revision() {
		t.Fatalf("Revision=%d ok=%v", revision, ok)
	}
	if hash, ok := binding.Hash(); !ok || hash != catalog.Hash() {
		t.Fatalf("Hash=%q ok=%v", hash, ok)
	}
	copied := binding
	copied.id, copied.revision = "catalog.other", 0
	copied.hash = "sha256:" + strings.Repeat("0", 64)
	if id, ok := binding.ID(); !ok || id != catalog.ID() {
		t.Fatalf("mutating a copy reached the original: id=%q ok=%v", id, ok)
	}
	if copied.Valid() {
		t.Fatal("tampered copy reported valid")
	}
}

func TestValidatorV2RefusesBindingDriftAndProfileAuthority(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	other := v2Profile(t, "beta", 1, analytic.CoverageUnknown, v2Limits(t, 10000))
	otherCatalog := v2Catalog(t, "catalog.other", 1, v2Active(other))
	refTo := func(datasetID string, version int64, hash string) ProposalV2 {
		return v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
			parts.Dataset = v2RefFields(t, datasetID, version, hash)
		}))
	}
	proposal := refTo("alpha", 1, profile.Hash())

	drift := []struct {
		name    string
		binding CatalogBindingV2
	}{
		{"zero binding", CatalogBindingV2{}},
		{"id drift", CatalogBindingV2{id: otherCatalog.ID(), revision: catalog.Revision(), hash: catalog.Hash()}},
		{"revision drift", CatalogBindingV2{id: catalog.ID(), revision: catalog.Revision() + 1, hash: catalog.Hash()}},
		{"hash drift", CatalogBindingV2{id: catalog.ID(), revision: catalog.Revision(), hash: otherCatalog.Hash()}},
	}
	for _, test := range drift {
		sealed, err := validator.ValidateProposalV2(proposal, test.binding)
		v2RefusalV2(t, test.name, CodeCatalogBindingMismatch, sealed, err)
	}

	retired := v2Catalog(t, "catalog.retired", 3, v2Retired(profile))
	resolution := []struct {
		name     string
		catalog  analytic.DatasetProfileCatalog
		binding  CatalogBindingV2
		proposal ProposalV2
	}{
		{"unknown dataset", catalog, binding, refTo("gamma", 1, profile.Hash())},
		{"unknown version", catalog, binding, refTo("alpha", 2, profile.Hash())},
		{"wrong profile hash", catalog, binding, refTo("alpha", 1, other.Hash())},
		{"non-profile dataset id", catalog, binding, refTo("alpha.beta", 1, profile.Hash())},
		{"retired profile", retired, v2Binding(t, retired), proposal},
	}
	for _, test := range resolution {
		sealed, err := v2Validator(t, test.catalog).ValidateProposalV2(test.proposal, test.binding)
		v2RefusalV2(t, test.name, CodeDatasetProfileUnavailable, sealed, err)
	}

	unknownMeasure := v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
		parts.Measure = v2Measure(t, "revenue")
	}))
	sealed, err := validator.ValidateProposalV2(unknownMeasure, binding)
	v2RefusalV2(t, "unknown measure", CodeMeasureUnavailable, sealed, err)
}

func TestValidatorV2LookupNeedsNoMeasure(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2LookupPartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	parts.OutputFields = v2OutputFields(t, "unlisted")
	lookup := v2SealLookup(t, parts)
	if measure, ok := lookup.Measure(); ok || measure.Valid() {
		t.Fatal("LOOKUP fixture carries a measure")
	}
	sealed, err := validator.ValidateProposalV2(lookup, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("lookup refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if _, ok := sealed.Measure(); ok {
		t.Fatal("sealed LOOKUP carries a measure")
	}
	v2Digest(t, sealed)
}

// Dimensions, output fields, sort targets, limits and periods the profile
// cannot resolve are deliberately left to a later card. Filter predicates are
// resolved by the R1.2g policy, so every baseline here filters on the allowed
// region field; the unknown filter field case now belongs to that policy.
func TestValidatorV2LeavesSemanticsUnresolved(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	agg := func(mutate func(*v2AggregateParts)) ProposalV2 {
		return v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
			parts.Filters = v2ValidatorFilters(t)
			mutate(parts)
		}))
	}
	lookupParts := v2LookupPartsFor(t, profile)
	lookupParts.Filters = v2ValidatorFilters(t)
	lookupParts.OutputFields = v2OutputFields(t, "unlisted")
	lookupParts.Sort = v2DimensionSort(t, "unlisted", SortDESC)

	cases := map[string]ProposalV2{
		"unknown dimension": agg(func(parts *v2AggregateParts) {
			parts.Dimensions = v2Dimensions(t, "unlisted")
			parts.Sort = v2DimensionSort(t, "unlisted", SortDESC)
		}),
		"unknown measure sort": agg(func(parts *v2AggregateParts) {
			parts.Sort = v2MeasureSort(t, "unlisted", SortDESC)
		}),
		"limit at the wire bound": agg(func(parts *v2AggregateParts) { parts.Limit = v2Limit(t, MaxLimit) }),
		"unresolved relative period": agg(func(parts *v2AggregateParts) {
			parts.Period = v2Relative(t, PeriodLATESTAVAILABLE)
		}),
		"period outside coverage": agg(func(parts *v2AggregateParts) {
			parts.Period = v2Explicit(t, "1999-01-01", "1999-12-31")
		}),
		"unknown lookup output field": v2SealLookup(t, lookupParts),
	}
	for name, proposal := range cases {
		sealed, err := validator.ValidateProposalV2(proposal, binding)
		if err != nil || !sealed.Valid() {
			t.Fatalf("%s refused: valid=%v err=%v", name, sealed.Valid(), err)
		}
		v2Digest(t, sealed)
	}
}
