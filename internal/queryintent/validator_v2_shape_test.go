package queryintent

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// v2ShapeProfile clones the v2Base fixture through its own spec, so one shape
// case can withdraw a field grant, add a measure or tighten a budget.
func v2ShapeProfile(t *testing.T, adjust func(test *testing.T, spec *analytic.DatasetProfileSpec)) analytic.DatasetProfile {
	t.Helper()
	spec := v2Profile(t, "alpha", 1, analytic.CoverageUnknown, v2Limits(t, 10000)).Spec()
	if adjust != nil {
		adjust(t, &spec)
	}
	profile, err := analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// v2ShapeField re-seals exactly one field of a cloned profile spec.
func v2ShapeField(t *testing.T, spec *analytic.DatasetProfileSpec, token string, adjust func(*analytic.FieldSpecInput)) {
	t.Helper()
	for index, field := range spec.Fields {
		if field.Values().Token != token {
			continue
		}
		input := field.Values()
		adjust(&input)
		rebuilt, err := analytic.NewFieldSpec(input)
		if err != nil {
			t.Fatal(err)
		}
		spec.Fields[index] = rebuilt
		return
	}
	t.Fatalf("fixture profile has no %s field", token)
}

// v2ShapeMeasure appends one COUNT_ROWS measure, with its semantics.
func v2ShapeMeasure(t *testing.T, spec *analytic.DatasetProfileSpec, id string) {
	t.Helper()
	measure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: id, Reducer: analytic.ReducerCountRows, Unit: "rows",
		NullPolicy: analytic.NullNotApplicable, Eligibility: analytic.EligibilityAllRows})
	if err != nil {
		t.Fatal(err)
	}
	semantics := spec.Semantics.Values()
	semantics.Measures = append(semantics.Measures, analytic.MeasureSemanticsInput{ID: id, Label: "Rows", Description: "Row count"})
	rebuilt, err := analytic.NewProfileSemantics(semantics)
	if err != nil {
		t.Fatal(err)
	}
	spec.Measures, spec.Semantics = append(spec.Measures, measure), rebuilt
}

// v2ShapeLimits replaces one cloned profile's output-group budget.
func v2ShapeLimits(t *testing.T, spec *analytic.DatasetProfileSpec, maxOutputGroups int) {
	t.Helper()
	input := spec.Limits.Values()
	input.MaxOutputGroups = maxOutputGroups
	limits, err := analytic.NewProfileLimits(input)
	if err != nil {
		t.Fatal(err)
	}
	spec.Limits = limits
}

// v2ShapeAggregate seals the shared AGGREGATE parts over profile with one override.
func v2ShapeAggregate(t *testing.T, profile analytic.DatasetProfile, mutate func(*v2AggregateParts)) ProposalV2 {
	t.Helper()
	return v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
		parts.Filters = v2ValidatorFilters(t)
		if mutate != nil {
			mutate(parts)
		}
	}))
}

// v2ShapeLookup seals the shared LOOKUP parts over profile the same way.
func v2ShapeLookup(t *testing.T, profile analytic.DatasetProfile, mutate func(*v2LookupParts)) ProposalV2 {
	t.Helper()
	parts := v2LookupPartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	if mutate != nil {
		mutate(&parts)
	}
	return v2SealLookup(t, parts)
}

// v2ShapeValidate validates one sealed proposal over the catalog that authorizes it.
func v2ShapeValidate(t *testing.T, profile analytic.DatasetProfile, proposal ProposalV2) (ValidatedIntentV2, error) {
	t.Helper()
	catalog := v2Catalog(t, "catalog.operations", 7, v2Active(profile))
	return v2Validator(t, catalog).ValidateProposalV2(proposal, v2Binding(t, catalog))
}

// v2ShapeAggregateCase pairs a profile with the AGGREGATE override to refuse.
type v2ShapeAggregateCase struct {
	name    string
	profile analytic.DatasetProfile
	code    ErrorCode
	mutate  func(*v2AggregateParts)
}

// v2ShapeLookupCase pairs a profile with the LOOKUP override to refuse.
type v2ShapeLookupCase struct {
	name    string
	profile analytic.DatasetProfile
	code    ErrorCode
	mutate  func(*v2LookupParts)
}

// v2ShapeDenied pins one R1.2h refusal: zero value, exact code, no echoed token.
func v2ShapeDenied(t *testing.T, name string, code ErrorCode, sealed ValidatedIntentV2, err error) {
	t.Helper()
	v2RefusalV2(t, name, code, sealed, err)
	for _, leaked := range []string{"business_day", "amount", "region", "unlisted", "revenue", "volume", "2026-01-01"} {
		if strings.Contains(err.Error(), leaked) || strings.Contains(ClarificationOf(err), leaked) {
			t.Fatalf("%s: refusal leaked %q", name, leaked)
		}
	}
}

// v2ShapeRefusesAggregates runs every aggregate case and pins its refusal.
func v2ShapeRefusesAggregates(t *testing.T, cases []v2ShapeAggregateCase) {
	t.Helper()
	for _, test := range cases {
		sealed, err := v2ShapeValidate(t, test.profile, v2ShapeAggregate(t, test.profile, test.mutate))
		v2ShapeDenied(t, test.name, test.code, sealed, err)
	}
}

// v2ShapeRefusesLookups runs every lookup case and pins its refusal.
func v2ShapeRefusesLookups(t *testing.T, cases []v2ShapeLookupCase) {
	t.Helper()
	for _, test := range cases {
		sealed, err := v2ShapeValidate(t, test.profile, v2ShapeLookup(t, test.profile, test.mutate))
		v2ShapeDenied(t, test.name, test.code, sealed, err)
	}
}

// TestValidatorV2ShapeAllowsAggregateSorts proves the profile authorizes both a
// dimension sort over a selected dimension and a measure sort over the selected
// measure, and that the seal keeps the requested grouping and sort order.
func TestValidatorV2ShapeAllowsAggregateSorts(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	for name, sort := range map[string]SortKeys{
		"dimension sort": v2DimensionSort(t, "region", SortDESC),
		"measure sort":   v2MeasureSort(t, "amount", SortASC),
	} {
		parts := v2Parts(t, profile, func(parts *v2AggregateParts) {
			parts.Filters = v2ValidatorFilters(t)
			parts.Dimensions = v2Dimensions(t, "business_day", "region")
			parts.Sort = sort
		})
		sealed, err := validator.ValidateProposalV2(v2SealAggregate(t, parts), binding)
		if err != nil || !sealed.Valid() {
			t.Fatalf("%s refused: valid=%v err=%v", name, sealed.Valid(), err)
		}
		if dimensions, ok := sealed.Dimensions(); !ok || dimensions != parts.Dimensions {
			t.Fatalf("%s: sealed dimensions=%v ok=%v", name, dimensions, ok)
		}
		if sealedSort, ok := sealed.Sort(); !ok || sealedSort != parts.Sort {
			t.Fatalf("%s: sealed sort order changed", name)
		}
		v2Digest(t, sealed)
	}
}

// TestValidatorV2ShapeAllowsLookupOutputsAndDetachedSort proves a LOOKUP may
// return output-allowed fields and order by a sortable field that is not one of
// them, keeping the request order in the seal.
func TestValidatorV2ShapeAllowsLookupOutputsAndDetachedSort(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2LookupPartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	parts.OutputFields = v2OutputFields(t, "amount", "region")
	parts.Sort = v2DimensionSort(t, "business_day", SortDESC)
	sealed, err := validator.ValidateProposalV2(v2SealLookup(t, parts), binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("authorized lookup refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if outputFields, ok := sealed.OutputFields(); !ok || outputFields != parts.OutputFields {
		t.Fatalf("sealed output fields=%v ok=%v", outputFields, ok)
	}
	if sort, ok := sealed.Sort(); !ok || sort != parts.Sort {
		t.Fatal("sealed lookup sort changed")
	}
	v2Digest(t, sealed)
}

// TestValidatorV2ShapeDeniesDimensions drives every AGGREGATE grouping denial: a
// group the profile does not define, a field it does not allow grouping by, and
// a dimension that stays checked before the sort key beside it.
func TestValidatorV2ShapeDeniesDimensions(t *testing.T) {
	plain := v2ShapeProfile(t, nil)
	nonGroupable := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeField(t, spec, "business_day", func(input *analytic.FieldSpecInput) { input.Groupable = false })
	})
	v2ShapeRefusesAggregates(t, []v2ShapeAggregateCase{
		{"unknown dimension", plain, CodeDimensionUnavailable, func(parts *v2AggregateParts) { parts.Dimensions = v2Dimensions(t, "unlisted") }},
		{"non-groupable dimension", nonGroupable, CodeDimensionUnavailable, nil},
		{"dimension before its sort", plain, CodeDimensionUnavailable, func(parts *v2AggregateParts) {
			parts.Dimensions = v2Dimensions(t, "unlisted")
			parts.Sort = v2DimensionSort(t, "unlisted", SortASC)
		}},
	})
}

// TestValidatorV2ShapeDeniesAggregateSorts drives every AGGREGATE sort denial: a
// dimension that was not selected, an unknown sort field, a non-sortable sort
// field, an unknown measure and a measure the profile defines but the proposal
// did not select.
func TestValidatorV2ShapeDeniesAggregateSorts(t *testing.T) {
	plain := v2ShapeProfile(t, nil)
	nonSortable := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeField(t, spec, "business_day", func(input *analytic.FieldSpecInput) { input.Sortable = false })
	})
	twoMeasures := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeMeasure(t, spec, "volume")
	})
	v2ShapeRefusesAggregates(t, []v2ShapeAggregateCase{
		{"dimension not selected", plain, CodeSortUnavailable, func(parts *v2AggregateParts) { parts.Sort = v2DimensionSort(t, "region", SortASC) }},
		{"unknown dimension sort", plain, CodeSortUnavailable, func(parts *v2AggregateParts) { parts.Sort = v2DimensionSort(t, "unlisted", SortASC) }},
		{"non-sortable dimension sort", nonSortable, CodeSortUnavailable, nil},
		{"unknown measure sort", plain, CodeSortUnavailable, func(parts *v2AggregateParts) { parts.Sort = v2MeasureSort(t, "revenue", SortASC) }},
		{"unselected measure sort", twoMeasures, CodeSortUnavailable, func(parts *v2AggregateParts) { parts.Sort = v2MeasureSort(t, "volume", SortASC) }},
	})
}

// TestValidatorV2ShapeDeniesLookupResults drives every LOOKUP result denial: an
// unknown output field, an output field the profile does not allow in results,
// an unknown sort field, a non-sortable sort field, and one output field that
// stays checked before the sort key beside it.
func TestValidatorV2ShapeDeniesLookupResults(t *testing.T) {
	plain := v2ShapeProfile(t, nil)
	hidden := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeField(t, spec, "amount", func(input *analytic.FieldSpecInput) { input.OutputAllowed = false })
	})
	nonSortable := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeField(t, spec, "region", func(input *analytic.FieldSpecInput) { input.Sortable = false })
	})
	v2ShapeRefusesLookups(t, []v2ShapeLookupCase{
		{"unknown output field", plain, CodeOutputFieldUnavailable, func(parts *v2LookupParts) { parts.OutputFields = v2OutputFields(t, "unlisted") }},
		{"output field not allowed in results", hidden, CodeOutputFieldUnavailable, func(parts *v2LookupParts) { parts.OutputFields = v2OutputFields(t, "amount") }},
		{"output before its sort", plain, CodeOutputFieldUnavailable, func(parts *v2LookupParts) {
			parts.OutputFields = v2OutputFields(t, "unlisted")
			parts.Sort = v2DimensionSort(t, "unlisted", SortASC)
		}},
		{"unknown lookup sort", plain, CodeSortUnavailable, func(parts *v2LookupParts) { parts.Sort = v2DimensionSort(t, "unlisted", SortASC) }},
		{"non-sortable lookup sort", nonSortable, CodeSortUnavailable, func(parts *v2LookupParts) {
			parts.OutputFields = v2OutputFields(t, "region")
			parts.Sort = v2DimensionSort(t, "region", SortASC)
		}},
	})
}

// TestValidatorV2ShapeLimits pins the common budget: a limit equal to the
// profile maximum is accepted, one above it is refused while still inside the
// wire bound, and the budget is resolved before the shape it applies to.
func TestValidatorV2ShapeLimits(t *testing.T) {
	plain := v2ShapeProfile(t, nil)
	narrow := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) { v2ShapeLimits(t, spec, 24) })
	sealed, err := v2ShapeValidate(t, narrow, v2ShapeAggregate(t, narrow, func(parts *v2AggregateParts) {
		parts.Limit = v2Limit(t, 24)
	}))
	if err != nil || !sealed.Valid() {
		t.Fatalf("limit equal to the profile budget refused: valid=%v err=%v", sealed.Valid(), err)
	}
	limit, limitOK := sealed.Limit()
	value, valueOK := limit.Value()
	if !limitOK || !valueOK || value != 24 {
		t.Fatalf("sealed limit=%d ok=%v", value, limitOK && valueOK)
	}
	v2Digest(t, sealed)
	v2ShapeRefusesAggregates(t, []v2ShapeAggregateCase{
		{"above the profile budget", narrow, CodeLimitExceeded, func(parts *v2AggregateParts) { parts.Limit = v2Limit(t, 25) }},
		{"budget before the shape", narrow, CodeLimitExceeded, func(parts *v2AggregateParts) {
			parts.Limit = v2Limit(t, 25)
			parts.Dimensions = v2Dimensions(t, "unlisted")
		}},
	})
	v2ShapeRefusesLookups(t, []v2ShapeLookupCase{
		{"above the profile budget at the wire bound", plain, CodeLimitExceeded, func(parts *v2LookupParts) { parts.Limit = v2Limit(t, MaxLimit) }},
	})
}

// TestValidatorV2ShapeKeepsStructuralInvariants proves the shape policy adds no
// VALUE/ROWSET versus dimension invariant: a grouped VALUE and an ungrouped
// ROWSET both stay valid, while a shape mixed by hand stays CodeInvalidProposal.
func TestValidatorV2ShapeKeepsStructuralInvariants(t *testing.T) {
	plain := v2ShapeProfile(t, nil)
	empty, _ := NewSortKeys()
	for name, mutate := range map[string]func(*v2AggregateParts){
		"grouped VALUE": func(parts *v2AggregateParts) { parts.Output = OutputValue },
		"ungrouped ROWSET": func(parts *v2AggregateParts) {
			parts.Dimensions, parts.Sort, parts.Output = v2Dimensions(t), empty, OutputRowset
		},
	} {
		sealed, err := v2ShapeValidate(t, plain, v2ShapeAggregate(t, plain, mutate))
		if err != nil || !sealed.Valid() {
			t.Fatalf("%s refused: valid=%v err=%v", name, sealed.Valid(), err)
		}
		v2Digest(t, sealed)
	}
	mixed := v2ShapeAggregate(t, plain, nil)
	mixed.operation = OperationLOOKUP
	sealed, err := v2ShapeValidate(t, plain, mixed)
	v2ShapeDenied(t, "mixed shape", CodeInvalidProposal, sealed, err)
}
