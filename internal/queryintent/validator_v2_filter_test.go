package queryintent

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// v2FilterScalarTypePairs are the seven exact ScalarKind -> ScalarType pairs
// the filter policy must map, in profile vocabulary order.
var v2FilterScalarTypePairs = []struct {
	kind    ScalarKind
	logical analytic.ScalarType
}{
	{KindBOOL, analytic.ScalarBool},
	{KindINT, analytic.ScalarInt},
	{KindNUMERIC, analytic.ScalarNumeric},
	{KindTEXT, analytic.ScalarText},
	{KindDATE, analytic.ScalarDate},
	{KindTIMESTAMP, analytic.ScalarTimestamp},
	{KindTIMESTAMPTZ, analytic.ScalarTimestamptz},
}

// TestFilterScalarMatchesV2 drives the explicit scalar-type helper directly:
// all seven matching pairs, one mismatched pair per kind, and unknown kinds.
func TestFilterScalarMatchesV2(t *testing.T) {
	for index, pair := range v2FilterScalarTypePairs {
		if !filterScalarMatchesV2(pair.kind, pair.logical) {
			t.Fatalf("%s did not match %s", pair.kind, pair.logical)
		}
		mismatch := v2FilterScalarTypePairs[(index+1)%len(v2FilterScalarTypePairs)].logical
		if filterScalarMatchesV2(pair.kind, mismatch) {
			t.Fatalf("%s matched %s", pair.kind, mismatch)
		}
	}
	for _, unknown := range []ScalarKind{"", "text", "UUID", "BOOL "} {
		if filterScalarMatchesV2(unknown, analytic.ScalarText) {
			t.Fatalf("unknown scalar kind %q matched a logical type", unknown)
		}
	}
}

// v2FilterField builds one fixture field with its exact operator grant.
func v2FilterField(t *testing.T, token string, ordinal int, kind analytic.ScalarType, nullable, output bool, operators ...analytic.PredicateOperator) analytic.FieldSpec {
	t.Helper()
	physical := map[analytic.ScalarType]analytic.PhysicalType{
		analytic.ScalarBool: analytic.PhysicalPGBool, analytic.ScalarText: analytic.PhysicalPGText,
		analytic.ScalarDate: analytic.PhysicalPGDate,
	}[kind]
	field, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: token, LogicalType: kind, PhysicalType: physical,
		Nullable: nullable, Filterable: len(operators) > 0, Groupable: true, Sortable: true,
		OutputAllowed: output, AllowedOps: operators,
	})
	if err != nil {
		t.Fatal(err)
	}
	return field
}

// v2FilterProfile seals the concise fixture the filter cases share: a filterable
// DATE field granting EQ only, a filterable TEXT field granting EQ and IN, a
// nullable BOOL field additionally granting IS_NULL, and a TEXT field no filter
// may touch. A time kind other than NONE reserves business_day as the time
// field, so the reserved-field case needs no other profile change.
func v2FilterProfile(t *testing.T, timeKind analytic.TimeKind) analytic.DatasetProfile {
	t.Helper()
	key, err := analytic.NewProfileKey("filters", 1)
	if err != nil {
		t.Fatal(err)
	}
	source, err := analytic.NewSourceProjectionSpec(analytic.SourceProjectionInput{
		SourceScopeID: "scope", ConnectionID: "primary", DatabaseIdentity: "knowledge",
		ProjectionLineageID: "operations", ProjectionRevision: 1,
		ProjectionContractHash: "sha256:" + strings.Repeat("1", 64),
		ExposedSchemaRevision:  1, ExposedSchemaHash: "sha256:" + strings.Repeat("2", 64),
		SchemaName: "public", RelationName: "operations", RelationKind: analytic.RelationView,
	})
	if err != nil {
		t.Fatal(err)
	}
	semantics, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel: "Filters", DatasetDescription: "Filter fixture",
		Fields: []analytic.FieldSemanticsInput{
			{Token: "business_day", Label: "Business day", Description: "Business day", NullMeaning: "Not recorded"},
			{Token: "region", Label: "Region", Description: "Region", NullMeaning: "Not assigned"},
			{Token: "status", Label: "Status", Description: "Status", NullMeaning: "Not known"},
			{Token: "note", Label: "Note", Description: "Note", NullMeaning: "Not recorded"},
		},
		Measures: []analytic.MeasureSemanticsInput{{ID: "amount", Label: "Amount", Description: "Row count"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description: "One row per region per business day", KeyFields: []string{"business_day", "region"},
		DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatal(err)
	}
	measure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: "amount", Reducer: analytic.ReducerCountRows, Unit: "rows",
		NullPolicy: analytic.NullNotApplicable, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatal(err)
	}
	timeInput := analytic.TimePolicyInput{Kind: timeKind}
	if timeKind != analytic.TimeNone {
		timeInput.FieldToken, timeInput.ReportingTimezone, timeInput.Calendar = "business_day", "UTC", analytic.CalendarGregorian
	}
	timePolicy, err := analytic.NewTimePolicy(timeInput)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source, Measures: []analytic.MeasureSpec{measure},
		Fields: []analytic.FieldSpec{
			v2FilterField(t, "business_day", 1, analytic.ScalarDate, false, true, analytic.PredicateEQ),
			v2FilterField(t, "region", 2, analytic.ScalarText, false, true, analytic.PredicateEQ, analytic.PredicateIN),
			v2FilterField(t, "status", 3, analytic.ScalarBool, true, true, analytic.PredicateEQ, analytic.PredicateIN, analytic.PredicateISNull),
			v2FilterField(t, "note", 4, analytic.ScalarText, false, false),
		},
		Semantics: semantics, Grain: grain, Time: timePolicy, Coverage: analytic.CoverageUnknown,
		Limits: v2Limits(t, 10000),
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

// v2FilterCase seals one AGGREGATE proposal over profile with exactly the given
// filter set, together with the validator and binding that authorize it.
func v2FilterCase(t *testing.T, profile analytic.DatasetProfile, predicates ...Predicate) (ValidatorV2, CatalogBindingV2, ProposalV2) {
	t.Helper()
	catalog := v2Catalog(t, "catalog.filters", 1, v2Active(profile))
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2Predicates(t, predicates...)
	return validator, binding, v2SealAggregate(t, parts)
}

// v2Numeric builds one NUMERIC scalar for the shared v2Base amount field.
func v2Numeric(t *testing.T, value string) Scalar {
	t.Helper()
	scalar, err := NumericScalar(value)
	if err != nil {
		t.Fatal(err)
	}
	return scalar
}

// v2FilterDenied pins one R1.2g denial: the zero sealed value, the exact
// CodeFilterNotAllowed code, the generic clarification, no unwrapping, and no
// fixture token echoed back.
func v2FilterDenied(t *testing.T, name string, sealed ValidatedIntentV2, err error) {
	t.Helper()
	v2RefusalV2(t, name, CodeFilterNotAllowed, sealed, err)
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("%s: refusal unwrapped to %v", name, unwrapped)
	}
	for _, leaked := range []string{"business_day", "region", "status", "note", "east", "2026-01-01"} {
		if strings.Contains(err.Error(), leaked) || strings.Contains(ClarificationOf(err), leaked) {
			t.Fatalf("%s: refusal leaked %q", name, leaked)
		}
	}
}

// TestValidatorV2AllowsAuthorizedFilters proves the policy admits exactly the
// predicates the profile authorizes: the shared v2Base profile grants region
// EQ, and the concise fixture adds the IN, IS_NULL true/false and DATE grants.
func TestValidatorV2AllowsAuthorizedFilters(t *testing.T) {
	catalog, base := v2Base(t)
	baseParts := v2AggregatePartsFor(t, base)
	baseParts.Filters = v2Predicates(t, v2Predicate(t, "region", OpEQ, v2Text(t, "north")))
	sealed, err := v2Validator(t, catalog).ValidateProposalV2(v2SealAggregate(t, baseParts), v2Binding(t, catalog))
	if err != nil || !sealed.Valid() {
		t.Fatalf("v2Base region EQ refused: valid=%v err=%v", sealed.Valid(), err)
	}
	v2Digest(t, sealed)

	plain, bound := v2FilterProfile(t, analytic.TimeNone), v2FilterProfile(t, analytic.TimeBusinessDate)
	cases := []struct {
		name       string
		profile    analytic.DatasetProfile
		predicates []Predicate
	}{
		{"text EQ", plain, []Predicate{v2Predicate(t, "region", OpEQ, v2Text(t, "east"))}},
		{"text IN", plain, []Predicate{v2Predicate(t, "region", OpIN, v2Text(t, "east"), v2Text(t, "west"))}},
		{"date EQ", plain, []Predicate{v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01"))}},
		{"is null true", plain, []Predicate{v2Predicate(t, "status", OpISNull, BoolScalar(true))}},
		{"is null false", plain, []Predicate{v2Predicate(t, "status", OpISNull, BoolScalar(false))}},
		{"non-time field beside a bound time field", bound, []Predicate{v2Predicate(t, "region", OpEQ, v2Text(t, "east"))}},
	}
	for _, test := range cases {
		validator, binding, proposal := v2FilterCase(t, test.profile, test.predicates...)
		sealed, err := validator.ValidateProposalV2(proposal, binding)
		if err != nil || !sealed.Valid() {
			t.Fatalf("%s refused: valid=%v err=%v", test.name, sealed.Valid(), err)
		}
		v2Digest(t, sealed)
	}
}

// TestValidatorV2DeniesUnauthorizedFilters drives every semantic denial through
// the validator and pins one content-free CodeFilterNotAllowed refusal each.
func TestValidatorV2DeniesUnauthorizedFilters(t *testing.T) {
	plain, bound := v2FilterProfile(t, analytic.TimeNone), v2FilterProfile(t, analytic.TimeBusinessDate)
	_, base := v2Base(t)
	cases := []struct {
		name      string
		profile   analytic.DatasetProfile
		predicate Predicate
	}{
		{"unknown field", plain, v2Predicate(t, "missing", OpEQ, v2Text(t, "east"))},
		{"non-filterable fixture field", plain, v2Predicate(t, "note", OpEQ, v2Text(t, "east"))},
		{"non-filterable v2Base field", base, v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01"))},
		{"reserved time field", bound, v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01"))},
		{"operator outside the field grant", plain, v2Predicate(t, "business_day", OpGTE, v2Date(t, "2026-01-01"))},
		{"operator outside the v2Base grant", base, v2Predicate(t, "amount", OpGTE, v2Numeric(t, "5"))},
		{"in outside the field grant", plain, v2Predicate(t, "business_day", OpIN, v2Date(t, "2026-01-01"))},
		{"text against the existing numeric field", base, v2Predicate(t, "amount", OpEQ, v2Text(t, "5"))},
		{"int against the text field", plain, v2Predicate(t, "region", OpEQ, IntScalar(7))},
		{"is null on a non-nullable field", plain, v2Predicate(t, "region", OpISNull, BoolScalar(true))},
	}
	for _, test := range cases {
		validator, binding, proposal := v2FilterCase(t, test.profile, test.predicate)
		sealed, err := validator.ValidateProposalV2(proposal, binding)
		v2FilterDenied(t, test.name, sealed, err)
	}
}

// TestValidatorV2SealsFilterOrder proves the two-predicate request order stays
// unchanged in the sealed accessor and remains part of the sealed digest.
func TestValidatorV2SealsFilterOrder(t *testing.T) {
	profile := v2FilterProfile(t, analytic.TimeNone)
	validator, binding, proposal := v2FilterCase(t, profile,
		v2Predicate(t, "region", OpEQ, v2Text(t, "east")),
		v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01")),
	)
	sealed, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("ordered filters refused: valid=%v err=%v", sealed.Valid(), err)
	}
	filters, ok := sealed.Filters()
	predicates, predicatesOK := filters.Values()
	if !ok || !predicatesOK || len(predicates) != 2 ||
		predicates[0].Field() != v2Token(t, "region") || predicates[0].Op() != OpEQ ||
		predicates[1].Field() != v2Token(t, "business_day") || predicates[1].Op() != OpEQ {
		t.Fatalf("sealed filter order changed: %v ok=%v", predicates, ok)
	}
	digest := v2Digest(t, sealed)

	otherValidator, otherBinding, otherProposal := v2FilterCase(t, profile,
		v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01")),
		v2Predicate(t, "region", OpEQ, v2Text(t, "east")),
	)
	swapped, err := otherValidator.ValidateProposalV2(otherProposal, otherBinding)
	if err != nil || !swapped.Valid() {
		t.Fatalf("swapped filters refused: valid=%v err=%v", swapped.Valid(), err)
	}
	if v2Digest(t, swapped) == digest {
		t.Fatal("swapping filter order did not change the sealed digest")
	}
}
