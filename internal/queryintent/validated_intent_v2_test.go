package queryintent

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

// v2Field builds one approved profile field. A filterable field must carry the
// EQ operator, and a non-filterable field must carry none, or the profile
// normalizer refuses it.
func v2Field(t *testing.T, token string, ordinal int, kind analytic.ScalarType, filterable, output bool) analytic.FieldSpec {
	t.Helper()
	var operators []analytic.PredicateOperator
	if filterable {
		operators = []analytic.PredicateOperator{analytic.PredicateEQ}
	}
	physical := map[analytic.ScalarType]analytic.PhysicalType{
		analytic.ScalarBool:    analytic.PhysicalPGBool,
		analytic.ScalarInt:     analytic.PhysicalPGInt8,
		analytic.ScalarNumeric: analytic.PhysicalPGNumeric,
		analytic.ScalarText:    analytic.PhysicalPGText,
		analytic.ScalarDate:    analytic.PhysicalPGDate,
	}[kind]
	field, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: token, LogicalType: kind,
		PhysicalType: physical, Filterable: filterable, Groupable: true, Sortable: true,
		OutputAllowed: output, AllowedOps: operators,
	})
	if err != nil {
		t.Fatal(err)
	}
	return field
}

// v2Profile seals one valid approved profile with the fixed field set the
// digest cases share. Only the identity, coverage and limits vary per case.
func v2Profile(t *testing.T, datasetID string, version int64, coverage analytic.CoveragePolicy, limits analytic.ProfileLimits) analytic.DatasetProfile {
	t.Helper()
	key, err := analytic.NewProfileKey(datasetID, version)
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
		DatasetLabel: "Operations", DatasetDescription: "Operations records",
		Fields: []analytic.FieldSemanticsInput{
			{Token: "business_day", Label: "Business day", Description: "Business day", NullMeaning: "Not recorded"},
			{Token: "amount", Label: "Amount", Description: "Amount", NullMeaning: "Not measured"},
			{Token: "region", Label: "Region", Description: "Region", NullMeaning: "Not assigned"},
		},
		Measures: []analytic.MeasureSemanticsInput{{ID: "amount", Label: "Amount", Description: "Sum of amount"}},
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
		ID: "amount", Reducer: analytic.ReducerSum, NumeratorField: "amount", Unit: "units",
		NullPolicy: analytic.NullExcludeAndReport, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatal(err)
	}
	timePolicy, err := analytic.NewTimePolicy(analytic.TimePolicyInput{
		Kind: analytic.TimeBusinessDate, FieldToken: "business_day", ReportingTimezone: "UTC", Calendar: analytic.CalendarGregorian,
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source, Measures: []analytic.MeasureSpec{measure},
		Fields: []analytic.FieldSpec{
			v2Field(t, "business_day", 1, analytic.ScalarDate, false, false),
			v2Field(t, "amount", 2, analytic.ScalarNumeric, true, true),
			v2Field(t, "region", 3, analytic.ScalarText, true, true),
		},
		Semantics: semantics, Grain: grain, Time: timePolicy, Coverage: coverage, Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func v2Limits(t *testing.T, maxInputRows int64) analytic.ProfileLimits {
	t.Helper()
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: maxInputRows, MaxOutputGroups: 50, MaxPeriodDays: 31,
		MaxResultBytes: 1 << 20, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatal(err)
	}
	return limits
}

func v2Catalog(t *testing.T, id string, revision int64, entries ...analytic.CatalogEntryInput) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog(id, revision, entries)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func v2Active(profile analytic.DatasetProfile) analytic.CatalogEntryInput {
	return analytic.CatalogEntryInput{Profile: profile, State: analytic.ProfileActive}
}

func v2Retired(profile analytic.DatasetProfile) analytic.CatalogEntryInput {
	return analytic.CatalogEntryInput{Profile: profile, State: analytic.ProfileRetired}
}

func v2Base(t *testing.T) (analytic.DatasetProfileCatalog, analytic.DatasetProfile) {
	t.Helper()
	profile := v2Profile(t, "alpha", 1, analytic.CoverageUnknown, v2Limits(t, 10000))
	return v2Catalog(t, "catalog.operations", 7, v2Active(profile)), profile
}

func v2Ref(t *testing.T, profile analytic.DatasetProfile) DatasetProfileRef {
	t.Helper()
	key := profile.Key()
	return v2RefFields(t, key.DatasetID(), key.Version(), profile.Hash())
}

func v2RefFields(t *testing.T, datasetID string, version int64, profileHash string) DatasetProfileRef {
	t.Helper()
	ref, err := NewDatasetProfileRef(datasetID, version, profileHash)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func v2Token(t *testing.T, name string) FieldToken {
	token, err := NewFieldToken(name)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func v2Text(t *testing.T, value string) Scalar {
	scalar, err := TextScalar(value)
	if err != nil {
		t.Fatal(err)
	}
	return scalar
}

func v2Date(t *testing.T, value string) Scalar {
	scalar, err := DateScalar(value)
	if err != nil {
		t.Fatal(err)
	}
	return scalar
}

func v2Dimensions(t *testing.T, names ...string) Dimensions {
	tokens := make([]FieldToken, len(names))
	for index, name := range names {
		tokens[index] = v2Token(t, name)
	}
	dimensions, err := NewDimensions(tokens...)
	if err != nil {
		t.Fatal(err)
	}
	return dimensions
}

func v2OutputFields(t *testing.T, names ...string) OutputFields {
	tokens := make([]FieldToken, len(names))
	for index, name := range names {
		tokens[index] = v2Token(t, name)
	}
	fields, err := NewOutputFields(tokens...)
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func v2DimensionSort(t *testing.T, name string, direction SortDirection) SortKeys {
	key, err := NewDimensionSortKey(v2Token(t, name), direction)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewSortKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func v2MeasureSort(t *testing.T, id string, direction SortDirection) SortKeys {
	measure, err := NewMeasureRef(id)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewMeasureSortKey(measure, direction)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := NewSortKeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func v2Limit(t *testing.T, value int) Limit {
	limit, err := NewLimit(value)
	if err != nil {
		t.Fatal(err)
	}
	return limit
}

func v2Measure(t *testing.T, id string) MeasureRef {
	measure, err := NewMeasureRef(id)
	if err != nil {
		t.Fatal(err)
	}
	return measure
}

func v2Explicit(t *testing.T, start, end string) PeriodProposal {
	period, err := NewExplicitPeriod(start, end)
	if err != nil {
		t.Fatal(err)
	}
	return period
}

func v2Relative(t *testing.T, mode PeriodMode) PeriodProposal {
	period, err := NewRelativePeriod(mode)
	if err != nil {
		t.Fatal(err)
	}
	return period
}

func v2Predicate(t *testing.T, field string, op Operator, values ...Scalar) Predicate {
	predicate, err := NewPredicate(v2Token(t, field), op, values...)
	if err != nil {
		t.Fatal(err)
	}
	return predicate
}

func v2Predicates(t *testing.T, predicates ...Predicate) Predicates {
	value, err := NewPredicates(predicates...)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// v2FiltersFor is the two-predicate filter set every case starts from, in
// request order.
func v2FiltersFor(t *testing.T, region string) Predicates {
	t.Helper()
	return v2Predicates(t,
		v2Predicate(t, "region", OpEQ, v2Text(t, region)),
		v2Predicate(t, "business_day", OpGTE, v2Date(t, "2026-01-01")),
	)
}

type v2AggregateParts struct {
	Dataset    DatasetProfileRef
	Measure    MeasureRef
	Period     PeriodProposal
	Filters    Predicates
	Dimensions Dimensions
	Sort       SortKeys
	Limit      Limit
	Output     Output
}

func v2AggregatePartsFor(t *testing.T, profile analytic.DatasetProfile) v2AggregateParts {
	t.Helper()
	return v2AggregateParts{
		Dataset:    v2Ref(t, profile),
		Measure:    v2Measure(t, "amount"),
		Period:     v2Explicit(t, "2026-01-01", "2026-01-31"),
		Filters:    v2FiltersFor(t, "north"),
		Dimensions: v2Dimensions(t, "business_day"),
		Sort:       v2DimensionSort(t, "business_day", SortASC),
		Limit:      v2Limit(t, 25),
		Output:     OutputValue,
	}
}

func v2SealAggregate(t *testing.T, parts v2AggregateParts) ProposalV2 {
	t.Helper()
	proposal, err := NewAggregateProposalV2(parts.Dataset, parts.Measure, parts.Period, parts.Filters,
		parts.Dimensions, parts.Sort, parts.Limit, parts.Output)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

type v2LookupParts struct {
	Dataset      DatasetProfileRef
	Period       PeriodProposal
	Filters      Predicates
	OutputFields OutputFields
	Sort         SortKeys
	Limit        Limit
}

func v2LookupPartsFor(t *testing.T, profile analytic.DatasetProfile) v2LookupParts {
	t.Helper()
	return v2LookupParts{
		Dataset:      v2Ref(t, profile),
		Period:       v2Explicit(t, "2026-01-01", "2026-01-31"),
		Filters:      v2FiltersFor(t, "north"),
		OutputFields: v2OutputFields(t, "region", "amount"),
		Sort:         v2DimensionSort(t, "business_day", SortASC),
		Limit:        v2Limit(t, 25),
	}
}

func v2SealLookup(t *testing.T, parts v2LookupParts) ProposalV2 {
	t.Helper()
	proposal, err := NewLookupProposalV2(parts.Dataset, parts.Period, parts.Filters, parts.OutputFields,
		parts.Sort, parts.Limit)
	if err != nil {
		t.Fatal(err)
	}
	return proposal
}

// v2Parts returns the shared AGGREGATE parts with one case-specific override.
func v2Parts(t *testing.T, profile analytic.DatasetProfile, mutate func(*v2AggregateParts)) v2AggregateParts {
	t.Helper()
	parts := v2AggregatePartsFor(t, profile)
	if mutate != nil {
		mutate(&parts)
	}
	return parts
}

func v2Seal(t *testing.T, catalog analytic.DatasetProfileCatalog, profile analytic.DatasetProfile, proposal ProposalV2) ValidatedIntentV2 {
	t.Helper()
	period, ok := proposal.Period()
	if !ok {
		t.Fatal("proposal has no period")
	}
	resolution, err := resolvePeriodForProfileV2(profile, period, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := newValidatedIntentV2(catalog, profile, proposal, resolution)
	if err != nil || !sealed.Valid() {
		t.Fatalf("seal failed: valid=%v err=%v", sealed.Valid(), err)
	}
	return sealed
}

func v2Digest(t *testing.T, sealed ValidatedIntentV2) string {
	t.Helper()
	digest, ok := sealed.Digest()
	if !ok || !validProfileHash(digest) {
		t.Fatalf("digest=%q ok=%v", digest, ok)
	}
	return digest
}

func v2AllAccessorsFail(t *testing.T, value ValidatedIntentV2) {
	t.Helper()
	if value.Valid() {
		t.Fatal("invalid value reported valid")
	}
	catalogID, catalogIDOK := value.CatalogID()
	catalogRevision, catalogRevisionOK := value.CatalogRevision()
	catalogHash, catalogHashOK := value.CatalogHash()
	dataset, datasetOK := value.Dataset()
	operation, operationOK := value.Operation()
	period, periodOK := value.Period()
	resolvedPeriod, resolvedPeriodOK := value.ResolvedPeriod()
	capturedAt, capturedAtOK := value.CapturedAt()
	filters, filtersOK := value.Filters()
	measure, measureOK := value.Measure()
	dimensions, dimensionsOK := value.Dimensions()
	outputFields, outputFieldsOK := value.OutputFields()
	sort, sortOK := value.Sort()
	limit, limitOK := value.Limit()
	output, outputOK := value.Output()
	limits, limitsOK := value.Limits()
	coverage, coverageOK := value.Coverage()
	digest, digestOK := value.Digest()
	results := map[string]bool{
		"CatalogID": catalogIDOK, "CatalogRevision": catalogRevisionOK, "CatalogHash": catalogHashOK,
		"Dataset": datasetOK, "Operation": operationOK, "Period": periodOK, "ResolvedPeriod": resolvedPeriodOK, "CapturedAt": capturedAtOK, "Filters": filtersOK,
		"Measure": measureOK, "Dimensions": dimensionsOK, "OutputFields": outputFieldsOK,
		"Sort": sortOK, "Limit": limitOK, "Output": outputOK, "Limits": limitsOK,
		"Coverage": coverageOK, "Digest": digestOK,
	}
	for name, ok := range results {
		if ok {
			t.Fatalf("%s exposed by an invalid value", name)
		}
	}
	if digest != "" {
		t.Fatalf("Digest exposed %q by an invalid value", digest)
	}
	if catalogID != "" || catalogRevision != 0 || catalogHash != "" || !reflect.DeepEqual(dataset, DatasetProfileRef{}) ||
		operation != "" || !reflect.DeepEqual(period, PeriodProposal{}) || !reflect.DeepEqual(resolvedPeriod, ResolvedPeriodV2{}) ||
		capturedAt != "" || !reflect.DeepEqual(filters, Predicates{}) || !reflect.DeepEqual(measure, MeasureRef{}) ||
		!reflect.DeepEqual(dimensions, Dimensions{}) || !reflect.DeepEqual(outputFields, OutputFields{}) ||
		!reflect.DeepEqual(sort, SortKeys{}) || !reflect.DeepEqual(limit, Limit{}) || output != "" ||
		!reflect.DeepEqual(limits, analytic.ProfileLimits{}) || coverage != "" {
		t.Fatalf("invalid value exposed non-zero accessor values")
	}
}

func TestValidatedIntentV2SealsAggregateAndLookup(t *testing.T) {
	catalog, profile := v2Base(t)
	aggregate := v2Seal(t, catalog, profile, v2SealAggregate(t, v2AggregatePartsFor(t, profile)))

	if id, ok := aggregate.CatalogID(); !ok || id != catalog.ID() {
		t.Fatalf("catalog id=%q ok=%v", id, ok)
	}
	if revision, ok := aggregate.CatalogRevision(); !ok || revision != catalog.Revision() {
		t.Fatalf("catalog revision=%d ok=%v", revision, ok)
	}
	if hash, ok := aggregate.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("catalog hash=%q ok=%v", hash, ok)
	}
	if dataset, ok := aggregate.Dataset(); !ok || dataset != v2Ref(t, profile) {
		t.Fatalf("dataset=%v ok=%v", dataset, ok)
	}
	if operation, ok := aggregate.Operation(); !ok || operation != OperationAGGREGATE {
		t.Fatalf("operation=%q ok=%v", operation, ok)
	}
	period, ok := aggregate.Period()
	mode, modeOK := period.Mode()
	start, end, boundsOK := period.ExplicitBounds()
	if !ok || !modeOK || mode != PeriodEXPLICIT || !boundsOK || start != "2026-01-01" || end != "2026-01-31" {
		t.Fatalf("period=%q/%q/%q ok=%v", mode, start, end, ok)
	}
	filters, ok := aggregate.Filters()
	predicates, predicatesOK := filters.Values()
	if !ok || !predicatesOK || len(predicates) != 2 ||
		predicates[0].Field() != v2Token(t, "region") || predicates[0].Op() != OpEQ ||
		predicates[1].Field() != v2Token(t, "business_day") || predicates[1].Op() != OpGTE {
		t.Fatalf("filters=%v ok=%v", predicates, ok)
	}
	scalars := predicates[0].Values()
	text, textOK := scalars[0].Text()
	if len(scalars) != 1 || !textOK || text != "north" {
		t.Fatalf("scalar=%v text=%q ok=%v", scalars, text, textOK)
	}
	measure, ok := aggregate.Measure()
	measureID, measureOK := measure.MeasureID()
	if !ok || !measureOK || measureID != "amount" {
		t.Fatalf("measure=%q ok=%v", measureID, ok)
	}
	dimensions, ok := aggregate.Dimensions()
	fields, fieldsOK := dimensions.Fields()
	if !ok || !fieldsOK || len(fields) != 1 || fields[0] != v2Token(t, "business_day") {
		t.Fatalf("dimensions=%v ok=%v", fields, ok)
	}
	if _, ok := aggregate.OutputFields(); ok {
		t.Fatal("AGGREGATE exposes LOOKUP output fields")
	}
	sortKeys, ok := aggregate.Sort()
	keys, keysOK := sortKeys.Values()
	if !ok || !keysOK || len(keys) != 1 {
		t.Fatalf("sort=%v ok=%v", keys, ok)
	}
	if kind, kindOK := keys[0].TargetKind(); !kindOK || kind != SortTargetDIMENSION {
		t.Fatalf("sort target=%q ok=%v", kind, kindOK)
	}
	if direction, directionOK := keys[0].Direction(); !directionOK || direction != SortASC {
		t.Fatalf("sort direction=%q ok=%v", direction, directionOK)
	}
	limit, ok := aggregate.Limit()
	limitValue, limitOK := limit.Value()
	if !ok || !limitOK || limitValue != 25 {
		t.Fatalf("limit=%d ok=%v", limitValue, ok)
	}
	if output, ok := aggregate.Output(); !ok || output != OutputValue {
		t.Fatalf("output=%q ok=%v", output, ok)
	}
	if limits, ok := aggregate.Limits(); !ok || limits != profile.Limits() {
		t.Fatalf("limits=%v ok=%v", limits, ok)
	}
	if coverage, ok := aggregate.Coverage(); !ok || coverage != analytic.CoverageUnknown {
		t.Fatalf("coverage=%q ok=%v", coverage, ok)
	}
	aggregateDigest := v2Digest(t, aggregate)

	lookup := v2Seal(t, catalog, profile, v2SealLookup(t, v2LookupPartsFor(t, profile)))
	if operation, ok := lookup.Operation(); !ok || operation != OperationLOOKUP {
		t.Fatalf("lookup operation=%q ok=%v", operation, ok)
	}
	if _, ok := lookup.Measure(); ok {
		t.Fatal("LOOKUP exposes an AGGREGATE measure")
	}
	if _, ok := lookup.Dimensions(); ok {
		t.Fatal("LOOKUP exposes AGGREGATE dimensions")
	}
	outputFields, ok := lookup.OutputFields()
	names, namesOK := outputFields.Fields()
	if !ok || !namesOK || len(names) != 2 || names[0] != v2Token(t, "region") || names[1] != v2Token(t, "amount") {
		t.Fatalf("output fields=%v ok=%v", names, ok)
	}
	if output, ok := lookup.Output(); !ok || output != OutputRowset {
		t.Fatalf("lookup output=%q ok=%v", output, ok)
	}
	if hash, ok := lookup.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("lookup catalog hash=%q ok=%v", hash, ok)
	}
	if coverage, ok := lookup.Coverage(); !ok || coverage != analytic.CoverageUnknown {
		t.Fatalf("lookup coverage=%q ok=%v", coverage, ok)
	}
	if v2Digest(t, lookup) == aggregateDigest {
		t.Fatal("AGGREGATE and LOOKUP sealed the same digest")
	}
}

func TestValidatedIntentV2ZeroAndForgedAreInvalid(t *testing.T) {
	v2AllAccessorsFail(t, ValidatedIntentV2{})

	catalog, profile := v2Base(t)
	sealed := v2Seal(t, catalog, profile, v2SealAggregate(t, v2AggregatePartsFor(t, profile)))
	digest := v2Digest(t, sealed)
	otherCatalog := v2Catalog(t, "catalog.other", 1,
		v2Active(v2Profile(t, "beta", 1, analytic.CoverageUnknown, v2Limits(t, 10000))))

	unsealed := sealed
	unsealed.sealed = false
	catalogIDBlank := sealed
	catalogIDBlank.catalogID = ""
	catalogIDRebound := sealed
	catalogIDRebound.catalogID = "catalog.other"
	catalogRevisionForged := sealed
	catalogRevisionForged.catalogRevision = catalog.Revision() + 1
	catalogHashForged := sealed
	catalogHashForged.catalogHash = otherCatalog.Hash()
	proposalForged := sealed
	proposalForged.proposal = v2SealLookup(t, v2LookupPartsFor(t, profile))
	limitsForged := sealed
	limitsForged.limits = v2Limits(t, 20000)
	coverageForged := sealed
	coverageForged.coverage = analytic.CoverageSourceGuaranteed
	digestForged := sealed
	digestForged.digest = "sha256:" + strings.Repeat("0", 64)
	digestTruncated := sealed
	digestTruncated.digest = digest[:len(digest)-1]

	forged := map[string]ValidatedIntentV2{
		"unsealed":           unsealed,
		"catalog id blank":   catalogIDBlank,
		"catalog id rebound": catalogIDRebound,
		"catalog revision":   catalogRevisionForged,
		"catalog hash":       catalogHashForged,
		"proposal":           proposalForged,
		"limits":             limitsForged,
		"coverage":           coverageForged,
		"digest":             digestForged,
		"digest truncated":   digestTruncated,
	}
	for name, value := range forged {
		t.Run(name, func(t *testing.T) {
			v2AllAccessorsFail(t, value)
		})
	}
}

func TestValidatedIntentV2SealRefusals(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	period, periodOK := proposal.Period()
	if !periodOK {
		t.Fatal("baseline proposal has no period")
	}
	baseline, err := resolvePeriodForProfileV2(profile, period, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	other := v2Profile(t, "beta", 1, analytic.CoverageUnknown, v2Limits(t, 10000))

	cases := []struct {
		name       string
		catalog    analytic.DatasetProfileCatalog
		profile    analytic.DatasetProfile
		proposal   ProposalV2
		resolution periodResolutionV2
	}{
		{"zero catalog", analytic.DatasetProfileCatalog{}, profile, proposal, baseline},
		{"zero profile", catalog, analytic.DatasetProfile{}, proposal, baseline},
		{"zero proposal", catalog, profile, ProposalV2{}, periodResolutionV2{}},
		{"retired profile", v2Catalog(t, "catalog.operations", 9, v2Retired(profile)), profile, proposal, baseline},
		{"profile absent from catalog", v2Catalog(t, "catalog.other", 1, v2Active(other)), profile, proposal, baseline},
		{"proposal dataset mismatch", catalog, profile, v2SealAggregate(t, v2Parts(t, profile,
			func(parts *v2AggregateParts) { parts.Dataset = v2RefFields(t, "beta", 1, profile.Hash()) })), baseline},
		{"proposal version mismatch", catalog, profile, v2SealAggregate(t, v2Parts(t, profile,
			func(parts *v2AggregateParts) { parts.Dataset = v2RefFields(t, "alpha", 2, profile.Hash()) })), baseline},
		{"proposal hash mismatch", catalog, profile, v2SealAggregate(t, v2Parts(t, profile,
			func(parts *v2AggregateParts) {
				parts.Dataset = v2RefFields(t, "alpha", 1, other.Hash())
			})), baseline},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			sealed, err := newValidatedIntentV2(test.catalog, test.profile, test.proposal, test.resolution)
			if err == nil || CodeOf(err) != CodeInvalidProposal || err.Error() != string(CodeInvalidProposal) ||
				ClarificationOf(err) == "" {
				t.Fatalf("refusal code=%q text=%q err=%v", CodeOf(err), ClarificationOf(err), err)
			}
			for _, leaked := range []string{"alpha", "beta", "sha256:", "amount", "region"} {
				if strings.Contains(err.Error(), leaked) || strings.Contains(ClarificationOf(err), leaked) {
					t.Fatalf("refusal leaked %q in %q", leaked, err)
				}
			}
			if !reflect.DeepEqual(sealed, ValidatedIntentV2{}) {
				t.Fatal("refusal returned a non-zero value")
			}
		})
	}
	sealed, err := newValidatedIntentV2(catalog, profile, proposal, periodResolutionV2{})
	if err == nil || CodeOf(err) != CodeInvalidProposal || !reflect.DeepEqual(sealed, ValidatedIntentV2{}) {
		t.Fatalf("zero resolution refusal=%v/%v", sealed, err)
	}
}

func TestValidatedIntentV2DigestIsDeterministic(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	first := v2Digest(t, v2Seal(t, catalog, profile, proposal))
	second := v2Digest(t, v2Seal(t, catalog, profile, proposal))
	if first != second {
		t.Fatalf("digest changed between seals: %q != %q", first, second)
	}
	rebuiltCatalog := v2Catalog(t, "catalog.operations", 7, v2Active(profile))
	rebuilt := v2Digest(t, v2Seal(t, rebuiltCatalog, profile, v2SealAggregate(t, v2AggregatePartsFor(t, profile))))
	if rebuilt != first {
		t.Fatalf("rebuilt fixture sealed a different digest: %q != %q", rebuilt, first)
	}
}

func TestValidatedIntentV2DigestSensitivity(t *testing.T) {
	catalog, profile := v2Base(t)
	base := v2Digest(t, v2Seal(t, catalog, profile, v2SealAggregate(t, v2AggregatePartsFor(t, profile))))
	agg := func(mutate func(*v2AggregateParts)) ProposalV2 {
		return v2SealAggregate(t, v2Parts(t, profile, mutate))
	}
	other := v2Profile(t, "beta", 1, analytic.CoverageUnknown, v2Limits(t, 10000))
	alphaV2 := v2Profile(t, "alpha", 2, analytic.CoverageUnknown, v2Limits(t, 10000))
	wide := v2Profile(t, "alpha", 1, analytic.CoverageUnknown, v2Limits(t, 20000))
	guaranteed := v2Profile(t, "alpha", 1, analytic.CoverageSourceGuaranteed, v2Limits(t, 10000))

	cases := []struct {
		name     string
		catalog  analytic.DatasetProfileCatalog
		profile  analytic.DatasetProfile
		proposal ProposalV2
	}{
		{"catalog id", v2Catalog(t, "catalog.other", 7, v2Active(profile)), profile,
			v2SealAggregate(t, v2AggregatePartsFor(t, profile))},
		{"catalog revision", v2Catalog(t, "catalog.operations", 8, v2Active(profile)), profile,
			v2SealAggregate(t, v2AggregatePartsFor(t, profile))},
		{"catalog entries", v2Catalog(t, "catalog.operations", 7, v2Active(profile), v2Active(other)), profile,
			v2SealAggregate(t, v2AggregatePartsFor(t, profile))},
		{"dataset id", v2Catalog(t, "catalog.operations", 7, v2Active(other)), other,
			v2SealAggregate(t, v2AggregatePartsFor(t, other))},
		{"dataset version", v2Catalog(t, "catalog.operations", 7, v2Active(alphaV2)), alphaV2,
			v2SealAggregate(t, v2AggregatePartsFor(t, alphaV2))},
		{"period bounds", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Period = v2Explicit(t, "2026-02-01", "2026-02-28")
		})},
		{"alternate period request", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Period = v2Explicit(t, "2026-02-01", "2026-02-27")
		})},
		{"filter value", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Filters = v2FiltersFor(t, "south")
		})},
		{"filter scalar kind", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Filters.values[0].values[0] = IntScalar(7)
		})},
		{"filter order", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Filters.values[0], parts.Filters.values[1] = parts.Filters.values[1], parts.Filters.values[0]
		})},
		{"operation arm", catalog, profile, v2SealLookup(t, v2LookupPartsFor(t, profile))},
		{"sort target", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Sort = v2MeasureSort(t, "amount", SortASC)
		})},
		{"sort direction", catalog, profile, agg(func(parts *v2AggregateParts) {
			parts.Sort = v2DimensionSort(t, "business_day", SortDESC)
		})},
		{"limit", catalog, profile, agg(func(parts *v2AggregateParts) { parts.Limit = v2Limit(t, 26) })},
		{"output", catalog, profile, agg(func(parts *v2AggregateParts) { parts.Output = OutputRowset })},
		{"limits", v2Catalog(t, "catalog.operations", 7, v2Active(wide)), wide,
			v2SealAggregate(t, v2AggregatePartsFor(t, wide))},
		{"coverage", v2Catalog(t, "catalog.operations", 7, v2Active(guaranteed)), guaranteed,
			v2SealAggregate(t, v2AggregatePartsFor(t, guaranteed))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			digest := v2Digest(t, v2Seal(t, test.catalog, test.profile, test.proposal))
			if digest == base {
				t.Fatalf("digest %q did not change for the %s case", digest, test.name)
			}
		})
	}
}

func TestValidatedIntentV2FilterAccessorIsDetached(t *testing.T) {
	catalog, profile := v2Base(t)
	sealed := v2Seal(t, catalog, profile, v2SealAggregate(t, v2AggregatePartsFor(t, profile)))
	digest := v2Digest(t, sealed)

	detached, ok := sealed.Filters()
	if !ok || int(detached.count) != 2 {
		t.Fatalf("detached filters ok=%v", ok)
	}
	detached.values[0].field = v2Token(t, "amount")
	detached.values[0].op = OpGTE
	detached.values[0].values[0] = IntScalar(99)

	again, ok := sealed.Filters()
	predicates, predicatesOK := again.Values()
	if !ok || !predicatesOK || len(predicates) != 2 ||
		predicates[0].Field() != v2Token(t, "region") || predicates[0].Op() != OpEQ {
		t.Fatalf("sealed filters changed: %v ok=%v", predicates, ok)
	}
	scalars := predicates[0].Values()
	text, textOK := scalars[0].Text()
	if len(scalars) != 1 || !textOK || text != "north" {
		t.Fatalf("sealed scalar changed: %v", scalars)
	}
	if !sealed.Valid() || v2Digest(t, sealed) != digest {
		t.Fatal("sealed value changed after accessor mutation")
	}
}

// Adjacent int64 values above 2^53 must not collide: every int64 semantic
// member is projected as exact base-10 text, never as a JSON number.
func TestValidatedIntentV2ExactInt64Encoding(t *testing.T) {
	catalog, profile := v2Base(t)
	seal := func(sealCatalog analytic.DatasetProfileCatalog, sealProfile analytic.DatasetProfile, parts v2AggregateParts) string {
		return v2Digest(t, v2Seal(t, sealCatalog, sealProfile, v2SealAggregate(t, parts)))
	}
	scalar := func(value int64) string {
		return seal(catalog, profile, v2Parts(t, profile, func(parts *v2AggregateParts) {
			parts.Filters = v2Predicates(t, v2Predicate(t, "region", OpEQ, IntScalar(value)))
		}))
	}
	if scalar(9007199254740992) == scalar(9007199254740993) {
		t.Fatal("adjacent large INT predicates sealed the same digest")
	}
	catalogRevision := func(revision int64) string {
		return seal(v2Catalog(t, "catalog.operations", revision, v2Active(profile)), profile,
			v2AggregatePartsFor(t, profile))
	}
	if catalogRevision(9007199254740992) == catalogRevision(9007199254740993) {
		t.Fatal("adjacent large catalog revisions sealed the same digest")
	}
	profileVersion := func(version int64) string {
		large := v2Profile(t, "alpha", version, analytic.CoverageUnknown, v2Limits(t, 10000))
		return seal(v2Catalog(t, "catalog.operations", 7, v2Active(large)), large, v2AggregatePartsFor(t, large))
	}
	if profileVersion(9007199254740992) == profileVersion(9007199254740993) {
		t.Fatal("adjacent large profile versions sealed the same digest")
	}
}

// The sealed value must own its predicate values: mutating the input proposal's
// internal slice after sealing must not change the seal.
func TestValidatedIntentV2SealDetachesProposalFilters(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	sealed := v2Seal(t, catalog, profile, proposal)
	digest := v2Digest(t, sealed)

	proposal.filters.values[0].values[0] = IntScalar(424242)
	if !sealed.Valid() || v2Digest(t, sealed) != digest {
		t.Fatal("mutating the input proposal changed the sealed intent")
	}
	filters, ok := sealed.Filters()
	predicates, predicatesOK := filters.Values()
	if !ok || !predicatesOK || len(predicates) != 2 {
		t.Fatalf("sealed filters=%v ok=%v", predicates, ok)
	}
	scalars := predicates[0].Values()
	text, textOK := scalars[0].Text()
	if len(scalars) != 1 || !textOK || text != "north" {
		t.Fatalf("sealed filter changed: %v", scalars)
	}
}
