package analyticsource

import (
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// TestScalarReadPlanMapsSelectedSourceOrdinals proves one successful ungrouped
// scalar SUM plan selects exactly the profile's non-contiguous source ordinals
// 2, 5 and 8 and maps them onto Snapshot positions 1, 2 and 3, so the mapping
// result fields never carry a source ordinal.
func TestScalarReadPlanMapsSelectedSourceOrdinals(t *testing.T) {
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)

	region, err := queryintent.NewFieldToken("region")
	if err != nil {
		t.Fatalf("build region token: %v", err)
	}
	regionValue, err := queryintent.TextScalar("north")
	if err != nil {
		t.Fatalf("build region scalar: %v", err)
	}
	predicate, err := queryintent.NewPredicate(region, queryintent.OpEQ, regionValue)
	if err != nil {
		t.Fatalf("build region predicate: %v", err)
	}
	filters, err := queryintent.NewPredicates(predicate)
	if err != nil {
		t.Fatalf("build predicates: %v", err)
	}

	proposal := scalarPlanAggregateProposal(t, profile, "assigned_orders", filters,
		scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue)
	intent := scalarPlanSeal(t, catalog, proposal)

	plan, err := compileScalarReadPlan(profile, intent)
	if err != nil {
		t.Fatalf("compile scalar read plan: %v", err)
	}

	// Selected source ordinals are the period field (2), the EQ filter field
	// (5) and the measure numerator (8); the grain key is the period field too.
	want := scalarReadPlan{
		read: repositoryFilteredRead(
			[]int{2, 5, 8},
			[]int{2},
			8,
			[]postgresqlquery.EqualityPredicate{{
				Ordinal: 5,
				Value:   postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeText, Text: "north"},
			}},
			&postgresqlquery.HalfOpenPeriod{
				Ordinal: 2, LogicalType: postgresqlquery.TypeDate,
				Start: "2026-09-10", EndExclusive: "2026-09-11",
			},
		),
		measureOrdinal:   3,
		identityOrdinals: []int{1},
	}
	if !reflect.DeepEqual(plan, want) {
		t.Fatalf("compiled plan = %+v want %+v", plan, want)
	}
	if plan.identityOrdinals[0] != 1 || plan.measureOrdinal != 3 {
		t.Fatalf("snapshot mapping = identity %v measure %d want identity [1] measure 3",
			plan.identityOrdinals, plan.measureOrdinal)
	}
}

// TestScalarReadPlanScalarConversions proves the seven closed scalar
// conversions of the filter mapping, including the exact logical type and value
// carrier each one uses.
func TestScalarReadPlanScalarConversions(t *testing.T) {
	numeric := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.NumericScalar("12.5") })
	text := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.TextScalar("north") })
	date := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.DateScalar("2026-09-10") })
	timestamp := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.TimestampScalar("2026-09-10T08:30:00") })
	timestamptz := scalarPlanScalar(t, func() (queryintent.Scalar, error) {
		return queryintent.TimestamptzScalar("2026-09-10T08:30:00Z")
	})

	cases := []struct {
		name    string
		logical analytic.ScalarType
		value   queryintent.Scalar
		want    postgresqlquery.ScalarArgument
	}{
		{"BOOL", analytic.ScalarBool, queryintent.BoolScalar(true),
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeBool, Bool: true}},
		{"INT", analytic.ScalarInt, queryintent.IntScalar(42),
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeInt, Int: 42}},
		{"NUMERIC", analytic.ScalarNumeric, numeric,
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeNumeric, Text: "12.5"}},
		{"TEXT", analytic.ScalarText, text,
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeText, Text: "north"}},
		{"DATE", analytic.ScalarDate, date,
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeDate, Text: "2026-09-10"}},
		{"TIMESTAMP", analytic.ScalarTimestamp, timestamp,
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeTimestamp, Text: "2026-09-10T08:30:00"}},
		{"TIMESTAMPTZ", analytic.ScalarTimestamptz, timestamptz,
			postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeTimestamptz, Text: "2026-09-10T08:30:00Z"}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, ok := scalarArgument(test.logical, test.value)
			if !ok {
				t.Fatalf("scalarArgument(%s) refused a matching kind", test.name)
			}
			if got != test.want {
				t.Fatalf("scalarArgument(%s) = %+v want %+v", test.name, got, test.want)
			}
		})
	}
}

// TestScalarReadPlanClosedMappingRefusals proves the two closed mappings that a
// sealed intent can never contradict - the period time kind and the filter
// scalar kind - refuse a non-NONE-only time kind and a kind/logical-type
// mismatch. A ValidatedIntentV2 is always resolved against the profile it was
// sealed for, so these two mismatch branches are provable only at the mapping
// helpers.
func TestScalarReadPlanClosedMappingRefusals(t *testing.T) {
	if _, ok := periodLogicalType(analytic.TimeNone); ok {
		t.Fatal("periodLogicalType accepted NONE")
	}
	for _, kind := range []analytic.TimeKind{"", "DATE", "business_date"} {
		if _, ok := periodLogicalType(kind); ok {
			t.Fatalf("periodLogicalType accepted %q", kind)
		}
	}
	if _, ok := scalarArgument(analytic.ScalarText, queryintent.IntScalar(7)); ok {
		t.Fatal("scalarArgument accepted INT against TEXT")
	}
	if _, ok := scalarArgument(analytic.ScalarNumeric, queryintent.BoolScalar(true)); ok {
		t.Fatal("scalarArgument accepted BOOL against NUMERIC")
	}
}

// TestScalarReadPlanRefusals proves every input outside the accepted shape is
// refused with the exact zero plan and the exact unwrapped errMismatch.
func TestScalarReadPlanRefusals(t *testing.T) {
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)
	foreign := scalarPlanProfile(t, "other_orders", 3)

	valid := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))

	region := scalarPlanToken(t, "region")
	grouped, err := queryintent.NewDimensions(region)
	if err != nil {
		t.Fatalf("build grouped dimensions: %v", err)
	}
	sortKey, err := queryintent.NewDimensionSortKey(region, queryintent.SortASC)
	if err != nil {
		t.Fatalf("build sort key: %v", err)
	}
	sorted, err := queryintent.NewSortKeys(sortKey)
	if err != nil {
		t.Fatalf("build sort keys: %v", err)
	}
	gteValue := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.NumericScalar("100") })
	gte, err := queryintent.NewPredicate(scalarPlanToken(t, "order_total"), queryintent.OpGTE, gteValue)
	if err != nil {
		t.Fatalf("build GTE predicate: %v", err)
	}
	gteFilters, err := queryintent.NewPredicates(gte)
	if err != nil {
		t.Fatalf("build GTE predicates: %v", err)
	}

	cases := []struct {
		name string
		plan func() (scalarReadPlan, error)
	}{
		{"zero profile", func() (scalarReadPlan, error) {
			return compileScalarReadPlan(analytic.DatasetProfile{}, valid)
		}},
		{"zero intent", func() (scalarReadPlan, error) {
			return compileScalarReadPlan(profile, queryintent.ValidatedIntentV2{})
		}},
		{"lookup operation", func() (scalarReadPlan, error) {
			return compileScalarReadPlan(profile, scalarPlanLookupIntent(t, profile, catalog))
		}},
		{"grouped shape", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
				scalarPlanEmptyFilters(t), grouped, scalarPlanEmptySort(t), 1, queryintent.OutputValue))
			return compileScalarReadPlan(profile, intent)
		}},
		{"rowset shape", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
				scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputRowset))
			return compileScalarReadPlan(profile, intent)
		}},
		{"limit shape", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
				scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 2, queryintent.OutputValue))
			return compileScalarReadPlan(profile, intent)
		}},
		{"sort shape", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
				scalarPlanEmptyFilters(t), grouped, sorted, 1, queryintent.OutputValue))
			return compileScalarReadPlan(profile, intent)
		}},
		{"foreign profile", func() (scalarReadPlan, error) {
			return compileScalarReadPlan(foreign, valid)
		}},
		{"count rows reducer", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "row_count",
				scalarPlanEmptyFilters(t), scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))
			return compileScalarReadPlan(profile, intent)
		}},
		{"inequality filter", func() (scalarReadPlan, error) {
			intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
				gteFilters, scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))
			return compileScalarReadPlan(profile, intent)
		}},
		{"filter scalar type", func() (scalarReadPlan, error) {
			// A sealed intent can never carry a filter whose scalar kind
			// disagrees with the profile the validator resolved it against, so
			// the mismatch branch is probed at the closed mapping itself.
			if _, ok := scalarArgument(analytic.ScalarText, queryintent.BoolScalar(true)); ok {
				return scalarReadPlan{}, nil
			}
			return scalarReadPlan{}, errMismatch
		}},
		{"period time kind", func() (scalarReadPlan, error) {
			if _, ok := periodLogicalType(analytic.TimeNone); ok {
				return scalarReadPlan{}, nil
			}
			return scalarReadPlan{}, errMismatch
		}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			plan, err := test.plan()
			if err != errMismatch {
				t.Fatalf("refusal = %v want the exact unwrapped errMismatch", err)
			}
			if !reflect.DeepEqual(plan, scalarReadPlan{}) {
				t.Fatalf("refused plan = %+v want the exact zero value", plan)
			}
		})
	}
}

// TestScalarReadPlanRefusesDuplicateEquality proves a sealed intent carrying two
// EQ predicates that resolve to the same approved source ordinal (the same
// filterable region field) is refused with the exact zero plan and the exact
// unwrapped errMismatch, because it would silently duplicate one equality.
func TestScalarReadPlanRefusesDuplicateEquality(t *testing.T) {
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)

	region := scalarPlanToken(t, "region")
	north := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.TextScalar("north") })
	south := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.TextScalar("south") })
	first, err := queryintent.NewPredicate(region, queryintent.OpEQ, north)
	if err != nil {
		t.Fatalf("build first predicate: %v", err)
	}
	second, err := queryintent.NewPredicate(region, queryintent.OpEQ, south)
	if err != nil {
		t.Fatalf("build second predicate: %v", err)
	}
	filters, err := queryintent.NewPredicates(first, second)
	if err != nil {
		t.Fatalf("build duplicate predicates: %v", err)
	}
	intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		filters, scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))

	plan, err := compileScalarReadPlan(profile, intent)
	if err != errMismatch {
		t.Fatalf("duplicate equality refusal = %v want the exact unwrapped errMismatch", err)
	}
	if !reflect.DeepEqual(plan, scalarReadPlan{}) {
		t.Fatalf("refused plan = %+v want the exact zero value", plan)
	}
}

// TestScalarReadPlanIsDetachedAndZeroOnRefusal proves the compiled plan owns
// freshly allocated slices: mutating the returned plan reaches neither the
// sealed intent nor a later compilation, and a refused call returns the exact
// zero plan.
func TestScalarReadPlanIsDetachedAndZeroOnRefusal(t *testing.T) {
	profile := scalarPlanProfile(t, "scooter_orders", 3)
	catalog := scalarPlanCatalog(t, profile)

	region := scalarPlanToken(t, "region")
	regionValue := scalarPlanScalar(t, func() (queryintent.Scalar, error) { return queryintent.TextScalar("north") })
	predicate, err := queryintent.NewPredicate(region, queryintent.OpEQ, regionValue)
	if err != nil {
		t.Fatalf("build predicate: %v", err)
	}
	filters, err := queryintent.NewPredicates(predicate)
	if err != nil {
		t.Fatalf("build predicates: %v", err)
	}
	intent := scalarPlanSeal(t, catalog, scalarPlanAggregateProposal(t, profile, "assigned_orders",
		filters, scalarPlanEmptyDimensions(t), scalarPlanEmptySort(t), 1, queryintent.OutputValue))

	expected, err := compileScalarReadPlan(profile, intent)
	if err != nil {
		t.Fatalf("compile expected plan: %v", err)
	}
	plan, err := compileScalarReadPlan(profile, intent)
	if err != nil {
		t.Fatalf("compile plan: %v", err)
	}

	plan.read.Selection.OutputOrdinals[0] = 999
	plan.read.Selection.IdentityOrdinals[0] = 999
	plan.read.Selection.MeasureOrdinal = 999
	plan.read.Equalities[0].Ordinal = 999
	plan.read.Equalities[0].Value.Text = "mutated"
	plan.read.Period.Ordinal = 999
	plan.read.Period.Start = "mutated"
	plan.measureOrdinal = 999
	plan.identityOrdinals[0] = 999

	recompiled, err := compileScalarReadPlan(profile, intent)
	if err != nil {
		t.Fatalf("recompile plan: %v", err)
	}
	if !reflect.DeepEqual(recompiled, expected) {
		t.Fatalf("recompiled plan = %+v want the unmuted %+v", recompiled, expected)
	}
	held, ok := intent.Filters()
	if !ok {
		t.Fatal("sealed intent lost its filters")
	}
	values, ok := held.Values()
	if !ok || len(values) != 1 {
		t.Fatalf("intent filters = %v ok=%v want one predicate", values, ok)
	}
	if text, textOK := values[0].Values()[0].Text(); !textOK || text != "north" {
		t.Fatalf("intent filter text = %q ok=%v want north", text, textOK)
	}

	refused, refuseErr := compileScalarReadPlan(analytic.DatasetProfile{}, intent)
	if refuseErr != errMismatch {
		t.Fatalf("refusal = %v want the exact unwrapped errMismatch", refuseErr)
	}
	if !reflect.DeepEqual(refused, scalarReadPlan{}) {
		t.Fatalf("refused plan = %+v want the exact zero value", refused)
	}
}

// scalarPlanProfile seals one valid eight-field BUSINESS_DATE profile whose
// selected source ordinals are deliberately non-contiguous: the period and
// grain field is 2, the EQ filter field is 5 and the SUM numerator is 8.
func scalarPlanProfile(t *testing.T, datasetID string, version int64) analytic.DatasetProfile {
	t.Helper()

	key, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatalf("build profile key %q/%d: %v", datasetID, version, err)
	}
	source, err := analytic.NewSourceProjectionSpec(analytic.SourceProjectionInput{
		SourceScopeID: "src_scope_plan", ConnectionID: "conn_plan", DatabaseIdentity: "db_plan",
		ProjectionLineageID: "lineage_plan", ProjectionRevision: 2,
		ProjectionContractHash: "sha256:" + strings.Repeat("a", 64), ExposedSchemaRevision: 3,
		ExposedSchemaHash: "sha256:" + strings.Repeat("b", 64), SchemaName: "plan_schema",
		RelationName: "plan_relation", RelationKind: analytic.RelationView,
	})
	if err != nil {
		t.Fatalf("build source projection: %v", err)
	}

	fields := []analytic.FieldSpec{
		scalarPlanField(t, "note", "note_phys", 1, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "business_day", "business_day_phys", 2, analytic.ScalarDate, analytic.PhysicalPGDate,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "channel", "channel_phys", 3, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "currency", "currency_phys", 4, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "region", "region_phys", 5, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "warehouse", "warehouse_phys", 6, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "customer", "customer_phys", 7, analytic.ScalarText, analytic.PhysicalPGText,
			[]analytic.PredicateOperator{analytic.PredicateEQ}),
		scalarPlanField(t, "order_total", "order_total_phys", 8, analytic.ScalarNumeric, analytic.PhysicalPGNumeric,
			[]analytic.PredicateOperator{analytic.PredicateEQ, analytic.PredicateGTE}),
	}

	sumMeasure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: "assigned_orders", Reducer: analytic.ReducerSum, NumeratorField: "order_total",
		Unit: "count", NullPolicy: analytic.NullExcludeAndReport, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatalf("build SUM measure: %v", err)
	}
	countMeasure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: "row_count", Reducer: analytic.ReducerCountRows, Unit: "rows",
		NullPolicy: analytic.NullNotApplicable, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatalf("build COUNT_ROWS measure: %v", err)
	}

	semantics := scalarPlanSemantics(t)
	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description: "One row per business day", KeyFields: []string{"business_day"},
		DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatalf("build grain: %v", err)
	}
	timePolicy, err := analytic.NewTimePolicy(analytic.TimePolicyInput{
		Kind: analytic.TimeBusinessDate, FieldToken: "business_day",
		ReportingTimezone: "UTC", Calendar: analytic.CalendarGregorian,
	})
	if err != nil {
		t.Fatalf("build time policy: %v", err)
	}
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: 1000, MaxOutputGroups: 20, MaxPeriodDays: 31,
		MaxResultBytes: 1048576, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("build limits: %v", err)
	}

	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source, Fields: fields,
		Measures: []analytic.MeasureSpec{sumMeasure, countMeasure}, Semantics: semantics,
		Grain: grain, Time: timePolicy, Coverage: analytic.CoverageSourceGuaranteed, Limits: limits,
	})
	if err != nil {
		t.Fatalf("seal profile %q/%d: %v", datasetID, version, err)
	}
	return profile
}

func scalarPlanField(
	t *testing.T,
	token, physical string,
	ordinal int,
	logical analytic.ScalarType,
	physicalType analytic.PhysicalType,
	allowedOps []analytic.PredicateOperator,
) analytic.FieldSpec {
	t.Helper()
	field, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: physical,
		LogicalType: logical, PhysicalType: physicalType, Nullable: false,
		Filterable: true, Groupable: true, Sortable: true, OutputAllowed: true,
		AllowedOps: allowedOps,
	})
	if err != nil {
		t.Fatalf("build field %q: %v", token, err)
	}
	return field
}

func scalarPlanSemantics(t *testing.T) analytic.ProfileSemantics {
	t.Helper()
	fields := []analytic.FieldSemanticsInput{
		{Token: "note", Label: "Note", Description: "Free note", NullMeaning: "Not noted"},
		{Token: "business_day", Label: "Business day", Description: "Reporting date", NullMeaning: "Not assigned"},
		{Token: "channel", Label: "Channel", Description: "Sales channel", NullMeaning: "Unknown"},
		{Token: "currency", Label: "Currency", Description: "Order currency", NullMeaning: "Unknown"},
		{Token: "region", Label: "Region", Description: "Delivery region", NullMeaning: "Unknown"},
		{Token: "warehouse", Label: "Warehouse", Description: "Fulfilling warehouse", NullMeaning: "Unknown"},
		{Token: "customer", Label: "Customer", Description: "Customer name", NullMeaning: "Unknown"},
		{Token: "order_total", Label: "Order total", Description: "Summed order value", NullMeaning: "Not measured"},
	}
	measures := []analytic.MeasureSemanticsInput{
		{ID: "assigned_orders", Label: "Assigned orders", Description: "Sum of assigned order totals"},
		{ID: "row_count", Label: "Row count", Description: "Number of source rows"},
	}
	semantics, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel: "Scalar plan fixture", DatasetDescription: "Scalar plan business records",
		Fields: fields, Measures: measures,
	})
	if err != nil {
		t.Fatalf("build semantics: %v", err)
	}
	return semantics
}

func scalarPlanCatalog(t *testing.T, profile analytic.DatasetProfile) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog("catalog.scalar.plan", 11,
		[]analytic.CatalogEntryInput{{Profile: profile, State: analytic.ProfileActive}})
	if err != nil {
		t.Fatalf("build catalog: %v", err)
	}
	return catalog
}

func scalarPlanAggregateProposal(
	t *testing.T,
	profile analytic.DatasetProfile,
	measureID string,
	filters queryintent.Predicates,
	dimensions queryintent.Dimensions,
	sortKeys queryintent.SortKeys,
	limitValue int,
	output queryintent.Output,
) queryintent.ProposalV2 {
	t.Helper()
	ref, err := queryintent.NewDatasetProfileRef(profile.Key().DatasetID(), profile.Key().Version(), profile.Hash())
	if err != nil {
		t.Fatalf("build dataset ref: %v", err)
	}
	measure, err := queryintent.NewMeasureRef(measureID)
	if err != nil {
		t.Fatalf("build measure ref %q: %v", measureID, err)
	}
	period, err := queryintent.NewExplicitPeriod("2026-09-10", "2026-09-11")
	if err != nil {
		t.Fatalf("build explicit period: %v", err)
	}
	limit, err := queryintent.NewLimit(limitValue)
	if err != nil {
		t.Fatalf("build limit %d: %v", limitValue, err)
	}
	proposal, err := queryintent.NewAggregateProposalV2(ref, measure, period, filters, dimensions, sortKeys, limit, output)
	if err != nil {
		t.Fatalf("build aggregate proposal: %v", err)
	}
	return proposal
}

func scalarPlanLookupIntent(t *testing.T, profile analytic.DatasetProfile, catalog analytic.DatasetProfileCatalog) queryintent.ValidatedIntentV2 {
	t.Helper()
	ref, err := queryintent.NewDatasetProfileRef(profile.Key().DatasetID(), profile.Key().Version(), profile.Hash())
	if err != nil {
		t.Fatalf("build dataset ref: %v", err)
	}
	period, err := queryintent.NewExplicitPeriod("2026-09-10", "2026-09-11")
	if err != nil {
		t.Fatalf("build explicit period: %v", err)
	}
	outputFields, err := queryintent.NewOutputFields(scalarPlanToken(t, "order_total"))
	if err != nil {
		t.Fatalf("build output fields: %v", err)
	}
	limit, err := queryintent.NewLimit(1)
	if err != nil {
		t.Fatalf("build limit: %v", err)
	}
	proposal, err := queryintent.NewLookupProposalV2(ref, period, scalarPlanEmptyFilters(t),
		outputFields, scalarPlanEmptySort(t), limit)
	if err != nil {
		t.Fatalf("build lookup proposal: %v", err)
	}
	return scalarPlanSeal(t, catalog, proposal)
}

func scalarPlanSeal(t *testing.T, catalog analytic.DatasetProfileCatalog, proposal queryintent.ProposalV2) queryintent.ValidatedIntentV2 {
	t.Helper()
	binding, err := queryintent.NewCatalogBindingV2(catalog.ID(), catalog.Revision(), catalog.Hash())
	if err != nil {
		t.Fatalf("build catalog binding: %v", err)
	}
	validator, err := queryintent.NewValidatorV2(catalog)
	if err != nil {
		t.Fatalf("build validator: %v", err)
	}
	intent, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil {
		t.Fatalf("seal proposal: %v", err)
	}
	if !intent.Valid() {
		t.Fatal("sealed intent is not valid")
	}
	return intent
}

func scalarPlanEmptyFilters(t *testing.T) queryintent.Predicates {
	t.Helper()
	filters, err := queryintent.NewPredicates()
	if err != nil {
		t.Fatalf("build empty predicates: %v", err)
	}
	return filters
}

func scalarPlanEmptyDimensions(t *testing.T) queryintent.Dimensions {
	t.Helper()
	dimensions, err := queryintent.NewDimensions()
	if err != nil {
		t.Fatalf("build empty dimensions: %v", err)
	}
	return dimensions
}

func scalarPlanEmptySort(t *testing.T) queryintent.SortKeys {
	t.Helper()
	sortKeys, err := queryintent.NewSortKeys()
	if err != nil {
		t.Fatalf("build empty sort keys: %v", err)
	}
	return sortKeys
}

func scalarPlanToken(t *testing.T, name string) queryintent.FieldToken {
	t.Helper()
	token, err := queryintent.NewFieldToken(name)
	if err != nil {
		t.Fatalf("build field token %q: %v", name, err)
	}
	return token
}

func scalarPlanScalar(t *testing.T, build func() (queryintent.Scalar, error)) queryintent.Scalar {
	t.Helper()
	value, err := build()
	if err != nil {
		t.Fatalf("build scalar: %v", err)
	}
	return value
}

// repositoryFilteredRead assembles the expected read plan literal.
func repositoryFilteredRead(
	outputs []int,
	identities []int,
	measure int,
	equalities []postgresqlquery.EqualityPredicate,
	period *postgresqlquery.HalfOpenPeriod,
) repository.PostgreSQLFilteredRead {
	return repository.PostgreSQLFilteredRead{
		Selection: postgresqlquery.ScalarReadSelection{
			OutputOrdinals: outputs, IdentityOrdinals: identities, MeasureOrdinal: measure,
		},
		Equalities: equalities,
		Period:     period,
	}
}
