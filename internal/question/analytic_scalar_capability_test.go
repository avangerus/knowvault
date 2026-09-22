package question

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// TestAnalyticScalarCapabilityProjectsOnlyCheckedProfiles proves the capability
// carries only the candidates it actually checked, in canonical catalog order,
// as detached safe projections that leak no physical identity. It also proves
// duplicate, reordered and stale candidate sets are refused instead of being
// repaired.
func TestAnalyticScalarCapabilityProjectsOnlyCheckedProfiles(t *testing.T) {
	alpha := scalarCapabilityFixtureEntry(t, "alpha_orders", 1, analytic.ProfileActive)
	beta := scalarCapabilityFixtureEntry(t, "beta_orders", 2, analytic.ProfileActive)
	gamma := scalarCapabilityFixtureEntry(t, "gamma_orders", 1, analytic.ProfileActive)
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 7,
		[]analytic.CatalogEntryInput{gamma, alpha, beta})

	checked := []analyticCandidate{scalarCapabilityFromEntry(alpha), scalarCapabilityFromEntry(gamma)}
	capability, err := newAnalyticScalarCapability(catalog, checked)
	if err != nil {
		t.Fatalf("construct capability from canonical checked subset: %v", err)
	}
	if !capability.valid() {
		t.Fatal("constructed capability is not valid")
	}

	projected := capability.modelProfiles()
	if len(projected) != 2 {
		t.Fatalf("model profiles = %d want the 2 checked projections", len(projected))
	}
	if projected[0].DatasetID != "alpha_orders" || projected[0].ProfileVersion != 1 ||
		projected[0].ProfileHash != alpha.Profile.Hash() {
		t.Fatalf("projected[0] = %q/%d/%q want the alpha checked profile", projected[0].DatasetID,
			projected[0].ProfileVersion, projected[0].ProfileHash)
	}
	if projected[1].DatasetID != "gamma_orders" || projected[1].ProfileVersion != 1 ||
		projected[1].ProfileHash != gamma.Profile.Hash() {
		t.Fatalf("projected[1] = %q/%d/%q want the gamma checked profile", projected[1].DatasetID,
			projected[1].ProfileVersion, projected[1].ProfileHash)
	}

	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatalf("marshal model profiles: %v", err)
	}
	text := string(raw)
	if strings.Contains(text, "beta_orders") {
		t.Fatalf("unchecked beta projection leaked into %s", text)
	}
	for _, sentinel := range []string{
		"src_scope_scalar", "conn_scalar", "db_scalar", "lineage_scalar",
		"scalar_schema", "scalar_relation", "business_day_phys",
	} {
		if strings.Contains(text, sentinel) {
			t.Fatalf("projection leaked sentinel %q in %s", sentinel, text)
		}
	}
	for _, key := range []string{"physical_name", "physical_type", "source_ordinal", "sql"} {
		if strings.Contains(text, key) {
			t.Fatalf("projection leaked forbidden key %q in %s", key, text)
		}
	}

	t.Run("detached", func(t *testing.T) {
		held := capability.projections[0].Fields[0].Aliases[0]
		heldAllowed := capability.projections[0].Fields[1].AllowedValues[0]
		projected[0].Fields[0].Aliases[0] = "mutated"
		projected[0].Fields[1].AllowedValues[0] = "mutated"
		projected[0] = modelDatasetProfile{}
		projected[1].Measures[0].Aliases[0] = "mutated"
		if capability.projections[0].Fields[0].Aliases[0] != held {
			t.Fatal("mutating the returned projection reached the retained field aliases")
		}
		if capability.projections[0].Fields[1].AllowedValues[0] != heldAllowed {
			t.Fatal("mutating the returned projection reached the retained allowed values")
		}
		if capability.projections[0].DatasetID != "alpha_orders" {
			t.Fatal("mutating the returned slice reached the retained projection")
		}
		if capability.projections[1].Measures[0].Aliases[0] == "mutated" {
			t.Fatal("mutating the returned projection reached the retained measure aliases")
		}
	})

	t.Run("duplicate candidates", func(t *testing.T) {
		refused, refuseErr := newAnalyticScalarCapability(catalog,
			[]analyticCandidate{scalarCapabilityFromEntry(alpha), scalarCapabilityFromEntry(alpha)})
		assertScalarCapabilityConstructorRefusal(t, refused, refuseErr)
	})

	t.Run("reordered candidates", func(t *testing.T) {
		refused, refuseErr := newAnalyticScalarCapability(catalog,
			[]analyticCandidate{scalarCapabilityFromEntry(gamma), scalarCapabilityFromEntry(alpha)})
		assertScalarCapabilityConstructorRefusal(t, refused, refuseErr)
	})

	t.Run("stale candidate", func(t *testing.T) {
		stale := analyticCandidate{
			profileKey:  alpha.Profile.Key(),
			profileHash: "sha256:" + strings.Repeat("0", 64),
		}
		refused, refuseErr := newAnalyticScalarCapability(catalog, []analyticCandidate{stale})
		assertScalarCapabilityConstructorRefusal(t, refused, refuseErr)
	})
}

func TestAnalyticScalarCapabilityRefusesUnsatisfiableRequiredFilterCount(t *testing.T) {
	entry := scalarCapabilityFixtureEntry(t, "orders", 1, analytic.ProfileActive)
	spec := entry.Profile.Spec()
	semantics := spec.Semantics.Values()
	for index := 0; index < 3; index++ {
		token := fmt.Sprintf("required_filter_%d", index+1)
		field := scalarCapabilityFixtureField(t, token, token+"_phys", 4+index,
			analytic.ScalarText, analytic.PhysicalPGText, []analytic.PredicateOperator{analytic.PredicateEQ}, "approved")
		spec.Fields = append(spec.Fields, field)
		semantics.Fields = append(semantics.Fields, analytic.FieldSemanticsInput{
			Token: token, Label: token, Description: token, NullMeaning: "Not assigned",
		})
	}
	var err error
	spec.Semantics, err = analytic.NewProfileSemantics(semantics)
	if err != nil {
		t.Fatalf("rebuild semantics: %v", err)
	}
	entry.Profile, err = analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatalf("rebuild over-filtered profile: %v", err)
	}
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 1, []analytic.CatalogEntryInput{entry})
	refused, refuseErr := newAnalyticScalarCapability(catalog, []analyticCandidate{scalarCapabilityFromEntry(entry)})
	assertScalarCapabilityConstructorRefusal(t, refused, refuseErr)
}

// TestAnalyticScalarCapabilityValidatesExplicitUngroupedValue proves one strict
// ungrouped VALUE proposal over a checked profile is decoded, validated and
// sealed against the capability's own catalog snapshot, and that the exact
// checked profile, resolved period and measure come back.
func TestAnalyticScalarCapabilityValidatesExplicitUngroupedValue(t *testing.T) {
	orders := scalarCapabilityFixtureEntry(t, "orders", 4, analytic.ProfileActive)
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 1, []analytic.CatalogEntryInput{orders})
	capability, err := newAnalyticScalarCapability(catalog, []analyticCandidate{scalarCapabilityFromEntry(orders)})
	if err != nil {
		t.Fatalf("construct scalar capability: %v", err)
	}

	doc := scalarCapabilityAggregateDoc(orders)
	intent, selected, err := capability.validateProposal([]byte(doc))
	if err != nil {
		t.Fatalf("validate explicit ungrouped value proposal: %v", err)
	}
	if !intent.Valid() {
		t.Fatal("validated intent is not valid")
	}
	if selected.Key() != orders.Profile.Key() || selected.Hash() != orders.Profile.Hash() {
		t.Fatalf("selected profile = %v/%q want the checked profile", selected.Key(), selected.Hash())
	}

	if operation, ok := intent.Operation(); !ok || operation != queryintent.OperationAGGREGATE {
		t.Fatalf("intent operation = %q ok=%v want %q", operation, ok, queryintent.OperationAGGREGATE)
	}
	if output, ok := intent.Output(); !ok || output != queryintent.OutputValue {
		t.Fatalf("intent output = %q ok=%v want %q", output, ok, queryintent.OutputValue)
	}
	limit, ok := intent.Limit()
	if !ok {
		t.Fatal("intent carries no limit")
	}
	if limitValue, valueOK := limit.Value(); !valueOK || limitValue != 1 {
		t.Fatalf("intent limit = %d ok=%v want 1", limitValue, valueOK)
	}
	dimensions, ok := intent.Dimensions()
	if !ok {
		t.Fatal("intent carries no dimensions")
	}
	if fields, fieldsOK := dimensions.Fields(); !fieldsOK || len(fields) != 0 {
		t.Fatalf("intent dimensions = %v ok=%v want empty", fields, fieldsOK)
	}
	measure, ok := intent.Measure()
	if !ok {
		t.Fatal("intent carries no measure")
	}
	if measureID, measureOK := measure.MeasureID(); !measureOK || measureID != "assigned_orders" {
		t.Fatalf("intent measure = %q ok=%v want assigned_orders", measureID, measureOK)
	}
	resolved, ok := intent.ResolvedPeriod()
	if !ok {
		t.Fatal("intent carries no resolved period")
	}
	if kind, kindOK := resolved.TimeKind(); !kindOK || kind != analytic.TimeBusinessDate {
		t.Fatalf("resolved time kind = %q ok=%v want %q", kind, kindOK, analytic.TimeBusinessDate)
	}
	start, end, boundsOK := resolved.Bounds()
	if !boundsOK || start != "2026-09-10" || end != "2026-09-11" {
		t.Fatalf("resolved bounds = %q..%q ok=%v want 2026-09-10..2026-09-11", start, end, boundsOK)
	}
	filters, ok := intent.Filters()
	if !ok {
		t.Fatal("intent carries no filters")
	}
	predicates, predicatesOK := filters.Values()
	if !predicatesOK || len(predicates) != 2 {
		t.Fatalf("intent filters = %v ok=%v want both required non-time predicates", predicates, predicatesOK)
	}
}

func TestAnalyticScalarCapabilityRequiresEveryExposedFilterExactlyOnce(t *testing.T) {
	orders := scalarCapabilityFixtureEntry(t, "orders", 4, analytic.ProfileActive)
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 1, []analytic.CatalogEntryInput{orders})
	capability, err := newAnalyticScalarCapability(catalog, []analyticCandidate{scalarCapabilityFromEntry(orders)})
	if err != nil {
		t.Fatalf("construct scalar capability: %v", err)
	}

	complete := scalarCapabilityAggregateDoc(orders)
	filterSet := scalarCapabilityRequiredFiltersMember()
	cases := []struct {
		name string
		doc  string
		ok   bool
	}{
		{name: "complete", doc: complete, ok: true},
		{name: "missing", doc: scalarCapabilityDocReplace(t, complete, filterSet,
			`"filters":[{"field":"order_total","op":"EQ","values":[{"kind":"NUMERIC","value":"100"}]}]`)},
		{name: "duplicate", doc: scalarCapabilityDocReplace(t, complete, filterSet,
			`"filters":[{"field":"order_total","op":"EQ","values":[{"kind":"NUMERIC","value":"100"}]},{"field":"order_total","op":"EQ","values":[{"kind":"NUMERIC","value":"200"}]}]`)},
		{name: "value outside allowlist", doc: scalarCapabilityDocReplace(t, complete, `"value":"order-1"`, `"value":"order-9"`)},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			intent, selected, validateErr := capability.validateProposal([]byte(test.doc))
			if test.ok {
				if validateErr != nil || !intent.Valid() || !selected.Valid() {
					t.Fatalf("complete predicate set refused: intent valid=%v selected valid=%v err=%v", intent.Valid(), selected.Valid(), validateErr)
				}
				return
			}
			assertScalarCapabilityRefusal(t, intent, selected, validateErr, CodeInvalid)
		})
	}
}

// TestAnalyticScalarCapabilityRefusesUnsupportedOrUncheckedProposal proves every
// document outside the closed ungrouped scalar shape is refused with zero
// outputs and a content-free code, and that an ACTIVE catalog profile the
// capability did not check is refused as unavailable rather than invalid.
func TestAnalyticScalarCapabilityRefusesUnsupportedOrUncheckedProposal(t *testing.T) {
	checked := scalarCapabilityFixtureEntry(t, "orders", 1, analytic.ProfileActive)
	unchecked := scalarCapabilityFixtureEntry(t, "returns", 1, analytic.ProfileActive)
	catalog := scalarCapabilityFixtureCatalog(t, "catalog.scalar", 3,
		[]analytic.CatalogEntryInput{checked, unchecked})
	capability, err := newAnalyticScalarCapability(catalog, []analyticCandidate{scalarCapabilityFromEntry(checked)})
	if err != nil {
		t.Fatalf("construct scalar capability: %v", err)
	}

	base := scalarCapabilityAggregateDoc(checked)
	uncheckedDoc := scalarCapabilityAggregateDoc(unchecked)
	lookup := scalarCapabilityLookupDoc(checked)

	cases := []struct {
		name string
		doc  string
		want ErrorCode
	}{
		{"malformed json", "{", CodeInvalid},
		{"unknown member", scalarCapabilityDocReplace(t, base, `"output":"VALUE"`, `"output":"VALUE","sql":"select 1"`), CodeInvalid},
		{"lookup", lookup, CodeInvalid},
		{"grouped", scalarCapabilityDocReplace(t, base, `"dimensions":[]`, `"dimensions":["order_id"]`), CodeInvalid},
		{"rowset", scalarCapabilityDocReplace(t, base, `"output":"VALUE"`, `"output":"ROWSET"`), CodeInvalid},
		{"non-empty sort", scalarCapabilityDocReplace(t, base, `"sort":[]`,
			`"sort":[{"target_kind":"DIMENSION","field":"order_id","direction":"ASC"}]`), CodeInvalid},
		{"limit two", scalarCapabilityDocReplace(t, base, `"limit":1`, `"limit":2`), CodeInvalid},
		{"relative period", scalarCapabilityDocReplace(t, base,
			`"period":{"mode":"EXPLICIT","start":"2026-09-10","end":"2026-09-11"}`,
			`"period":{"mode":"TODAY"}`), CodeInvalid},
		{"unchecked active profile", uncheckedDoc, CodeUnavailable},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			intent, selected, refuseErr := capability.validateProposal([]byte(test.doc))
			assertScalarCapabilityRefusal(t, intent, selected, refuseErr, test.want)
		})
	}
}

// scalarCapabilityFixtureProfile seals one small valid live BUSINESS_DATE
// profile through the public analytic constructors. Every source, schema,
// relation and physical value is a unique sentinel so the projection test can
// prove none of them survive into the model-facing contract.
func scalarCapabilityFixtureProfile(t *testing.T, datasetID string, version int64) analytic.DatasetProfile {
	t.Helper()

	key, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatalf("build scalar profile key %q/%d: %v", datasetID, version, err)
	}
	source, err := analytic.NewSourceProjectionSpec(analytic.SourceProjectionInput{
		SourceScopeID: "src_scope_scalar", ConnectionID: "conn_scalar", DatabaseIdentity: "db_scalar",
		ProjectionLineageID: "lineage_scalar", ProjectionRevision: 2,
		ProjectionContractHash: "sha256:" + strings.Repeat("e", 64), ExposedSchemaRevision: 3,
		ExposedSchemaHash: "sha256:" + strings.Repeat("f", 64), SchemaName: "scalar_schema",
		RelationName: "scalar_relation", RelationKind: analytic.RelationView,
	})
	if err != nil {
		t.Fatalf("build scalar source projection: %v", err)
	}

	businessDay := scalarCapabilityFixtureField(t, "business_day", "business_day_phys", 1,
		analytic.ScalarDate, analytic.PhysicalPGDate, []analytic.PredicateOperator{analytic.PredicateEQ})
	orderID := scalarCapabilityFixtureField(t, "order_id", "order_id_phys", 2,
		analytic.ScalarText, analytic.PhysicalPGText, []analytic.PredicateOperator{analytic.PredicateEQ, analytic.PredicateIN}, "order-1", "order-2")
	orderTotal := scalarCapabilityFixtureField(t, "order_total", "order_total_phys", 3,
		analytic.ScalarNumeric, analytic.PhysicalPGNumeric, []analytic.PredicateOperator{analytic.PredicateEQ})

	measure, err := analytic.NewMeasureSpec(analytic.MeasureSpecInput{
		ID: "assigned_orders", Reducer: analytic.ReducerSum, NumeratorField: "order_total",
		Unit: "count", NullPolicy: analytic.NullExcludeAndReport, Eligibility: analytic.EligibilityAllRows,
	})
	if err != nil {
		t.Fatalf("build scalar measure: %v", err)
	}

	semantics, err := analytic.NewProfileSemantics(analytic.ProfileSemanticsInput{
		DatasetLabel:       "Scalar fixture",
		DatasetDescription: "Scalar capability business records",
		Fields: []analytic.FieldSemanticsInput{
			{Token: "business_day", Label: "Business day", Description: "Reporting business date", NullMeaning: "Not assigned", Aliases: []string{"day"}},
			{Token: "order_id", Label: "Order id", Description: "Order identifier", NullMeaning: "Not assigned", Aliases: []string{"order"}},
			{Token: "order_total", Label: "Order total", Description: "Total order value", NullMeaning: "Not measured"},
		},
		Measures: []analytic.MeasureSemanticsInput{
			{ID: "assigned_orders", Label: "Assigned orders", Description: "Sum of assigned order totals", Aliases: []string{"assigned"}},
		},
	})
	if err != nil {
		t.Fatalf("build scalar semantics: %v", err)
	}

	grain, err := analytic.NewDatasetGrain(analytic.DatasetGrainInput{
		Description: "One row per order", KeyFields: []string{"order_id"}, DuplicatePolicy: analytic.DuplicateReject,
	})
	if err != nil {
		t.Fatalf("build scalar grain: %v", err)
	}

	timePolicy, err := analytic.NewTimePolicy(analytic.TimePolicyInput{
		Kind: analytic.TimeBusinessDate, FieldToken: "business_day",
		ReportingTimezone: "UTC", Calendar: analytic.CalendarGregorian,
	})
	if err != nil {
		t.Fatalf("build scalar time policy: %v", err)
	}
	limits, err := analytic.NewProfileLimits(analytic.ProfileLimitsInput{
		MaxInputRows: 1000, MaxOutputGroups: 20, MaxPeriodDays: 31, MaxResultBytes: 1048576, StatementTimeoutMS: 5000,
	})
	if err != nil {
		t.Fatalf("build scalar limits: %v", err)
	}

	profile, err := analytic.NewDatasetProfile(analytic.DatasetProfileSpec{
		Key: key, Mode: analytic.ExecutionLive, Source: source,
		Fields:    []analytic.FieldSpec{businessDay, orderID, orderTotal},
		Measures:  []analytic.MeasureSpec{measure},
		Semantics: semantics, Grain: grain, Time: timePolicy,
		Coverage: analytic.CoverageUnknown, Limits: limits,
	})
	if err != nil {
		t.Fatalf("seal scalar profile %q/%d: %v", datasetID, version, err)
	}
	return profile
}

// scalarCapabilityFixtureField seals one approved field with a fixed
// sortable/output-allowed grant and the supplied operator vocabulary.
func scalarCapabilityFixtureField(
	t *testing.T,
	token, physical string,
	ordinal int,
	logical analytic.ScalarType,
	physicalType analytic.PhysicalType,
	allowedOps []analytic.PredicateOperator,
	allowedValues ...string,
) analytic.FieldSpec {
	t.Helper()
	field, err := analytic.NewFieldSpec(analytic.FieldSpecInput{
		Token: token, SourceOrdinal: ordinal, PhysicalName: physical,
		LogicalType: logical, PhysicalType: physicalType, Nullable: false,
		Filterable: true, Groupable: true, Sortable: true, OutputAllowed: true,
		AllowedOps: allowedOps, AllowedValues: allowedValues,
	})
	if err != nil {
		t.Fatalf("build scalar field %q: %v", token, err)
	}
	return field
}

// scalarCapabilityFixtureEntry pairs one sealed scalar fixture profile with a
// catalog state.
func scalarCapabilityFixtureEntry(t *testing.T, datasetID string, version int64, state analytic.ProfileState) analytic.CatalogEntryInput {
	t.Helper()
	return analytic.CatalogEntryInput{Profile: scalarCapabilityFixtureProfile(t, datasetID, version), State: state}
}

// scalarCapabilityFixtureCatalog seals one immutable catalog over the entries.
func scalarCapabilityFixtureCatalog(t *testing.T, catalogID string, revision int64, entries []analytic.CatalogEntryInput) analytic.DatasetProfileCatalog {
	t.Helper()
	catalog, err := analytic.NewDatasetProfileCatalog(catalogID, revision, entries)
	if err != nil {
		t.Fatalf("build scalar catalog %q/%d: %v", catalogID, revision, err)
	}
	return catalog
}

// scalarCapabilityFromEntry returns the checked candidate for one catalog entry.
func scalarCapabilityFromEntry(entry analytic.CatalogEntryInput) analyticCandidate {
	return analyticCandidate{profileKey: entry.Profile.Key(), profileHash: entry.Profile.Hash()}
}

// scalarCapabilityAggregateDoc builds the strict, closed ungrouped VALUE
// document for one catalog entry: one measure, empty dimensions and sort, limit
// 1 and an EXPLICIT business-date period. Callers rewrite exactly one member to
// redirect one aspect of the shape.
func scalarCapabilityAggregateDoc(entry analytic.CatalogEntryInput) string {
	members := []string{
		`"schema_version":"queryintent-proposal-v2"`,
		`"operation":"AGGREGATE"`,
		scalarCapabilityDatasetMember(entry),
		`"period":{"mode":"EXPLICIT","start":"2026-09-10","end":"2026-09-11"}`,
		scalarCapabilityRequiredFiltersMember(),
		`"sort":[]`,
		`"limit":1`,
		`"measure":"assigned_orders"`,
		`"dimensions":[]`,
		`"output":"VALUE"`,
	}
	return "{" + strings.Join(members, ",") + "}"
}

func scalarCapabilityRequiredFiltersMember() string {
	return `"filters":[{"field":"order_id","op":"EQ","values":[{"kind":"TEXT","value":"order-1"}]},{"field":"order_total","op":"EQ","values":[{"kind":"NUMERIC","value":"100"}]}]`
}

// scalarCapabilityLookupDoc builds a strict LOOKUP document, the other closed
// proposal shape this capability must refuse.
func scalarCapabilityLookupDoc(entry analytic.CatalogEntryInput) string {
	return "{" + strings.Join([]string{
		`"schema_version":"queryintent-proposal-v2"`,
		`"operation":"LOOKUP"`,
		scalarCapabilityDatasetMember(entry),
		`"period":{"mode":"EXPLICIT","start":"2026-09-10","end":"2026-09-11"}`,
		`"filters":[]`,
		`"sort":[]`,
		`"limit":1`,
		`"output_fields":["order_id"]`,
	}, ",") + "}"
}

// scalarCapabilityDatasetMember renders the exact dataset profile triple one
// checked profile carries.
func scalarCapabilityDatasetMember(entry analytic.CatalogEntryInput) string {
	return fmt.Sprintf(`"dataset":{"dataset_id":%q,"profile_version":%d,"expected_profile_hash":%q}`,
		entry.Profile.Key().DatasetID(), entry.Profile.Key().Version(), entry.Profile.Hash())
}

// scalarCapabilityDocReplace rewrites exactly one member of an otherwise valid
// document.
func scalarCapabilityDocReplace(t *testing.T, doc, old, replacement string) string {
	t.Helper()
	if !strings.Contains(doc, old) {
		t.Fatalf("scalar capability fixture does not contain %q", old)
	}
	return strings.Replace(doc, old, replacement, 1)
}

// assertScalarCapabilityConstructorRefusal proves one constructor refusal is the
// exact zero capability plus the content-free CodeInvalid error.
func assertScalarCapabilityConstructorRefusal(t *testing.T, capability analyticScalarCapability, err error) {
	t.Helper()
	if !reflect.DeepEqual(capability, analyticScalarCapability{}) {
		t.Fatalf("refused capability = %+v want the exact zero value", capability)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil || typed.clarification != "" {
		t.Fatalf("refusal = %#v want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v want nil", unwrapped)
	}
}

// assertScalarCapabilityRefusal proves one proposal refusal returned the exact
// zero intent and profile plus the requested content-free error code.
func assertScalarCapabilityRefusal(t *testing.T, intent queryintent.ValidatedIntentV2, profile analytic.DatasetProfile, err error, want ErrorCode) {
	t.Helper()
	if !reflect.DeepEqual(intent, queryintent.ValidatedIntentV2{}) {
		t.Fatalf("refused intent = %+v want the exact zero value", intent)
	}
	if !reflect.DeepEqual(profile, analytic.DatasetProfile{}) {
		t.Fatalf("refused profile = %+v want the exact zero value", profile)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != want || typed.cause != nil || typed.clarification != "" {
		t.Fatalf("refusal = %#v want content-free %s", err, want)
	}
	if err.Error() != string(want) {
		t.Fatalf("refusal message = %q want %q", err.Error(), want)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v want nil", unwrapped)
	}
}
