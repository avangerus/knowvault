package queryintent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/metricdef"
)

type stubAuditor struct{}

func (stubAuditor) RecordApproval(metricdef.ApprovalEvent) error { return nil }
func (stubAuditor) RecordRetirement(metricdef.RetirementEvent) error {
	return nil
}

func baseSpec() metricdef.Spec {
	return metricdef.Spec{
		Name:           "Net revenue",
		Source:         metricdef.SourceConnection{ConnectionID: "conn-orders", ProjectionVersion: 3},
		EntityKey:      "order_id",
		Grain:          metricdef.GrainMonth,
		Unit:           "RUB",
		AllowedFilters: []string{"region", "channel"},
	}
}

func mustSeries(t *testing.T, id, workspaceID, owner string, spec metricdef.Spec) metricdef.Series {
	t.Helper()
	series, err := metricdef.NewSeries(id, workspaceID, owner, spec)
	if err != nil {
		t.Fatalf("NewSeries(%s): %v", id, err)
	}
	return series
}

func mustApprove(t *testing.T, series metricdef.Series) metricdef.Series {
	t.Helper()
	approved, err := series.Approve(series.OwnerPrincipalID(), stubAuditor{}, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return approved
}

func mustRetire(t *testing.T, series metricdef.Series) metricdef.Series {
	t.Helper()
	retired, err := series.Retire(series.OwnerPrincipalID(), stubAuditor{}, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	return retired
}

func mustSupersede(t *testing.T, series metricdef.Series, spec metricdef.Spec) metricdef.Series {
	t.Helper()
	next, err := series.Supersede(spec)
	if err != nil {
		t.Fatalf("Supersede: %v", err)
	}
	return next
}

// testCatalog holds, in workspace ws-1:
//   - metric-revenue v1 APPROVED and v2 DRAFT,
//   - metric-legacy v1 RETIRED,
// and in workspace ws-2 metric-other v1 APPROVED.
func testCatalog(t *testing.T) *MemoryCatalog {
	t.Helper()
	catalog := NewMemoryCatalog()

	revenue := mustSeries(t, "metric-revenue", "ws-1", "owner-1", baseSpec())
	revenue = mustApprove(t, revenue)
	approved, ok := revenue.Version(1)
	if !ok {
		t.Fatal("approved version 1 missing")
	}
	catalog.Add(approved)
	revenue = mustSupersede(t, revenue, baseSpec())
	catalog.Add(revenue.Current())

	legacy := mustSeries(t, "metric-legacy", "ws-1", "owner-1", baseSpec())
	legacy = mustApprove(t, legacy)
	legacy = mustRetire(t, legacy)
	catalog.Add(legacy.Current())

	other := mustSeries(t, "metric-other", "ws-2", "owner-2", baseSpec())
	other = mustApprove(t, other)
	catalog.Add(other.Current())

	return catalog
}

func mustValidator(t *testing.T, workspaceID string, catalog Catalog) Validator {
	t.Helper()
	validator, err := NewValidator(workspaceID, catalog)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return validator
}

func validProposal() Proposal {
	return Proposal{
		MetricID: "metric-revenue",
		Version:  1,
		Period: Period{
			Grain: metricdef.GrainMonth,
			Start: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			End:   time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
		},
		Filters: []string{"region"},
		Output:  OutputValue,
		AsOf:    time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestValidateRefusals(t *testing.T) {
	validator := mustValidator(t, "ws-1", testCatalog(t))

	unknownMetric := validProposal()
	unknownMetric.MetricID = "metric-missing"

	unknownVersion := validProposal()
	unknownVersion.Version = 9

	retired := validProposal()
	retired.MetricID = "metric-legacy"

	draft := validProposal()
	draft.Version = 2

	notAllowed := validProposal()
	notAllowed.Filters = []string{"region", "planet"}

	missingPeriod := validProposal()
	missingPeriod.Period = Period{}

	grainMismatch := validProposal()
	grainMismatch.Period.Grain = metricdef.GrainDay

	unknownGrain := validProposal()
	unknownGrain.Period.Grain = metricdef.PeriodGrain("HOUR")

	reversed := validProposal()
	reversed.Period.Start = reversed.Period.End

	zeroStart := validProposal()
	zeroStart.Period.Start = time.Time{}

	badOutput := validProposal()
	badOutput.Output = Output("CSV")

	zeroAsOf := validProposal()
	zeroAsOf.AsOf = time.Time{}

	emptyMetric := validProposal()
	emptyMetric.MetricID = ""

	zeroVersion := validProposal()
	zeroVersion.Version = 0

	crossWorkspace := validProposal()
	crossWorkspace.MetricID = "metric-other"

	cases := []struct {
		name     string
		proposal Proposal
		want     ErrorCode
	}{
		{"unknown metric", unknownMetric, CodeUnknownMetric},
		{"unknown version", unknownVersion, CodeUnknownVersion},
		{"retired version", retired, CodeRetiredVersion},
		{"draft version never validates", draft, CodeNotApproved},
		{"filter outside definition", notAllowed, CodeFilterNotAllowed},
		{"missing period", missingPeriod, CodeMalformedPeriod},
		{"grain mismatched period", grainMismatch, CodeMalformedPeriod},
		{"unknown period grain", unknownGrain, CodeMalformedPeriod},
		{"reversed period", reversed, CodeMalformedPeriod},
		{"zero period start", zeroStart, CodeMalformedPeriod},
		{"bad output", badOutput, CodeInvalidProposal},
		{"missing as_of", zeroAsOf, CodeInvalidProposal},
		{"empty metric id", emptyMetric, CodeInvalidProposal},
		{"zero version", zeroVersion, CodeInvalidProposal},
		{"other workspace metric is unknown", crossWorkspace, CodeUnknownMetric},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			intent, err := validator.Validate(testCase.proposal)
			if err == nil {
				t.Fatalf("expected refusal %s, got intent %+v", testCase.want, intent)
			}
			if code := CodeOf(err); code != testCase.want {
				t.Fatalf("code = %q, want %q", code, testCase.want)
			}
			if text := ClarificationOf(err); text == "" {
				t.Fatalf("code %q has empty clarification", testCase.want)
			}
			if intent != (Intent{}) {
				t.Fatalf("refusal returned an executable intent: %+v", intent)
			}
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("err %v is not a *queryintent.Error", err)
			}
		})
	}
}

func TestValidateRefusesWhenCatalogUnavailable(t *testing.T) {
	validator, err := NewValidator("ws-1", nil)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	intent, err := validator.Validate(validProposal())
	if CodeOf(err) != CodeCatalogUnavailable {
		t.Fatalf("code = %q, want %q", CodeOf(err), CodeCatalogUnavailable)
	}
	if ClarificationOf(err) == "" {
		t.Fatal("empty clarification")
	}
	if intent != (Intent{}) {
		t.Fatalf("intent returned on refusal: %+v", intent)
	}
}

func TestNewValidatorRejectsEmptyWorkspace(t *testing.T) {
	if _, err := NewValidator("", NewMemoryCatalog()); CodeOf(err) != CodeInvalidProposal {
		t.Fatalf("code = %q, want %q", CodeOf(err), CodeInvalidProposal)
	}
}

func TestValidateApprovedDefinitionExposesCanonicalIdentity(t *testing.T) {
	validator := mustValidator(t, "ws-1", testCatalog(t))
	intent, err := validator.Validate(validProposal())
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if intent.MetricID() != "metric-revenue" {
		t.Fatalf("metric id = %q", intent.MetricID())
	}
	if intent.Version() != 1 {
		t.Fatalf("version = %d", intent.Version())
	}
	if intent.Unit() != "RUB" {
		t.Fatalf("unit = %q", intent.Unit())
	}
	if intent.Period().Grain != metricdef.GrainMonth {
		t.Fatalf("grain = %q", intent.Period().Grain)
	}
	filters := intent.Filters()
	if len(filters) != 1 || filters[0] != "region" {
		t.Fatalf("filters = %#v", filters)
	}
	if intent.Output() != OutputValue {
		t.Fatalf("output = %q", intent.Output())
	}
	if !intent.AsOf().Equal(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("as_of = %v", intent.AsOf())
	}
}

func TestAllowedFilterPasses(t *testing.T) {
	validator := mustValidator(t, "ws-1", testCatalog(t))
	proposal := validProposal()
	proposal.Filters = []string{"channel"}
	if _, err := validator.Validate(proposal); err != nil {
		t.Fatalf("allowed filter refused: %v", err)
	}
}

func TestEqualProposalsYieldEqualIntents(t *testing.T) {
	validator := mustValidator(t, "ws-1", testCatalog(t))

	first, err := validator.Validate(validProposal())
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	second, err := validator.Validate(validProposal())
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if first != second {
		t.Fatalf("equal proposals produced different intents: %+v vs %+v", first, second)
	}
	if first.Digest() != second.Digest() {
		t.Fatalf("digests differ: %q vs %q", first.Digest(), second.Digest())
	}

	// Filter order must not change the canonical intent.
	unordered := validProposal()
	unordered.Filters = []string{"channel", "region"}
	ordered := validProposal()
	ordered.Filters = []string{"region", "channel"}
	a, err := validator.Validate(unordered)
	if err != nil {
		t.Fatalf("unordered Validate: %v", err)
	}
	b, err := validator.Validate(ordered)
	if err != nil {
		t.Fatalf("ordered Validate: %v", err)
	}
	if a != b || a.Digest() != b.Digest() {
		t.Fatalf("filter order changed the canonical intent")
	}
	if got := a.Filters(); len(got) != 2 || got[0] != "channel" || got[1] != "region" {
		t.Fatalf("filters not canonical: %#v", got)
	}
}

func TestIntentHasNoExportedFields(t *testing.T) {
	typ := reflect.TypeOf(Intent{})
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if field.PkgPath == "" {
			t.Fatalf("Intent exposes exported field %q; only the validator may build an intent", field.Name)
		}
	}
}

func TestProposalShapeIsExactAndFreeTextFree(t *testing.T) {
	want := map[string]bool{
		"MetricID": true, "Version": true, "Period": true,
		"Filters": true, "Output": true, "AsOf": true,
	}
	typ := reflect.TypeOf(Proposal{})
	if typ.NumField() != len(want) {
		t.Fatalf("Proposal has %d fields, want %d", typ.NumField(), len(want))
	}
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if !want[field.Name] {
			t.Fatalf("unexpected exported field %q", field.Name)
		}
		if field.PkgPath != "" {
			t.Fatalf("field %q must be exported", field.Name)
		}
	}
}

func TestNoFreeTextFieldOnExportedTypes(t *testing.T) {
	types := []reflect.Type{
		reflect.TypeOf(Proposal{}),
		reflect.TypeOf(Period{}),
		reflect.TypeOf(Intent{}),
		reflect.TypeOf(Error{}),
		reflect.TypeOf(MemoryCatalog{}),
	}
	banned := []string{"query", "sql", "statement", "raw", "prompt", "freetext", "text"}
	for _, typ := range types {
		for index := 0; index < typ.NumField(); index++ {
			name := strings.ToLower(typ.Field(index).Name)
			for _, token := range banned {
				if strings.Contains(name, token) {
					t.Fatalf("%s.%s looks like a free-text field", typ.Name(), typ.Field(index).Name)
				}
			}
		}
	}
}

func TestClarificationForEveryCodeIsNonEmpty(t *testing.T) {
	codes := []ErrorCode{
		CodeInvalidProposal,
		CodeUnknownMetric,
		CodeUnknownVersion,
		CodeRetiredVersion,
		CodeNotApproved,
		CodeFilterNotAllowed,
		CodeMalformedPeriod,
		CodeCatalogUnavailable,
		CodeCatalogBindingMismatch,
		CodeDatasetProfileUnavailable,
		CodeMeasureUnavailable,
		CodeDimensionUnavailable,
		CodeOutputFieldUnavailable,
		CodeSortUnavailable,
		CodeLimitExceeded,
	}
	for _, code := range codes {
		if clarificationFor(code) == "" {
			t.Fatalf("code %q has no clarification", code)
		}
	}
}
