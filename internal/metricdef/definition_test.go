package metricdef

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

type fakeAuditor struct {
	approvals     []ApprovalEvent
	retirements   []RetirementEvent
	approvalErr   error
	retirementErr error
}

func (f *fakeAuditor) RecordApproval(event ApprovalEvent) error {
	if f.approvalErr != nil {
		return f.approvalErr
	}
	f.approvals = append(f.approvals, event)
	return nil
}

func (f *fakeAuditor) RecordRetirement(event RetirementEvent) error {
	if f.retirementErr != nil {
		return f.retirementErr
	}
	f.retirements = append(f.retirements, event)
	return nil
}

func testSpec() Spec {
	return Spec{
		Name:           "Net revenue",
		Source:         SourceConnection{ConnectionID: "conn-orders", ProjectionVersion: 3},
		EntityKey:      "order_id",
		Grain:          GrainMonth,
		Unit:           "RUB",
		AllowedFilters: []string{"region", "channel", "region"},
	}
}

func newTestSeries(t *testing.T) Series {
	t.Helper()
	series, err := NewSeries("metric-revenue", "ws-1", "owner-1", testSpec())
	if err != nil {
		t.Fatalf("NewSeries: %v", err)
	}
	return series
}

func TestNewSeriesCarriesEveryOutcomeOneField(t *testing.T) {
	series := newTestSeries(t)
	current := series.Current()

	if current.ID() != "metric-revenue" || current.WorkspaceID() != "ws-1" || current.OwnerPrincipalID() != "owner-1" {
		t.Fatalf("identity mismatch: %+v", current)
	}
	if current.Version() != 1 || series.Highest() != 1 {
		t.Fatalf("expected first version 1, got %d (highest %d)", current.Version(), series.Highest())
	}
	if current.Name() != "Net revenue" {
		t.Fatalf("name mismatch: %q", current.Name())
	}
	if current.Source() != (SourceConnection{ConnectionID: "conn-orders", ProjectionVersion: 3}) {
		t.Fatalf("source mismatch: %+v", current.Source())
	}
	if current.EntityKey() != "order_id" || current.Grain() != GrainMonth || current.Unit() != "RUB" {
		t.Fatalf("field mismatch: %+v", current)
	}
	if current.Status() != StatusDraft || current.Approved() {
		t.Fatalf("new version must be a DRAFT, got %q", current.Status())
	}
	want := []string{"channel", "region"}
	if got := current.AllowedFilters(); !reflect.DeepEqual(got, want) {
		t.Fatalf("filters must be a sorted set %v, got %v", want, got)
	}
	if !current.AllowsFilter("region") || current.AllowsFilter("tenant_id") {
		t.Fatalf("filter membership mismatch: %v", current.AllowedFilters())
	}
	if _, ok := series.Version(2); ok {
		t.Fatalf("only version 1 should be issued")
	}
}

func TestStatusVocabularyIsClosed(t *testing.T) {
	for _, status := range []Status{StatusDraft, StatusApproved, StatusRetired} {
		if !ValidStatus(status) || !status.valid() {
			t.Fatalf("status %q must be valid", status)
		}
	}
	for _, status := range []Status{"", "PENDING", "DRAFT ", "draft"} {
		if ValidStatus(status) {
			t.Fatalf("status %q must be rejected", status)
		}
	}
	for _, grain := range []PeriodGrain{GrainDay, GrainWeek, GrainMonth, GrainQuarter, GrainYear} {
		if !ValidPeriodGrain(grain) {
			t.Fatalf("grain %q must be valid", grain)
		}
	}
	if ValidPeriodGrain("HOUR") {
		t.Fatalf("unknown grain must be rejected")
	}
}

func TestVersionMonotonicityIsEnforced(t *testing.T) {
	series := newTestSeries(t)

	if _, err := series.ImportVersion(1, testSpec()); CodeOf(err) != CodeVersionNotMonotonic {
		t.Fatalf("reusing version 1 must be refused, got %v", err)
	}
	if _, err := series.ImportVersion(0, testSpec()); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("version 0 must be refused, got %v", err)
	}
	if series.Highest() != 1 || series.Current().Version() != 1 {
		t.Fatalf("refused import must not change state: highest=%d", series.Highest())
	}

	advanced, err := series.ImportVersion(3, testSpec())
	if err != nil {
		t.Fatalf("ImportVersion(3): %v", err)
	}
	if advanced.Highest() != 3 || advanced.Current().Version() != 3 {
		t.Fatalf("expected highest 3, got %d", advanced.Highest())
	}
	if _, err := advanced.ImportVersion(2, testSpec()); CodeOf(err) != CodeVersionNotMonotonic {
		t.Fatalf("lowering the version must be refused, got %v", err)
	}
	if advanced.Highest() != 3 {
		t.Fatalf("refused import must not lower highest: %d", advanced.Highest())
	}

	// Editing a DRAFT must not issue or lower a version.
	edited, err := advanced.Supersede(testSpec())
	if err != nil {
		t.Fatalf("Supersede draft: %v", err)
	}
	if edited.Highest() != 3 || edited.Current().Status() != StatusDraft {
		t.Fatalf("draft edit must keep version 3, got highest=%d status=%q", edited.Highest(), edited.Current().Status())
	}
}

func TestApproveIsOwnerOnlyAndAudited(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.FixedZone("MSK", 3*60*60))

	if _, err := series.Approve("member-1", auditor, at); CodeOf(err) != CodeNotWorkspaceOwner {
		t.Fatalf("non-owner approval must be refused, got %v", err)
	}
	if _, err := series.Approve("", auditor, at); CodeOf(err) != CodeNotWorkspaceOwner {
		t.Fatalf("absent principal approval must be refused, got %v", err)
	}
	if series.Current().Status() != StatusDraft || len(auditor.approvals) != 0 {
		t.Fatalf("refused approval must leave state and audit untouched")
	}

	if _, err := series.Approve("owner-1", nil, at); CodeOf(err) != CodeAuditUnavailable {
		t.Fatalf("missing auditor must be refused, got %v", err)
	}
	if series.Current().Status() != StatusDraft {
		t.Fatalf("missing auditor must not flip status")
	}

	failing := &fakeAuditor{approvalErr: errors.New("audit down")}
	if _, err := series.Approve("owner-1", failing, at); CodeOf(err) != CodeAuditFailed {
		t.Fatalf("audit failure must fail closed, got %v", err)
	}
	if series.Current().Status() != StatusDraft || len(failing.approvals) != 0 {
		t.Fatalf("failed audit must not approve")
	}

	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("owner approval failed: %v", err)
	}
	if approved.Current().Status() != StatusApproved || !approved.Current().Approved() {
		t.Fatalf("approval must flip the current version to APPROVED")
	}
	if len(auditor.approvals) != 1 {
		t.Fatalf("successful approval must emit exactly one audit event, got %d", len(auditor.approvals))
	}
	event := auditor.approvals[0]
	if event.DefinitionID != "metric-revenue" || event.WorkspaceID != "ws-1" || event.Version != 1 ||
		event.ActorPrincipalID != "owner-1" || !event.OccurredAt.Equal(at.UTC()) {
		t.Fatalf("audit event mismatch: %+v", event)
	}

	if _, err := approved.Approve("owner-1", auditor, at); CodeOf(err) != CodeNotApprovable {
		t.Fatalf("re-approving an approved version must be refused, got %v", err)
	}
	if len(auditor.approvals) != 1 {
		t.Fatalf("refused re-approval must not emit a second event")
	}
}

func TestApprovedVersionIsImmutableAndCreatesNextDraft(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	changed := testSpec()
	changed.Name = "Gross revenue"
	changed.Source.ProjectionVersion = 4
	superseded, err := approved.Supersede(changed)
	if err != nil {
		t.Fatalf("Supersede approved: %v", err)
	}
	if superseded.Highest() != 2 || superseded.Current().Version() != 2 || superseded.Current().Status() != StatusDraft {
		t.Fatalf("superseding an approved version must create a DRAFT version 2, got %+v", superseded.Current())
	}
	if superseded.Current().Name() != "Gross revenue" || superseded.Current().Source().ProjectionVersion != 4 {
		t.Fatalf("new draft must carry the changed spec: %+v", superseded.Current())
	}

	original, ok := superseded.Version(1)
	if !ok {
		t.Fatalf("approved version 1 must remain addressable")
	}
	if original.Status() != StatusApproved || original.Name() != "Net revenue" || original.Source().ProjectionVersion != 3 {
		t.Fatalf("approved version must never change: %+v", original)
	}
	if _, err := superseded.ImportVersion(1, changed); CodeOf(err) != CodeVersionNotMonotonic {
		t.Fatalf("editing an issued version in place must be refused, got %v", err)
	}

	// A DRAFT cannot be treated as approved, and cannot be retired.
	if _, err := superseded.Retire("owner-1", auditor, at); CodeOf(err) != CodeNotRetirable {
		t.Fatalf("retiring a draft must be refused, got %v", err)
	}
}

func TestRetiredVersionIsTerminal(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if _, err := approved.Retire("member-1", auditor, at); CodeOf(err) != CodeNotWorkspaceOwner {
		t.Fatalf("non-owner retirement must be refused, got %v", err)
	}
	if _, err := approved.Retire("owner-1", nil, at); CodeOf(err) != CodeAuditUnavailable {
		t.Fatalf("retirement without auditor must be refused, got %v", err)
	}
	failing := &fakeAuditor{retirementErr: errors.New("audit down")}
	if _, err := approved.Retire("owner-1", failing, at); CodeOf(err) != CodeAuditFailed {
		t.Fatalf("failed retirement audit must fail closed, got %v", err)
	}

	retired, err := approved.Retire("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if retired.Current().Status() != StatusRetired {
		t.Fatalf("retirement must flip status to RETIRED")
	}
	if len(auditor.retirements) != 1 || auditor.retirements[0].Version != 1 {
		t.Fatalf("retirement must emit exactly one audit event: %+v", auditor.retirements)
	}
	if _, err := retired.Approve("owner-1", auditor, at); CodeOf(err) != CodeNotApprovable {
		t.Fatalf("approving a retired version must be refused, got %v", err)
	}
	if _, err := retired.Supersede(testSpec()); CodeOf(err) != CodeRetiredImmutable {
		t.Fatalf("editing a retired version must be refused, got %v", err)
	}
	if retired.Highest() != 1 || retired.Current().Status() != StatusRetired {
		t.Fatalf("refusals must not change the retired series")
	}
}

func TestSpecValidationIsFailClosed(t *testing.T) {
	valid := testSpec()

	badName := valid
	badName.Name = " "
	if _, err := NewSeries("metric-1", "ws-1", "owner-1", badName); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("blank name must be refused, got %v", err)
	}
	badSource := valid
	badSource.Source.ProjectionVersion = 0
	if _, err := NewSeries("metric-1", "ws-1", "owner-1", badSource); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("projection version 0 must be refused, got %v", err)
	}
	badGrain := valid
	badGrain.Grain = "HOUR"
	if _, err := NewSeries("metric-1", "ws-1", "owner-1", badGrain); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("unknown grain must be refused, got %v", err)
	}
	badFilter := valid
	badFilter.AllowedFilters = []string{"region", ""}
	if _, err := NewSeries("metric-1", "ws-1", "owner-1", badFilter); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("empty filter name must be refused, got %v", err)
	}
	if _, err := NewSeries("", "ws-1", "owner-1", valid); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("empty id must be refused, got %v", err)
	}
	if _, err := NewSeries("metric-1", "ws-1", "owner-1", valid); err != nil {
		t.Fatalf("valid spec must be accepted, got %v", err)
	}
}

func TestFilterSetIsCanonical(t *testing.T) {
	set, err := NewFilterSet([]string{"b", "a", "b"})
	if err != nil {
		t.Fatalf("NewFilterSet: %v", err)
	}
	if !reflect.DeepEqual(set.Values(), []string{"a", "b"}) || set.Len() != 2 {
		t.Fatalf("filters must be a sorted set, got %v", set.Values())
	}
	values := set.Values()
	values[0] = "mutated"
	if set.Allows("mutated") {
		t.Fatalf("Values must return a defensive copy")
	}
	if _, err := NewFilterSet([]string{"ok", "bad\n"}); CodeOf(err) != CodeInvalidDefinition {
		t.Fatalf("control characters must be refused, got %v", err)
	}
}
