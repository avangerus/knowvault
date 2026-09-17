package metricdef

import (
	"reflect"
	"testing"
	"time"
)

func versionNumbers(versions []Definition) []int64 {
	numbers := make([]int64, 0, len(versions))
	for _, definition := range versions {
		numbers = append(numbers, definition.Version())
	}
	return numbers
}

func TestVersionsEnumeratesDraftEdit(t *testing.T) {
	series := newTestSeries(t)

	edited, err := series.Supersede(testSpec())
	if err != nil {
		t.Fatalf("Supersede draft: %v", err)
	}

	versions := edited.Versions()
	if len(versions) != 1 {
		t.Fatalf("a draft edit must not add a version, got %d", len(versions))
	}
	if !reflect.DeepEqual(versionNumbers(versions), []int64{1}) {
		t.Fatalf("unexpected version order: %v", versionNumbers(versions))
	}
	versioned, ok := edited.Version(1)
	if !ok || !reflect.DeepEqual(versions[0], versioned) {
		t.Fatalf("Versions()[0] must equal Version(1): %+v vs %+v", versions[0], versioned)
	}
}

func TestVersionsEnumeratesApprovedThenNewDraft(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	superseded, err := approved.Supersede(testSpec())
	if err != nil {
		t.Fatalf("Supersede approved: %v", err)
	}
	// Import a non-contiguous future version to prove the enumeration is sorted
	// rather than relying on map iteration order.
	imported, err := superseded.ImportVersion(4, testSpec())
	if err != nil {
		t.Fatalf("ImportVersion(4): %v", err)
	}

	versions := imported.Versions()
	if !reflect.DeepEqual(versionNumbers(versions), []int64{1, 2, 4}) {
		t.Fatalf("versions must be ascending: %v", versionNumbers(versions))
	}
	if versions[0].Status() != StatusApproved {
		t.Fatalf("version 1 must stay APPROVED, got %q", versions[0].Status())
	}
	if versions[1].Status() != StatusDraft || versions[2].Status() != StatusDraft {
		t.Fatalf("superseded and imported versions must be DRAFT")
	}
	for _, definition := range versions {
		versioned, ok := imported.Version(definition.Version())
		if !ok || !reflect.DeepEqual(definition, versioned) {
			t.Fatalf("Versions() entry must equal Version(%d)", definition.Version())
		}
	}
}

func TestVersionsEnumeratesRetiredStatus(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	retired, err := approved.Retire("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}

	versions := retired.Versions()
	if len(versions) != 1 || versions[0].Status() != StatusRetired {
		t.Fatalf("retired series must expose one RETIRED version, got %+v", versions)
	}
	versioned, ok := retired.Version(1)
	if !ok || !reflect.DeepEqual(versions[0], versioned) {
		t.Fatalf("retired enumeration must match Version(1)")
	}
}

func TestVersionsZeroSeriesIsEmptyAndNeverPanics(t *testing.T) {
	var series Series
	versions := series.Versions()
	if versions == nil || len(versions) != 0 {
		t.Fatalf("zero Series must yield an empty non-nil slice, got %#v", versions)
	}
	if series.Highest() != 0 || series.Current().Version() != 0 {
		t.Fatalf("zero Series accessors must stay zero")
	}
}

func TestVersionsReturnCopiesThatCannotMutateSeries(t *testing.T) {
	series := newTestSeries(t)
	auditor := &fakeAuditor{}
	at := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	approved, err := series.Approve("owner-1", auditor, at)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}

	versions := approved.Versions()
	if len(versions) != 1 {
		t.Fatalf("expected one version, got %d", len(versions))
	}
	// Overwriting a returned element must not change the series.
	versions[0] = Definition{}
	// Mutating the returned filter backing array must not change the series.
	versions = approved.Versions()
	if len(versions[0].allowedFilters.values) == 0 {
		t.Fatalf("expected a non-empty allowed filter set")
	}
	versions[0].allowedFilters.values[0] = "mutated"

	again, ok := approved.Version(1)
	if !ok {
		t.Fatalf("version 1 must remain addressable")
	}
	if !reflect.DeepEqual(again.AllowedFilters(), []string{"channel", "region"}) {
		t.Fatalf("internal filter set must be unaffected, got %v", again.AllowedFilters())
	}
	if approved.Current().Status() != StatusApproved {
		t.Fatalf("series must be unaffected by returned-value mutation")
	}
}
