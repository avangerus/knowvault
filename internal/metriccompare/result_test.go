package metriccompare

import (
	"errors"
	"testing"
)

func cell(value string) *string { return &value }

func comparisonResult() TableResult {
	return TableResult{
		Columns:  []string{"local_date", "snapshot_at", "contributing_rows", "distinct_subjects", "nonnull_count", "value"},
		RowCount: 2,
		Rows: [][]*string{
			{cell("2026-09-10"), cell("2026-09-10 00:00:00+03"), cell("407"), cell("407"), cell("407"), cell("3888")},
			{cell("2026-09-09"), cell("2026-09-09 00:00:00+03"), cell("457"), cell("457"), cell("457"), cell("4140")},
		},
	}
}

func testProfile(t *testing.T) Profile {
	t.Helper()
	p, err := NewProfile(exampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestParseResultVerifiedComparison(t *testing.T) {
	p := testProfile(t)
	got, err := ParseResult(comparisonResult(), "2026-09-10", "2026-09-09", p)
	if err != nil {
		t.Fatal(err)
	}
	if got.First.Value != "3888" || got.Second.Value != "4140" ||
		got.First.ContributingRows != 407 || got.Second.DistinctSubjects != 457 ||
		got.Delta != "-252" || got.PercentChange != "-6.09" ||
		got.Coverage != ObservedSnapshot || got.Unit != "unknown" || got.ProfileHash != p.Hash() {
		t.Fatalf("incorrect projection: %+v", got)
	}
	if got.First.SnapshotAt != "2026-09-10T00:00:00+03:00" {
		t.Fatalf("snapshot: %q", got.First.SnapshotAt)
	}
	// The caller's order determines the sign, independent of descending SQL order.
	reversed, err := ParseResult(comparisonResult(), "2026-09-09", "2026-09-10", p)
	if err != nil || reversed.First.Value != "4140" || reversed.Delta != "252" || reversed.PercentChange != "6.48" {
		t.Fatalf("reordered projection: %+v / %v", reversed, err)
	}
}

func TestParseResultRejectsIncompleteOrAlteredData(t *testing.T) {
	p := testProfile(t)
	tests := map[string]func(*TableResult){
		"missing period":     func(r *TableResult) { r.Rows = r.Rows[:1]; r.RowCount = 1 },
		"duplicate period":   func(r *TableResult) { r.Rows[1][0] = cell("2026-09-10") },
		"wrong period":       func(r *TableResult) { r.Rows[1][0] = cell("2026-09-08") },
		"row count mismatch": func(r *TableResult) { r.RowCount = 3 },
		"column mismatch":    func(r *TableResult) { r.Columns[5] = "amount" },
		"missing snapshot":   func(r *TableResult) { r.Rows[0][1] = nil },
		"wrong date snapshot": func(r *TableResult) {
			r.Rows[0][1] = cell("2026-09-09 23:59:59+03")
		},
		"missing value":     func(r *TableResult) { r.Rows[0][5] = nil },
		"missing subjects":  func(r *TableResult) { r.Rows[0][3] = cell("406") },
		"null measure":      func(r *TableResult) { r.Rows[0][4] = cell("406") },
		"zero rows":         func(r *TableResult) { r.Rows[0][2] = cell("0") },
		"malformed decimal": func(r *TableResult) { r.Rows[0][5] = cell("1/2") },
		"nonfinite decimal": func(r *TableResult) { r.Rows[0][5] = cell("NaN") },
		"zero denominator":  func(r *TableResult) { r.Rows[1][5] = cell("0") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			r := comparisonResult()
			mutate(&r)
			got, err := ParseResult(r, "2026-09-10", "2026-09-09", p)
			if !errors.Is(err, ErrInvalid) || got != (Comparison{}) {
				t.Fatalf("accepted invalid projection: %+v / %v", got, err)
			}
		})
	}
}

func TestParseResultExactDecimalAndRounding(t *testing.T) {
	r := comparisonResult()
	r.Rows[0][5] = cell("1.005")
	r.Rows[1][5] = cell("1")
	got, err := ParseResult(r, "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil || got.Delta != "0.005" || got.PercentChange != "0.50" {
		t.Fatalf("decimal rounding: %+v / %v", got, err)
	}
	r.Rows[0][5] = cell("1.00005")
	got, err = ParseResult(r, "2026-09-10", "2026-09-09", testProfile(t))
	if err != nil || got.Delta != "0.00005" || got.PercentChange != "0.01" {
		t.Fatalf("half away from zero: %+v / %v", got, err)
	}
}
