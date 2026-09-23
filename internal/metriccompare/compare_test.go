package metriccompare

import (
	"errors"
	"strings"
	"testing"
)

func exampleSpec() ProfileSpec {
	return ProfileSpec{
		MetricID: "work.assignments", Unit: "unknown", Schema: "reporting", View: "v_metric",
		SubjectColumn: "team_id", SnapshotColumn: "observed_at", MeasureColumn: "amount",
		Timezone: "Europe/Moscow", Filters: []FixedFilter{
			{Column: "range_kind", Value: "METER"}, {Column: "metric_code", Value: "work.assignments"},
		},
	}
}

func TestCompileDeterministicLatestCommonSnapshot(t *testing.T) {
	spec := exampleSpec()
	profile, err := NewProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	spec.Filters[0].Value = "changed" // constructor copied caller-owned filters
	a, err := Compile(profile, "2026-09-10", "2026-09-09")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Compile(profile, "2026-09-10", "2026-09-09")
	if err != nil || a != b {
		t.Fatalf("nondeterministic compilation: %v", err)
	}
	if a.ProfileHash != profile.Hash() || a.MetricID != "work.assignments" || a.Unit != "unknown" {
		t.Fatalf("lost profile identity: %+v", a)
	}
	for _, fragment := range []string{
		`VALUES (DATE '2026-09-10'), (DATE '2026-09-09')`,
		`MAX(src."observed_at") AS snapshot_at`,
		`AT TIME ZONE 'Europe/Moscow'`,
		`src."observed_at" = l.snapshot_at`,
		`COUNT(DISTINCT src."team_id")`,
		`COUNT(src."observed_at") = COUNT(DISTINCT src."team_id")`,
		`THEN SUM(src."amount"::numeric) ELSE NULL`,
		`src."metric_code" = 'work.assignments'`,
		`src."range_kind" = 'METER'`,
		`FROM totals ORDER BY local_date DESC`,
	} {
		if !strings.Contains(a.SQL, fragment) {
			t.Errorf("SQL missing %q", fragment)
		}
	}
	if strings.Contains(a.SQL, "changed") {
		t.Fatal("compiled SQL changed with caller filter slice")
	}
	reversed := exampleSpec()
	reversed.Filters[0], reversed.Filters[1] = reversed.Filters[1], reversed.Filters[0]
	other, err := NewProfile(reversed)
	if err != nil || other.Hash() != profile.Hash() {
		t.Fatalf("filter order changed sealed profile: %v", err)
	}
}

func TestInvalidProfilesRefused(t *testing.T) {
	tests := map[string]func(*ProfileSpec){
		"schema injection": func(s *ProfileSpec) { s.Schema = `public"; DROP TABLE x` },
		"reserved view":    func(s *ProfileSpec) { s.View = "delete" },
		"empty subject":    func(s *ProfileSpec) { s.SubjectColumn = "" },
		"literal quote":    func(s *ProfileSpec) { s.Filters[0].Value = "x' OR true" },
		"literal comment":  func(s *ProfileSpec) { s.Filters[0].Value = "x--y" },
		"literal keyword":  func(s *ProfileSpec) { s.Filters[0].Value = "drop" },
		"duplicate filter": func(s *ProfileSpec) { s.Filters[1].Column = s.Filters[0].Column },
		"measure filter":   func(s *ProfileSpec) { s.Filters[0].Column = s.MeasureColumn },
		"invalid timezone": func(s *ProfileSpec) { s.Timezone = "Invalid/Unknown" },
		"unsafe timezone":  func(s *ProfileSpec) { s.Timezone = "../UTC" },
		"local timezone":   func(s *ProfileSpec) { s.Timezone = "Local" },
		"empty unit":       func(s *ProfileSpec) { s.Unit = "" },
		"control unit":     func(s *ProfileSpec) { s.Unit = "tasks\nraw" },
		"five filters": func(s *ProfileSpec) {
			s.Filters = append(s.Filters, FixedFilter{"a", "a"}, FixedFilter{"b", "b"}, FixedFilter{"c", "c"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spec := exampleSpec()
			mutate(&spec)
			if _, err := NewProfile(spec); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
}

func TestInvalidDatesRefused(t *testing.T) {
	profile, err := NewProfile(exampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, dates := range [][2]string{
		{"2026-09-10", "2026-09-10"}, {"2026-02-30", "2026-03-01"},
		{"2026-9-10", "2026-09-09"}, {"2026-09-10'; DROP", "2026-09-09"},
		{"", "2026-09-09"},
	} {
		compiled, err := Compile(profile, dates[0], dates[1])
		if !errors.Is(err, ErrInvalid) || compiled != (Compiled{}) {
			t.Fatalf("dates %q: got %+v / %v", dates, compiled, err)
		}
	}
	if _, err := Compile(Profile{}, "2026-09-10", "2026-09-09"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero profile: %v", err)
	}
}
