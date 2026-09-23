package metriccompare

import (
	"errors"
	"strings"
	"testing"
)

func exampleSpec() ProfileSpec {
	return ProfileSpec{
		ExposedSchemaRevision: 7,
		MetricID:              "work.assignments", Unit: "unknown", Schema: "reporting", View: "v_metric",
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
		`COUNT(src."observed_at") = COUNT(src."amount") FILTER (WHERE src."amount"::text NOT IN ('NaN', 'Infinity', '-Infinity'))`,
		`THEN SUM(src."amount"::numeric) FILTER (WHERE src."amount"::text NOT IN ('NaN', 'Infinity', '-Infinity'))`,
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
		"schema injection":         func(s *ProfileSpec) { s.Schema = `public"; DROP TABLE x` },
		"zero schema revision":     func(s *ProfileSpec) { s.ExposedSchemaRevision = 0 },
		"reserved view":            func(s *ProfileSpec) { s.View = "delete" },
		"empty subject":            func(s *ProfileSpec) { s.SubjectColumn = "" },
		"literal quote":            func(s *ProfileSpec) { s.Filters[0].Value = "x' OR true" },
		"literal comment":          func(s *ProfileSpec) { s.Filters[0].Value = "x--y" },
		"literal keyword":          func(s *ProfileSpec) { s.Filters[0].Value = "drop" },
		"duplicate filter":         func(s *ProfileSpec) { s.Filters[1].Column = s.Filters[0].Column },
		"measure filter":           func(s *ProfileSpec) { s.Filters[0].Column = s.MeasureColumn },
		"invalid timezone":         func(s *ProfileSpec) { s.Timezone = "Invalid/Unknown" },
		"unsafe timezone":          func(s *ProfileSpec) { s.Timezone = "../UTC" },
		"local timezone":           func(s *ProfileSpec) { s.Timezone = "Local" },
		"empty unit":               func(s *ProfileSpec) { s.Unit = "" },
		"control unit":             func(s *ProfileSpec) { s.Unit = "tasks\nraw" },
		"description newline":      func(s *ProfileSpec) { s.Description = "Human\nlabel" },
		"description tab":          func(s *ProfileSpec) { s.Description = "Human\tlabel" },
		"description nbsp":         func(s *ProfileSpec) { s.Description = "Human\u00a0label" },
		"description too long":     func(s *ProfileSpec) { s.Description = strings.Repeat("x", 257) },
		"description invalid utf8": func(s *ProfileSpec) { s.Description = string([]byte{0xff}) },
		"description whitespace":   func(s *ProfileSpec) { s.Description = "   " },
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

func TestOptionalDescriptionIsSealedAndNotSQL(t *testing.T) {
	base, err := NewProfile(exampleSpec())
	if err != nil || base.Description() != "" {
		t.Fatalf("empty optional description: %v", err)
	}
	spec := exampleSpec()
	spec.Description = "Résumé of assigned work by agreement; observed metric."
	withDescription, err := NewProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if withDescription.Description() != spec.Description || withDescription.Hash() == base.Hash() {
		t.Fatal("description lost or absent from profile hash")
	}
	compiled, err := Compile(withDescription, "2026-09-10", "2026-09-09")
	if err != nil || strings.Contains(compiled.SQL, spec.Description) {
		t.Fatalf("description entered SQL: %v", err)
	}
}

func TestInvalidDatesRefused(t *testing.T) {
	profile, err := NewProfile(exampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	for _, dates := range [][2]string{
		{"2026-09-10", "2026-09-10"}, {"2026-02-30", "2026-03-01"},
		{"0000-01-01", "2026-03-01"},
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

func exposedSchema() Schema {
	return Schema{
		Revision: 7,
		Objects: []SchemaObject{{
			SchemaName: "reporting", TableName: "v_metric",
			Columns: []SchemaColumn{
				{Name: "team_id", DataType: "integer"},
				{Name: "observed_at", DataType: "timestamp with time zone"},
				{Name: "amount", DataType: "numeric"},
				{Name: "range_kind", DataType: "text"},
				{Name: "metric_code", DataType: "text"},
			},
		}},
	}
}

func TestValidateAgainstExposedSchema(t *testing.T) {
	profile, err := NewProfile(exampleSpec())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgainstExposedSchema(profile, exposedSchema()); err != nil {
		t.Fatalf("valid projection rejected: %v", err)
	}
	integral := exposedSchema()
	integral.Objects[0].Columns[2].DataType = "bigint"
	if err := ValidateAgainstExposedSchema(profile, integral); err != nil {
		t.Fatalf("safe integral measure rejected: %v", err)
	}
	tests := map[string]func(*Schema){
		"stale revision":      func(s *Schema) { s.Revision++ },
		"missing object":      func(s *Schema) { s.Objects[0].TableName = "other_view" },
		"missing filter":      func(s *Schema) { s.Objects[0].Columns = s.Objects[0].Columns[:4] },
		"wrong snapshot type": func(s *Schema) { s.Objects[0].Columns[1].DataType = "timestamp without time zone" },
		"float measure":       func(s *Schema) { s.Objects[0].Columns[2].DataType = "double precision" },
		"missing subject":     func(s *Schema) { s.Objects[0].Columns[0].Name = "other_id" },
		"duplicate object":    func(s *Schema) { s.Objects = append(s.Objects, s.Objects[0]) },
		"duplicate column":    func(s *Schema) { s.Objects[0].Columns[1].Name = s.Objects[0].Columns[0].Name },
		"empty type":          func(s *Schema) { s.Objects[0].Columns[0].DataType = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			schema := exposedSchema()
			mutate(&schema)
			if err := ValidateAgainstExposedSchema(profile, schema); !errors.Is(err, ErrInvalid) {
				t.Fatalf("got %v, want ErrInvalid", err)
			}
		})
	}
	if err := ValidateAgainstExposedSchema(Profile{}, exposedSchema()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero profile: %v", err)
	}
}
