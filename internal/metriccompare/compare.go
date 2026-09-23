// Package metriccompare compiles a sealed operator metric into one bounded,
// read-only comparison of two explicit business dates. It does no database I/O.
package metriccompare

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/tzrules"
)

var ErrInvalid = errors.New("invalid metric comparison")

// FixedFilter is set by an operator, never by a question or model.
type FixedFilter struct {
	Column string
	Value  string
}

// ProfileSpec names one approved metric and its physical read projection.
// Unit must be an operator supplied label or the literal "unknown".
type ProfileSpec struct {
	ExposedSchemaRevision int64
	MetricID              string
	Description           string
	Unit                  string
	Schema                string
	View                  string
	SubjectColumn         string
	SnapshotColumn        string
	MeasureColumn         string
	Timezone              string
	Filters               []FixedFilter
}

// Profile is sealed by NewProfile. Its fields and filter slice cannot be
// changed by a caller after validation.
type Profile struct {
	spec ProfileSpec
	hash string
}

func (p Profile) Hash() string        { return p.hash }
func (p Profile) MetricID() string    { return p.spec.MetricID }
func (p Profile) Description() string { return p.spec.Description }
func (p Profile) Unit() string        { return p.spec.Unit }

// PlanningEvidence projects only sealed source semantics for the SQL planner.
// Filters are part of the scope: the calendar is never a workspace default.
func (p Profile) PlanningEvidence() string {
	if p.hash == "" {
		return ""
	}
	filters := make(map[string]string, len(p.spec.Filters))
	for _, filter := range p.spec.Filters {
		filters[filter.Column] = filter.Value
	}
	value := struct {
		MetricID          string            `json:"metric_id"`
		Relation          string            `json:"relation"`
		Filters           map[string]string `json:"required_equal_filters"`
		ReportingTimezone string            `json:"reporting_timezone"`
		SnapshotColumn    string            `json:"snapshot_column"`
		MeasureColumn     string            `json:"measure_column"`
		SubjectColumn     string            `json:"subject_column"`
		Unit              string            `json:"unit"`
		SnapshotRule      string            `json:"snapshot_rule"`
		Coverage          string            `json:"population_coverage"`
	}{p.spec.MetricID, p.spec.Schema + "." + p.spec.View, filters, p.spec.Timezone,
		p.spec.SnapshotColumn, p.spec.MeasureColumn, p.spec.SubjectColumn, p.spec.Unit,
		"latest snapshot within the requested local reporting date; aggregate its contributing rows", "UNKNOWN"}
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
var metricID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*$`)
var literal = regexp.MustCompile(`^[A-Za-z0-9_.:/+-]+$`)
var datePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)

// The governed-query static precheck rejects these as whole words, including
// inside quoted literals. Refusing them here keeps compiled SQL compatible.
var rejectedWords = map[string]bool{
	"insert": true, "update": true, "delete": true, "drop": true,
	"alter": true, "create": true, "grant": true, "revoke": true,
	"truncate": true, "copy": true, "call": true, "do": true,
	"vacuum": true, "merge": true, "execute": true, "prepare": true,
	"listen": true, "notify": true, "set": true, "reset": true,
	"begin": true, "commit": true, "rollback": true, "savepoint": true,
	"lock": true,
}

func safeIdentifier(value string) bool {
	return len(value) <= 63 && identifier.MatchString(value) && !rejectedWords[value]
}

func safeLiteral(value string) bool {
	if len(value) == 0 || len(value) > 128 || !literal.MatchString(value) ||
		strings.Contains(value, "--") || strings.Contains(value, "/*") {
		return false
	}
	for _, word := range strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_'
	}) {
		if rejectedWords[word] {
			return false
		}
	}
	return true
}

func safeUnit(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func safeDescription(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if (r != ' ' && !unicode.IsPrint(r)) || (unicode.IsSpace(r) && r != ' ') {
			return false
		}
	}
	return true
}

func NewProfile(spec ProfileSpec) (Profile, error) {
	if spec.ExposedSchemaRevision < 1 || len(spec.MetricID) > 128 || !metricID.MatchString(spec.MetricID) ||
		!safeDescription(spec.Description) || !safeUnit(spec.Unit) || !safeIdentifier(spec.Schema) ||
		!safeIdentifier(spec.View) || !safeIdentifier(spec.SubjectColumn) ||
		!safeIdentifier(spec.SnapshotColumn) || !safeIdentifier(spec.MeasureColumn) ||
		spec.SubjectColumn == spec.SnapshotColumn || spec.SubjectColumn == spec.MeasureColumn ||
		spec.SnapshotColumn == spec.MeasureColumn ||
		!safeLiteral(spec.Timezone) ||
		(spec.Timezone != "UTC" && !strings.Contains(spec.Timezone, "/")) ||
		len(spec.Filters) > 4 {
		return Profile{}, ErrInvalid
	}
	if _, err := tzrules.Load(spec.Timezone); err != nil {
		return Profile{}, ErrInvalid
	}
	seen := map[string]bool{}
	for _, filter := range spec.Filters {
		if !safeIdentifier(filter.Column) || !safeLiteral(filter.Value) || seen[filter.Column] ||
			filter.Column == spec.SubjectColumn || filter.Column == spec.SnapshotColumn ||
			filter.Column == spec.MeasureColumn {
			return Profile{}, ErrInvalid
		}
		seen[filter.Column] = true
	}
	spec.Filters = append([]FixedFilter(nil), spec.Filters...)
	sort.Slice(spec.Filters, func(i, j int) bool { return spec.Filters[i].Column < spec.Filters[j].Column })
	canonical, err := json.Marshal(spec)
	if err != nil {
		return Profile{}, ErrInvalid
	}
	digest := sha256.Sum256(canonical)
	return Profile{spec: spec, hash: "sha256:" + hex.EncodeToString(digest[:])}, nil
}

// Schema is a neutral projection supplied by the SQL capability owner. It
// carries only the names and types needed to validate an operator profile.
type Schema struct {
	Revision int64
	Objects  []SchemaObject
}

type SchemaObject struct {
	SchemaName string
	TableName  string
	Columns    []SchemaColumn
}

type SchemaColumn struct {
	Name     string
	DataType string
}

// ValidateAgainstExposedSchema refuses a stale, ambiguous, or mismatched
// projection before a compiled read can be handed to the SQL capability owner.
func ValidateAgainstExposedSchema(profile Profile, schema Schema) error {
	if profile.hash == "" || schema.Revision != profile.spec.ExposedSchemaRevision ||
		len(schema.Objects) == 0 || len(schema.Objects) > 32 {
		return ErrInvalid
	}
	s := profile.spec
	seenObjects := map[string]bool{}
	found := false
	for _, object := range schema.Objects {
		if !safeIdentifier(object.SchemaName) || !safeIdentifier(object.TableName) ||
			len(object.Columns) == 0 || len(object.Columns) > 64 {
			return ErrInvalid
		}
		key := object.SchemaName + "." + object.TableName
		if seenObjects[key] {
			return ErrInvalid
		}
		seenObjects[key] = true
		columns := make(map[string]string, len(object.Columns))
		for _, column := range object.Columns {
			if !safeIdentifier(column.Name) || column.DataType == "" ||
				len(column.DataType) > 128 || !utf8.ValidString(column.DataType) ||
				strings.ContainsAny(column.DataType, "\x00\r\n") || columns[column.Name] != "" {
				return ErrInvalid
			}
			columns[column.Name] = column.DataType
		}
		if object.SchemaName != s.Schema || object.TableName != s.View {
			continue
		}
		found = true
		if columns[s.SnapshotColumn] != "timestamp with time zone" {
			return ErrInvalid
		}
		switch columns[s.MeasureColumn] {
		case "numeric", "smallint", "integer", "bigint":
		default:
			return ErrInvalid
		}
		if columns[s.SubjectColumn] == "" {
			return ErrInvalid
		}
		for _, filter := range s.Filters {
			if columns[filter.Column] == "" {
				return ErrInvalid
			}
		}
	}
	if !found {
		return ErrInvalid
	}
	return nil
}

// Compiled holds only SQL derived from the sealed profile and validated dates.
// A null value means no snapshot, duplicate subjects, or missing measures.
type Compiled struct {
	SQL         string
	ProfileHash string
	MetricID    string
	Unit        string
}

func validDate(value string) bool {
	if !datePattern.MatchString(value) {
		return false
	}
	parsed, err := time.Parse("2006-01-02", value)
	return err == nil && parsed.Year() >= 1 && parsed.Format("2006-01-02") == value
}

// Compile accepts exactly two distinct explicit dates. Dates determine read
// windows only; they cannot change the metric, filters, or SQL structure.
func Compile(profile Profile, firstDate, secondDate string) (Compiled, error) {
	if profile.hash == "" || !validDate(firstDate) || !validDate(secondDate) || firstDate == secondDate {
		return Compiled{}, ErrInvalid
	}
	s := profile.spec
	table := `"` + s.Schema + `"."` + s.View + `"`
	snapshot := `src."` + s.SnapshotColumn + `"`
	subject := `src."` + s.SubjectColumn + `"`
	measure := `src."` + s.MeasureColumn + `"`
	filters := ""
	for _, filter := range s.Filters {
		filters += ` AND src."` + filter.Column + `" = '` + filter.Value + `'`
	}
	// Each date first finds the latest timestamp shared by that date's rows.
	// At that exact timestamp, SUM covers observed rows only. Duplicate subjects,
	// null measures, and non-finite numeric values yield NULL; no population
	// completeness is inferred from the observed row count.
	sql := fmt.Sprintf(`WITH requested(local_date) AS (
  VALUES (DATE '%s'), (DATE '%s')
), latest AS (
  SELECT r.local_date, MAX(%s) AS snapshot_at
  FROM requested AS r
  LEFT JOIN %s AS src ON %s >= (r.local_date::timestamp AT TIME ZONE '%s')
    AND %s < ((r.local_date + 1)::timestamp AT TIME ZONE '%s')%s
  GROUP BY r.local_date
), totals AS (
  SELECT l.local_date, l.snapshot_at,
    COUNT(%s)::bigint AS contributing_rows,
    COUNT(DISTINCT %s)::bigint AS distinct_subjects,
    COUNT(%s)::bigint AS nonnull_count,
    CASE WHEN COUNT(%s) > 0
      AND COUNT(%s) = COUNT(DISTINCT %s)
      AND COUNT(%s) = COUNT(%s)
      AND COUNT(%s) = COUNT(%s) FILTER (WHERE %s::text NOT IN ('NaN', 'Infinity', '-Infinity'))
      THEN SUM(%s::numeric) FILTER (WHERE %s::text NOT IN ('NaN', 'Infinity', '-Infinity'))
      ELSE NULL END AS value
  FROM latest AS l
  LEFT JOIN %s AS src ON %s = l.snapshot_at%s
  GROUP BY l.local_date, l.snapshot_at
)
SELECT local_date, snapshot_at, contributing_rows, distinct_subjects, nonnull_count, value
FROM totals ORDER BY local_date DESC`, firstDate, secondDate,
		snapshot, table, snapshot, s.Timezone, snapshot, s.Timezone, filters,
		snapshot, subject, measure, snapshot, snapshot, subject, snapshot, measure,
		snapshot, measure, measure, measure, measure, table, snapshot, filters)
	return Compiled{SQL: sql, ProfileHash: profile.hash, MetricID: s.MetricID, Unit: s.Unit}, nil
}
