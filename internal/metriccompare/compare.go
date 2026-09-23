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
	MetricID       string
	Unit           string
	Schema         string
	View           string
	SubjectColumn  string
	SnapshotColumn string
	MeasureColumn  string
	Timezone       string
	Filters        []FixedFilter
}

// Profile is sealed by NewProfile. Its fields and filter slice cannot be
// changed by a caller after validation.
type Profile struct {
	spec ProfileSpec
	hash string
}

func (p Profile) Hash() string     { return p.hash }
func (p Profile) MetricID() string { return p.spec.MetricID }
func (p Profile) Unit() string     { return p.spec.Unit }

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

func NewProfile(spec ProfileSpec) (Profile, error) {
	if len(spec.MetricID) > 128 || !metricID.MatchString(spec.MetricID) ||
		!safeUnit(spec.Unit) || !safeIdentifier(spec.Schema) ||
		!safeIdentifier(spec.View) || !safeIdentifier(spec.SubjectColumn) ||
		!safeIdentifier(spec.SnapshotColumn) || !safeIdentifier(spec.MeasureColumn) ||
		!safeLiteral(spec.Timezone) ||
		(spec.Timezone != "UTC" && !strings.Contains(spec.Timezone, "/")) ||
		len(spec.Filters) > 4 {
		return Profile{}, ErrInvalid
	}
	if _, err := time.LoadLocation(spec.Timezone); err != nil {
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
	return err == nil && parsed.Format("2006-01-02") == value
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
	// At that exact timestamp, SUM is allowed only for a complete one-row-per-
	// subject snapshot. A malformed or incomplete snapshot yields NULL.
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
      THEN SUM(%s::numeric) ELSE NULL END AS value
  FROM latest AS l
  LEFT JOIN %s AS src ON %s = l.snapshot_at%s
  GROUP BY l.local_date, l.snapshot_at
)
SELECT local_date, snapshot_at, contributing_rows, distinct_subjects, nonnull_count, value
FROM totals ORDER BY local_date DESC`, firstDate, secondDate,
		snapshot, table, snapshot, s.Timezone, snapshot, s.Timezone, filters,
		snapshot, subject, measure, snapshot, snapshot, subject, snapshot, measure,
		measure, table, snapshot, filters)
	return Compiled{SQL: sql, ProfileHash: profile.hash, MetricID: s.MetricID, Unit: s.Unit}, nil
}
