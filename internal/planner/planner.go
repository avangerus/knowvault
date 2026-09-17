// Package planner classifies a natural-language question into a server-owned
// operation plan.  It is deliberately source-agnostic: the planner names the
// work to do (lookup, compare, aggregate, etc.) but never emits SQL, evidence
// IDs, URLs, or factual values.  Those remain authority-owned responsibilities
// of retrieval and tool adapters.
package planner

import (
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	SchemaVersion    = "knowledge-plan-v1"
	MaxQuestionBytes = 32 << 10
)

// Operation is the generic task vocabulary.  Adding a source or a business
// entity must not add an operation or a question-specific branch.
type Operation string

const (
	Lookup    Operation = "LOOKUP"
	Explain   Operation = "EXPLAIN"
	Compare   Operation = "COMPARE"
	Aggregate Operation = "AGGREGATE"
	Audit     Operation = "AUDIT"
	CodeTrace Operation = "CODE_TRACE"
	Unknown   Operation = "UNKNOWN"
	Clarify   Operation = "CLARIFY"
)

type Status string

const (
	Ready         Status = "READY"
	UnknownStatus Status = "UNKNOWN"
	ClarifyStatus Status = "CLARIFICATION_REQUIRED"
)

// Filter is a typed, source-neutral constraint.  It is a planner hint only;
// an adapter must validate and bind it before executing any tool call.
type Filter struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AggregateSpec expresses the generic group-by + aggregate + rank shape.  No
// business noun is special-cased here: GroupBy and Metric are terms extracted
// from the question and are later resolved against the semantic catalog.
type AggregateSpec struct {
	Function string   `json:"function"`
	Metric   string   `json:"metric,omitempty"`
	GroupBy  []string `json:"group_by,omitempty"`
	Order    string   `json:"order,omitempty"`
	Limit    int      `json:"limit,omitempty"`
}

// Plan is immutable output of the planner. CanonicalBytes and PlanHash are
// server-generated and can be persisted with a Question Run as provenance.
type Plan struct {
	SchemaVersion  string         `json:"schema_version"`
	Status         Status         `json:"status"`
	Operation      Operation      `json:"operation"`
	SubjectTerms   []string       `json:"subject_terms,omitempty"`
	EntityHints    []string       `json:"entity_hints,omitempty"`
	Filters        []Filter       `json:"filters,omitempty"`
	Aggregate      *AggregateSpec `json:"aggregate,omitempty"`
	Confidence     string         `json:"confidence"`
	Reasons        []string       `json:"reasons,omitempty"`
	Clarification  string         `json:"clarification,omitempty"`
	QuestionHash   string         `json:"question_hash"`
	PlanHash       string         `json:"plan_hash"`
	CanonicalBytes []byte         `json:"-"`
}

// Validate is the trust boundary for downstream executors. A caller may
// inspect a plan, but an adapter must reject a forged operation, hash or
// aggregate specification before it can touch retrieval or a tool.
func (plan Plan) Validate() error {
	if plan.SchemaVersion != SchemaVersion || !validDigest(plan.QuestionHash) || !validDigest(plan.PlanHash) {
		return ErrInvalidQuestion
	}
	if ValidateFilters(plan.Filters) != nil {
		return ErrInvalidQuestion
	}
	switch plan.Status {
	case Ready:
		switch plan.Operation {
		case Lookup, Explain, Compare, Aggregate, Audit, CodeTrace:
		default:
			return ErrInvalidQuestion
		}
	case UnknownStatus:
		if plan.Operation != Unknown {
			return ErrInvalidQuestion
		}
	case ClarifyStatus:
		if plan.Operation != Clarify || strings.TrimSpace(plan.Clarification) == "" {
			return ErrInvalidQuestion
		}
	default:
		return ErrInvalidQuestion
	}
	if plan.Operation == Aggregate {
		if plan.Aggregate == nil {
			return ErrInvalidQuestion
		}
		switch plan.Aggregate.Function {
		case "SUM", "COUNT", "AVG", "MIN", "MAX", "LIST":
		default:
			return ErrInvalidQuestion
		}
		if plan.Aggregate.Order != "" && plan.Aggregate.Order != "ASC" && plan.Aggregate.Order != "DESC" {
			return ErrInvalidQuestion
		}
		if plan.Aggregate.Limit < 0 {
			return ErrInvalidQuestion
		}
		if plan.Aggregate.Metric != "" && !aggregateTermPattern.MatchString(strings.TrimSpace(plan.Aggregate.Metric)) {
			return ErrInvalidQuestion
		}
		if len(plan.Aggregate.GroupBy) > 4 {
			return ErrInvalidQuestion
		}
		seenGroups := make(map[string]struct{}, len(plan.Aggregate.GroupBy))
		for _, group := range plan.Aggregate.GroupBy {
			group = aggregateFieldIdentity(group)
			if !aggregateTermPattern.MatchString(group) {
				return ErrInvalidQuestion
			}
			if _, duplicate := seenGroups[group]; duplicate {
				return ErrInvalidQuestion
			}
			seenGroups[group] = struct{}{}
		}
	}
	projection := planProjection(plan)
	raw, err := canon.CanonicalJSON(projection)
	if err != nil || string(raw) != string(plan.CanonicalBytes) || canon.Hash(raw) != plan.PlanHash {
		return ErrInvalidQuestion
	}
	return nil
}

// ErrInvalidQuestion is returned only for malformed input.  An ordinary
// unsupported or ambiguous question is represented as UNKNOWN/CLARIFY so the
// caller can persist a safe terminal outcome instead of fabricating an answer.
var ErrInvalidQuestion = errors.New("planner: invalid question")

type rule struct {
	operation Operation
	markers   []string
	weight    int
}

var defaultRules = []rule{
	{operation: Explain, weight: 3, markers: []string{
		"\u0447\u0442\u043e \u043e\u0437\u043d\u0430\u0447\u0430\u0435\u0442", "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435", "\u043e\u0431\u044a\u044f\u0441\u043d\u0438", "\u043e\u0431\u044a\u044f\u0441\u043d\u0438\u0442\u044c", "meaning", "define", "how does", "\u043a\u0430\u043a \u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442", "\u0433\u0434\u0435 \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u0443\u0435\u0442\u0441\u044f", "used",
	}},
	{operation: Compare, weight: 3, markers: []string{
		"\u0441\u0440\u0430\u0432\u043d\u0438", "\u0441\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435", "\u0440\u0430\u0441\u0445\u043e\u0436\u0434", "\u043e\u0442\u043b\u0438\u0447", "\u043c\u0435\u0436\u0434\u0443", "compare", "difference", "versus", " vs ",
	}},
	{operation: Aggregate, weight: 3, markers: []string{
		"\u0441\u043a\u043e\u043b\u044c\u043a\u043e", "\u0441\u0443\u043c\u043c", "\u0438\u0442\u043e\u0433\u043e", "\u0432\u0441\u0435\u0433\u043e", "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432", "\u0447\u0438\u0441\u043b", "\u0431\u043e\u043b\u044c\u0448\u0435", "\u043c\u0435\u043d\u044c\u0448\u0435", "\u043d\u0430\u0438\u0431\u043e\u043b", "\u043d\u0430\u0438\u043c\u0435\u043d\u044c", "total", "how many", "how much", "aggregate", "sum", "count", "counts", "number", "average", "avg", "\u043c\u0430\u043a\u0441\u0438\u043c\u0443\u043c", "\u043c\u0438\u043d\u0438\u043c\u0443\u043c", "\u0442\u043e\u043f", "rank", "group by",
		// "which vehicles were on a route yesterday" is the same analytic task
		// as "how many vehicles are on a route today" — one asks the reduced
		// count, the other the reduced set — and both are answered by reducing
		// the source's whole current snapshot, never by quoting whichever rows
		// lexical retrieval returned. Enumeration markers therefore score the
		// AGGREGATE operation, and aggregateListRequest below turns the plan
		// into the LIST function. A question that also carries a stronger
		// EXPLAIN/AUDIT/CODE_TRACE signal still wins on score, unchanged.
		"\u043a\u0430\u043a\u0438\u0435", "\u043a\u0430\u043a\u0438\u0445", "\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438", "\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438\u0442\u044c",
	}},
	{operation: Audit, weight: 3, markers: []string{
		"\u043f\u0440\u043e\u0432\u0435\u0440\u044c", "\u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c", "\u0430\u0443\u0434\u0438\u0442", "audit", "compliance", "compliant", "\u043a\u043e\u043d\u0442\u0440\u043e\u043b", "\u0441\u043e\u043e\u0442\u0432\u0435\u0442\u0441\u0442\u0432", "\u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434", "\u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d", "\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c",
	}},
	{operation: CodeTrace, weight: 3, markers: []string{
		"\u0432 \u043a\u043e\u0434\u0435", "\u043a\u043e\u0434", "commit", "\u043a\u043e\u043c\u043c\u0438\u0442", "\u0440\u0435\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d", "\u0440\u0435\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d\u044b", "\u0440\u0435\u0430\u043b\u0438\u0437\u0430\u0446", "implemented", "implementation", "repository", "\u0440\u0435\u043f\u043e\u0437\u0438\u0442\u043e\u0440", "git", "trace",
	}},
}

var tokenPattern = regexp.MustCompile(`(?i)[\p{L}\p{N}][\p{L}\p{N}_-]*`)

// Date filters are deliberately a small, unambiguous grammar. They become
// end-exclusive UTC ranges before retrieval; malformed or unbounded windows
// are rejected rather than silently widening an aggregate.
// Keep the lexical recognizer broader than the canonical form.  Parsing below
// validates calendar values and emits a normalized, end-exclusive range; this
// ensures a malformed value cannot fall through as an unscoped aggregate.
var explicitDateRangePattern = regexp.MustCompile("(?i)([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})\\s*(?:\u043f\u043e|\u0434\u043e|through|to|[-\u2013\u2014])\\s*([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})")
var relativeDaysPattern = regexp.MustCompile("(?i)(?:\u043f\u043e\u0441\u043b\u0435\u0434\u043d(?:\u0438\u0435|\u0438\u0445)?|last|\u0437\u0430)\\s+([0-9]+)\\s+(?:\u0434\u043d(?:\u044f|\u0435\u0439)?|days?)")
var unboundedDatePattern = regexp.MustCompile("(?i)(?:\u0441|from|after|\u043f\u043e\u0441\u043b\u0435|\u0434\u043e|before|until)\\s+([0-9]{4}-[0-9]{1,2}-[0-9]{1,2})")
// overdueConditionPattern is SEED-3 #1's marker dictionary for a declarable
// "condition" filter: Russian inflections of "overdue" and English "overdue" all
// name the same server-owned condition (a structured row whose declared
// PERIOD/due-date column is before "now" and, when the projection declares a
// STATUS column, not already closed -- internal/question/snapshot_aggregate.go
// resolves the actual comparison; the planner only recognizes the word and
// emits an opaque condition name, exactly like every other filter here).
var overdueConditionPattern = regexp.MustCompile("(?i)^(?:\u043f\u0440\u043e\u0441\u0440\u043e\u0447\\p{L}*|overdue)$")

var filterFieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n]*\])?$`)
var equalityFilterPattern = regexp.MustCompile("(?i)(?:^|[\\s,;])([A-Za-z_][A-Za-z0-9_$]{0,62}(?:\\[/[^\\x00-\\x1F\\x7F-\\x9F\\r\\n]*\\])?)\\s*(?:=|\u0440\u0430\u0432\u0435\u043d|\u0440\u0430\u0432\u043d\u0430|\u0440\u0430\u0432\u043d\u043e|equals?)\\s*(?:\"([^\"\\r\\n]{1,128})\"|'([^'\\r\\n]{1,128})'|([^\\s,;]{1,128}))")
var incompleteEqualityFilterPattern = regexp.MustCompile("(?i)(?:^|[\\s,;])([A-Za-z_][A-Za-z0-9_$]{0,62}(?:\\[/[^\\x00-\\x1F\\x7F-\\x9F\\r\\n]*\\])?)\\s*(?:=|\u0440\u0430\u0432\u0435\u043d|\u0440\u0430\u0432\u043d\u0430|\u0440\u0430\u0432\u043d\u043e|equals?)\\s*(?:\"\"|''|[?!.,]|$)")
var unterminatedEqualityQuotePattern = regexp.MustCompile("(?i)(?:^|[\\s,;])([A-Za-z_][A-Za-z0-9_$]{0,62}(?:\\[/[^\\x00-\\x1F\\x7F-\\x9F\\r\\n]*\\])?)\\s*(?:=|\u0440\u0430\u0432\u0435\u043d|\u0440\u0430\u0432\u043d\u0430|\u0440\u0430\u0432\u043d\u043e|equals?)\\s*(?:\"[^\"\\r\\n]*$|'[^'\\r\\n]*$)")

// unsupportedActionPattern is deliberately limited to imperative/write
// requests and raw statement prefixes. A question such as "what is SQL"
// remains an ordinary EXPLAIN request, while a caller cannot smuggle an
// executable SQL statement or a side effect into a read-only knowledge query.
// This is an authority boundary, not a business-question branch: the planner
// returns UNKNOWN and no downstream adapter is allowed to run.
var unsupportedActionPattern = regexp.MustCompile("(?i)^(?:select|insert|update|delete|drop|alter|truncate|merge|\u0432\u044b\u043f\u043e\u043b\u043d\u0438|\u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u044c|\u0437\u0430\u043f\u0443\u0441\u0442\u0438|\u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u044c|\u0443\u0434\u0430\u043b\u0438|\u0443\u0434\u0430\u043b\u0438\u0442\u044c|\u0438\u0437\u043c\u0435\u043d\u0438|\u0438\u0437\u043c\u0435\u043d\u0438\u0442\u044c|\u043e\u0431\u043d\u043e\u0432\u0438|\u043e\u0431\u043d\u043e\u0432\u0438\u0442\u044c|\u0441\u043e\u0437\u0434\u0430\u0439|\u0441\u043e\u0437\u0434\u0430\u0442\u044c|\u0437\u0430\u043f\u0438\u0448\u0438|\u0437\u0430\u043f\u0438\u0441\u0430\u0442\u044c|\u043e\u0442\u043f\u0440\u0430\u0432\u044c|\u043e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c)(?:\\s|$)")

var stopWords = map[string]struct{}{
	"\u0430": {}, "\u0438": {}, "\u0432": {}, "\u0432\u043e": {}, "\u043d\u0430": {}, "\u043f\u043e": {}, "\u0438\u0437": {}, "\u0437\u0430": {}, "\u0434\u043b\u044f": {}, "\u043a\u0430\u043a": {}, "\u0447\u0442\u043e": {}, "\u044d\u0442\u043e": {},
	"\u043b\u0438": {}, "\u0443": {}, "\u043a": {}, "\u043e": {}, "\u043e\u0431": {}, "\u043d\u0430\u0441": {}, "\u043d\u0430\u043c": {}, "\u043c\u044b": {}, "\u043d\u0430\u0448": {}, "\u043d\u0430\u0448\u0430": {}, "\u043d\u0430\u0448\u0438": {},
	"\u044d\u0442\u043e\u043c": {}, "\u044d\u0442\u043e\u0442": {}, "\u044d\u0442\u0430": {}, "\u044d\u0442\u0438": {}, "the": {}, "and": {}, "of": {}, "to": {}, "in": {}, "is": {}, "are": {},
	"what": {}, "which": {}, "who": {}, "how": {}, "does": {}, "do": {}, "our": {}, "this": {}, "that": {},
}

var aggregateNoiseTerms = map[string]struct{}{
	"\u0441\u043a\u043e\u043b\u044c\u043a\u043e": {}, "sum": {}, "total": {}, "\u0438\u0442\u043e\u0433\u043e": {}, "\u0432\u0441\u0435\u0433\u043e": {}, "how": {}, "many": {},
	"much": {}, "\u043f\u043e": {}, "by": {}, "group": {}, "\u0442\u043e\u043f": {}, "top": {}, "rank": {},
	"\u0441": {}, "\u0434\u043e": {}, "\u0437\u0430": {}, "\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435": {}, "\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0445": {}, "last": {}, "\u0434\u0435\u043d\u044c": {}, "\u0434\u043d\u044f": {}, "\u0434\u043d\u0435\u0439": {}, "days": {},
	"\u0431\u043e\u043b\u044c\u0448\u0435": {}, "\u043c\u0435\u043d\u044c\u0448\u0435": {}, "\u043d\u0430\u0438\u0431\u043e\u043b": {}, "\u043d\u0430\u0438\u043c\u0435\u043d\u044c": {}, "highest": {}, "lowest": {},
	"\u0441\u0443\u043c\u043c\u0430": {}, "\u0441\u0443\u043c\u043c\u0435": {}, "\u0441\u0443\u043c\u043c\u043e\u0439": {}, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432\u043e": {}, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432": {},
	"\u0441\u0435\u0433\u043e\u0434\u043d\u044f": {}, "today": {}, "\u0432\u0447\u0435\u0440\u0430": {}, "yesterday": {}, "\u043d\u0435\u0434\u0435\u043b\u044f": {}, "\u043d\u0435\u0434\u0435\u043b\u0435": {}, "week": {},
	"\u043c\u0435\u0441\u044f\u0446": {}, "\u043c\u0435\u0441\u044f\u0446\u0435": {}, "month": {}, "\u0433\u043e\u0434": {}, "\u0433\u043e\u0434\u0443": {}, "year": {},
}

var aggregateMetricMarkers = map[string]struct{}{
	"\u0441\u043a\u043e\u043b\u044c\u043a\u043e": {}, "sum": {}, "total": {}, "\u0438\u0442\u043e\u0433\u043e": {}, "\u0432\u0441\u0435\u0433\u043e": {}, "how": {}, "many": {}, "much": {},
	"\u0431\u043e\u043b\u044c\u0448\u0435": {}, "\u043c\u0435\u043d\u044c\u0448\u0435": {}, "highest": {}, "lowest": {}, "\u0442\u043e\u043f": {}, "top": {}, "rank": {},
}

// Explicit aggregate clauses keep the planner source-neutral while allowing a
// semantic catalog to name arbitrary metric and grouping fields. They are
// still only opaque identifiers here; resolution and authorization happen in
// the downstream adapter.
var aggregateMetricClausePattern = regexp.MustCompile(`(?i)(?:^|[\s,;])metric(?:_field)?\s*(?:=|:)\s*([^\s;]{1,256})`)

// The raw value is bounded to one whitespace-delimited token; commas/plus
// signs inside that token are parsed as an ordered list. Empty, malformed or
// duplicate dimensions therefore fail closed instead of silently selecting
// only the first column.
var aggregateGroupClausePattern = regexp.MustCompile(`(?i)(?:^|[\s,;])group[_ ]?by\s*(?:=|:)\s*([^\s;]{1,256})`)
var aggregateGroupClausePresencePattern = regexp.MustCompile(`(?i)(?:^|[\s,;])group[_ ]?by\s*(?:=|:)`)
var aggregateIdentifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}$`)
var aggregateFieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]{0,62}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n\]]{1,192}\])?$`)
var aggregateTermPattern = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_$.-]{0,62}(?:\[/[^\x00-\x1F\x7F-\x9F\r\n\]]{1,192}\])?$`)
var aggregateOrderClausePattern = regexp.MustCompile(`(?i)(?:^|[\s,;])order\s*(?:=|:)\s*(asc|desc)\b`)
var aggregateRankClausePattern = regexp.MustCompile(`(?i)(?:^|[\s,;])(?:top|rank|limit)\s*(?:=|:)\s*([0-9]{1,3})\b`)

// aggregateFieldIdentity normalizes only the SQL column portion. JSON Pointer
// member names are case-sensitive, so lower-casing the complete term would
// make `/Region` and `/region` address the wrong business-object leaf.
func aggregateFieldIdentity(value string) string {
	value = strings.TrimSpace(value)
	if open := strings.IndexByte(value, '['); open >= 0 {
		return strings.ToLower(value[:open]) + value[open:]
	}
	return strings.ToLower(value)
}

func canonicalAggregateField(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if !aggregateFieldPattern.MatchString(value) {
		return "", false
	}
	return aggregateFieldIdentity(value), true
}

type aggregateClauseSpec struct {
	metric  string
	groupBy []string
	order   string
	limit   int
	invalid bool
}

func parseAggregateClauses(normalized string) aggregateClauseSpec {
	var clauses aggregateClauseSpec
	if match := aggregateMetricClausePattern.FindStringSubmatch(normalized); len(match) == 2 {
		metric, ok := canonicalAggregateField(match[1])
		if !ok {
			clauses.invalid = true
		} else {
			clauses.metric = metric
		}
	}
	groupMatches := aggregateGroupClausePattern.FindAllStringSubmatch(normalized, -1)
	if aggregateGroupClausePresencePattern.MatchString(normalized) && len(groupMatches) == 0 {
		clauses.invalid = true
	}
	for _, match := range groupMatches {
		if len(match) != 2 || match[1] == "" {
			clauses.invalid = true
			continue
		}
		parts := strings.FieldsFunc(match[1], func(r rune) bool { return r == ',' || r == '+' })
		if len(parts) == 0 || len(parts) > 4 || len(parts) != strings.Count(match[1], ",")+strings.Count(match[1], "+")+1 {
			clauses.invalid = true
			continue
		}
		seen := make(map[string]struct{}, len(parts))
		for _, part := range parts {
			canonical, ok := canonicalAggregateField(part)
			if !ok {
				clauses.invalid = true
				continue
			}
			if _, duplicate := seen[canonical]; duplicate {
				clauses.invalid = true
				continue
			}
			seen[canonical] = struct{}{}
			clauses.groupBy = append(clauses.groupBy, canonical)
		}
	}
	if match := aggregateOrderClausePattern.FindStringSubmatch(normalized); len(match) == 2 {
		clauses.order = strings.ToUpper(match[1])
	}
	if match := aggregateRankClausePattern.FindStringSubmatch(normalized); len(match) == 2 {
		if limit, err := strconv.Atoi(match[1]); err == nil && limit > 0 && limit <= 128 {
			clauses.limit = limit
		}
	}
	return clauses
}

func applyAggregateClauses(spec *AggregateSpec, clauses aggregateClauseSpec) {
	if spec == nil {
		return
	}
	if clauses.metric != "" {
		spec.Metric = clauses.metric
	}
	if len(clauses.groupBy) > 0 {
		spec.GroupBy = append([]string(nil), clauses.groupBy...)
	}
	if clauses.order != "" {
		spec.Order = clauses.order
	}
	if clauses.limit > 0 {
		spec.Limit = clauses.limit
	}
}

// Planner is stateless and safe to share between requests. Rules are copied
// on construction so a caller cannot mutate the server-owned registry.
type Planner struct {
	rules []rule
}

func New() *Planner {
	rules := make([]rule, len(defaultRules))
	copy(rules, defaultRules)
	return &Planner{rules: rules}
}

// Default returns the built-in source-neutral planner.
func Default() *Planner { return New() }

// Plan creates a deterministic plan. The only lexical knowledge here is a
// versioned operation vocabulary; entity names, source kinds, columns and
// values are deliberately not encoded in the planner.
func (p *Planner) Plan(question string) (Plan, error) {
	if p == nil {
		p = Default()
	}
	canonical, err := canon.Canonicalize([]byte(question))
	if err != nil || len(canonical) == 0 || len(canonical) > MaxQuestionBytes {
		return Plan{}, ErrInvalidQuestion
	}
	normalized := strings.ToLower(string(canonical))
	tokens := questionTokens(normalized)
	terms := meaningfulTerms(tokens)
	if len(terms) == 0 {
		return p.finish(Plan{SchemaVersion: SchemaVersion, Status: UnknownStatus, Operation: Unknown, Confidence: "NONE", Reasons: []string{"no_searchable_terms"}}, canonical)
	}
	if malformedEqualityFilter(normalized) {
		return p.finish(Plan{SchemaVersion: SchemaVersion, Status: UnknownStatus, Operation: Unknown,
			SubjectTerms: terms, EntityHints: entityHints(terms), Confidence: "NONE",
			Reasons: []string{"invalid_equality_filter"}}, canonical)
	}
	filters, invalidPeriod := extractFilters(normalized, tokens)
	if invalidPeriod {
		return p.finish(Plan{SchemaVersion: SchemaVersion, Status: UnknownStatus, Operation: Unknown,
			SubjectTerms: terms, EntityHints: entityHints(terms), Confidence: "NONE",
			Reasons: []string{"invalid_time_period"}}, canonical)
	}
	if conflictingEqualityFilters(filters) {
		// Different values for one server-resolved field cannot be interpreted as
		// a safe conjunction.  Stop before retrieval so neither a lexical hit nor
		// an analytic adapter can guess which value the user intended.
		return p.finish(Plan{SchemaVersion: SchemaVersion, Status: UnknownStatus, Operation: Unknown,
			SubjectTerms: terms, EntityHints: entityHints(terms), Confidence: "NONE",
			Reasons: []string{"conflicting_equality_filter"}}, canonical)
	}
	if unsupportedActionPattern.MatchString(normalized) {
		return p.finish(Plan{
			SchemaVersion: SchemaVersion, Status: UnknownStatus, Operation: Unknown,
			SubjectTerms: terms, EntityHints: entityHints(terms), Confidence: "NONE",
			Reasons: []string{"unsupported_read_only_boundary"},
		}, canonical)
	}

	scores := make(map[Operation]int, len(p.rules))
	reasons := make(map[Operation][]string, len(p.rules))
	for _, candidate := range p.rules {
		for _, marker := range candidate.markers {
			if strings.Contains(normalized, marker) {
				scores[candidate.operation] += candidate.weight
				reasons[candidate.operation] = append(reasons[candidate.operation], marker)
			}
		}
	}
	chosen, top, tied := choose(scores)
	if top == 0 {
		chosen = Lookup
		reasons[chosen] = []string{"default_lookup"}
	}
	if len(tied) > 1 && top > 0 {
		// Two equally strong task types cannot safely be executed by guessing.
		// The caller must ask a clarification question.
		return p.finish(Plan{
			SchemaVersion: SchemaVersion, Status: ClarifyStatus, Operation: Clarify,
			SubjectTerms: terms, Confidence: "LOW", Reasons: []string{"ambiguous_operations:" + strings.Join(tied, ",")},
			Clarification: "Please clarify whether you want to find a fact, compare sources, aggregate data, or run an audit.",
		}, canonical)
	}

	plan := Plan{
		SchemaVersion: SchemaVersion, Status: Ready, Operation: chosen,
		SubjectTerms: terms, Confidence: confidence(top), Reasons: reasons[chosen],
	}
	plan.Filters = filters
	plan.EntityHints = entityHints(terms)
	if chosen == Aggregate {
		plan.Aggregate = aggregateSpec(normalized, string(canonical), tokens, terms)
		if plan.Aggregate == nil {
			// An explicit analytic clause that cannot be parsed safely is not an
			// invitation to guess. Keep the terminal plan hashable, but stop before
			// retrieval/tool execution with bounded UNKNOWN semantics.
			plan.Status = UnknownStatus
			plan.Operation = Unknown
			plan.Reasons = []string{"invalid_aggregate_clause"}
		}
	}
	return p.finish(plan, canonical)
}

func (p *Planner) finish(plan Plan, canonical []byte) (Plan, error) {
	plan.SchemaVersion = SchemaVersion
	plan.QuestionHash = canon.Hash(canonical)
	// Hash only server-owned, canonical plan fields. This keeps the digest
	// stable while excluding CanonicalBytes and the digest itself.
	projection := planProjection(plan)
	raw, err := canon.CanonicalJSON(projection)
	if err != nil {
		return Plan{}, err
	}
	plan.CanonicalBytes = append([]byte(nil), raw...)
	plan.PlanHash = canon.Hash(raw)
	return plan, nil
}

func planProjection(plan Plan) any {
	return struct {
		SchemaVersion string         `json:"schema_version"`
		Status        Status         `json:"status"`
		Operation     Operation      `json:"operation"`
		SubjectTerms  []string       `json:"subject_terms,omitempty"`
		EntityHints   []string       `json:"entity_hints,omitempty"`
		Filters       []Filter       `json:"filters,omitempty"`
		Aggregate     *AggregateSpec `json:"aggregate,omitempty"`
		Confidence    string         `json:"confidence"`
		Reasons       []string       `json:"reasons,omitempty"`
		Clarification string         `json:"clarification,omitempty"`
		QuestionHash  string         `json:"question_hash"`
	}{plan.SchemaVersion, plan.Status, plan.Operation, plan.SubjectTerms, plan.EntityHints, plan.Filters, plan.Aggregate, plan.Confidence, plan.Reasons, plan.Clarification, plan.QuestionHash}
}

func validDigest(value string) bool {
	return len(value) == len("sha256:")+64 && strings.HasPrefix(value, "sha256:")
}

func choose(scores map[Operation]int) (Operation, int, []string) {
	top := 0
	chosen := Unknown
	for operation, score := range scores {
		if score > top || score == top && (chosen == Unknown || string(operation) < string(chosen)) {
			chosen, top = operation, score
		}
	}
	tied := make([]string, 0)
	if top > 0 {
		for operation, score := range scores {
			if score == top {
				tied = append(tied, string(operation))
			}
		}
		sort.Strings(tied)
	}
	return chosen, top, tied
}

func confidence(score int) string {
	switch {
	case score >= 6:
		return "HIGH"
	case score >= 3:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func questionTokens(value string) []string {
	return tokenPattern.FindAllString(value, -1)
}

func meaningfulTerms(tokens []string) []string {
	seen := make(map[string]struct{}, len(tokens))
	terms := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.ToLower(strings.TrimSpace(token))
		if token == "" || len([]rune(token)) < 2 {
			continue
		}
		if _, stop := stopWords[token]; stop {
			continue
		}
		if _, exists := seen[token]; exists {
			continue
		}
		seen[token] = struct{}{}
		terms = append(terms, token)
	}
	return terms
}

func entityHints(terms []string) []string {
	// Entity hints are opaque catalog lookup keys, not facts. Keep only terms
	// that contain a letter and leave semantic resolution to the catalog.
	hints := make([]string, 0, len(terms))
	for _, term := range terms {
		if strings.IndexFunc(term, unicode.IsLetter) >= 0 {
			hints = append(hints, term)
		}
	}
	return hints
}

func extractFilters(normalized string, tokens []string) (filters []Filter, malformed bool) {
	filters = make([]Filter, 0, 4)
	defer func() {
		filtered := filters[:0]
		for _, filter := range filters {
			field := strings.TrimPrefix(filter.Name, "equals:")
			switch strings.ToLower(field) {
			case "metric", "metric_field", "group_by", "groupby", "top", "rank", "limit", "order":
				continue
			}
			filtered = append(filtered, filter)
		}
		filters = filtered
	}()
	// A question may contain more than one temporal expression. Picking the
	// first one would make the answer depend on regex order and silently widen
	// or narrow the requested corpus. Keep the temporal grammar single-valued:
	// conflicting/duplicated windows become UNKNOWN at the planner boundary.
	explicitRanges := explicitDateRangePattern.FindAllStringSubmatch(normalized, -1)
	relativeWindows := relativeDaysPattern.FindAllStringSubmatch(normalized, -1)
	if len(explicitRanges) > 1 || len(relativeWindows) > 1 {
		return nil, true
	}
	if len(explicitRanges) == 1 {
		matches := explicitRanges[0]
		start, startOK := parseDateToken(matches[1])
		end, endOK := parseDateToken(matches[2])
		if !startOK || !endOK || !start.Before(end) {
			return nil, true
		}
		if len(relativeWindows) > 0 {
			return nil, true
		}
		// Natural-language "to" ranges in Russian and English include the right edge;
		// persist the normalized end-exclusive boundary so retrieval cannot
		// disagree about date precision.
		end = end.AddDate(0, 0, 1)
		filters = append(filters, Filter{Name: "time_range", Value: start.Format("2006-01-02") + "/" + end.Format("2006-01-02")})
	} else if len(relativeWindows) == 1 {
		matches := relativeWindows[0]
		count, err := strconv.Atoi(matches[1])
		if err != nil || count < 1 || count > 366 {
			return nil, true
		}
		filters = append(filters, Filter{Name: "time_window", Value: "last_days:" + strconv.Itoa(count)})
	} else if unboundedDatePattern.MatchString(normalized) {
		// A one-sided date bound is not safe for a bounded planner: accepting it
		// without an execution contract would silently widen the query. Require
		// the caller to provide an explicit two-sided range instead.
		return nil, true
	}
	periods := make([]string, 0, 1)
	for _, value := range []string{"\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today", "\u0432\u0447\u0435\u0440\u0430", "yesterday", "\u043c\u0435\u0441\u044f\u0446", "month", "\u043d\u0435\u0434\u0435\u043b\u044f", "week", "\u0433\u043e\u0434", "year"} {
		if periodTokenPresent(tokens, value) {
			periods = append(periods, value)
		}
	}
	if len(periods) > 1 || len(filters) > 0 && len(periods) > 0 {
		return nil, true
	}
	if len(periods) == 1 {
		filters = append(filters, Filter{Name: "time_period", Value: periods[0]})
	}
	// Equality predicates are deliberately explicit (`field = value` or
	// `field equals value`). The field is a server-resolved projection/catalog
	// key, never SQL text. The analytic adapter rechecks this filter against the
	// authorized Evidence cells before reducing rows.
	for _, matches := range equalityFilterPattern.FindAllStringSubmatch(normalized, -1) {
		if len(matches) != 5 {
			continue
		}
		value := matches[2]
		if value == "" {
			value = matches[3]
		}
		if value == "" {
			value = matches[4]
			// Sentence punctuation belongs to the question, not an unquoted
			// scalar filter value. Quoted values retain punctuation verbatim.
			value = strings.TrimRight(value, "?!.,")
		}
		if value == "" {
			return nil, true
		}
		filters = append(filters, Filter{Name: "equals:" + strings.ToLower(matches[1]), Value: strings.TrimSpace(value)})
	}
	// SEED-3 #1: "overdue" is a declarable condition, not a time window --
	// it names a fixed comparison against "now" (and, when declared, a closed
	// status set) rather than a calendar range, so it is independent of the
	// time_period/time_window/time_range grammar above and never conflicts
	// with it.
	if overdueConditionRequested(tokens) {
		filters = append(filters, Filter{Name: "condition", Value: "overdue"})
	}
	return filters, false
}

func overdueConditionRequested(tokens []string) bool {
	for _, token := range tokens {
		if overdueConditionPattern.MatchString(token) {
			return true
		}
	}
	return false
}

// periodFollowUpWords are the tokens that a pure period follow-up ("and
// yesterday?", "and for the week?") may carry besides the recognized time filter
// itself: fillers stopWords already removes ("and", "for", ...) plus the
// words the relative-days grammar leaves behind once its digit token is
// dropped as too short to be a meaningfulTerm ("for 3 days" -> the digit "3"
// never reaches terms; Russian inflections of "day" and "last" would).
var periodFollowUpWords = map[string]struct{}{
	"\u0434\u043d\u044f": {}, "\u0434\u043d\u0435\u0439": {}, "\u0434\u0435\u043d\u044c": {}, "days": {}, "day": {},
	"\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0435": {}, "\u043f\u043e\u0441\u043b\u0435\u0434\u043d\u0438\u0445": {}, "last": {},
}

// PeriodFollowUp recognizes a minimal topic-memory follow-up: a question that
// carries exactly one recognized time filter (extractFilters' time_period or
// time_window grammar) and nothing else meaningful -- "and yesterday?", "for
// the week?", "and for the last 3 days?". It deliberately does not attempt
// time_range (an explicit two-sided date) or an equality filter: those are
// full new questions, not a bare period continuation. A caller uses this to
// decide whether to splice the recognized filter onto a prior turn's
// question (SpliceFollowUpPeriod) rather than plan this text on its own.
func PeriodFollowUp(question string) (Filter, bool) {
	canonical, err := canon.Canonicalize([]byte(question))
	if err != nil || len(canonical) == 0 || len(canonical) > MaxQuestionBytes {
		return Filter{}, false
	}
	normalized := strings.ToLower(string(canonical))
	tokens := questionTokens(normalized)
	terms := meaningfulTerms(tokens)
	if len(terms) == 0 {
		return Filter{}, false
	}
	if malformedEqualityFilter(normalized) {
		return Filter{}, false
	}
	filters, malformed := extractFilters(normalized, tokens)
	if malformed || len(filters) != 1 {
		return Filter{}, false
	}
	filter := filters[0]
	if filter.Name != "time_period" && filter.Name != "time_window" {
		return Filter{}, false
	}
	for _, term := range terms {
		if periodFollowUpTerm(term) {
			continue
		}
		return Filter{}, false
	}
	return filter, true
}

func periodFollowUpTerm(term string) bool {
	for _, period := range []string{"\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today", "\u0432\u0447\u0435\u0440\u0430", "yesterday", "\u043c\u0435\u0441\u044f\u0446", "month", "\u043d\u0435\u0434\u0435\u043b\u044f", "week", "\u0433\u043e\u0434", "year"} {
		if periodTokenPresent([]string{term}, period) {
			return true
		}
	}
	_, ok := periodFollowUpWords[term]
	return ok
}

// SpliceFollowUpPeriod combines a prior turn's literal question text with a
// follow-up's recognized period filter, replacing nothing: it only appends
// the new period phrase. It declines (returns false) when the base question
// already carries its own time filter -- splicing a second one would either
// conflict inside extractFilters (two periods) or silently pick one, and
// this package never guesses which period the caller means now.
func SpliceFollowUpPeriod(baseQuestion string, filter Filter) (string, bool) {
	if filter.Name != "time_period" && filter.Name != "time_window" {
		return "", false
	}
	canonical, err := canon.Canonicalize([]byte(baseQuestion))
	if err != nil || len(canonical) == 0 {
		return "", false
	}
	normalized := strings.ToLower(string(canonical))
	tokens := questionTokens(normalized)
	if malformedEqualityFilter(normalized) {
		return "", false
	}
	baseFilters, malformed := extractFilters(normalized, tokens)
	if malformed {
		return "", false
	}
	for _, existing := range baseFilters {
		if existing.Name == "time_period" || existing.Name == "time_window" || existing.Name == "time_range" {
			return "", false
		}
	}
	var phrase string
	switch filter.Name {
	case "time_period":
		phrase = filter.Value
	case "time_window":
		parts := strings.SplitN(filter.Value, ":", 2)
		if len(parts) != 2 || parts[1] == "" {
			return "", false
		}
		phrase = "\u0437\u0430 " + parts[1] + " \u0434\u043d\u0435\u0439"
	}
	combined := strings.TrimSpace(baseQuestion) + " " + phrase
	if len(combined) > MaxQuestionBytes {
		return "", false
	}
	return combined, true
}

// isAggregateFunctionMarker names the single reduction (COUNT vs LIST) one
// lexical term asks for. It is deliberately a small closed dictionary,
// shared by AggregateFunctionFollowUp (recognizing a bare operation-only
// follow-up) and SpliceFollowUpFunction (stripping a base question's own
// marker before splicing in a new one) -- never wired into defaultRules, so
// it has no effect on ordinary first-turn classification.
func isAggregateFunctionMarker(term string) (function string, ok bool) {
	switch {
	case term == "\u0441\u043a\u043e\u043b\u044c\u043a\u043e":
		return "COUNT", true
	case strings.HasPrefix(term, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432"):
		return "COUNT", true
	case strings.HasPrefix(term, "\u0447\u0438\u0441\u043b"):
		return "COUNT", true
	case term == "\u043a\u0430\u043a\u0438\u0435" || term == "\u043a\u0430\u043a\u0438\u0445":
		return "LIST", true
	case strings.HasPrefix(term, "\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b"):
		return "LIST", true
	case strings.HasPrefix(term, "\u043f\u043e\u043a\u0430\u0436"):
		return "LIST", true
	default:
		return "", false
	}
}

// AggregateFunctionFollowUp recognizes FIX-6 #1's second minimal topic-memory
// shape: a bare operation-only follow-up ("which ones?", "and how many?",
// "list them") whose only meaningful terms are one recognized aggregate
// reduction marker (isAggregateFunctionMarker) and otherwise-ignorable
// filler. It deliberately declines whenever the text also carries its own
// recognized period/equality filter (extractFilters returning anything):
// PeriodFollowUp/a full new question already own that case, and this narrow
// detector never guesses between two conditions named in the same follow-up.
func AggregateFunctionFollowUp(question string) (string, bool) {
	canonical, err := canon.Canonicalize([]byte(question))
	if err != nil || len(canonical) == 0 || len(canonical) > MaxQuestionBytes {
		return "", false
	}
	normalized := strings.ToLower(string(canonical))
	tokens := questionTokens(normalized)
	terms := meaningfulTerms(tokens)
	if len(terms) == 0 {
		return "", false
	}
	if malformedEqualityFilter(normalized) {
		return "", false
	}
	if filters, malformed := extractFilters(normalized, tokens); malformed || len(filters) != 0 {
		return "", false
	}
	function := ""
	for _, term := range terms {
		candidate, ok := isAggregateFunctionMarker(term)
		if !ok {
			return "", false
		}
		if function != "" && function != candidate {
			// Two different reduction markers in one bare follow-up ("how many,
			// which ones?") name no single request; decline instead of picking one.
			return "", false
		}
		function = candidate
	}
	if function == "" {
		return "", false
	}
	return function, true
}

// SpliceFollowUpFunction combines a prior turn's literal question text with a
// follow-up's requested reduction (function, from AggregateFunctionFollowUp),
// changing only which reduction is requested: every occurrence of the base
// question's own reduction marker word(s) is removed (a plain textual append
// would leave the base's own marker in place and defeat the new one -- see
// aggregateListRequest's quantity-word veto), and the follow-up's canonical
// marker phrase is appended in its place. It declines (returns false) when
// the base question names no recognized reduction marker at all: nothing to
// replace means this is not a safe operation-only continuation of it.
func SpliceFollowUpFunction(baseQuestion, function string) (string, bool) {
	var phrase string
	switch function {
	case "COUNT":
		phrase = "\u0441\u043a\u043e\u043b\u044c\u043a\u043e"
	case "LIST":
		phrase = "\u043a\u0430\u043a\u0438\u0435"
	default:
		return "", false
	}
	canonical, err := canon.Canonicalize([]byte(baseQuestion))
	if err != nil || len(canonical) == 0 {
		return "", false
	}
	text := string(canonical)
	locations := tokenPattern.FindAllStringIndex(text, -1)
	var builder strings.Builder
	last := 0
	removedAny := false
	for _, loc := range locations {
		token := strings.ToLower(text[loc[0]:loc[1]])
		if _, ok := isAggregateFunctionMarker(token); !ok {
			continue
		}
		builder.WriteString(text[last:loc[0]])
		last = loc[1]
		removedAny = true
	}
	builder.WriteString(text[last:])
	rebuilt := strings.Join(strings.Fields(builder.String()), " ")
	if !removedAny || rebuilt == "" {
		return "", false
	}
	combined := rebuilt + " " + phrase
	if len(combined) > MaxQuestionBytes {
		return "", false
	}
	return combined, true
}

// conflictingEqualityFilters detects an unsatisfiable/ambiguous conjunction
// without assigning meaning to the field or value.  Both are still opaque
// catalog keys; comparison only uses the same case-insensitive scalar equality
// semantics as the Evidence authorization layer.
func conflictingEqualityFilters(filters []Filter) bool {
	seen := make(map[string]string)
	for _, filter := range filters {
		if !strings.HasPrefix(filter.Name, "equals:") {
			continue
		}
		field := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(filter.Name, "equals:")))
		value := strings.TrimSpace(filter.Value)
		if previous, ok := seen[field]; ok && !strings.EqualFold(previous, value) {
			return true
		}
		seen[field] = value
	}
	return false
}

// malformedEqualityFilter catches an explicit field/operator whose scalar is
// absent or unterminated. Ignoring it would silently widen a query by treating
// the rest of the request as unfiltered. The check is syntax-only; catalog
// resolution and Evidence authorization still happen downstream.
func malformedEqualityFilter(normalized string) bool {
	return incompleteEqualityFilterPattern.MatchString(normalized) || unterminatedEqualityQuotePattern.MatchString(normalized)
}

// periodTokenPresent deliberately uses token boundaries. A substring check
// would match Russian "segodnya" (today) as both "segodnya" and "god" (year), turning an ordinary
// single-day request into a false ambiguity.
func periodTokenPresent(tokens []string, period string) bool {
	for _, token := range tokens {
		token = strings.ToLower(token)
		switch period {
		case "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today", "\u0432\u0447\u0435\u0440\u0430", "yesterday", "month", "week", "year":
			if token == period {
				return true
			}
		case "\u043c\u0435\u0441\u044f\u0446":
			if strings.HasPrefix(token, "\u043c\u0435\u0441\u044f\u0446") {
				return true
			}
		case "\u043d\u0435\u0434\u0435\u043b\u044f":
			if strings.HasPrefix(token, "\u043d\u0435\u0434\u0435\u043b") {
				return true
			}
		case "\u0433\u043e\u0434":
			if strings.HasPrefix(token, "\u0433\u043e\u0434") || token == "\u043b\u0435\u0442" {
				return true
			}
		}
	}
	return false
}

func parseDateToken(value string) (time.Time, bool) {
	parts := strings.Split(value, "-")
	if len(parts) != 3 || len(parts[0]) != 4 || (len(parts[1]) != 1 && len(parts[1]) != 2) || (len(parts[2]) != 1 && len(parts[2]) != 2) {
		return time.Time{}, false
	}
	year, yearErr := strconv.Atoi(parts[0])
	month, monthErr := strconv.Atoi(parts[1])
	day, dayErr := strconv.Atoi(parts[2])
	if yearErr != nil || monthErr != nil || dayErr != nil || year < 1 || year > 9999 {
		return time.Time{}, false
	}
	parsed := time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	if parsed.Year() != year || int(parsed.Month()) != month || parsed.Day() != day {
		return time.Time{}, false
	}
	return parsed, true
}

// ValidateFilters is the shared plan/filter trust boundary used by planner and
// analytic adapters. Unknown filter encodings are rejected rather than ignored
// (which could otherwise turn a constrained aggregate into a wider one).
func ValidateFilters(filters []Filter) error {
	if len(filters) > 32 {
		return ErrInvalidQuestion
	}
	for _, filter := range filters {
		if !validFilter(filter) {
			return ErrInvalidQuestion
		}
	}
	return nil
}

func validFilter(filter Filter) bool {
	if filter.Name == "" || filter.Value == "" || len(filter.Name) > 128 || len(filter.Value) > 256 ||
		strings.TrimSpace(filter.Name) != filter.Name || strings.TrimSpace(filter.Value) != filter.Value ||
		strings.ContainsAny(filter.Name+filter.Value, "\r\n\x00") {
		return false
	}
	switch filter.Name {
	case "time_period":
		switch strings.ToLower(filter.Value) {
		case "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "today", "\u0432\u0447\u0435\u0440\u0430", "yesterday", "\u043c\u0435\u0441\u044f\u0446", "month", "\u043d\u0435\u0434\u0435\u043b\u044f", "week", "\u0433\u043e\u0434", "year":
			return true
		default:
			return false
		}
	case "time_range":
		parts := strings.Split(filter.Value, "/")
		if len(parts) != 2 || len(parts[0]) != 10 || len(parts[1]) != 10 {
			return false
		}
		start, startOK := parseDateToken(parts[0])
		end, endOK := parseDateToken(parts[1])
		return startOK && endOK && start.Before(end)
	case "time_window":
		if !strings.HasPrefix(filter.Value, "last_days:") {
			return false
		}
		count, err := strconv.Atoi(strings.TrimPrefix(filter.Value, "last_days:"))
		return err == nil && count >= 1 && count <= 366
	case "condition":
		// SEED-3 #1: "overdue" is the only condition name the planner ever
		// emits; a closed vocabulary here keeps a forged plan from smuggling
		// in an unrecognized condition the reducer would have to interpret.
		return filter.Value == "overdue"
	default:
		if !strings.HasPrefix(filter.Name, "equals:") {
			return false
		}
		field := strings.TrimPrefix(filter.Name, "equals:")
		return filterFieldPattern.MatchString(field)
	}
}

// aggregateListRequest recognizes "enumerate the matching rows' subject"
// phrasing. A question that also asks for a quantity, a total or a ranking is
// not an enumeration: those keep their own reduction, so the two families never
// collide and an ambiguous phrasing stays with the arithmetic reading.
func aggregateListRequest(normalized string) bool {
	for _, quantity := range []string{
		"\u0441\u043a\u043e\u043b\u044c\u043a\u043e", "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432", "\u0447\u0438\u0441\u043b", "\u0441\u0443\u043c\u043c", "\u0438\u0442\u043e\u0433\u043e", "\u0432\u0441\u0435\u0433\u043e", "\u0441\u0440\u0435\u0434\u043d", "\u043c\u0430\u043a\u0441\u0438\u043c\u0443\u043c", "\u043c\u0438\u043d\u0438\u043c\u0443\u043c",
		"how many", "how much", "total", "sum", "count", "average", "avg", "\u0442\u043e\u043f", "top", "rank",
		"\u0431\u043e\u043b\u044c\u0448\u0435", "\u043c\u0435\u043d\u044c\u0448\u0435", "\u043d\u0430\u0438\u0431\u043e\u043b", "\u043d\u0430\u0438\u043c\u0435\u043d\u044c",
	} {
		if strings.Contains(normalized, quantity) {
			return false
		}
	}
	for _, enumeration := range []string{"\u043a\u0430\u043a\u0438\u0435", "\u043a\u0430\u043a\u0438\u0445", "\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438", "\u043f\u0435\u0440\u0435\u0447\u0438\u0441\u043b\u0438\u0442\u044c"} {
		if strings.Contains(normalized, enumeration) {
			return true
		}
	}
	return false
}

func aggregateSpec(normalized, clauseText string, tokens, terms []string) (spec *AggregateSpec) {
	spec = &AggregateSpec{Function: "SUM"}
	clauses := parseAggregateClauses(clauseText)
	if clauses.invalid {
		return nil
	}
	defer func() { applyAggregateClauses(spec, clauses) }()
	if aggregateListRequest(normalized) {
		// An enumeration request names no metric and no ranking; it asks for the
		// distinct set the matching rows are about. Returning here also keeps the
		// Russian and English "which/who" grammar below from reading the enumerated noun as
		// a grouping column — in "which vehicles were on a trip yesterday" that noun is
		// the thing being listed, not a dimension to group by, and treating it as
		// a column would make the plan unresolvable against the real projection.
		spec.Function = "LIST"
		return spec
	}
	switch {
	case strings.Contains(normalized, "\u043a\u043e\u043b\u0438\u0447\u0435\u0441\u0442\u0432"), strings.Contains(normalized, "\u0447\u0438\u0441\u043b"), containsToken(tokens, "count", "counts", "number"):
		spec.Function = "COUNT"
	case strings.Contains(normalized, "average"), strings.Contains(normalized, "avg"), strings.Contains(normalized, "\u0441\u0440\u0435\u0434\u043d"):
		spec.Function = "AVG"
	case strings.Contains(normalized, "\u043c\u0430\u043a\u0441\u0438\u043c\u0443\u043c"), strings.Contains(normalized, "maximum"), strings.Contains(normalized, "max"):
		spec.Function = "MAX"
	case strings.Contains(normalized, "\u043c\u0438\u043d\u0438\u043c\u0443\u043c"), strings.Contains(normalized, "minimum"), strings.Contains(normalized, "min"):
		spec.Function = "MIN"
	}
	if strings.Contains(normalized, "\u0431\u043e\u043b\u044c\u0448\u0435") || strings.Contains(normalized, "\u0442\u043e\u043f") || strings.Contains(normalized, "\u043d\u0430\u0438\u0431\u043e\u043b") || strings.Contains(normalized, "highest") || strings.Contains(normalized, "top") || strings.Contains(normalized, "rank") {
		spec.Order = "DESC"
		spec.Limit = 1
		// "top N" is a generic ranking constraint, not an entity-specific
		// branch. Keep the number bounded so a natural-language request cannot
		// widen the analytic result beyond the server-owned budget.
		for index, token := range tokens {
			if token != "\u0442\u043e\u043f" && token != "top" && token != "rank" {
				continue
			}
			if index+1 >= len(tokens) {
				continue
			}
			value := 0
			for _, digit := range tokens[index+1] {
				if digit < '0' || digit > '9' {
					value = 0
					break
				}
				value = value*10 + int(digit-'0')
				if value > 128 {
					value = 0
					break
				}
			}
			if value > 0 {
				spec.Limit = value
			}
			break
		}
	}
	for index, token := range tokens {
		if token == "\u043f\u043e" || token == "by" || token == "group" && index+1 < len(tokens) && tokens[index+1] == "by" {
			start := index + 1
			if token == "group" {
				start++
			}
			// In ranking phrasing such as "top teams by total requests" or
			// "top teams by total requests", the preposition introduces the
			// metric, while the group noun is immediately before it. Treat that
			// as a generic grammar rule; ordinary "by department" keeps the
			// following term as the group.
			if (token == "\u043f\u043e" || token == "by") && start < len(tokens) {
				next := strings.ToLower(tokens[start])
				if _, metricPhrase := aggregateNoiseTerms[next]; metricPhrase {
					if previous := previousMeaningful(tokens, index-1); previous != "" {
						spec.GroupBy = []string{previous}
						continue
					}
				}
			}
			if start < len(tokens) {
				candidateIndex := start
				if strings.ToLower(tokens[candidateIndex]) == "by" && candidateIndex+1 < len(tokens) {
					candidateIndex++
				}
				candidate := strings.ToLower(tokens[candidateIndex])
				if _, stop := stopWords[candidate]; !stop && len(candidate) > 1 && !strings.ContainsAny(candidate, "0123456789") {
					spec.GroupBy = []string{candidate}
					// A conjunction after the first dimension is a generic grammar
					// signal, not a business-specific branch. Keep the list bounded and
					// let the typed adapter resolve every term exactly.
					next := candidateIndex + 1
					if next < len(tokens) && (tokens[next] == "\u0438" || tokens[next] == "and") {
						if second := nextMeaningful(tokens, next+1); second != "" && second != candidate {
							spec.GroupBy = append(spec.GroupBy, second)
						}
					}
				}
			}
		}
	}
	if len(spec.GroupBy) == 0 {
		for index, token := range tokens {
			if (token == "\u043a\u0442\u043e" || token == "\u043a\u0430\u043a\u0438\u0435" || token == "which" || token == "who") && index+1 < len(tokens) {
				candidate := nextMeaningful(tokens, index+1)
				if candidate != "" {
					spec.GroupBy = []string{candidate}
					break
				}
			}
		}
	}
	// Metric remains a catalog term. Prefer a non-stop term after an
	// aggregation marker, but never reuse a group term or a ranking/filler
	// token as the metric. If the question does not name a metric, leave it
	// unresolved so the typed adapter can resolve exactly one numeric column or
	// return INSUFFICIENT_EVIDENCE instead of guessing.
	groupTerms := make(map[string]struct{}, len(spec.GroupBy))
	for _, group := range spec.GroupBy {
		groupTerms[strings.ToLower(group)] = struct{}{}
	}
	for index, token := range tokens {
		if _, marker := aggregateMetricMarkers[token]; !marker {
			continue
		}
		for _, next := range tokens[index+1:] {
			candidate := strings.ToLower(next)
			if strings.ContainsAny(candidate, "0123456789") || len(candidate) < 2 {
				continue
			}
			if _, stop := stopWords[candidate]; stop {
				continue
			}
			if _, noise := aggregateNoiseTerms[candidate]; noise {
				continue
			}
			if _, group := groupTerms[candidate]; group {
				continue
			}
			spec.Metric = candidate
			break
		}
		if spec.Metric != "" {
			break
		}
	}
	if spec.Metric == "" {
		for index := len(terms) - 1; index >= 0; index-- {
			candidate := strings.ToLower(terms[index])
			if _, noise := aggregateNoiseTerms[candidate]; noise {
				continue
			}
			if _, group := groupTerms[candidate]; group {
				continue
			}
			spec.Metric = candidate
			break
		}
	}
	return spec
}

func containsToken(tokens []string, values ...string) bool {
	for _, token := range tokens {
		for _, value := range values {
			if token == value {
				return true
			}
		}
	}
	return false
}

func nextMeaningful(tokens []string, start int) string {
	for _, token := range tokens[start:] {
		token = strings.ToLower(token)
		if len(token) > 1 {
			if _, stop := stopWords[token]; stop {
				continue
			}
			if _, noise := aggregateNoiseTerms[token]; noise {
				continue
			}
			if !strings.ContainsAny(token, "0123456789") {
				return token
			}
		}
	}
	return ""
}

func previousMeaningful(tokens []string, start int) string {
	for index := start; index >= 0; index-- {
		token := strings.ToLower(tokens[index])
		if len(token) <= 1 || strings.ContainsAny(token, "0123456789") {
			continue
		}
		if _, stop := stopWords[token]; stop {
			continue
		}
		if _, noise := aggregateNoiseTerms[token]; noise {
			continue
		}
		return token
	}
	return ""
}
