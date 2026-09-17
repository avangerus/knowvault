// Package analytic owns bounded, server-selected analytic operations.  It is
// deliberately independent from SQL: callers provide only post-authorized,
// typed Evidence cells and a planner-owned AggregateSpec.  The adapter never
// receives query text, identifiers of database objects, or a citation choice.
package analytic

import (
	"context"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/planner"
)

const (
	maximumCells           = 256
	maximumBuckets         = 128
	maximumGroupDimensions = 4
)

type ErrorCode string

const (
	CodeInvalidRequest ErrorCode = "ANALYTIC_REQUEST_INVALID"
	CodeUnsupported    ErrorCode = "ANALYTIC_OPERATION_UNSUPPORTED"
	CodeIncomplete     ErrorCode = "ANALYTIC_EVIDENCE_INCOMPLETE"
	CodeConflict       ErrorCode = "ANALYTIC_EVIDENCE_CONFLICT"
)

type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeInvalidRequest
}

// Evidence is the metadata-only provenance carried into the analytic adapter.
// Text and anchors are rendered by the Question authority after this result is
// returned; the adapter cannot invent or select citations.
type Evidence struct {
	ID              string
	SourceObjectID  string
	SourceVersionID string
	ExtractionID    string
	TextHash        string
	AnchorHash      string
	ContentHash     string
}

// Validate exposes the reducer's provenance guard to other server-owned
// renderers. Keeping one validator prevents a legacy aggregate path from
// accepting a weaker Evidence shape than the generic adapter.
func (value Evidence) Validate() error {
	if !validEvidence(value) {
		return &Error{code: CodeInvalidRequest}
	}
	return nil
}

// Cell is one already-authorized typed projection cell.  RowKey is a stable
// source-row identity derived by the source adapter, never a caller label.
// Numeric cells carry a canonical decimal Value; non-numeric cells carry a
// canonical group label.  The adapter treats both as opaque Evidence-bound
// values and never parses arbitrary SQL output.
type Cell struct {
	Evidence Evidence
	RowKey   string
	Column   string
	Value    string
	Numeric  bool
}

// Request binds an aggregate to the immutable planner output.  PlanHash is
// required even though the caller also passes the typed spec: this prevents a
// result from being reused for a different Question Run.
type Request struct {
	WorkspaceID string
	PlanHash    string
	Spec        planner.AggregateSpec
	// Filters are copied from the immutable planner output. Equality filters
	// are applied to complete authorized rows; temporal filters are enforced by
	// the source-aware selection boundary before this source-neutral reducer.
	Filters []planner.Filter
	Cells   []Cell
}

type EvidenceRef struct {
	ID              string
	SourceObjectID  string
	SourceVersionID string
	ExtractionID    string
	TextHash        string
	AnchorHash      string
	ContentHash     string
}

type Bucket struct {
	Key           string
	Value         string
	Count         int64
	Evidence      []EvidenceRef
	GroupValues   []string
	GroupEvidence []EvidenceRef
	// FilterEvidence proves server-owned equality predicates used to select the
	// bucket's rows. It is separate from numeric witnesses so a filter cell can
	// be cited without being mistaken for an aggregate input.
	FilterEvidence []EvidenceRef
}

type Result struct {
	Function string
	Metric   string
	GroupBy  []string
	Order    string
	Buckets  []Bucket
}

// Adapter is the generic analytic tool contract.  A production SQL adapter
// may build Cells from a trusted projection snapshot, but this operation stays
// source-neutral and cannot execute or accept model-generated SQL.
type Adapter interface {
	Aggregate(context.Context, Request) (Result, error)
}

// EvidenceAdapter is the deterministic reducer used by the first live slice.
// It performs no I/O and is safe for concurrent calls; its inputs must already
// have passed the PostgreSQL Evidence authorization gate.
type EvidenceAdapter struct{}

func NewEvidenceAdapter() *EvidenceAdapter { return &EvidenceAdapter{} }

var decimalPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
var hmacDigestPattern = regexp.MustCompile(`^hmac-sha256:k[1-9][0-9]{0,8}:[0-9a-f]{64}$`)

func (adapter *EvidenceAdapter) Aggregate(ctx context.Context, request Request) (Result, error) {
	if adapter == nil || ctx == nil || !validOpaque(request.WorkspaceID) || !validDigest(request.PlanHash) || len(request.Cells) == 0 || len(request.Cells) > maximumCells {
		return Result{}, &Error{code: CodeInvalidRequest}
	}
	select {
	case <-ctx.Done():
		return Result{}, &Error{code: CodeIncomplete, cause: ctx.Err()}
	default:
	}
	if err := validateSpec(request.Spec); err != nil {
		return Result{}, err
	}
	if err := planner.ValidateFilters(request.Filters); err != nil {
		return Result{}, err
	}
	seenEvidence := make(map[string]struct{}, len(request.Cells))
	rows := make(map[string][]Cell)
	for _, cell := range request.Cells {
		if !validCell(cell) {
			return Result{}, &Error{code: CodeInvalidRequest}
		}
		if _, duplicate := seenEvidence[cell.Evidence.ID]; duplicate {
			return Result{}, &Error{code: CodeConflict}
		}
		seenEvidence[cell.Evidence.ID] = struct{}{}
		rows[cell.RowKey] = append(rows[cell.RowKey], cell)
	}
	rows = applyFilters(rows, request.Filters)
	if len(rows) == 0 {
		return Result{}, &Error{code: CodeIncomplete, cause: errors.New("filters matched no evidence rows")}
	}
	numericColumns := make(map[string]struct{})
	nonNumericColumns := make(map[string]struct{})
	for _, cells := range rows {
		for _, cell := range cells {
			if cell.Numeric {
				numericColumns[aggregateTermIdentity(cell.Column)] = struct{}{}
			} else {
				nonNumericColumns[aggregateTermIdentity(cell.Column)] = struct{}{}
			}
		}
	}
	metric := chooseColumn(request.Spec.Metric, numericColumns)
	effectiveFunction := request.Spec.Function
	countRows := effectiveFunction == "COUNT"
	if metric == "" && !countRows {
		if effectiveFunction == "SUM" && request.Spec.Metric == "" && len(numericColumns) == 0 {
			// The planner's lexical default is SUM, but this evidence has no
			// numeric column to sum at all (a source-neutral fact discovered
			// only here from the actual cells, not from any keyword). A
			// request to aggregate a quantity that does not exist as a number
			// is, for these rows, a request to count matching rows instead —
			// e.g. "how many vehicles are on a trip today" over row cards with no
			// numeric EVIDENCE column (V1-A). This never fires when a numeric
			// column exists but is merely ambiguous or unresolved: that stays
			// CodeIncomplete, unchanged.
			effectiveFunction = "COUNT"
			countRows = true
		} else {
			return Result{}, &Error{code: CodeIncomplete, cause: errors.New("metric column is not unambiguous")}
		}
	}
	groups := chooseGroupColumns(request.Spec.GroupBy, nonNumericColumns)
	if len(request.Spec.GroupBy) > 0 && len(groups) != len(request.Spec.GroupBy) {
		return Result{}, &Error{code: CodeIncomplete, cause: errors.New("group columns are not resolvable")}
	}
	type aggregate struct {
		key            string
		value          *big.Rat
		count          int64
		scale          int
		evidence       []EvidenceRef
		groupValues    []string
		groupEvidence  []EvidenceRef
		filterEvidence []EvidenceRef
	}
	buckets := make(map[string]*aggregate)
	for _, cells := range rows {
		groupValues := make([]string, len(groups))
		groupEvidence := make([]EvidenceRef, len(groups))
		groupFound := make([]bool, len(groups))
		var numbers []Cell
		for _, cell := range cells {
			if cell.Numeric && aggregateTermsEqual(cell.Column, metric) {
				numbers = append(numbers, cell)
			}
			if !cell.Numeric {
				for index, group := range groups {
					if !aggregateTermsEqual(cell.Column, group) {
						continue
					}
					if groupFound[index] && groupValues[index] != cell.Value {
						return Result{}, &Error{code: CodeConflict, cause: errors.New("row has conflicting group values")}
					}
					groupFound[index] = true
					groupValues[index] = cell.Value
					groupEvidence[index] = evidenceRef(cell.Evidence)
				}
			}
		}
		if !countRows && len(numbers) == 0 {
			return Result{}, &Error{code: CodeIncomplete, cause: errors.New("row lacks selected metric or group evidence")}
		}
		for index := range groups {
			if !groupFound[index] || groupValues[index] == "" {
				return Result{}, &Error{code: CodeIncomplete, cause: errors.New("row lacks selected metric or group evidence")}
			}
		}
		bucketKey := "__all__"
		if len(groups) > 0 {
			bucketKey = compositeGroupKey(groupValues)
		}
		bucket := buckets[bucketKey]
		if bucket == nil {
			if len(buckets) >= maximumBuckets {
				return Result{}, &Error{code: CodeIncomplete, cause: errors.New("aggregate bucket limit exceeded")}
			}
			bucket = &aggregate{key: bucketKey, value: new(big.Rat), groupValues: append([]string(nil), groupValues...), groupEvidence: append([]EvidenceRef(nil), groupEvidence...)}
			buckets[bucketKey] = bucket
		} else {
			// Map iteration order is intentionally unspecified. Keep the smallest
			// Evidence ID for each dimension so receipts and rendered citations are
			// deterministic across runs while still proving every label.
			for index, ref := range groupEvidence {
				if ref.ID != "" && (bucket.groupEvidence[index].ID == "" || ref.ID < bucket.groupEvidence[index].ID) {
					bucket.groupEvidence[index] = ref
				}
			}
		}
		if countRows {
			// COUNT counts immutable rows, not whichever numeric columns happened
			// to be projected. One deterministic cell proves each counted row.
			witness := append([]Cell(nil), cells...)
			sort.Slice(witness, func(i, j int) bool { return witness[i].Evidence.ID < witness[j].Evidence.ID })
			bucket.count++
			bucket.evidence = append(bucket.evidence, evidenceRef(witness[0].Evidence))
			bucket.filterEvidence = appendFilterEvidence(bucket.filterEvidence, cells, request.Filters)
			continue
		}
		for _, cell := range numbers {
			value, err := decimal(cell.Value)
			if err != nil {
				return Result{}, err
			}
			bucket.value.Add(bucket.value, value)
			bucket.count++
			bucket.scale = max(bucket.scale, decimalScale(cell.Value))
			bucket.evidence = append(bucket.evidence, evidenceRef(cell.Evidence))
		}
		bucket.filterEvidence = appendFilterEvidence(bucket.filterEvidence, cells, request.Filters)
	}
	if len(buckets) == 0 {
		return Result{}, &Error{code: CodeIncomplete}
	}
	keys := make([]string, 0, len(buckets))
	for key := range buckets {
		keys = append(keys, key)
	}
	for _, bucket := range buckets {
		switch effectiveFunction {
		case "COUNT":
			bucket.value.SetInt64(bucket.count)
			bucket.scale = 0
		case "AVG":
			bucket.value.Quo(bucket.value, big.NewRat(bucket.count, 1))
			if exactScale, exact := terminatingDecimalScale(bucket.value); exact {
				bucket.scale = max(bucket.scale, exactScale)
			} else if bucket.scale < 6 {
				// A recurring average is rounded only at a visible, deterministic
				// precision; never let FloatString(0) turn 3/2 into 2.
				bucket.scale = 6
			}
		case "MIN", "MAX":
			chosen, err := chooseExtremum(bucket.evidence, request.Cells, effectiveFunction, metric)
			if err != nil {
				return Result{}, err
			}
			bucket.value = chosen
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := buckets[keys[i]], buckets[keys[j]]
		if request.Spec.Order == "ASC" || request.Spec.Order == "DESC" {
			cmp := left.value.Cmp(right.value)
			if cmp != 0 {
				if request.Spec.Order == "ASC" {
					return cmp < 0
				}
				return cmp > 0
			}
		}
		return keys[i] < keys[j]
	})
	limit := len(keys)
	if request.Spec.Limit > 0 && request.Spec.Limit < limit {
		limit = request.Spec.Limit
	}
	result := Result{Function: effectiveFunction, Metric: metric, GroupBy: append([]string(nil), groups...), Order: request.Spec.Order, Buckets: make([]Bucket, 0, limit)}
	for _, key := range keys[:limit] {
		bucket := buckets[key]
		scale := bucket.scale
		if effectiveFunction == "COUNT" {
			scale = 0
		}
		evidence := append([]EvidenceRef(nil), bucket.evidence...)
		sort.Slice(evidence, func(i, j int) bool { return evidence[i].ID < evidence[j].ID })
		filterEvidence := append([]EvidenceRef(nil), bucket.filterEvidence...)
		sort.Slice(filterEvidence, func(i, j int) bool { return filterEvidence[i].ID < filterEvidence[j].ID })
		groupValues := append([]string(nil), bucket.groupValues...)
		groupEvidence := append([]EvidenceRef(nil), bucket.groupEvidence...)
		result.Buckets = append(result.Buckets, Bucket{Key: compositeGroupLabel(groupValues), Value: bucket.value.FloatString(scale), Count: bucket.count, Evidence: evidence, GroupValues: groupValues, GroupEvidence: groupEvidence, FilterEvidence: filterEvidence})
	}
	return result, nil
}

func appendFilterEvidence(existing []EvidenceRef, cells []Cell, filters []planner.Filter) []EvidenceRef {
	seen := make(map[string]struct{}, len(existing))
	for _, ref := range existing {
		seen[ref.ID] = struct{}{}
	}
	for _, filter := range filters {
		if !strings.HasPrefix(filter.Name, "equals:") {
			continue
		}
		field := strings.TrimPrefix(filter.Name, "equals:")
		for _, cell := range cells {
			if !aggregateTermsEqual(cell.Column, field) || !strings.EqualFold(cell.Value, filter.Value) {
				continue
			}
			ref := evidenceRef(cell.Evidence)
			if _, ok := seen[ref.ID]; ok {
				continue
			}
			seen[ref.ID] = struct{}{}
			existing = append(existing, ref)
		}
	}
	return existing
}

func applyFilters(rows map[string][]Cell, filters []planner.Filter) map[string][]Cell {
	if len(filters) == 0 {
		return rows
	}
	filtered := rows
	for _, filter := range filters {
		if !strings.HasPrefix(filter.Name, "equals:") {
			// Temporal filters are enforced while selecting/expanding authorized
			// PostgreSQL rows. They are intentionally not interpreted here because
			// the reducer receives no wall-clock or date-column policy.
			continue
		}
		field := strings.TrimPrefix(filter.Name, "equals:")
		next := make(map[string][]Cell, len(filtered))
		for rowKey, cells := range filtered {
			matched := false
			for _, cell := range cells {
				if aggregateTermsEqual(cell.Column, field) && strings.EqualFold(cell.Value, filter.Value) {
					matched = true
					break
				}
			}
			if matched {
				next[rowKey] = cells
			}
		}
		filtered = next
	}
	return filtered
}

func validateSpec(spec planner.AggregateSpec) error {
	switch spec.Function {
	case "SUM", "COUNT", "AVG", "MIN", "MAX":
	default:
		return &Error{code: CodeUnsupported}
	}
	if spec.Limit < 0 || spec.Order != "" && spec.Order != "ASC" && spec.Order != "DESC" || len(spec.GroupBy) > maximumGroupDimensions {
		return &Error{code: CodeInvalidRequest}
	}
	seenGroups := make(map[string]struct{}, len(spec.GroupBy))
	for _, term := range spec.GroupBy {
		if term == "" {
			return &Error{code: CodeInvalidRequest}
		}
		canonical := aggregateTermIdentity(term)
		if _, duplicate := seenGroups[canonical]; duplicate {
			return &Error{code: CodeInvalidRequest}
		}
		seenGroups[canonical] = struct{}{}
	}
	for _, term := range append(append([]string{}, spec.GroupBy...), spec.Metric) {
		if term != "" && !validOpaque(term) {
			return &Error{code: CodeInvalidRequest}
		}
	}
	return nil
}

func chooseColumn(requested string, columns map[string]struct{}) string {
	if requested != "" {
		for column := range columns {
			if aggregateTermsEqual(column, requested) {
				return column
			}
		}
		// Planner terms are semantic hints.  If the source adapter has exposed
		// exactly one numeric column, that column is an unambiguous resolution;
		// multiple numeric columns remain incomplete rather than guessing.
		if len(columns) == 1 {
			for column := range columns {
				return column
			}
		}
		return ""
	}
	if len(columns) != 1 {
		return ""
	}
	for column := range columns {
		return column
	}
	return ""
}

func chooseGroupColumns(requested []string, columns map[string]struct{}) []string {
	if len(requested) == 0 {
		// An omitted group-by is an explicit ungrouped aggregate. Never infer a
		// grouping merely because one context column happens to be present.
		return nil
	}
	resolved := make([]string, 0, len(requested))
	for _, term := range requested {
		var match string
		for column := range columns {
			if aggregateTermsEqual(column, term) {
				match = column
				break
			}
		}
		if match == "" {
			// A semantic alias may use one unambiguous non-temporal context
			// column, but only for a single requested dimension. Multi-group
			// requests must resolve every dimension exactly instead of guessing.
			if len(requested) != 1 {
				return nil
			}
			var fallback string
			for column := range columns {
				if temporalColumn(column) {
					continue
				}
				if fallback != "" {
					return nil
				}
				fallback = column
			}
			match = fallback
		}
		if match == "" {
			return nil
		}
		resolved = append(resolved, match)
	}
	return resolved
}

// compositeGroupKey is an internal collision-resistant key. Length-prefixing
// keeps values such as "a / b" distinct from two dimensions "a" and "b".
func compositeGroupKey(values []string) string {
	var builder strings.Builder
	for _, value := range values {
		builder.WriteString(strconv.Itoa(len(value)))
		builder.WriteByte(':')
		builder.WriteString(value)
		builder.WriteByte('|')
	}
	return builder.String()
}

func compositeGroupLabel(values []string) string {
	if len(values) == 0 {
		return "__all__"
	}
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values, " / ")
}

func temporalColumn(column string) bool {
	lower := strings.ToLower(column)
	return strings.Contains(lower, "date") || strings.Contains(lower, "time") ||
		strings.Contains(lower, "timestamp") || strings.Contains(lower, "\u0434\u0430\u0442\u0430") || strings.Contains(lower, "\u0432\u0440\u0435\u043c\u044f") ||
		strings.HasSuffix(lower, "_at") || strings.HasSuffix(lower, "_on")
}

func chooseExtremum(evidence []EvidenceRef, cells []Cell, function, metric string) (*big.Rat, error) {
	var chosen *big.Rat
	for _, ref := range evidence {
		for _, cell := range cells {
			if cell.Evidence.ID != ref.ID || !cell.Numeric || !aggregateTermsEqual(cell.Column, metric) {
				continue
			}
			value, err := decimal(cell.Value)
			if err != nil {
				return nil, err
			}
			if chosen == nil || function == "MIN" && value.Cmp(chosen) < 0 || function == "MAX" && value.Cmp(chosen) > 0 {
				chosen = value
			}
		}
	}
	if chosen == nil {
		return nil, &Error{code: CodeIncomplete}
	}
	return chosen, nil
}

func decimal(value string) (*big.Rat, error) {
	if !decimalPattern.MatchString(value) {
		return nil, &Error{code: CodeInvalidRequest, cause: errors.New("non-canonical decimal")}
	}
	ratio, ok := new(big.Rat).SetString(value)
	if !ok {
		return nil, &Error{code: CodeInvalidRequest}
	}
	return ratio, nil
}

func decimalScale(value string) int {
	if index := strings.IndexByte(value, '.'); index >= 0 {
		return len(value) - index - 1
	}
	return 0
}

func terminatingDecimalScale(value *big.Rat) (int, bool) {
	if value == nil {
		return 0, false
	}
	denominator := new(big.Int).Set(value.Denom())
	two, five := big.NewInt(2), big.NewInt(5)
	twos, fives := 0, 0
	for new(big.Int).Mod(denominator, two).Sign() == 0 {
		denominator.Quo(denominator, two)
		twos++
	}
	for new(big.Int).Mod(denominator, five).Sign() == 0 {
		denominator.Quo(denominator, five)
		fives++
	}
	if denominator.Cmp(big.NewInt(1)) != 0 {
		return 0, false
	}
	if twos > fives {
		return twos, true
	}
	return fives, true
}

func evidenceRef(value Evidence) EvidenceRef {
	return EvidenceRef{ID: value.ID, SourceObjectID: value.SourceObjectID, SourceVersionID: value.SourceVersionID, ExtractionID: value.ExtractionID, TextHash: value.TextHash, AnchorHash: value.AnchorHash, ContentHash: value.ContentHash}
}

func validCell(cell Cell) bool {
	if !validEvidence(cell.Evidence) || !validOpaque(cell.RowKey) || !validOpaque(cell.Column) || !validOpaque(cell.Value) {
		return false
	}
	if cell.Numeric && !decimalPattern.MatchString(cell.Value) {
		return false
	}
	return true
}

// validEvidence is intentionally stricter than the generic opaque checks. An
// analytic result is publishable only when every value carries the complete
// immutable source lineage that the PostgreSQL authorization gate returned.
// Empty or malformed lineage is never treated as a low-quality hit: it is an
// invalid tool input and fails closed before reduction.
func validEvidence(value Evidence) bool {
	return validOpaque(value.ID) && validOpaque(value.SourceObjectID) &&
		validOpaque(value.SourceVersionID) && validOpaque(value.ExtractionID) &&
		validDigest(value.ContentHash) && validKeyedDigest(value.TextHash) &&
		validKeyedDigest(value.AnchorHash)
}

func validOpaque(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\r\n\x00")
}

// aggregateTermIdentity normalizes only the SQL column portion. JSON Pointer
// member names remain case-sensitive so distinct Evidence paths cannot merge.
func aggregateTermIdentity(value string) string {
	value = strings.TrimSpace(value)
	if open := strings.IndexByte(value, '['); open >= 0 {
		return strings.ToLower(value[:open]) + value[open:]
	}
	return strings.ToLower(value)
}

func aggregateTermsEqual(left, right string) bool {
	return aggregateTermIdentity(left) == aggregateTermIdentity(right)
}

func validDigest(value string) bool {
	if hmacDigestPattern.MatchString(value) {
		return true
	}
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validKeyedDigest(value string) bool {
	return hmacDigestPattern.MatchString(value)
}

func max(left, right int) int {
	if left > right {
		return left
	}
	return right
}
