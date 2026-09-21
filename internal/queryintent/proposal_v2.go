package queryintent

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type ScalarKind string

const (
	KindBOOL        ScalarKind = "BOOL"
	KindINT         ScalarKind = "INT"
	KindNUMERIC     ScalarKind = "NUMERIC"
	KindTEXT        ScalarKind = "TEXT"
	KindDATE        ScalarKind = "DATE"
	KindTIMESTAMP   ScalarKind = "TIMESTAMP"
	KindTIMESTAMPTZ ScalarKind = "TIMESTAMPTZ"
)

func (k ScalarKind) Valid() bool {
	return k == KindBOOL || k == KindINT || k == KindNUMERIC || k == KindTEXT || k == KindDATE || k == KindTIMESTAMP || k == KindTIMESTAMPTZ
}

const (
	MaxScalarText   = 256
	maxNumericBytes = 128
	maxInMembers    = 20
)

type Scalar struct {
	kind ScalarKind
	text string
	i    int64
	b    bool
}

func (s Scalar) Kind() ScalarKind            { return s.kind }
func (s Scalar) Bool() (bool, bool)          { return s.b, s.kind == KindBOOL }
func (s Scalar) Int() (int64, bool)          { return s.i, s.kind == KindINT }
func (s Scalar) Numeric() (string, bool)     { return s.text, s.kind == KindNUMERIC }
func (s Scalar) Text() (string, bool)        { return s.text, s.kind == KindTEXT }
func (s Scalar) Date() (string, bool)        { return s.text, s.kind == KindDATE }
func (s Scalar) Timestamp() (string, bool)   { return s.text, s.kind == KindTIMESTAMP }
func (s Scalar) Timestamptz() (string, bool) { return s.text, s.kind == KindTIMESTAMPTZ }

func BoolScalar(v bool) Scalar { return Scalar{kind: KindBOOL, b: v} }
func IntScalar(v int64) Scalar { return Scalar{kind: KindINT, i: v} }

func TextScalar(v string) (Scalar, error) {
	return textScalar(KindTEXT, v, utf8.ValidString(v) && len(v) <= MaxScalarText)
}

func NumericScalar(v string) (Scalar, error) {
	if len(v) == 0 || len(v) > maxNumericBytes {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	body, negative := v, false
	if body[0] == '-' {
		negative, body = true, body[1:]
	}
	parts := strings.Split(body, ".")
	if len(parts) > 2 || len(parts[0]) == 0 || !asciiDigits(parts[0]) || (len(parts) == 2 && (len(parts[1]) == 0 || !asciiDigits(parts[1]))) {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	ip, fp := strings.TrimLeft(parts[0], "0"), ""
	if ip == "" {
		ip = "0"
	}
	if len(parts) == 2 {
		fp = strings.TrimRight(parts[1], "0")
	}
	canon := ip
	if fp != "" {
		canon += "." + fp
	}
	if canon == "0" {
		negative = false
	}
	if negative {
		canon = "-" + canon
	}
	if len(canon) > maxNumericBytes {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	return Scalar{kind: KindNUMERIC, text: canon}, nil
}

func DateScalar(v string) (Scalar, error) {
	return textScalar(KindDATE, v, validDate(v))
}

func TimestampScalar(v string) (Scalar, error) {
	tail, ok := wallTail(v)
	return textScalar(KindTIMESTAMP, v, ok && tail == "")
}

func TimestamptzScalar(v string) (Scalar, error) {
	tail, ok := wallTail(v)
	if !ok || (tail != "Z" && !validOffset(tail)) {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	return textScalar(KindTIMESTAMPTZ, t.UTC().Format(time.RFC3339Nano), true)
}

func textScalar(k ScalarKind, v string, ok bool) (Scalar, error) {
	if !ok {
		return Scalar{}, newRefusal(CodeInvalidProposal)
	}
	return Scalar{kind: k, text: v}, nil
}

func asciiDigits(v string) bool {
	return v != "" && strings.Trim(v, "0123456789") == ""
}

func validDate(v string) bool {
	if len(v) != 10 || v[:4] == "0000" {
		return false
	}
	t, err := time.Parse("2006-01-02", v)
	return err == nil && t.Format("2006-01-02") == v
}

func validClock(v string) bool {
	if len(v) != 8 {
		return false
	}
	_, err := time.Parse("15:04:05", v)
	return err == nil
}

func wallTail(v string) (string, bool) {
	if len(v) < 19 || v[10] != 'T' || !validDate(v[:10]) || !validClock(v[11:19]) {
		return "", false
	}
	tail := v[19:]
	if tail == "" || tail[0] != '.' {
		return tail, true
	}
	frac := tail[1:]
	n := 0
	for n < len(frac) && frac[n] >= '0' && frac[n] <= '9' {
		n++
	}
	if n < 1 || n > 9 || n < len(frac) && frac[n] >= '0' && frac[n] <= '9' {
		return "", false
	}
	return frac[n:], true
}

func validOffset(v string) bool {
	if len(v) != 6 || (v[0] != '+' && v[0] != '-') || v[3] != ':' || !asciiDigits(v[1:3]) || !asciiDigits(v[4:]) {
		return false
	}
	h, m := int(v[1]-'0')*10+int(v[2]-'0'), int(v[4]-'0')*10+int(v[5]-'0')
	return h <= 14 && m <= 59 && (h < 14 || m == 0)
}

type FieldToken struct{ name string }

func (f FieldToken) Valid() bool           { return validFieldToken(f.name) }
func (f FieldToken) Value() (string, bool) { return f.name, f.Valid() }
func validFieldToken(v string) bool {
	if len(v) == 0 || len(v) > 128 {
		return false
	}
	for i := range v {
		c := v[i]
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func NewFieldToken(v string) (FieldToken, error) {
	if !validFieldToken(v) {
		return FieldToken{}, newRefusal(CodeInvalidProposal)
	}
	return FieldToken{name: v}, nil
}

// DatasetProfileRef identifies an approved dataset profile definition.
// Its fields are private so proposals cannot bypass constructor validation.
type DatasetProfileRef struct {
	datasetID           string
	profileVersion      int64
	expectedProfileHash string
}

const (
	profileHashPrefix    = "sha256:"
	profileHashHexLength = 64
)

// validProfileHash requires the exact canonical form: the "sha256:" tag
// followed by 64 lowercase hex digits.
func validProfileHash(value string) bool {
	if len(value) != len(profileHashPrefix)+profileHashHexLength || !strings.HasPrefix(value, profileHashPrefix) {
		return false
	}
	for i := len(profileHashPrefix); i < len(value); i++ {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func NewDatasetProfileRef(datasetID string, profileVersion int64, expectedProfileHash string) (DatasetProfileRef, error) {
	if !validLabel(datasetID, maxIDLength) || profileVersion <= 0 || !validProfileHash(expectedProfileHash) {
		return DatasetProfileRef{}, newRefusal(CodeInvalidProposal)
	}
	return DatasetProfileRef{datasetID: datasetID, profileVersion: profileVersion, expectedProfileHash: expectedProfileHash}, nil
}

func (r DatasetProfileRef) Valid() bool {
	return validLabel(r.datasetID, maxIDLength) && r.profileVersion > 0 && validProfileHash(r.expectedProfileHash)
}

func (r DatasetProfileRef) DatasetID() (string, bool) {
	if !r.Valid() {
		return "", false
	}
	return r.datasetID, true
}

func (r DatasetProfileRef) ProfileVersion() (int64, bool) {
	if !r.Valid() {
		return 0, false
	}
	return r.profileVersion, true
}

// ExpectedProfileHash returns the pinned profile hash used for stale-profile
// detection. The hash carries no authority of its own.
func (r DatasetProfileRef) ExpectedProfileHash() (string, bool) {
	if !r.Valid() {
		return "", false
	}
	return r.expectedProfileHash, true
}

// MeasureRef identifies a measure defined by the pinned dataset profile. It
// carries no independent version: the profile version is authoritative.
type MeasureRef struct {
	measureID string
}

func NewMeasureRef(measureID string) (MeasureRef, error) {
	if !validLabel(measureID, maxIDLength) {
		return MeasureRef{}, newRefusal(CodeInvalidProposal)
	}
	return MeasureRef{measureID: measureID}, nil
}

func (r MeasureRef) Valid() bool { return validLabel(r.measureID, maxIDLength) }

func (r MeasureRef) MeasureID() (string, bool) {
	if !r.Valid() {
		return "", false
	}
	return r.measureID, true
}

type PeriodMode string

const (
	PeriodEXPLICIT        PeriodMode = "EXPLICIT"
	PeriodTODAY           PeriodMode = "TODAY"
	PeriodCURRENTMONTH    PeriodMode = "CURRENT_MONTH"
	PeriodLATESTAVAILABLE PeriodMode = "LATEST_AVAILABLE"
)

func (m PeriodMode) Valid() bool {
	return m == PeriodEXPLICIT || m == PeriodTODAY || m == PeriodCURRENTMONTH || m == PeriodLATESTAVAILABLE
}

// PeriodProposal preserves unresolved period input. Resolution belongs to a
// later stage that has the approved profile and its timezone available.
type PeriodProposal struct {
	mode        PeriodMode
	start       string
	end         string
	initialized bool
}

func NewRelativePeriod(mode PeriodMode) (PeriodProposal, error) {
	if mode != PeriodTODAY && mode != PeriodCURRENTMONTH && mode != PeriodLATESTAVAILABLE {
		return PeriodProposal{}, newRefusal(CodeInvalidProposal)
	}
	return PeriodProposal{mode: mode, initialized: true}, nil
}

func NewExplicitPeriod(start, end string) (PeriodProposal, error) {
	if !validPeriodBound(start) || !validPeriodBound(end) {
		return PeriodProposal{}, newRefusal(CodeInvalidProposal)
	}
	return PeriodProposal{mode: PeriodEXPLICIT, start: start, end: end, initialized: true}, nil
}

func (p PeriodProposal) Valid() bool {
	if !p.initialized || !p.mode.Valid() {
		return false
	}
	if p.mode == PeriodEXPLICIT {
		return validPeriodBound(p.start) && validPeriodBound(p.end)
	}
	return p.start == "" && p.end == ""
}

func (p PeriodProposal) Mode() (PeriodMode, bool) {
	if !p.Valid() {
		return "", false
	}
	return p.mode, true
}

func (p PeriodProposal) ExplicitBounds() (string, string, bool) {
	if !p.Valid() || p.mode != PeriodEXPLICIT {
		return "", "", false
	}
	return p.start, p.end, true
}

func validPeriodBound(value string) bool {
	return value != "" && len(value) <= 64 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

const (
	MaxDimensions     = 2
	MaxSortKeys       = 2
	MinLimit          = 1
	MaxLimit          = 100
	DefaultLimitValue = 20
)

type SortDirection string

const (
	SortASC  SortDirection = "ASC"
	SortDESC SortDirection = "DESC"
)

func (d SortDirection) Valid() bool { return d == SortASC || d == SortDESC }

type Dimensions struct {
	fields      [MaxDimensions]FieldToken
	count       uint8
	initialized bool
}

func NewDimensions(fields ...FieldToken) (Dimensions, error) {
	if len(fields) > MaxDimensions {
		return Dimensions{}, newRefusal(CodeInvalidProposal)
	}
	var dimensions Dimensions
	for i, field := range fields {
		if !field.Valid() || duplicateField(fields[:i], field) {
			return Dimensions{}, newRefusal(CodeInvalidProposal)
		}
		dimensions.fields[i] = field
	}
	dimensions.count = uint8(len(fields))
	dimensions.initialized = true
	return dimensions, nil
}

func (d Dimensions) Valid() bool {
	if !d.initialized || int(d.count) > MaxDimensions {
		return false
	}
	for i := 0; i < int(d.count); i++ {
		if !d.fields[i].Valid() || duplicateField(d.fields[:i], d.fields[i]) {
			return false
		}
	}
	return true
}

func (d Dimensions) Fields() ([]FieldToken, bool) {
	if !d.Valid() {
		return nil, false
	}
	fields := make([]FieldToken, int(d.count))
	copy(fields, d.fields[:d.count])
	return fields, true
}

func duplicateField(fields []FieldToken, candidate FieldToken) bool {
	name, _ := candidate.Value()
	for _, field := range fields {
		other, _ := field.Value()
		if other == name {
			return true
		}
	}
	return false
}

type SortKey struct {
	field     FieldToken
	direction SortDirection
}

func NewSortKey(field FieldToken, direction SortDirection) (SortKey, error) {
	if !field.Valid() || !direction.Valid() {
		return SortKey{}, newRefusal(CodeInvalidProposal)
	}
	return SortKey{field: field, direction: direction}, nil
}

func (k SortKey) Valid() bool { return k.field.Valid() && k.direction.Valid() }

func (k SortKey) Field() (FieldToken, bool) {
	if !k.Valid() {
		return FieldToken{}, false
	}
	return k.field, true
}

func (k SortKey) Direction() (SortDirection, bool) {
	if !k.Valid() {
		return "", false
	}
	return k.direction, true
}

type SortKeys struct {
	keys        [MaxSortKeys]SortKey
	count       uint8
	initialized bool
}

func NewSortKeys(keys ...SortKey) (SortKeys, error) {
	if len(keys) > MaxSortKeys {
		return SortKeys{}, newRefusal(CodeInvalidProposal)
	}
	var sortKeys SortKeys
	for i, key := range keys {
		if !key.Valid() || duplicateSortField(keys[:i], key) {
			return SortKeys{}, newRefusal(CodeInvalidProposal)
		}
		sortKeys.keys[i] = key
	}
	sortKeys.count = uint8(len(keys))
	sortKeys.initialized = true
	return sortKeys, nil
}

func (s SortKeys) Valid() bool {
	if !s.initialized || int(s.count) > MaxSortKeys {
		return false
	}
	for i := 0; i < int(s.count); i++ {
		if !s.keys[i].Valid() || duplicateSortField(s.keys[:i], s.keys[i]) {
			return false
		}
	}
	return true
}

func (s SortKeys) Values() ([]SortKey, bool) {
	if !s.Valid() {
		return nil, false
	}
	keys := make([]SortKey, int(s.count))
	copy(keys, s.keys[:s.count])
	return keys, true
}

func duplicateSortField(keys []SortKey, candidate SortKey) bool {
	field, _ := candidate.Field()
	for _, key := range keys {
		other, _ := key.Field()
		if other == field {
			return true
		}
	}
	return false
}

type Limit struct {
	value       uint8
	initialized bool
}

func NewLimit(value int) (Limit, error) {
	if value < MinLimit || value > MaxLimit {
		return Limit{}, newRefusal(CodeInvalidProposal)
	}
	return Limit{value: uint8(value), initialized: true}, nil
}

func DefaultLimit() Limit {
	limit, _ := NewLimit(DefaultLimitValue)
	return limit
}

func (l Limit) Valid() bool {
	return l.initialized && int(l.value) >= MinLimit && int(l.value) <= MaxLimit
}

func (l Limit) Value() (int, bool) {
	if !l.Valid() {
		return 0, false
	}
	return int(l.value), true
}

type Operator string

const (
	OpEQ     Operator = "EQ"
	OpIN     Operator = "IN"
	OpGTE    Operator = "GTE"
	OpLTE    Operator = "LTE"
	OpISNull Operator = "IS_NULL"
)

func (o Operator) Valid() bool {
	return o == OpEQ || o == OpIN || o == OpGTE || o == OpLTE || o == OpISNull
}

type Predicate struct {
	field  FieldToken
	op     Operator
	values []Scalar
}

func NewPredicate(field FieldToken, op Operator, values ...Scalar) (Predicate, error) {
	predicate := Predicate{field: field, op: op, values: append([]Scalar(nil), values...)}
	if !predicate.Valid() {
		return Predicate{}, newRefusal(CodeInvalidProposal)
	}
	return predicate, nil
}

func validArity(op Operator, n int) bool {
	return (op == OpISNull && n == 1) || (op == OpEQ || op == OpGTE || op == OpLTE) && n == 1 || op == OpIN && n >= 1 && n <= maxInMembers
}
func orderable(k ScalarKind) bool {
	return k == KindINT || k == KindNUMERIC || k == KindDATE || k == KindTIMESTAMP || k == KindTIMESTAMPTZ
}

func (p Predicate) Valid() bool {
	if !p.field.Valid() || !p.op.Valid() || !validArity(p.op, len(p.values)) {
		return false
	}
	kind := p.values[0].kind
	if p.op == OpISNull && kind != KindBOOL || (p.op == OpGTE || p.op == OpLTE) && !orderable(kind) {
		return false
	}
	for _, value := range p.values {
		if value.kind != kind || !value.valid() {
			return false
		}
	}
	return true
}

func (s Scalar) valid() bool {
	if !s.kind.Valid() {
		return false
	}
	if s.kind == KindBOOL {
		return s.text == "" && s.i == 0
	}
	if s.kind == KindINT {
		return s.text == "" && !s.b
	}
	if s.i != 0 || s.b {
		return false
	}
	switch s.kind {
	case KindTEXT:
		return utf8.ValidString(s.text) && len(s.text) <= MaxScalarText
	case KindNUMERIC:
		value, err := NumericScalar(s.text)
		return err == nil && value.text == s.text
	case KindDATE:
		return validDate(s.text)
	case KindTIMESTAMP:
		tail, ok := wallTail(s.text)
		return ok && tail == ""
	case KindTIMESTAMPTZ:
		value, err := TimestamptzScalar(s.text)
		return err == nil && value.text == s.text
	default:
		return false
	}
}

func (p Predicate) Field() FieldToken { return p.field }
func (p Predicate) Op() Operator      { return p.op }
func (p Predicate) Values() []Scalar  { return append([]Scalar(nil), p.values...) }

const MaxPredicates = 4

type Predicates struct {
	values      [MaxPredicates]Predicate
	count       uint8
	initialized bool
}

func NewPredicates(values ...Predicate) (Predicates, error) {
	if len(values) > MaxPredicates {
		return Predicates{}, newRefusal(CodeInvalidProposal)
	}
	var predicates Predicates
	for i, predicate := range values {
		if !predicate.Valid() {
			return Predicates{}, newRefusal(CodeInvalidProposal)
		}
		predicates.values[i] = clonePredicate(predicate)
	}
	predicates.count = uint8(len(values))
	predicates.initialized = true
	return predicates, nil
}

func (p Predicates) Valid() bool {
	if !p.initialized || int(p.count) > MaxPredicates {
		return false
	}
	for i := 0; i < int(p.count); i++ {
		if !p.values[i].Valid() {
			return false
		}
	}
	return true
}

func (p Predicates) Values() ([]Predicate, bool) {
	if !p.Valid() {
		return nil, false
	}
	values := make([]Predicate, int(p.count))
	for i := range values {
		values[i] = clonePredicate(p.values[i])
	}
	return values, true
}

func clonePredicate(predicate Predicate) Predicate {
	predicate.values = append([]Scalar(nil), predicate.values...)
	return predicate
}

type ProposalV2 struct {
	dataset     DatasetProfileRef
	measure     MeasureRef
	period      PeriodProposal
	filters     Predicates
	dimensions  Dimensions
	sort        SortKeys
	limit       Limit
	output      Output
	initialized bool
}

func NewProposalV2(dataset DatasetProfileRef, measure MeasureRef, period PeriodProposal, filters Predicates, dimensions Dimensions, sort SortKeys, limit Limit, output Output) (ProposalV2, error) {
	proposal := ProposalV2{dataset: dataset, measure: measure, period: period, filters: clonePredicates(filters), dimensions: dimensions, sort: sort, limit: limit, output: output, initialized: true}
	if !proposal.Valid() {
		return ProposalV2{}, newRefusal(CodeInvalidProposal)
	}
	return proposal, nil
}

func (p ProposalV2) Valid() bool {
	return p.initialized && p.dataset.Valid() && p.measure.Valid() && p.period.Valid() && p.filters.Valid() &&
		p.dimensions.Valid() && p.sort.Valid() && p.limit.Valid() && p.output.valid()
}

func clonePredicates(predicates Predicates) Predicates {
	for i := 0; i < int(predicates.count) && i < MaxPredicates; i++ {
		predicates.values[i] = clonePredicate(predicates.values[i])
	}
	return predicates
}

func (p ProposalV2) Dataset() (DatasetProfileRef, bool) {
	if !p.Valid() {
		return DatasetProfileRef{}, false
	}
	return p.dataset, true
}

func (p ProposalV2) Measure() (MeasureRef, bool) {
	if !p.Valid() {
		return MeasureRef{}, false
	}
	return p.measure, true
}

func (p ProposalV2) Period() (PeriodProposal, bool) {
	if !p.Valid() {
		return PeriodProposal{}, false
	}
	return p.period, true
}

func (p ProposalV2) Dimensions() (Dimensions, bool) {
	if !p.Valid() {
		return Dimensions{}, false
	}
	return p.dimensions, true
}

func (p ProposalV2) Sort() (SortKeys, bool) {
	if !p.Valid() {
		return SortKeys{}, false
	}
	return p.sort, true
}

func (p ProposalV2) Limit() (Limit, bool) {
	if !p.Valid() {
		return Limit{}, false
	}
	return p.limit, true
}

func (p ProposalV2) Output() (Output, bool) {
	if !p.Valid() {
		return "", false
	}
	return p.output, true
}

func (p ProposalV2) Filters() (Predicates, bool) {
	if !p.Valid() {
		return Predicates{}, false
	}
	return clonePredicates(p.filters), true
}
