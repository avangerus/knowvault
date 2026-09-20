package queryintent

import (
	"strings"
	"time"
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
	if !field.Valid() || !op.Valid() || !validArity(op, len(values)) {
		return Predicate{}, newRefusal(CodeInvalidProposal)
	}
	if len(values) > 0 && (!values[0].kind.Valid() || op == OpISNull && values[0].kind != KindBOOL || (op == OpGTE || op == OpLTE) && !orderable(values[0].kind)) {
		return Predicate{}, newRefusal(CodeInvalidProposal)
	}
	for _, v := range values[1:] {
		if !v.kind.Valid() || v.kind != values[0].kind {
			return Predicate{}, newRefusal(CodeInvalidProposal)
		}
	}
	return Predicate{field: field, op: op, values: append([]Scalar(nil), values...)}, nil
}

func validArity(op Operator, n int) bool {
	return (op == OpISNull && n == 1) || (op == OpEQ || op == OpGTE || op == OpLTE) && n == 1 || op == OpIN && n >= 1 && n <= maxInMembers
}
func orderable(k ScalarKind) bool {
	return k == KindINT || k == KindNUMERIC || k == KindDATE || k == KindTIMESTAMP || k == KindTIMESTAMPTZ
}

func (p Predicate) Field() FieldToken { return p.field }
func (p Predicate) Op() Operator      { return p.op }
func (p Predicate) Values() []Scalar  { return append([]Scalar(nil), p.values...) }
