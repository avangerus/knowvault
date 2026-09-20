package queryintent

import (
	"strings"
	"testing"
)

func pBad(t *testing.T, e error) {
	t.Helper()
	if CodeOf(e) != CodeInvalidProposal || ClarificationOf(e) == "" {
		t.Fatalf("code=%q text=%q", CodeOf(e), ClarificationOf(e))
	}
}

func TestProposalV2ClosedVocabulary(t *testing.T) {
	for _, k := range []ScalarKind{KindBOOL, KindINT, KindNUMERIC, KindTEXT, KindDATE, KindTIMESTAMP, KindTIMESTAMPTZ} {
		if !k.Valid() {
			t.Fatal(k)
		}
	}
	_, e := NewFieldToken("supplier_name; DROP TABLE x")
	pBad(t, e)
	f, _ := NewFieldToken("supplier_name_1")
	if _, e := NewPredicate(FieldToken{}, OpEQ, IntScalar(1)); CodeOf(e) != CodeInvalidProposal {
		t.Fatal("zero field accepted")
	}
	_, e = NewPredicate(f, Operator("LIKE"), IntScalar(1))
	pBad(t, e)
}

func TestProposalV2ScalarsAndTemporalGrammar(t *testing.T) {
	for in, want := range map[string]string{"00012.3400": "12.34", "-000.000": "0", "0.0100": "0.01"} {
		s, e := NumericScalar(in)
		if e != nil {
			t.Fatal(e)
		}
		if v, ok := s.Numeric(); !ok || v != want {
			t.Fatalf("%s=%s", in, v)
		}
	}
	for _, in := range []string{"+1", "1e9", "NaN", "Inf", ".1", "1.", "1.2.3"} {
		_, e := NumericScalar(in)
		pBad(t, e)
	}
	txt, _ := TextScalar(`x' OR 1=1 --`)
	if v, ok := txt.Text(); !ok || v != `x' OR 1=1 --` {
		t.Fatal("text payload")
	}
	if _, e := TextScalar(strings.Repeat("é", 128)); e != nil {
		t.Fatal("256-byte text")
	}
	if _, e := TextScalar(strings.Repeat("é", 128) + "x"); CodeOf(e) != CodeInvalidProposal {
		t.Fatal("257-byte text")
	}
	for _, in := range []string{"2024-02-30", "2023-02-29", "0000-01-01"} {
		_, e := DateScalar(in)
		pBad(t, e)
	}
	for _, in := range []string{"2024-01-01T12:30:45,1", "2024-01-01T12:30:45.1234567890", "2024-01-01T12:30:45Z"} {
		_, e := TimestampScalar(in)
		pBad(t, e)
	}
	z, e := TimestamptzScalar("2024-01-01T12:00:00.5+05:30")
	if e != nil {
		t.Fatal(e)
	}
	if v, ok := z.Timestamptz(); !ok || v != "2024-01-01T06:30:00.5Z" {
		t.Fatal(v)
	}
	for _, in := range []string{"2024-01-01T12:00:00", "2024-01-01T12:00:00+24:00", "2024-01-01T12:00:00+14:01", "2024-01-01T12:00:00+12:60"} {
		_, e := TimestamptzScalar(in)
		pBad(t, e)
	}
	var zero Scalar
	if _, ok := zero.Bool(); ok {
		t.Fatal("zero scalar")
	}
}

func TestProposalV2PredicateArityKindsAndCopy(t *testing.T) {
	f, _ := NewFieldToken("f")
	i, _ := NumericScalar("1")
	s, _ := TextScalar("x")
	bad := []struct {
		op Operator
		v  []Scalar
	}{{OpEQ, nil}, {OpEQ, []Scalar{i, i}}, {OpISNull, nil}, {OpISNull, []Scalar{i}}, {OpISNull, []Scalar{BoolScalar(true), BoolScalar(false)}}, {OpIN, nil}, {OpIN, []Scalar{i, s}}, {OpIN, make([]Scalar, 21)}, {Operator("LIKE"), []Scalar{i}}, {OpGTE, []Scalar{s}}}
	for _, c := range bad {
		_, e := NewPredicate(f, c.op, c.v...)
		pBad(t, e)
	}
	for _, b := range []bool{true, false} {
		if _, e := NewPredicate(f, OpISNull, BoolScalar(b)); e != nil {
			t.Fatal(e)
		}
	}
	p, e := NewPredicate(f, OpIN, i, i)
	if e != nil {
		t.Fatal(e)
	}
	values := p.Values()
	values[0] = IntScalar(9)
	if got, _ := p.Values()[0].Numeric(); got != "1" {
		t.Fatal("mutable values")
	}
}

func TestProposalV2DimensionsBoundsDuplicatesAndCopies(t *testing.T) {
	if MaxDimensions != 2 {
		t.Fatal(MaxDimensions)
	}
	a, _ := NewFieldToken("a")
	b, _ := NewFieldToken("b")
	c, _ := NewFieldToken("c")
	upper, _ := NewFieldToken("A")

	var zero Dimensions
	if zero.Valid() {
		t.Fatal("zero dimensions valid")
	}
	if fields, ok := zero.Fields(); ok || fields != nil {
		t.Fatal("zero dimensions readable")
	}
	empty, e := NewDimensions()
	if e != nil || !empty.Valid() {
		t.Fatal(e)
	}
	if fields, ok := empty.Fields(); !ok || fields == nil || len(fields) != 0 {
		t.Fatal("constructed empty dimensions invalid")
	}
	for _, fields := range [][]FieldToken{{a}, {a, b}} {
		d, e := NewDimensions(fields...)
		if e != nil || !d.Valid() {
			t.Fatal(e)
		}
	}
	for _, fields := range [][]FieldToken{{a, b, c}, {FieldToken{}}, {a, a}} {
		_, e := NewDimensions(fields...)
		pBad(t, e)
	}
	if _, e := NewDimensions(a, upper); e != nil {
		t.Fatal("case-folded duplicate")
	}

	input := []FieldToken{a, b}
	d, _ := NewDimensions(input...)
	input[0] = c
	first, _ := d.Fields()
	first[0] = c
	second, _ := d.Fields()
	if second[0] != a || second[1] != b {
		t.Fatal("dimensions alias input or accessor")
	}
}

func TestProposalV2SortDirectionAndKeyClosedVocabulary(t *testing.T) {
	if !SortASC.Valid() || !SortDESC.Valid() {
		t.Fatal("declared sort direction invalid")
	}
	for _, direction := range []SortDirection{"", "asc", "DESCENDING"} {
		if direction.Valid() {
			t.Fatal(direction)
		}
	}
	field, _ := NewFieldToken("created_at")
	for _, candidate := range []struct {
		field     FieldToken
		direction SortDirection
	}{{FieldToken{}, SortASC}, {field, "asc"}} {
		_, e := NewSortKey(candidate.field, candidate.direction)
		pBad(t, e)
	}

	var zero SortKey
	if zero.Valid() {
		t.Fatal("zero sort key valid")
	}
	if _, ok := zero.Field(); ok {
		t.Fatal("zero sort field readable")
	}
	if _, ok := zero.Direction(); ok {
		t.Fatal("zero sort direction readable")
	}
	key, e := NewSortKey(field, SortDESC)
	if e != nil || !key.Valid() {
		t.Fatal(e)
	}
	if got, ok := key.Field(); !ok || got != field {
		t.Fatal(got)
	}
	if got, ok := key.Direction(); !ok || got != SortDESC {
		t.Fatal(got)
	}
}

func TestProposalV2SortKeysBoundsDuplicatesAndCopies(t *testing.T) {
	if MaxSortKeys != 2 {
		t.Fatal(MaxSortKeys)
	}
	a, _ := NewFieldToken("a")
	b, _ := NewFieldToken("b")
	c, _ := NewFieldToken("c")
	ascA, _ := NewSortKey(a, SortASC)
	descA, _ := NewSortKey(a, SortDESC)
	descB, _ := NewSortKey(b, SortDESC)
	ascC, _ := NewSortKey(c, SortASC)

	var zero SortKeys
	if zero.Valid() {
		t.Fatal("zero sort keys valid")
	}
	if values, ok := zero.Values(); ok || values != nil {
		t.Fatal("zero sort keys readable")
	}
	empty, e := NewSortKeys()
	if e != nil || !empty.Valid() {
		t.Fatal(e)
	}
	if values, ok := empty.Values(); !ok || values == nil || len(values) != 0 {
		t.Fatal("constructed empty sort keys invalid")
	}
	for _, keys := range [][]SortKey{{ascA}, {ascA, descB}} {
		s, e := NewSortKeys(keys...)
		if e != nil || !s.Valid() {
			t.Fatal(e)
		}
	}
	for _, keys := range [][]SortKey{{ascA, descB, ascC}, {SortKey{}}, {ascA, descA}} {
		_, e := NewSortKeys(keys...)
		pBad(t, e)
	}
	if _, e := NewDimensions(a); e != nil {
		t.Fatal(e)
	}
	if _, e := NewSortKeys(ascA); e != nil {
		t.Fatal("dimension/sort overlap rejected")
	}

	input := []SortKey{ascA, descB}
	s, _ := NewSortKeys(input...)
	input[0] = ascC
	first, _ := s.Values()
	first[0] = ascC
	second, _ := s.Values()
	if second[0] != ascA || second[1] != descB {
		t.Fatal("sort keys alias input or accessor")
	}
}

func TestProposalV2LimitBoundsDefaultAndZero(t *testing.T) {
	if MinLimit != 1 || MaxLimit != 100 || DefaultLimitValue != 20 {
		t.Fatal(MinLimit, MaxLimit, DefaultLimitValue)
	}
	var zero Limit
	if zero.Valid() {
		t.Fatal("zero limit valid")
	}
	if _, ok := zero.Value(); ok {
		t.Fatal("zero limit readable")
	}
	for _, value := range []int{-1, 0, 101} {
		_, e := NewLimit(value)
		pBad(t, e)
	}
	for _, value := range []int{1, 20, 100} {
		limit, e := NewLimit(value)
		if e != nil || !limit.Valid() {
			t.Fatal(value, e)
		}
		if got, ok := limit.Value(); !ok || got != value {
			t.Fatal(got)
		}
	}
	if got, ok := DefaultLimit().Value(); !ok || got != DefaultLimitValue {
		t.Fatal(got)
	}
}
