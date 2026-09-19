package queryintent

import "testing"

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
	_, e := NumericScalar("1e9")
	pBad(t, e)
	txt, _ := TextScalar(`x' OR 1=1 --`)
	if v, ok := txt.Text(); !ok || v != `x' OR 1=1 --` {
		t.Fatal("text payload")
	}
	_, e = DateScalar("2024-02-30")
	pBad(t, e)
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
	}{{OpEQ, nil}, {OpEQ, []Scalar{i, i}}, {OpISNull, []Scalar{i}}, {OpIN, nil}, {OpIN, []Scalar{i, s}}, {OpIN, make([]Scalar, 21)}, {Operator("LIKE"), []Scalar{i}}, {OpGTE, []Scalar{s}}}
	for _, c := range bad {
		_, e := NewPredicate(f, c.op, c.v...)
		pBad(t, e)
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
