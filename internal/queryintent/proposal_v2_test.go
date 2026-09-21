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

const testProfileHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

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

func TestProposalV2DefinitionReferences(t *testing.T) {
	dataset, e := NewDatasetProfileRef("service-desk", 7, testProfileHash)
	if e != nil || !dataset.Valid() {
		t.Fatal(e)
	}
	if id, ok := dataset.DatasetID(); !ok || id != "service-desk" {
		t.Fatal(id, ok)
	}
	if version, ok := dataset.ProfileVersion(); !ok || version != 7 {
		t.Fatal(version, ok)
	}
	if hash, ok := dataset.ExpectedProfileHash(); !ok || hash != testProfileHash {
		t.Fatal(hash, ok)
	}
	measure, e := NewMeasureRef("open_tickets")
	if e != nil || !measure.Valid() {
		t.Fatal(e)
	}
	if id, ok := measure.MeasureID(); !ok || id != "open_tickets" {
		t.Fatal(id, ok)
	}

	for _, id := range []string{"", " leading", "trailing ", "line\nbreak", strings.Repeat("x", maxIDLength+1)} {
		_, e := NewDatasetProfileRef(id, 1, testProfileHash)
		pBad(t, e)
		_, e = NewMeasureRef(id)
		pBad(t, e)
	}
	for _, version := range []int64{-1, 0} {
		_, e := NewDatasetProfileRef("dataset", version, testProfileHash)
		pBad(t, e)
	}
	for _, hash := range []string{
		"",
		"sha256:",
		"sha256:" + strings.Repeat("a", 63),
		"sha256:" + strings.Repeat("a", 65),
		"sha256:" + strings.Repeat("A", 64),
		"sha256:" + strings.Repeat("g", 64),
		"sha256:" + strings.Repeat("a", 63) + "-",
		"sha256" + strings.Repeat("a", 64),
		"SHA256:" + strings.Repeat("a", 64),
		"sha512:" + strings.Repeat("a", 64),
		strings.Repeat("a", 64),
	} {
		_, e := NewDatasetProfileRef("dataset", 1, hash)
		pBad(t, e)
	}

	var zeroDataset DatasetProfileRef
	if zeroDataset.Valid() {
		t.Fatal("zero dataset profile reference valid")
	}
	if _, ok := zeroDataset.DatasetID(); ok {
		t.Fatal("zero dataset id readable")
	}
	if _, ok := zeroDataset.ProfileVersion(); ok {
		t.Fatal("zero profile version readable")
	}
	if _, ok := zeroDataset.ExpectedProfileHash(); ok {
		t.Fatal("zero expected profile hash readable")
	}
	for _, forged := range []DatasetProfileRef{
		{datasetID: "service-desk", profileVersion: 7},
		{datasetID: "service-desk", profileVersion: 7, expectedProfileHash: "sha256:" + strings.Repeat("A", 64)},
		{datasetID: "service-desk", expectedProfileHash: testProfileHash},
	} {
		if forged.Valid() {
			t.Fatal("forged dataset profile reference valid")
		}
		if _, ok := forged.ExpectedProfileHash(); ok {
			t.Fatal("forged expected profile hash readable")
		}
	}
	var zeroMeasure MeasureRef
	if zeroMeasure.Valid() {
		t.Fatal("zero measure reference valid")
	}
	if _, ok := zeroMeasure.MeasureID(); ok {
		t.Fatal("zero measure id readable")
	}
}

func TestProposalV2PeriodModesAndRelativePeriods(t *testing.T) {
	for _, mode := range []PeriodMode{PeriodEXPLICIT, PeriodTODAY, PeriodCURRENTMONTH, PeriodLATESTAVAILABLE} {
		if !mode.Valid() {
			t.Fatal(mode)
		}
	}
	for _, mode := range []PeriodMode{"", "today", "CURRENT-MONTH", "UNKNOWN"} {
		if mode.Valid() {
			t.Fatal(mode)
		}
		_, e := NewRelativePeriod(mode)
		pBad(t, e)
	}
	_, e := NewRelativePeriod(PeriodEXPLICIT)
	pBad(t, e)
	for _, mode := range []PeriodMode{PeriodTODAY, PeriodCURRENTMONTH, PeriodLATESTAVAILABLE} {
		period, e := NewRelativePeriod(mode)
		if e != nil || !period.Valid() {
			t.Fatal(mode, e)
		}
		if got, ok := period.Mode(); !ok || got != mode {
			t.Fatal(got, ok)
		}
		if start, end, ok := period.ExplicitBounds(); ok || start != "" || end != "" {
			t.Fatal(start, end, ok)
		}
	}
}

func TestProposalV2ExplicitPeriodSyntaxAndAccessors(t *testing.T) {
	start := "2026-13-45T25:61:61Z"
	end := "2024-01-01T00:00:00Z"
	period, e := NewExplicitPeriod(start, end)
	if e != nil || !period.Valid() {
		t.Fatal(e)
	}
	if got, ok := period.Mode(); !ok || got != PeriodEXPLICIT {
		t.Fatal(got, ok)
	}
	if gotStart, gotEnd, ok := period.ExplicitBounds(); !ok || gotStart != start || gotEnd != end {
		t.Fatal(gotStart, gotEnd, ok)
	}
	if _, e := NewExplicitPeriod(strings.Repeat("x", 64), strings.Repeat("y", 64)); e != nil {
		t.Fatal("64-byte bounds rejected", e)
	}
	for _, bounds := range [][2]string{
		{"", "end"}, {"start", ""}, {" start", "end"}, {"start", "end "},
		{"start\a", "end"}, {"start", "end\u009f"}, {strings.Repeat("x", 65), "end"}, {"start", strings.Repeat("y", 65)},
		{string([]byte{0xff}), "end"},
	} {
		_, e := NewExplicitPeriod(bounds[0], bounds[1])
		pBad(t, e)
	}
}

func TestProposalV2ZeroAndForgedPeriodsInvalid(t *testing.T) {
	for _, period := range []PeriodProposal{
		{},
		{mode: PeriodTODAY},
		{mode: "UNKNOWN", initialized: true},
		{mode: PeriodTODAY, start: "forged", initialized: true},
		{mode: PeriodCURRENTMONTH, end: "forged", initialized: true},
		{mode: PeriodEXPLICIT, start: "", end: "end", initialized: true},
		{mode: PeriodEXPLICIT, start: " start", end: "end", initialized: true},
	} {
		if period.Valid() {
			t.Fatal("forged period valid", period)
		}
		if _, ok := period.Mode(); ok {
			t.Fatal("invalid period mode readable")
		}
		if _, _, ok := period.ExplicitBounds(); ok {
			t.Fatal("invalid period bounds readable")
		}
	}
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

func TestProposalV2PredicateValidRejectsForgedValues(t *testing.T) {
	field, _ := NewFieldToken("status")
	valid, _ := NewPredicate(field, OpEQ, IntScalar(1))
	if !valid.Valid() {
		t.Fatal("constructed predicate invalid")
	}
	for _, predicate := range []Predicate{
		{},
		{field: FieldToken{}, op: OpEQ, values: []Scalar{IntScalar(1)}},
		{field: field, op: "LIKE", values: []Scalar{IntScalar(1)}},
		{field: field, op: OpEQ},
		{field: field, op: OpIN, values: []Scalar{IntScalar(1), BoolScalar(true)}},
		{field: field, op: OpGTE, values: []Scalar{{kind: KindTEXT, text: "x"}}},
		{field: field, op: OpEQ, values: []Scalar{{kind: KindDATE, text: "2024-02-30"}}},
	} {
		if predicate.Valid() {
			t.Fatal("forged predicate valid", predicate)
		}
	}
}

func TestProposalV2PredicatesBoundsRepeatedFieldsAndCopies(t *testing.T) {
	if MaxPredicates != 4 {
		t.Fatal(MaxPredicates)
	}
	field, _ := NewFieldToken("amount")
	one, _ := NumericScalar("1")
	two, _ := NumericScalar("2")
	lower, _ := NewPredicate(field, OpGTE, one)
	upper, _ := NewPredicate(field, OpLTE, two)

	var zero Predicates
	if zero.Valid() {
		t.Fatal("zero predicates valid")
	}
	empty, err := NewPredicates()
	if err != nil || !empty.Valid() {
		t.Fatal(err)
	}
	four, err := NewPredicates(lower, upper, lower, upper)
	if err != nil || !four.Valid() {
		t.Fatal("four or repeated field rejected", err)
	}
	_, err = NewPredicates(lower, upper, lower, upper, lower)
	pBad(t, err)

	inputValues := []Scalar{one, two}
	in, _ := NewPredicate(field, OpIN, inputValues...)
	input := []Predicate{in}
	predicates, _ := NewPredicates(input...)
	inputValues[0] = IntScalar(9)
	input[0].values[0] = IntScalar(8)
	first, _ := predicates.Values()
	first[0].values[0] = IntScalar(7)
	second, _ := predicates.Values()
	if got, _ := second[0].values[0].Numeric(); got != "1" {
		t.Fatal("predicate values alias input or output", got)
	}
}

func validProposalV2Parts(t *testing.T) (DatasetProfileRef, MeasureRef, PeriodProposal, Predicates, Dimensions, SortKeys, Limit) {
	t.Helper()
	dataset, _ := NewDatasetProfileRef("service-desk", 2, testProfileHash)
	measure, _ := NewMeasureRef("open_tickets")
	period, _ := NewRelativePeriod(PeriodCURRENTMONTH)
	field, _ := NewFieldToken("team")
	value, _ := TextScalar("support")
	predicate, _ := NewPredicate(field, OpEQ, value)
	filters, _ := NewPredicates(predicate)
	dimensions, _ := NewDimensions(field)
	key, _ := NewSortKey(field, SortASC)
	sort, _ := NewSortKeys(key)
	limit, _ := NewLimit(25)
	return dataset, measure, period, filters, dimensions, sort, limit
}

func TestProposalV2RejectsEveryInvalidNestedValueAndOutput(t *testing.T) {
	d, measure, p, f, dimensions, sort, limit := validProposalV2Parts(t)
	for _, candidate := range []struct {
		d          DatasetProfileRef
		measure    MeasureRef
		p          PeriodProposal
		f          Predicates
		dimensions Dimensions
		sort       SortKeys
		limit      Limit
		output     Output
	}{
		{measure: measure, p: p, f: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue},
		{d: d, p: p, f: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue},
		{d: d, measure: measure, f: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue},
		{d: d, measure: measure, p: p, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue},
		{d: d, measure: measure, p: p, f: f, sort: sort, limit: limit, output: OutputValue},
		{d: d, measure: measure, p: p, f: f, dimensions: dimensions, limit: limit, output: OutputValue},
		{d: d, measure: measure, p: p, f: f, dimensions: dimensions, sort: sort, output: OutputValue},
		{d: d, measure: measure, p: p, f: f, dimensions: dimensions, sort: sort, limit: limit, output: "TABLE"},
	} {
		_, err := NewProposalV2(candidate.d, candidate.measure, candidate.p, candidate.f, candidate.dimensions, candidate.sort, candidate.limit, candidate.output)
		pBad(t, err)
	}
	var zero ProposalV2
	if zero.Valid() {
		t.Fatal("zero proposal valid")
	}
	if _, ok := zero.Dataset(); ok {
		t.Fatal("zero dataset accessor succeeded")
	}
	if _, ok := zero.Measure(); ok {
		t.Fatal("zero measure accessor succeeded")
	}
	if _, ok := zero.Period(); ok {
		t.Fatal("zero period accessor succeeded")
	}
	if _, ok := zero.Filters(); ok {
		t.Fatal("zero proposal accessor succeeded")
	}
	if _, ok := zero.Dimensions(); ok {
		t.Fatal("zero dimensions accessor succeeded")
	}
	if _, ok := zero.Sort(); ok {
		t.Fatal("zero sort accessor succeeded")
	}
	if _, ok := zero.Limit(); ok {
		t.Fatal("zero limit accessor succeeded")
	}
	if _, ok := zero.Output(); ok {
		t.Fatal("zero output accessor succeeded")
	}
}

func TestProposalV2CompleteRoundTripAndFilterIsolation(t *testing.T) {
	d, measure, p, f, dimensions, sort, limit := validProposalV2Parts(t)
	proposal, err := NewProposalV2(d, measure, p, f, dimensions, sort, limit, OutputRowset)
	if err != nil || !proposal.Valid() {
		t.Fatal(err)
	}
	f.values[0].values[0], _ = TextScalar("mutated-input")
	if got, ok := proposal.Dataset(); !ok || got != d {
		t.Fatal("dataset", got, ok)
	}
	if got, ok := proposal.Measure(); !ok || got != measure {
		t.Fatal("measure", got, ok)
	}
	if got, ok := proposal.Period(); !ok || got != p {
		t.Fatal("period", got, ok)
	}
	if got, ok := proposal.Dimensions(); !ok || got != dimensions {
		t.Fatal("dimensions", got, ok)
	}
	if got, ok := proposal.Sort(); !ok || got != sort {
		t.Fatal("sort", got, ok)
	}
	if got, ok := proposal.Limit(); !ok || got != limit {
		t.Fatal("limit", got, ok)
	}
	if got, ok := proposal.Output(); !ok || got != OutputRowset {
		t.Fatal("output", got, ok)
	}
	read, ok := proposal.Filters()
	if !ok {
		t.Fatal("filters")
	}
	values, _ := read.Values()
	values[0].values[0], _ = TextScalar("changed")
	again, _ := proposal.Filters()
	againValues, _ := again.Values()
	if got, _ := againValues[0].values[0].Text(); got != "support" {
		t.Fatal("proposal filters alias accessor", got)
	}
}
