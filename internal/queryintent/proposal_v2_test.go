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

func TestProposalV2SortDirectionAndTargetClosedVocabulary(t *testing.T) {
	if !SortASC.Valid() || !SortDESC.Valid() {
		t.Fatal("declared sort direction invalid")
	}
	for _, direction := range []SortDirection{"", "asc", "DESCENDING"} {
		if direction.Valid() {
			t.Fatal(direction)
		}
	}
	if !SortTargetDIMENSION.Valid() || !SortTargetMEASURE.Valid() {
		t.Fatal("declared sort target kind invalid")
	}
	for _, kind := range []SortTargetKind{"", "dimension", "measure", "FIELD", "MEASURE_REF"} {
		if kind.Valid() {
			t.Fatal(kind)
		}
	}
	field, _ := NewFieldToken("created_at")
	measure, _ := NewMeasureRef("created_at")
	for _, candidate := range []struct {
		field     FieldToken
		direction SortDirection
	}{{FieldToken{}, SortASC}, {field, "asc"}} {
		_, e := NewDimensionSortKey(candidate.field, candidate.direction)
		pBad(t, e)
	}
	for _, candidate := range []struct {
		measure   MeasureRef
		direction SortDirection
	}{{MeasureRef{}, SortDESC}, {measure, ""}} {
		_, e := NewMeasureSortKey(candidate.measure, candidate.direction)
		pBad(t, e)
	}

	var zero SortKey
	if zero.Valid() {
		t.Fatal("zero sort key valid")
	}
	if _, ok := zero.TargetKind(); ok {
		t.Fatal("zero sort target kind readable")
	}
	if _, ok := zero.Dimension(); ok {
		t.Fatal("zero sort dimension readable")
	}
	if _, ok := zero.Measure(); ok {
		t.Fatal("zero sort measure readable")
	}
	if _, ok := zero.Direction(); ok {
		t.Fatal("zero sort direction readable")
	}
	for _, forged := range []SortKey{
		{dimension: field, direction: SortASC},
		{kind: SortTargetDIMENSION, direction: SortASC},
		{kind: SortTargetMEASURE, direction: SortASC},
		{kind: SortTargetDIMENSION, dimension: field},
		{kind: SortTargetDIMENSION, dimension: field, direction: "asc"},
		{kind: SortTargetDIMENSION, dimension: field, measure: measure, direction: SortASC},
		{kind: SortTargetMEASURE, dimension: field, measure: measure, direction: SortASC},
		{kind: SortTargetDIMENSION, measure: measure, direction: SortASC},
		{kind: SortTargetMEASURE, dimension: field, direction: SortASC},
		{kind: SortTargetKind("FIELD"), dimension: field, direction: SortASC},
	} {
		if forged.Valid() {
			t.Fatal("forged sort key valid", forged)
		}
		if _, ok := forged.TargetKind(); ok {
			t.Fatal("forged sort target kind readable", forged)
		}
		if _, ok := forged.Dimension(); ok {
			t.Fatal("forged sort dimension readable", forged)
		}
		if _, ok := forged.Measure(); ok {
			t.Fatal("forged sort measure readable", forged)
		}
		if _, ok := forged.Direction(); ok {
			t.Fatal("forged sort direction readable", forged)
		}
	}
	key, e := NewDimensionSortKey(field, SortDESC)
	if e != nil || !key.Valid() {
		t.Fatal(e)
	}
	if got, ok := key.TargetKind(); !ok || got != SortTargetDIMENSION {
		t.Fatal(got, ok)
	}
	if got, ok := key.Dimension(); !ok || got != field {
		t.Fatal(got)
	}
	if got, ok := key.Measure(); ok {
		t.Fatal("dimension key measure readable", got)
	}
	if got, ok := key.Direction(); !ok || got != SortDESC {
		t.Fatal(got)
	}
	measureKey, e := NewMeasureSortKey(measure, SortASC)
	if e != nil || !measureKey.Valid() {
		t.Fatal(e)
	}
	if got, ok := measureKey.TargetKind(); !ok || got != SortTargetMEASURE {
		t.Fatal(got, ok)
	}
	if got, ok := measureKey.Measure(); !ok || got != measure {
		t.Fatal(got)
	}
	if got, ok := measureKey.Dimension(); ok {
		t.Fatal("measure key dimension readable", got)
	}
	if got, ok := measureKey.Direction(); !ok || got != SortASC {
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
	measureA, _ := NewMeasureRef("a")
	measureB, _ := NewMeasureRef("b")
	ascA, _ := NewDimensionSortKey(a, SortASC)
	descA, _ := NewDimensionSortKey(a, SortDESC)
	descB, _ := NewDimensionSortKey(b, SortDESC)
	ascC, _ := NewDimensionSortKey(c, SortASC)
	ascMeasureA, _ := NewMeasureSortKey(measureA, SortASC)
	descMeasureA, _ := NewMeasureSortKey(measureA, SortDESC)
	descMeasureB, _ := NewMeasureSortKey(measureB, SortDESC)
	forged := SortKey{kind: SortTargetDIMENSION, dimension: a, measure: measureA, direction: SortASC}

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
	for _, keys := range [][]SortKey{{ascA}, {ascA, descB}, {ascA, ascMeasureA}, {ascA, descMeasureB}, {ascMeasureA, descMeasureB}} {
		s, e := NewSortKeys(keys...)
		if e != nil || !s.Valid() {
			t.Fatal(e)
		}
	}
	for _, keys := range [][]SortKey{
		{ascA, descB, ascC},
		{SortKey{}},
		{ascA, descA},
		{ascA, forged},
		{forged},
		{ascMeasureA, descMeasureA},
		{ascMeasureA, descMeasureB, ascC},
	} {
		_, e := NewSortKeys(keys...)
		pBad(t, e)
	}
	mixed, e := NewSortKeys(ascA, ascMeasureA)
	if e != nil || !mixed.Valid() {
		t.Fatal("dimension and measure with same text not distinct", e)
	}
	mixedValues, _ := mixed.Values()
	if kind, ok := mixedValues[0].TargetKind(); !ok || kind != SortTargetDIMENSION {
		t.Fatal(kind, ok)
	}
	if kind, ok := mixedValues[1].TargetKind(); !ok || kind != SortTargetMEASURE {
		t.Fatal(kind, ok)
	}

	input := []SortKey{ascA, descMeasureB}
	s, _ := NewSortKeys(input...)
	input[0] = ascC
	first, _ := s.Values()
	first[0] = ascC
	second, _ := s.Values()
	if second[0] != ascA || second[1] != descMeasureB {
		t.Fatal("sort keys alias input or accessor")
	}
}

func TestProposalV2OperationAndOutputFieldsClosedVocabulary(t *testing.T) {
	if !OperationAGGREGATE.Valid() || !OperationLOOKUP.Valid() {
		t.Fatal("declared operation invalid")
	}
	for _, operation := range []Operation{"", "aggregate", "lookup", "SELECT", "AGGREGATE_LOOKUP"} {
		if operation.Valid() {
			t.Fatal(operation)
		}
	}
	if MaxOutputFields != 8 {
		t.Fatal(MaxOutputFields)
	}
	tokens := make([]FieldToken, 0, MaxOutputFields+1)
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
		token, e := NewFieldToken(name)
		if e != nil {
			t.Fatal(e)
		}
		tokens = append(tokens, token)
	}

	var zero OutputFields
	if zero.Valid() {
		t.Fatal("zero output fields valid")
	}
	if fields, ok := zero.Fields(); ok || fields != nil {
		t.Fatal("zero output fields readable")
	}
	for _, rejected := range [][]FieldToken{
		{},
		{FieldToken{}},
		{tokens[0], tokens[0]},
		{tokens[8], tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5], tokens[6], tokens[7]},
	} {
		_, e := NewOutputFields(rejected...)
		pBad(t, e)
	}
	for _, forged := range []OutputFields{
		{count: 1, initialized: true},
		{fields: [MaxOutputFields]FieldToken{tokens[0]}, count: 0, initialized: true},
		{fields: [MaxOutputFields]FieldToken{tokens[0], tokens[0]}, count: 2, initialized: true},
		{fields: [MaxOutputFields]FieldToken{tokens[0]}, count: MaxOutputFields + 1, initialized: true},
	} {
		if forged.Valid() {
			t.Fatal("forged output fields valid", forged)
		}
		if fields, ok := forged.Fields(); ok || fields != nil {
			t.Fatal("forged output fields readable")
		}
	}

	fields, e := NewOutputFields(tokens[:MaxOutputFields]...)
	if e != nil || !fields.Valid() {
		t.Fatal(e)
	}
	if got, ok := fields.Fields(); !ok || len(got) != MaxOutputFields || got[0] != tokens[0] || got[MaxOutputFields-1] != tokens[MaxOutputFields-1] {
		t.Fatal(got, ok)
	}
	input := []FieldToken{tokens[0], tokens[1]}
	outputFields, e := NewOutputFields(input...)
	if e != nil || !outputFields.Valid() {
		t.Fatal(e)
	}
	input[0] = tokens[2]
	first, _ := outputFields.Fields()
	first[0] = tokens[2]
	second, _ := outputFields.Fields()
	if second[0] != tokens[0] || second[1] != tokens[1] {
		t.Fatal("output fields alias input or accessor")
	}
}

func TestProposalV2AggregateProposalAcceptsMeasureSortTarget(t *testing.T) {
	d, measure, p, f, dimensions, _, limit := validProposalV2Parts(t)
	key, e := NewMeasureSortKey(measure, SortDESC)
	if e != nil {
		t.Fatal(e)
	}
	sort, e := NewSortKeys(key)
	if e != nil || !sort.Valid() {
		t.Fatal(e)
	}
	proposal, e := NewAggregateProposalV2(d, measure, p, f, dimensions, sort, limit, OutputRowset)
	if e != nil || !proposal.Valid() {
		t.Fatal(e)
	}
	if got, ok := proposal.Operation(); !ok || got != OperationAGGREGATE {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Measure(); !ok || got != measure {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Dimensions(); !ok || got != dimensions {
		t.Fatal(got, ok)
	}
	if _, ok := proposal.OutputFields(); ok {
		t.Fatal("aggregate output fields readable")
	}
	if got, ok := proposal.Output(); !ok || got != OutputRowset {
		t.Fatal(got, ok)
	}
	got, ok := proposal.Sort()
	if !ok {
		t.Fatal("sort")
	}
	values, _ := got.Values()
	if kind, ok := values[0].TargetKind(); !ok || kind != SortTargetMEASURE {
		t.Fatal(kind, ok)
	}
	if got, ok := values[0].Measure(); !ok || got != measure {
		t.Fatal(got, ok)
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
	key, _ := NewDimensionSortKey(field, SortASC)
	sort, _ := NewSortKeys(key)
	limit, _ := NewLimit(25)
	return dataset, measure, period, filters, dimensions, sort, limit
}

func validLookupProposalV2Parts(t *testing.T) (DatasetProfileRef, MeasureRef, PeriodProposal, Predicates, OutputFields, SortKeys, SortKeys, Limit) {
	t.Helper()
	dataset, measure, period, filters, _, sort, limit := validProposalV2Parts(t)
	field, _ := NewFieldToken("team")
	status, _ := NewFieldToken("status")
	outputFields, e := NewOutputFields(field, status)
	if e != nil {
		t.Fatal(e)
	}
	key, e := NewMeasureSortKey(measure, SortDESC)
	if e != nil {
		t.Fatal(e)
	}
	measureSort, e := NewSortKeys(key)
	if e != nil {
		t.Fatal(e)
	}
	return dataset, measure, period, filters, outputFields, sort, measureSort, limit
}

func TestProposalV2LookupShape(t *testing.T) {
	d, _, p, f, outputFields, sort, measureSort, limit := validLookupProposalV2Parts(t)
	if !measureSort.Valid() || !sort.Valid() {
		t.Fatal("fixture sort keys invalid")
	}
	team, _ := NewFieldToken("team")
	status, _ := NewFieldToken("status")
	if fields, ok := outputFields.Fields(); !ok || len(fields) != 2 || fields[0] != team || fields[1] != status {
		t.Fatal(fields, ok)
	}
	proposal, e := NewLookupProposalV2(d, p, f, outputFields, sort, limit)
	if e != nil || !proposal.Valid() {
		t.Fatal(e)
	}
	if got, ok := proposal.Operation(); !ok || got != OperationLOOKUP {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Output(); !ok || got != OutputRowset {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.OutputFields(); !ok || got != outputFields {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Dataset(); !ok || got != d {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Period(); !ok || got != p {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Sort(); !ok || got != sort {
		t.Fatal(got, ok)
	}
	if got, ok := proposal.Limit(); !ok || got != limit {
		t.Fatal(got, ok)
	}
	if _, ok := proposal.Filters(); !ok {
		t.Fatal("filters")
	}
	if got, ok := proposal.Measure(); ok {
		t.Fatal("lookup measure readable", got)
	}
	if got, ok := proposal.Dimensions(); ok {
		t.Fatal("lookup dimensions readable", got)
	}
	read, _ := proposal.OutputFields()
	fields, ok := read.Fields()
	if !ok || len(fields) != 2 {
		t.Fatal(fields, ok)
	}
	fields[0], _ = NewFieldToken("mutated")
	again, _ := proposal.OutputFields()
	againFields, _ := again.Fields()
	if againFields[0] != team || againFields[1] != status {
		t.Fatal("lookup output fields alias accessor", againFields)
	}

	f.values[0].values[0], _ = TextScalar("mutated-input")
	stored, ok := proposal.Filters()
	if !ok {
		t.Fatal("filters")
	}
	storedValues, _ := stored.Values()
	if got, _ := storedValues[0].values[0].Text(); got != "support" {
		t.Fatal("lookup filters alias input", got)
	}
}

func TestProposalV2LookupRejectsMissingValuesAndMeasureSort(t *testing.T) {
	d, _, p, f, outputFields, sort, measureSort, limit := validLookupProposalV2Parts(t)
	for _, candidate := range []struct {
		d            DatasetProfileRef
		p            PeriodProposal
		f            Predicates
		outputFields OutputFields
		sort         SortKeys
		limit        Limit
	}{
		{p: p, f: f, outputFields: outputFields, sort: sort, limit: limit},
		{d: d, f: f, outputFields: outputFields, sort: sort, limit: limit},
		{d: d, p: p, outputFields: outputFields, sort: sort, limit: limit},
		{d: d, p: p, f: f, sort: sort, limit: limit},
		{d: d, p: p, f: f, outputFields: outputFields, limit: limit},
		{d: d, p: p, f: f, outputFields: outputFields, sort: sort},
		{d: d, p: p, f: f, outputFields: outputFields, sort: measureSort, limit: limit},
	} {
		_, e := NewLookupProposalV2(candidate.d, candidate.p, candidate.f, candidate.outputFields, candidate.sort, candidate.limit)
		pBad(t, e)
	}
}

func TestProposalV2ZeroAndForgedMixedShapesInvalid(t *testing.T) {
	d, measure, p, f, dimensions, sort, limit := validProposalV2Parts(t)
	_, _, _, _, outputFields, _, measureSort, _ := validLookupProposalV2Parts(t)
	field, _ := NewFieldToken("team")
	singleFields, e := NewOutputFields(field)
	if e != nil {
		t.Fatal(e)
	}
	forgedMeasure := MeasureRef{measureID: "open_tickets"}
	forgedDimensions := Dimensions{fields: [MaxDimensions]FieldToken{field}, count: 0, initialized: true}
	if !forgedMeasure.Valid() || !forgedDimensions.Valid() {
		t.Fatal("forgery fixture rejected by its own type")
	}
	for _, forged := range []ProposalV2{
		{dataset: d, measure: measure, period: p, filters: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: Operation("SELECT"), dataset: d, measure: measure, period: p, filters: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationAGGREGATE, dataset: d, measure: measure, period: p, filters: f, dimensions: dimensions, outputFields: singleFields, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationAGGREGATE, dataset: d, measure: measure, period: p, filters: f, outputFields: OutputFields{fields: [MaxOutputFields]FieldToken{field}, count: 1}, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationAGGREGATE, dataset: d, measure: measure, period: p, filters: f, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationAGGREGATE, dataset: d, period: p, filters: f, dimensions: dimensions, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationAGGREGATE, dataset: d, measure: measure, period: p, filters: f, dimensions: dimensions, sort: sort, limit: limit, initialized: true},
		{operation: OperationLOOKUP, dataset: d, measure: measure, period: p, filters: f, outputFields: outputFields, sort: sort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, dimensions: dimensions, outputFields: outputFields, sort: sort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, measure: forgedMeasure, period: p, filters: f, outputFields: outputFields, sort: sort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, dimensions: forgedDimensions, outputFields: outputFields, sort: sort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, outputFields: outputFields, sort: sort, limit: limit, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, outputFields: outputFields, sort: sort, limit: limit, output: OutputValue, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, outputFields: outputFields, sort: measureSort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, sort: sort, limit: limit, output: OutputRowset, initialized: true},
		{operation: OperationLOOKUP, dataset: d, period: p, filters: f, outputFields: OutputFields{count: 1, initialized: true}, sort: sort, limit: limit, output: OutputRowset, initialized: true},
	} {
		if forged.Valid() {
			t.Fatal("forged proposal valid", forged)
		}
		if got, ok := forged.Operation(); ok || got != "" {
			t.Fatal("forged operation readable", got)
		}
		if got, ok := forged.Dataset(); ok {
			t.Fatal("forged dataset readable", got)
		}
		if got, ok := forged.Measure(); ok {
			t.Fatal("forged measure readable", got)
		}
		if got, ok := forged.Period(); ok {
			t.Fatal("forged period readable", got)
		}
		if got, ok := forged.Filters(); ok {
			t.Fatal("forged filters readable", got)
		}
		if got, ok := forged.Dimensions(); ok {
			t.Fatal("forged dimensions readable", got)
		}
		if got, ok := forged.OutputFields(); ok {
			t.Fatal("forged output fields readable", got)
		}
		if got, ok := forged.Sort(); ok {
			t.Fatal("forged sort readable", got)
		}
		if got, ok := forged.Limit(); ok {
			t.Fatal("forged limit readable", got)
		}
		if got, ok := forged.Output(); ok {
			t.Fatal("forged output readable", got)
		}
	}
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
		{d: d, measure: measure, p: p, f: f, dimensions: dimensions, sort: sort, limit: limit},
		{d: d, measure: measure, p: p, f: f, dimensions: dimensions, sort: sort, limit: limit, output: "TABLE"},
	} {
		_, err := NewAggregateProposalV2(candidate.d, candidate.measure, candidate.p, candidate.f, candidate.dimensions, candidate.sort, candidate.limit, candidate.output)
		pBad(t, err)
	}
	emptyDimensions, err := NewDimensions()
	if err != nil || !emptyDimensions.Valid() {
		t.Fatal(err)
	}
	unGrouped, err := NewAggregateProposalV2(d, measure, p, f, emptyDimensions, sort, limit, OutputValue)
	if err != nil || !unGrouped.Valid() {
		t.Fatal("empty dimensions rejected", err)
	}
	if got, ok := unGrouped.Output(); !ok || got != OutputValue {
		t.Fatal(got, ok)
	}
	var zero ProposalV2
	if zero.Valid() {
		t.Fatal("zero proposal valid")
	}
	if got, ok := zero.Operation(); ok || got != "" {
		t.Fatal("zero proposal operation readable")
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
	if _, ok := zero.OutputFields(); ok {
		t.Fatal("zero output fields accessor succeeded")
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
	proposal, err := NewAggregateProposalV2(d, measure, p, f, dimensions, sort, limit, OutputValue)
	if err != nil || !proposal.Valid() {
		t.Fatal(err)
	}
	if got, ok := proposal.Operation(); !ok || got != OperationAGGREGATE {
		t.Fatal("operation", got, ok)
	}
	if _, ok := proposal.OutputFields(); ok {
		t.Fatal("aggregate output fields readable")
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
	if got, ok := proposal.Output(); !ok || got != OutputValue {
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
