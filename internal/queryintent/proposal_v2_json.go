package queryintent

import (
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strconv"
)

// proposalV2JSONSchemaVersion is the literal schema tag of a model-proposed
// ProposalV2 document. The decoder never infers a shape from the values around
// it: a document that does not carry this exact tag is refused.
const proposalV2JSONSchemaVersion = "queryintent-proposal-v2"

// maxProposalV2JSONBytes bounds one model-proposed document.
const maxProposalV2JSONBytes = 256 << 10

// DecodeProposalV2JSON strictly decodes exactly one model-proposed ProposalV2
// document. The wire is closed: unknown or duplicate members, a missing or null
// required member, a member that belongs to the other operation shape, and a
// scalar whose JSON kind does not match its declared kind are all refused.
// Decoding carries no semantics of its own: it hands every value to the same
// constructors a caller would use, so a decoded proposal is valid for exactly
// the same reasons a hand-built one is. The wire deliberately has no place for
// SQL text, a relation, an endpoint, or a credential.
//
// Every failure returns the zero ProposalV2 and the same content-free
// CodeInvalidProposal refusal: a decoder error never echoes model input and
// never exposes a partially decoded proposal.
func DecodeProposalV2JSON(raw []byte) (ProposalV2, error) {
	if len(raw) == 0 || len(raw) > maxProposalV2JSONBytes {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	var wire proposalV2JSON
	if err := jsonv2.Unmarshal(raw, &wire,
		jsonv2.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false)); err != nil {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	proposal, err := wire.proposal()
	if err != nil {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	return proposal, nil
}

func invalidProposalV2JSON() error { return newRefusal(CodeInvalidProposal) }

// proposalV2JSON is the closed wire document of one proposal. A required member
// is a pointer, so a missing member and an explicit null are both refused. The
// members that one shape must be able to forbid are raw JSON instead: json/v2
// collapses an absent member and an explicit null into the same nil pointer, so
// only the raw value tells a written forbidden member from an unwritten one.
type proposalV2JSON struct {
	SchemaVersion *string                 `json:"schema_version"`
	Operation     *Operation              `json:"operation"`
	Dataset       *proposalV2DatasetJSON  `json:"dataset"`
	Period        *proposalV2PeriodJSON   `json:"period"`
	Filters       *[]proposalV2FilterJSON `json:"filters"`
	Sort          *[]proposalV2SortJSON   `json:"sort"`
	Limit         *int                    `json:"limit"`

	// AGGREGATE assigns the measure, the possibly empty dimension list and the
	// configured VALUE or ROWSET answer; LOOKUP forbids all three and carries
	// the row fields instead, which AGGREGATE in turn forbids.
	Measure      jsontext.Value `json:"measure"`
	Dimensions   jsontext.Value `json:"dimensions"`
	Output       jsontext.Value `json:"output"`
	OutputFields jsontext.Value `json:"output_fields"`
}

// proposalV2DatasetJSON pins the proposal to one approved dataset profile.
type proposalV2DatasetJSON struct {
	DatasetID           *string `json:"dataset_id"`
	ProfileVersion      *int64  `json:"profile_version"`
	ExpectedProfileHash *string `json:"expected_profile_hash"`
}

// proposalV2PeriodJSON carries the requested window. EXPLICIT needs both
// bounds; every relative mode must leave them out, even as a written null.
type proposalV2PeriodJSON struct {
	Mode  *PeriodMode    `json:"mode"`
	Start jsontext.Value `json:"start"`
	End   jsontext.Value `json:"end"`
}

// proposalV2FilterJSON is one predicate over a closed dataset field.
type proposalV2FilterJSON struct {
	Field  *string                 `json:"field"`
	Op     *Operator               `json:"op"`
	Values *[]proposalV2ScalarJSON `json:"values"`
}

// proposalV2ScalarJSON is one typed predicate value: BOOL is a JSON boolean,
// INT is a JSON integer, and every other scalar kind is a JSON string.
type proposalV2ScalarJSON struct {
	Kind  *ScalarKind     `json:"kind"`
	Value *jsontext.Value `json:"value"`
}

// proposalV2SortJSON names one closed sort target: a field or a measure. The
// target that target_kind does not name is forbidden, even as a written null.
type proposalV2SortJSON struct {
	TargetKind *SortTargetKind `json:"target_kind"`
	Field      jsontext.Value  `json:"field"`
	Measure    jsontext.Value  `json:"measure"`
	Direction  *SortDirection  `json:"direction"`
}

// proposal converts a wire document that carries every required member into a
// proposal through the existing constructors.
func (wire proposalV2JSON) proposal() (ProposalV2, error) {
	if wire.SchemaVersion == nil || *wire.SchemaVersion != proposalV2JSONSchemaVersion ||
		wire.Operation == nil || !wire.Operation.Valid() || wire.Dataset == nil || wire.Period == nil ||
		wire.Filters == nil || wire.Sort == nil || wire.Limit == nil {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	dataset, err := wire.Dataset.value()
	if err != nil {
		return ProposalV2{}, err
	}
	period, err := wire.Period.value()
	if err != nil {
		return ProposalV2{}, err
	}
	filters, err := proposalV2JSONFilters(*wire.Filters)
	if err != nil {
		return ProposalV2{}, err
	}
	sortKeys, err := proposalV2JSONSortKeys(*wire.Sort)
	if err != nil {
		return ProposalV2{}, err
	}
	limit, err := NewLimit(*wire.Limit)
	if err != nil {
		return ProposalV2{}, err
	}
	switch *wire.Operation {
	case OperationAGGREGATE:
		return wire.aggregate(dataset, period, filters, sortKeys, limit)
	case OperationLOOKUP:
		return wire.lookup(dataset, period, filters, sortKeys, limit)
	default:
		return ProposalV2{}, invalidProposalV2JSON()
	}
}

// aggregate decodes the AGGREGATE arm: the measure, the possibly empty
// dimension list and the configured output are required, and the LOOKUP fields
// are forbidden.
func (wire proposalV2JSON) aggregate(dataset DatasetProfileRef, period PeriodProposal, filters Predicates, sortKeys SortKeys, limit Limit) (ProposalV2, error) {
	measureID, measureOK := proposalV2JSONString(wire.Measure)
	output, outputOK := proposalV2JSONString(wire.Output)
	if !measureOK || !outputOK || wire.Dimensions == nil || wire.OutputFields != nil {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	measure, err := NewMeasureRef(measureID)
	if err != nil {
		return ProposalV2{}, err
	}
	dimensions, err := proposalV2JSONDimensions(wire.Dimensions)
	if err != nil {
		return ProposalV2{}, err
	}
	return NewAggregateProposalV2(dataset, measure, period, filters, dimensions, sortKeys, limit, Output(output))
}

// lookup decodes the LOOKUP arm: the requested row fields are required, and the
// measure, the dimension list and the aggregate output are forbidden.
func (wire proposalV2JSON) lookup(dataset DatasetProfileRef, period PeriodProposal, filters Predicates, sortKeys SortKeys, limit Limit) (ProposalV2, error) {
	if wire.OutputFields == nil || wire.Measure != nil || wire.Dimensions != nil || wire.Output != nil {
		return ProposalV2{}, invalidProposalV2JSON()
	}
	outputFields, err := proposalV2JSONOutputFields(wire.OutputFields)
	if err != nil {
		return ProposalV2{}, err
	}
	return NewLookupProposalV2(dataset, period, filters, outputFields, sortKeys, limit)
}

func (wire proposalV2DatasetJSON) value() (DatasetProfileRef, error) {
	if wire.DatasetID == nil || wire.ProfileVersion == nil || wire.ExpectedProfileHash == nil {
		return DatasetProfileRef{}, invalidProposalV2JSON()
	}
	return NewDatasetProfileRef(*wire.DatasetID, *wire.ProfileVersion, *wire.ExpectedProfileHash)
}

func (wire proposalV2PeriodJSON) value() (PeriodProposal, error) {
	if wire.Mode == nil || !wire.Mode.Valid() {
		return PeriodProposal{}, invalidProposalV2JSON()
	}
	if *wire.Mode == PeriodEXPLICIT {
		start, startOK := proposalV2JSONString(wire.Start)
		end, endOK := proposalV2JSONString(wire.End)
		if !startOK || !endOK {
			return PeriodProposal{}, invalidProposalV2JSON()
		}
		return NewExplicitPeriod(start, end)
	}
	if wire.Start != nil || wire.End != nil {
		return PeriodProposal{}, invalidProposalV2JSON()
	}
	return NewRelativePeriod(*wire.Mode)
}

func proposalV2JSONDimensions(raw jsontext.Value) (Dimensions, error) {
	tokens, err := proposalV2JSONFieldTokens(raw)
	if err != nil {
		return Dimensions{}, err
	}
	return NewDimensions(tokens...)
}

func proposalV2JSONOutputFields(raw jsontext.Value) (OutputFields, error) {
	tokens, err := proposalV2JSONFieldTokens(raw)
	if err != nil {
		return OutputFields{}, err
	}
	return NewOutputFields(tokens...)
}

// proposalV2JSONFieldTokens decodes a present raw array member into field
// tokens, refusing a written null or any other kind instead of coercing it.
func proposalV2JSONFieldTokens(raw jsontext.Value) ([]FieldToken, error) {
	if raw.Kind() != '[' {
		return nil, invalidProposalV2JSON()
	}
	var names []string
	if err := jsonv2.Unmarshal(raw, &names); err != nil {
		return nil, invalidProposalV2JSON()
	}
	tokens := make([]FieldToken, len(names))
	for index, name := range names {
		token, err := NewFieldToken(name)
		if err != nil {
			return nil, err
		}
		tokens[index] = token
	}
	return tokens, nil
}

func proposalV2JSONFilters(wires []proposalV2FilterJSON) (Predicates, error) {
	predicates := make([]Predicate, len(wires))
	for index, wire := range wires {
		predicate, err := wire.value()
		if err != nil {
			return Predicates{}, err
		}
		predicates[index] = predicate
	}
	return NewPredicates(predicates...)
}

func (wire proposalV2FilterJSON) value() (Predicate, error) {
	if wire.Field == nil || wire.Op == nil || wire.Values == nil {
		return Predicate{}, invalidProposalV2JSON()
	}
	field, err := NewFieldToken(*wire.Field)
	if err != nil {
		return Predicate{}, err
	}
	values, err := proposalV2JSONScalars(*wire.Values)
	if err != nil {
		return Predicate{}, err
	}
	return NewPredicate(field, *wire.Op, values...)
}

func proposalV2JSONScalars(wires []proposalV2ScalarJSON) ([]Scalar, error) {
	values := make([]Scalar, len(wires))
	for index, wire := range wires {
		value, err := wire.value()
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

// value decodes one scalar through the constructor of its declared kind. The
// JSON kind of value must match that kind, so a quoted integer, a fractional or
// exponent number, and a stringified boolean are refused instead of coerced.
func (wire proposalV2ScalarJSON) value() (Scalar, error) {
	if wire.Kind == nil || wire.Value == nil {
		return Scalar{}, invalidProposalV2JSON()
	}
	switch *wire.Kind {
	case KindBOOL:
		flag, ok := proposalV2JSONBool(*wire.Value)
		if !ok {
			return Scalar{}, invalidProposalV2JSON()
		}
		return BoolScalar(flag), nil
	case KindINT:
		number, ok := proposalV2JSONInteger(*wire.Value)
		if !ok {
			return Scalar{}, invalidProposalV2JSON()
		}
		return IntScalar(number), nil
	case KindNUMERIC, KindTEXT, KindDATE, KindTIMESTAMP, KindTIMESTAMPTZ:
		text, ok := proposalV2JSONString(*wire.Value)
		if !ok {
			return Scalar{}, invalidProposalV2JSON()
		}
		return proposalV2JSONTextScalar(*wire.Kind, text)
	default:
		return Scalar{}, invalidProposalV2JSON()
	}
}

func proposalV2JSONTextScalar(kind ScalarKind, text string) (Scalar, error) {
	switch kind {
	case KindNUMERIC:
		return NumericScalar(text)
	case KindTEXT:
		return TextScalar(text)
	case KindDATE:
		return DateScalar(text)
	case KindTIMESTAMP:
		return TimestampScalar(text)
	default:
		return TimestamptzScalar(text)
	}
}

// proposalV2JSONBool reports whether raw is exactly the JSON literal true or
// false; the literal comparison refuses the string "true" as well.
func proposalV2JSONBool(raw jsontext.Value) (bool, bool) {
	switch string(raw) {
	case "true":
		return true, true
	case "false":
		return false, true
	default:
		return false, false
	}
}

// proposalV2JSONInteger parses raw as a signed JSON integer. Only an optional
// minus sign followed by decimal digits is accepted, so a fraction or an
// exponent is refused rather than rounded.
func proposalV2JSONInteger(raw jsontext.Value) (int64, bool) {
	text := string(raw)
	body := text
	if len(body) > 0 && body[0] == '-' {
		body = body[1:]
	}
	if !asciiDigits(body) {
		return 0, false
	}
	number, err := strconv.ParseInt(text, 10, 64)
	return number, err == nil
}

// proposalV2JSONString decodes a present JSON string, the carrier of every
// scalar kind that is not a boolean or an integer. It refuses a written null
// and any other kind, so it also decodes the raw members above.
func proposalV2JSONString(raw jsontext.Value) (string, bool) {
	if raw.Kind() != '"' {
		return "", false
	}
	var text string
	if err := jsonv2.Unmarshal(raw, &text); err != nil {
		return "", false
	}
	return text, true
}

func proposalV2JSONSortKeys(wires []proposalV2SortJSON) (SortKeys, error) {
	keys := make([]SortKey, len(wires))
	for index, wire := range wires {
		key, err := wire.value()
		if err != nil {
			return SortKeys{}, err
		}
		keys[index] = key
	}
	return NewSortKeys(keys...)
}

// value decodes one sort key. Exactly one of field and measure must be present
// for the declared target kind, so a key that names both targets, or neither,
// is refused before any constructor sees it.
func (wire proposalV2SortJSON) value() (SortKey, error) {
	if wire.TargetKind == nil || wire.Direction == nil {
		return SortKey{}, invalidProposalV2JSON()
	}
	switch *wire.TargetKind {
	case SortTargetDIMENSION:
		name, ok := proposalV2JSONString(wire.Field)
		if !ok || wire.Measure != nil {
			return SortKey{}, invalidProposalV2JSON()
		}
		field, err := NewFieldToken(name)
		if err != nil {
			return SortKey{}, err
		}
		return NewDimensionSortKey(field, *wire.Direction)
	case SortTargetMEASURE:
		name, ok := proposalV2JSONString(wire.Measure)
		if !ok || wire.Field != nil {
			return SortKey{}, invalidProposalV2JSON()
		}
		measure, err := NewMeasureRef(name)
		if err != nil {
			return SortKey{}, err
		}
		return NewMeasureSortKey(measure, *wire.Direction)
	default:
		return SortKey{}, invalidProposalV2JSON()
	}
}
