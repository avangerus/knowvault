package analytic

import "regexp"

// ScalarType is the logical type exposed by an approved dataset profile.
type ScalarType string

const (
	ScalarBool        ScalarType = "BOOL"
	ScalarInt         ScalarType = "INT"
	ScalarNumeric     ScalarType = "NUMERIC"
	ScalarText        ScalarType = "TEXT"
	ScalarDate        ScalarType = "DATE"
	ScalarTimestamp   ScalarType = "TIMESTAMP"
	ScalarTimestamptz ScalarType = "TIMESTAMPTZ"
)

func (value ScalarType) Valid() bool {
	switch value {
	case ScalarBool, ScalarInt, ScalarNumeric, ScalarText, ScalarDate, ScalarTimestamp, ScalarTimestamptz:
		return true
	default:
		return false
	}
}

// PhysicalType is the exact PostgreSQL type allowed at the projection boundary.
type PhysicalType string

const (
	PhysicalPGBool        PhysicalType = "PG_BOOL"
	PhysicalPGInt8        PhysicalType = "PG_INT8"
	PhysicalPGNumeric     PhysicalType = "PG_NUMERIC"
	PhysicalPGText        PhysicalType = "PG_TEXT"
	PhysicalPGDate        PhysicalType = "PG_DATE"
	PhysicalPGTimestamp   PhysicalType = "PG_TIMESTAMP"
	PhysicalPGTimestamptz PhysicalType = "PG_TIMESTAMPTZ"
)

func (value PhysicalType) Valid() bool {
	switch value {
	case PhysicalPGBool, PhysicalPGInt8, PhysicalPGNumeric, PhysicalPGText, PhysicalPGDate, PhysicalPGTimestamp, PhysicalPGTimestamptz:
		return true
	default:
		return false
	}
}

// PredicateOperator is a closed filter operation vocabulary.
type PredicateOperator string

const (
	PredicateEQ     PredicateOperator = "EQ"
	PredicateIN     PredicateOperator = "IN"
	PredicateGTE    PredicateOperator = "GTE"
	PredicateLTE    PredicateOperator = "LTE"
	PredicateISNull PredicateOperator = "IS_NULL"
)

var canonicalPredicateOperators = [...]PredicateOperator{
	PredicateEQ, PredicateIN, PredicateGTE, PredicateLTE, PredicateISNull,
}

func (value PredicateOperator) Valid() bool {
	for _, candidate := range canonicalPredicateOperators {
		if value == candidate {
			return true
		}
	}
	return false
}

// FieldSpecInput is both the constructor input and detached read DTO.
type FieldSpecInput struct {
	Token         string
	SourceOrdinal int
	PhysicalName  string
	LogicalType   ScalarType
	PhysicalType  PhysicalType
	Nullable      bool
	Filterable    bool
	Groupable     bool
	Sortable      bool
	OutputAllowed bool
	AllowedOps    []PredicateOperator
}

// FieldSpec is an immutable approved field definition.
type FieldSpec struct {
	token         string
	sourceOrdinal int
	physicalName  string
	logicalType   ScalarType
	physicalType  PhysicalType
	nullable      bool
	filterable    bool
	groupable     bool
	sortable      bool
	outputAllowed bool
	allowedOps    [len(canonicalPredicateOperators)]PredicateOperator
	allowedCount  uint8
}

func NewFieldSpec(input FieldSpecInput) (FieldSpec, error) {
	if len(input.AllowedOps) > len(canonicalPredicateOperators) {
		return FieldSpec{}, &Error{code: CodeInvalidRequest}
	}
	value := FieldSpec{
		token: input.Token, sourceOrdinal: input.SourceOrdinal, physicalName: input.PhysicalName,
		logicalType: input.LogicalType, physicalType: input.PhysicalType, nullable: input.Nullable,
		filterable: input.Filterable, groupable: input.Groupable, sortable: input.Sortable,
		outputAllowed: input.OutputAllowed,
	}
	for _, canonical := range canonicalPredicateOperators {
		for _, requested := range input.AllowedOps {
			if requested == canonical {
				value.allowedOps[value.allowedCount] = requested
				value.allowedCount++
			}
		}
	}
	if len(input.AllowedOps) != int(value.allowedCount) || !value.Valid() {
		return FieldSpec{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value FieldSpec) Valid() bool {
	if !fieldTokenPattern.MatchString(value.token) || value.sourceOrdinal <= 0 ||
		!projectionIdentifierPattern.MatchString(value.physicalName) ||
		!value.logicalType.Valid() || !value.physicalType.Valid() ||
		!compatibleFieldTypes(value.logicalType, value.physicalType) ||
		value.allowedCount > uint8(len(value.allowedOps)) || value.filterable != (value.allowedCount > 0) {
		return false
	}
	for index := range value.allowedOps {
		if index < int(value.allowedCount) {
			operator := value.allowedOps[index]
			if !operator.Valid() || !fieldOperatorAllowed(value.logicalType, value.nullable, operator) ||
				(index > 0 && predicateOperatorRank(value.allowedOps[index-1]) >= predicateOperatorRank(operator)) {
				return false
			}
		} else if value.allowedOps[index] != "" {
			return false
		}
	}
	return true
}

func (value FieldSpec) Values() FieldSpecInput {
	operators := make([]PredicateOperator, int(value.allowedCount))
	copy(operators, value.allowedOps[:value.allowedCount])
	return FieldSpecInput{
		Token: value.token, SourceOrdinal: value.sourceOrdinal, PhysicalName: value.physicalName,
		LogicalType: value.logicalType, PhysicalType: value.physicalType, Nullable: value.nullable,
		Filterable: value.filterable, Groupable: value.groupable, Sortable: value.sortable,
		OutputAllowed: value.outputAllowed, AllowedOps: operators,
	}
}

var fieldTokenPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func compatibleFieldTypes(logical ScalarType, physical PhysicalType) bool {
	pairs := map[ScalarType]PhysicalType{
		ScalarBool: PhysicalPGBool, ScalarInt: PhysicalPGInt8, ScalarNumeric: PhysicalPGNumeric,
		ScalarText: PhysicalPGText, ScalarDate: PhysicalPGDate, ScalarTimestamp: PhysicalPGTimestamp,
		ScalarTimestamptz: PhysicalPGTimestamptz,
	}
	return pairs[logical] == physical
}

func fieldOperatorAllowed(kind ScalarType, nullable bool, operator PredicateOperator) bool {
	if operator == PredicateEQ || operator == PredicateIN {
		return true
	}
	if operator == PredicateISNull {
		return nullable
	}
	return (operator == PredicateGTE || operator == PredicateLTE) && kind != ScalarBool && kind != ScalarText
}

func predicateOperatorRank(operator PredicateOperator) int {
	for index, candidate := range canonicalPredicateOperators {
		if operator == candidate {
			return index
		}
	}
	return len(canonicalPredicateOperators)
}
