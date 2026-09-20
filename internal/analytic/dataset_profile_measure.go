package analytic

import (
	"strings"
	"unicode/utf8"
)

// Reducer is the closed set of aggregation operations owned by a dataset profile.
type Reducer string

const (
	ReducerCountRows     Reducer = "COUNT_ROWS"
	ReducerCountDistinct Reducer = "COUNT_DISTINCT"
	ReducerSum           Reducer = "SUM"
	ReducerRatioOfSums   Reducer = "RATIO_OF_SUMS"
)

func (value Reducer) Valid() bool {
	switch value {
	case ReducerCountRows, ReducerCountDistinct, ReducerSum, ReducerRatioOfSums:
		return true
	default:
		return false
	}
}

// NullPolicy declares how absent operands affect an aggregate.
type NullPolicy string

const (
	NullNotApplicable    NullPolicy = "NOT_APPLICABLE"
	NullExcludeAndReport NullPolicy = "EXCLUDE_AND_REPORT"
	NullRequireComplete  NullPolicy = "REQUIRE_COMPLETE"
)

func (value NullPolicy) Valid() bool {
	return value == NullNotApplicable || value == NullExcludeAndReport || value == NullRequireComplete
}

// Eligibility is explicit even though schema v1 permits only all approved rows.
type Eligibility string

const EligibilityAllRows Eligibility = "ALL_ROWS"

func (value Eligibility) Valid() bool { return value == EligibilityAllRows }

// MeasureSpecInput is both construction input and detached read DTO.
type MeasureSpecInput struct {
	ID               string
	Reducer          Reducer
	DistinctField    string
	NumeratorField   string
	DenominatorField string
	Unit             string
	NullPolicy       NullPolicy
	Eligibility      Eligibility
}

// MeasureSpec is an immutable, bounded aggregate definition.
type MeasureSpec struct {
	id               string
	reducer          Reducer
	distinctField    string
	numeratorField   string
	denominatorField string
	unit             string
	nullPolicy       NullPolicy
	eligibility      Eligibility
}

func NewMeasureSpec(input MeasureSpecInput) (MeasureSpec, error) {
	value := MeasureSpec{
		id: input.ID, reducer: input.Reducer, distinctField: input.DistinctField,
		numeratorField: input.NumeratorField, denominatorField: input.DenominatorField,
		unit: input.Unit, nullPolicy: input.NullPolicy, eligibility: input.Eligibility,
	}
	if !value.Valid() {
		return MeasureSpec{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value MeasureSpec) Valid() bool {
	if !validProfileIdentity(value.id) || !validMeasureUnit(value.unit) ||
		!value.reducer.Valid() || !value.nullPolicy.Valid() || value.eligibility != EligibilityAllRows {
		return false
	}
	distinct := validOptionalMeasureField(value.distinctField)
	numerator := validOptionalMeasureField(value.numeratorField)
	denominator := validOptionalMeasureField(value.denominatorField)
	if !distinct || !numerator || !denominator {
		return false
	}
	switch value.reducer {
	case ReducerCountRows:
		return value.distinctField == "" && value.numeratorField == "" && value.denominatorField == "" && value.nullPolicy == NullNotApplicable
	case ReducerCountDistinct:
		return value.distinctField != "" && value.numeratorField == "" && value.denominatorField == "" && measureOperandNullPolicy(value.nullPolicy)
	case ReducerSum:
		return value.distinctField == "" && value.numeratorField != "" && value.denominatorField == "" && measureOperandNullPolicy(value.nullPolicy)
	case ReducerRatioOfSums:
		return value.distinctField == "" && value.numeratorField != "" && value.denominatorField != "" && measureOperandNullPolicy(value.nullPolicy)
	default:
		return false
	}
}

func (value MeasureSpec) Values() MeasureSpecInput {
	return MeasureSpecInput{
		ID: value.id, Reducer: value.reducer, DistinctField: value.distinctField,
		NumeratorField: value.numeratorField, DenominatorField: value.denominatorField,
		Unit: value.unit, NullPolicy: value.nullPolicy, Eligibility: value.eligibility,
	}
}

func validOptionalMeasureField(value string) bool {
	return value == "" || fieldTokenPattern.MatchString(value)
}

func measureOperandNullPolicy(value NullPolicy) bool {
	return value == NullExcludeAndReport || value == NullRequireComplete
}

func validMeasureUnit(value string) bool {
	if !utf8.ValidString(value) || len(value) == 0 || len(value) > 64 || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}
