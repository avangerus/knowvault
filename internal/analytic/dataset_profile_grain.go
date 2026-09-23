package analytic

import "sort"

// DuplicatePolicy declares how the profile treats duplicate rows on the grain.
// The only valid value is REJECT; there is deliberately no default.
type DuplicatePolicy string

const DuplicateReject DuplicatePolicy = "REJECT"

func (value DuplicatePolicy) Valid() bool { return value == DuplicateReject }

// DatasetGrainInput is both the construction input and the detached read DTO
// for a dataset grain declaration.
type DatasetGrainInput struct {
	Description     string
	KeyFields       []string
	DuplicatePolicy DuplicatePolicy
}

// DatasetGrain is an immutable, validated grain declaration. It stores only
// private fields and exposes no aliased state.
type DatasetGrain struct {
	description     string
	keyFields       []string
	duplicatePolicy DuplicatePolicy
}

// grainMaxKeyFields bounds the composite key arity.
const grainMaxKeyFields = 8

// grainMaxDescriptionBytes bounds the description by UTF-8 byte length.
const grainMaxDescriptionBytes = 1024

// grainMaxFieldTokenBytes bounds each logical field token by byte length. It
// mirrors the 128-byte bound carried by fieldTokenPattern.
const grainMaxFieldTokenBytes = 128

func NewDatasetGrain(input DatasetGrainInput) (DatasetGrain, error) {
	value := DatasetGrain{
		description:     input.Description,
		keyFields:       cloneGrainTokens(input.KeyFields),
		duplicatePolicy: input.DuplicatePolicy,
	}
	sort.Strings(value.keyFields)
	if !value.Valid() {
		return DatasetGrain{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value DatasetGrain) Valid() bool {
	if !validGrainDescription(value.description) || !value.duplicatePolicy.Valid() {
		return false
	}
	if len(value.keyFields) < 1 || len(value.keyFields) > grainMaxKeyFields {
		return false
	}
	for index, token := range value.keyFields {
		if !validGrainFieldToken(token) {
			return false
		}
		if index > 0 && value.keyFields[index-1] >= token {
			return false
		}
	}
	return true
}

func (value DatasetGrain) Values() DatasetGrainInput {
	return DatasetGrainInput{
		Description:     value.description,
		KeyFields:       cloneGrainTokens(value.keyFields),
		DuplicatePolicy: value.duplicatePolicy,
	}
}

func validGrainDescription(value string) bool {
	return validSemanticsString(value, grainMaxDescriptionBytes)
}

func validGrainFieldToken(token string) bool {
	return len(token) <= grainMaxFieldTokenBytes && fieldTokenPattern.MatchString(token)
}

func cloneGrainTokens(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}
