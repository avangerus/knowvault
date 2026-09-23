package analytic

import "sort"

// DatasetProfileSpec is the constructor DTO for one approved dataset profile.
type DatasetProfileSpec struct {
	Key       ProfileKey
	Mode      ExecutionMode
	Source    SourceProjectionSpec
	Fields    []FieldSpec
	Measures  []MeasureSpec
	Semantics ProfileSemantics
	Grain     DatasetGrain
	Time      TimePolicy
	Coverage  CoveragePolicy
	Limits    ProfileLimits
}

// normalizedDatasetProfileSpec is the validated, deterministic representation
// consumed by profile construction. Its slices never alias caller-owned slices.
type normalizedDatasetProfileSpec struct {
	key       ProfileKey
	mode      ExecutionMode
	source    SourceProjectionSpec
	fields    []FieldSpec
	measures  []MeasureSpec
	semantics ProfileSemantics
	grain     DatasetGrain
	time      TimePolicy
	coverage  CoveragePolicy
	limits    ProfileLimits
}

func normalizeDatasetProfileSpec(spec DatasetProfileSpec) (normalizedDatasetProfileSpec, error) {
	if !spec.Key.Valid() || spec.Mode != ExecutionLive || !spec.Source.Valid() ||
		!spec.Semantics.Valid() || !spec.Grain.Valid() ||
		!spec.Time.Valid() || !spec.Coverage.Valid() || !spec.Limits.Valid() ||
		len(spec.Fields) == 0 || len(spec.Measures) == 0 {
		return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
	}

	fields := append([]FieldSpec(nil), spec.Fields...)
	measures := append([]MeasureSpec(nil), spec.Measures...)
	sort.Slice(fields, func(left, right int) bool {
		return fields[left].Values().SourceOrdinal < fields[right].Values().SourceOrdinal
	})
	sort.Slice(measures, func(left, right int) bool {
		return measures[left].Values().ID < measures[right].Values().ID
	})

	semantics := spec.Semantics.Values()
	semanticFieldTokens := make(map[string]struct{}, len(semantics.Fields))
	for _, field := range semantics.Fields {
		semanticFieldTokens[field.Token] = struct{}{}
	}
	semanticMeasureIDs := make(map[string]struct{}, len(semantics.Measures))
	for _, measure := range semantics.Measures {
		semanticMeasureIDs[measure.ID] = struct{}{}
	}

	fieldByToken := make(map[string]ScalarType, len(fields))
	fieldNullability := make(map[string]bool, len(fields))
	physicalNames := make(map[string]struct{}, len(fields))
	hasOutput := false
	for index, field := range fields {
		if !field.Valid() {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		value := field.Values()
		if value.SourceOrdinal != index+1 {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		if _, duplicate := fieldByToken[value.Token]; duplicate {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		if _, duplicate := physicalNames[value.PhysicalName]; duplicate {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		fieldByToken[value.Token] = value.LogicalType
		fieldNullability[value.Token] = value.Nullable
		physicalNames[value.PhysicalName] = struct{}{}
		hasOutput = hasOutput || value.OutputAllowed
	}
	if !hasOutput {
		return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
	}

	for index, measure := range measures {
		if !measure.Valid() {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		value := measure.Values()
		if index > 0 && measures[index-1].Values().ID == value.ID {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
		if !measureOperandsValid(value, fieldByToken) {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
	}

	if len(semanticFieldTokens) != len(fieldByToken) {
		return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
	}
	for token := range fieldByToken {
		if _, found := semanticFieldTokens[token]; !found {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
	}
	if len(semanticMeasureIDs) != len(measures) {
		return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
	}
	for _, measure := range measures {
		if _, found := semanticMeasureIDs[measure.Values().ID]; !found {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
	}

	for _, token := range spec.Grain.Values().KeyFields {
		nullable, found := fieldNullability[token]
		if !found || nullable {
			return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
		}
	}

	if !timeFieldValid(spec.Time.Values(), fieldByToken) {
		return normalizedDatasetProfileSpec{}, invalidDatasetProfileSpec()
	}
	return normalizedDatasetProfileSpec{
		key: spec.Key, mode: spec.Mode, source: spec.Source,
		fields: fields, measures: measures, semantics: spec.Semantics, grain: spec.Grain,
		time: spec.Time, coverage: spec.Coverage, limits: spec.Limits,
	}, nil
}

func measureOperandsValid(measure MeasureSpecInput, fields map[string]ScalarType) bool {
	switch measure.Reducer {
	case ReducerCountRows:
		return true
	case ReducerCountDistinct:
		_, found := fields[measure.DistinctField]
		return found
	case ReducerSum:
		return numericOperand(fields, measure.NumeratorField)
	case ReducerRatioOfSums:
		return numericOperand(fields, measure.NumeratorField) &&
			numericOperand(fields, measure.DenominatorField)
	default:
		return false
	}
}

func numericOperand(fields map[string]ScalarType, token string) bool {
	kind, found := fields[token]
	return found && (kind == ScalarInt || kind == ScalarNumeric)
}

func timeFieldValid(policy TimePolicyInput, fields map[string]ScalarType) bool {
	if policy.Kind == TimeNone {
		return true
	}
	kind, found := fields[policy.FieldToken]
	if !found {
		return false
	}
	switch policy.Kind {
	case TimeBusinessDate:
		return kind == ScalarDate
	case TimeLocalTimestamp:
		return kind == ScalarTimestamp
	case TimeZonedTimestamp:
		return kind == ScalarTimestamptz
	default:
		return false
	}
}

func invalidDatasetProfileSpec() error { return &Error{code: CodeInvalidRequest} }
