package analytic

// DatasetProfile is the immutable, sealed representation of one validated
// dataset profile. Its hash binds every member that can affect execution.
type DatasetProfile struct {
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
	hash      string
}

// NewDatasetProfile validates, normalizes, and seals a profile specification.
func NewDatasetProfile(spec DatasetProfileSpec) (DatasetProfile, error) {
	normalized, err := normalizeDatasetProfileSpec(spec)
	if err != nil {
		return DatasetProfile{}, err
	}
	_, hash, err := canonicalDatasetProfile(normalized)
	if err != nil {
		return DatasetProfile{}, err
	}
	return DatasetProfile{
		key: normalized.key, mode: normalized.mode, source: normalized.source,
		fields:    append([]FieldSpec(nil), normalized.fields...),
		measures:  append([]MeasureSpec(nil), normalized.measures...),
		semantics: normalized.semantics, grain: normalized.grain,
		time: normalized.time, coverage: normalized.coverage,
		limits: normalized.limits, hash: hash,
	}, nil
}

// Valid reconstructs and reseals the profile, detecting changes to either its
// members or seal. The stored normalized order is part of the sealed value.
func (value DatasetProfile) Valid() bool {
	if !validProfileHash(value.hash) {
		return false
	}
	normalized, err := normalizeDatasetProfileSpec(value.Spec())
	if err != nil || !value.matches(normalized) {
		return false
	}
	_, hash, err := canonicalDatasetProfile(normalized)
	return err == nil && hash == value.hash
}

func (value DatasetProfile) matches(normalized normalizedDatasetProfileSpec) bool {
	if value.key != normalized.key || value.mode != normalized.mode ||
		value.source != normalized.source || value.time != normalized.time ||
		value.coverage != normalized.coverage || value.limits != normalized.limits ||
		!value.semantics.Valid() || !normalized.semantics.Valid() ||
		!value.grain.Valid() || !normalized.grain.Valid() ||
		len(value.fields) != len(normalized.fields) || len(value.measures) != len(normalized.measures) {
		return false
	}
	for index := range value.fields {
		if value.fields[index] != normalized.fields[index] {
			return false
		}
	}
	for index := range value.measures {
		if value.measures[index] != normalized.measures[index] {
			return false
		}
	}
	return true
}

func (value DatasetProfile) Hash() string                 { return value.hash }
func (value DatasetProfile) Key() ProfileKey              { return value.key }
func (value DatasetProfile) Mode() ExecutionMode          { return value.mode }
func (value DatasetProfile) Source() SourceProjectionSpec { return value.source }
func (value DatasetProfile) Semantics() ProfileSemantics  { return value.semantics }
func (value DatasetProfile) Grain() DatasetGrain          { return value.grain }
func (value DatasetProfile) Time() TimePolicy             { return value.time }
func (value DatasetProfile) Coverage() CoveragePolicy     { return value.coverage }
func (value DatasetProfile) Limits() ProfileLimits        { return value.limits }

// Spec returns a detached DTO suitable for reconstruction or persistence.
func (value DatasetProfile) Spec() DatasetProfileSpec {
	return DatasetProfileSpec{
		Key: value.key, Mode: value.mode, Source: value.source,
		Fields: value.Fields(), Measures: value.Measures(),
		Semantics: value.Semantics(), Grain: value.Grain(), Time: value.time,
		Coverage: value.coverage, Limits: value.limits,
	}
}

func (value DatasetProfile) Fields() []FieldSpec {
	return append([]FieldSpec(nil), value.fields...)
}

func (value DatasetProfile) Measures() []MeasureSpec {
	return append([]MeasureSpec(nil), value.measures...)
}

func (value DatasetProfile) Field(token string) (FieldSpec, bool) {
	for _, field := range value.fields {
		if field.Values().Token == token {
			return field, true
		}
	}
	return FieldSpec{}, false
}

func (value DatasetProfile) Measure(id string) (MeasureSpec, bool) {
	for _, measure := range value.measures {
		if measure.Values().ID == id {
			return measure, true
		}
	}
	return MeasureSpec{}, false
}
