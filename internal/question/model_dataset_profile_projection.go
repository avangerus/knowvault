package question

import (
	"sort"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// Fixed schema and capability identity of the model-facing dataset profile
// projection. They are the only values the projection advertises to a model
// caller; there is no negotiation and no version discovery.
const (
	modelDatasetProfileSchemaVersion = "knowvault-model-dataset-profile-v1"
	modelDatasetProfileCapability    = "READ_ONLY_ANALYTIC"

	// modelDatasetProfileMaxBytes freezes the canonical size of the complete
	// model-facing projection, including its projection digest.
	modelDatasetProfileMaxBytes = 256 * 1024
)

// modelDatasetProfile is the safe, model-facing projection of one approved
// dataset profile. It carries only business semantics: no source, schema,
// relation, physical or SQL identity survives into it.
type modelDatasetProfile struct {
	SchemaVersion          string                       `json:"schema_version"`
	Capability             string                       `json:"capability"`
	DatasetID              string                       `json:"dataset_id"`
	ProfileVersion         int64                        `json:"profile_version"`
	ProfileHash            string                       `json:"profile_hash"`
	DatasetLabel           string                       `json:"dataset_label"`
	DatasetDescription     string                       `json:"dataset_description"`
	GrainDescription       string                       `json:"grain_description"`
	Fields                 []modelDatasetProfileField   `json:"fields"`
	Measures               []modelDatasetProfileMeasure `json:"measures"`
	Time                   modelDatasetProfileTime      `json:"time"`
	DeclaredCoveragePolicy string                       `json:"declared_coverage_policy"`
	Limits                 modelDatasetProfileLimits    `json:"limits"`
	ProjectionDigest       string                       `json:"projection_digest"`
}

// modelDatasetProfileField is the safe projection of one approved field. The
// physical name, ordinal and physical type are deliberately excluded.
type modelDatasetProfileField struct {
	Token            string   `json:"token"`
	Label            string   `json:"label"`
	Description      string   `json:"description"`
	NullMeaning      string   `json:"null_meaning"`
	Aliases          []string `json:"aliases"`
	LogicalType      string   `json:"logical_type"`
	Nullable         bool     `json:"nullable"`
	Filterable       bool     `json:"filterable"`
	Groupable        bool     `json:"groupable"`
	Sortable         bool     `json:"sortable"`
	OutputAllowed    bool     `json:"output_allowed"`
	AllowedOperators []string `json:"allowed_operators"`
	AllowedValues    []string `json:"allowed_values,omitempty"`
}

// modelDatasetProfileMeasure is the safe projection of one approved measure.
// Operand fields, eligibility internals and reducer wiring are excluded.
type modelDatasetProfileMeasure struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
	Reducer     string   `json:"reducer"`
	Unit        string   `json:"unit"`
	NullPolicy  string   `json:"null_policy"`
}

// modelDatasetProfileTime is the safe projection of the profile time policy.
// The source timezone is deliberately excluded; only the reporting timezone is
// exposed.
type modelDatasetProfileTime struct {
	Kind              string `json:"kind"`
	FieldToken        string `json:"field_token"`
	ReportingTimezone string `json:"reporting_timezone"`
	Calendar          string `json:"calendar"`
}

// modelDatasetProfileLimits is the safe projection of the profile execution
// bounds a model caller needs to shape a request. Bytes and timeout are
// excluded.
type modelDatasetProfileLimits struct {
	MaxOutputGroups int `json:"max_output_groups"`
	MaxPeriodDays   int `json:"max_period_days"`
}

// projectModelDatasetProfile projects one validated profile into the safe,
// content-free model contract. It reads only public detached accessors and
// joins field/measure semantics by logical token/ID.
func projectModelDatasetProfile(profile analytic.DatasetProfile) (modelDatasetProfile, error) {
	if !profile.Valid() {
		return modelDatasetProfile{}, &Error{code: CodeInvalid}
	}

	semantics := profile.Semantics().Values()
	fields, err := projectModelDatasetProfileFields(profile, semantics)
	if err != nil {
		return modelDatasetProfile{}, err
	}
	measures, err := projectModelDatasetProfileMeasures(profile, semantics)
	if err != nil {
		return modelDatasetProfile{}, err
	}

	timePolicy := profile.Time().Values()
	limits := profile.Limits().Values()

	projected := modelDatasetProfile{
		SchemaVersion:      modelDatasetProfileSchemaVersion,
		Capability:         modelDatasetProfileCapability,
		DatasetID:          profile.Key().DatasetID(),
		ProfileVersion:     profile.Key().Version(),
		ProfileHash:        profile.Hash(),
		DatasetLabel:       semantics.DatasetLabel,
		DatasetDescription: semantics.DatasetDescription,
		GrainDescription:   profile.Grain().Values().Description,
		Fields:             fields,
		Measures:           measures,
		Time: modelDatasetProfileTime{
			Kind:              string(timePolicy.Kind),
			FieldToken:        timePolicy.FieldToken,
			ReportingTimezone: timePolicy.ReportingTimezone,
			Calendar:          string(timePolicy.Calendar),
		},
		DeclaredCoveragePolicy: string(profile.Coverage()),
		Limits: modelDatasetProfileLimits{
			MaxOutputGroups: limits.MaxOutputGroups,
			MaxPeriodDays:   limits.MaxPeriodDays,
		},
	}

	digest, err := modelDatasetProfileDigest(projected)
	if err != nil {
		return modelDatasetProfile{}, err
	}
	projected.ProjectionDigest = digest

	canonical, err := canon.CanonicalJSON(projected)
	if err != nil {
		return modelDatasetProfile{}, &Error{code: CodeInvalid}
	}
	if len(canonical) == 0 || len(canonical) > modelDatasetProfileMaxBytes {
		return modelDatasetProfile{}, &Error{code: CodeInvalid}
	}
	return projected, nil
}

// projectModelDatasetProfileFields joins every approved field with its
// business semantics by logical token, sorts by token, and detaches aliases and
// allowed operators into non-nil slices.
func projectModelDatasetProfileFields(
	profile analytic.DatasetProfile,
	semantics analytic.ProfileSemanticsInput,
) ([]modelDatasetProfileField, error) {
	byToken := make(map[string]analytic.FieldSemanticsInput, len(semantics.Fields))
	for _, field := range semantics.Fields {
		if _, exists := byToken[field.Token]; exists {
			return nil, &Error{code: CodeInvalid}
		}
		byToken[field.Token] = field
	}

	specs := profile.Fields()
	projectedFields := make([]modelDatasetProfileField, 0, len(specs))
	for _, spec := range specs {
		values := spec.Values()
		field, ok := byToken[values.Token]
		if !ok {
			return nil, &Error{code: CodeInvalid}
		}
		operators := make([]string, 0, len(values.AllowedOps))
		for _, operator := range values.AllowedOps {
			operators = append(operators, string(operator))
		}
		aliases := append([]string{}, field.Aliases...)
		allowedValues := append([]string{}, values.AllowedValues...)
		projectedFields = append(projectedFields, modelDatasetProfileField{
			Token:            values.Token,
			Label:            field.Label,
			Description:      field.Description,
			NullMeaning:      field.NullMeaning,
			Aliases:          aliases,
			LogicalType:      string(values.LogicalType),
			Nullable:         values.Nullable,
			Filterable:       values.Filterable,
			Groupable:        values.Groupable,
			Sortable:         values.Sortable,
			OutputAllowed:    values.OutputAllowed,
			AllowedOperators: operators,
			AllowedValues:    allowedValues,
		})
	}
	sort.Slice(projectedFields, func(left, right int) bool {
		return projectedFields[left].Token < projectedFields[right].Token
	})
	return projectedFields, nil
}

// projectModelDatasetProfileMeasures joins every approved measure with its
// business semantics by ID, sorts by ID, and detaches aliases into a non-nil
// slice.
func projectModelDatasetProfileMeasures(
	profile analytic.DatasetProfile,
	semantics analytic.ProfileSemanticsInput,
) ([]modelDatasetProfileMeasure, error) {
	byID := make(map[string]analytic.MeasureSemanticsInput, len(semantics.Measures))
	for _, measure := range semantics.Measures {
		if _, exists := byID[measure.ID]; exists {
			return nil, &Error{code: CodeInvalid}
		}
		byID[measure.ID] = measure
	}

	specs := profile.Measures()
	projectedMeasures := make([]modelDatasetProfileMeasure, 0, len(specs))
	for _, spec := range specs {
		values := spec.Values()
		measure, ok := byID[values.ID]
		if !ok {
			return nil, &Error{code: CodeInvalid}
		}
		aliases := append([]string{}, measure.Aliases...)
		projectedMeasures = append(projectedMeasures, modelDatasetProfileMeasure{
			ID:          values.ID,
			Label:       measure.Label,
			Description: measure.Description,
			Aliases:     aliases,
			Reducer:     string(values.Reducer),
			Unit:        values.Unit,
			NullPolicy:  string(values.NullPolicy),
		})
	}
	sort.Slice(projectedMeasures, func(left, right int) bool {
		return projectedMeasures[left].ID < projectedMeasures[right].ID
	})
	return projectedMeasures, nil
}

// modelDatasetProfileDigest returns the deterministic SHA-256 digest of the
// projection over an explicit payload that omits projection_digest itself.
func modelDatasetProfileDigest(projected modelDatasetProfile) (string, error) {
	payload := struct {
		SchemaVersion          string                       `json:"schema_version"`
		Capability             string                       `json:"capability"`
		DatasetID              string                       `json:"dataset_id"`
		ProfileVersion         int64                        `json:"profile_version"`
		ProfileHash            string                       `json:"profile_hash"`
		DatasetLabel           string                       `json:"dataset_label"`
		DatasetDescription     string                       `json:"dataset_description"`
		GrainDescription       string                       `json:"grain_description"`
		Fields                 []modelDatasetProfileField   `json:"fields"`
		Measures               []modelDatasetProfileMeasure `json:"measures"`
		Time                   modelDatasetProfileTime      `json:"time"`
		DeclaredCoveragePolicy string                       `json:"declared_coverage_policy"`
		Limits                 modelDatasetProfileLimits    `json:"limits"`
	}{
		SchemaVersion:          projected.SchemaVersion,
		Capability:             projected.Capability,
		DatasetID:              projected.DatasetID,
		ProfileVersion:         projected.ProfileVersion,
		ProfileHash:            projected.ProfileHash,
		DatasetLabel:           projected.DatasetLabel,
		DatasetDescription:     projected.DatasetDescription,
		GrainDescription:       projected.GrainDescription,
		Fields:                 projected.Fields,
		Measures:               projected.Measures,
		Time:                   projected.Time,
		DeclaredCoveragePolicy: projected.DeclaredCoveragePolicy,
		Limits:                 projected.Limits,
	}

	canonical, err := canon.CanonicalJSON(payload)
	if err != nil {
		return "", &Error{code: CodeInvalid}
	}
	if len(canonical) == 0 {
		return "", &Error{code: CodeInvalid}
	}
	return canon.Hash(canonical), nil
}
