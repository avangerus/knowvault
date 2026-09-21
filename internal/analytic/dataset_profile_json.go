package analytic

import (
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/tzrules"
)

// maxDatasetProfileJSONBytes bounds one trusted, server-owned profile before
// decoding can allocate any nested representation.
const maxDatasetProfileJSONBytes = 256 << 10

// DecodeDatasetProfileJSON strictly decodes one server-owned dataset profile.
// The wire contract deliberately contains projection identity but has no place
// for an endpoint, credential, SQL text, or a caller-supplied profile hash.
func DecodeDatasetProfileJSON(raw []byte) (DatasetProfile, error) {
	if len(raw) == 0 || len(raw) > maxDatasetProfileJSONBytes {
		return DatasetProfile{}, invalidDatasetProfileJSON()
	}
	var wire datasetProfileJSON
	if err := jsonv2.Unmarshal(raw, &wire,
		jsonv2.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false)); err != nil {
		return DatasetProfile{}, invalidDatasetProfileJSON()
	}
	profile, err := wire.profile()
	if err != nil {
		return DatasetProfile{}, invalidDatasetProfileJSON()
	}
	return profile, nil
}

type datasetProfileJSON struct {
	SchemaVersion *string                      `json:"schema_version"`
	Key           *datasetProfileKeyJSON       `json:"key"`
	Mode          *ExecutionMode               `json:"mode"`
	Source        *datasetProfileSourceJSON    `json:"source"`
	Fields        *[]datasetProfileFieldJSON   `json:"fields"`
	Measures      *[]datasetProfileMeasureJSON `json:"measures"`
	Semantics     *datasetProfileSemanticsJSON `json:"semantics"`
	Grain         *datasetProfileGrainJSON     `json:"grain"`
	Time          *datasetProfileTimeJSON      `json:"time"`
	Coverage      *CoveragePolicy              `json:"coverage"`
	Limits        *datasetProfileLimitsJSON    `json:"limits"`
}

type datasetProfileKeyJSON struct {
	DatasetID *string `json:"dataset_id"`
	Version   *int64  `json:"version"`
}

type datasetProfileSourceJSON struct {
	SourceScopeID          *string       `json:"source_scope_id"`
	ConnectionID           *string       `json:"connection_id"`
	DatabaseIdentity       *string       `json:"database_identity"`
	ProjectionLineageID    *string       `json:"projection_lineage_id"`
	ProjectionRevision     *int64        `json:"projection_revision"`
	ProjectionContractHash *string       `json:"projection_contract_hash"`
	ExposedSchemaRevision  *int64        `json:"exposed_schema_revision"`
	ExposedSchemaHash      *string       `json:"exposed_schema_hash"`
	SchemaName             *string       `json:"schema_name"`
	RelationName           *string       `json:"relation_name"`
	RelationKind           *RelationKind `json:"relation_kind"`
}

type datasetProfileFieldJSON struct {
	Token         *string              `json:"token"`
	SourceOrdinal *int                 `json:"source_ordinal"`
	PhysicalName  *string              `json:"physical_name"`
	LogicalType   *ScalarType          `json:"logical_type"`
	PhysicalType  *PhysicalType        `json:"physical_type"`
	Nullable      *bool                `json:"nullable"`
	Filterable    *bool                `json:"filterable"`
	Groupable     *bool                `json:"groupable"`
	Sortable      *bool                `json:"sortable"`
	OutputAllowed *bool                `json:"output_allowed"`
	AllowedOps    *[]PredicateOperator `json:"allowed_ops"`
}

type datasetProfileMeasureJSON struct {
	ID               *string      `json:"id"`
	Reducer          *Reducer     `json:"reducer"`
	DistinctField    *string      `json:"distinct_field"`
	NumeratorField   *string      `json:"numerator_field"`
	DenominatorField *string      `json:"denominator_field"`
	Unit             *string      `json:"unit"`
	NullPolicy       *NullPolicy  `json:"null_policy"`
	Eligibility      *Eligibility `json:"eligibility"`
}

type datasetProfileSemanticsJSON struct {
	DatasetLabel       *string                               `json:"dataset_label"`
	DatasetDescription *string                               `json:"dataset_description"`
	Fields             *[]datasetProfileFieldSemanticsJSON   `json:"fields"`
	Measures           *[]datasetProfileMeasureSemanticsJSON `json:"measures"`
}

type datasetProfileFieldSemanticsJSON struct {
	Token       *string   `json:"token"`
	Label       *string   `json:"label"`
	Description *string   `json:"description"`
	NullMeaning *string   `json:"null_meaning"`
	Aliases     *[]string `json:"aliases"`
}

type datasetProfileMeasureSemanticsJSON struct {
	ID          *string   `json:"id"`
	Label       *string   `json:"label"`
	Description *string   `json:"description"`
	Aliases     *[]string `json:"aliases"`
}

type datasetProfileGrainJSON struct {
	Description     *string          `json:"description"`
	KeyFields       *[]string        `json:"key_fields"`
	DuplicatePolicy *DuplicatePolicy `json:"duplicate_policy"`
}

type datasetProfileTimeJSON struct {
	Kind                      *TimeKind `json:"kind"`
	FieldToken                *string   `json:"field_token"`
	ReportingTimezone         *string   `json:"reporting_timezone"`
	SourceTimezone            *string   `json:"source_timezone"`
	Calendar                  *Calendar `json:"calendar"`
	TimezoneRulesBundleSHA256 *string   `json:"timezone_rules_bundle_sha256"`
}

type datasetProfileLimitsJSON struct {
	MaxInputRows       *int64 `json:"max_input_rows"`
	MaxOutputGroups    *int   `json:"max_output_groups"`
	MaxPeriodDays      *int   `json:"max_period_days"`
	MaxResultBytes     *int64 `json:"max_result_bytes"`
	StatementTimeoutMS *int64 `json:"statement_timeout_ms"`
}

func (wire datasetProfileJSON) profile() (DatasetProfile, error) {
	if wire.SchemaVersion == nil || *wire.SchemaVersion != datasetProfileSchemaVersion ||
		wire.Key == nil || wire.Mode == nil || !wire.Mode.Valid() || wire.Source == nil ||
		wire.Fields == nil || wire.Measures == nil || wire.Semantics == nil || wire.Grain == nil ||
		wire.Time == nil || wire.Coverage == nil || !wire.Coverage.Valid() || wire.Limits == nil {
		return DatasetProfile{}, invalidDatasetProfileJSON()
	}
	key, err := wire.Key.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	source, err := wire.Source.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	fields, err := datasetProfileJSONFields(*wire.Fields)
	if err != nil {
		return DatasetProfile{}, err
	}
	measures, err := datasetProfileJSONMeasures(*wire.Measures)
	if err != nil {
		return DatasetProfile{}, err
	}
	semantics, err := wire.Semantics.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	grain, err := wire.Grain.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	timePolicy, err := wire.Time.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	limits, err := wire.Limits.value()
	if err != nil {
		return DatasetProfile{}, err
	}
	return NewDatasetProfile(DatasetProfileSpec{
		Key: key, Mode: *wire.Mode, Source: source, Fields: fields, Measures: measures,
		Semantics: semantics, Grain: grain, Time: timePolicy, Coverage: *wire.Coverage, Limits: limits,
	})
}

func (wire datasetProfileKeyJSON) value() (ProfileKey, error) {
	if wire.DatasetID == nil || wire.Version == nil {
		return ProfileKey{}, invalidDatasetProfileJSON()
	}
	return NewProfileKey(*wire.DatasetID, *wire.Version)
}

func (wire datasetProfileSourceJSON) value() (SourceProjectionSpec, error) {
	if wire.SourceScopeID == nil || wire.ConnectionID == nil || wire.DatabaseIdentity == nil ||
		wire.ProjectionLineageID == nil || wire.ProjectionRevision == nil || wire.ProjectionContractHash == nil ||
		wire.ExposedSchemaRevision == nil || wire.ExposedSchemaHash == nil || wire.SchemaName == nil ||
		wire.RelationName == nil || wire.RelationKind == nil || !wire.RelationKind.Valid() {
		return SourceProjectionSpec{}, invalidDatasetProfileJSON()
	}
	return NewSourceProjectionSpec(SourceProjectionInput{
		SourceScopeID: *wire.SourceScopeID, ConnectionID: *wire.ConnectionID,
		DatabaseIdentity: *wire.DatabaseIdentity, ProjectionLineageID: *wire.ProjectionLineageID,
		ProjectionRevision: *wire.ProjectionRevision, ProjectionContractHash: *wire.ProjectionContractHash,
		ExposedSchemaRevision: *wire.ExposedSchemaRevision, ExposedSchemaHash: *wire.ExposedSchemaHash,
		SchemaName: *wire.SchemaName, RelationName: *wire.RelationName, RelationKind: *wire.RelationKind,
	})
}

func datasetProfileJSONFields(wires []datasetProfileFieldJSON) ([]FieldSpec, error) {
	values := make([]FieldSpec, len(wires))
	for index, wire := range wires {
		if wire.Token == nil || wire.SourceOrdinal == nil || wire.PhysicalName == nil ||
			wire.LogicalType == nil || !wire.LogicalType.Valid() || wire.PhysicalType == nil || !wire.PhysicalType.Valid() ||
			wire.Nullable == nil || wire.Filterable == nil || wire.Groupable == nil || wire.Sortable == nil ||
			wire.OutputAllowed == nil || wire.AllowedOps == nil {
			return nil, invalidDatasetProfileJSON()
		}
		value, err := NewFieldSpec(FieldSpecInput{
			Token: *wire.Token, SourceOrdinal: *wire.SourceOrdinal, PhysicalName: *wire.PhysicalName,
			LogicalType: *wire.LogicalType, PhysicalType: *wire.PhysicalType,
			Nullable: *wire.Nullable, Filterable: *wire.Filterable, Groupable: *wire.Groupable,
			Sortable: *wire.Sortable, OutputAllowed: *wire.OutputAllowed,
			AllowedOps: append([]PredicateOperator(nil), (*wire.AllowedOps)...),
		})
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func datasetProfileJSONMeasures(wires []datasetProfileMeasureJSON) ([]MeasureSpec, error) {
	values := make([]MeasureSpec, len(wires))
	for index, wire := range wires {
		if wire.ID == nil || wire.Reducer == nil || !wire.Reducer.Valid() || wire.DistinctField == nil ||
			wire.NumeratorField == nil || wire.DenominatorField == nil || wire.Unit == nil ||
			wire.NullPolicy == nil || !wire.NullPolicy.Valid() || wire.Eligibility == nil || !wire.Eligibility.Valid() {
			return nil, invalidDatasetProfileJSON()
		}
		value, err := NewMeasureSpec(MeasureSpecInput{
			ID: *wire.ID, Reducer: *wire.Reducer, DistinctField: *wire.DistinctField,
			NumeratorField: *wire.NumeratorField, DenominatorField: *wire.DenominatorField,
			Unit: *wire.Unit, NullPolicy: *wire.NullPolicy, Eligibility: *wire.Eligibility,
		})
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func (wire datasetProfileSemanticsJSON) value() (ProfileSemantics, error) {
	if wire.DatasetLabel == nil || wire.DatasetDescription == nil || wire.Fields == nil || wire.Measures == nil {
		return ProfileSemantics{}, invalidDatasetProfileJSON()
	}
	fields := make([]FieldSemanticsInput, len(*wire.Fields))
	for index, item := range *wire.Fields {
		if item.Token == nil || item.Label == nil || item.Description == nil || item.NullMeaning == nil || item.Aliases == nil {
			return ProfileSemantics{}, invalidDatasetProfileJSON()
		}
		fields[index] = FieldSemanticsInput{
			Token: *item.Token, Label: *item.Label, Description: *item.Description,
			NullMeaning: *item.NullMeaning, Aliases: append([]string(nil), (*item.Aliases)...),
		}
	}
	measures := make([]MeasureSemanticsInput, len(*wire.Measures))
	for index, item := range *wire.Measures {
		if item.ID == nil || item.Label == nil || item.Description == nil || item.Aliases == nil {
			return ProfileSemantics{}, invalidDatasetProfileJSON()
		}
		measures[index] = MeasureSemanticsInput{
			ID: *item.ID, Label: *item.Label, Description: *item.Description,
			Aliases: append([]string(nil), (*item.Aliases)...),
		}
	}
	return NewProfileSemantics(ProfileSemanticsInput{
		DatasetLabel: *wire.DatasetLabel, DatasetDescription: *wire.DatasetDescription,
		Fields: fields, Measures: measures,
	})
}

func (wire datasetProfileGrainJSON) value() (DatasetGrain, error) {
	if wire.Description == nil || wire.KeyFields == nil || wire.DuplicatePolicy == nil || !wire.DuplicatePolicy.Valid() {
		return DatasetGrain{}, invalidDatasetProfileJSON()
	}
	return NewDatasetGrain(DatasetGrainInput{
		Description: *wire.Description, KeyFields: append([]string(nil), (*wire.KeyFields)...),
		DuplicatePolicy: *wire.DuplicatePolicy,
	})
}

func (wire datasetProfileTimeJSON) value() (TimePolicy, error) {
	if wire.Kind == nil || !wire.Kind.Valid() || wire.FieldToken == nil || wire.ReportingTimezone == nil ||
		wire.SourceTimezone == nil || wire.Calendar == nil || wire.TimezoneRulesBundleSHA256 == nil ||
		*wire.TimezoneRulesBundleSHA256 != tzrules.BundleSHA256 {
		return TimePolicy{}, invalidDatasetProfileJSON()
	}
	return NewTimePolicy(TimePolicyInput{
		Kind: *wire.Kind, FieldToken: *wire.FieldToken, ReportingTimezone: *wire.ReportingTimezone,
		SourceTimezone: *wire.SourceTimezone, Calendar: *wire.Calendar,
	})
}

func (wire datasetProfileLimitsJSON) value() (ProfileLimits, error) {
	if wire.MaxInputRows == nil || wire.MaxOutputGroups == nil || wire.MaxPeriodDays == nil ||
		wire.MaxResultBytes == nil || wire.StatementTimeoutMS == nil {
		return ProfileLimits{}, invalidDatasetProfileJSON()
	}
	return NewProfileLimits(ProfileLimitsInput{
		MaxInputRows: *wire.MaxInputRows, MaxOutputGroups: *wire.MaxOutputGroups,
		MaxPeriodDays: *wire.MaxPeriodDays, MaxResultBytes: *wire.MaxResultBytes,
		StatementTimeoutMS: *wire.StatementTimeoutMS,
	})
}

func invalidDatasetProfileJSON() error { return &Error{code: CodeInvalidRequest} }
