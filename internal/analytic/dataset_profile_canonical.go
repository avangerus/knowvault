package analytic

import (
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/tzrules"
)

const datasetProfileSchemaVersion = "knowvault-dataset-profile-v2"

type canonicalProfileField struct {
	Token         string              `json:"token"`
	SourceOrdinal int                 `json:"source_ordinal"`
	PhysicalName  string              `json:"physical_name"`
	LogicalType   ScalarType          `json:"logical_type"`
	PhysicalType  PhysicalType        `json:"physical_type"`
	Nullable      bool                `json:"nullable"`
	Filterable    bool                `json:"filterable"`
	Groupable     bool                `json:"groupable"`
	Sortable      bool                `json:"sortable"`
	OutputAllowed bool                `json:"output_allowed"`
	AllowedOps    []PredicateOperator `json:"allowed_ops"`
	AllowedValues []string            `json:"allowed_values,omitempty"`
}

type canonicalProfileMeasure struct {
	ID               string      `json:"id"`
	Reducer          Reducer     `json:"reducer"`
	DistinctField    string      `json:"distinct_field"`
	NumeratorField   string      `json:"numerator_field"`
	DenominatorField string      `json:"denominator_field"`
	Unit             string      `json:"unit"`
	NullPolicy       NullPolicy  `json:"null_policy"`
	Eligibility      Eligibility `json:"eligibility"`
}

type canonicalProfileFieldSemantics struct {
	Token       string   `json:"token"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	NullMeaning string   `json:"null_meaning"`
	Aliases     []string `json:"aliases"`
}

type canonicalProfileMeasureSemantics struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases"`
}

type canonicalProfileSemantics struct {
	DatasetLabel       string                             `json:"dataset_label"`
	DatasetDescription string                             `json:"dataset_description"`
	Fields             []canonicalProfileFieldSemantics   `json:"fields"`
	Measures           []canonicalProfileMeasureSemantics `json:"measures"`
}

type canonicalProfileGrain struct {
	Description     string          `json:"description"`
	KeyFields       []string        `json:"key_fields"`
	DuplicatePolicy DuplicatePolicy `json:"duplicate_policy"`
}

func cloneCanonicalStrings(values []string) []string {
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func canonicalProfileSemanticsValue(value ProfileSemantics) canonicalProfileSemantics {
	input := value.Values()
	fields := make([]canonicalProfileFieldSemantics, len(input.Fields))
	for index, field := range input.Fields {
		fields[index] = canonicalProfileFieldSemantics{
			Token: field.Token, Label: field.Label, Description: field.Description,
			NullMeaning: field.NullMeaning, Aliases: cloneCanonicalStrings(field.Aliases),
		}
	}
	measures := make([]canonicalProfileMeasureSemantics, len(input.Measures))
	for index, measure := range input.Measures {
		measures[index] = canonicalProfileMeasureSemantics{
			ID: measure.ID, Label: measure.Label, Description: measure.Description,
			Aliases: cloneCanonicalStrings(measure.Aliases),
		}
	}
	return canonicalProfileSemantics{
		DatasetLabel: input.DatasetLabel, DatasetDescription: input.DatasetDescription,
		Fields: fields, Measures: measures,
	}
}

func canonicalProfileGrainValue(value DatasetGrain) canonicalProfileGrain {
	input := value.Values()
	return canonicalProfileGrain{
		Description: input.Description, KeyFields: cloneCanonicalStrings(input.KeyFields),
		DuplicatePolicy: input.DuplicatePolicy,
	}
}

// canonicalDatasetProfile projects one already-normalized profile into the
// complete, versioned identity hashed by persistence and execution layers.
func canonicalDatasetProfile(value normalizedDatasetProfileSpec) ([]byte, string, error) {
	fields := make([]canonicalProfileField, len(value.fields))
	for index, field := range value.fields {
		item := field.Values()
		allowed := make([]PredicateOperator, len(item.AllowedOps))
		copy(allowed, item.AllowedOps)
		allowedValues := cloneCanonicalStrings(item.AllowedValues)
		fields[index] = canonicalProfileField{
			Token: item.Token, SourceOrdinal: item.SourceOrdinal, PhysicalName: item.PhysicalName,
			LogicalType: item.LogicalType, PhysicalType: item.PhysicalType,
			Nullable: item.Nullable, Filterable: item.Filterable, Groupable: item.Groupable,
			Sortable: item.Sortable, OutputAllowed: item.OutputAllowed, AllowedOps: allowed,
			AllowedValues: allowedValues,
		}
	}
	measures := make([]canonicalProfileMeasure, len(value.measures))
	for index, measure := range value.measures {
		item := measure.Values()
		measures[index] = canonicalProfileMeasure{
			ID: item.ID, Reducer: item.Reducer, DistinctField: item.DistinctField,
			NumeratorField: item.NumeratorField, DenominatorField: item.DenominatorField,
			Unit: item.Unit, NullPolicy: item.NullPolicy, Eligibility: item.Eligibility,
		}
	}
	source := value.source.Values()
	timePolicy := value.time.Values()
	limits := value.limits.Values()
	projection := struct {
		SchemaVersion string `json:"schema_version"`
		Key           struct {
			DatasetID string `json:"dataset_id"`
			Version   int64  `json:"version"`
		} `json:"key"`
		Mode   ExecutionMode `json:"mode"`
		Source struct {
			SourceScopeID          string       `json:"source_scope_id"`
			ConnectionID           string       `json:"connection_id"`
			DatabaseIdentity       string       `json:"database_identity"`
			ProjectionLineageID    string       `json:"projection_lineage_id"`
			ProjectionRevision     int64        `json:"projection_revision"`
			ProjectionContractHash string       `json:"projection_contract_hash"`
			ExposedSchemaRevision  int64        `json:"exposed_schema_revision"`
			ExposedSchemaHash      string       `json:"exposed_schema_hash"`
			SchemaName             string       `json:"schema_name"`
			RelationName           string       `json:"relation_name"`
			RelationKind           RelationKind `json:"relation_kind"`
		} `json:"source"`
		Fields    []canonicalProfileField   `json:"fields"`
		Measures  []canonicalProfileMeasure `json:"measures"`
		Semantics canonicalProfileSemantics `json:"semantics"`
		Grain     canonicalProfileGrain     `json:"grain"`
		Time      struct {
			Kind                      TimeKind `json:"kind"`
			FieldToken                string   `json:"field_token"`
			ReportingTimezone         string   `json:"reporting_timezone"`
			SourceTimezone            string   `json:"source_timezone"`
			Calendar                  Calendar `json:"calendar"`
			TimezoneRulesBundleSHA256 string   `json:"timezone_rules_bundle_sha256"`
		} `json:"time"`
		Coverage CoveragePolicy `json:"coverage"`
		Limits   struct {
			MaxInputRows       int64 `json:"max_input_rows"`
			MaxOutputGroups    int   `json:"max_output_groups"`
			MaxPeriodDays      int   `json:"max_period_days"`
			MaxResultBytes     int64 `json:"max_result_bytes"`
			StatementTimeoutMS int64 `json:"statement_timeout_ms"`
		} `json:"limits"`
	}{SchemaVersion: datasetProfileSchemaVersion, Mode: value.mode, Fields: fields,
		Measures: measures, Semantics: canonicalProfileSemanticsValue(value.semantics),
		Grain: canonicalProfileGrainValue(value.grain), Coverage: value.coverage}
	projection.Key.DatasetID, projection.Key.Version = value.key.DatasetID(), value.key.Version()
	projection.Source.SourceScopeID, projection.Source.ConnectionID = source.SourceScopeID, source.ConnectionID
	projection.Source.DatabaseIdentity, projection.Source.ProjectionLineageID = source.DatabaseIdentity, source.ProjectionLineageID
	projection.Source.ProjectionRevision, projection.Source.ProjectionContractHash = source.ProjectionRevision, source.ProjectionContractHash
	projection.Source.ExposedSchemaRevision, projection.Source.ExposedSchemaHash = source.ExposedSchemaRevision, source.ExposedSchemaHash
	projection.Source.SchemaName, projection.Source.RelationName, projection.Source.RelationKind = source.SchemaName, source.RelationName, source.RelationKind
	projection.Time.Kind, projection.Time.FieldToken = timePolicy.Kind, timePolicy.FieldToken
	projection.Time.ReportingTimezone, projection.Time.SourceTimezone, projection.Time.Calendar = timePolicy.ReportingTimezone, timePolicy.SourceTimezone, timePolicy.Calendar
	projection.Time.TimezoneRulesBundleSHA256 = tzrules.BundleSHA256
	projection.Limits.MaxInputRows, projection.Limits.MaxOutputGroups = limits.MaxInputRows, limits.MaxOutputGroups
	projection.Limits.MaxPeriodDays, projection.Limits.MaxResultBytes = limits.MaxPeriodDays, limits.MaxResultBytes
	projection.Limits.StatementTimeoutMS = limits.StatementTimeoutMS
	canonical, err := canon.CanonicalJSON(projection)
	if err != nil {
		return nil, "", &Error{code: CodeInvalidRequest}
	}
	return canonical, canon.Hash(canonical), nil
}
