package analytic

import (
	"errors"
	"strings"
	"testing"
)

func TestDatasetProfileSpecNormalizesAndDetaches(t *testing.T) {
	spec := validDatasetProfileSpec(t)
	normalized, err := normalizeDatasetProfileSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if got := normalized.fields[0].Values().SourceOrdinal; got != 1 ||
		normalized.fields[len(normalized.fields)-1].Values().SourceOrdinal != 5 {
		t.Fatalf("fields not ordered: first=%d", got)
	}
	if normalized.measures[0].Values().ID != "amount" || normalized.measures[1].Values().ID != "rows" {
		t.Fatalf("measures not ordered: %q, %q", normalized.measures[0].Values().ID, normalized.measures[1].Values().ID)
	}
	originalField := normalized.fields[0]
	originalMeasure := normalized.measures[0]
	spec.Fields[0], spec.Measures[0] = spec.Fields[1], spec.Measures[1]
	if normalized.fields[0] != originalField || normalized.measures[0] != originalMeasure {
		t.Fatal("normalized slices alias caller slices")
	}
}

func TestDatasetProfileSpecRejectsFieldShapeFailures(t *testing.T) {
	cases := map[string]func(*DatasetProfileSpec){
		"duplicate token": func(s *DatasetProfileSpec) {
			s.Fields = []FieldSpec{
				profileField(t, "same", "one", 1, ScalarText, true),
				profileField(t, "same", "two", 2, ScalarText, false),
			}
		},
		"duplicate physical": func(s *DatasetProfileSpec) {
			s.Fields = []FieldSpec{
				profileField(t, "one", "same", 1, ScalarText, true),
				profileField(t, "two", "same", 2, ScalarText, false),
			}
		},
		"duplicate ordinal": func(s *DatasetProfileSpec) {
			s.Fields = []FieldSpec{
				profileField(t, "one", "one", 1, ScalarText, true),
				profileField(t, "two", "two", 1, ScalarText, false),
			}
		},
		"ordinal gap": func(s *DatasetProfileSpec) {
			s.Fields = []FieldSpec{
				profileField(t, "one", "one", 1, ScalarText, true),
				profileField(t, "three", "three", 3, ScalarText, false),
			}
		},
		"ordinal starts at zero": func(s *DatasetProfileSpec) {
			field := profileField(t, "zero", "zero", 1, ScalarText, true)
			field.sourceOrdinal = 0
			s.Fields = []FieldSpec{field}
		},
		"no output": func(s *DatasetProfileSpec) {
			s.Fields = []FieldSpec{profileField(t, "hidden", "hidden", 1, ScalarText, false)}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			mutate(&spec)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
}

func TestDatasetProfileSpecRejectsMeasureFailures(t *testing.T) {
	cases := map[string]func(*DatasetProfileSpec){
		"duplicate id": func(s *DatasetProfileSpec) { s.Measures[1] = s.Measures[0] },
		"distinct missing": func(s *DatasetProfileSpec) {
			s.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "m", Reducer: ReducerCountDistinct, DistinctField: "absent", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
		},
		"sum missing": func(s *DatasetProfileSpec) {
			s.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "m", Reducer: ReducerSum, NumeratorField: "absent", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
		},
		"sum wrong type": func(s *DatasetProfileSpec) {
			s.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "m", Reducer: ReducerSum, NumeratorField: "object_id", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
		},
		"ratio missing": func(s *DatasetProfileSpec) {
			s.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "m", Reducer: ReducerRatioOfSums, NumeratorField: "amount", DenominatorField: "absent", Unit: "ratio", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
		},
		"ratio wrong type": func(s *DatasetProfileSpec) {
			s.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "m", Reducer: ReducerRatioOfSums, NumeratorField: "object_id", DenominatorField: "amount", Unit: "ratio", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			mutate(&spec)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
	valid := validDatasetProfileSpec(t)
	valid.Measures = []MeasureSpec{profileMeasure(t, MeasureSpecInput{ID: "distinct", Reducer: ReducerCountDistinct, DistinctField: "object_id", Unit: "items", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows})}
	semantics := valid.Semantics.Values()
	semantics.Measures = []MeasureSemanticsInput{{ID: "distinct", Label: "Distinct objects", Description: "Number of distinct objects"}}
	valid.Semantics = mustCanonicalSemantics(t, semantics)
	if _, err := normalizeDatasetProfileSpec(valid); err != nil {
		t.Fatalf("distinct over non-numeric field rejected: %v", err)
	}
}

func TestDatasetProfileSpecRejectsTimeFieldFailures(t *testing.T) {
	cases := []struct {
		name  string
		kind  TimeKind
		token string
	}{
		{"business missing", TimeBusinessDate, "absent"}, {"business wrong", TimeBusinessDate, "amount"},
		{"local missing", TimeLocalTimestamp, "absent"}, {"local wrong", TimeLocalTimestamp, "business_day"},
		{"zoned missing", TimeZonedTimestamp, "absent"}, {"zoned wrong", TimeZonedTimestamp, "local_at"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			spec.Time = profileTime(t, test.kind, test.token)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
	for kind, token := range map[TimeKind]string{
		TimeBusinessDate: "business_day", TimeLocalTimestamp: "local_at", TimeZonedTimestamp: "zoned_at",
	} {
		spec := validDatasetProfileSpec(t)
		spec.Time = profileTime(t, kind, token)
		if _, err := normalizeDatasetProfileSpec(spec); err != nil {
			t.Fatalf("valid %s time field rejected: %v", kind, err)
		}
	}
}

func TestDatasetProfileSpecRejectsInvalidNestedAndEmptyValues(t *testing.T) {
	cases := map[string]func(*DatasetProfileSpec){
		"key":            func(s *DatasetProfileSpec) { s.Key = ProfileKey{} },
		"mode":           func(s *DatasetProfileSpec) { s.Mode = "SNAPSHOT" },
		"source":         func(s *DatasetProfileSpec) { s.Source = SourceProjectionSpec{} },
		"field":          func(s *DatasetProfileSpec) { s.Fields = []FieldSpec{{}} },
		"measure":        func(s *DatasetProfileSpec) { s.Measures = []MeasureSpec{{}} },
		"time":           func(s *DatasetProfileSpec) { s.Time = TimePolicy{} },
		"coverage":       func(s *DatasetProfileSpec) { s.Coverage = "COMPLETE" },
		"limits":         func(s *DatasetProfileSpec) { s.Limits = ProfileLimits{} },
		"empty fields":   func(s *DatasetProfileSpec) { s.Fields = nil },
		"empty measures": func(s *DatasetProfileSpec) { s.Measures = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			spec := validDatasetProfileSpec(t)
			mutate(&spec)
			assertInvalidDatasetProfileSpec(t, spec)
		})
	}
}

func validDatasetProfileSpec(t *testing.T) DatasetProfileSpec {
	t.Helper()
	key, err := NewProfileKey("operations", 1)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSourceProjectionSpec(SourceProjectionInput{
		SourceScopeID: "gm", ConnectionID: "primary", DatabaseIdentity: "gm",
		ProjectionLineageID: "operations", ProjectionRevision: 1,
		ProjectionContractHash: "sha256:" + strings.Repeat("1", 64), ExposedSchemaRevision: 1,
		ExposedSchemaHash: "sha256:" + strings.Repeat("2", 64), SchemaName: "public",
		RelationName: "operations", RelationKind: RelationView,
	})
	if err != nil {
		t.Fatal(err)
	}
	timePolicy, _ := NewTimePolicy(TimePolicyInput{Kind: TimeNone})
	limits, _ := NewProfileLimits(ProfileLimitsInput{1000, 20, 31, 1048576, 5000})
	return DatasetProfileSpec{
		Key: key, Mode: ExecutionLive, Source: source,
		Fields: []FieldSpec{
			profileField(t, "zoned_at", "zoned_at", 5, ScalarTimestamptz, false),
			profileField(t, "object_id", "object_id", 1, ScalarText, true),
			profileField(t, "local_at", "local_at", 4, ScalarTimestamp, false),
			profileField(t, "amount", "amount", 2, ScalarNumeric, true),
			profileField(t, "business_day", "business_day", 3, ScalarDate, false),
		},
		Measures: []MeasureSpec{
			profileMeasure(t, MeasureSpecInput{ID: "rows", Reducer: ReducerCountRows, Unit: "rows", NullPolicy: NullNotApplicable, Eligibility: EligibilityAllRows}),
			profileMeasure(t, MeasureSpecInput{ID: "amount", Reducer: ReducerSum, NumeratorField: "amount", Unit: "units", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows}),
		},
		Time: timePolicy, Coverage: CoverageUnknown, Limits: limits,
		Semantics: profileSemantics(t), Grain: profileGrain(t),
	}
}

func profileSemantics(t *testing.T) ProfileSemantics {
	t.Helper()
	value, err := NewProfileSemantics(ProfileSemanticsInput{
		DatasetLabel:       "Operations",
		DatasetDescription: "Business operations records",
		Fields: []FieldSemanticsInput{
			{Token: "zoned_at", Label: "Zoned at", Description: "Zoned timestamp", NullMeaning: "Not recorded"},
			{Token: "object_id", Label: "Object id", Description: "Object identifier", NullMeaning: "Not assigned"},
			{Token: "local_at", Label: "Local at", Description: "Local timestamp", NullMeaning: "Not recorded"},
			{Token: "amount", Label: "Amount", Description: "Measured amount", NullMeaning: "Not measured"},
			{Token: "business_day", Label: "Business day", Description: "Business date", NullMeaning: "Not recorded"},
		},
		Measures: []MeasureSemanticsInput{
			{ID: "rows", Label: "Rows", Description: "Number of rows"},
			{ID: "amount", Label: "Amount", Description: "Sum of amount"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func profileGrain(t *testing.T) DatasetGrain {
	t.Helper()
	value, err := NewDatasetGrain(DatasetGrainInput{
		Description:     "One row per object per business day",
		KeyFields:       []string{"object_id", "business_day"},
		DuplicatePolicy: DuplicateReject,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func profileField(t *testing.T, token, physical string, ordinal int, kind ScalarType, output bool) FieldSpec {
	t.Helper()
	physicalTypes := map[ScalarType]PhysicalType{
		ScalarText: PhysicalPGText, ScalarInt: PhysicalPGInt8, ScalarNumeric: PhysicalPGNumeric,
		ScalarDate: PhysicalPGDate, ScalarTimestamp: PhysicalPGTimestamp, ScalarTimestamptz: PhysicalPGTimestamptz,
	}
	value, err := NewFieldSpec(FieldSpecInput{Token: token, SourceOrdinal: ordinal, PhysicalName: physical, LogicalType: kind, PhysicalType: physicalTypes[kind], OutputAllowed: output})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func profileMeasure(t *testing.T, input MeasureSpecInput) MeasureSpec {
	t.Helper()
	value, err := NewMeasureSpec(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func profileTime(t *testing.T, kind TimeKind, token string) TimePolicy {
	t.Helper()
	input := TimePolicyInput{Kind: kind, FieldToken: token, ReportingTimezone: "UTC", Calendar: CalendarGregorian}
	if kind == TimeLocalTimestamp {
		input.SourceTimezone = "UTC"
	}
	value, err := NewTimePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertInvalidDatasetProfileSpec(t *testing.T, spec DatasetProfileSpec) {
	t.Helper()
	_, err := normalizeDatasetProfileSpec(spec)
	if err == nil || CodeOf(err) != CodeInvalidRequest || err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid profile accepted or leaked detail: %v", err)
	}
}
