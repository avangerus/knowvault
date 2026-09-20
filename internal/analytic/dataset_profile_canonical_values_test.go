package analytic

import "testing"

func TestDatasetProfileCanonicalConstrainedValuesChangeHash(t *testing.T) {
	tests := map[string]func(*testing.T) (DatasetProfileSpec, DatasetProfileSpec){
		"allowed operators":  canonicalAllowedOperatorsPair,
		"distinct field":     canonicalDistinctFieldPair,
		"denominator field":  canonicalDenominatorFieldPair,
		"reporting timezone": canonicalReportingTimezonePair,
		"source timezone":    canonicalSourceTimezonePair,
	}
	for name, pair := range tests {
		t.Run(name, func(t *testing.T) {
			left, right := pair(t)
			_, leftHash := canonicalProfileForTest(t, left)
			_, rightHash := canonicalProfileForTest(t, right)
			if leftHash == rightHash {
				t.Fatal("constrained canonical value did not change hash")
			}
		})
	}
}

func canonicalAllowedOperatorsPair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	left, right := canonicalValueProfilePair(t)
	mutateField(t, &left, "amount", func(value *FieldSpecInput) {
		value.Filterable = true
		value.AllowedOps = []PredicateOperator{PredicateEQ}
	})
	mutateField(t, &right, "amount", func(value *FieldSpecInput) {
		value.Filterable = true
		value.AllowedOps = []PredicateOperator{PredicateEQ, PredicateIN}
	})
	return left, right
}

func canonicalDistinctFieldPair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	left, right := canonicalValueProfilePair(t)
	measure := MeasureSpecInput{
		ID: "objects", Reducer: ReducerCountDistinct, DistinctField: "object_id",
		Unit: "objects", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows,
	}
	left.Measures = append(left.Measures, profileMeasure(t, measure))
	measure.DistinctField = "business_day"
	right.Measures = append(right.Measures, profileMeasure(t, measure))
	return left, right
}

func canonicalDenominatorFieldPair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	left, right := canonicalValueProfilePair(t)
	for _, spec := range []*DatasetProfileSpec{&left, &right} {
		spec.Fields = append(spec.Fields, profileField(t, "amount_net", "amount_net", 6, ScalarNumeric, true))
	}
	measure := MeasureSpecInput{
		ID: "amount_ratio", Reducer: ReducerRatioOfSums,
		NumeratorField: "amount", DenominatorField: "amount",
		Unit: "ratio", NullPolicy: NullExcludeAndReport, Eligibility: EligibilityAllRows,
	}
	left.Measures = append(left.Measures, profileMeasure(t, measure))
	measure.DenominatorField = "amount_net"
	right.Measures = append(right.Measures, profileMeasure(t, measure))
	return left, right
}

func canonicalReportingTimezonePair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	left, right := canonicalValueProfilePair(t)
	left.Time = profileTime(t, TimeBusinessDate, "business_day")
	right.Time = mustCanonicalTimePolicy(t, TimePolicyInput{
		Kind: TimeBusinessDate, FieldToken: "business_day",
		ReportingTimezone: "Europe/Moscow", Calendar: CalendarGregorian,
	})
	return left, right
}

func canonicalSourceTimezonePair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	left, right := canonicalValueProfilePair(t)
	left.Time = profileTime(t, TimeLocalTimestamp, "local_at")
	right.Time = mustCanonicalTimePolicy(t, TimePolicyInput{
		Kind: TimeLocalTimestamp, FieldToken: "local_at",
		ReportingTimezone: "UTC", SourceTimezone: "Europe/Moscow", Calendar: CalendarGregorian,
	})
	return left, right
}

func canonicalValueProfilePair(t *testing.T) (DatasetProfileSpec, DatasetProfileSpec) {
	t.Helper()
	return validDatasetProfileSpec(t), validDatasetProfileSpec(t)
}

func mustCanonicalTimePolicy(t *testing.T, input TimePolicyInput) TimePolicy {
	t.Helper()
	value, err := NewTimePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
