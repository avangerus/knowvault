package question

import (
	"bytes"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analyticsource"
)

// TestAnalyticScalarObservationRoundTripsInStructuredAnswer proves one exact
// scalar observation survives the existing JSON v2 codec inside the private
// structured answer: it decodes with unknown members rejected, still passes
// valid(), equals the constructed value field for field, and re-marshals to the
// same bytes. The JSON also carries none of the private members the observation
// must never project.
func TestAnalyticScalarObservationRoundTripsInStructuredAnswer(t *testing.T) {
	observation := analyticScalarObservationFixture(t)

	structured := structuredAnswer{
		SchemaVersion:  "extractive-answer-v1",
		QuestionRunID:  "run_scalar_observation",
		AnalyticScalar: &observation,
	}
	first, err := jsonv2.Marshal(structured)
	if err != nil {
		t.Fatalf("marshal structured answer: %v", err)
	}
	assertAnalyticScalarObservationWithholdsPrivateFields(t, first)

	var decoded structuredAnswer
	if err := jsonv2.Unmarshal(first, &decoded, jsonv2.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("unmarshal structured answer: %v", err)
	}
	if decoded.AnalyticScalar == nil {
		t.Fatalf("decoded analytic scalar observation is nil")
	}
	if !decoded.AnalyticScalar.valid() {
		t.Fatalf("decoded analytic scalar observation is invalid: %+v", decoded.AnalyticScalar)
	}
	if *decoded.AnalyticScalar != observation {
		t.Fatalf("decoded observation = %+v want %+v", *decoded.AnalyticScalar, observation)
	}
	second, err := jsonv2.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal decoded structured answer: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("re-marshaled JSON differs:\n first: %s\nsecond: %s", first, second)
	}
}

// TestMarshalStructuredAnswerCarriesAnalyticScalarPair proves the persistence
// marshal path attaches the exact validated scalar and its opaque dependency
// together, and that the strict run-aware decoder returns both the projection
// and the retained private pair. The encoded observation JSON is checked with
// the same disclosure assertion as the observation itself.
func TestMarshalStructuredAnswerCarriesAnalyticScalarPair(t *testing.T) {
	pair := analyticScalarPairFixture(t)

	raw, err := marshalStructuredAnswerWithAnalyticScalarPair(analyticScalarPairRunID, "hash_scalar_persist", []Citation{}, nil, nil, &pair)
	if err != nil {
		t.Fatalf("marshal structured answer with analytic scalar pair: %v", err)
	}

	decoded, err := decodeStructuredAnswer(analyticScalarPairRunID, raw)
	if err != nil {
		t.Fatalf("decode structured answer: %v", err)
	}
	if decoded.AnalyticScalar == nil {
		t.Fatalf("decoded analytic scalar observation is nil")
	}
	if *decoded.AnalyticScalar != pair.observation {
		t.Fatalf("decoded observation = %+v want %+v", *decoded.AnalyticScalar, pair.observation)
	}
	if decoded.AnalyticScalar.Value != "3888" || decoded.AnalyticScalar.ContributingRows != 407 || !decoded.AnalyticScalar.CoverageComplete {
		t.Fatalf("decoded observation = %+v, want value 3888 with 407 complete rows", decoded.AnalyticScalar)
	}
	if len(decoded.AnalyticScalarDependency) == 0 {
		t.Fatalf("decoded structured answer carries no encoded dependency")
	}
	if decoded.analyticScalarPair == nil {
		t.Fatalf("decoded structured answer retains no private pair")
	}
	if decoded.analyticScalarPair.dependency != pair.dependency {
		t.Fatalf("decoded dependency = %+v want %+v", decoded.analyticScalarPair.dependency, pair.dependency)
	}
	observationJSON, err := jsonv2.Marshal(decoded.AnalyticScalar)
	if err != nil {
		t.Fatalf("marshal decoded observation: %v", err)
	}
	assertAnalyticScalarObservationWithholdsPrivateFields(t, observationJSON)
}

// TestAnalyticScalarObservationRefusesInvalidInput proves the constructor
// applies each non-period field family exactly once and refuses with the exact
// zero observation plus the content-free CodeInvalid error. The observation's
// own JSON is also checked to carry no private source members.
func TestAnalyticScalarObservationRefusesInvalidInput(t *testing.T) {
	raw, err := jsonv2.Marshal(analyticScalarObservationFixture(t))
	if err != nil {
		t.Fatalf("marshal observation fixture: %v", err)
	}
	assertAnalyticScalarObservationWithholdsPrivateFields(t, raw)

	for _, testCase := range []struct {
		name   string
		mutate func(*analyticScalarObservationInput)
	}{
		{"receipt schema", func(input *analyticScalarObservationInput) {
			input.ReceiptSchema = "knowvault.analyticsource.live-scalar-receipt.v2"
		}},
		{"receipt kind", func(input *analyticScalarObservationInput) { input.ReceiptKind = "OBSERVATION" }},
		{"window basis", func(input *analyticScalarObservationInput) { input.WindowBasis = "SERVER_WINDOW" }},
		{"dataset id empty", func(input *analyticScalarObservationInput) { input.DatasetID = "" }},
		{"dataset id opaque", func(input *analyticScalarObservationInput) { input.DatasetID = "gm assignments" }},
		{"profile version zero", func(input *analyticScalarObservationInput) { input.ProfileVersion = 0 }},
		{"profile version negative", func(input *analyticScalarObservationInput) { input.ProfileVersion = -1 }},
		{"profile hash uppercase", func(input *analyticScalarObservationInput) {
			input.ProfileHash = "sha256:" + strings.Repeat("B", 64)
		}},
		{"profile hash short", func(input *analyticScalarObservationInput) { input.ProfileHash = "sha256:short" }},
		{"metric id", func(input *analyticScalarObservationInput) { input.MetricID = "assigned tasks" }},
		{"metric reducer", func(input *analyticScalarObservationInput) { input.MetricReducer = "COUNT_ROWS" }},
		{"metric unit", func(input *analyticScalarObservationInput) { input.MetricUnit = "tasks!" }},
		{"metric null policy", func(input *analyticScalarObservationInput) { input.MetricNullPolicy = "" }},
		{"value grammar", func(input *analyticScalarObservationInput) { input.Value = "03888" }},
		{"value negative zero", func(input *analyticScalarObservationInput) { input.Value = "-0" }},
		{"value zero with fraction", func(input *analyticScalarObservationInput) { input.Value = "0.0" }},
		{"value negative zero with fraction", func(input *analyticScalarObservationInput) { input.Value = "-0.0" }},
		{"value trailing integer fraction", func(input *analyticScalarObservationInput) { input.Value = "3888.0" }},
		{"value trailing zero fraction", func(input *analyticScalarObservationInput) { input.Value = "1.20" }},
		{"reporting timezone empty", func(input *analyticScalarObservationInput) { input.PeriodReportingTimezone = "" }},
		{"reporting timezone oversized", func(input *analyticScalarObservationInput) {
			input.PeriodReportingTimezone = strings.Repeat("a", 129)
		}},
		{"reporting timezone padded", func(input *analyticScalarObservationInput) {
			input.PeriodReportingTimezone = " Europe/Moscow"
		}},
		{"reporting timezone control", func(input *analyticScalarObservationInput) {
			input.PeriodReportingTimezone = "Europe/Moscow\x01"
		}},
		{"source timezone padded", func(input *analyticScalarObservationInput) {
			input.PeriodSourceTimezone = "Europe/Moscow "
		}},
		{"contributing rows zero", func(input *analyticScalarObservationInput) { input.ContributingRows = 0 }},
		{"contributing rows negative", func(input *analyticScalarObservationInput) { input.ContributingRows = -1 }},
		{"coverage incomplete", func(input *analyticScalarObservationInput) { input.CoverageComplete = false }},
		{"receipt digest uppercase", func(input *analyticScalarObservationInput) {
			input.ReceiptDigest = "sha256:" + strings.Repeat("A", 64)
		}},
		{"receipt digest short", func(input *analyticScalarObservationInput) { input.ReceiptDigest = "sha256:" + strings.Repeat("a", 63) }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := analyticScalarObservationInputFixture()
			testCase.mutate(&input)

			observation, err := newAnalyticScalarObservation(input)
			assertAnalyticScalarObservationRefusal(t, observation, err)
		})
	}
}

// TestAnalyticScalarObservationRefusesUnsupportedTypedPeriod proves the typed
// period is closed in this card: only BUSINESS_DATE + DATE + GREGORIAN is
// accepted, and the half-open bounds must be exact ordered YYYY-MM-DD date
// strings rather than timestamps, noncanonical dates or reversed bounds.
func TestAnalyticScalarObservationRefusesUnsupportedTypedPeriod(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*analyticScalarObservationInput)
	}{
		{"local timestamp kind", func(input *analyticScalarObservationInput) {
			input.PeriodTimeKind = "LOCAL_TIMESTAMP"
		}},
		{"zoned timestamp kind", func(input *analyticScalarObservationInput) {
			input.PeriodTimeKind = "ZONED_TIMESTAMP"
		}},
		{"timestamp logical type", func(input *analyticScalarObservationInput) {
			input.PeriodLogicalType = "TIMESTAMP"
		}},
		{"timestamptz logical type", func(input *analyticScalarObservationInput) {
			input.PeriodLogicalType = "TIMESTAMPTZ"
		}},
		{"julian calendar", func(input *analyticScalarObservationInput) { input.PeriodCalendar = "JULIAN" }},
		{"noncanonical start", func(input *analyticScalarObservationInput) { input.PeriodStart = "2026-9-10" }},
		{"noncanonical end", func(input *analyticScalarObservationInput) {
			input.PeriodEndExclusive = "2026-09-1"
		}},
		{"timestamp start", func(input *analyticScalarObservationInput) {
			input.PeriodStart = "2026-09-10T00:00:00Z"
		}},
		{"timestamp end", func(input *analyticScalarObservationInput) {
			input.PeriodEndExclusive = "2026-09-11T00:00:00Z"
		}},
		{"untrimmed start", func(input *analyticScalarObservationInput) { input.PeriodStart = " 2026-09-10" }},
		{"reversed bounds", func(input *analyticScalarObservationInput) {
			input.PeriodStart, input.PeriodEndExclusive = "2026-09-11", "2026-09-10"
		}},
		{"equal bounds", func(input *analyticScalarObservationInput) {
			input.PeriodEndExclusive = input.PeriodStart
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := analyticScalarObservationInputFixture()
			testCase.mutate(&input)

			observation, err := newAnalyticScalarObservation(input)
			assertAnalyticScalarObservationRefusal(t, observation, err)
		})
	}
}

// TestAnalyticScalarObservationRefusesNoncanonicalObservedWindow proves the
// observed window is closed to exact canonical UTC RFC3339Nano instants: an
// offset instant, a zero-offset instant written without Z, a noncanonical
// fraction, the zero instant, and a reversed window are all refused.
func TestAnalyticScalarObservationRefusesNoncanonicalObservedWindow(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*analyticScalarObservationInput)
	}{
		{"started offset", func(input *analyticScalarObservationInput) {
			input.ObservedStartedAt = "2026-09-10T03:00:01+03:00"
		}},
		{"started explicit zero offset", func(input *analyticScalarObservationInput) {
			input.ObservedStartedAt = "2026-09-10T00:00:01+00:00"
		}},
		{"started noncanonical fraction", func(input *analyticScalarObservationInput) {
			input.ObservedStartedAt = "2026-09-10T00:00:01.000Z"
		}},
		{"started empty", func(input *analyticScalarObservationInput) { input.ObservedStartedAt = "" }},
		{"completed zero instant", func(input *analyticScalarObservationInput) {
			input.ObservedCompletedAt = "0001-01-01T00:00:00Z"
		}},
		{"completed offset", func(input *analyticScalarObservationInput) {
			input.ObservedCompletedAt = "2026-09-10T03:00:02+03:00"
		}},
		{"reversed window", func(input *analyticScalarObservationInput) {
			input.ObservedStartedAt, input.ObservedCompletedAt = "2026-09-10T00:00:02Z", "2026-09-10T00:00:01Z"
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			input := analyticScalarObservationInputFixture()
			testCase.mutate(&input)

			observation, err := newAnalyticScalarObservation(input)
			assertAnalyticScalarObservationRefusal(t, observation, err)
		})
	}
}

// TestAnalyticScalarObservationAcceptsEmptySourceTimezone proves the source
// timezone may be absent while the reporting timezone and every other period
// rule still hold.
func TestAnalyticScalarObservationAcceptsEmptySourceTimezone(t *testing.T) {
	input := analyticScalarObservationInputFixture()
	input.PeriodSourceTimezone = ""

	observation, err := newAnalyticScalarObservation(input)
	if err != nil {
		t.Fatalf("construct observation with empty source timezone: %v", err)
	}
	if !observation.valid() {
		t.Fatalf("observation with empty source timezone is invalid: %+v", observation)
	}
}

// TestAnalyticScalarObservationCanonicalValueTable proves the observation value
// is closed to the exact canonical decimals a scalar_sum can emit: 0 and 3888
// stay integers with no fraction, -1.25 and 0.1 keep a nonzero final fraction
// digit, and the noncanonical near misses -0, 0.0, -0.0, 3888.0 and 1.20 are
// refused with the exact zero observation.
func TestAnalyticScalarObservationCanonicalValueTable(t *testing.T) {
	for _, testCase := range []struct {
		value string
		valid bool
	}{
		{"0", true},
		{"3888", true},
		{"-1.25", true},
		{"0.1", true},
		{"-0", false},
		{"0.0", false},
		{"-0.0", false},
		{"3888.0", false},
		{"1.20", false},
	} {
		t.Run(testCase.value, func(t *testing.T) {
			input := analyticScalarObservationInputFixture()
			input.Value = testCase.value

			observation, err := newAnalyticScalarObservation(input)
			if testCase.valid {
				if err != nil {
					t.Fatalf("construct observation with value %q: %v", testCase.value, err)
				}
				if observation.Value != testCase.value {
					t.Fatalf("observation value = %q, want %q", observation.Value, testCase.value)
				}
				return
			}
			assertAnalyticScalarObservationRefusal(t, observation, err)
		})
	}
}

// analyticScalarObservationFixture builds the exact valid GM scalar used by
// both tests: the controlled receipt identity, dataset and metric, exact decimal
// 3888, half-open BUSINESS_DATE day, full 407-row coverage and live receipt
// digest.
func analyticScalarObservationFixture(t *testing.T) analyticScalarObservation {
	t.Helper()
	observation, err := newAnalyticScalarObservation(analyticScalarObservationInputFixture())
	if err != nil {
		t.Fatalf("construct scalar observation fixture: %v", err)
	}
	return observation
}

func analyticScalarObservationInputFixture() analyticScalarObservationInput {
	return analyticScalarObservationInput{
		ReceiptSchema: "knowvault.analyticsource.live-scalar-receipt.v1",
		ReceiptKind:   "LIVE_OBSERVATION",
		WindowBasis:   "CLIENT_READ_CALL",

		DatasetID:      "gm_assignments",
		ProfileVersion: 3,
		ProfileHash:    "sha256:" + strings.Repeat("b", 64),

		MetricID:         "assigned_tasks",
		MetricReducer:    "SUM",
		MetricUnit:       "tasks",
		MetricNullPolicy: "EXCLUDE_AND_REPORT",

		Value: "3888",

		PeriodTimeKind:          "BUSINESS_DATE",
		PeriodLogicalType:       "DATE",
		PeriodStart:             "2026-09-10",
		PeriodEndExclusive:      "2026-09-11",
		PeriodReportingTimezone: "UTC",
		PeriodSourceTimezone:    "Europe/Moscow",
		PeriodCalendar:          "GREGORIAN",

		ContributingRows: 407,
		CoverageComplete: true,

		ObservedStartedAt:   "2026-09-10T00:00:01Z",
		ObservedCompletedAt: "2026-09-10T00:00:02Z",

		ReceiptDigest: "sha256:" + strings.Repeat("a", 64),
	}
}

// assertAnalyticScalarObservationRefusal proves one refusal returns the exact
// zero observation plus the content-free CodeInvalid error, whose unwrap chain
// is empty.
func assertAnalyticScalarObservationRefusal(t *testing.T, observation analyticScalarObservation, err error) {
	t.Helper()
	if observation != (analyticScalarObservation{}) {
		t.Fatalf("refused observation = %+v want the exact zero value", observation)
	}
	var typed *Error
	if !errors.As(err, &typed) || typed.code != CodeInvalid || typed.cause != nil {
		t.Fatalf("refusal = %v, want content-free %s", err, CodeInvalid)
	}
	if unwrapped := errors.Unwrap(err); unwrapped != nil {
		t.Fatalf("errors.Unwrap(err) = %v, want nil", unwrapped)
	}
}

// assertAnalyticScalarObservationWithholdsPrivateFields proves the encoded
// observation never carries the retired subject/dependency claims or any
// private source member: no covered_subjects, dependency_id, subject or
// dependency text, no sql, relation, column, credential or model_text member
// anywhere, and no rows member as an array. contributing_rows is a count and is
// intentionally not rows.
func assertAnalyticScalarObservationWithholdsPrivateFields(t *testing.T, raw []byte) {
	t.Helper()
	lower := strings.ToLower(string(raw))
	for _, forbidden := range []string{"covered_subjects", "dependency_id", "dependency", "subject"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("JSON carries forbidden member text %q: %s", forbidden, raw)
		}
	}
	var decoded any
	if err := jsonv2.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode observation JSON for disclosure check: %v", err)
	}
	assertAnalyticScalarObservationNoPrivateMembers(t, raw, decoded)
}

func assertAnalyticScalarObservationNoPrivateMembers(t *testing.T, raw []byte, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for key, member := range typed {
			switch key {
			case "sql", "relation", "column", "credential", "model_text":
				t.Fatalf("JSON carries private member %q: %s", key, raw)
			case "rows":
				if _, isArray := member.([]any); isArray {
					t.Fatalf("JSON carries rows as an array: %s", raw)
				}
			}
			assertAnalyticScalarObservationNoPrivateMembers(t, raw, member)
		}
	case []any:
		for _, member := range typed {
			assertAnalyticScalarObservationNoPrivateMembers(t, raw, member)
		}
	}
}

// TestAnalyticScalarObservationFromRefusesZeroSealedObservation proves the
// concrete sealed mapper refuses the zero analyticsource.ScalarObservation with
// the exact zero observation and the content-free CodeInvalid error: a zero or
// invalid sealed state publishes no projection.
func TestAnalyticScalarObservationFromRefusesZeroSealedObservation(t *testing.T) {
	observation, err := newAnalyticScalarObservationFrom(analyticsource.ScalarObservation{})
	assertAnalyticScalarObservationRefusal(t, observation, err)
}

// TestAnalyticScalarObservationInputFromValuesCopiesEveryField proves the pure
// copy helper maps all 23 safe value fields one-for-one by index, name and type.
// Every field receives a distinct sentinel, so a dropped, cross-wired or
// repaired field fails rather than silently defaulting.
func TestAnalyticScalarObservationInputFromValuesCopiesEveryField(t *testing.T) {
	const fieldCount = 23
	values := analyticsource.ScalarObservationValues{}
	valuesType := reflect.TypeOf(values)
	if valuesType.NumField() != fieldCount {
		t.Fatalf("analyticsource.ScalarObservationValues fields = %d, want %d", valuesType.NumField(), fieldCount)
	}
	valuesValue := reflect.ValueOf(&values).Elem()
	for index := 0; index < valuesValue.NumField(); index++ {
		field := valuesValue.Field(index)
		switch field.Kind() {
		case reflect.String:
			field.SetString(fmt.Sprintf("sentinel_%02d", index))
		case reflect.Int64:
			field.SetInt(int64(1000 + index))
		case reflect.Bool:
			field.SetBool(index%2 == 0)
		default:
			t.Fatalf("ScalarObservationValues field %s is %s, want a scalar", valuesType.Field(index).Name, field.Kind())
		}
	}

	input := analyticScalarObservationInputFromValues(values)
	inputType := reflect.TypeOf(input)
	if ast.IsExported(inputType.Name()) {
		t.Fatalf("analyticScalarObservationInput is exported as %q", inputType.Name())
	}
	if inputType.NumField() != fieldCount {
		t.Fatalf("analyticScalarObservationInput fields = %d, want %d", inputType.NumField(), fieldCount)
	}
	inputValue := reflect.ValueOf(input)
	for index := 0; index < fieldCount; index++ {
		wantField := valuesType.Field(index)
		gotField := inputType.Field(index)
		if gotField.Name != wantField.Name || gotField.Type != wantField.Type {
			t.Fatalf("input field %d = %s %s, want %s %s", index, gotField.Name, gotField.Type, wantField.Name, wantField.Type)
		}
		if got, want := inputValue.Field(index).Interface(), valuesValue.Field(index).Interface(); got != want {
			t.Fatalf("input field %s = %v, want the copied sentinel %v", gotField.Name, got, want)
		}
	}
}

// TestAnalyticScalarObservationFromCopiesApprovedValuesExactly proves the
// approved detached projection of the controlled GM scalar copies field for
// field into the existing untrusted input and constructs the exact existing
// DTO: exact decimal 3888, 407 contributing rows, complete coverage, typed
// half-open BUSINESS_DATE day and the same live receipt digest.
func TestAnalyticScalarObservationFromCopiesApprovedValuesExactly(t *testing.T) {
	values := analyticScalarObservationValuesFixture()
	input := analyticScalarObservationInputFromValues(values)
	if input != analyticScalarObservationInputFixture() {
		t.Fatalf("copied input = %+v, want the approved input %+v", input, analyticScalarObservationInputFixture())
	}

	observation, err := newAnalyticScalarObservation(input)
	if err != nil {
		t.Fatalf("construct observation from copied input: %v", err)
	}
	want := analyticScalarObservationFixture(t)
	if observation != want {
		t.Fatalf("copied observation = %+v, want the approved DTO %+v", observation, want)
	}
	if observation.Value != "3888" || observation.ContributingRows != 407 || !observation.CoverageComplete {
		t.Fatalf("copied observation = %+v, want value 3888 with 407 complete rows", observation)
	}
}

// TestAnalyticScalarObservationFromRejectsMutatedValuesFamilies proves every
// semantic family of the detached projection is still rejected by the existing
// closed validation after the copy: omitting or mutating one family never
// reaches the DTO and always yields the exact zero observation.
func TestAnalyticScalarObservationFromRejectsMutatedValuesFamilies(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*analyticsource.ScalarObservationValues)
	}{
		{"receipt schema omitted", func(values *analyticsource.ScalarObservationValues) { values.ReceiptSchema = "" }},
		{"receipt kind mutated", func(values *analyticsource.ScalarObservationValues) { values.ReceiptKind = "OBSERVATION" }},
		{"window basis mutated", func(values *analyticsource.ScalarObservationValues) { values.WindowBasis = "SERVER_WINDOW" }},
		{"dataset id omitted", func(values *analyticsource.ScalarObservationValues) { values.DatasetID = "" }},
		{"profile version omitted", func(values *analyticsource.ScalarObservationValues) { values.ProfileVersion = 0 }},
		{"profile hash malformed", func(values *analyticsource.ScalarObservationValues) { values.ProfileHash = "sha256:short" }},
		{"metric id omitted", func(values *analyticsource.ScalarObservationValues) { values.MetricID = "" }},
		{"metric reducer mutated", func(values *analyticsource.ScalarObservationValues) { values.MetricReducer = "COUNT_ROWS" }},
		{"metric unit omitted", func(values *analyticsource.ScalarObservationValues) { values.MetricUnit = "" }},
		{"metric null policy omitted", func(values *analyticsource.ScalarObservationValues) { values.MetricNullPolicy = "" }},
		{"value omitted", func(values *analyticsource.ScalarObservationValues) { values.Value = "" }},
		{"value noncanonical", func(values *analyticsource.ScalarObservationValues) { values.Value = "03888" }},
		{"period time kind mutated", func(values *analyticsource.ScalarObservationValues) { values.PeriodTimeKind = "ZONED_TIMESTAMP" }},
		{"period logical type mutated", func(values *analyticsource.ScalarObservationValues) { values.PeriodLogicalType = "TIMESTAMP" }},
		{"period start omitted", func(values *analyticsource.ScalarObservationValues) { values.PeriodStart = "" }},
		{"period bounds reversed", func(values *analyticsource.ScalarObservationValues) {
			values.PeriodStart, values.PeriodEndExclusive = "2026-09-11", "2026-09-10"
		}},
		{"reporting timezone omitted", func(values *analyticsource.ScalarObservationValues) { values.PeriodReportingTimezone = "" }},
		{"reporting timezone padded", func(values *analyticsource.ScalarObservationValues) { values.PeriodReportingTimezone = " UTC" }},
		{"period calendar mutated", func(values *analyticsource.ScalarObservationValues) { values.PeriodCalendar = "JULIAN" }},
		{"contributing rows omitted", func(values *analyticsource.ScalarObservationValues) { values.ContributingRows = 0 }},
		{"coverage incomplete", func(values *analyticsource.ScalarObservationValues) { values.CoverageComplete = false }},
		{"observed start omitted", func(values *analyticsource.ScalarObservationValues) { values.ObservedStartedAt = "" }},
		{"observed window reversed", func(values *analyticsource.ScalarObservationValues) {
			values.ObservedStartedAt, values.ObservedCompletedAt = "2026-09-10T00:00:02Z", "2026-09-10T00:00:01Z"
		}},
		{"receipt digest omitted", func(values *analyticsource.ScalarObservationValues) { values.ReceiptDigest = "" }},
		{"receipt digest malformed", func(values *analyticsource.ScalarObservationValues) { values.ReceiptDigest = "sha256:xyz" }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			values := analyticScalarObservationValuesFixture()
			testCase.mutate(&values)

			observation, err := newAnalyticScalarObservation(analyticScalarObservationInputFromValues(values))
			assertAnalyticScalarObservationRefusal(t, observation, err)
		})
	}
}

// TestAnalyticScalarObservationFromAcceptsOmittedSourceTimezone proves the
// omission the existing validation permits still holds through the copy: an
// absent source timezone copies to the empty string and the DTO stays valid.
func TestAnalyticScalarObservationFromAcceptsOmittedSourceTimezone(t *testing.T) {
	values := analyticScalarObservationValuesFixture()
	values.PeriodSourceTimezone = ""

	input := analyticScalarObservationInputFromValues(values)
	if input.PeriodSourceTimezone != "" {
		t.Fatalf("copied source timezone = %q, want empty", input.PeriodSourceTimezone)
	}
	if _, err := newAnalyticScalarObservation(input); err != nil {
		t.Fatalf("construct observation with omitted source timezone: %v", err)
	}
}

// TestAnalyticScalarObservationMapperSurfaceIsSealed proves by AST and
// reflection that the new seam is exactly one unexported mapper over the
// concrete sealed analyticsource type: the file still declares no exported
// function, method, type or value, so no exported mapper, factory or decoder
// exists, and the sealed observation keeps no exported field.
func TestAnalyticScalarObservationMapperSurfaceIsSealed(t *testing.T) {
	const filename = "analytic_scalar_observation.go"
	rawFile, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, rawFile, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	found := false
	for _, declaration := range parsed.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Recv == nil && typed.Name.IsExported() {
				t.Fatalf("%s declares the exported function %s", filename, typed.Name.Name)
			}
			if typed.Recv != nil && typed.Name.IsExported() {
				t.Fatalf("%s declares the exported method %s", filename, typed.Name.Name)
			}
			if typed.Name.Name != "newAnalyticScalarObservationFrom" {
				continue
			}
			found = true
			if typed.Recv != nil {
				t.Fatalf("the mapper is declared as a method")
			}
			if typed.Type.Params == nil || len(typed.Type.Params.List) != 1 {
				t.Fatalf("the mapper must accept exactly one parameter")
			}
			parameter := typed.Type.Params.List[0]
			if len(parameter.Names) != 1 || parameter.Names[0].Name != "source" {
				t.Fatalf("the mapper parameter = %v, want source", parameter.Names)
			}
			selector, ok := parameter.Type.(*ast.SelectorExpr)
			if !ok {
				t.Fatalf("the mapper parameter type = %T, want the concrete analyticsource.ScalarObservation selector", parameter.Type)
			}
			qualifier, ok := selector.X.(*ast.Ident)
			if !ok || qualifier.Name != "analyticsource" || selector.Sel.Name != "ScalarObservation" {
				t.Fatalf("the mapper parameter type = %s, want analyticsource.ScalarObservation", expressionText(selector))
			}
			if typed.Type.Results == nil || len(typed.Type.Results.List) != 2 {
				t.Fatalf("the mapper must return exactly two results")
			}
			if first, ok := typed.Type.Results.List[0].Type.(*ast.Ident); !ok || first.Name != "analyticScalarObservation" {
				t.Fatalf("the mapper first result = %T, want analyticScalarObservation", typed.Type.Results.List[0].Type)
			}
			if second, ok := typed.Type.Results.List[1].Type.(*ast.Ident); !ok || second.Name != "error" {
				t.Fatalf("the mapper second result = %T, want error", typed.Type.Results.List[1].Type)
			}
		case *ast.GenDecl:
			for _, specification := range typed.Specs {
				switch named := specification.(type) {
				case *ast.TypeSpec:
					if named.Name.IsExported() {
						t.Fatalf("%s declares the exported type %s", filename, named.Name.Name)
					}
				case *ast.ValueSpec:
					for _, name := range named.Names {
						if name.IsExported() {
							t.Fatalf("%s declares the exported value %s", filename, name.Name)
						}
					}
				}
			}
		}
	}
	if !found {
		t.Fatalf("%s does not declare newAnalyticScalarObservationFrom", filename)
	}

	observationType := reflect.TypeOf(analyticsource.ScalarObservation{})
	if observationType.Kind() != reflect.Struct {
		t.Fatalf("analyticsource.ScalarObservation kind = %s, want struct", observationType.Kind())
	}
	for index := 0; index < observationType.NumField(); index++ {
		if observationType.Field(index).IsExported() {
			t.Fatalf("analyticsource.ScalarObservation exposes the exported field %q", observationType.Field(index).Name)
		}
	}
	if _, ok := observationType.MethodByName("Values"); !ok {
		t.Fatalf("analyticsource.ScalarObservation has no Values projection method")
	}
}

// expressionText renders a parsed identifier or selector for test failures.
func expressionText(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return expressionText(typed.X) + "." + typed.Sel.Name
	case *ast.StarExpr:
		return "*" + expressionText(typed.X)
	default:
		return fmt.Sprintf("%T", expression)
	}
}

// analyticScalarObservationValuesFixture is the approved detached sealed
// projection for the controlled GM scalar. The sealed
// analyticsource.ScalarObservation has no test constructor, so tests reach the
// mapping through the pure field-copy helper.
func analyticScalarObservationValuesFixture() analyticsource.ScalarObservationValues {
	return analyticsource.ScalarObservationValues{
		ReceiptSchema: "knowvault.analyticsource.live-scalar-receipt.v1",
		ReceiptKind:   "LIVE_OBSERVATION",
		WindowBasis:   "CLIENT_READ_CALL",

		DatasetID:      "gm_assignments",
		ProfileVersion: 3,
		ProfileHash:    "sha256:" + strings.Repeat("b", 64),

		MetricID:         "assigned_tasks",
		MetricReducer:    "SUM",
		MetricUnit:       "tasks",
		MetricNullPolicy: "EXCLUDE_AND_REPORT",

		Value: "3888",

		PeriodTimeKind:          "BUSINESS_DATE",
		PeriodLogicalType:       "DATE",
		PeriodStart:             "2026-09-10",
		PeriodEndExclusive:      "2026-09-11",
		PeriodReportingTimezone: "UTC",
		PeriodSourceTimezone:    "Europe/Moscow",
		PeriodCalendar:          "GREGORIAN",

		ContributingRows: 407,
		CoverageComplete: true,

		ObservedStartedAt:   "2026-09-10T00:00:01Z",
		ObservedCompletedAt: "2026-09-10T00:00:02Z",

		ReceiptDigest: "sha256:" + strings.Repeat("a", 64),
	}
}
