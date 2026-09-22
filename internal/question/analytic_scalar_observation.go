package question

import (
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/analyticsource"
	"knowvault.local/verified-workspace/internal/workspace"
)

// The one receipt identity, reducer and period policy this Question slice
// accepts. They mirror the live scalar receipt vocabulary as local literals;
// the typed adapter below copies the sealed analyticsource projection into the
// untrusted input, and the closed validation remains the only trust boundary.
const (
	analyticScalarReceiptSchema      = "knowvault.analyticsource.live-scalar-receipt.v1"
	analyticScalarReceiptKind        = "LIVE_OBSERVATION"
	analyticScalarReceiptWindowBasis = "CLIENT_READ_CALL"

	analyticScalarMetricReducer = "SUM"

	analyticScalarPeriodTimeKind    = "BUSINESS_DATE"
	analyticScalarPeriodLogicalType = "DATE"
	analyticScalarPeriodCalendar    = "GREGORIAN"
)

// analyticScalarObservationInput carries the untrusted field values supplied to
// the scalar observation constructor. It names the same fields as the
// observation and holds no trusted state.
type analyticScalarObservationInput struct {
	ReceiptSchema string
	ReceiptKind   string
	WindowBasis   string

	DatasetID      string
	ProfileVersion int64
	ProfileHash    string

	MetricID         string
	MetricReducer    string
	MetricUnit       string
	MetricNullPolicy string

	Value string

	PeriodTimeKind          string
	PeriodLogicalType       string
	PeriodStart             string
	PeriodEndExclusive      string
	PeriodReportingTimezone string
	PeriodSourceTimezone    string
	PeriodCalendar          string

	ContributingRows int64
	CoverageComplete bool

	ObservedStartedAt   string
	ObservedCompletedAt string

	ReceiptDigest string
}

// analyticScalarObservation is one exact canonical scalar observation. Every
// field is an exported JSON member so the JSON v2 codec can serialize the
// private type directly, without a custom method. The constructor and valid()
// are the only trusted boundaries in this card; tool-loop decode validation is
// a later card.
type analyticScalarObservation struct {
	ReceiptSchema string `json:"receipt_schema"`
	ReceiptKind   string `json:"receipt_kind"`
	WindowBasis   string `json:"window_basis"`

	DatasetID      string `json:"dataset_id"`
	ProfileVersion int64  `json:"profile_version"`
	ProfileHash    string `json:"profile_hash"`

	MetricID         string `json:"metric_id"`
	MetricReducer    string `json:"metric_reducer"`
	MetricUnit       string `json:"metric_unit"`
	MetricNullPolicy string `json:"metric_null_policy"`

	Value string `json:"value"`

	PeriodTimeKind          string `json:"period_time_kind"`
	PeriodLogicalType       string `json:"period_logical_type"`
	PeriodStart             string `json:"period_start"`
	PeriodEndExclusive      string `json:"period_end_exclusive"`
	PeriodReportingTimezone string `json:"period_reporting_timezone"`
	PeriodSourceTimezone    string `json:"period_source_timezone"`
	PeriodCalendar          string `json:"period_calendar"`

	ContributingRows int64 `json:"contributing_rows"`
	CoverageComplete bool  `json:"coverage_complete"`

	ObservedStartedAt   string `json:"observed_started_at"`
	ObservedCompletedAt string `json:"observed_completed_at"`

	ReceiptDigest string `json:"receipt_digest"`
}

// analyticScalarValuePattern is the exact canonical scalar grammar: an optional
// sign, a non-padded integer, and an optional non-empty fractional part. The
// value stays a string so no decimal is ever re-interpreted as binary floating
// point.
var analyticScalarValuePattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)

// validAnalyticScalarValue reports whether value is a closed canonical decimal
// byte for byte identical to a scalar_sum output: the grammar above, never a
// negative zero, and, when a fraction exists, a nonzero final digit so no
// trailing fractional zeroes survive. It is the only value check valid() uses.
func validAnalyticScalarValue(value string) bool {
	if !analyticScalarValuePattern.MatchString(value) {
		return false
	}
	if value == "-0" {
		return false
	}
	if dot := strings.IndexByte(value, '.'); dot >= 0 {
		return value[len(value)-1] != '0'
	}
	return true
}

// newAnalyticScalarObservation validates one untrusted input and returns the
// exact zero observation plus a content-free error when any rule fails. An
// accepted call returns the observation whose validation passed unchanged.
func newAnalyticScalarObservation(input analyticScalarObservationInput) (analyticScalarObservation, error) {
	observation := analyticScalarObservation{
		ReceiptSchema: input.ReceiptSchema,
		ReceiptKind:   input.ReceiptKind,
		WindowBasis:   input.WindowBasis,

		DatasetID:      input.DatasetID,
		ProfileVersion: input.ProfileVersion,
		ProfileHash:    input.ProfileHash,

		MetricID:         input.MetricID,
		MetricReducer:    input.MetricReducer,
		MetricUnit:       input.MetricUnit,
		MetricNullPolicy: input.MetricNullPolicy,

		Value: input.Value,

		PeriodTimeKind:          input.PeriodTimeKind,
		PeriodLogicalType:       input.PeriodLogicalType,
		PeriodStart:             input.PeriodStart,
		PeriodEndExclusive:      input.PeriodEndExclusive,
		PeriodReportingTimezone: input.PeriodReportingTimezone,
		PeriodSourceTimezone:    input.PeriodSourceTimezone,
		PeriodCalendar:          input.PeriodCalendar,

		ContributingRows: input.ContributingRows,
		CoverageComplete: input.CoverageComplete,

		ObservedStartedAt:   input.ObservedStartedAt,
		ObservedCompletedAt: input.ObservedCompletedAt,

		ReceiptDigest: input.ReceiptDigest,
	}
	if !observation.valid() {
		return analyticScalarObservation{}, &Error{code: CodeInvalid}
	}
	return observation, nil
}

// newAnalyticScalarObservationFrom is the one typed adapter from the accepted
// sealed live analyticsource result to this Question encrypted artifact DTO. It
// accepts only the concrete sealed analyticsource.ScalarObservation, never an
// interface or the detached value struct, so model text, caller JSON and
// arbitrary SQL cannot supply the numeric fact. It asks the sealed observation
// for its detached projection exactly once; a refusal returns the exact zero
// observation plus the content-free CodeInvalid error. Every safe value field is
// copied one-for-one into the existing untrusted input and the existing closed
// validation in newAnalyticScalarObservation stays the only trust boundary.
// There is no default, trim, conversion, repair, recomputed digest, inferred
// subject, dependency id, source internal or fallback.
func newAnalyticScalarObservationFrom(source analyticsource.ScalarObservation) (analyticScalarObservation, error) {
	values, ok := source.Values()
	if !ok {
		return analyticScalarObservation{}, &Error{code: CodeInvalid}
	}
	return newAnalyticScalarObservation(analyticScalarObservationInputFromValues(values))
}

// analyticScalarObservationInputFromValues copies every safe value field of the
// detached sealed projection one-for-one into the untrusted input. It is a pure
// field copy: it adds no default, drops no field, trims nothing, converts
// nothing and recomputes nothing.
func analyticScalarObservationInputFromValues(values analyticsource.ScalarObservationValues) analyticScalarObservationInput {
	return analyticScalarObservationInput{
		ReceiptSchema: values.ReceiptSchema,
		ReceiptKind:   values.ReceiptKind,
		WindowBasis:   values.WindowBasis,

		DatasetID:      values.DatasetID,
		ProfileVersion: values.ProfileVersion,
		ProfileHash:    values.ProfileHash,

		MetricID:         values.MetricID,
		MetricReducer:    values.MetricReducer,
		MetricUnit:       values.MetricUnit,
		MetricNullPolicy: values.MetricNullPolicy,

		Value: values.Value,

		PeriodTimeKind:          values.PeriodTimeKind,
		PeriodLogicalType:       values.PeriodLogicalType,
		PeriodStart:             values.PeriodStart,
		PeriodEndExclusive:      values.PeriodEndExclusive,
		PeriodReportingTimezone: values.PeriodReportingTimezone,
		PeriodSourceTimezone:    values.PeriodSourceTimezone,
		PeriodCalendar:          values.PeriodCalendar,

		ContributingRows: values.ContributingRows,
		CoverageComplete: values.CoverageComplete,

		ObservedStartedAt:   values.ObservedStartedAt,
		ObservedCompletedAt: values.ObservedCompletedAt,

		ReceiptDigest: values.ReceiptDigest,
	}
}

// valid applies the exact scalar observation rules to a decoded observation.
// The receipt identity, reducer and period policy are closed to the one live
// vocabulary this card accepts; identifiers stay opaque; the value must match
// the canonical decimal grammar; the period is an exact half-open ordered
// BUSINESS_DATE/DATE day; the reporting timezone must use the safe timezone
// shape and the source timezone may be empty; coverage must be positive and
// complete; both observed instants must be canonical nonzero ordered UTC
// RFC3339Nano strings; and both hashes must be exact configuration-hash
// representations.
func (observation analyticScalarObservation) valid() bool {
	if observation.ReceiptSchema != analyticScalarReceiptSchema ||
		observation.ReceiptKind != analyticScalarReceiptKind ||
		observation.WindowBasis != analyticScalarReceiptWindowBasis {
		return false
	}
	if !validOpaque(observation.DatasetID) ||
		observation.ProfileVersion <= 0 ||
		!workspace.IsConfigurationHash(observation.ProfileHash) {
		return false
	}
	if !validOpaque(observation.MetricID) ||
		observation.MetricReducer != analyticScalarMetricReducer ||
		!validOpaque(observation.MetricUnit) ||
		!validOpaque(observation.MetricNullPolicy) {
		return false
	}
	if !validAnalyticScalarValue(observation.Value) {
		return false
	}
	if observation.PeriodTimeKind != analyticScalarPeriodTimeKind ||
		observation.PeriodLogicalType != analyticScalarPeriodLogicalType ||
		observation.PeriodCalendar != analyticScalarPeriodCalendar {
		return false
	}
	start, err := time.Parse("2006-01-02", observation.PeriodStart)
	if err != nil || start.Format("2006-01-02") != observation.PeriodStart {
		return false
	}
	end, err := time.Parse("2006-01-02", observation.PeriodEndExclusive)
	if err != nil || end.Format("2006-01-02") != observation.PeriodEndExclusive {
		return false
	}
	if !end.After(start) {
		return false
	}
	if !validAnalyticScalarTimezone(observation.PeriodReportingTimezone) {
		return false
	}
	if observation.PeriodSourceTimezone != "" && !validAnalyticScalarTimezone(observation.PeriodSourceTimezone) {
		return false
	}
	if observation.ContributingRows <= 0 || !observation.CoverageComplete {
		return false
	}
	startedAt, startedOK := validAnalyticScalarObservedInstant(observation.ObservedStartedAt)
	completedAt, completedOK := validAnalyticScalarObservedInstant(observation.ObservedCompletedAt)
	if !startedOK || !completedOK || completedAt.Before(startedAt) {
		return false
	}
	return workspace.IsConfigurationHash(observation.ReceiptDigest)
}

// validAnalyticScalarObservedInstant checks one observed instant shape: a
// canonical RFC3339Nano string in UTC rendered with a trailing Z. It parses and
// reformats to the same bytes so no mere equivalent offset or noncanonical
// fraction is accepted, and rejects the zero instant.
func validAnalyticScalarObservedInstant(value string) (time.Time, bool) {
	if !strings.HasSuffix(value, "Z") {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.IsZero() || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, false
	}
	return parsed, true
}

// validAnalyticScalarTimezone checks only the timezone shape: 1..128 UTF-8
// bytes, unchanged by strings.TrimSpace, and free of control characters. It is
// otherwise opaque and loads no timezone rules.
func validAnalyticScalarTimezone(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}
