package analytic

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/tzrules"
)

// CoveragePolicy states whether the approved source guarantees complete coverage.
type CoveragePolicy string

const (
	CoverageUnknown          CoveragePolicy = "UNKNOWN"
	CoverageSourceGuaranteed CoveragePolicy = "SOURCE_GUARANTEED"
)

func (value CoveragePolicy) Valid() bool {
	return value == CoverageUnknown || value == CoverageSourceGuaranteed
}

// TimeKind identifies how an approved projection represents event time.
type TimeKind string

const (
	TimeNone           TimeKind = "NONE"
	TimeBusinessDate   TimeKind = "BUSINESS_DATE"
	TimeLocalTimestamp TimeKind = "LOCAL_TIMESTAMP"
	TimeZonedTimestamp TimeKind = "ZONED_TIMESTAMP"
)

func (value TimeKind) Valid() bool {
	switch value {
	case TimeNone, TimeBusinessDate, TimeLocalTimestamp, TimeZonedTimestamp:
		return true
	default:
		return false
	}
}

// Calendar is the closed calendar vocabulary for profile schema v1.
type Calendar string

const CalendarGregorian Calendar = "GREGORIAN"

func (value Calendar) Valid() bool { return value == CalendarGregorian }

// TimePolicyInput is both construction input and detached read DTO.
type TimePolicyInput struct {
	Kind              TimeKind
	FieldToken        string
	ReportingTimezone string
	SourceTimezone    string
	Calendar          Calendar
}

// TimePolicy is an immutable description of the projection's time semantics.
type TimePolicy struct {
	kind              TimeKind
	fieldToken        string
	reportingTimezone string
	sourceTimezone    string
	calendar          Calendar
	constructed       bool
}

func NewTimePolicy(input TimePolicyInput) (TimePolicy, error) {
	value := TimePolicy{
		kind: input.Kind, fieldToken: input.FieldToken,
		reportingTimezone: input.ReportingTimezone, sourceTimezone: input.SourceTimezone,
		calendar: input.Calendar, constructed: true,
	}
	if !value.Valid() {
		return TimePolicy{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value TimePolicy) Valid() bool {
	if !value.constructed || !value.kind.Valid() {
		return false
	}
	if value.kind == TimeNone {
		return value.fieldToken == "" && value.reportingTimezone == "" &&
			value.sourceTimezone == "" && value.calendar == ""
	}
	if !fieldTokenPattern.MatchString(value.fieldToken) ||
		!validProfileTimezone(value.reportingTimezone) || value.calendar != CalendarGregorian {
		return false
	}
	switch value.kind {
	case TimeBusinessDate, TimeZonedTimestamp:
		return value.sourceTimezone == ""
	case TimeLocalTimestamp:
		return validProfileTimezone(value.sourceTimezone)
	default:
		return false
	}
}

func (value TimePolicy) Values() TimePolicyInput {
	return TimePolicyInput{
		Kind: value.kind, FieldToken: value.fieldToken,
		ReportingTimezone: value.reportingTimezone, SourceTimezone: value.sourceTimezone,
		Calendar: value.calendar,
	}
}

// validProfileTimezone accepts only names the embedded pinned rules resolve; the
// host zone database (TZ, ZONEINFO) is never consulted and there is no fallback.
func validProfileTimezone(value string) bool {
	if value == "" || len(value) > 64 || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		strings.ContainsFunc(value, unicode.IsControl) {
		return false
	}
	_, err := tzrules.Load(value)
	return err == nil
}

// ProfileLimitsInput is both construction input and detached read DTO.
type ProfileLimitsInput struct {
	MaxInputRows       int64
	MaxOutputGroups    int
	MaxPeriodDays      int
	MaxResultBytes     int64
	StatementTimeoutMS int64
}

// ProfileLimits contains immutable execution bounds for one approved profile.
type ProfileLimits struct {
	maxInputRows       int64
	maxOutputGroups    int
	maxPeriodDays      int
	maxResultBytes     int64
	statementTimeoutMS int64
}

func NewProfileLimits(input ProfileLimitsInput) (ProfileLimits, error) {
	value := ProfileLimits{
		maxInputRows: input.MaxInputRows, maxOutputGroups: input.MaxOutputGroups,
		maxPeriodDays: input.MaxPeriodDays, maxResultBytes: input.MaxResultBytes,
		statementTimeoutMS: input.StatementTimeoutMS,
	}
	if !value.Valid() {
		return ProfileLimits{}, &Error{code: CodeInvalidRequest}
	}
	return value, nil
}

func (value ProfileLimits) Valid() bool {
	return value.maxInputRows >= 1 && value.maxInputRows <= 100000 &&
		value.maxOutputGroups >= 1 && value.maxOutputGroups <= 100 &&
		value.maxPeriodDays >= 1 && value.maxPeriodDays <= 31 &&
		value.maxResultBytes >= 1 && value.maxResultBytes <= 67108864 &&
		value.statementTimeoutMS >= 1000 && value.statementTimeoutMS <= 300000
}

func (value ProfileLimits) Values() ProfileLimitsInput {
	return ProfileLimitsInput{
		MaxInputRows: value.maxInputRows, MaxOutputGroups: value.maxOutputGroups,
		MaxPeriodDays: value.maxPeriodDays, MaxResultBytes: value.maxResultBytes,
		StatementTimeoutMS: value.statementTimeoutMS,
	}
}
