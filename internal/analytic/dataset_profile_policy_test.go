package analytic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatasetProfilePolicyEnumsAreClosed(t *testing.T) {
	for _, value := range []CoveragePolicy{CoverageUnknown, CoverageSourceGuaranteed} {
		if !value.Valid() || CoveragePolicy(strings.ToLower(string(value))).Valid() {
			t.Fatalf("coverage policy set is not closed: %q", value)
		}
	}
	for _, value := range []TimeKind{TimeNone, TimeBusinessDate, TimeLocalTimestamp, TimeZonedTimestamp} {
		if !value.Valid() || TimeKind(strings.ToLower(string(value))).Valid() {
			t.Fatalf("time kind set is not closed: %q", value)
		}
	}
	if CoveragePolicy("").Valid() || CoveragePolicy("COMPLETE").Valid() ||
		TimeKind("").Valid() || TimeKind("DATE").Valid() ||
		!CalendarGregorian.Valid() || Calendar("").Valid() || Calendar("gregorian").Valid() {
		t.Fatal("unknown or case-variant enum accepted")
	}
}

func TestDatasetProfilePolicyTimeKinds(t *testing.T) {
	cases := []TimePolicyInput{
		{Kind: TimeNone},
		{Kind: TimeBusinessDate, FieldToken: "business_date", ReportingTimezone: "UTC", Calendar: CalendarGregorian},
		{Kind: TimeLocalTimestamp, FieldToken: "recorded_at", ReportingTimezone: "UTC", SourceTimezone: "UTC", Calendar: CalendarGregorian},
		{Kind: TimeZonedTimestamp, FieldToken: "event_at", ReportingTimezone: "UTC", Calendar: CalendarGregorian},
	}
	for _, input := range cases {
		value, err := NewTimePolicy(input)
		if err != nil || !value.Valid() || value.Values() != input {
			t.Fatalf("valid %s policy rejected: %+v err=%v", input.Kind, value.Values(), err)
		}
	}
	if (TimePolicy{}).Valid() {
		t.Fatal("zero time policy is valid")
	}
}

func TestDatasetProfilePolicyTimeRequirements(t *testing.T) {
	valid := map[TimeKind]TimePolicyInput{
		TimeBusinessDate:   {Kind: TimeBusinessDate, FieldToken: "business_date", ReportingTimezone: "UTC", Calendar: CalendarGregorian},
		TimeLocalTimestamp: {Kind: TimeLocalTimestamp, FieldToken: "local_time", ReportingTimezone: "UTC", SourceTimezone: "UTC", Calendar: CalendarGregorian},
		TimeZonedTimestamp: {Kind: TimeZonedTimestamp, FieldToken: "zoned_time", ReportingTimezone: "UTC", Calendar: CalendarGregorian},
	}
	for kind, base := range valid {
		mutations := []func(*TimePolicyInput){
			func(v *TimePolicyInput) { v.FieldToken = "" },
			func(v *TimePolicyInput) { v.FieldToken = "bad.field" },
			func(v *TimePolicyInput) { v.ReportingTimezone = "" },
			func(v *TimePolicyInput) { v.Calendar = "" },
		}
		for _, mutate := range mutations {
			input := base
			mutate(&input)
			assertInvalidPolicyTime(t, input)
		}
		if kind != TimeLocalTimestamp {
			input := base
			input.SourceTimezone = "UTC"
			assertInvalidPolicyTime(t, input)
		}
	}
	local := valid[TimeLocalTimestamp]
	local.SourceTimezone = ""
	assertInvalidPolicyTime(t, local)
	for _, token := range []string{"9field", "field.name", "field$", "field;drop", "é", strings.Repeat("a", 129)} {
		input := valid[TimeBusinessDate]
		input.FieldToken = token
		assertInvalidPolicyTime(t, input)
	}
	longToken := valid[TimeBusinessDate]
	longToken.FieldToken = strings.Repeat("a", 128)
	if _, err := NewTimePolicy(longToken); err != nil {
		t.Fatalf("valid maximum-length field token rejected: %v", err)
	}
	for _, mutate := range []func(*TimePolicyInput){
		func(v *TimePolicyInput) { v.FieldToken = "field" },
		func(v *TimePolicyInput) { v.ReportingTimezone = "UTC" },
		func(v *TimePolicyInput) { v.SourceTimezone = "UTC" },
		func(v *TimePolicyInput) { v.Calendar = CalendarGregorian },
	} {
		input := TimePolicyInput{Kind: TimeNone}
		mutate(&input)
		assertInvalidPolicyTime(t, input)
	}
}

func TestDatasetProfilePolicyTimezoneValidation(t *testing.T) {
	accepted := []string{"UTC", "Europe/Moscow", "America/New_York"}
	rejected := []string{
		"", "Local", "CET", "Etc/UTC", "US/Eastern",
		"posix/America/New_York", "right/America/New_York",
		" UTC", "UTC ", "UT\nC", "Unknown/Nowhere",
		strings.Repeat("A", 65), string([]byte{0xff}), "UTC\x7f",
	}
	for round := 0; round < 2; round++ {
		if round == 1 {
			poisonHostZoneDatabase(t)
		}
		for _, zone := range accepted {
			assertTimezoneVerdict(t, zone, false, true)
			assertTimezoneVerdict(t, zone, true, true)
		}
		for _, zone := range rejected {
			assertTimezoneVerdict(t, zone, false, false)
			assertTimezoneVerdict(t, zone, true, false)
		}
	}
}

func TestDatasetProfilePolicyTimeValuesAreDetached(t *testing.T) {
	input := TimePolicyInput{Kind: TimeLocalTimestamp, FieldToken: "at", ReportingTimezone: "UTC", SourceTimezone: "UTC", Calendar: CalendarGregorian}
	value, err := NewTimePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	copy := value.Values()
	copy.FieldToken, copy.ReportingTimezone = "changed", "changed"
	if value.Values() != input {
		t.Fatal("mutating returned time DTO changed immutable value")
	}
}

func TestDatasetProfilePolicyLimitsBoundaries(t *testing.T) {
	minimum := ProfileLimitsInput{MaxInputRows: 1, MaxOutputGroups: 1, MaxPeriodDays: 1, MaxResultBytes: 1, StatementTimeoutMS: 1000}
	maximum := ProfileLimitsInput{MaxInputRows: 100000, MaxOutputGroups: 100, MaxPeriodDays: 31, MaxResultBytes: 67108864, StatementTimeoutMS: 300000}
	for _, input := range []ProfileLimitsInput{minimum, maximum} {
		value, err := NewProfileLimits(input)
		if err != nil || !value.Valid() || value.Values() != input {
			t.Fatalf("valid limits rejected: %+v err=%v", input, err)
		}
	}
	invalid := []ProfileLimitsInput{
		{0, 1, 1, 1, 1000}, {100001, 1, 1, 1, 1000},
		{1, 0, 1, 1, 1000}, {1, 101, 1, 1, 1000},
		{1, 1, 0, 1, 1000}, {1, 1, 32, 1, 1000},
		{1, 1, 1, 0, 1000}, {1, 1, 1, 67108865, 1000},
		{1, 1, 1, 1, 999}, {1, 1, 1, 1, 300001},
	}
	for _, input := range invalid {
		if value, err := NewProfileLimits(input); err == nil || CodeOf(err) != CodeInvalidRequest || value.Valid() {
			t.Fatalf("invalid limits accepted: %+v", input)
		}
	}
	if (ProfileLimits{}).Valid() {
		t.Fatal("zero limits are valid")
	}
}

func TestDatasetProfilePolicyLimitValuesAreDetached(t *testing.T) {
	input := ProfileLimitsInput{10, 2, 3, 4096, 2000}
	value, err := NewProfileLimits(input)
	if err != nil {
		t.Fatal(err)
	}
	copy := value.Values()
	copy.MaxInputRows = 999
	if value.Values() != input {
		t.Fatal("mutating returned limits DTO changed immutable value")
	}
}

func assertInvalidPolicyTime(t *testing.T, input TimePolicyInput) {
	t.Helper()
	if value, err := NewTimePolicy(input); err == nil || CodeOf(err) != CodeInvalidRequest || value.Valid() {
		t.Fatalf("invalid time policy accepted: %+v", input)
	}
}

// poisonHostZoneDatabase makes host tzdata lookups misleading or unavailable, so
// any acceptance can only come from the embedded pinned rules.
func poisonHostZoneDatabase(t *testing.T) {
	t.Helper()
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "Europe"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "Europe", "Moscow"), []byte("not TZif"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TZ", "America/Los_Angeles")
	t.Setenv("ZONEINFO", directory)
}

func assertTimezoneVerdict(t *testing.T, zone string, source bool, want bool) {
	t.Helper()
	input := TimePolicyInput{Kind: TimeBusinessDate, FieldToken: "day", ReportingTimezone: "UTC", Calendar: CalendarGregorian}
	if source {
		input.Kind = TimeLocalTimestamp
		input.SourceTimezone = zone
	} else {
		input.ReportingTimezone = zone
	}
	value, err := NewTimePolicy(input)
	if want && (err != nil || !value.Valid()) {
		t.Fatalf("timezone %q rejected (source=%v): %v", zone, source, err)
	}
	if !want && (err == nil || CodeOf(err) != CodeInvalidRequest || value.Valid()) {
		t.Fatalf("timezone %q accepted (source=%v)", zone, source)
	}
}
