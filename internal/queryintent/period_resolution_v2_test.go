package queryintent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

func resolutionProfile(t *testing.T, kind analytic.TimeKind, zone string, maxDays int) analytic.DatasetProfile {
	t.Helper()
	profile := v2Profile(t, "period-resolution", 1, analytic.CoverageUnknown, v2Limits(t, 1000))
	spec := profile.Spec()
	if kind == analytic.TimeLocalTimestamp || kind == analytic.TimeZonedTimestamp {
		for index, field := range spec.Fields {
			if field.Values().Token != "region" {
				continue
			}
			input := field.Values()
			input.LogicalType, input.PhysicalType = analytic.ScalarTimestamp, analytic.PhysicalPGTimestamp
			if kind == analytic.TimeZonedTimestamp {
				input.LogicalType, input.PhysicalType = analytic.ScalarTimestamptz, analytic.PhysicalPGTimestamptz
			}
			field, err := analytic.NewFieldSpec(input)
			if err != nil {
				t.Fatal(err)
			}
			spec.Fields[index] = field
		}
	}
	input := analytic.TimePolicyInput{Kind: kind}
	if kind != analytic.TimeNone {
		input.FieldToken, input.ReportingTimezone, input.Calendar = "business_day", zone, analytic.CalendarGregorian
		if kind == analytic.TimeLocalTimestamp || kind == analytic.TimeZonedTimestamp {
			input.FieldToken = "region"
		}
		if kind == analytic.TimeLocalTimestamp {
			input.SourceTimezone = "UTC"
		}
	}
	var err error
	spec.Time, err = analytic.NewTimePolicy(input)
	if err != nil {
		t.Fatal(err)
	}
	limits := spec.Limits.Values()
	limits.MaxPeriodDays = maxDays
	spec.Limits, err = analytic.NewProfileLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	profile, err = analytic.NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func resolutionRelative(t *testing.T, mode PeriodMode) PeriodProposal {
	t.Helper()
	value, err := NewRelativePeriod(mode)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func resolutionExplicit(t *testing.T, start, end string) PeriodProposal {
	t.Helper()
	value, err := NewExplicitPeriod(start, end)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertResolutionRefused(t *testing.T, value periodResolutionV2, err error, code ErrorCode, leaked ...string) {
	t.Helper()
	if value != (periodResolutionV2{}) || err == nil || CodeOf(err) != code || err.Error() != string(code) ||
		ClarificationOf(err) != clarificationFor(code) || errors.Unwrap(err) != nil {
		t.Fatalf("value=%v err=%v clarification=%q", value, err, ClarificationOf(err))
	}
	for _, text := range leaked {
		if text != "" && (strings.Contains(err.Error(), text) || strings.Contains(ClarificationOf(err), text)) {
			t.Fatalf("refusal leaked %q", text)
		}
	}
}

func TestResolvePeriodForProfileV2BusinessCurrentMonthMoscow(t *testing.T) {
	profile := resolutionProfile(t, analytic.TimeBusinessDate, "Europe/Moscow", 31)
	instant := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	value, err := resolvePeriodForProfileV2(profile, resolutionRelative(t, PeriodCURRENTMONTH), instant)
	same, sameErr := resolvePeriodForProfileV2(profile, resolutionRelative(t, PeriodCURRENTMONTH), instant.In(time.FixedZone("source", 11*60*60)))
	if err != nil || sameErr != nil || value != same {
		t.Fatalf("source location changed resolution: %v/%v %v/%v", value, err, same, sameErr)
	}
	period, periodOK := value.ResolvedPeriod()
	start, end, boundsOK := period.Bounds()
	clock, clockOK := value.TrustedNowUTC()
	if !periodOK || !boundsOK || start != "2026-03-01" || end != "2026-04-01" ||
		!clockOK || clock != "2026-03-15T12:00:00Z" {
		t.Fatalf("period=%v bounds=%q..%q clock=%q", period, start, end, clock)
	}
}

func TestResolvePeriodForProfileV2ZonedCurrentMonthMoscow(t *testing.T) {
	profile := resolutionProfile(t, analytic.TimeZonedTimestamp, "Europe/Moscow", 31)
	value, err := resolvePeriodForProfileV2(profile, resolutionRelative(t, PeriodCURRENTMONTH), time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	period, periodOK := value.ResolvedPeriod()
	start, end, boundsOK := period.Bounds()
	clock, clockOK := value.TrustedNowUTC()
	if !periodOK || !boundsOK || start != "2026-02-28T21:00:00Z" || end != "2026-03-31T21:00:00Z" ||
		!clockOK || clock != "2026-03-15T12:00:00Z" {
		t.Fatalf("period=%v bounds=%q..%q clock=%q", period, start, end, clock)
	}
}

func TestResolvePeriodForProfileV2CurrentMonthLimitRefusal(t *testing.T) {
	profile := resolutionProfile(t, analytic.TimeBusinessDate, "Europe/Moscow", 30)
	value, err := resolvePeriodForProfileV2(profile, resolutionRelative(t, PeriodCURRENTMONTH), time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	assertResolutionRefused(t, value, err, CodePeriodLimitExceeded, "CURRENT_MONTH", "2026-03", "Europe/Moscow")
}

func TestResolvePeriodForProfileV2ExplicitIgnoresYear10000Clock(t *testing.T) {
	profile := resolutionProfile(t, analytic.TimeBusinessDate, "UTC", 31)
	proposal := resolutionExplicit(t, "2026-03-01", "2026-03-02")
	zero, zeroErr := resolvePeriodForProfileV2(profile, proposal, time.Time{})
	future, futureErr := resolvePeriodForProfileV2(profile, proposal, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	if zeroErr != nil || futureErr != nil || zero != future {
		t.Fatalf("explicit clock changed result: zero=%v/%v future=%v/%v", zero, zeroErr, future, futureErr)
	}
	if clock, ok := future.TrustedNowUTC(); ok || clock != "" {
		t.Fatalf("explicit trusted clock=%q/%v", clock, ok)
	}
}

func TestResolvePeriodForProfileV2ExplicitLocalTimestampUnavailable(t *testing.T) {
	profile := resolutionProfile(t, analytic.TimeLocalTimestamp, "Europe/Moscow", 31)
	value, err := resolvePeriodForProfileV2(profile, resolutionExplicit(t, "2026-03-01", "2026-03-02"), time.Time{})
	assertResolutionRefused(t, value, err, CodePeriodUnavailable, "LOCAL_TIMESTAMP", "2026-03-01", "2026-03-02")
}

func TestPeriodResolutionV2EnvelopeForgedAndAccessors(t *testing.T) {
	explicit := resolvedV2(t, PeriodEXPLICIT, analytic.TimeBusinessDate, "2026-03-01", "2026-03-02")
	relative := resolvedV2(t, PeriodTODAY, analytic.TimeBusinessDate, "2026-03-01", "2026-03-02")
	latest := resolvedV2(t, PeriodLATESTAVAILABLE, analytic.TimeBusinessDate, "", "")
	clock := "2026-03-01T12:00:00.123Z"
	for _, tc := range []struct {
		name  string
		value periodResolutionV2
		valid bool
	}{
		{"zero", periodResolutionV2{}, false},
		{"explicit", periodResolutionV2{period: explicit, initialized: true}, true},
		{"explicit clock", periodResolutionV2{period: explicit, trustedNowUTC: clock, initialized: true}, false},
		{"relative", periodResolutionV2{period: relative, trustedNowUTC: clock, initialized: true}, true},
		{"bad clock", periodResolutionV2{period: relative, trustedNowUTC: "2026-03-01T12:00:00+00:00", initialized: true}, false},
		{"forged period", periodResolutionV2{period: ResolvedPeriodV2{mode: PeriodTODAY, timeKind: analytic.TimeBusinessDate, start: "bad", end: "bad", initialized: true}, trustedNowUTC: clock, initialized: true}, false},
		{"latest", periodResolutionV2{period: latest, trustedNowUTC: clock, initialized: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.value.Valid() != tc.valid {
				t.Fatalf("Valid()=%v want %v", tc.value.Valid(), tc.valid)
			}
			period, periodOK := tc.value.ResolvedPeriod()
			trusted, trustedOK := tc.value.TrustedNowUTC()
			if !tc.valid && (periodOK || trustedOK || period != (ResolvedPeriodV2{}) || trusted != "") {
				t.Fatalf("invalid accessors=%v/%v %q/%v", period, periodOK, trusted, trustedOK)
			}
		})
	}
	value := periodResolutionV2{period: explicit, initialized: true}
	if _, ok := value.ResolvedPeriod(); !ok {
		t.Fatal("explicit period accessor refused")
	}
	if clock, ok := value.TrustedNowUTC(); ok || clock != "" {
		t.Fatalf("explicit clock accessor=%q/%v", clock, ok)
	}
}

func TestResolvePeriodForProfileV2OriginalDispatchMatrix(t *testing.T) {
	clock := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	business := resolutionProfile(t, analytic.TimeBusinessDate, "UTC", 31)
	value, err := resolvePeriodForProfileV2(business, resolutionExplicit(t, "2026-03-01", "2026-03-05"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	period, _ := value.ResolvedPeriod()
	start, end, _ := period.Bounds()
	if start != "2026-03-01" || end != "2026-03-05" {
		t.Fatalf("business explicit bounds=%q..%q", start, end)
	}
	if trusted, ok := value.TrustedNowUTC(); ok || trusted != "" {
		t.Fatalf("explicit clock=%q/%v", trusted, ok)
	}
	value, err = resolvePeriodForProfileV2(business, resolutionRelative(t, PeriodTODAY), clock)
	if err != nil {
		t.Fatal(err)
	}
	period, _ = value.ResolvedPeriod()
	start, end, _ = period.Bounds()
	if start != "2026-03-15" || end != "2026-03-16" {
		t.Fatalf("business today bounds=%q..%q", start, end)
	}

	zoned := resolutionProfile(t, analytic.TimeZonedTimestamp, "UTC", 2)
	value, err = resolvePeriodForProfileV2(zoned, resolutionExplicit(t, "2026-03-01T03:00:00+03:00", "2026-03-02T03:00:00+03:00"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	period, _ = value.ResolvedPeriod()
	start, end, _ = period.Bounds()
	if start != "2026-03-01T00:00:00Z" || end != "2026-03-02T00:00:00Z" {
		t.Fatalf("zoned explicit bounds=%q..%q", start, end)
	}
	value, err = resolvePeriodForProfileV2(zoned, resolutionRelative(t, PeriodTODAY), clock)
	if err != nil {
		t.Fatal(err)
	}
	period, _ = value.ResolvedPeriod()
	start, end, _ = period.Bounds()
	if start != "2026-03-15T00:00:00Z" || end != "2026-03-16T00:00:00Z" {
		t.Fatalf("zoned today bounds=%q..%q", start, end)
	}
	nonUTC := resolutionProfile(t, analytic.TimeZonedTimestamp, "Europe/Moscow", 31)
	value, err = resolvePeriodForProfileV2(nonUTC, resolutionExplicit(t, "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z"), time.Time{})
	assertResolutionRefused(t, value, err, CodePeriodUnavailable)

	zero, err := resolvePeriodForProfileV2(business, resolutionRelative(t, PeriodTODAY), time.Time{})
	assertResolutionRefused(t, zero, err, CodeTrustedNowRequired)
	for _, tc := range []struct {
		name     string
		profile  analytic.DatasetProfile
		proposal PeriodProposal
	}{
		{"local relative", resolutionProfile(t, analytic.TimeLocalTimestamp, "UTC", 31), resolutionRelative(t, PeriodTODAY)},
		{"none", resolutionProfile(t, analytic.TimeNone, "", 31), resolutionExplicit(t, "2026-03-01", "2026-03-02")},
		{"latest", business, resolutionRelative(t, PeriodLATESTAVAILABLE)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := resolvePeriodForProfileV2(tc.profile, tc.proposal, clock)
			assertResolutionRefused(t, value, err, CodePeriodUnavailable)
		})
	}
	for _, tc := range []struct {
		name     string
		profile  analytic.DatasetProfile
		proposal PeriodProposal
	}{
		{"invalid profile", analytic.DatasetProfile{}, resolutionRelative(t, PeriodTODAY)},
		{"invalid proposal", business, PeriodProposal{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, err := resolvePeriodForProfileV2(tc.profile, tc.proposal, clock)
			assertResolutionRefused(t, value, err, CodePeriodInvalid)
		})
	}
}
