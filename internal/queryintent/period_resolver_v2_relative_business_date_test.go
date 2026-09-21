package queryintent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

// relativeProposal builds one valid relative proposal.
func relativeProposal(t *testing.T, mode PeriodMode) PeriodProposal {
	t.Helper()
	proposal, err := NewRelativePeriod(mode)
	if err != nil {
		t.Fatalf("NewRelativePeriod(%q) err=%v", mode, err)
	}
	return proposal
}

// relativeBusinessDateAccepted resolves one relative proposal twice and pins the
// whole result: no error, the same value on repeat, the proposal mode, the
// BUSINESS_DATE kind, the canonical bounds and no latest-available flag.
func relativeBusinessDateAccepted(t *testing.T, name string, proposal PeriodProposal, capturedAt time.Time, zone string, maxPeriodDays int, wantStart, wantEnd string) {
	t.Helper()
	value, err := resolveRelativeBusinessDateV2(proposal, capturedAt, zone, maxPeriodDays)
	again, againErr := resolveRelativeBusinessDateV2(proposal, capturedAt, zone, maxPeriodDays)
	if err != nil || againErr != nil || !value.Valid() || value != again {
		t.Fatalf("%s: value=%v err=%v again=%v againErr=%v", name, value, err, again, againErr)
	}
	mode, modeOK := value.Mode()
	kind, kindOK := value.TimeKind()
	start, end, boundsOK := value.Bounds()
	if !modeOK || mode != proposal.mode || !kindOK || kind != analytic.TimeBusinessDate ||
		!boundsOK || start != wantStart || end != wantEnd || value.IsLatestAvailable() {
		t.Fatalf("%s: resolved %q/%q %q..%q ok=%v/%v/%v", name, mode, kind, start, end, modeOK, kindOK, boundsOK)
	}
}

// relativeBusinessDateRefused pins one whole refusal: the zero period, the exact
// content-free code and clarification, no unwrap, and no echoed input text.
func relativeBusinessDateRefused(t *testing.T, name string, proposal PeriodProposal, capturedAt time.Time, zone string, maxPeriodDays int, code ErrorCode) {
	t.Helper()
	value, err := resolveRelativeBusinessDateV2(proposal, capturedAt, zone, maxPeriodDays)
	clarification := ClarificationOf(err)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != code ||
		err.Error() != string(code) || clarification != clarificationFor(code) || errors.Unwrap(err) != nil {
		t.Fatalf("%s: value=%v err=%v clarification=%q", name, value, err, clarification)
	}
	for _, leaked := range []string{proposal.start, proposal.end, string(proposal.mode), zone} {
		if leaked != "" && (strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked)) {
			t.Fatalf("%s: refusal leaked %q", name, leaked)
		}
	}
}

func TestResolveRelativeBusinessDateV2ResolvesTodayAcrossZones(t *testing.T) {
	// Host timezone configuration must not influence the pinned resolver.
	t.Setenv("TZ", "Pacific/Kiritimati")
	t.Setenv("ZONEINFO", t.TempDir())
	today := relativeProposal(t, PeriodTODAY)
	for _, tc := range []struct {
		name, zone, wantStart, wantEnd string
		capturedAt                     time.Time
	}{
		{"UTC at midnight", "UTC", "2026-03-31", "2026-04-01", time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)},
		{"UTC before midnight", "UTC", "2026-03-31", "2026-04-01", time.Date(2026, 3, 31, 23, 59, 59, 999999999, time.UTC)},
		{"Moscow before midnight", "Europe/Moscow", "2026-03-31", "2026-04-01", time.Date(2026, 3, 31, 20, 59, 59, 0, time.UTC)},
		{"Moscow after midnight", "Europe/Moscow", "2026-04-01", "2026-04-02", time.Date(2026, 3, 31, 21, 0, 0, 0, time.UTC)},
		{"New York before midnight", "America/New_York", "2025-12-31", "2026-01-01", time.Date(2026, 1, 1, 4, 59, 59, 0, time.UTC)},
		{"New York at midnight", "America/New_York", "2026-01-01", "2026-01-02", time.Date(2026, 1, 1, 5, 0, 0, 0, time.UTC)},
		{"New York spring-forward day", "America/New_York", "2026-03-08", "2026-03-09", time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)},
		{"New York 25-hour fall-back day", "America/New_York", "2026-11-01", "2026-11-02", time.Date(2026, 11, 1, 16, 0, 0, 0, time.UTC)},
		{"canonical first year", "UTC", "0001-01-02", "0001-01-03", time.Date(1, 1, 2, 12, 0, 0, 0, time.UTC)},
	} {
		relativeBusinessDateAccepted(t, tc.name, today, tc.capturedAt, tc.zone, 1, tc.wantStart, tc.wantEnd)
	}
}

func TestResolveRelativeBusinessDateV2ResolvesCurrentMonthSpans(t *testing.T) {
	month := relativeProposal(t, PeriodCURRENTMONTH)
	for _, tc := range []struct {
		name, zone, wantStart, wantEnd string
		capturedAt                     time.Time
		maxPeriodDays                  int
	}{
		{"31-day month at exact budget", "UTC", "2026-03-01", "2026-04-01", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 31},
		{"30-day month at exact budget", "UTC", "2026-04-01", "2026-05-01", time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC), 30},
		{"leap February at exact budget", "UTC", "2024-02-01", "2024-03-01", time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC), 29},
		{"non-leap century February", "UTC", "2100-02-01", "2100-03-01", time.Date(2100, 2, 28, 12, 0, 0, 0, time.UTC), 28},
		{"December crosses into January", "UTC", "2026-12-01", "2027-01-01", time.Date(2026, 12, 31, 12, 0, 0, 0, time.UTC), 31},
		{"month chosen in the zone", "Pacific/Kiritimati", "2026-04-01", "2026-05-01", time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC), 30},
		{"canonical first year month", "UTC", "0001-01-01", "0001-02-01", time.Date(1, 1, 15, 12, 0, 0, 0, time.UTC), 31},
	} {
		relativeBusinessDateAccepted(t, tc.name, month, tc.capturedAt, tc.zone, tc.maxPeriodDays, tc.wantStart, tc.wantEnd)
	}
}

func TestResolveRelativeBusinessDateV2FallBackRepeatedHourIsOneCivilDay(t *testing.T) {
	proposal := relativeProposal(t, PeriodTODAY)
	first, firstErr := resolveRelativeBusinessDateV2(proposal, time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC), "America/New_York", 1)
	second, secondErr := resolveRelativeBusinessDateV2(proposal, time.Date(2026, 11, 1, 6, 30, 0, 0, time.UTC), "America/New_York", 1)
	if firstErr != nil || secondErr != nil || first != second {
		t.Fatalf("repeated fall-back hour differs: first=%v/%v second=%v/%v", first, firstErr, second, secondErr)
	}
	start, end, ok := first.Bounds()
	if !ok || start != "2026-11-01" || end != "2026-11-02" {
		t.Fatalf("repeated fall-back hour resolved %q..%q ok=%v", start, end, ok)
	}
}

func TestResolveRelativeBusinessDateV2SourceLocationDoesNotChangeInstant(t *testing.T) {
	proposal := relativeProposal(t, PeriodTODAY)
	instant := time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	sourceLocation := time.FixedZone("source", 11*60*60)
	utcValue, utcErr := resolveRelativeBusinessDateV2(proposal, instant, "America/New_York", 1)
	sourceValue, sourceErr := resolveRelativeBusinessDateV2(proposal, instant.In(sourceLocation), "America/New_York", 1)
	if utcErr != nil || sourceErr != nil || utcValue != sourceValue {
		t.Fatalf("source location changed result: UTC=%v/%v source=%v/%v", utcValue, utcErr, sourceValue, sourceErr)
	}
}

func TestResolveRelativeBusinessDateV2RefusesInvalidInput(t *testing.T) {
	today, month := relativeProposal(t, PeriodTODAY), relativeProposal(t, PeriodCURRENTMONTH)
	noon := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name          string
		proposal      PeriodProposal
		capturedAt    time.Time
		zone          string
		maxPeriodDays int
		code          ErrorCode
	}{
		{"31-day month one day too small", month, noon, "UTC", 30, CodePeriodLimitExceeded},
		{"30-day month one day too small", month, time.Date(2026, 4, 15, 12, 0, 0, 0, time.UTC), "UTC", 29, CodePeriodLimitExceeded},
		{"leap February one day too small", month, time.Date(2024, 2, 10, 12, 0, 0, 0, time.UTC), "UTC", 28, CodePeriodLimitExceeded},
		{"non-leap February one day too small", month, time.Date(2100, 2, 10, 12, 0, 0, 0, time.UTC), "UTC", 27, CodePeriodLimitExceeded},
		{"zero budget", today, noon, "UTC", 0, CodePeriodInvalid},
		{"negative budget", month, noon, "UTC", -1, CodePeriodInvalid},
		{"budget above maximum", month, noon, "UTC", 32, CodePeriodInvalid},
		{"budget precedes the clock", today, time.Time{}, "UTC", 0, CodePeriodInvalid},
		{"zero clock", today, time.Time{}, "UTC", 31, CodeTrustedNowRequired},
		{"zero proposal before zero clock", PeriodProposal{}, time.Time{}, "UTC", 31, CodePeriodInvalid},
		{"clock precedes the timezone", today, time.Time{}, "Local", 31, CodeTrustedNowRequired},
		{"explicit proposal", businessDateProposal(t, "2026-03-01", "2026-04-01"), noon, "UTC", 31, CodePeriodInvalid},
		{"latest-available proposal", relativeProposal(t, PeriodLATESTAVAILABLE), noon, "UTC", 31, CodePeriodInvalid},
		{"zero proposal", PeriodProposal{}, noon, "UTC", 31, CodePeriodInvalid},
		{"forged mixed proposal", PeriodProposal{mode: PeriodTODAY, start: "2026-03-01", end: "2026-04-01", initialized: true}, noon, "UTC", 31, CodePeriodInvalid},
		{"uninitialized proposal", PeriodProposal{mode: PeriodTODAY}, noon, "UTC", 31, CodePeriodInvalid},
		{"Local timezone", today, noon, "Local", 31, CodePeriodUnavailable},
		{"Etc/UTC timezone", today, noon, "Etc/UTC", 31, CodePeriodUnavailable},
		{"unknown timezone", today, noon, "Mars/Olympus", 31, CodePeriodUnavailable},
		{"empty timezone", today, noon, "", 31, CodePeriodUnavailable},
	} {
		relativeBusinessDateRefused(t, tc.name, tc.proposal, tc.capturedAt, tc.zone, tc.maxPeriodDays, tc.code)
	}
}

func TestResolveRelativeBusinessDateV2RefusesUnprojectableYears(t *testing.T) {
	today, month := relativeProposal(t, PeriodTODAY), relativeProposal(t, PeriodCURRENTMONTH)
	for _, tc := range []struct {
		name          string
		proposal      PeriodProposal
		capturedAt    time.Time
		zone          string
		maxPeriodDays int
		code          ErrorCode
	}{
		{"clock in year zero", today, time.Date(0, 12, 31, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"clock above the last year", today, time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"local date underflows year one", today, time.Date(1, 1, 1, 1, 0, 0, 0, time.UTC), "America/New_York", 31, CodePeriodUnavailable},
		{"local date overflows the last year", today, time.Date(9999, 12, 31, 12, 0, 0, 0, time.UTC), "Pacific/Kiritimati", 31, CodePeriodUnavailable},
		{"month end leaves the last year", month, time.Date(9999, 12, 15, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"projected range precedes the span check", month, time.Date(9999, 12, 15, 12, 0, 0, 0, time.UTC), "UTC", 1, CodePeriodUnavailable},
	} {
		relativeBusinessDateRefused(t, tc.name, tc.proposal, tc.capturedAt, tc.zone, tc.maxPeriodDays, tc.code)
	}
}
