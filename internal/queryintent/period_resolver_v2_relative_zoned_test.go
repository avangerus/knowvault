package queryintent

import (
	"errors"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

// zonedRelativeAccepted resolves one relative ZONED_TIMESTAMP proposal twice and
// pins the whole result: no error, the same value on repeat, the proposal mode,
// the ZONED_TIMESTAMP kind, the canonical UTC bounds and no latest-available
// flag.
func zonedRelativeAccepted(t *testing.T, name string, proposal PeriodProposal, capturedAt time.Time, zone string, maxPeriodDays int, wantStart, wantEnd string) {
	t.Helper()
	value, err := resolveRelativeZonedTimestampV2(proposal, capturedAt, zone, maxPeriodDays)
	again, againErr := resolveRelativeZonedTimestampV2(proposal, capturedAt, zone, maxPeriodDays)
	if err != nil || againErr != nil || !value.Valid() || value != again {
		t.Fatalf("%s: value=%v err=%v again=%v againErr=%v", name, value, err, again, againErr)
	}
	mode, modeOK := value.Mode()
	kind, kindOK := value.TimeKind()
	start, end, boundsOK := value.Bounds()
	if !modeOK || mode != proposal.mode || !kindOK || kind != analytic.TimeZonedTimestamp ||
		!boundsOK || start != wantStart || end != wantEnd || value.IsLatestAvailable() {
		t.Fatalf("%s: resolved %q/%q %q..%q ok=%v/%v/%v", name, mode, kind, start, end, modeOK, kindOK, boundsOK)
	}
}

// zonedRelativeRefused pins one whole refusal: the zero period, the exact
// content-free code and clarification, no unwrap and no echoed zone or proposal
// text.
func zonedRelativeRefused(t *testing.T, name string, proposal PeriodProposal, capturedAt time.Time, zone string, maxPeriodDays int, code ErrorCode) {
	t.Helper()
	value, err := resolveRelativeZonedTimestampV2(proposal, capturedAt, zone, maxPeriodDays)
	clarification := ClarificationOf(err)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != code ||
		err.Error() != string(code) || clarification != clarificationFor(code) || errors.Unwrap(err) != nil {
		t.Fatalf("%s: value=%v err=%v clarification=%q", name, value, err, clarification)
	}
	for _, leaked := range []string{zone, string(proposal.mode), proposal.start, proposal.end} {
		if leaked != "" && (strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked)) {
			t.Fatalf("%s: refusal leaked %q", name, leaked)
		}
	}
}

func TestResolveRelativeZonedTimestampV2AcceptsUTCAndMoscow(t *testing.T) {
	today, month := relativeProposal(t, PeriodTODAY), relativeProposal(t, PeriodCURRENTMONTH)
	for _, tc := range []struct {
		name, zone, wantStart, wantEnd string
		proposal                       PeriodProposal
		capturedAt                     time.Time
		maxPeriodDays                  int
	}{
		{"UTC at midnight", "UTC", "2026-03-31T00:00:00Z", "2026-04-01T00:00:00Z", today, time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), 1},
		{"UTC last nanosecond", "UTC", "2026-03-31T00:00:00Z", "2026-04-01T00:00:00Z", today, time.Date(2026, 3, 31, 23, 59, 59, 999999999, time.UTC), 1},
		{"Moscow before local midnight", "Europe/Moscow", "2026-03-30T21:00:00Z", "2026-03-31T21:00:00Z", today, time.Date(2026, 3, 31, 20, 59, 59, 0, time.UTC), 1},
		{"Moscow at local midnight", "Europe/Moscow", "2026-03-31T21:00:00Z", "2026-04-01T21:00:00Z", today, time.Date(2026, 3, 31, 21, 0, 0, 0, time.UTC), 1},
		{"Moscow month at exact budget", "Europe/Moscow", "2026-02-28T21:00:00Z", "2026-03-31T21:00:00Z", month, time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC), 31},
		{"UTC month at exact budget", "UTC", "2026-04-01T00:00:00Z", "2026-05-01T00:00:00Z", month, time.Date(2026, 4, 30, 23, 59, 59, 0, time.UTC), 30},
	} {
		zonedRelativeAccepted(t, tc.name, tc.proposal, tc.capturedAt, tc.zone, tc.maxPeriodDays, tc.wantStart, tc.wantEnd)
	}
}

func TestResolveRelativeZonedTimestampV2NewYorkTransitionDays(t *testing.T) {
	today := relativeProposal(t, PeriodTODAY)
	for _, tc := range []struct {
		name, wantStart, wantEnd string
		capturedAt               time.Time
		want                     time.Duration
	}{
		{"spring-forward day is 23 hours", "2026-03-08T05:00:00Z", "2026-03-09T04:00:00Z", time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC), 23 * time.Hour},
		{"fall-back day is 25 hours", "2026-11-01T04:00:00Z", "2026-11-02T05:00:00Z", time.Date(2026, 11, 1, 16, 0, 0, 0, time.UTC), 25 * time.Hour},
	} {
		zonedRelativeAccepted(t, tc.name, today, tc.capturedAt, "America/New_York", 1, tc.wantStart, tc.wantEnd)
		value, err := resolveRelativeZonedTimestampV2(today, tc.capturedAt, "America/New_York", 1)
		start, end, _ := value.Bounds()
		startAt, startErr := time.Parse(time.RFC3339Nano, start)
		endAt, endErr := time.Parse(time.RFC3339Nano, end)
		if err != nil || startErr != nil || endErr != nil || endAt.Sub(startAt) != tc.want {
			t.Fatalf("%s: bounds %q..%q span %v err=%v/%v/%v", tc.name, start, end, endAt.Sub(startAt), err, startErr, endErr)
		}
	}
}

func TestResolveRelativeZonedTimestampV2RefusesHavanaMidnightTransitions(t *testing.T) {
	// Havana starts DST at local midnight (a gap) and ends it at local midnight
	// (a fold), so those local days have no unique start or end instant.
	today, month := relativeProposal(t, PeriodTODAY), relativeProposal(t, PeriodCURRENTMONTH)
	zonedRelativeRefused(t, "spring-forward midnight is a gap", today, time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC), "America/Havana", 1, CodePeriodUnavailable)
	zonedRelativeRefused(t, "fall-back midnight is a fold", today, time.Date(2026, 11, 1, 16, 0, 0, 0, time.UTC), "America/Havana", 1, CodePeriodUnavailable)
	// The local day before each transition starts at a unique midnight but ends
	// on the gap or the fold itself, so the day is refused.
	zonedRelativeRefused(t, "day before the spring-forward gap", today, time.Date(2026, 3, 7, 17, 0, 0, 0, time.UTC), "America/Havana", 1, CodePeriodUnavailable)
	zonedRelativeRefused(t, "day before the fall-back fold", today, time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC), "America/Havana", 1, CodePeriodUnavailable)
	zonedRelativeRefused(t, "November month starts in the fold", month, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), "America/Havana", 31, CodePeriodUnavailable)
	// The span is refused before either boundary is resolved: November is 30
	// civil days wide and this budget holds only 29.
	zonedRelativeRefused(t, "November month past the budget", month, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), "America/Havana", 29, CodePeriodLimitExceeded)
}

func TestResolveRelativeZonedTimestampV2SourceLocationAndHostZoneInvariance(t *testing.T) {
	// Host timezone configuration must not influence the pinned resolver.
	t.Setenv("TZ", "Pacific/Kiritimati")
	t.Setenv("ZONEINFO", t.TempDir())
	today := relativeProposal(t, PeriodTODAY)
	instant := time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	source := time.FixedZone("source", 11*60*60)
	utcValue, utcErr := resolveRelativeZonedTimestampV2(today, instant, "America/New_York", 1)
	sourceValue, sourceErr := resolveRelativeZonedTimestampV2(today, instant.In(source), "America/New_York", 1)
	if utcErr != nil || sourceErr != nil || utcValue != sourceValue {
		t.Fatalf("source location changed result: UTC=%v/%v source=%v/%v", utcValue, utcErr, sourceValue, sourceErr)
	}
	zonedRelativeAccepted(t, "repeated call", today, instant, "America/New_York", 1, "2026-03-08T05:00:00Z", "2026-03-09T04:00:00Z")
}

func TestResolveRelativeZonedTimestampV2RefusesInvalidInput(t *testing.T) {
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
		{"clock in year zero", today, time.Date(0, 12, 31, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"clock above the last year", today, time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"local date underflows year one", today, time.Date(1, 1, 1, 1, 0, 0, 0, time.UTC), "America/New_York", 31, CodePeriodUnavailable},
		// Moscow keeps the projected walls in civil year 1, but its local
		// midnight is three hours behind UTC and so underflows into year zero.
		{"local midnight underflows the first UTC year", today, time.Date(1, 1, 1, 12, 0, 0, 0, time.UTC), "Europe/Moscow", 1, CodePeriodUnavailable},
		{"local date overflows the last year", today, time.Date(9999, 12, 31, 12, 0, 0, 0, time.UTC), "Pacific/Kiritimati", 31, CodePeriodUnavailable},
		{"month end leaves the last year", month, time.Date(9999, 12, 15, 12, 0, 0, 0, time.UTC), "UTC", 31, CodePeriodUnavailable},
		{"projected range precedes the span check", month, time.Date(9999, 12, 15, 12, 0, 0, 0, time.UTC), "UTC", 1, CodePeriodUnavailable},
	} {
		zonedRelativeRefused(t, tc.name, tc.proposal, tc.capturedAt, tc.zone, tc.maxPeriodDays, tc.code)
	}
}
