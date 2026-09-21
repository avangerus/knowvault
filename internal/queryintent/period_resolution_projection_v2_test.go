package queryintent

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func projectionResolution(t *testing.T, kind analytic.TimeKind, proposal PeriodProposal, zone string, capturedAt time.Time) (periodResolutionV2, periodResolutionV2Projection) {
	t.Helper()
	profile := resolutionProfile(t, kind, zone, 31)
	resolution, err := resolvePeriodForProfileV2(profile, proposal, capturedAt)
	if err != nil {
		t.Fatal(err)
	}
	projected, ok := projectPeriodResolutionV2(proposal, resolution)
	if !ok {
		t.Fatal("projection refused valid resolution")
	}
	return resolution, projected
}

func TestProjectPeriodResolutionV2CanonicalBytes(t *testing.T) {
	explicitProposal := resolutionExplicit(t, "2026-03-01", "2026-03-02")
	_, explicit := projectionResolution(t, analytic.TimeBusinessDate, explicitProposal, "UTC", time.Time{})
	raw, err := canon.CanonicalJSON(explicit)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resolved_period":{"end":"2026-03-02","mode":"EXPLICIT","start":"2026-03-01","time_kind":"BUSINESS_DATE"},"trusted_now":null}`
	if string(raw) != want || explicit.TrustedNow != nil {
		t.Fatalf("explicit JSON=%s projection=%+v", raw, explicit)
	}

	relativeProposal := resolutionRelative(t, PeriodTODAY)
	_, relative := projectionResolution(t, analytic.TimeBusinessDate, relativeProposal, "UTC", time.Date(2026, 3, 15, 12, 0, 0, 123000000, time.UTC))
	raw, err = canon.CanonicalJSON(relative)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"resolved_period":{"end":"2026-03-16","mode":"TODAY","start":"2026-03-15","time_kind":"BUSINESS_DATE"},"trusted_now":"2026-03-15T12:00:00.123Z"}`
	if string(raw) != want || relative.TrustedNow == nil || *relative.TrustedNow != "2026-03-15T12:00:00.123Z" {
		t.Fatalf("relative JSON=%s projection=%+v", raw, relative)
	}
}

func TestProjectPeriodResolutionV2AcceptsZonedExplicitAndBusinessRelative(t *testing.T) {
	zonedProposal := resolutionExplicit(t, "2026-03-01T03:00:00+03:00", "2026-03-02T03:00:00+03:00")
	_, zoned := projectionResolution(t, analytic.TimeZonedTimestamp, zonedProposal, "UTC", time.Time{})
	if zoned.ResolvedPeriod.TimeKind != analytic.TimeZonedTimestamp || zoned.TrustedNow != nil ||
		zoned.ResolvedPeriod.Start != "2026-03-01T00:00:00Z" {
		t.Fatalf("zoned projection=%+v", zoned)
	}
	relativeProposal := resolutionRelative(t, PeriodCURRENTMONTH)
	_, business := projectionResolution(t, analytic.TimeBusinessDate, relativeProposal, "Europe/Moscow", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	if business.ResolvedPeriod.Mode != PeriodCURRENTMONTH || business.TrustedNow == nil ||
		*business.TrustedNow != "2026-03-15T12:00:00Z" {
		t.Fatalf("business projection=%+v", business)
	}
	proposal := resolutionRelative(t, PeriodTODAY)
	_, zonedRelative := projectionResolution(t, analytic.TimeZonedTimestamp, proposal, "America/New_York", time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC))
	raw, err := canon.CanonicalJSON(zonedRelative)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resolved_period":{"end":"2026-03-09T04:00:00Z","mode":"TODAY","start":"2026-03-08T05:00:00Z","time_kind":"ZONED_TIMESTAMP"},"trusted_now":"2026-03-08T07:30:00Z"}`
	if string(raw) != want {
		t.Fatalf("zoned relative JSON=%s", raw)
	}
}

func TestProjectPeriodResolutionV2AcceptsLocalKinds(t *testing.T) {
	explicitProposal := resolutionExplicit(t, "2026-03-15T00:00:00", "2026-03-16T00:00:00")
	explicitPeriod, _ := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeLocalTimestamp, "2026-03-15T00:00:00", "2026-03-16T00:00:00")
	explicit, ok := projectPeriodResolutionV2(explicitProposal, periodResolutionV2{period: explicitPeriod, initialized: true})
	if !ok || explicit.ResolvedPeriod.TimeKind != analytic.TimeLocalTimestamp || explicit.TrustedNow != nil {
		t.Fatalf("explicit local projection=%+v/%v", explicit, ok)
	}
	relativeProposal := resolutionRelative(t, PeriodTODAY)
	relativePeriod, _ := newResolvedPeriodV2(PeriodTODAY, analytic.TimeLocalTimestamp, "2026-03-15T00:00:00", "2026-03-16T00:00:00")
	relative, ok := projectPeriodResolutionV2(relativeProposal, periodResolutionV2{
		period: relativePeriod, trustedNowUTC: "2026-03-15T12:00:00Z", initialized: true,
	})
	if !ok || relative.ResolvedPeriod.Start != "2026-03-15T00:00:00" || relative.ResolvedPeriod.End != "2026-03-16T00:00:00" ||
		relative.TrustedNow == nil || *relative.TrustedNow != "2026-03-15T12:00:00Z" {
		t.Fatalf("relative local projection=%+v/%v", relative, ok)
	}
}

func TestProjectPeriodResolutionV2RejectsMalformedInputs(t *testing.T) {
	proposal := resolutionRelative(t, PeriodTODAY)
	resolved, _ := projectionResolution(t, analytic.TimeBusinessDate, proposal, "UTC", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	period, _ := resolved.ResolvedPeriod()
	for _, tc := range []struct {
		name       string
		proposal   PeriodProposal
		resolution periodResolutionV2
	}{
		{"zero proposal", PeriodProposal{}, resolved},
		{"zero resolution", proposal, periodResolutionV2{}},
		{"mode mismatch", resolutionExplicit(t, "2026-03-01", "2026-03-02"), resolved},
		{"forged", proposal, periodResolutionV2{period: period, trustedNowUTC: "2026-03-15T12:00:00Z", initialized: false}},
		{"latest", resolutionRelative(t, PeriodLATESTAVAILABLE), periodResolutionV2{period: resolvedV2(t, PeriodLATESTAVAILABLE, analytic.TimeBusinessDate, "", ""), initialized: true}},
		{"noncanonical clock", proposal, periodResolutionV2{period: period, trustedNowUTC: "2026-03-15T12:00:00+00:00", initialized: true}},
		{"none kind", proposal, periodResolutionV2{period: ResolvedPeriodV2{mode: PeriodTODAY, timeKind: analytic.TimeNone, start: "2026-03-15", end: "2026-03-16", initialized: true}, trustedNowUTC: "2026-03-15T12:00:00Z", initialized: true}},
		{"unknown kind", proposal, periodResolutionV2{period: ResolvedPeriodV2{mode: PeriodTODAY, timeKind: analytic.TimeKind("UNKNOWN"), start: "2026-03-15", end: "2026-03-16", initialized: true}, trustedNowUTC: "2026-03-15T12:00:00Z", initialized: true}},
		{"no bounds", proposal, periodResolutionV2{period: ResolvedPeriodV2{mode: PeriodTODAY, timeKind: analytic.TimeBusinessDate, initialized: true}, trustedNowUTC: "2026-03-15T12:00:00Z", initialized: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if projected, ok := projectPeriodResolutionV2(tc.proposal, tc.resolution); ok || projected != (periodResolutionV2Projection{}) {
				t.Fatalf("projected=%+v ok=%v", projected, ok)
			}
		})
	}
}

func TestProjectPeriodResolutionV2DeterministicAndDetached(t *testing.T) {
	proposal := resolutionRelative(t, PeriodTODAY)
	resolution, first := projectionResolution(t, analytic.TimeBusinessDate, proposal, "UTC", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	_, second := projectionResolution(t, analytic.TimeBusinessDate, proposal, "UTC", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	firstJSON, _ := canon.CanonicalJSON(first)
	secondJSON, _ := canon.CanonicalJSON(second)
	if !bytes.Equal(firstJSON, secondJSON) || !reflect.DeepEqual(first, second) {
		t.Fatalf("repeat differs: %s / %s or %+v / %+v", firstJSON, secondJSON, first, second)
	}
	*first.TrustedNow = "mutated"
	if trusted, ok := resolution.TrustedNowUTC(); !ok || trusted != "2026-03-15T12:00:00Z" {
		t.Fatalf("projection mutation changed resolution=%q/%v", trusted, ok)
	}
	_, third := projectionResolution(t, analytic.TimeBusinessDate, proposal, "UTC", time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC))
	if third.TrustedNow == nil || *third.TrustedNow != "2026-03-15T12:00:00Z" {
		t.Fatalf("reprojection after mutation=%+v", third)
	}
}
