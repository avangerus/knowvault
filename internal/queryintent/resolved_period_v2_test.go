package queryintent

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// resolvedV2Kinds maps each valid time kind to a canonical, increasing pair.
var resolvedV2Kinds = map[analytic.TimeKind][2]string{
	analytic.TimeBusinessDate:   {"2026-01-01", "2026-02-01"},
	analytic.TimeLocalTimestamp: {"2026-01-01T08:00:00", "2026-02-01T09:30:00.25"},
	analytic.TimeZonedTimestamp: {"2026-01-01T08:00:00Z", "2026-02-01T09:30:00.25Z"},
}

func resolvedV2(t *testing.T, mode PeriodMode, kind analytic.TimeKind, start, end string) ResolvedPeriodV2 {
	t.Helper()
	value, err := newResolvedPeriodV2(mode, kind, start, end)
	if err != nil || !value.Valid() {
		t.Fatalf("newResolvedPeriodV2(%q, %q, %q, %q) valid=%v err=%v", mode, kind, start, end, value.Valid(), err)
	}
	return value
}

// resolvedV2Refused pins the whole refusal: the zero value, the typed code, a
// content-free message and clarification, no unwrap and no echoed input.
func resolvedV2Refused(t *testing.T, mode PeriodMode, kind analytic.TimeKind, start, end string) {
	t.Helper()
	value, err := newResolvedPeriodV2(mode, kind, start, end)
	clarification := ClarificationOf(err)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != CodeInvalidProposal ||
		err.Error() != string(CodeInvalidProposal) || clarification == "" ||
		clarification != clarificationFor(CodeInvalidProposal) || errors.Unwrap(err) != nil {
		t.Fatalf("refusal %q/%q %q..%q: value=%v code=%q text=%q err=%v",
			mode, kind, start, end, value, CodeOf(err), clarification, err)
	}
	for _, leaked := range []string{string(mode), string(kind), start, end} {
		if leaked != "" && (strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked)) {
			t.Fatalf("refusal %q/%q leaked %q", mode, kind, leaked)
		}
	}
}

func TestResolvedPeriodV2AcceptsEveryModeAndKind(t *testing.T) {
	for kind, bounds := range resolvedV2Kinds {
		latest := resolvedV2(t, PeriodLATESTAVAILABLE, kind, "", "")
		if !latest.IsLatestAvailable() {
			t.Fatal("latest-available period not reported", kind)
		}
		if start, end, ok := latest.Bounds(); ok || start != "" || end != "" {
			t.Fatal("latest-available bounds readable", start, end, ok)
		}
		if got, ok := latest.Mode(); !ok || got != PeriodLATESTAVAILABLE {
			t.Fatal(got, ok)
		}
		for _, mode := range []PeriodMode{PeriodEXPLICIT, PeriodTODAY, PeriodCURRENTMONTH} {
			value := resolvedV2(t, mode, kind, bounds[0], bounds[1])
			gotMode, modeOK := value.Mode()
			gotKind, kindOK := value.TimeKind()
			start, end, boundsOK := value.Bounds()
			if !modeOK || gotMode != mode || !kindOK || gotKind != kind ||
				!boundsOK || start != bounds[0] || end != bounds[1] {
				t.Fatal(mode, kind, gotMode, gotKind, start, end, boundsOK)
			}
			if value.IsLatestAvailable() {
				t.Fatal("bounded period reported latest-available", mode, kind)
			}
		}
	}
}

func TestResolvedPeriodV2RefusesUnknownKindAndMode(t *testing.T) {
	for _, kind := range []analytic.TimeKind{analytic.TimeNone, "", "DATE", "business_date", "UTC"} {
		resolvedV2Refused(t, PeriodTODAY, kind, "2026-01-01", "2026-02-01")
	}
	for _, mode := range []PeriodMode{"", "Explicit", "EXPLICIT ", "UNKNOWN", "CURRENT-MONTH"} {
		resolvedV2Refused(t, mode, analytic.TimeBusinessDate, "2026-01-01", "2026-02-01")
	}
}

func TestResolvedPeriodV2RefusesBoundPolicyFailures(t *testing.T) {
	for kind, bounds := range resolvedV2Kinds {
		start, end := bounds[0], bounds[1]
		for _, pair := range [][2]string{
			{"", ""}, {"", end}, {start, ""}, {end, start}, {start, start},
		} {
			resolvedV2Refused(t, PeriodEXPLICIT, kind, pair[0], pair[1])
		}
		for _, mode := range []PeriodMode{PeriodTODAY, PeriodCURRENTMONTH} {
			resolvedV2Refused(t, mode, kind, "", "")
			resolvedV2Refused(t, mode, kind, "", end)
			resolvedV2Refused(t, mode, kind, start, "")
		}
		resolvedV2Refused(t, PeriodLATESTAVAILABLE, kind, start, end)
		resolvedV2Refused(t, PeriodLATESTAVAILABLE, kind, start, "")
		resolvedV2Refused(t, PeriodLATESTAVAILABLE, kind, "", end)
	}
	// Ordering is never textual: a trimmed fraction extends the whole second it
	// follows, although it sorts before Z or end-of-input as text.
	resolvedV2(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T08:00:00Z", "2026-01-01T08:00:00.5Z")
	resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T08:00:00.5Z", "2026-01-01T08:00:00Z")
	resolvedV2(t, PeriodEXPLICIT, analytic.TimeLocalTimestamp, "2026-01-01T08:00:00", "2026-01-01T08:00:00.5")
	resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeLocalTimestamp, "2026-01-01T08:00:00.5", "2026-01-01T08:00:00")
}

func TestResolvedPeriodV2RefusesNoncanonicalDates(t *testing.T) {
	for _, bad := range []string{
		"2026-02-30", "2025-02-29", "2026-13-01", "2026-00-10", "2026-01-00", "0000-01-01",
		"2026-1-01", "2026-01-1", "26-01-01", "2026/01/01", "20260101", "2026-01-01T00:00:00",
		"2026-01-01Z", "2026-01-01 ", " 2026-01-01",
	} {
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeBusinessDate, bad, "2026-03-01")
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeBusinessDate, "2026-01-01", bad)
	}
}

func TestResolvedPeriodV2RefusesNoncanonicalWallTimestamps(t *testing.T) {
	for _, bad := range []string{
		"2026-01-01T08:00:00Z", "2026-01-01T08:00:00+00:00", "2026-01-01T08:00:00-03:00",
		"2026-01-01 08:00:00", "2026-01-01t08:00:00", "2026-01-01T8:00:00", "2026-01-01T08:00",
		"2026-01-01T08:00:00.", "2026-01-01T08:00:00,5", "2026-01-01T08:00:00.250",
		"2026-01-01T08:00:00.000", "2026-01-01T08:00:00.1234567890", "2026-01-01T24:00:00",
		"2026-01-01T08:60:00", "2026-01-01T08:00:60", "2026-02-30T08:00:00",
	} {
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeLocalTimestamp, bad, "2026-03-01T00:00:00")
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeLocalTimestamp, "2026-01-01T00:00:00", bad)
	}
	// A trimmed fraction is canonical: no trailing zeros, at most nine digits.
	value := resolvedV2(t, PeriodEXPLICIT, analytic.TimeLocalTimestamp,
		"2026-01-01T08:00:00.5", "2026-01-01T08:00:00.500000001")
	if start, _, ok := value.Bounds(); !ok || start != "2026-01-01T08:00:00.5" {
		t.Fatal(start, ok)
	}
}

func TestResolvedPeriodV2RefusesNoncanonicalZonedTimestamps(t *testing.T) {
	for _, bad := range []string{
		"2026-01-01T08:00:00", "2026-01-01T08:00:00z", "2026-01-01T08:00:00+00:00",
		"2026-01-01T08:00:00-03:30", "2026-01-01T08:00:00+05:00", "2026-01-01T08:00:00.500Z",
		"2026-01-01T08:00:00.0Z", "2026-01-01T08:00:00.1234567890Z", "2026-01-01T08:00:00Z ",
		"2026-01-01T24:00:00Z", "2026-02-30T08:00:00Z", "0000-01-01T08:00:00Z",
	} {
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, bad, "2026-03-01T00:00:00Z")
		resolvedV2Refused(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T00:00:00Z", bad)
	}
}

func TestResolvedPeriodV2ZeroAndForgedAreInvalid(t *testing.T) {
	for _, value := range []ResolvedPeriodV2{
		{},
		{mode: PeriodTODAY, initialized: true},
		{mode: PeriodTODAY, timeKind: analytic.TimeNone, initialized: true},
		{mode: "UNKNOWN", timeKind: analytic.TimeBusinessDate, start: "2026-01-01", end: "2026-02-01", initialized: true},
		{mode: PeriodTODAY, timeKind: analytic.TimeBusinessDate, initialized: true},
		{mode: PeriodEXPLICIT, timeKind: analytic.TimeBusinessDate, start: "2026-02-01", end: "2026-01-01", initialized: true},
		{mode: PeriodEXPLICIT, timeKind: analytic.TimeBusinessDate, start: "2026-01-01", end: "2026-01-01", initialized: true},
		{mode: PeriodEXPLICIT, timeKind: analytic.TimeBusinessDate, start: "2026-1-01", end: "2026-02-01", initialized: true},
		{mode: PeriodEXPLICIT, timeKind: analytic.TimeZonedTimestamp, start: "2026-01-01T08:00:00+05:00", end: "2026-02-01T00:00:00Z", initialized: true},
		{mode: PeriodLATESTAVAILABLE, timeKind: analytic.TimeBusinessDate, start: "forged", initialized: true},
	} {
		if value.Valid() {
			t.Fatal("forged resolved period valid", value)
		}
		if _, ok := value.Mode(); ok {
			t.Fatal("invalid mode readable")
		}
		if _, ok := value.TimeKind(); ok {
			t.Fatal("invalid kind readable")
		}
		if start, end, ok := value.Bounds(); ok || start != "" || end != "" {
			t.Fatal("invalid bounds readable", start, end)
		}
		if value.IsLatestAvailable() {
			t.Fatal("invalid period reported latest-available")
		}
	}
}

func TestResolvedPeriodV2EqualInputsCompareEqual(t *testing.T) {
	left := resolvedV2(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T08:00:00Z", "2026-01-02T08:00:00Z")
	right := resolvedV2(t, PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T08:00:00Z", "2026-01-02T08:00:00Z")
	if left != right {
		t.Fatal("equal inputs did not compare equal")
	}
	other := resolvedV2(t, PeriodCURRENTMONTH, analytic.TimeZonedTimestamp, "2026-01-01T08:00:00Z", "2026-01-02T08:00:00Z")
	if left == other {
		t.Fatal("different modes compared equal")
	}
}
