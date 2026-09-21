package queryintent

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// zonedTimestampRefused pins one whole refusal: the zero period, the
// content-free CodePeriodInvalid error with its clarification, no unwrap and no
// echoed bound text.
func zonedTimestampRefused(t *testing.T, name string, proposal PeriodProposal) {
	t.Helper()
	value, err := resolveExplicitZonedTimestampV2(proposal)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != CodePeriodInvalid ||
		err.Error() != string(CodePeriodInvalid) || ClarificationOf(err) != clarificationFor(CodePeriodInvalid) ||
		errors.Unwrap(err) != nil {
		t.Fatalf("%s: value=%v err=%v", name, value, err)
	}
	if start, end, ok := proposal.ExplicitBounds(); ok {
		for _, echoed := range []string{start, end} {
			if echoed != "" && (strings.Contains(err.Error(), echoed) || strings.Contains(ClarificationOf(err), echoed)) {
				t.Fatalf("%s: refusal leaked %q", name, echoed)
			}
		}
	}
}

func TestResolveExplicitZonedTimestampV2AcceptsCanonicalBounds(t *testing.T) {
	for _, tc := range []struct{ name, start, end, wantStart, wantEnd string }{
		{"Z bounds", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"},
		{"numeric offsets", "2026-01-01T09:30:00+09:30", "2026-01-01T12:00:00-11:00", "2026-01-01T00:00:00Z", "2026-01-01T23:00:00Z"},
		{"zero offsets", "2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00-00:00", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z"},
		{"maximum offsets", "2026-01-01T14:00:00+14:00", "2026-01-02T00:00:00-14:00", "2026-01-01T00:00:00Z", "2026-01-02T14:00:00Z"},
		{"fractions", "2026-01-01T00:00:00.5+02:00", "2026-01-01T00:00:01.123456789Z", "2025-12-31T22:00:00.5Z", "2026-01-01T00:00:01.123456789Z"},
		{"instants out of wall order", "2026-01-02T03:00:00+09:00", "2026-01-01T23:00:00Z", "2026-01-01T18:00:00Z", "2026-01-01T23:00:00Z"},
	} {
		value, err := resolveExplicitZonedTimestampV2(businessDateProposal(t, tc.start, tc.end))
		if err != nil || !value.Valid() {
			t.Fatalf("%s: value=%v err=%v", tc.name, value, err)
		}
		mode, modeOK := value.Mode()
		kind, kindOK := value.TimeKind()
		start, end, boundsOK := value.Bounds()
		if !modeOK || mode != PeriodEXPLICIT || !kindOK || kind != analytic.TimeZonedTimestamp ||
			!boundsOK || start != tc.wantStart || end != tc.wantEnd || value.IsLatestAvailable() {
			t.Fatalf("%s: resolved %q/%q %q..%q ok=%v/%v/%v", tc.name, mode, kind, start, end, modeOK, kindOK, boundsOK)
		}
	}
}

func TestResolveExplicitZonedTimestampV2RefusesMalformedBounds(t *testing.T) {
	const good = "2027-01-01T00:00:00Z"
	for _, bad := range []string{
		"2026-01-01T00:00:00",             // offset-free
		"2026-01-01T00:00:00.5",           // offset-free with fraction
		"2026-01-01T00:00:00ZPST",         // trailing text
		"2026-01-01T00:00:00.Z",           // empty fraction
		"2026-01-01T00:00:00.120Z",        // padded fraction
		"2026-01-01T00:00:00.000000000Z",  // all-zero fraction
		"2026-01-01T00:00:00.1234567890Z", // fraction beyond nanoseconds
		"2026-01-01T00:00:00+0300",        // offset without colon
		"2026-01-01T00:00:00+3:00",        // offset without leading zero
		"2026-01-01T00:00:00+03:0",        // short offset
		"2026-01-01T00:00:00+15:00",       // offset out of range
		"2026-01-01T00:00:00z",            // lowercase zone
		"2026-02-30T00:00:00Z",            // impossible date
		"2025-02-29T00:00:00Z",            // impossible leap day
		"2026-01-01T24:00:00Z",            // impossible clock
		"2026-01-01T00:00:60Z",            // impossible clock
		"2026-1-01T00:00:00Z",             // noncanonical date
		"0000-01-01T00:00:00Z",            // year zero
		"0001-01-01T00:00:00+14:00",       // normalizes below year one
	} {
		zonedTimestampRefused(t, bad+" as start", businessDateProposal(t, bad, good))
		zonedTimestampRefused(t, bad+" as end", businessDateProposal(t, "2026-01-01T00:00:00Z", bad))
	}
}

func TestResolveExplicitZonedTimestampV2RefusesNonIncreasingInstants(t *testing.T) {
	for _, tc := range []struct{ name, start, end string }{
		{"equal spellings", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"},
		{"equal instants across offsets", "2026-01-01T00:00:00Z", "2026-01-01T03:00:00+03:00"},
		{"equal instants across fractions", "2026-01-01T00:00:00.25Z", "2025-12-31T21:00:00.25-03:00"},
		{"reverse instants", "2026-01-01T05:00:02+05:00", "2026-01-01T00:00:01Z"},
	} {
		zonedTimestampRefused(t, tc.name, businessDateProposal(t, tc.start, tc.end))
	}
}

func TestResolveExplicitZonedTimestampV2RefusesRelativeAndForgedProposals(t *testing.T) {
	for _, mode := range []PeriodMode{PeriodTODAY, PeriodCURRENTMONTH, PeriodLATESTAVAILABLE} {
		relative, err := NewRelativePeriod(mode)
		if err != nil {
			t.Fatalf("NewRelativePeriod(%q) err=%v", mode, err)
		}
		zonedTimestampRefused(t, string(mode), relative)
	}
	for name, proposal := range map[string]PeriodProposal{
		"zero":             {},
		"uninitialized":    {mode: PeriodEXPLICIT, start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z"},
		"unknown mode":     {mode: "UNKNOWN", start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z", initialized: true},
		"mixed":            {mode: PeriodTODAY, start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z", initialized: true},
		"leading space":    {mode: PeriodEXPLICIT, start: " 2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z", initialized: true},
		"trailing space":   {mode: PeriodEXPLICIT, start: "2026-01-01T00:00:00Z", end: "2026-01-02T00:00:00Z ", initialized: true},
		"trailing newline": {mode: PeriodEXPLICIT, start: "2026-01-01T00:00:00Z\n", end: "2026-01-02T00:00:00Z", initialized: true},
	} {
		zonedTimestampRefused(t, name, proposal)
	}
}
