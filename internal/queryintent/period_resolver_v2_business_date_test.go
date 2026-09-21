package queryintent

import (
	"errors"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/analytic"
)

// businessDateProposal builds a valid EXPLICIT proposal whose loosely checked
// bounds the resolver must still re-check: NewExplicitPeriod accepts any
// bounded text, not necessarily a canonical date.
func businessDateProposal(t *testing.T, start, end string) PeriodProposal {
	t.Helper()
	proposal, err := NewExplicitPeriod(start, end)
	if err != nil {
		t.Fatalf("NewExplicitPeriod(%q, %q) err=%v", start, end, err)
	}
	return proposal
}

// businessDateRefused pins one whole refusal for the given budget: the zero
// value, the expected code as a content-free typed error and clarification, no
// unwrap and no echoed text. The budget is a parameter so illegal budgets are
// pinned the same way.
func businessDateRefused(t *testing.T, name string, proposal PeriodProposal, maxPeriodDays int, code ErrorCode) {
	t.Helper()
	value, err := resolveExplicitBusinessDateV2(proposal, maxPeriodDays)
	clarification := ClarificationOf(err)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != code ||
		err.Error() != string(code) || clarification != clarificationFor(code) ||
		errors.Unwrap(err) != nil {
		t.Fatalf("%s: value=%v err=%v clarification=%q", name, value, err, clarification)
	}
	for _, leaked := range []string{proposal.start, proposal.end, string(proposal.mode)} {
		if leaked != "" && (strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked)) {
			t.Fatalf("%s: refusal leaked %q", name, leaked)
		}
	}
}

func TestResolveExplicitBusinessDateV2AcceptsCanonicalRange(t *testing.T) {
	value, err := resolveExplicitBusinessDateV2(businessDateProposal(t, "2026-01-01", "2026-02-01"), 31)
	if err != nil || !value.Valid() {
		t.Fatalf("canonical range refused: value=%v err=%v", value, err)
	}
	mode, modeOK := value.Mode()
	kind, kindOK := value.TimeKind()
	start, end, boundsOK := value.Bounds()
	if !modeOK || mode != PeriodEXPLICIT || !kindOK || kind != analytic.TimeBusinessDate ||
		!boundsOK || start != "2026-01-01" || end != "2026-02-01" || value.IsLatestAvailable() {
		t.Fatalf("resolved %q/%q %q..%q ok=%v/%v/%v", mode, kind, start, end, modeOK, kindOK, boundsOK)
	}
}

func TestResolveExplicitBusinessDateV2RefusesNonIncreasingRange(t *testing.T) {
	for _, pair := range [][2]string{
		{"2026-01-01", "2026-01-01"},
		{"2026-02-01", "2026-01-01"},
	} {
		businessDateRefused(t, pair[0]+".."+pair[1], businessDateProposal(t, pair[0], pair[1]), 31, CodePeriodInvalid)
	}
}

func TestResolveExplicitBusinessDateV2RefusesNoncanonicalBounds(t *testing.T) {
	for _, bad := range []string{
		"2026-02-30", "2025-02-29", "2026-13-01", "0000-01-01",
		"2026-1-01", "2026/01/01", "20260101",
		"2026-01-01T00:00:00", "2026-01-01T00:00:00Z",
	} {
		businessDateRefused(t, bad, businessDateProposal(t, bad, "2026-03-01"), 31, CodePeriodInvalid)
		businessDateRefused(t, bad, businessDateProposal(t, "2026-01-01", bad), 31, CodePeriodInvalid)
	}
}

func TestResolveExplicitBusinessDateV2RefusesRelativeAndForgedProposals(t *testing.T) {
	for _, mode := range []PeriodMode{PeriodTODAY, PeriodCURRENTMONTH, PeriodLATESTAVAILABLE} {
		relative, err := NewRelativePeriod(mode)
		if err != nil {
			t.Fatalf("NewRelativePeriod(%q) err=%v", mode, err)
		}
		businessDateRefused(t, string(mode), relative, 31, CodePeriodInvalid)
	}
	for name, proposal := range map[string]PeriodProposal{
		"zero":          {},
		"uninitialized": {mode: PeriodEXPLICIT, start: "2026-01-01", end: "2026-02-01"},
		"unknown mode":  {mode: "UNKNOWN", start: "2026-01-01", end: "2026-02-01", initialized: true},
		"mixed":         {mode: PeriodTODAY, start: "2026-01-01", end: "2026-02-01", initialized: true},
		"untrimmed":     {mode: PeriodEXPLICIT, start: " 2026-01-01", end: "2026-02-01", initialized: true},
	} {
		businessDateRefused(t, name, proposal, 31, CodePeriodInvalid)
	}
}

func TestResolveExplicitBusinessDateV2AcceptsRangesWithinDayBudget(t *testing.T) {
	for _, tc := range []struct {
		name          string
		start, end    string
		maxPeriodDays int
	}{
		{"full month at maximum budget", "2026-01-01", "2026-02-01", 31},
		{"full month at exact budget", "2026-01-01", "2026-01-31", 30},
		{"narrower than budget", "2026-01-01", "2026-01-02", 31},
		{"leap-day month at exact budget", "2024-02-01", "2024-03-01", 29},
		{"leap day at exact budget", "2024-02-28", "2024-03-01", 2},
	} {
		value, err := resolveExplicitBusinessDateV2(businessDateProposal(t, tc.start, tc.end), tc.maxPeriodDays)
		if err != nil || !value.Valid() {
			t.Fatalf("%s: value=%v err=%v", tc.name, value, err)
		}
		start, end, boundsOK := value.Bounds()
		if !boundsOK || start != tc.start || end != tc.end {
			t.Fatalf("%s: resolved %q..%q ok=%v", tc.name, start, end, boundsOK)
		}
	}
}

func TestResolveExplicitBusinessDateV2RefusesRangesWiderThanDayBudget(t *testing.T) {
	for _, tc := range []struct {
		name          string
		start, end    string
		maxPeriodDays int
	}{
		{"one day wider than budget", "2026-01-01", "2026-02-01", 30},
		{"one day wider than leap-day budget", "2024-02-01", "2024-03-01", 28},
		{"leap day wider than budget", "2024-02-28", "2024-03-01", 1},
		{"far wider than budget", "2026-01-01", "2026-03-01", 1},
	} {
		businessDateRefused(t, tc.name, businessDateProposal(t, tc.start, tc.end), tc.maxPeriodDays, CodePeriodLimitExceeded)
	}
}

func TestResolveExplicitBusinessDateV2RefusesInvalidDayBudget(t *testing.T) {
	for _, tc := range []struct {
		name          string
		start, end    string
		maxPeriodDays int
	}{
		{"zero budget", "2026-01-01", "2026-01-02", 0},
		{"negative budget", "2026-01-01", "2026-01-02", -1},
		{"budget above maximum", "2026-01-01", "2026-02-01", 32},
		{"huge budget", "2026-01-01", "2026-01-02", 1000},
	} {
		businessDateRefused(t, tc.name, businessDateProposal(t, tc.start, tc.end), tc.maxPeriodDays, CodePeriodInvalid)
	}
}
