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

// businessDateRefused pins the whole refusal: the zero value, CodePeriodInvalid,
// a content-free typed error and clarification, no unwrap, no echoed text.
func businessDateRefused(t *testing.T, name string, proposal PeriodProposal) {
	t.Helper()
	value, err := resolveExplicitBusinessDateV2(proposal)
	clarification := ClarificationOf(err)
	if value != (ResolvedPeriodV2{}) || err == nil || CodeOf(err) != CodePeriodInvalid ||
		err.Error() != string(CodePeriodInvalid) || clarification != clarificationFor(CodePeriodInvalid) ||
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
	value, err := resolveExplicitBusinessDateV2(businessDateProposal(t, "2026-01-01", "2026-02-01"))
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
		businessDateRefused(t, pair[0]+".."+pair[1], businessDateProposal(t, pair[0], pair[1]))
	}
}

func TestResolveExplicitBusinessDateV2RefusesNoncanonicalBounds(t *testing.T) {
	for _, bad := range []string{
		"2026-02-30", "2025-02-29", "2026-13-01", "0000-01-01",
		"2026-1-01", "2026/01/01", "20260101",
		"2026-01-01T00:00:00", "2026-01-01T00:00:00Z",
	} {
		businessDateRefused(t, bad, businessDateProposal(t, bad, "2026-03-01"))
		businessDateRefused(t, bad, businessDateProposal(t, "2026-01-01", bad))
	}
}

func TestResolveExplicitBusinessDateV2RefusesRelativeAndForgedProposals(t *testing.T) {
	for _, mode := range []PeriodMode{PeriodTODAY, PeriodCURRENTMONTH, PeriodLATESTAVAILABLE} {
		relative, err := NewRelativePeriod(mode)
		if err != nil {
			t.Fatalf("NewRelativePeriod(%q) err=%v", mode, err)
		}
		businessDateRefused(t, string(mode), relative)
	}
	for name, proposal := range map[string]PeriodProposal{
		"zero":          {},
		"uninitialized": {mode: PeriodEXPLICIT, start: "2026-01-01", end: "2026-02-01"},
		"unknown mode":  {mode: "UNKNOWN", start: "2026-01-01", end: "2026-02-01", initialized: true},
		"mixed":         {mode: PeriodTODAY, start: "2026-01-01", end: "2026-02-01", initialized: true},
		"untrimmed":     {mode: PeriodEXPLICIT, start: " 2026-01-01", end: "2026-02-01", initialized: true},
	} {
		businessDateRefused(t, name, proposal)
	}
}
