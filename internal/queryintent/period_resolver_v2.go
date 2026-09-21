package queryintent

import (
	"knowvault.local/verified-workspace/internal/analytic"
)

// resolveExplicitBusinessDateV2 resolves one already-valid EXPLICIT proposal
// against a BUSINESS_DATE field. Both bounds must already be canonical real
// YYYY-MM-DD dates in strictly increasing calendar order: nothing is trimmed,
// coerced or defaulted, and no relative mode is resolved here. Every failure
// returns the zero period with a content-free CodePeriodInvalid refusal.
func resolveExplicitBusinessDateV2(proposal PeriodProposal) (ResolvedPeriodV2, error) {
	if !proposal.Valid() || proposal.mode != PeriodEXPLICIT {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	start, end, ok := proposal.ExplicitBounds()
	if !ok {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	startAt, startOK := resolvedPeriodV2Instant(analytic.TimeBusinessDate, start)
	endAt, endOK := resolvedPeriodV2Instant(analytic.TimeBusinessDate, end)
	if !startOK || !endOK || !startAt.Before(endAt) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	value, err := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeBusinessDate, start, end)
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	return value, nil
}
