package queryintent

import (
	"knowvault.local/verified-workspace/internal/analytic"
)

// resolveExplicitBusinessDateV2 resolves one already-valid EXPLICIT proposal
// against a BUSINESS_DATE field under one profile day budget. Both bounds must
// already be canonical real YYYY-MM-DD dates in strictly increasing calendar
// order: nothing is trimmed, coerced or defaulted, and no relative mode is
// resolved here. The budget must be a legal ProfileLimits day budget in 1..31,
// and the half-open range [start, end) may span at most that many calendar
// days, counted with Gregorian calendar arithmetic. Every failure returns the
// zero period with a content-free refusal: CodePeriodInvalid for a malformed
// proposal or an out-of-range budget, and CodePeriodLimitExceeded when the
// range is wider than the budget.
func resolveExplicitBusinessDateV2(proposal PeriodProposal, maxPeriodDays int) (ResolvedPeriodV2, error) {
	if maxPeriodDays < 1 || maxPeriodDays > 31 {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
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
	if endAt.After(startAt.AddDate(0, 0, maxPeriodDays)) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodLimitExceeded)
	}
	value, err := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeBusinessDate, start, end)
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	return value, nil
}
