package queryintent

import (
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/tzrules"
)

// resolveRelativeBusinessDateV2 resolves one valid relative proposal against a
// BUSINESS_DATE field in the approved reporting timezone. Only TODAY and
// CURRENT_MONTH are accepted, and each resolves to a half-open range of
// canonical local dates: the single local date holding the trusted clock, or the
// whole local calendar month holding it. The local date is derived exactly once
// from capturedAt; all later arithmetic runs on UTC surrogate midnights, so no
// local midnight, host zone database or alias canonicalization is consulted.
// The clock must be non-zero with a canonical UTC year, the zone must load from
// the pinned tzrules bundle, both projected dates must stay inside years
// 1..9999, and the span must fit the profile day budget in 1..31. Validation
// priority is exactly proposal, budget, clock, timezone, projected years, span.
// Every failure returns the zero period with a content-free refusal:
// CodePeriodInvalid for an unusable proposal or budget, CodeTrustedNowRequired
// for a missing clock, CodePeriodUnavailable for an unusable zone or an
// unprojectable year, and CodePeriodLimitExceeded for a wider span.
func resolveRelativeBusinessDateV2(proposal PeriodProposal, capturedAt time.Time, reportingTimezone string, maxPeriodDays int) (ResolvedPeriodV2, error) {
	if !proposal.Valid() || proposal.mode != PeriodTODAY && proposal.mode != PeriodCURRENTMONTH {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	if maxPeriodDays < 1 || maxPeriodDays > 31 {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	if capturedAt.IsZero() {
		return ResolvedPeriodV2{}, newRefusal(CodeTrustedNowRequired)
	}
	if year := capturedAt.UTC().Year(); year < 1 || year > 9999 {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	location, err := tzrules.Load(reportingTimezone)
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	year, month, day := capturedAt.In(location).Date()
	start := time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
	end := start.AddDate(0, 0, 1)
	if proposal.mode == PeriodCURRENTMONTH {
		start = time.Date(year, month, 1, 0, 0, 0, 0, time.UTC)
		end = start.AddDate(0, 1, 0)
	}
	if start.Year() < 1 || start.Year() > 9999 || end.Year() < 1 || end.Year() > 9999 {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	if end.After(start.AddDate(0, 0, maxPeriodDays)) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodLimitExceeded)
	}
	value, err := newResolvedPeriodV2(proposal.mode, analytic.TimeBusinessDate, start.Format("2006-01-02"), end.Format("2006-01-02"))
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	return value, nil
}
