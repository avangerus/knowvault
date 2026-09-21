package queryintent

import (
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/tzrules"
)

// resolveRelativeZonedTimestampV2 resolves one valid relative proposal against a
// ZONED_TIMESTAMP field in the approved reporting timezone. Only TODAY and
// CURRENT_MONTH are accepted: each names a half-open range of local civil dates,
// the local date holding the trusted clock or the whole local calendar month
// holding it, and that range is then pinned to the unique UTC instants of its
// local midnights. The local date is derived exactly once from capturedAt; the
// projected bounds stay UTC surrogate local midnights and only the two canonical
// offset-free walls are handed to the pinned zone rules, so the target location
// is never passed to time.Date and no host zone database or alias
// canonicalization is consulted. The clock must be non-zero with a canonical UTC
// year, the zone must load from the tzrules bundle, both projected walls must
// stay inside years 1..9999, and the civil-date span must fit the profile day
// budget in 1..31. Validation priority is exactly proposal, budget, clock,
// timezone, projected years, span, boundary resolution. Every failure returns
// the zero period with a content-free refusal: CodePeriodInvalid for an unusable
// proposal or budget, CodeTrustedNowRequired for a missing clock,
// CodePeriodLimitExceeded for a wider span, and CodePeriodUnavailable for an
// unusable zone, an unprojectable year, a boundary that is a gap or a fold, or
// bounds that do not increase.
func resolveRelativeZonedTimestampV2(proposal PeriodProposal, capturedAt time.Time, reportingTimezone string, maxPeriodDays int) (ResolvedPeriodV2, error) {
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
	startInstant, startErr := tzrules.ResolveCivil(reportingTimezone, start.Format("2006-01-02T15:04:05"))
	endInstant, endErr := tzrules.ResolveCivil(reportingTimezone, end.Format("2006-01-02T15:04:05"))
	if startErr != nil || endErr != nil || !startInstant.Before(endInstant) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	value, err := newResolvedPeriodV2(proposal.mode, analytic.TimeZonedTimestamp, startInstant.UTC().Format(time.RFC3339Nano), endInstant.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodUnavailable)
	}
	return value, nil
}
