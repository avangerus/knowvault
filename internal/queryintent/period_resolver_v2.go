package queryintent

import (
	"time"

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

// resolveExplicitZonedTimestampV2 resolves one already-valid EXPLICIT proposal
// against a ZONED_TIMESTAMP field: both bounds must be canonical RFC3339Nano
// instants with an explicit Z or numeric offset, each normalized to UTC ending
// in Z, and the two instants must be strictly increasing. Nothing is trimmed,
// coerced or defaulted here, and no relative mode is resolved. Every failure
// returns the zero period with a content-free CodePeriodInvalid refusal.
func resolveExplicitZonedTimestampV2(proposal PeriodProposal) (ResolvedPeriodV2, error) {
	if !proposal.Valid() || proposal.mode != PeriodEXPLICIT {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	start, end, ok := proposal.ExplicitBounds()
	if !ok {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	startAt, startUTC, startOK := zonedTimestampV2Instant(start)
	endAt, endUTC, endOK := zonedTimestampV2Instant(end)
	if !startOK || !endOK || !startAt.Before(endAt) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	value, err := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeZonedTimestamp, startUTC, endUTC)
	if err != nil {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	return value, nil
}

// zonedTimestampV2Instant parses one canonical RFC3339Nano bound with an
// explicit Z or numeric offset and returns its instant together with the UTC
// spelling of that instant. The wall fields, offset and fraction are rechecked
// here: a zero-padded fraction is refused because the canonical spelling trims
// it, and anything offset-free or padded fails before the parse.
func zonedTimestampV2Instant(value string) (time.Time, string, bool) {
	tail, ok := wallTail(value)
	if !ok || tail != "Z" && !validOffset(tail) {
		return time.Time{}, "", false
	}
	if frac := value[19 : len(value)-len(tail)]; frac != "" && frac[len(frac)-1] == '0' {
		return time.Time{}, "", false
	}
	instant, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, "", false
	}
	return instant, instant.UTC().Format(time.RFC3339Nano), true
}

// resolveExplicitZonedTimestampUTCV2 resolves one already-valid EXPLICIT
// proposal against a ZONED_TIMESTAMP field under one profile day budget. The
// accepted zoned-timestamp resolver parses, normalizes both bounds to UTC and
// checks strict ordering first: every failure it reports is returned unchanged.
// The budget must then be a legal ProfileLimits day budget in 1..31, and the
// half-open range [start, end) may cover at most that many UTC reporting
// calendar dates, counted from the UTC date holding start through the UTC date
// holding the last included instant immediately before end. An illegal budget
// refuses with CodePeriodInvalid, a wider span with CodePeriodLimitExceeded.
func resolveExplicitZonedTimestampUTCV2(proposal PeriodProposal, maxPeriodDays int) (ResolvedPeriodV2, error) {
	value, err := resolveExplicitZonedTimestampV2(proposal)
	if err != nil {
		return ResolvedPeriodV2{}, err
	}
	if maxPeriodDays < 1 || maxPeriodDays > 31 {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	start, end, boundsOK := value.Bounds()
	startAt, startOK := resolvedPeriodV2Instant(analytic.TimeZonedTimestamp, start)
	endAt, endOK := resolvedPeriodV2Instant(analytic.TimeZonedTimestamp, end)
	if !boundsOK || !startOK || !endOK {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodInvalid)
	}
	lastIncluded := utcCivilDateV2(endAt.Add(-time.Nanosecond))
	if lastIncluded.After(utcCivilDateV2(startAt).AddDate(0, 0, maxPeriodDays-1)) {
		return ResolvedPeriodV2{}, newRefusal(CodePeriodLimitExceeded)
	}
	return value, nil
}

// utcCivilDateV2 returns the midnight UTC civil date containing instant.
func utcCivilDateV2(instant time.Time) time.Time {
	year, month, day := instant.UTC().Date()
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}
