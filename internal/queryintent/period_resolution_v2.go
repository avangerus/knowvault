package queryintent

import (
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

// periodResolutionV2 seals a resolved period together with the trusted clock
// used for relative modes. Its fields remain private so callers can only obtain
// a value after all envelope invariants have been rechecked.
type periodResolutionV2 struct {
	period        ResolvedPeriodV2
	trustedNowUTC string
	initialized   bool
}

func (value periodResolutionV2) Valid() bool {
	if !value.initialized || !value.period.Valid() {
		return false
	}
	switch value.period.mode {
	case PeriodEXPLICIT:
		return value.trustedNowUTC == ""
	case PeriodTODAY, PeriodCURRENTMONTH:
		return validTrustedNowUTCV2(value.trustedNowUTC)
	default:
		return false
	}
}

func validTrustedNowUTCV2(value string) bool {
	if value == "" {
		return false
	}
	instant, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && instant.UTC().Year() >= 1 && instant.UTC().Year() <= 9999 &&
		instant.UTC().Format(time.RFC3339Nano) == value
}

// ResolvedPeriod returns the sealed resolved period when the envelope is valid.
func (value periodResolutionV2) ResolvedPeriod() (ResolvedPeriodV2, bool) {
	if !value.Valid() {
		return ResolvedPeriodV2{}, false
	}
	return value.period, true
}

// TrustedNowUTC returns the canonical UTC clock for a relative resolution.
func (value periodResolutionV2) TrustedNowUTC() (string, bool) {
	if !value.Valid() || value.period.mode == PeriodEXPLICIT {
		return "", false
	}
	return value.trustedNowUTC, true
}

// resolvePeriodForProfileV2 dispatches period resolution using only the
// approved profile's time policy and period budget.
func resolvePeriodForProfileV2(profile analytic.DatasetProfile, proposal PeriodProposal, capturedAt time.Time) (periodResolutionV2, error) {
	if !profile.Valid() || !proposal.Valid() {
		return periodResolutionV2{}, newRefusal(CodePeriodInvalid)
	}
	policy, limits := profile.Time().Values(), profile.Limits().Values()
	var (
		period ResolvedPeriodV2
		err    error
	)
	switch proposal.mode {
	case PeriodEXPLICIT:
		switch policy.Kind {
		case analytic.TimeBusinessDate:
			period, err = resolveExplicitBusinessDateV2(proposal, limits.MaxPeriodDays)
		case analytic.TimeZonedTimestamp:
			if policy.ReportingTimezone != "UTC" {
				return periodResolutionV2{}, newRefusal(CodePeriodUnavailable)
			}
			period, err = resolveExplicitZonedTimestampUTCV2(proposal, limits.MaxPeriodDays)
		default:
			return periodResolutionV2{}, newRefusal(CodePeriodUnavailable)
		}
	case PeriodTODAY, PeriodCURRENTMONTH:
		switch policy.Kind {
		case analytic.TimeBusinessDate:
			period, err = resolveRelativeBusinessDateV2(proposal, capturedAt, policy.ReportingTimezone, limits.MaxPeriodDays)
		case analytic.TimeZonedTimestamp:
			period, err = resolveRelativeZonedTimestampV2(proposal, capturedAt, policy.ReportingTimezone, limits.MaxPeriodDays)
		default:
			return periodResolutionV2{}, newRefusal(CodePeriodUnavailable)
		}
	case PeriodLATESTAVAILABLE:
		return periodResolutionV2{}, newRefusal(CodePeriodUnavailable)
	default:
		return periodResolutionV2{}, newRefusal(CodePeriodInvalid)
	}
	if err != nil {
		return periodResolutionV2{}, err
	}
	clock := ""
	if proposal.mode != PeriodEXPLICIT {
		clock = capturedAt.UTC().Format(time.RFC3339Nano)
	}
	value := periodResolutionV2{period: period, trustedNowUTC: clock, initialized: true}
	if !value.Valid() {
		return periodResolutionV2{}, newRefusal(CodePeriodUnavailable)
	}
	return value, nil
}
