package queryintent

import "knowvault.local/verified-workspace/internal/analytic"

type periodResolutionV2ProjectedPeriod struct {
	Mode     PeriodMode        `json:"mode"`
	TimeKind analytic.TimeKind `json:"time_kind"`
	Start    string            `json:"start"`
	End      string            `json:"end"`
}

type periodResolutionV2Projection struct {
	ResolvedPeriod periodResolutionV2ProjectedPeriod `json:"resolved_period"`
	TrustedNow     *string                           `json:"trusted_now"`
}

func projectPeriodResolutionV2(proposal PeriodProposal, resolution periodResolutionV2) (periodResolutionV2Projection, bool) {
	if !proposal.Valid() || !resolution.Valid() {
		return periodResolutionV2Projection{}, false
	}
	proposalMode, proposalOK := proposal.Mode()
	period, periodOK := resolution.ResolvedPeriod()
	mode, modeOK := period.Mode()
	kind, kindOK := period.TimeKind()
	start, end, boundsOK := period.Bounds()
	if !proposalOK || !periodOK || !modeOK || !kindOK || !boundsOK || proposalMode != mode ||
		!kind.Valid() || kind == analytic.TimeNone || start == "" || end == "" {
		return periodResolutionV2Projection{}, false
	}
	projected := periodResolutionV2Projection{
		ResolvedPeriod: periodResolutionV2ProjectedPeriod{Mode: mode, TimeKind: kind, Start: start, End: end},
	}
	switch mode {
	case PeriodEXPLICIT:
	case PeriodTODAY, PeriodCURRENTMONTH:
		trusted, trustedOK := resolution.TrustedNowUTC()
		if !trustedOK {
			return periodResolutionV2Projection{}, false
		}
		projected.TrustedNow = &trusted
	default:
		return periodResolutionV2Projection{}, false
	}
	return projected, true
}
