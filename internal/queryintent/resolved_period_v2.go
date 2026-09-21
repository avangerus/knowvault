package queryintent

import (
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
)

// ResolvedPeriodV2 is one resolved, canonical period: the period mode, the
// closed time kind of the approved profile field the period was resolved
// against, and the canonical bounds when the mode carries any. It is a
// value-only type: every field is unexported, no exported constructor exists,
// and no catalog, profile, SQL, question or run identity is stored. All fields
// are comparable, so two equal resolved periods compare equal with ==.
type ResolvedPeriodV2 struct {
	mode        PeriodMode
	timeKind    analytic.TimeKind
	start       string
	end         string
	initialized bool
}

// newResolvedPeriodV2 resolves one period against the time kind of the approved
// field it was resolved for. The mode must be EXPLICIT, TODAY, CURRENT_MONTH or
// LATEST_AVAILABLE, the kind must be BUSINESS_DATE, LOCAL_TIMESTAMP or
// ZONED_TIMESTAMP, and the bounds must be canonically encoded for that kind and
// strictly increasing, except for LATEST_AVAILABLE, which carries no bounds.
// Every failure returns the zero value with a content-free CodeInvalidProposal
// refusal.
func newResolvedPeriodV2(mode PeriodMode, kind analytic.TimeKind, start, end string) (ResolvedPeriodV2, error) {
	value := ResolvedPeriodV2{mode: mode, timeKind: kind, start: start, end: end, initialized: true}
	if !value.Valid() {
		return ResolvedPeriodV2{}, newRefusal(CodeInvalidProposal)
	}
	return value, nil
}

// Valid reports whether this resolved period is well formed. It rejects the zero
// value and every forged or tampered copy by rechecking all stored state: the
// mode, the kind, the bound policy, each bound's canonical encoding and the
// strict bound ordering. It never consults live profile or catalog state.
func (value ResolvedPeriodV2) Valid() bool {
	if !value.initialized || !value.mode.Valid() || !value.timeKind.Valid() ||
		value.timeKind == analytic.TimeNone {
		return false
	}
	if value.mode == PeriodLATESTAVAILABLE {
		return value.start == "" && value.end == ""
	}
	start, startOK := resolvedPeriodV2Instant(value.timeKind, value.start)
	end, endOK := resolvedPeriodV2Instant(value.timeKind, value.end)
	return startOK && endOK && start.Before(end)
}

// resolvedPeriodV2Instant parses one canonical bound and returns the instant it
// compares by: the calendar value for BUSINESS_DATE (exact real YYYY-MM-DD), the
// wall fields for LOCAL_TIMESTAMP (offset-free with a trimmed fraction), and the
// instant for ZONED_TIMESTAMP (exact UTC RFC3339Nano ending Z). Every
// non-canonical form fails: for LOCAL_TIMESTAMP a parse followed by reformat
// must reproduce the input, and for ZONED_TIMESTAMP any offset other than Z
// reformats differently, so the resolver must normalize before construction.
func resolvedPeriodV2Instant(kind analytic.TimeKind, value string) (time.Time, bool) {
	switch kind {
	case analytic.TimeBusinessDate:
		if !validDate(value) {
			return time.Time{}, false
		}
		instant, err := time.Parse("2006-01-02", value)
		return instant, err == nil
	case analytic.TimeLocalTimestamp:
		tail, ok := wallTail(value)
		if !ok || tail != "" {
			return time.Time{}, false
		}
		instant, err := time.Parse("2006-01-02T15:04:05", value)
		if err != nil || strings.TrimSuffix(instant.Format(time.RFC3339Nano), "Z") != value {
			return time.Time{}, false
		}
		return instant, true
	case analytic.TimeZonedTimestamp:
		tail, ok := wallTail(value)
		if !ok || (tail != "Z" && !validOffset(tail)) {
			return time.Time{}, false
		}
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil || instant.UTC().Format(time.RFC3339Nano) != value {
			return time.Time{}, false
		}
		return instant, true
	default:
		return time.Time{}, false
	}
}

// Mode is the resolved period mode.
func (value ResolvedPeriodV2) Mode() (PeriodMode, bool) {
	if !value.Valid() {
		return "", false
	}
	return value.mode, true
}

// TimeKind is the time kind of the approved field the period was resolved for.
func (value ResolvedPeriodV2) TimeKind() (analytic.TimeKind, bool) {
	if !value.Valid() {
		return "", false
	}
	return value.timeKind, true
}

// Bounds are the canonical start and end in request order. A LATEST_AVAILABLE
// period carries none, so it reports false with two empty strings, as does
// every invalid value.
func (value ResolvedPeriodV2) Bounds() (string, string, bool) {
	if !value.Valid() || value.mode == PeriodLATESTAVAILABLE {
		return "", "", false
	}
	return value.start, value.end, true
}

// IsLatestAvailable reports whether this period asks for the latest available
// data instead of fixed bounds; the zero and every forged value report false.
func (value ResolvedPeriodV2) IsLatestAvailable() bool {
	return value.Valid() && value.mode == PeriodLATESTAVAILABLE
}
