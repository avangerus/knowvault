package queryintent

import (
	"reflect"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func v2ClockValidator(t *testing.T, catalog analytic.DatasetProfileCatalog, clock func() time.Time) ValidatorV2 {
	t.Helper()
	validator, err := NewValidatorV2WithClock(catalog, clock)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

func v2ClockAggregate(t *testing.T, profile analytic.DatasetProfile, mode PeriodMode) ProposalV2 {
	t.Helper()
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	parts.Period = v2Relative(t, mode)
	return v2SealAggregate(t, parts)
}

func TestNewValidatorV2WithClockConstructor(t *testing.T) {
	if validator, err := NewValidatorV2WithClock(analytic.DatasetProfileCatalog{}, nil); !reflect.DeepEqual(validator, ValidatorV2{}) {
		t.Fatalf("invalid catalog produced %v", validator)
	} else {
		v2ContentFreeV2(t, "invalid catalog precedes nil clock", CodeCatalogUnavailable, err)
	}
	catalog, _ := v2Base(t)
	validator, err := NewValidatorV2WithClock(catalog, nil)
	if !reflect.DeepEqual(validator, ValidatorV2{}) {
		t.Fatalf("nil clock produced %v", validator)
	}
	v2ContentFreeV2(t, "nil clock", CodeTrustedNowRequired, err)
}

func TestValidatorV2ExplicitNeverCallsClock(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, func() v2AggregateParts {
		parts := v2AggregatePartsFor(t, profile)
		parts.Filters = v2ValidatorFilters(t)
		return parts
	}())
	binding := v2Binding(t, catalog)
	called := 0
	clock := func() time.Time {
		called++
		return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	}
	for _, constructor := range []struct {
		name string
		make func() ValidatorV2
	}{
		{"without clock", func() ValidatorV2 {
			validator, err := NewValidatorV2(catalog)
			if err != nil {
				t.Fatal(err)
			}
			return validator
		}},
		{"with clock", func() ValidatorV2 { return v2ClockValidator(t, catalog, clock) }},
	} {
		t.Run(constructor.name, func(t *testing.T) {
			sealed, err := constructor.make().ValidateProposalV2(proposal, binding)
			if err != nil || !sealed.Valid() {
				t.Fatalf("explicit refused: valid=%v err=%v", sealed.Valid(), err)
			}
			if captured, ok := sealed.CapturedAt(); ok || captured != "" {
				t.Fatalf("explicit captured clock=%q/%v", captured, ok)
			}
		})
	}
	if called != 0 {
		t.Fatalf("explicit validation called clock %d times", called)
	}
}

func TestValidatorV2RelativeClockCanonicalizationAndDigest(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2ClockAggregate(t, profile, PeriodTODAY)
	binding := v2Binding(t, catalog)
	called := 0
	instant := time.Date(2026, 1, 15, 15, 4, 5, 123000000, time.FixedZone("source", 3*60*60))
	validator := v2ClockValidator(t, catalog, func() time.Time {
		called++
		return instant
	})
	sealed, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("relative refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if called != 1 {
		t.Fatalf("relative provider calls=%d, want 1", called)
	}
	resolved, ok := sealed.ResolvedPeriod()
	start, end, boundsOK := resolved.Bounds()
	if !ok || !boundsOK || start != "2026-01-15" || end != "2026-01-16" {
		t.Fatalf("resolved=%v bounds=%q..%q ok=%v", resolved, start, end, ok)
	}
	captured, capturedOK := sealed.CapturedAt()
	if !capturedOK || captured != "2026-01-15T12:04:05.123Z" {
		t.Fatalf("captured=%q/%v", captured, capturedOK)
	}
	projection, projectionOK := sealed.canonicalProjection()
	if !projectionOK || projection.TrustedNow == nil || *projection.TrustedNow != captured {
		t.Fatalf("projection=%+v ok=%v", projection, projectionOK)
	}
	raw, err := canon.CanonicalJSON(projection)
	if err != nil {
		t.Fatal(err)
	}
	digest, digestOK := sealed.Digest()
	if !digestOK || digest != canon.Hash(raw) {
		t.Fatalf("digest=%q/%v raw=%s", digest, digestOK, raw)
	}
	if !sealed.Valid() {
		t.Fatal("sealed relative value became invalid")
	}
	sealed.ResolvedPeriod()
	sealed.CapturedAt()
	sealed.Digest()
	if called != 1 {
		t.Fatalf("seal validity/accessors called provider %d times", called)
	}
	monthCalls := 0
	monthValidator := v2ClockValidator(t, catalog, func() time.Time {
		monthCalls++
		return instant
	})
	month, err := monthValidator.ValidateProposalV2(v2ClockAggregate(t, profile, PeriodCURRENTMONTH), binding)
	if err != nil || !month.Valid() {
		t.Fatalf("current month refused: valid=%v err=%v", month.Valid(), err)
	}
	monthPeriod, monthOK := month.ResolvedPeriod()
	monthStart, monthEnd, monthBoundsOK := monthPeriod.Bounds()
	if !monthOK || !monthBoundsOK || monthStart != "2026-01-01" || monthEnd != "2026-02-01" || monthCalls != 1 {
		t.Fatalf("current month=%v bounds=%q..%q calls=%d", monthPeriod, monthStart, monthEnd, monthCalls)
	}
}

func TestValidatorV2RelativeClockIdentityAndBounds(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2ClockAggregate(t, profile, PeriodTODAY)
	binding := v2Binding(t, catalog)
	validate := func(instant time.Time) ValidatedIntentV2 {
		validator := v2ClockValidator(t, catalog, func() time.Time { return instant })
		sealed, err := validator.ValidateProposalV2(proposal, binding)
		if err != nil || !sealed.Valid() {
			t.Fatalf("relative refused: valid=%v err=%v", sealed.Valid(), err)
		}
		return sealed
	}
	utc := validate(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	offset := validate(time.Date(2026, 1, 15, 15, 0, 0, 0, time.FixedZone("source", 3*60*60)))
	utcClock, utcClockOK := utc.CapturedAt()
	offsetClock, offsetClockOK := offset.CapturedAt()
	utcDigest, utcDigestOK := utc.Digest()
	offsetDigest, offsetDigestOK := offset.Digest()
	if !utcClockOK || !offsetClockOK || utcClock != offsetClock || !utcDigestOK || !offsetDigestOK || utcDigest != offsetDigest {
		t.Fatalf("same instant differs: %q/%v %q/%v; %q/%v %q/%v", utcClock, utcClockOK, offsetClock, offsetClockOK, utcDigest, utcDigestOK, offsetDigest, offsetDigestOK)
	}
	first := validate(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	second := validate(time.Date(2026, 1, 15, 13, 0, 0, 0, time.UTC))
	firstPeriod, firstOK := first.ResolvedPeriod()
	secondPeriod, secondOK := second.ResolvedPeriod()
	firstStart, firstEnd, firstBoundsOK := firstPeriod.Bounds()
	secondStart, secondEnd, secondBoundsOK := secondPeriod.Bounds()
	firstDigest, firstDigestOK := first.Digest()
	secondDigest, secondDigestOK := second.Digest()
	if !firstOK || !secondOK || !firstBoundsOK || !secondBoundsOK || firstStart != secondStart || firstEnd != secondEnd ||
		!firstDigestOK || !secondDigestOK || firstDigest == secondDigest {
		t.Fatalf("same-day bounds/digests: %q..%q/%q %q..%q/%q", firstStart, firstEnd, firstDigest, secondStart, secondEnd, secondDigest)
	}
}

func TestValidatorV2RelativeClockRefusals(t *testing.T) {
	catalog, profile := v2Base(t)
	proposal := v2ClockAggregate(t, profile, PeriodTODAY)
	binding := v2Binding(t, catalog)
	for _, test := range []struct {
		name  string
		clock time.Time
		code  ErrorCode
	}{
		{"zero clock", time.Time{}, CodeTrustedNowRequired},
		{"clock above supported year", time.Date(10000, 1, 1, 12, 0, 0, 0, time.UTC), CodePeriodUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := 0
			validator := v2ClockValidator(t, catalog, func() time.Time {
				called++
				return test.clock
			})
			sealed, err := validator.ValidateProposalV2(proposal, binding)
			v2RefusalV2(t, test.name, test.code, sealed, err)
			if called != 1 {
				t.Fatalf("provider calls=%d, want 1", called)
			}
		})
	}

	zoneProfile := resolutionProfile(t, analytic.TimeZonedTimestamp, "America/Havana", 1)
	zoneCatalog := v2Catalog(t, "catalog.havana", 1, v2Active(zoneProfile))
	parts := v2AggregatePartsFor(t, zoneProfile)
	parts.Filters = v2Predicates(t)
	parts.Period = v2Relative(t, PeriodTODAY)
	zoneProposal := v2SealAggregate(t, parts)
	called := 0
	validator := v2ClockValidator(t, zoneCatalog, func() time.Time {
		called++
		return time.Date(2026, 3, 8, 7, 30, 0, 0, time.UTC)
	})
	sealed, err := validator.ValidateProposalV2(zoneProposal, v2Binding(t, zoneCatalog))
	v2RefusalV2(t, "DST transition refusal", CodePeriodUnavailable, sealed, err)
	if called != 1 {
		t.Fatalf("DST provider calls=%d, want 1", called)
	}
}

func TestValidatorV2ClockNotCalledForEarlyRefusalsAndLatest(t *testing.T) {
	tests := []struct {
		name  string
		build func(*testing.T, func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode)
	}{
		{"invalid proposal", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, _ := v2Base(t)
			return v2ClockValidator(t, catalog, clock), ProposalV2{}, v2Binding(t, catalog), CodeInvalidProposal
		}},
		{"invalid catalog", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			return ValidatorV2{catalog: analytic.DatasetProfileCatalog{}, clock: clock}, v2ClockAggregate(t, profile, PeriodTODAY), v2Binding(t, catalog), CodeCatalogUnavailable
		}},
		{"binding mismatch", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			return v2ClockValidator(t, catalog, clock), v2ClockAggregate(t, profile, PeriodTODAY), CatalogBindingV2{}, CodeCatalogBindingMismatch
		}},
		{"profile unavailable", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			parts := v2AggregatePartsFor(t, profile)
			parts.Filters, parts.Period = v2ValidatorFilters(t), v2Relative(t, PeriodTODAY)
			parts.Dataset = v2RefFields(t, "missing", 1, profile.Hash())
			return v2ClockValidator(t, catalog, clock), v2SealAggregate(t, parts), v2Binding(t, catalog), CodeDatasetProfileUnavailable
		}},
		{"measure unavailable", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			parts := v2AggregatePartsFor(t, profile)
			parts.Filters, parts.Period, parts.Measure = v2ValidatorFilters(t), v2Relative(t, PeriodTODAY), v2Measure(t, "missing")
			return v2ClockValidator(t, catalog, clock), v2SealAggregate(t, parts), v2Binding(t, catalog), CodeMeasureUnavailable
		}},
		{"filter unavailable", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			parts := v2AggregatePartsFor(t, profile)
			parts.Filters, parts.Period = v2Predicates(t, v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01"))), v2Relative(t, PeriodTODAY)
			return v2ClockValidator(t, catalog, clock), v2SealAggregate(t, parts), v2Binding(t, catalog), CodeFilterNotAllowed
		}},
		{"shape unavailable", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			parts := v2AggregatePartsFor(t, profile)
			parts.Filters, parts.Period, parts.Dimensions = v2ValidatorFilters(t), v2Relative(t, PeriodTODAY), v2Dimensions(t, "missing")
			return v2ClockValidator(t, catalog, clock), v2SealAggregate(t, parts), v2Binding(t, catalog), CodeDimensionUnavailable
		}},
		{"latest available", func(t *testing.T, clock func() time.Time) (ValidatorV2, ProposalV2, CatalogBindingV2, ErrorCode) {
			catalog, profile := v2Base(t)
			return v2ClockValidator(t, catalog, clock), v2ClockAggregate(t, profile, PeriodLATESTAVAILABLE), v2Binding(t, catalog), CodePeriodUnavailable
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := 0
			clock := func() time.Time {
				called++
				return time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
			}
			validator, proposal, binding, code := test.build(t, clock)
			sealed, err := validator.ValidateProposalV2(proposal, binding)
			v2RefusalV2(t, test.name, code, sealed, err)
			if called != 0 {
				t.Fatalf("early refusal called provider %d times", called)
			}
		})
	}
}

func TestValidatorV2RelativeWithoutClockRefuses(t *testing.T) {
	catalog, profile := v2Base(t)
	sealed, err := v2Validator(t, catalog).ValidateProposalV2(v2ClockAggregate(t, profile, PeriodTODAY), v2Binding(t, catalog))
	v2RefusalV2(t, "relative without provider", CodeTrustedNowRequired, sealed, err)
}
