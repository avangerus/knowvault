package queryintent

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// v2Binding builds the exact binding of one installed catalog snapshot.
func v2Binding(t *testing.T, catalog analytic.DatasetProfileCatalog) CatalogBindingV2 {
	t.Helper()
	binding, err := NewCatalogBindingV2(catalog.ID(), catalog.Revision(), catalog.Hash())
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func v2Validator(t *testing.T, catalog analytic.DatasetProfileCatalog) ValidatorV2 {
	t.Helper()
	validator, err := NewValidatorV2(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return validator
}

// v2ContentFreeV2 pins one generic refusal: the exact typed code, the generic
// clarification for that code, no unwrapping, and no echoed fixture content.
func v2ContentFreeV2(t *testing.T, name string, code ErrorCode, err error) {
	t.Helper()
	clarification := ClarificationOf(err)
	if err == nil || CodeOf(err) != code || err.Error() != string(code) || clarification == "" ||
		clarification != clarificationFor(code) || errors.Unwrap(err) != nil {
		t.Fatalf("%s: code=%q clarification=%q err=%v", name, CodeOf(err), clarification, err)
	}
	for _, leaked := range []string{"alpha", "beta", "gamma", "catalog.operations", "catalog.other", "sha256:", "amount", "region"} {
		if strings.Contains(err.Error(), leaked) || strings.Contains(clarification, leaked) {
			t.Fatalf("%s: refusal leaked %q in %q", name, leaked, clarification)
		}
	}
}

// v2RefusalV2 additionally requires a refusal to return the zero sealed value.
func v2RefusalV2(t *testing.T, name string, code ErrorCode, sealed ValidatedIntentV2, err error) {
	t.Helper()
	v2ContentFreeV2(t, name, code, err)
	if !reflect.DeepEqual(sealed, ValidatedIntentV2{}) {
		t.Fatalf("%s: refusal returned %v", name, sealed)
	}
}

// v2ValidatorFilters replaces the R1.2f baseline filter set with the one the
// R1.2g filter policy allows the v2Base profile: business_day is not filterable,
// so these baselines filter on the filterable region field instead.
func v2ValidatorFilters(t *testing.T) Predicates {
	t.Helper()
	return v2Predicates(t, v2Predicate(t, "region", OpEQ, v2Text(t, "north")))
}

func TestValidatorV2ValidAggregateAndLookup(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	proposal := v2SealAggregate(t, parts)

	sealed, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("aggregate refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if id, ok := sealed.CatalogID(); !ok || id != catalog.ID() {
		t.Fatalf("catalog id=%q ok=%v", id, ok)
	}
	if revision, ok := sealed.CatalogRevision(); !ok || revision != catalog.Revision() {
		t.Fatalf("catalog revision=%d ok=%v", revision, ok)
	}
	if hash, ok := sealed.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("catalog hash=%q ok=%v", hash, ok)
	}
	if limits, ok := sealed.Limits(); !ok || limits != profile.Limits() {
		t.Fatalf("limits=%v ok=%v", limits, ok)
	}
	if coverage, ok := sealed.Coverage(); !ok || coverage != profile.Coverage() {
		t.Fatalf("coverage=%q ok=%v", coverage, ok)
	}
	direct := v2Seal(t, catalog, profile, proposal)
	if !reflect.DeepEqual(sealed, direct) || v2Digest(t, sealed) != v2Digest(t, direct) {
		t.Fatal("the validator sealed a different value than the direct seal")
	}

	lookupParts := v2LookupPartsFor(t, profile)
	lookupParts.Filters = v2ValidatorFilters(t)
	lookup, err := validator.ValidateProposalV2(v2SealLookup(t, lookupParts), binding)
	if err != nil || !lookup.Valid() {
		t.Fatalf("lookup refused: valid=%v err=%v", lookup.Valid(), err)
	}
	if _, ok := lookup.Measure(); ok {
		t.Fatal("LOOKUP sealed an AGGREGATE measure")
	}
	if hash, ok := lookup.CatalogHash(); !ok || hash != catalog.Hash() {
		t.Fatalf("lookup catalog hash=%q ok=%v", hash, ok)
	}
	if v2Digest(t, lookup) == v2Digest(t, sealed) {
		t.Fatal("LOOKUP and AGGREGATE sealed the same digest")
	}
}

func TestValidatorV2RefusesInvalidProposalFirst(t *testing.T) {
	catalog, profile := v2Base(t)
	validator := v2Validator(t, catalog)
	mixed := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	mixed.operation = OperationLOOKUP
	cases := map[string]ProposalV2{"zero proposal": {}, "mixed shape": mixed}
	for name, proposal := range cases {
		sealed, err := validator.ValidateProposalV2(proposal, v2Binding(t, catalog))
		v2RefusalV2(t, name, CodeInvalidProposal, sealed, err)
	}
	sealed, err := ValidatorV2{}.ValidateProposalV2(ProposalV2{}, CatalogBindingV2{})
	v2RefusalV2(t, "proposal before the invalid validator", CodeInvalidProposal, sealed, err)
}

func TestValidatorV2ConstructorRefusesInvalidCatalog(t *testing.T) {
	validator, err := NewValidatorV2(analytic.DatasetProfileCatalog{})
	if !reflect.DeepEqual(validator, ValidatorV2{}) {
		t.Fatalf("invalid catalog produced %v", validator)
	}
	v2ContentFreeV2(t, "invalid catalog", CodeCatalogUnavailable, err)

	catalog, profile := v2Base(t)
	proposal := v2SealAggregate(t, v2AggregatePartsFor(t, profile))
	sealed, err := ValidatorV2{}.ValidateProposalV2(proposal, v2Binding(t, catalog))
	v2RefusalV2(t, "zero validator", CodeCatalogUnavailable, sealed, err)
}

func TestCatalogBindingV2ShapeAndImmutability(t *testing.T) {
	zero := CatalogBindingV2{}
	if zero.Valid() {
		t.Fatal("zero binding reported valid")
	}
	if id, ok := zero.ID(); ok || id != "" {
		t.Fatalf("zero ID=%q ok=%v", id, ok)
	}
	if revision, ok := zero.Revision(); ok || revision != 0 {
		t.Fatalf("zero Revision=%d ok=%v", revision, ok)
	}
	if hash, ok := zero.Hash(); ok || hash != "" {
		t.Fatalf("zero Hash=%q ok=%v", hash, ok)
	}

	catalog, _ := v2Base(t)
	bad := []struct {
		name     string
		id       string
		revision int64
		hash     string
	}{
		{"empty id", "", 7, catalog.Hash()},
		{"untrimmed id", " catalog.operations", 7, catalog.Hash()},
		{"control id", "catalog\noperations", 7, catalog.Hash()},
		{"zero revision", catalog.ID(), 0, catalog.Hash()},
		{"negative revision", catalog.ID(), -1, catalog.Hash()},
		{"empty hash", catalog.ID(), 7, ""},
		{"untagged hash", catalog.ID(), 7, strings.Repeat("0", 64)},
		{"uppercase hash", catalog.ID(), 7, "sha256:" + strings.Repeat("A", 64)},
	}
	for _, test := range bad {
		binding, err := NewCatalogBindingV2(test.id, test.revision, test.hash)
		if !reflect.DeepEqual(binding, CatalogBindingV2{}) {
			t.Fatalf("%s produced %v", test.name, binding)
		}
		v2ContentFreeV2(t, test.name, CodeInvalidProposal, err)
	}

	binding := v2Binding(t, catalog)
	if id, ok := binding.ID(); !ok || id != catalog.ID() {
		t.Fatalf("ID=%q ok=%v", id, ok)
	}
	if revision, ok := binding.Revision(); !ok || revision != catalog.Revision() {
		t.Fatalf("Revision=%d ok=%v", revision, ok)
	}
	if hash, ok := binding.Hash(); !ok || hash != catalog.Hash() {
		t.Fatalf("Hash=%q ok=%v", hash, ok)
	}
	copied := binding
	copied.id, copied.revision = "catalog.other", 0
	copied.hash = "sha256:" + strings.Repeat("0", 64)
	if id, ok := binding.ID(); !ok || id != catalog.ID() {
		t.Fatalf("mutating a copy reached the original: id=%q ok=%v", id, ok)
	}
	if copied.Valid() {
		t.Fatal("tampered copy reported valid")
	}
}

func TestValidatorV2RefusesBindingDriftAndProfileAuthority(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	other := v2Profile(t, "beta", 1, analytic.CoverageUnknown, v2Limits(t, 10000))
	otherCatalog := v2Catalog(t, "catalog.other", 1, v2Active(other))
	refTo := func(datasetID string, version int64, hash string) ProposalV2 {
		return v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
			parts.Dataset = v2RefFields(t, datasetID, version, hash)
		}))
	}
	proposal := refTo("alpha", 1, profile.Hash())

	drift := []struct {
		name    string
		binding CatalogBindingV2
	}{
		{"zero binding", CatalogBindingV2{}},
		{"id drift", CatalogBindingV2{id: otherCatalog.ID(), revision: catalog.Revision(), hash: catalog.Hash()}},
		{"revision drift", CatalogBindingV2{id: catalog.ID(), revision: catalog.Revision() + 1, hash: catalog.Hash()}},
		{"hash drift", CatalogBindingV2{id: catalog.ID(), revision: catalog.Revision(), hash: otherCatalog.Hash()}},
	}
	for _, test := range drift {
		sealed, err := validator.ValidateProposalV2(proposal, test.binding)
		v2RefusalV2(t, test.name, CodeCatalogBindingMismatch, sealed, err)
	}

	retired := v2Catalog(t, "catalog.retired", 3, v2Retired(profile))
	resolution := []struct {
		name     string
		catalog  analytic.DatasetProfileCatalog
		binding  CatalogBindingV2
		proposal ProposalV2
	}{
		{"unknown dataset", catalog, binding, refTo("gamma", 1, profile.Hash())},
		{"unknown version", catalog, binding, refTo("alpha", 2, profile.Hash())},
		{"wrong profile hash", catalog, binding, refTo("alpha", 1, other.Hash())},
		{"non-profile dataset id", catalog, binding, refTo("alpha.beta", 1, profile.Hash())},
		{"retired profile", retired, v2Binding(t, retired), proposal},
	}
	for _, test := range resolution {
		sealed, err := v2Validator(t, test.catalog).ValidateProposalV2(test.proposal, test.binding)
		v2RefusalV2(t, test.name, CodeDatasetProfileUnavailable, sealed, err)
	}

	unknownMeasure := v2SealAggregate(t, v2Parts(t, profile, func(parts *v2AggregateParts) {
		parts.Measure = v2Measure(t, "revenue")
	}))
	sealed, err := validator.ValidateProposalV2(unknownMeasure, binding)
	v2RefusalV2(t, "unknown measure", CodeMeasureUnavailable, sealed, err)
}

func TestValidatorV2LookupNeedsNoMeasure(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2LookupPartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	lookup := v2SealLookup(t, parts)
	if measure, ok := lookup.Measure(); ok || measure.Valid() {
		t.Fatal("LOOKUP fixture carries a measure")
	}
	sealed, err := validator.ValidateProposalV2(lookup, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("lookup refused: valid=%v err=%v", sealed.Valid(), err)
	}
	if _, ok := sealed.Measure(); ok {
		t.Fatal("sealed LOOKUP carries a measure")
	}
	v2Digest(t, sealed)
}

func TestValidatorV2ResolvesExplicitPeriodAndRejectsRelative(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	proposal := v2SealAggregate(t, parts)
	sealed, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !sealed.Valid() {
		t.Fatalf("explicit refused: valid=%v err=%v", sealed.Valid(), err)
	}
	resolved, ok := sealed.ResolvedPeriod()
	start, end, boundsOK := resolved.Bounds()
	if !ok || !boundsOK || start != "2026-01-01" || end != "2026-01-31" {
		t.Fatalf("resolved=%v bounds=%q..%q ok=%v", resolved, start, end, ok)
	}
	if captured, capturedOK := sealed.CapturedAt(); capturedOK || captured != "" {
		t.Fatalf("explicit captured_at=%q/%v", captured, capturedOK)
	}
	projection, ok := sealed.canonicalProjection()
	if !ok || projection.SchemaVersion != "queryintent-validated-intent-v3" || projection.TrustedNow != nil ||
		projection.ResolvedPeriod.Start != start || projection.ResolvedPeriod.End != end {
		t.Fatalf("projection=%+v ok=%v", projection, ok)
	}
	raw, err := canon.CanonicalJSON(projection)
	if err != nil || !strings.Contains(string(raw), `"resolved_period"`) || !strings.Contains(string(raw), `"trusted_now":null`) {
		t.Fatalf("canonical projection=%s err=%v", raw, err)
	}
	if digest, ok := sealed.Digest(); !ok || digest != canon.Hash(raw) {
		t.Fatalf("digest=%q ok=%v", digest, ok)
	}
	relative := parts
	relative.Period = v2Relative(t, PeriodTODAY)
	sealed, err = validator.ValidateProposalV2(v2SealAggregate(t, relative), binding)
	v2RefusalV2(t, "relative without clock", CodeTrustedNowRequired, sealed, err)
}

func TestValidatedIntentV2CanonicalV3Fixtures(t *testing.T) {
	catalog, profile := v2Base(t)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	proposal := v2SealAggregate(t, parts)
	sealed := v2Seal(t, catalog, profile, proposal)
	explicitBytes := `{"aggregate":{"dimensions":["business_day"],"measure":"amount"},"catalog":{"hash":"sha256:80a09508f52d27551199aa425be597807b46bf0819849c302eef1d1fd258e6f8","id":"catalog.operations","revision":"7"},"coverage":"UNKNOWN","dataset":{"dataset_id":"alpha","profile_hash":"sha256:ed6d15aa3ef0cd63e74d461f44fc73a0439105c75df517fd487571b78aed4a9a","version":"1"},"filters":[{"field":"region","op":"EQ","values":[{"kind":"TEXT","text":"north"}]}],"limit":25,"limits":{"max_input_rows":"10000","max_output_groups":50,"max_period_days":31,"max_result_bytes":"1048576","statement_timeout_ms":"5000"},"operation":"AGGREGATE","output":"VALUE","period":{"end":"2026-01-31","mode":"EXPLICIT","start":"2026-01-01"},"resolved_period":{"end":"2026-01-31","mode":"EXPLICIT","start":"2026-01-01","time_kind":"BUSINESS_DATE"},"schema_version":"queryintent-validated-intent-v3","sort":[{"direction":"ASC","field":"business_day","target_kind":"DIMENSION"}],"trusted_now":null}`
	explicitProjection, ok := sealed.canonicalProjection()
	if !ok {
		t.Fatal("explicit projection refused")
	}
	raw, err := canon.CanonicalJSON(explicitProjection)
	if err != nil || string(raw) != explicitBytes {
		t.Fatalf("explicit bytes=%s err=%v", raw, err)
	}
	expectedExplicitHash := "sha256:0125a2c8af18ada49ea7b6e3b2ca9f9762d09739d30c8701f135b49095ca112f"
	if canon.Hash([]byte(explicitBytes)) != expectedExplicitHash {
		t.Fatalf("explicit fixture hash changed: %q", canon.Hash([]byte(explicitBytes)))
	}
	if digest, ok := sealed.Digest(); !ok || digest != expectedExplicitHash {
		t.Fatalf("explicit digest=%q ok=%v", digest, ok)
	}

	parts.Period = v2Relative(t, PeriodTODAY)
	relativeProposal := v2SealAggregate(t, parts)
	relativePeriod, _ := relativeProposal.Period()
	resolution, err := resolvePeriodForProfileV2(profile, relativePeriod, time.Date(2026, 1, 15, 12, 0, 0, 123000000, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	relative, err := newValidatedIntentV2(catalog, profile, relativeProposal, resolution)
	if err != nil || !relative.Valid() {
		t.Fatalf("relative seal: valid=%v err=%v", relative.Valid(), err)
	}
	relativeBytes := `{"aggregate":{"dimensions":["business_day"],"measure":"amount"},"catalog":{"hash":"sha256:80a09508f52d27551199aa425be597807b46bf0819849c302eef1d1fd258e6f8","id":"catalog.operations","revision":"7"},"coverage":"UNKNOWN","dataset":{"dataset_id":"alpha","profile_hash":"sha256:ed6d15aa3ef0cd63e74d461f44fc73a0439105c75df517fd487571b78aed4a9a","version":"1"},"filters":[{"field":"region","op":"EQ","values":[{"kind":"TEXT","text":"north"}]}],"limit":25,"limits":{"max_input_rows":"10000","max_output_groups":50,"max_period_days":31,"max_result_bytes":"1048576","statement_timeout_ms":"5000"},"operation":"AGGREGATE","output":"VALUE","period":{"end":"","mode":"TODAY","start":""},"resolved_period":{"end":"2026-01-16","mode":"TODAY","start":"2026-01-15","time_kind":"BUSINESS_DATE"},"schema_version":"queryintent-validated-intent-v3","sort":[{"direction":"ASC","field":"business_day","target_kind":"DIMENSION"}],"trusted_now":"2026-01-15T12:00:00.123Z"}`
	relativeProjection, ok := relative.canonicalProjection()
	if !ok {
		t.Fatal("relative projection refused")
	}
	raw, err = canon.CanonicalJSON(relativeProjection)
	if err != nil || string(raw) != relativeBytes {
		t.Fatalf("relative bytes=%s err=%v", raw, err)
	}
	expectedRelativeHash := "sha256:d568df20b9d0dc3047980296acff40dba1a1a630adbce1de3aa845b4d46de945"
	if canon.Hash([]byte(relativeBytes)) != expectedRelativeHash {
		t.Fatalf("relative fixture hash changed: %q", canon.Hash([]byte(relativeBytes)))
	}
	if digest, ok := relative.Digest(); !ok || digest != expectedRelativeHash {
		t.Fatalf("relative digest=%q ok=%v", digest, ok)
	}
}

func TestValidatorV2RejectsUnsupportedLatestAndOverBudget(t *testing.T) {
	catalog, profile := v2Base(t)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	validator := v2Validator(t, catalog)
	latest := parts
	latest.Period = v2Relative(t, PeriodLATESTAVAILABLE)
	sealed, err := validator.ValidateProposalV2(v2SealAggregate(t, latest), v2Binding(t, catalog))
	v2RefusalV2(t, "latest", CodePeriodUnavailable, sealed, err)

	unsupportedSpec := profile.Spec()
	unsupportedSpec.Time, err = analytic.NewTimePolicy(analytic.TimePolicyInput{Kind: analytic.TimeNone})
	if err != nil {
		t.Fatal(err)
	}
	unsupported, err := analytic.NewDatasetProfile(unsupportedSpec)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedCatalog := v2Catalog(t, "catalog.unsupported", 1, v2Active(unsupported))
	unsupportedParts := v2AggregatePartsFor(t, unsupported)
	unsupportedParts.Filters = v2ValidatorFilters(t)
	unsupportedParts.Dataset = v2Ref(t, unsupported)
	sealed, err = v2Validator(t, unsupportedCatalog).ValidateProposalV2(v2SealAggregate(t, unsupportedParts), v2Binding(t, unsupportedCatalog))
	v2RefusalV2(t, "time none", CodePeriodUnavailable, sealed, err)

	wideSpec := profile.Spec()
	limits := wideSpec.Limits.Values()
	limits.MaxPeriodDays = 30
	wideSpec.Limits, err = analytic.NewProfileLimits(limits)
	if err != nil {
		t.Fatal(err)
	}
	wide, err := analytic.NewDatasetProfile(wideSpec)
	if err != nil {
		t.Fatal(err)
	}
	wideCatalog := v2Catalog(t, "catalog.wide", 1, v2Active(wide))
	wideParts := v2AggregatePartsFor(t, wide)
	wideParts.Dataset, wideParts.Filters = v2Ref(t, wide), v2ValidatorFilters(t)
	wideParts.Period = v2Explicit(t, "2026-03-01", "2026-04-01")
	sealed, err = v2Validator(t, wideCatalog).ValidateProposalV2(v2SealAggregate(t, wideParts), v2Binding(t, wideCatalog))
	v2RefusalV2(t, "over budget", CodePeriodLimitExceeded, sealed, err)
}

func TestValidatedIntentV2ConstructorResolutionAndTamper(t *testing.T) {
	catalog, profile := v2Base(t)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters = v2ValidatorFilters(t)
	proposal := v2SealAggregate(t, parts)
	period, _ := proposal.Period()
	resolution, err := resolvePeriodForProfileV2(profile, period, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := newValidatedIntentV2(catalog, profile, proposal, periodResolutionV2{})
	v2RefusalV2(t, "unresolved constructor path", CodeInvalidProposal, sealed, err)
	relative, _ := newResolvedPeriodV2(PeriodTODAY, analytic.TimeBusinessDate, "2026-01-01", "2026-01-02")
	sealed, err = newValidatedIntentV2(catalog, profile, proposal, periodResolutionV2{period: relative, trustedNowUTC: "2026-01-01T00:00:00Z", initialized: true})
	v2RefusalV2(t, "mode mismatch", CodeInvalidProposal, sealed, err)
	reject := func(name string, candidate ProposalV2, candidateResolution periodResolutionV2) {
		t.Helper()
		got, candidateErr := newValidatedIntentV2(catalog, profile, candidate, candidateResolution)
		v2RefusalV2(t, name, CodeInvalidProposal, got, candidateErr)
	}
	differentBounds, _ := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeBusinessDate, "2026-01-02", "2026-01-30")
	reject("canonical different bounds", proposal, periodResolutionV2{period: differentBounds, initialized: true})
	zoned, _ := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeZonedTimestamp, "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
	reject("incompatible time kind", proposal, periodResolutionV2{period: zoned, initialized: true})
	wideParts := parts
	wideParts.Period = v2Explicit(t, "2026-01-01", "2026-02-15")
	wideProposal := v2SealAggregate(t, wideParts)
	wideResolved, _ := newResolvedPeriodV2(PeriodEXPLICIT, analytic.TimeBusinessDate, "2026-01-01", "2026-02-15")
	reject("incompatible period budget", wideProposal, periodResolutionV2{period: wideResolved, initialized: true})
	sealed, err = newValidatedIntentV2(catalog, profile, proposal, resolution)
	if err != nil || !sealed.Valid() {
		t.Fatalf("direct seal failed: valid=%v err=%v", sealed.Valid(), err)
	}
	for _, mutate := range []func(*ValidatedIntentV2){
		func(value *ValidatedIntentV2) { value.resolution.period.start = "2026-01-02" },
		func(value *ValidatedIntentV2) { value.resolution.period.timeKind = analytic.TimeLocalTimestamp },
		func(value *ValidatedIntentV2) { value.resolution.period.mode = PeriodTODAY },
		func(value *ValidatedIntentV2) { value.resolution.trustedNowUTC = "2026-01-01T00:00:00Z" },
		func(value *ValidatedIntentV2) { value.digest = "sha256:" + strings.Repeat("0", 64) },
	} {
		tampered := sealed
		mutate(&tampered)
		v2AllAccessorsFail(t, tampered)
	}
}

func TestValidatedIntentV2RelativeDigestBindsCanonicalClock(t *testing.T) {
	catalog, profile := v2Base(t)
	parts := v2AggregatePartsFor(t, profile)
	parts.Filters, parts.Period = v2ValidatorFilters(t), v2Relative(t, PeriodTODAY)
	proposal := v2SealAggregate(t, parts)
	period, _ := proposal.Period()
	firstResolution, err := resolvePeriodForProfileV2(profile, period, time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	secondResolution, err := resolvePeriodForProfileV2(profile, period, time.Date(2026, 1, 15, 13, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	first, err := newValidatedIntentV2(catalog, profile, proposal, firstResolution)
	if err != nil || !first.Valid() {
		t.Fatalf("first relative seal: valid=%v err=%v", first.Valid(), err)
	}
	second, err := newValidatedIntentV2(catalog, profile, proposal, secondResolution)
	if err != nil || !second.Valid() {
		t.Fatalf("second relative seal: valid=%v err=%v", second.Valid(), err)
	}
	firstPeriod, firstOK := first.ResolvedPeriod()
	secondPeriod, secondOK := second.ResolvedPeriod()
	firstStart, firstEnd, firstBoundsOK := firstPeriod.Bounds()
	secondStart, secondEnd, secondBoundsOK := secondPeriod.Bounds()
	if !firstOK || !secondOK || !firstBoundsOK || !secondBoundsOK || firstStart != secondStart || firstEnd != secondEnd {
		t.Fatalf("same-day bounds differ: %q..%q / %q..%q", firstStart, firstEnd, secondStart, secondEnd)
	}
	firstDigest, firstDigestOK := first.Digest()
	secondDigest, secondDigestOK := second.Digest()
	if !firstDigestOK || !secondDigestOK || firstDigest == secondDigest {
		t.Fatalf("canonical clocks did not bind digest: %q/%v %q/%v", firstDigest, firstDigestOK, secondDigest, secondDigestOK)
	}
	secondClock, secondClockOK := second.CapturedAt()
	tampered := first
	tampered.resolution.trustedNowUTC = secondClock
	if !secondClockOK || secondClock == "" {
		t.Fatal("second relative seal has no trusted clock")
	}
	v2AllAccessorsFail(t, tampered)
}

func TestValidatorV2ValidationOrderPrecedesPeriodResolution(t *testing.T) {
	catalog, profile := v2Base(t)
	validator, binding := v2Validator(t, catalog), v2Binding(t, catalog)
	badFilter := v2AggregatePartsFor(t, profile)
	badFilter.Filters = v2Predicates(t, v2Predicate(t, "business_day", OpEQ, v2Date(t, "2026-01-01")))
	badFilter.Period = v2Relative(t, PeriodTODAY)
	sealed, err := validator.ValidateProposalV2(v2SealAggregate(t, badFilter), binding)
	v2RefusalV2(t, "bad filter before relative period", CodeFilterNotAllowed, sealed, err)

	narrow := v2ShapeProfile(t, func(test *testing.T, spec *analytic.DatasetProfileSpec) {
		v2ShapeLimits(test, spec, 24)
	})
	badLimit := v2AggregatePartsFor(t, narrow)
	badLimit.Filters = v2ValidatorFilters(t)
	badLimit.Limit = v2Limit(t, 25)
	badLimit.Period = v2Relative(t, PeriodLATESTAVAILABLE)
	sealed, err = v2ShapeValidate(t, narrow, v2SealAggregate(t, badLimit))
	v2RefusalV2(t, "bad limit before unsupported period", CodeLimitExceeded, sealed, err)

	badShape := v2ShapeProfile(t, nil)
	badDimensions := v2AggregatePartsFor(t, badShape)
	badDimensions.Filters = v2ValidatorFilters(t)
	badDimensions.Dimensions = v2Dimensions(t, "unlisted")
	badDimensions.Period = v2Relative(t, PeriodLATESTAVAILABLE)
	sealed, err = v2ShapeValidate(t, badShape, v2SealAggregate(t, badDimensions))
	v2RefusalV2(t, "bad shape before unsupported period", CodeDimensionUnavailable, sealed, err)
}
