package question

import (
	"context"
	"reflect"
	"slices"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
)

// analyticScalarCapability is one prepared, server-owned analytic capability for
// a single closed ungrouped scalar question. It binds the retained immutable
// catalog snapshot to the exact checked candidate subset and keeps, for each
// checked candidate, the resolved profile plus its safe model-facing
// projection. It carries no workspace or access identity, connection, schema,
// relation, SQL, physical field, resolution, receipt or execution handle, and
// nothing persists, caches or serializes it.
//
// The value is only trustworthy when valid() holds: every member is rederived
// from the retained catalog and the checked candidates, never taken on faith
// from a caller. A capability that is not valid is never used.
type analyticScalarCapability struct {
	catalog     analytic.DatasetProfileCatalog
	candidates  []analyticCandidate
	profiles    []analytic.DatasetProfile
	projections []modelDatasetProfile
}

// prepareAnalyticScalarCapability attempts exactly one complete candidate check
// for the workspace and, when it yields at least one accepted candidate, builds
// the private scalar capability over those candidates and the retained catalog.
//
// The check runs exactly once through the existing adapter and adds no authority
// of its own. An existing CodeInvalid or CodeUnavailable refusal from the check
// is returned unchanged: a refused check is never repaired, completed or
// retried. An absent catalog, an all-RETIRED catalog and a check that accepted
// no candidate are indistinguishable here and all return the exact zero
// capability with the content-free CodeUnavailable refusal, because an installed
// but empty capability can serve no scalar question. The accepted candidates are
// then handed to the pure constructor together with the service's retained
// catalog; this method performs no further I/O, resolver call, persistence,
// logging or model projection, and it never mutates either retained slot.
func (service *Service) prepareAnalyticScalarCapability(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
) (analyticScalarCapability, error) {
	checked, err := service.checkAnalyticCandidates(ctx, access, workspaceID)
	if err != nil {
		return analyticScalarCapability{}, err
	}
	if len(checked) == 0 {
		return analyticScalarCapability{}, &Error{code: CodeUnavailable}
	}
	return newAnalyticScalarCapability(service.datasetProfileCatalog, checked)
}

// newAnalyticScalarCapability is the pure capability constructor. It requires a
// valid retained catalog and a non-empty checked slice; every other argument
// returns the exact zero capability and the content-free CodeInvalid refusal.
//
// The checked slice must be a subsequence of the catalog's canonical ACTIVE
// entries: every candidate occurs exactly once, in catalog canonical order, as
// an ACTIVE entry whose exact profile key and hash it carries. A missing,
// duplicate, reordered, stale or invalid candidate fails closed rather than
// being repaired or truncated. Each accepted candidate is resolved only with
// catalog.ResolveActive and projected only with projectModelDatasetProfile; the
// candidate, profile and projection slices are freshly allocated, so the
// constructor retains no caller-owned storage. There is no I/O, resolver call,
// persistence or audit here.
func newAnalyticScalarCapability(
	catalog analytic.DatasetProfileCatalog,
	checked []analyticCandidate,
) (analyticScalarCapability, error) {
	if !catalog.Valid() || len(checked) == 0 {
		return analyticScalarCapability{}, &Error{code: CodeInvalid}
	}

	candidates := append([]analyticCandidate(nil), checked...)
	profiles := make([]analytic.DatasetProfile, 0, len(candidates))
	projections := make([]modelDatasetProfile, 0, len(candidates))
	next := 0
	for _, entry := range catalog.Entries() {
		if next == len(candidates) {
			break
		}
		if candidates[next].profileKey != entry.Profile.Key() ||
			candidates[next].profileHash != entry.Profile.Hash() {
			continue
		}
		if entry.State != analytic.ProfileActive {
			return analyticScalarCapability{}, &Error{code: CodeInvalid}
		}
		profile, active := catalog.ResolveActive(candidates[next].profileKey, candidates[next].profileHash)
		if !active || scalarCapabilityRequiredFilterCount(profile) > queryintent.MaxPredicates {
			return analyticScalarCapability{}, &Error{code: CodeInvalid}
		}
		projection, err := projectModelDatasetProfile(profile)
		if err != nil {
			return analyticScalarCapability{}, &Error{code: CodeInvalid}
		}
		profiles = append(profiles, profile)
		projections = append(projections, projection)
		next++
	}

	value := analyticScalarCapability{
		catalog:     catalog,
		candidates:  candidates,
		profiles:    profiles,
		projections: projections,
	}
	if !value.valid() {
		return analyticScalarCapability{}, &Error{code: CodeInvalid}
	}
	return value, nil
}

// valid rederives every retained member from the catalog and the checked
// candidates. It requires a valid catalog, non-empty equal-length slices, the
// canonical catalog order and identity of every candidate, a valid, key- and
// hash-exact profile for each candidate, and the exact safe projection
// recomputed from that profile. A tampered, partial or stale capability is
// invalid and never served.
func (value analyticScalarCapability) valid() bool {
	if !value.catalog.Valid() || len(value.candidates) == 0 ||
		len(value.candidates) != len(value.profiles) ||
		len(value.candidates) != len(value.projections) {
		return false
	}

	next := 0
	for _, entry := range value.catalog.Entries() {
		if next == len(value.candidates) {
			break
		}
		candidate := value.candidates[next]
		if candidate.profileKey != entry.Profile.Key() || candidate.profileHash != entry.Profile.Hash() {
			continue
		}
		if entry.State != analytic.ProfileActive {
			return false
		}
		profile := value.profiles[next]
		if !profile.Valid() || profile.Key() != candidate.profileKey || profile.Hash() != candidate.profileHash {
			return false
		}
		if scalarCapabilityRequiredFilterCount(profile) > queryintent.MaxPredicates {
			return false
		}
		projection, err := projectModelDatasetProfile(profile)
		if err != nil || !reflect.DeepEqual(projection, value.projections[next]) {
			return false
		}
		next++
	}
	return next == len(value.candidates)
}

// modelProfiles returns a fresh, deeply detached copy of the safe model-facing
// projections in canonical checked order, and nil when the capability is not
// valid. A caller may mutate the returned value without reaching the
// capability, its profiles or the retained catalog.
func (value analyticScalarCapability) modelProfiles() []modelDatasetProfile {
	if !value.valid() {
		return nil
	}
	profiles := make([]modelDatasetProfile, len(value.projections))
	for index, projection := range value.projections {
		profiles[index] = cloneModelDatasetProfile(projection)
	}
	return profiles
}

// cloneModelDatasetProfile detaches the nested slices of one safe projection so
// no caller can reach the capability's retained projection through an alias
// slice.
func cloneModelDatasetProfile(projection modelDatasetProfile) modelDatasetProfile {
	projection.Fields = append([]modelDatasetProfileField(nil), projection.Fields...)
	for index := range projection.Fields {
		projection.Fields[index].Aliases = append([]string{}, projection.Fields[index].Aliases...)
		projection.Fields[index].AllowedOperators = append([]string{}, projection.Fields[index].AllowedOperators...)
		projection.Fields[index].AllowedValues = append([]string{}, projection.Fields[index].AllowedValues...)
	}
	projection.Measures = append([]modelDatasetProfileMeasure(nil), projection.Measures...)
	for index := range projection.Measures {
		projection.Measures[index].Aliases = append([]string{}, projection.Measures[index].Aliases...)
	}
	return projection
}

func scalarCapabilityRequiredFilterCount(profile analytic.DatasetProfile) int {
	if !profile.Valid() {
		return queryintent.MaxPredicates + 1
	}
	timeField := profile.Time().Values().FieldToken
	count := 0
	for _, field := range profile.Fields() {
		values := field.Values()
		if values.Token != timeField && values.Filterable && slices.Contains(values.AllowedOps, analytic.PredicateEQ) {
			count++
		}
	}
	return count
}

// validateProposal strictly decodes one model-proposed document and validates it
// against this capability. It only accepts the single closed ungrouped scalar
// shape: an AGGREGATE proposal naming one measure, empty dimensions, empty sort,
// limit exactly 1, the VALUE output and an EXPLICIT period that carries both
// bounds. Filters are accepted only through the existing proposal constructors
// and the frozen V2 validator.
//
// It first requires a valid capability, then decodes with
// queryintent.DecodeProposalV2JSON, then enforces the closed shape, then requires
// the proposal's dataset id, version and hash to match one checked profile
// exactly. A selected profile that is ACTIVE in the retained catalog but was not
// checked returns the content-free CodeUnavailable refusal; any other unknown or
// stale dataset selection returns CodeInvalid. The frozen catalog binding and
// the queryintent V2 validator are then built from the capability's own catalog
// snapshot, and the sealed intent is returned only when the validator accepts.
//
// Every refusal returns the exact zero intent and the exact zero profile. A
// malformed document, an unsupported shape, a binding or validator refusal are
// all the content-free CodeInvalid refusal: no model input is echoed, and no
// queryintent or catalog cause is exposed through this value.
func (value analyticScalarCapability) validateProposal(
	proposalJSON []byte,
) (queryintent.ValidatedIntentV2, analytic.DatasetProfile, error) {
	if !value.valid() {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}

	proposal, err := queryintent.DecodeProposalV2JSON(proposalJSON)
	if err != nil || !scalarCapabilityShape(proposal) {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}

	dataset, ok := proposal.Dataset()
	if !ok {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, hashOK := dataset.ExpectedProfileHash()
	if !idOK || !versionOK || !hashOK {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}
	selected, err := value.selectCheckedProfile(datasetID, version, profileHash)
	if err != nil {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, err
	}
	if !scalarCapabilityHasRequiredFilters(proposal, selected) {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}

	binding, err := queryintent.NewCatalogBindingV2(value.catalog.ID(), value.catalog.Revision(), value.catalog.Hash())
	if err != nil {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}
	validator, err := queryintent.NewValidatorV2(value.catalog)
	if err != nil {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}
	intent, err := validator.ValidateProposalV2(proposal, binding)
	if err != nil || !intent.Valid() {
		return queryintent.ValidatedIntentV2{}, analytic.DatasetProfile{}, &Error{code: CodeInvalid}
	}
	return intent, selected, nil
}

// scalarCapabilityHasRequiredFilters binds the model-proposed predicate set to
// the selected profile. Every filterable field that grants EQ is model-facing
// and therefore mandatory for this scalar capability: it must occur exactly
// once with EQ, with no additional or duplicate predicates. This prevents an
// omitted discriminator from silently aggregating several business measures.
func scalarCapabilityHasRequiredFilters(proposal queryintent.ProposalV2, profile analytic.DatasetProfile) bool {
	filters, ok := proposal.Filters()
	if !ok {
		return false
	}
	predicates, ok := filters.Values()
	if !ok {
		return false
	}

	required := make(map[string][]string)
	timeField := profile.Time().Values().FieldToken
	for _, field := range profile.Fields() {
		values := field.Values()
		if values.Token != timeField && values.Filterable && slices.Contains(values.AllowedOps, analytic.PredicateEQ) {
			required[values.Token] = append([]string(nil), values.AllowedValues...)
		}
	}
	if len(predicates) != len(required) {
		return false
	}

	seen := make(map[string]struct{}, len(predicates))
	for _, predicate := range predicates {
		field, valid := predicate.Field().Value()
		if !valid || predicate.Op() != queryintent.OpEQ {
			return false
		}
		allowedValues, expected := required[field]
		if !expected {
			return false
		}
		if _, duplicate := seen[field]; duplicate {
			return false
		}
		if len(allowedValues) > 0 {
			values := predicate.Values()
			if len(values) != 1 {
				return false
			}
			text, textOK := values[0].Text()
			if !textOK || !slices.Contains(allowedValues, text) {
				return false
			}
		}
		seen[field] = struct{}{}
	}
	return len(seen) == len(required)
}

// selectCheckedProfile returns the exact checked profile the proposal names, or
// the content-free CodeUnavailable refusal when the selection is an ACTIVE
// catalog profile this capability did not check, or the content-free CodeInvalid
// refusal when it matches nothing the retained catalog can serve.
func (value analyticScalarCapability) selectCheckedProfile(
	datasetID string,
	version int64,
	profileHash string,
) (analytic.DatasetProfile, error) {
	for _, profile := range value.profiles {
		if profile.Key().DatasetID() == datasetID &&
			profile.Key().Version() == version &&
			profile.Hash() == profileHash {
			return profile, nil
		}
	}
	key, err := analytic.NewProfileKey(datasetID, version)
	if err == nil {
		if _, active := value.catalog.ResolveActive(key, profileHash); active {
			return analytic.DatasetProfile{}, &Error{code: CodeUnavailable}
		}
	}
	return analytic.DatasetProfile{}, &Error{code: CodeInvalid}
}

// scalarCapabilityShape reports whether one decoded proposal is exactly the
// closed ungrouped scalar shape this capability serves: AGGREGATE, one measure,
// empty dimensions, empty sort, limit 1, VALUE output and an EXPLICIT period
// with both bounds present. Filters are deliberately not inspected here; the
// frozen V2 validator is their only authority.
func scalarCapabilityShape(proposal queryintent.ProposalV2) bool {
	operation, ok := proposal.Operation()
	if !ok || operation != queryintent.OperationAGGREGATE {
		return false
	}
	output, ok := proposal.Output()
	if !ok || output != queryintent.OutputValue {
		return false
	}
	dimensions, ok := proposal.Dimensions()
	if !ok {
		return false
	}
	fields, ok := dimensions.Fields()
	if !ok || len(fields) != 0 {
		return false
	}
	sort, ok := proposal.Sort()
	if !ok {
		return false
	}
	keys, ok := sort.Values()
	if !ok || len(keys) != 0 {
		return false
	}
	limit, ok := proposal.Limit()
	if !ok {
		return false
	}
	limitValue, ok := limit.Value()
	if !ok || limitValue != 1 {
		return false
	}
	period, ok := proposal.Period()
	if !ok {
		return false
	}
	mode, ok := period.Mode()
	if !ok || mode != queryintent.PeriodEXPLICIT {
		return false
	}
	_, _, boundsOK := period.ExplicitBounds()
	return boundsOK
}
