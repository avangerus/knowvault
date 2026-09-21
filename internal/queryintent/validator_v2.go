package queryintent

import "knowvault.local/verified-workspace/internal/analytic"

// CatalogBindingV2 is the caller-supplied identity of the catalog snapshot a
// proposal claims was checked against. Its members are private, so only
// NewCatalogBindingV2 can build one outside this package, and the value is
// copied on assignment. The binding carries no authority of its own: it proves
// nothing until every member matches the installed catalog exactly.
type CatalogBindingV2 struct {
	id       string
	revision int64
	hash     string
}

// NewCatalogBindingV2 builds a binding from a catalog snapshot identity. The id
// and hash must use the same safe form this package requires of its profile
// references, the revision must be positive, and anything else is refused
// without echoing the input.
func NewCatalogBindingV2(id string, revision int64, hash string) (CatalogBindingV2, error) {
	binding := CatalogBindingV2{id: id, revision: revision, hash: hash}
	if !binding.Valid() {
		return CatalogBindingV2{}, newRefusal(CodeInvalidProposal)
	}
	return binding, nil
}

// Valid reports whether the bound id, revision and hash are each in canonical
// form. This is a shape check only: no installed catalog is consulted.
func (binding CatalogBindingV2) Valid() bool {
	return validLabel(binding.id, maxIDLength) && binding.revision > 0 && validProfileHash(binding.hash)
}

// ID is the bound catalog id, detached from any live catalog.
func (binding CatalogBindingV2) ID() (string, bool) {
	if !binding.Valid() {
		return "", false
	}
	return binding.id, true
}

// Revision is the bound catalog revision.
func (binding CatalogBindingV2) Revision() (int64, bool) {
	if !binding.Valid() {
		return 0, false
	}
	return binding.revision, true
}

// Hash is the bound catalog content hash.
func (binding CatalogBindingV2) Hash() (string, bool) {
	if !binding.Valid() {
		return "", false
	}
	return binding.hash, true
}

// ValidatorV2 validates a ProposalV2 against exactly one installed catalog
// snapshot. The snapshot is private and fixed at construction, so a validator
// can only ever authorize the authority it was built from.
type ValidatorV2 struct {
	catalog analytic.DatasetProfileCatalog
}

// NewValidatorV2 builds a validator over one installed catalog snapshot. An
// invalid snapshot is refused with a content-free code and a zero validator.
func NewValidatorV2(catalog analytic.DatasetProfileCatalog) (ValidatorV2, error) {
	if !catalog.Valid() {
		return ValidatorV2{}, newRefusal(CodeCatalogUnavailable)
	}
	return ValidatorV2{catalog: catalog}, nil
}

// ValidateProposalV2 is the only path from a ProposalV2 to a ValidatedIntentV2.
// The checks run in a fixed order: proposal shape, validator catalog, frozen
// binding, exact profile resolution, measure authority for AGGREGATE, and then
// the seal. Filter predicates are resolved against the resolved profile before
// the seal; dimensions, output fields, sort, limits and period semantics are
// deliberately out of scope here, and the seal re-proves only the catalog
// snapshot, the resolved profile and the proposal's dataset reference.
func (validator ValidatorV2) ValidateProposalV2(proposal ProposalV2, frozen CatalogBindingV2) (ValidatedIntentV2, error) {
	if !proposal.Valid() {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	if !validator.catalog.Valid() {
		return ValidatedIntentV2{}, newRefusal(CodeCatalogUnavailable)
	}
	if !frozen.Valid() || !sameCatalogBindingV2(frozen, validator.catalog) {
		return ValidatedIntentV2{}, newRefusal(CodeCatalogBindingMismatch)
	}
	profile, err := validator.resolveProfileV2(proposal)
	if err != nil {
		return ValidatedIntentV2{}, err
	}
	operation, ok := proposal.Operation()
	if !ok {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	if operation == OperationAGGREGATE && !profileAuthorizesMeasureV2(proposal, profile) {
		return ValidatedIntentV2{}, newRefusal(CodeMeasureUnavailable)
	}
	filters, filtersOK := proposal.Filters()
	if !filtersOK {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	if err := validateV2Filters(profile, filters); err != nil {
		return ValidatedIntentV2{}, err
	}
	sealed, err := newValidatedIntentV2(validator.catalog, profile, proposal)
	if err != nil || !sealed.Valid() {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	return sealed, nil
}

// sameCatalogBindingV2 compares every bound member against the installed
// snapshot: one drifted member is a mismatch.
func sameCatalogBindingV2(binding CatalogBindingV2, catalog analytic.DatasetProfileCatalog) bool {
	id, idOK := binding.ID()
	revision, revisionOK := binding.Revision()
	hash, hashOK := binding.Hash()
	return idOK && revisionOK && hashOK && id == catalog.ID() &&
		revision == catalog.Revision() && hash == catalog.Hash()
}

// resolveProfileV2 turns the proposal's exact dataset reference into a profile
// key and resolves it as ACTIVE inside the installed snapshot, pinned to the
// reference's expected profile hash. Unknown, retired and hash-mismatched
// profiles share one content-free refusal.
func (validator ValidatorV2) resolveProfileV2(proposal ProposalV2) (analytic.DatasetProfile, error) {
	dataset, datasetOK := proposal.Dataset()
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, hashOK := dataset.ExpectedProfileHash()
	if !datasetOK || !idOK || !versionOK || !hashOK {
		return analytic.DatasetProfile{}, newRefusal(CodeDatasetProfileUnavailable)
	}
	key, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		return analytic.DatasetProfile{}, newRefusal(CodeDatasetProfileUnavailable)
	}
	profile, active := validator.catalog.ResolveActive(key, profileHash)
	if !active {
		return analytic.DatasetProfile{}, newRefusal(CodeDatasetProfileUnavailable)
	}
	return profile, nil
}

// profileAuthorizesMeasureV2 reports whether the AGGREGATE arm names a measure
// the resolved profile defines. A LOOKUP arm never reaches this check.
func profileAuthorizesMeasureV2(proposal ProposalV2, profile analytic.DatasetProfile) bool {
	measure, measureOK := proposal.Measure()
	measureID, idOK := measure.MeasureID()
	if !measureOK || !idOK {
		return false
	}
	_, found := profile.Measure(measureID)
	return found
}

// validateV2Filters denies every filter predicate the resolved profile does not
// exactly authorize. The profile's declared time field is reserved whenever its
// time kind is not NONE, even when that field is itself filterable. Unknown and
// non-filterable fields, operators outside the field's grant, scalar values
// that do not exactly match the field's logical type, and IS_NULL on a field
// that is not nullable are all one content-free CodeFilterNotAllowed denial.
func validateV2Filters(profile analytic.DatasetProfile, filters Predicates) error {
	predicates, ok := filters.Values()
	if !ok {
		return newRefusal(CodeFilterNotAllowed)
	}
	time := profile.Time().Values()
	for _, predicate := range predicates {
		if !filterAllowedV2(profile, time, predicate) {
			return newRefusal(CodeFilterNotAllowed)
		}
	}
	return nil
}

// filterAllowedV2 reports whether one predicate is exactly what the profile
// authorizes, and nothing more.
func filterAllowedV2(profile analytic.DatasetProfile, time analytic.TimePolicyInput, predicate Predicate) bool {
	name, ok := predicate.Field().Value()
	if !ok || (time.Kind != analytic.TimeNone && time.FieldToken == name) {
		return false
	}
	field, found := profile.Field(name)
	if !found {
		return false
	}
	spec := field.Values()
	if !spec.Filterable {
		return false
	}
	operator, ok := filterOperatorV2(predicate.Op())
	if !ok || !filterOperatorGrantedV2(spec.AllowedOps, operator) {
		return false
	}
	values := predicate.Values()
	if operator == analytic.PredicateISNull {
		return spec.Nullable && len(values) == 1 && values[0].Kind() == KindBOOL
	}
	for _, value := range values {
		if !filterScalarMatchesV2(value.Kind(), spec.LogicalType) {
			return false
		}
	}
	return true
}

// filterOperatorGrantedV2 reports whether the field's own grant lists exactly
// this operator.
func filterOperatorGrantedV2(granted []analytic.PredicateOperator, operator analytic.PredicateOperator) bool {
	for _, candidate := range granted {
		if candidate == operator {
			return true
		}
	}
	return false
}

// filterOperatorV2 maps one proposal operator onto the profile's closed
// operator vocabulary. The switch is explicit so no other wire value can be
// textually reinterpreted as a granted profile operator.
func filterOperatorV2(op Operator) (analytic.PredicateOperator, bool) {
	switch op {
	case OpEQ:
		return analytic.PredicateEQ, true
	case OpIN:
		return analytic.PredicateIN, true
	case OpGTE:
		return analytic.PredicateGTE, true
	case OpLTE:
		return analytic.PredicateLTE, true
	case OpISNull:
		return analytic.PredicateISNull, true
	default:
		return "", false
	}
}

// filterScalarMatchesV2 reports whether one scalar kind is exactly the logical
// type of the field it filters. Both vocabularies are strings, so the mapping
// is an explicit switch: a cast would silently accept a near-miss kind.
func filterScalarMatchesV2(kind ScalarKind, logical analytic.ScalarType) bool {
	switch kind {
	case KindBOOL:
		return logical == analytic.ScalarBool
	case KindINT:
		return logical == analytic.ScalarInt
	case KindNUMERIC:
		return logical == analytic.ScalarNumeric
	case KindTEXT:
		return logical == analytic.ScalarText
	case KindDATE:
		return logical == analytic.ScalarDate
	case KindTIMESTAMP:
		return logical == analytic.ScalarTimestamp
	case KindTIMESTAMPTZ:
		return logical == analytic.ScalarTimestamptz
	default:
		return false
	}
}
