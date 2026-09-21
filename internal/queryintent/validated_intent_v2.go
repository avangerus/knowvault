package queryintent

import (
	"strconv"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// validatedIntentV2SchemaVersion is the literal tag of the digest projection.
const validatedIntentV2SchemaVersion = "queryintent-validated-intent-v2"

// ValidatedIntentV2 is a server-sealed analytic intent: one validated ProposalV2
// bound to the catalog snapshot and dataset profile version that authorized it,
// plus that profile's limits and coverage policy. Every field is unexported with
// no exported constructor, and no catalog, profile, SQL, question or run identity.
type ValidatedIntentV2 struct {
	catalogID       string
	catalogRevision int64
	catalogHash     string
	proposal        ProposalV2
	limits          analytic.ProfileLimits
	coverage        analytic.CoveragePolicy
	digest          string
	sealed          bool
}

// newValidatedIntentV2 seals one proposal against the profile and catalog
// snapshot that authorized it. All three must be valid, the catalog must resolve
// exactly this profile as ACTIVE in this snapshot, and the proposal must name
// exactly that profile's dataset id, version and hash. Binding and budgets come
// only from the catalog and profile, the digest is computed last over the sealed
// members, and every failure returns the zero value with a content-free
// CodeInvalidProposal refusal.
func newValidatedIntentV2(catalog analytic.DatasetProfileCatalog, profile analytic.DatasetProfile, proposal ProposalV2) (ValidatedIntentV2, error) {
	if !catalog.Valid() || !profile.Valid() || !proposal.Valid() {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	if _, active := catalog.ResolveActive(profile.Key(), profile.Hash()); !active {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	dataset, ok := proposal.Dataset()
	if !ok {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, hashOK := dataset.ExpectedProfileHash()
	if !idOK || !versionOK || !hashOK || datasetID != profile.Key().DatasetID() ||
		version != profile.Key().Version() || profileHash != profile.Hash() {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	// Predicate values are slices, so detach the proposal's filters before
	// storing it: mutating the caller's proposal must not reach the seal.
	proposal.filters = clonePredicates(proposal.filters)
	value := ValidatedIntentV2{
		catalogID:       catalog.ID(),
		catalogRevision: catalog.Revision(),
		catalogHash:     catalog.Hash(),
		proposal:        proposal,
		limits:          profile.Limits(),
		coverage:        profile.Coverage(),
		sealed:          true,
	}
	digest, ok := value.canonicalDigest()
	if !ok {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	value.digest = digest
	if !value.Valid() {
		return ValidatedIntentV2{}, newRefusal(CodeInvalidProposal)
	}
	return value, nil
}

// Valid reports whether this is a value this package sealed and nothing has
// changed since. It rejects the zero value and every forged or tampered copy:
// the catalog form, the proposal, the limits, the coverage and the seal flag are
// rechecked, and the canonical digest is recomputed and must equal the stored
// digest exactly. Validity covers the stored binding only, never a live catalog.
func (value ValidatedIntentV2) Valid() bool {
	if !value.sealed || !validLabel(value.catalogID, maxIDLength) || value.catalogRevision <= 0 ||
		!validProfileHash(value.catalogHash) || !value.proposal.Valid() || !value.limits.Valid() ||
		!value.coverage.Valid() || !validProfileHash(value.digest) {
		return false
	}
	digest, ok := value.canonicalDigest()
	return ok && digest == value.digest
}

// sealedAccessor is the validity gate every detached accessor shares.
func sealedAccessor[T any](value ValidatedIntentV2, extract func() (T, bool)) (T, bool) {
	if !value.Valid() {
		var zero T
		return zero, false
	}
	return extract()
}

// CatalogID is the id of the catalog snapshot that proved the profile active.
func (value ValidatedIntentV2) CatalogID() (string, bool) {
	return sealedAccessor(value, func() (string, bool) { return value.catalogID, true })
}

// CatalogRevision is the revision of that catalog snapshot.
func (value ValidatedIntentV2) CatalogRevision() (int64, bool) {
	return sealedAccessor(value, func() (int64, bool) { return value.catalogRevision, true })
}

// CatalogHash is the content hash of that catalog snapshot.
func (value ValidatedIntentV2) CatalogHash() (string, bool) {
	return sealedAccessor(value, func() (string, bool) { return value.catalogHash, true })
}

// Dataset is the exact dataset profile identity the catalog resolved.
func (value ValidatedIntentV2) Dataset() (DatasetProfileRef, bool) {
	return sealedAccessor(value, value.proposal.Dataset)
}

// Operation is the sealed proposal's closed shape.
func (value ValidatedIntentV2) Operation() (Operation, bool) {
	return sealedAccessor(value, value.proposal.Operation)
}

// Period is the requested, still unresolved period.
func (value ValidatedIntentV2) Period() (PeriodProposal, bool) {
	return sealedAccessor(value, value.proposal.Period)
}

// Filters is a detached copy of the predicates in request order.
func (value ValidatedIntentV2) Filters() (Predicates, bool) {
	return sealedAccessor(value, value.proposal.Filters)
}

// Measure is the AGGREGATE measure reference; a LOOKUP intent has none.
func (value ValidatedIntentV2) Measure() (MeasureRef, bool) {
	return sealedAccessor(value, value.proposal.Measure)
}

// Dimensions are the AGGREGATE grouping fields; a LOOKUP intent has none.
func (value ValidatedIntentV2) Dimensions() (Dimensions, bool) {
	return sealedAccessor(value, value.proposal.Dimensions)
}

// OutputFields are the LOOKUP fields in request order; an AGGREGATE has none.
func (value ValidatedIntentV2) OutputFields() (OutputFields, bool) {
	return sealedAccessor(value, value.proposal.OutputFields)
}

// Sort is the requested sort keys in request order.
func (value ValidatedIntentV2) Sort() (SortKeys, bool) {
	return sealedAccessor(value, value.proposal.Sort)
}

// Limit is the requested row limit.
func (value ValidatedIntentV2) Limit() (Limit, bool) {
	return sealedAccessor(value, value.proposal.Limit)
}

// Output is the requested answer shape.
func (value ValidatedIntentV2) Output() (Output, bool) {
	return sealedAccessor(value, value.proposal.Output)
}

// Limits are the execution bounds copied from the approved profile.
func (value ValidatedIntentV2) Limits() (analytic.ProfileLimits, bool) {
	return sealedAccessor(value, func() (analytic.ProfileLimits, bool) { return value.limits, true })
}

// Coverage is the coverage policy copied from the approved profile.
func (value ValidatedIntentV2) Coverage() (analytic.CoveragePolicy, bool) {
	return sealedAccessor(value, func() (analytic.CoveragePolicy, bool) { return value.coverage, true })
}

// Digest is the canonical digest of the sealed binding and semantics.
func (value ValidatedIntentV2) Digest() (string, bool) {
	return sealedAccessor(value, func() (string, bool) { return value.digest, true })
}

// validatedIntentV2Projection is the explicit, closed digest projection: catalog
// snapshot, exact dataset profile triple, operation, period, every predicate with
// its scalar kind and canonical value, the active operation arm only, sort
// targets, limit and output, all five profile limits and coverage. Every int64
// member is exact base-10 text; an unselected arm is absent, never empty.
type validatedIntentV2Projection struct {
	SchemaVersion string                       `json:"schema_version"`
	Catalog       validatedIntentV2Catalog     `json:"catalog"`
	Dataset       validatedIntentV2Dataset     `json:"dataset"`
	Operation     Operation                    `json:"operation"`
	Period        validatedIntentV2Period      `json:"period"`
	Filters       []validatedIntentV2Predicate `json:"filters"`
	Aggregate     *validatedIntentV2Aggregate  `json:"aggregate,omitempty"`
	Lookup        *validatedIntentV2Lookup     `json:"lookup,omitempty"`
	Sort          []validatedIntentV2SortKey   `json:"sort"`
	Limit         int                          `json:"limit"`
	Output        Output                       `json:"output"`
	Limits        validatedIntentV2Limits      `json:"limits"`
	Coverage      analytic.CoveragePolicy      `json:"coverage"`
}

type validatedIntentV2Catalog struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Hash     string `json:"hash"`
}

type validatedIntentV2Dataset struct {
	DatasetID   string `json:"dataset_id"`
	Version     string `json:"version"`
	ProfileHash string `json:"profile_hash"`
}

type validatedIntentV2Period struct {
	Mode  PeriodMode `json:"mode"`
	Start string     `json:"start"`
	End   string     `json:"end"`
}

type validatedIntentV2Predicate struct {
	Field  string                    `json:"field"`
	Op     Operator                  `json:"op"`
	Values []validatedIntentV2Scalar `json:"values"`
}

// validatedIntentV2Scalar carries the kind plus canonical value: bool for BOOL,
// exact base-10 text for INT (canonicalizers use float64), text otherwise.
type validatedIntentV2Scalar struct {
	Kind ScalarKind `json:"kind"`
	Bool *bool      `json:"bool,omitempty"`
	Int  *string    `json:"int,omitempty"`
	Text *string    `json:"text,omitempty"`
}

type validatedIntentV2Aggregate struct {
	Measure    string   `json:"measure"`
	Dimensions []string `json:"dimensions"`
}

type validatedIntentV2Lookup struct {
	OutputFields []string `json:"output_fields"`
}

type validatedIntentV2SortKey struct {
	TargetKind SortTargetKind `json:"target_kind"`
	Field      string         `json:"field,omitempty"`
	Measure    string         `json:"measure,omitempty"`
	Direction  SortDirection  `json:"direction"`
}

type validatedIntentV2Limits struct {
	MaxInputRows       string `json:"max_input_rows"`
	MaxOutputGroups    int    `json:"max_output_groups"`
	MaxPeriodDays      int    `json:"max_period_days"`
	MaxResultBytes     string `json:"max_result_bytes"`
	StatementTimeoutMS string `json:"statement_timeout_ms"`
}

// canonicalProjection projects the stored values, failing closed on any member.
func (value ValidatedIntentV2) canonicalProjection() (validatedIntentV2Projection, bool) {
	dataset, datasetOK := value.proposal.Dataset()
	operation, operationOK := value.proposal.Operation()
	period, periodOK := value.proposal.Period()
	limit, limitOK := value.proposal.Limit()
	limitValue, limitValueOK := limit.Value()
	output, outputOK := value.proposal.Output()
	predicates, predicatesOK := value.proposal.Filters()
	predicateValues, predicateValuesOK := predicates.Values()
	filters, filtersOK := projectValidatedIntentV2Predicates(predicateValues)
	sortKeys, sortOK := value.proposal.Sort()
	sortKeyValues, sortKeyValuesOK := sortKeys.Values()
	sort, sortProjectionOK := projectValidatedIntentV2SortKeys(sortKeyValues)
	if !datasetOK || !operationOK || !periodOK || !limitOK || !limitValueOK || !outputOK ||
		!predicatesOK || !predicateValuesOK || !filtersOK || !sortOK || !sortKeyValuesOK || !sortProjectionOK {
		return validatedIntentV2Projection{}, false
	}
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, hashOK := dataset.ExpectedProfileHash()
	mode, modeOK := period.Mode()
	start, end, boundsOK := "", "", true
	if mode == PeriodEXPLICIT {
		start, end, boundsOK = period.ExplicitBounds()
	}
	if !idOK || !versionOK || !hashOK || !modeOK || !boundsOK {
		return validatedIntentV2Projection{}, false
	}
	limits := value.limits.Values()
	projected := validatedIntentV2Projection{
		SchemaVersion: validatedIntentV2SchemaVersion,
		Catalog: validatedIntentV2Catalog{
			ID: value.catalogID, Revision: strconv.FormatInt(value.catalogRevision, 10), Hash: value.catalogHash,
		},
		Dataset: validatedIntentV2Dataset{
			DatasetID: datasetID, Version: strconv.FormatInt(version, 10), ProfileHash: profileHash,
		},
		Operation: operation,
		Period:    validatedIntentV2Period{Mode: mode, Start: start, End: end},
		Filters:   filters,
		Sort:      sort,
		Limit:     limitValue,
		Output:    output,
		Limits: validatedIntentV2Limits{
			MaxInputRows: strconv.FormatInt(limits.MaxInputRows, 10), MaxOutputGroups: limits.MaxOutputGroups,
			MaxPeriodDays: limits.MaxPeriodDays, MaxResultBytes: strconv.FormatInt(limits.MaxResultBytes, 10),
			StatementTimeoutMS: strconv.FormatInt(limits.StatementTimeoutMS, 10),
		},
		Coverage: value.coverage,
	}
	switch operation {
	case OperationAGGREGATE:
		measure, measureOK := value.proposal.Measure()
		measureID, measureIDOK := measure.MeasureID()
		dimensions, dimensionsOK := value.proposal.Dimensions()
		fields, fieldsOK := dimensions.Fields()
		names, namesOK := projectValidatedIntentV2FieldNames(fields)
		if !measureOK || !measureIDOK || !dimensionsOK || !fieldsOK || !namesOK {
			return validatedIntentV2Projection{}, false
		}
		projected.Aggregate = &validatedIntentV2Aggregate{Measure: measureID, Dimensions: names}
	case OperationLOOKUP:
		outputFields, outputFieldsOK := value.proposal.OutputFields()
		fields, fieldsOK := outputFields.Fields()
		names, namesOK := projectValidatedIntentV2FieldNames(fields)
		if !outputFieldsOK || !fieldsOK || !namesOK {
			return validatedIntentV2Projection{}, false
		}
		projected.Lookup = &validatedIntentV2Lookup{OutputFields: names}
	default:
		return validatedIntentV2Projection{}, false
	}
	return projected, true
}

// canonicalDigest recomputes the seal digest, failing closed on projection.
func (value ValidatedIntentV2) canonicalDigest() (string, bool) {
	projection, ok := value.canonicalProjection()
	if !ok {
		return "", false
	}
	raw, err := canon.CanonicalJSON(projection)
	if err != nil {
		return "", false
	}
	return canon.Hash(raw), true
}

func projectValidatedIntentV2Predicates(predicates []Predicate) ([]validatedIntentV2Predicate, bool) {
	projected := make([]validatedIntentV2Predicate, len(predicates))
	for index, predicate := range predicates {
		field, fieldOK := predicate.Field().Value()
		op := predicate.Op()
		values := predicate.Values()
		if !fieldOK || !op.Valid() || len(values) == 0 {
			return nil, false
		}
		scalars := make([]validatedIntentV2Scalar, len(values))
		for valueIndex, scalar := range values {
			projectedScalar, ok := projectValidatedIntentV2Scalar(scalar)
			if !ok {
				return nil, false
			}
			scalars[valueIndex] = projectedScalar
		}
		projected[index] = validatedIntentV2Predicate{Field: field, Op: op, Values: scalars}
	}
	return projected, true
}

// projectValidatedIntentV2Scalar preserves the kind and exact canonical value.
func projectValidatedIntentV2Scalar(value Scalar) (validatedIntentV2Scalar, bool) {
	projected := validatedIntentV2Scalar{Kind: value.Kind()}
	if flag, ok := value.Bool(); ok {
		projected.Bool = &flag
		return projected, true
	}
	if number, ok := value.Int(); ok {
		text := strconv.FormatInt(number, 10)
		projected.Int = &text
		return projected, true
	}
	if text, ok := projectValidatedIntentV2ScalarText(value); ok {
		projected.Text = &text
		return projected, true
	}
	return validatedIntentV2Scalar{}, false
}

func projectValidatedIntentV2ScalarText(value Scalar) (string, bool) {
	switch value.Kind() {
	case KindNUMERIC:
		return value.Numeric()
	case KindTEXT:
		return value.Text()
	case KindDATE:
		return value.Date()
	case KindTIMESTAMP:
		return value.Timestamp()
	case KindTIMESTAMPTZ:
		return value.Timestamptz()
	default:
		return "", false
	}
}

func projectValidatedIntentV2SortKeys(keys []SortKey) ([]validatedIntentV2SortKey, bool) {
	projected := make([]validatedIntentV2SortKey, len(keys))
	for index, key := range keys {
		targetKind, targetOK := key.TargetKind()
		direction, directionOK := key.Direction()
		if !targetOK || !directionOK {
			return nil, false
		}
		item := validatedIntentV2SortKey{TargetKind: targetKind, Direction: direction}
		switch targetKind {
		case SortTargetDIMENSION:
			field, fieldOK := key.Dimension()
			name, nameOK := field.Value()
			if !fieldOK || !nameOK {
				return nil, false
			}
			item.Field = name
		case SortTargetMEASURE:
			measure, measureOK := key.Measure()
			id, idOK := measure.MeasureID()
			if !measureOK || !idOK {
				return nil, false
			}
			item.Measure = id
		default:
			return nil, false
		}
		projected[index] = item
	}
	return projected, true
}

// projectValidatedIntentV2FieldNames projects tokens in request order into a
// non-nil list, so an empty dimension list seals as [] and never null.
func projectValidatedIntentV2FieldNames(fields []FieldToken) ([]string, bool) {
	names := make([]string, 0, len(fields))
	for _, field := range fields {
		name, ok := field.Value()
		if !ok {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}
