// Package queryintent models the model-proposed QueryIntent from R2 Outcome 2.
//
// The model never receives a database handle or a query builder: it only emits
// a Proposal, and the server-side Validator either turns that proposal into a
// sealed Intent or refuses it with a typed Error carrying a human clarification
// text. Validation is the only path to an Intent, and an Intent is only ever
// produced against an APPROVED metricdef.Definition whose WorkspaceID matches
// the validator's workspace.
//
// The package is deliberately pure. It performs no I/O, holds no SQL, and
// exposes no free-text or query field on any exported type: a proposal can
// carry a metric id, a version, a period, filter names, an output shape and an
// as-of instant, and nothing else. Refusal messages are generic and never echo
// proposal or model content.
package queryintent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/metricdef"
)

const (
	maxIDLength     = 256
	maxNameLength   = 128
	maxFilterLength = 128
	maxFilters      = 64
)

// Output is the closed shape of a requested structured answer. VALUE and
// ROWSET mirror the two arms of the R2 AnswerResult (value | rowset_ref).
type Output string

const (
	OutputValue  Output = "VALUE"
	OutputRowset Output = "ROWSET"
)

func (o Output) valid() bool {
	return o == OutputValue || o == OutputRowset
}

// Period is the requested time window and its aggregation grain. Grain must
// equal the grain of the APPROVED definition; a mismatch is a malformed period
// rather than a silently coerced query.
type Period struct {
	Grain metricdef.PeriodGrain
	Start time.Time
	End   time.Time
}

// Proposal is exactly the model-proposed QueryIntent shape
// {metric_id, version, period, filters, output, as_of}. It has no query, SQL or
// free-text field: the only strings it can carry are a bounded metric id and
// bounded filter names, both checked against server-owned data.
type Proposal struct {
	MetricID string
	Version  int64
	Period   Period
	Filters  []string
	Output   Output
	AsOf     time.Time
}

// ErrorCode is a content-free, safe-to-map refusal class.
type ErrorCode string

const (
	CodeInvalidProposal           ErrorCode = "QUERYINTENT_INVALID_PROPOSAL"
	CodeUnknownMetric             ErrorCode = "QUERYINTENT_UNKNOWN_METRIC"
	CodeUnknownVersion            ErrorCode = "QUERYINTENT_UNKNOWN_VERSION"
	CodeRetiredVersion            ErrorCode = "QUERYINTENT_RETIRED_VERSION"
	CodeNotApproved               ErrorCode = "QUERYINTENT_NOT_APPROVED"
	CodeFilterNotAllowed          ErrorCode = "QUERYINTENT_FILTER_NOT_ALLOWED"
	CodeMalformedPeriod           ErrorCode = "QUERYINTENT_MALFORMED_PERIOD"
	CodeCatalogUnavailable        ErrorCode = "QUERYINTENT_CATALOG_UNAVAILABLE"
	CodeCatalogBindingMismatch    ErrorCode = "QUERYINTENT_CATALOG_BINDING_MISMATCH"
	CodeDatasetProfileUnavailable ErrorCode = "QUERYINTENT_DATASET_PROFILE_UNAVAILABLE"
	CodeMeasureUnavailable        ErrorCode = "QUERYINTENT_MEASURE_UNAVAILABLE"
	CodeDimensionUnavailable      ErrorCode = "QUERYINTENT_DIMENSION_UNAVAILABLE"
	CodeOutputFieldUnavailable    ErrorCode = "QUERYINTENT_OUTPUT_FIELD_UNAVAILABLE"
	CodeSortUnavailable           ErrorCode = "QUERYINTENT_SORT_UNAVAILABLE"
	CodeLimitExceeded             ErrorCode = "QUERYINTENT_LIMIT_EXCEEDED"
)

func clarificationFor(code ErrorCode) string {
	switch code {
	case CodeInvalidProposal:
		return "The request is incomplete: provide a metric id, a positive version, an output of VALUE or ROWSET, and an explicit as-of time."
	case CodeUnknownMetric:
		return "No metric definition with this id exists in this workspace. Choose an existing metric."
	case CodeUnknownVersion:
		return "This metric definition version is not known. Choose a published version."
	case CodeRetiredVersion:
		return "This metric definition version has been retired and can no longer be queried. Choose the current approved version."
	case CodeNotApproved:
		return "This metric definition version is not approved yet and cannot be queried. Ask the workspace owner to approve it."
	case CodeFilterNotAllowed:
		return "One or more requested filters are not allowed by this metric definition. Remove them or use an allowed filter."
	case CodeMalformedPeriod:
		return "The requested period is missing or does not match this metric definition's grain. Provide a start and end that match the definition grain."
	case CodeCatalogUnavailable:
		return "Metric definitions are temporarily unavailable. Try again later."
	case CodeCatalogBindingMismatch:
		return "The snapshot this request was checked against is not the snapshot now installed. Refresh and try again."
	case CodeDatasetProfileUnavailable:
		return "This dataset profile is not available in the current catalog. Choose a dataset profile that is active."
	case CodeMeasureUnavailable:
		return "This measure is not available in the selected dataset profile. Choose a measure that profile defines."
	case CodeDimensionUnavailable:
		return "A requested grouping field is not available in the selected dataset profile. Choose a field this profile allows grouping by."
	case CodeOutputFieldUnavailable:
		return "A requested output field is not available in the selected dataset profile. Choose a field this profile allows in results."
	case CodeSortUnavailable:
		return "A requested sort is not available in the selected dataset profile. Sort by a field or measure this profile allows."
	case CodeLimitExceeded:
		return "The requested row limit is above what the selected dataset profile allows. Ask for fewer rows."
	default:
		return "The request could not be validated. Adjust it and try again."
	}
}

// Error is the typed refusal returned by this package. It never carries source,
// metric or model content: only a code and a generic clarification text.
type Error struct {
	code          ErrorCode
	clarification string
}

func (e *Error) Error() string { return string(e.code) }

// Code is this refusal's typed code.
func (e *Error) Code() ErrorCode { return e.code }

// Clarification is the non-empty, human-readable text the UI shows.
func (e *Error) Clarification() string { return e.clarification }

func newRefusal(code ErrorCode) *Error {
	return &Error{code: code, clarification: clarificationFor(code)}
}

// CodeOf returns the typed refusal code of err, or an empty code when err is
// nil or is not a queryintent refusal.
func CodeOf(err error) ErrorCode {
	if err == nil {
		return ""
	}
	var target *Error
	if errors.As(err, &target) {
		return target.code
	}
	return ""
}

// ClarificationOf returns the clarification text of err, or an empty string
// when err is nil or is not a queryintent refusal.
func ClarificationOf(err error) string {
	if err == nil {
		return ""
	}
	var target *Error
	if errors.As(err, &target) {
		return target.clarification
	}
	return ""
}

// Intent is a validated, server-sealed query intent. Every field is unexported
// and no exported constructor exists, so an "executed" intent can only come
// from Validator.Validate's success path. All fields are comparable, so two
// equal validated intents compare equal with ==.
type Intent struct {
	metricID    string
	version     int64
	unit        string
	grain       metricdef.PeriodGrain
	periodStart time.Time
	periodEnd   time.Time
	filterKey   string
	output      Output
	asOf        time.Time
}

// MetricID is the canonical definition id the intent was validated against.
func (intent Intent) MetricID() string { return intent.metricID }

// Version is the exact APPROVED definition version the intent is bound to.
func (intent Intent) Version() int64 { return intent.version }

// Unit is the unit of the validated definition.
func (intent Intent) Unit() string { return intent.unit }

// Period is the validated period window.
func (intent Intent) Period() Period {
	return Period{Grain: intent.grain, Start: intent.periodStart, End: intent.periodEnd}
}

// Filters returns a fresh, canonical (sorted, de-duplicated) copy of the
// validated filter names.
func (intent Intent) Filters() []string { return decodeFilterKey(intent.filterKey) }

// Output is the requested structured output shape.
func (intent Intent) Output() Output { return intent.output }

// AsOf is the validated as-of instant, in UTC.
func (intent Intent) AsOf() time.Time { return intent.asOf }

// Digest is a deterministic hash of the canonical validated intent. Equal
// intents always produce the same digest.
func (intent Intent) Digest() string {
	var builder strings.Builder
	builder.WriteString(intent.metricID)
	builder.WriteByte('\x1f')
	builder.WriteString(strconv.FormatInt(intent.version, 10))
	builder.WriteByte('\x1f')
	builder.WriteString(string(intent.grain))
	builder.WriteByte('\x1f')
	builder.WriteString(formatInstant(intent.periodStart))
	builder.WriteByte('\x1f')
	builder.WriteString(formatInstant(intent.periodEnd))
	builder.WriteByte('\x1f')
	builder.WriteString(intent.filterKey)
	builder.WriteByte('\x1f')
	builder.WriteString(string(intent.output))
	builder.WriteByte('\x1f')
	builder.WriteString(formatInstant(intent.asOf))
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

func formatInstant(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func encodeFilterKey(filters []string) string {
	return strings.Join(filters, "\x00")
}

func decodeFilterKey(key string) []string {
	if key == "" {
		return []string{}
	}
	return strings.Split(key, "\x00")
}

// Catalog is the injected definition lookup. Versions returns every version of
// metricID that the workspace knows; the second result is false when the metric
// id is unknown to the catalog. The validator only reads definitions through
// this boundary and never mutates them.
type Catalog interface {
	Versions(workspaceID, metricID string) ([]metricdef.Definition, bool)
}

// CatalogFunc adapts a function to the Catalog interface.
type CatalogFunc func(workspaceID, metricID string) ([]metricdef.Definition, bool)

// Versions implements Catalog.
func (f CatalogFunc) Versions(workspaceID, metricID string) ([]metricdef.Definition, bool) {
	if f == nil {
		return nil, false
	}
	return f(workspaceID, metricID)
}

// MemoryCatalog is a small in-process Catalog, useful at the persistence
// boundary and in tests. It stores definitions by workspace and metric id.
type MemoryCatalog struct {
	mu          sync.RWMutex
	byWorkspace map[string]map[string][]metricdef.Definition
}

// NewMemoryCatalog returns an empty catalog.
func NewMemoryCatalog() *MemoryCatalog {
	return &MemoryCatalog{byWorkspace: map[string]map[string][]metricdef.Definition{}}
}

// Add records one definition version. Definitions with an empty workspace or
// metric id are ignored: the catalog never invents identity.
func (c *MemoryCatalog) Add(definition metricdef.Definition) {
	workspaceID := definition.WorkspaceID()
	metricID := definition.ID()
	if workspaceID == "" || metricID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.byWorkspace == nil {
		c.byWorkspace = map[string]map[string][]metricdef.Definition{}
	}
	byMetric := c.byWorkspace[workspaceID]
	if byMetric == nil {
		byMetric = map[string][]metricdef.Definition{}
		c.byWorkspace[workspaceID] = byMetric
	}
	byMetric[metricID] = append(byMetric[metricID], definition)
}

// Versions implements Catalog.
func (c *MemoryCatalog) Versions(workspaceID, metricID string) ([]metricdef.Definition, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	byMetric := c.byWorkspace[workspaceID]
	if byMetric == nil {
		return nil, false
	}
	versions, ok := byMetric[metricID]
	if !ok {
		return nil, false
	}
	copied := make([]metricdef.Definition, len(versions))
	copy(copied, versions)
	return copied, true
}

// Validator validates model proposals against one workspace's APPROVED metric
// definitions. It is safe for concurrent use because it holds no mutable state.
type Validator struct {
	workspaceID string
	catalog     Catalog
}

// NewValidator returns a validator bound to workspaceID and the injected
// catalog. A nil catalog is accepted here but every Validate call fails closed
// with CodeCatalogUnavailable.
func NewValidator(workspaceID string, catalog Catalog) (Validator, error) {
	if !validLabel(workspaceID, maxIDLength) {
		return Validator{}, newRefusal(CodeInvalidProposal)
	}
	return Validator{workspaceID: workspaceID, catalog: catalog}, nil
}

// WorkspaceID is the workspace this validator is bound to.
func (v Validator) WorkspaceID() string { return v.workspaceID }

// Validate turns a proposal into a sealed Intent or a typed refusal. The
// returned Intent is always the zero value on refusal, so a caller can never
// execute a partially validated intent.
func (v Validator) Validate(proposal Proposal) (Intent, error) {
	if v.catalog == nil {
		return Intent{}, newRefusal(CodeCatalogUnavailable)
	}
	if err := validateProposalShape(proposal); err != nil {
		return Intent{}, err
	}

	versions, ok := v.catalog.Versions(v.workspaceID, proposal.MetricID)
	if !ok || len(versions) == 0 {
		return Intent{}, newRefusal(CodeUnknownMetric)
	}

	definition, found := findVersion(versions, v.workspaceID, proposal.MetricID, proposal.Version)
	if !found {
		return Intent{}, newRefusal(CodeUnknownVersion)
	}

	switch definition.Status() {
	case metricdef.StatusRetired:
		return Intent{}, newRefusal(CodeRetiredVersion)
	case metricdef.StatusApproved:
		// Continue: only an APPROVED version may be executed.
	default:
		return Intent{}, newRefusal(CodeNotApproved)
	}

	if !validPeriod(proposal.Period, definition.Grain()) {
		return Intent{}, newRefusal(CodeMalformedPeriod)
	}

	filters, err := canonicalFilters(proposal.Filters, definition)
	if err != nil {
		return Intent{}, err
	}

	return Intent{
		metricID:    definition.ID(),
		version:     definition.Version(),
		unit:        definition.Unit(),
		grain:       definition.Grain(),
		periodStart: proposal.Period.Start.UTC(),
		periodEnd:   proposal.Period.End.UTC(),
		filterKey:   encodeFilterKey(filters),
		output:      proposal.Output,
		asOf:        proposal.AsOf.UTC(),
	}, nil
}

func validateProposalShape(proposal Proposal) error {
	if !validLabel(proposal.MetricID, maxIDLength) {
		return newRefusal(CodeInvalidProposal)
	}
	if proposal.Version < 1 {
		return newRefusal(CodeInvalidProposal)
	}
	if !proposal.Output.valid() {
		return newRefusal(CodeInvalidProposal)
	}
	if proposal.AsOf.IsZero() {
		return newRefusal(CodeInvalidProposal)
	}
	return nil
}

func findVersion(versions []metricdef.Definition, workspaceID, metricID string, version int64) (metricdef.Definition, bool) {
	for _, definition := range versions {
		if definition.WorkspaceID() != workspaceID || definition.ID() != metricID {
			continue
		}
		if definition.Version() == version {
			return definition, true
		}
	}
	return metricdef.Definition{}, false
}

func validPeriod(period Period, grain metricdef.PeriodGrain) bool {
	if !metricdef.ValidPeriodGrain(period.Grain) || period.Grain != grain {
		return false
	}
	if period.Start.IsZero() || period.End.IsZero() {
		return false
	}
	return period.Start.Before(period.End)
}

func canonicalFilters(filters []string, definition metricdef.Definition) ([]string, error) {
	if len(filters) > maxFilters {
		return nil, newRefusal(CodeFilterNotAllowed)
	}
	for _, name := range filters {
		if !validLabel(name, maxFilterLength) || !definition.AllowsFilter(name) {
			return nil, newRefusal(CodeFilterNotAllowed)
		}
	}
	unique := make(map[string]struct{}, len(filters))
	for _, name := range filters {
		unique[name] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for name := range unique {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)
	return ordered, nil
}

func validLabel(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}
