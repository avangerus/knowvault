// Package metricdef models the workspace-owned, versioned MetricDefinition
// from R2 Outcome 1. It is deliberately pure: identity resolution and
// persistence live at its boundary, while version monotonicity, owner-only
// approval and approved-version immutability stay testable without HTTP or
// PostgreSQL.
//
// A Definition value itself has no mutators. Every lifecycle transition is a
// method on Series, which owns the version history of one definition id and
// therefore cannot silently reuse or lower an already issued version.
package metricdef

import (
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxIDLength     = 256
	maxNameLength   = 200
	maxUnitLength   = 64
	maxFilterLength = 128
	maxFilters      = 64
)

// Status is the closed lifecycle state of one MetricDefinition version.
// Exactly three states exist; there is no implicit "approved" middle state.
type Status string

const (
	StatusDraft    Status = "DRAFT"
	StatusApproved Status = "APPROVED"
	StatusRetired  Status = "RETIRED"
)

func (status Status) valid() bool {
	switch status {
	case StatusDraft, StatusApproved, StatusRetired:
		return true
	default:
		return false
	}
}

// ValidStatus reports whether value is one of the three server-owned states.
func ValidStatus(value Status) bool { return value.valid() }

// PeriodGrain is the closed aggregation grain of a definition's period.
type PeriodGrain string

const (
	GrainDay     PeriodGrain = "DAY"
	GrainWeek    PeriodGrain = "WEEK"
	GrainMonth   PeriodGrain = "MONTH"
	GrainQuarter PeriodGrain = "QUARTER"
	GrainYear    PeriodGrain = "YEAR"
)

func (grain PeriodGrain) valid() bool {
	switch grain {
	case GrainDay, GrainWeek, GrainMonth, GrainQuarter, GrainYear:
		return true
	default:
		return false
	}
}

// ValidPeriodGrain reports whether value is a known grain.
func ValidPeriodGrain(value PeriodGrain) bool { return value.valid() }

// SourceConnection pins a definition to an exact source projection version,
// never a floating "latest" reference.
type SourceConnection struct {
	ConnectionID      string
	ProjectionVersion int64
}

func (source SourceConnection) valid() bool {
	return validID(source.ConnectionID) && source.ProjectionVersion >= 1
}

// FilterSet is a canonical, order-insensitive set of filter names a definition
// allows. It is a value: Values always returns a defensive sorted copy, so a
// caller cannot mutate the set through a getter.
type FilterSet struct {
	values []string
}

// NewFilterSet validates, de-duplicates and sorts the supplied filter names.
func NewFilterSet(values []string) (FilterSet, error) {
	if len(values) > maxFilters {
		return FilterSet{}, newError(CodeInvalidDefinition)
	}
	unique := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validLabel(value, maxFilterLength) {
			return FilterSet{}, newError(CodeInvalidDefinition)
		}
		unique[value] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for value := range unique {
		ordered = append(ordered, value)
	}
	sort.Strings(ordered)
	return FilterSet{values: ordered}, nil
}

// Values returns the canonical, sorted filter names as a copy.
func (set FilterSet) Values() []string {
	copied := make([]string, len(set.values))
	copy(copied, set.values)
	return copied
}

// Allows reports whether name is part of the allowed filter set.
func (set FilterSet) Allows(name string) bool {
	for _, value := range set.values {
		if value == name {
			return true
		}
	}
	return false
}

// Len is the number of allowed filters.
func (set FilterSet) Len() int { return len(set.values) }

// Spec carries the product fields of one metric-definition version. Identity
// (id, workspace, owner) and the version number are never part of a Spec: they
// are owned by the Series, so a caller cannot choose or reuse a version.
type Spec struct {
	Name           string
	Source         SourceConnection
	EntityKey      string
	Grain          PeriodGrain
	Unit           string
	AllowedFilters []string
}

type normalizedSpec struct {
	name      string
	source    SourceConnection
	entityKey string
	grain     PeriodGrain
	unit      string
	filters   FilterSet
}

func normalizeSpec(spec Spec) (normalizedSpec, error) {
	if !validLabel(spec.Name, maxNameLength) || !spec.Source.valid() || !validFieldName(spec.EntityKey) ||
		!spec.Grain.valid() || !validOptionalLabel(spec.Unit, maxUnitLength) {
		return normalizedSpec{}, newError(CodeInvalidDefinition)
	}
	filters, err := NewFilterSet(spec.AllowedFilters)
	if err != nil {
		return normalizedSpec{}, err
	}
	return normalizedSpec{
		name:      spec.Name,
		source:    spec.Source,
		entityKey: spec.EntityKey,
		grain:     spec.Grain,
		unit:      spec.Unit,
		filters:   filters,
	}, nil
}

// ErrorCode is a content-free, safe-to-map failure class.
type ErrorCode string

const (
	CodeInvalidDefinition   ErrorCode = "METRICDEF_INVALID_DEFINITION"
	CodeVersionNotMonotonic ErrorCode = "METRICDEF_VERSION_NOT_MONOTONIC"
	CodeNotWorkspaceOwner   ErrorCode = "METRICDEF_NOT_WORKSPACE_OWNER"
	CodeNotApprovable       ErrorCode = "METRICDEF_NOT_APPROVABLE"
	CodeNotRetirable        ErrorCode = "METRICDEF_NOT_RETIRABLE"
	CodeRetiredImmutable    ErrorCode = "METRICDEF_RETIRED_IMMUTABLE"
	CodeAuditUnavailable    ErrorCode = "METRICDEF_AUDIT_UNAVAILABLE"
	CodeAuditFailed         ErrorCode = "METRICDEF_AUDIT_FAILED"
	CodeUnknownVersion      ErrorCode = "METRICDEF_UNKNOWN_VERSION"
)

// Error is the typed refusal returned by this package. It never carries
// source, metric or model content.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

func newError(code ErrorCode) *Error { return &Error{code: code} }

// CodeOf returns the typed code of err, or an empty code when err is nil or is
// not a metricdef error.
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

// Definition is one immutable MetricDefinition version. Its fields are
// unexported so an approved value cannot be edited in place; changes flow
// through Series, which creates a new version.
type Definition struct {
	id               string
	workspaceID      string
	ownerPrincipalID string
	version          int64
	name             string
	source           SourceConnection
	entityKey        string
	grain            PeriodGrain
	allowedFilters   FilterSet
	unit             string
	status           Status
}

// ID is the stable definition id shared by every version.
func (definition Definition) ID() string { return definition.id }

// WorkspaceID is the owning workspace.
func (definition Definition) WorkspaceID() string { return definition.workspaceID }

// OwnerPrincipalID is the workspace owner allowed to approve this version.
func (definition Definition) OwnerPrincipalID() string { return definition.ownerPrincipalID }

// Version is the monotonic version number issued for this id.
func (definition Definition) Version() int64 { return definition.version }

// Name is the human-readable definition name.
func (definition Definition) Name() string { return definition.name }

// Source is the pinned source connection and projection version.
func (definition Definition) Source() SourceConnection { return definition.source }

// EntityKey is the entity key the definition aggregates over.
func (definition Definition) EntityKey() string { return definition.entityKey }

// Grain is the period grain.
func (definition Definition) Grain() PeriodGrain { return definition.grain }

// AllowedFilters returns a copy of the canonical allowed filter names.
func (definition Definition) AllowedFilters() []string { return definition.allowedFilters.Values() }

// AllowsFilter reports whether name is inside the allowed filter set.
func (definition Definition) AllowsFilter(name string) bool {
	return definition.allowedFilters.Allows(name)
}

// Unit is the result unit (may be empty for a dimensionless metric).
func (definition Definition) Unit() string { return definition.unit }

// Status is the lifecycle state of this exact version.
func (definition Definition) Status() Status { return definition.status }

// Approved reports whether this version carries the APPROVED state.
func (definition Definition) Approved() bool { return definition.status == StatusApproved }

// ApprovalEvent is the content-free record of one successful approval.
type ApprovalEvent struct {
	DefinitionID     string
	WorkspaceID      string
	Version          int64
	ActorPrincipalID string
	OccurredAt       time.Time
}

// ApprovalAuditor is the injected audit boundary for approvals. Approve calls
// RecordApproval exactly once and fails closed when the auditor refuses.
type ApprovalAuditor interface {
	RecordApproval(ApprovalEvent) error
}

// RetirementEvent is the content-free record of one successful retirement.
type RetirementEvent struct {
	DefinitionID     string
	WorkspaceID      string
	Version          int64
	ActorPrincipalID string
	OccurredAt       time.Time
}

// RetirementAuditor is the injected audit boundary for retirements.
type RetirementAuditor interface {
	RecordRetirement(RetirementEvent) error
}

// Series is the version history for a single definition id. Every mutating
// method returns a new Series value and never changes an existing Definition.
type Series struct {
	id               string
	workspaceID      string
	ownerPrincipalID string
	versions         map[int64]Definition
	highest          int64
}

// NewSeries creates version 1 of a new definition id in DRAFT state.
func NewSeries(id, workspaceID, ownerPrincipalID string, spec Spec) (Series, error) {
	if !validID(id) || !validID(workspaceID) || !validID(ownerPrincipalID) {
		return Series{}, newError(CodeInvalidDefinition)
	}
	normalized, err := normalizeSpec(spec)
	if err != nil {
		return Series{}, err
	}
	definition := Definition{
		id:               id,
		workspaceID:      workspaceID,
		ownerPrincipalID: ownerPrincipalID,
		version:          1,
		name:             normalized.name,
		source:           normalized.source,
		entityKey:        normalized.entityKey,
		grain:            normalized.grain,
		allowedFilters:   normalized.filters,
		unit:             normalized.unit,
		status:           StatusDraft,
	}
	return Series{
		id:               id,
		workspaceID:      workspaceID,
		ownerPrincipalID: ownerPrincipalID,
		versions:         map[int64]Definition{1: definition},
		highest:          1,
	}, nil
}

// ID is the definition id shared by every version of this series.
func (s Series) ID() string { return s.id }

// WorkspaceID is the owning workspace.
func (s Series) WorkspaceID() string { return s.workspaceID }

// OwnerPrincipalID is the workspace owner allowed to approve a version.
func (s Series) OwnerPrincipalID() string { return s.ownerPrincipalID }

// Highest is the highest version number issued so far (0 for a zero Series).
func (s Series) Highest() int64 { return s.highest }

// Current returns the highest issued version.
func (s Series) Current() Definition {
	definition, _ := s.Version(s.highest)
	return definition
}

// Version returns the definition for an exact version number.
func (s Series) Version(version int64) (Definition, bool) {
	if s.versions == nil {
		return Definition{}, false
	}
	definition, ok := s.versions[version]
	return definition, ok
}

// Versions enumerates every issued version of this definition id in ascending
// version order. A nil or zero Series yields an empty slice, never a panic. The
// returned Definitions are defensive copies, so mutating the slice or any
// returned value cannot change the Series.
func (s Series) Versions() []Definition {
	ordered := make([]Definition, 0, len(s.versions))
	for _, definition := range s.versions {
		ordered = append(ordered, definition.defensiveCopy())
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].version < ordered[j].version })
	return ordered
}

// defensiveCopy returns a Definition value that shares no mutable state with
// the receiver. The struct itself is copied by value; the only reference field
// is the allowed-filter slice, which is copied so a caller cannot reach the
// Series' backing array.
func (definition Definition) defensiveCopy() Definition {
	copied := definition
	copied.allowedFilters = FilterSet{values: definition.allowedFilters.Values()}
	return copied
}

// Supersede applies spec to the current version. A DRAFT is edited in place
// (same version); an APPROVED version is immutable, so this creates a new DRAFT
// with version highest+1 for the same id. A RETIRED version is refused.
func (s Series) Supersede(spec Spec) (Series, error) {
	current, ok := s.Version(s.highest)
	if !ok {
		return s, newError(CodeUnknownVersion)
	}
	normalized, err := normalizeSpec(spec)
	if err != nil {
		return s, err
	}
	switch current.status {
	case StatusDraft:
		next := current
		next.name = normalized.name
		next.source = normalized.source
		next.entityKey = normalized.entityKey
		next.grain = normalized.grain
		next.allowedFilters = normalized.filters
		next.unit = normalized.unit
		updated := s.clone()
		updated.versions[next.version] = next
		return updated, nil
	case StatusApproved:
		next := Definition{
			id:               s.id,
			workspaceID:      s.workspaceID,
			ownerPrincipalID: s.ownerPrincipalID,
			version:          s.highest + 1,
			name:             normalized.name,
			source:           normalized.source,
			entityKey:        normalized.entityKey,
			grain:            normalized.grain,
			allowedFilters:   normalized.filters,
			unit:             normalized.unit,
			status:           StatusDraft,
		}
		updated := s.clone()
		updated.versions[next.version] = next
		updated.highest = next.version
		return updated, nil
	default:
		return s, newError(CodeRetiredImmutable)
	}
}

// ImportVersion adds an explicit future DRAFT version for the persistence
// boundary when rehydrating history. It refuses any version that is not
// strictly greater than the highest already issued, so a version can never be
// reused or lowered, and it can never fabricate an APPROVED version.
func (s Series) ImportVersion(version int64, spec Spec) (Series, error) {
	if version < 1 {
		return s, newError(CodeInvalidDefinition)
	}
	if version <= s.highest {
		return s, newError(CodeVersionNotMonotonic)
	}
	normalized, err := normalizeSpec(spec)
	if err != nil {
		return s, err
	}
	definition := Definition{
		id:               s.id,
		workspaceID:      s.workspaceID,
		ownerPrincipalID: s.ownerPrincipalID,
		version:          version,
		name:             normalized.name,
		source:           normalized.source,
		entityKey:        normalized.entityKey,
		grain:            normalized.grain,
		allowedFilters:   normalized.filters,
		unit:             normalized.unit,
		status:           StatusDraft,
	}
	updated := s.clone()
	updated.versions[version] = definition
	updated.highest = version
	return updated, nil
}

// Approve flips the current DRAFT version to APPROVED. It succeeds only for
// the workspace owner and only with a working auditor; a successful approval
// emits exactly one ApprovalEvent. Any refusal leaves the Series unchanged.
func (s Series) Approve(actorPrincipalID string, auditor ApprovalAuditor, at time.Time) (Series, error) {
	if !validID(actorPrincipalID) || actorPrincipalID != s.ownerPrincipalID {
		return s, newError(CodeNotWorkspaceOwner)
	}
	current, ok := s.Version(s.highest)
	if !ok {
		return s, newError(CodeUnknownVersion)
	}
	if current.status != StatusDraft {
		return s, newError(CodeNotApprovable)
	}
	if at.IsZero() {
		return s, newError(CodeInvalidDefinition)
	}
	if auditor == nil {
		return s, newError(CodeAuditUnavailable)
	}
	event := ApprovalEvent{
		DefinitionID:     s.id,
		WorkspaceID:      s.workspaceID,
		Version:          current.version,
		ActorPrincipalID: actorPrincipalID,
		OccurredAt:       at.UTC(),
	}
	if err := auditor.RecordApproval(event); err != nil {
		return s, &Error{code: CodeAuditFailed, cause: err}
	}
	approved := current
	approved.status = StatusApproved
	updated := s.clone()
	updated.versions[approved.version] = approved
	return updated, nil
}

// Retire flips the current APPROVED version to RETIRED. It is owner-only and
// audited like Approve. A RETIRED version can neither be approved nor edited.
func (s Series) Retire(actorPrincipalID string, auditor RetirementAuditor, at time.Time) (Series, error) {
	if !validID(actorPrincipalID) || actorPrincipalID != s.ownerPrincipalID {
		return s, newError(CodeNotWorkspaceOwner)
	}
	current, ok := s.Version(s.highest)
	if !ok {
		return s, newError(CodeUnknownVersion)
	}
	if current.status != StatusApproved {
		return s, newError(CodeNotRetirable)
	}
	if at.IsZero() {
		return s, newError(CodeInvalidDefinition)
	}
	if auditor == nil {
		return s, newError(CodeAuditUnavailable)
	}
	event := RetirementEvent{
		DefinitionID:     s.id,
		WorkspaceID:      s.workspaceID,
		Version:          current.version,
		ActorPrincipalID: actorPrincipalID,
		OccurredAt:       at.UTC(),
	}
	if err := auditor.RecordRetirement(event); err != nil {
		return s, &Error{code: CodeAuditFailed, cause: err}
	}
	retired := current
	retired.status = StatusRetired
	updated := s.clone()
	updated.versions[retired.version] = retired
	return updated, nil
}

func (s Series) clone() Series {
	versions := make(map[int64]Definition, len(s.versions))
	for version, definition := range s.versions {
		versions[version] = definition
	}
	return Series{
		id:               s.id,
		workspaceID:      s.workspaceID,
		ownerPrincipalID: s.ownerPrincipalID,
		versions:         versions,
		highest:          s.highest,
	}
}

func validID(value string) bool {
	return validLabel(value, maxIDLength)
}

func validFieldName(value string) bool {
	return validLabel(value, maxIDLength)
}

func validOptionalLabel(value string, max int) bool {
	return value == "" || validLabel(value, max)
}

func validLabel(value string, max int) bool {
	return value != "" && len(value) <= max && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}
