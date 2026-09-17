// Package workspace owns the pure, immutable configuration of a workspace.
//
// It intentionally does not open PostgreSQL or evaluate a request identity.
// Persistence, authorization and any required source-access confirmation live
// at their respective boundaries. This package makes one workspace revision a
// stable, canonical object before it is written or referenced by a future
// Question Run.
package workspace

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const configurationSchemaVersion = "workspace-configuration-v1"

const maxIJSONInteger = int64(9007199254740991)

// ErrorCode is content-free and safe for an API mapper or audit metadata.
type ErrorCode string

const (
	CodeInvalidSnapshot ErrorCode = "WORKSPACE_SNAPSHOT_INVALID"
	CodeHashFailed      ErrorCode = "WORKSPACE_CONFIGURATION_HASH_FAILED"
)

// Error has no caller-visible cause because workspace text may itself be
// sensitive. Callers can use CodeOf for a stable safe code.
type Error struct{ code ErrorCode }

func (e *Error) Error() string { return string(e.code) }

// CodeOf returns a stable, content-free workspace error code.
func CodeOf(err error) ErrorCode {
	var workspaceError *Error
	if errors.As(err, &workspaceError) {
		return workspaceError.code
	}
	return CodeInvalidSnapshot
}

// Status is the durable lifecycle of a workspace configuration.
type Status string

const (
	StatusActive   Status = "ACTIVE"
	StatusReadOnly Status = "READ_ONLY"
	StatusArchived Status = "ARCHIVED"
	StatusDeleting Status = "DELETING"
	StatusDeleted  Status = "DELETED"
)

// Role is a direct current workspace membership role.
type Role string

const (
	RoleOwner   Role = "OWNER"
	RoleManager Role = "MANAGER"
	RoleMember  Role = "MEMBER"
	RoleViewer  Role = "VIEWER"
	RoleAuditor Role = "AUDITOR"
)

// Member is the current role and same-organization display projection of
// exactly one workspace principal. DisplayName is resolved from the current
// principal row for API/UI reads; it is deliberately absent from a revision
// configuration hash so renaming a principal does not mutate workspace
// configuration or its ETag.
type Member struct {
	PrincipalID string
	Role        Role
	DisplayName string
}

// SourceBinding is the immutable source-scope projection for one workspace
// revision. Enabling or disabling a binding advances the workspace revision;
// an existing source-scope ID can never be silently rebound to a different
// scope revision or configuration hash.
type SourceBinding struct {
	SourceScopeID       string
	SourceScopeRevision int64
	ScopeConfigHash     string
	Enabled             bool
}

// Snapshot is the current workspace configuration for one revision plus live
// member display projections. CanonicalSnapshot includes the configuration
// fields only, so Member.DisplayName does not make a revision mutable.
type Snapshot struct {
	OrganizationID    string
	ID                string
	Revision          int64
	Name              string
	Description       string
	Status            Status
	OwnerPrincipalID  string
	RetentionPolicyID string
	Members           []Member
	SourceBindings    []SourceBinding

	// Degraded and DegradedReason are transport-visible read-path markers. They
	// are deliberately outside workspace-configuration-v1: CanonicalSnapshot
	// builds its explicit projection and Normalize clears them, so a marker can
	// never change a configuration hash or be persisted as workspace content.
	Degraded       bool
	DegradedReason string
}

// Normalize validates a snapshot, applies the accepted text-v1 NFC
// normalization and returns a private copy with members in canonical order.
// The supplied slice is never retained or mutated.
func Normalize(snapshot Snapshot) (Snapshot, error) {
	snapshot.Name = norm.NFC.String(snapshot.Name)
	snapshot.Description = norm.NFC.String(snapshot.Description)
	// Keep private slice ownership during normalization. CanonicalSnapshot
	// deliberately materializes source_bindings with make(len), so an empty
	// collection is always the accepted JSON array [] under schema v1.
	snapshot.Members = append([]Member(nil), snapshot.Members...)
	snapshot.SourceBindings = append([]SourceBinding(nil), snapshot.SourceBindings...)
	// Read-path degraded markers are not part of the immutable configuration and
	// are cleared so they can never survive into a canonical snapshot or hash.
	snapshot.Degraded = false
	snapshot.DegradedReason = ""

	if !validID(snapshot.OrganizationID) || !validID(snapshot.ID) || snapshot.Revision < 1 || snapshot.Revision > maxIJSONInteger ||
		!validName(snapshot.Name) || !validDescription(snapshot.Description) || !validStatus(snapshot.Status) ||
		!validID(snapshot.OwnerPrincipalID) || (snapshot.RetentionPolicyID != "" && !validID(snapshot.RetentionPolicyID)) {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	sort.Slice(snapshot.Members, func(left, right int) bool {
		return snapshot.Members[left].PrincipalID < snapshot.Members[right].PrincipalID
	})

	ownerCount := 0
	previousID := ""
	ownerFound := false
	for _, member := range snapshot.Members {
		if !validID(member.PrincipalID) || !validRole(member.Role) || (previousID != "" && member.PrincipalID == previousID) {
			return Snapshot{}, &Error{code: CodeInvalidSnapshot}
		}
		if member.Role == RoleOwner {
			ownerCount++
			ownerFound = member.PrincipalID == snapshot.OwnerPrincipalID
		}
		previousID = member.PrincipalID
	}
	if ownerCount != 1 || !ownerFound {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	sort.Slice(snapshot.SourceBindings, func(left, right int) bool {
		return snapshot.SourceBindings[left].SourceScopeID < snapshot.SourceBindings[right].SourceScopeID
	})
	previousScopeID := ""
	for _, binding := range snapshot.SourceBindings {
		if !validID(binding.SourceScopeID) || binding.SourceScopeRevision < 1 || binding.SourceScopeRevision > maxIJSONInteger || !validHash(binding.ScopeConfigHash) ||
			(previousScopeID != "" && binding.SourceScopeID == previousScopeID) {
			return Snapshot{}, &Error{code: CodeInvalidSnapshot}
		}
		previousScopeID = binding.SourceScopeID
	}
	return snapshot, nil
}

type canonicalMember struct {
	PrincipalID string `json:"principal_id"`
	Role        Role   `json:"role"`
}

type canonicalSourceBinding struct {
	SourceScopeID       string `json:"source_scope_id"`
	SourceScopeRevision int64  `json:"source_scope_revision"`
	ScopeConfigHash     string `json:"scope_config_hash"`
	Enabled             bool   `json:"enabled"`
}

type canonicalConfiguration struct {
	SchemaVersion     string                   `json:"schema_version"`
	OrganizationID    string                   `json:"organization_id"`
	WorkspaceID       string                   `json:"workspace_id"`
	Revision          int64                    `json:"revision"`
	Name              string                   `json:"name"`
	Description       string                   `json:"description"`
	Status            Status                   `json:"status"`
	OwnerPrincipalID  string                   `json:"owner_principal_id"`
	RetentionPolicyID string                   `json:"retention_policy_id"`
	Members           []canonicalMember        `json:"members"`
	SourceBindings    []canonicalSourceBinding `json:"source_bindings"`
}

// CanonicalSnapshot returns the exact JCS bytes of workspace-configuration-v1.
// These bytes are the immutable artifact for one WorkspaceRevision; callers
// must persist them together with the hash, rather than attempting to rebuild
// an older revision from mutable current workspace rows.
func CanonicalSnapshot(snapshot Snapshot) ([]byte, error) {
	normalized, err := Normalize(snapshot)
	if err != nil {
		return nil, err
	}
	members := make([]canonicalMember, len(normalized.Members))
	for index, member := range normalized.Members {
		members[index] = canonicalMember{PrincipalID: member.PrincipalID, Role: member.Role}
	}
	bindings := make([]canonicalSourceBinding, len(normalized.SourceBindings))
	for index, binding := range normalized.SourceBindings {
		bindings[index] = canonicalSourceBinding{
			SourceScopeID: binding.SourceScopeID, SourceScopeRevision: binding.SourceScopeRevision,
			ScopeConfigHash: binding.ScopeConfigHash, Enabled: binding.Enabled,
		}
	}

	raw, err := json.Marshal(canonicalConfiguration{
		SchemaVersion: configurationSchemaVersion, OrganizationID: normalized.OrganizationID,
		WorkspaceID: normalized.ID, Revision: normalized.Revision, Name: normalized.Name,
		Description: normalized.Description, Status: normalized.Status, OwnerPrincipalID: normalized.OwnerPrincipalID,
		RetentionPolicyID: normalized.RetentionPolicyID, Members: members, SourceBindings: bindings,
	})
	if err != nil {
		return nil, &Error{code: CodeHashFailed}
	}
	jsonValue := jsontext.Value(raw)
	if err := jsonValue.Canonicalize(); err != nil {
		return nil, &Error{code: CodeHashFailed}
	}
	return append([]byte(nil), jsonValue...), nil
}

// ParseCanonicalSnapshot accepts only exact workspace-configuration-v1 JCS
// bytes. A semantically equivalent but differently encoded JSON value is
// rejected so a persisted artifact cannot be silently substituted.
func ParseCanonicalSnapshot(canonical []byte) (Snapshot, error) {
	if len(canonical) == 0 || len(canonical) > 1<<20 {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	var configuration canonicalConfiguration
	if err := jsonv2.Unmarshal(canonical, &configuration,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.MatchCaseInsensitiveNames(false),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	); err != nil {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	if configuration.SchemaVersion != configurationSchemaVersion {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	snapshot := Snapshot{
		OrganizationID:    configuration.OrganizationID,
		ID:                configuration.WorkspaceID,
		Revision:          configuration.Revision,
		Name:              configuration.Name,
		Description:       configuration.Description,
		Status:            configuration.Status,
		OwnerPrincipalID:  configuration.OwnerPrincipalID,
		RetentionPolicyID: configuration.RetentionPolicyID,
		Members:           make([]Member, len(configuration.Members)),
		SourceBindings:    make([]SourceBinding, len(configuration.SourceBindings)),
	}
	for index, member := range configuration.Members {
		snapshot.Members[index] = Member{PrincipalID: member.PrincipalID, Role: member.Role}
	}
	for index, binding := range configuration.SourceBindings {
		snapshot.SourceBindings[index] = SourceBinding{
			SourceScopeID: binding.SourceScopeID, SourceScopeRevision: binding.SourceScopeRevision,
			ScopeConfigHash: binding.ScopeConfigHash, Enabled: binding.Enabled,
		}
	}

	normalized, err := Normalize(snapshot)
	if err != nil {
		return Snapshot{}, err
	}
	recomputed, err := CanonicalSnapshot(normalized)
	if err != nil || !bytes.Equal(canonical, recomputed) {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	return normalized, nil
}

// ConfigurationHash creates the deterministic sha256 hash stored with a
// WorkspaceRevision. It hashes the same immutable bytes returned by
// CanonicalSnapshot, never a separately constructed projection.
func ConfigurationHash(snapshot Snapshot) (string, error) {
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

// IsConfigurationHash validates the exact precondition representation emitted
// by ConfigurationHash without accepting aliases or uppercase hexadecimal.
func IsConfigurationHash(value string) bool { return validHash(value) }

// NextMetadata advances one workspace revision without changing direct
// memberships or source bindings. Callers must persist the returned snapshot
// atomically with its new WorkspaceRevision row.
func NextMetadata(current Snapshot, name, description, retentionPolicyID string) (Snapshot, error) {
	return next(current, func(snapshot *Snapshot) {
		snapshot.Name = name
		snapshot.Description = description
		snapshot.RetentionPolicyID = retentionPolicyID
	})
}

// NextSourceBindingEnabled advances one workspace revision by adding an
// enabled binding or re-enabling the exact disabled binding. A caller must
// supply the desired enabled state. An already-enabled binding and any attempt
// to reuse a source-scope ID with a different revision or hash fail closed.
func NextSourceBindingEnabled(current Snapshot, binding SourceBinding) (Snapshot, error) {
	if !binding.Enabled || !validSourceBinding(binding) {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	normalized, err := Normalize(current)
	if err != nil {
		return Snapshot{}, err
	}
	for index, existing := range normalized.SourceBindings {
		if existing.SourceScopeID != binding.SourceScopeID {
			continue
		}
		if !sameSourceBindingIdentity(existing, binding) || existing.Enabled {
			return Snapshot{}, &Error{code: CodeInvalidSnapshot}
		}
		return next(normalized, func(snapshot *Snapshot) {
			snapshot.SourceBindings[index].Enabled = true
		})
	}

	return next(normalized, func(snapshot *Snapshot) {
		snapshot.SourceBindings = append(snapshot.SourceBindings, binding)
	})
}

// NextSourceBindingDisabled advances one workspace revision by disabling the
// exact enabled binding while retaining it in the canonical snapshot. A caller
// must supply the desired disabled state. Missing, already-disabled or
// tuple-mismatched bindings fail closed.
func NextSourceBindingDisabled(current Snapshot, binding SourceBinding) (Snapshot, error) {
	if binding.Enabled || !validSourceBinding(binding) {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}

	normalized, err := Normalize(current)
	if err != nil {
		return Snapshot{}, err
	}
	for index, existing := range normalized.SourceBindings {
		if existing.SourceScopeID != binding.SourceScopeID {
			continue
		}
		if !sameSourceBindingIdentity(existing, binding) || !existing.Enabled {
			return Snapshot{}, &Error{code: CodeInvalidSnapshot}
		}
		return next(normalized, func(snapshot *Snapshot) {
			snapshot.SourceBindings[index].Enabled = false
		})
	}
	return Snapshot{}, &Error{code: CodeInvalidSnapshot}
}

// NextArchived advances the lifecycle state. It does not delete a workspace
// or any historical revision.
func NextArchived(current Snapshot) (Snapshot, error) {
	return next(current, func(snapshot *Snapshot) { snapshot.Status = StatusArchived })
}

// NextWithMember advances a revision with one newly active non-owner member.
// Ownership transfer is deliberately separate because it must close and
// recreate two historical membership rows in one persistence transaction.
func NextWithMember(current Snapshot, member Member) (Snapshot, error) {
	if member.Role == RoleOwner {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	return next(current, func(snapshot *Snapshot) {
		snapshot.Members = append(snapshot.Members, member)
	})
}

// NextWithoutMember advances a revision after removing one non-owner member.
func NextWithoutMember(current Snapshot, principalID string) (Snapshot, error) {
	normalized, index, err := mutableMember(current, principalID)
	if err != nil {
		return Snapshot{}, err
	}
	return next(normalized, func(snapshot *Snapshot) {
		snapshot.Members = append(snapshot.Members[:index], snapshot.Members[index+1:]...)
	})
}

// NextWithMemberRole closes the previous non-owner role conceptually and
// returns the configuration containing its replacement role.
func NextWithMemberRole(current Snapshot, principalID string, role Role) (Snapshot, error) {
	if role == RoleOwner || !validRole(role) {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	normalized, index, err := mutableMember(current, principalID)
	if err != nil || normalized.Members[index].Role == role {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	return next(normalized, func(snapshot *Snapshot) { snapshot.Members[index].Role = role })
}

// NextOwnershipTransferred moves the sole OWNER role to an existing non-owner
// member and demotes the previous owner to MANAGER.
func NextOwnershipTransferred(current Snapshot, newOwnerPrincipalID string) (Snapshot, error) {
	normalized, targetIndex, err := mutableMember(current, newOwnerPrincipalID)
	if err != nil {
		return Snapshot{}, err
	}
	previousOwnerIndex := -1
	for index, member := range normalized.Members {
		if member.Role == RoleOwner {
			previousOwnerIndex = index
			break
		}
	}
	if previousOwnerIndex < 0 || previousOwnerIndex == targetIndex {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	return next(normalized, func(snapshot *Snapshot) {
		snapshot.Members[previousOwnerIndex].Role = RoleManager
		snapshot.Members[targetIndex].Role = RoleOwner
		snapshot.OwnerPrincipalID = newOwnerPrincipalID
	})
}

func mutableMember(current Snapshot, principalID string) (Snapshot, int, error) {
	normalized, err := Normalize(current)
	if err != nil || !validID(principalID) || principalID == normalized.OwnerPrincipalID {
		return Snapshot{}, -1, &Error{code: CodeInvalidSnapshot}
	}
	for index, member := range normalized.Members {
		if member.PrincipalID == principalID {
			return normalized, index, nil
		}
	}
	return Snapshot{}, -1, &Error{code: CodeInvalidSnapshot}
}

func next(current Snapshot, mutate func(*Snapshot)) (Snapshot, error) {
	normalized, err := Normalize(current)
	if err != nil || normalized.Revision == maxIJSONInteger || mutate == nil {
		return Snapshot{}, &Error{code: CodeInvalidSnapshot}
	}
	next := normalized
	next.Members = append([]Member(nil), normalized.Members...)
	next.SourceBindings = append([]SourceBinding(nil), normalized.SourceBindings...)
	next.Revision++
	mutate(&next)
	return Normalize(next)
}

func validID(value string) bool {
	if runeCount(value) < 3 || runeCount(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validName(value string) bool {
	return runeCount(value) >= 1 && runeCount(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value && !hasControl(value)
}

func validDescription(value string) bool {
	return runeCount(value) <= 4096 && utf8.ValidString(value) && !hasControl(value)
}

func validStatus(status Status) bool {
	switch status {
	case StatusActive, StatusReadOnly, StatusArchived, StatusDeleting, StatusDeleted:
		return true
	default:
		return false
	}
}

func validRole(role Role) bool {
	switch role {
	case RoleOwner, RoleManager, RoleMember, RoleViewer, RoleAuditor:
		return true
	default:
		return false
	}
}

func validSourceBinding(binding SourceBinding) bool {
	return validID(binding.SourceScopeID) && binding.SourceScopeRevision >= 1 &&
		binding.SourceScopeRevision <= maxIJSONInteger && validHash(binding.ScopeConfigHash)
}

func sameSourceBindingIdentity(left, right SourceBinding) bool {
	return left.SourceScopeID == right.SourceScopeID &&
		left.SourceScopeRevision == right.SourceScopeRevision &&
		left.ScopeConfigHash == right.ScopeConfigHash
}

func hasControl(value string) bool {
	return strings.ContainsFunc(value, func(character rune) bool {
		return character < 0x20 || (character >= 0x7f && character <= 0x9f)
	})
}

func validHash(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func runeCount(value string) int { return utf8.RuneCountInString(value) }
