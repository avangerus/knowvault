package repository

// Workspace-managed authority command surface (ADR-0052/0053/0054, migration
// 000011). This file owns the closed canonical request envelope: the exact
// per-operation request shape, its syntactic validation and its RFC 8785 JCS
// request hash. It reuses the one canonicalization engine already used by the
// workspace command family (encoding/json + encoding/json/jsontext); it never
// introduces a second JCS engine.
//
// The four operations and the WORKSPACE_AUTHORITY_ error namespace live here
// and in the sibling authority_*.go files by design: this is the repository
// checkpoint ADR-0054 deferred them to. They remain forbidden in every API,
// UI, composition, outbox, activation, ingestion and retrieval surface, and the
// architecture checker still proves their absence there.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"strings"

	"knowvault.local/verified-workspace/internal/workspace"
)

// authorityOperation is the closed set of ADR-0053 operations. An unknown
// operation is a request-shape error, never a soft no-op.
type authorityOperation string

const (
	operationConfirmationGrantIssue  authorityOperation = "WORKSPACE_CONFIRMATION_GRANT_ISSUE"
	operationConfirmationGrantRevoke authorityOperation = "WORKSPACE_CONFIRMATION_GRANT_REVOKE"
	operationManagedConfirm          authorityOperation = "WORKSPACE_MANAGED_CONFIRM"
	operationManagedConfirmRevoke    authorityOperation = "WORKSPACE_MANAGED_CONFIRM_REVOKE"
)

const authorityCommandSchemaVersion = "workspace-managed-authority-command-v1"

// Closed constants a request may only carry as the exact literal.
const (
	authorityAccessModeManaged   = "WORKSPACE_MANAGED"
	authorityWarningVersion      = "workspace-managed-risk-v1"
	authorityAcknowledgementCode = "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
	authorityGrantPermission     = "workspace.source.confirm"
	authorityReasonGrantRevoked  = "AUTHORITY_REVOKED"
	authorityReasonAccessRevoked = "ACCESS_REVOKED"
)

// The public error surface of the authority command boundary (ADR-0053). It is
// content-free and safe for API mapping. It is deliberately distinct from the
// workspace command surface: an authority command never creates a
// WorkspaceRevision, so it must not reuse the WORKSPACE_ codes.
const (
	CodeAuthorityRequestInvalid      ErrorCode = "WORKSPACE_AUTHORITY_REQUEST_INVALID"
	CodeAuthorityIdempotencyConflict ErrorCode = "WORKSPACE_AUTHORITY_IDEMPOTENCY_CONFLICT"
	CodeAuthorityDenied              ErrorCode = "WORKSPACE_AUTHORITY_DENIED"
	CodeAuthorityNotFound            ErrorCode = "WORKSPACE_AUTHORITY_NOT_FOUND"
	CodeAuthorityPreconditionFailed  ErrorCode = "WORKSPACE_AUTHORITY_PRECONDITION_FAILED"
	CodeAuthorityPersistence         ErrorCode = "WORKSPACE_AUTHORITY_PERSISTENCE_FAILED"
)

// IssueGrantRequest is the ADR-0053 WORKSPACE_CONFIRMATION_GRANT_ISSUE request.
// OrganizationID is canonical request data, never tenant authority: it is
// exact-matched against the trusted AccessContext.OrganizationID before any
// tenant-scoped access. Every server-owned field (grant ID, revision,
// permission, granted_at, valid_*) is deliberately absent.
type IssueGrantRequest struct {
	IdempotencyKey                     string
	OrganizationID                     string
	WorkspaceID                        string
	ExpectedWorkspaceRevision          int64
	ExpectedWorkspaceConfigurationHash string
	TargetPrincipalID                  string
	TTLSeconds                         int64
	ExpectedPolicyRevision             string
}

// RevokeGrantRequest is the ADR-0053 WORKSPACE_CONFIRMATION_GRANT_REVOKE
// request. It deliberately carries no expected WorkspaceRevision: a stale grant
// must remain revocable.
type RevokeGrantRequest struct {
	IdempotencyKey         string
	OrganizationID         string
	WorkspaceID            string
	GrantID                string
	GrantRevision          int64
	GrantHash              string
	ExpectedPolicyRevision string
}

// ConfirmRequest is the ADR-0053 WORKSPACE_MANAGED_CONFIRM request.
type ConfirmRequest struct {
	IdempotencyKey                 string
	OrganizationID                 string
	WorkspaceID                    string
	WorkspaceRevision              int64
	WorkspaceConfigurationHash     string
	WorkspaceSourceID              string
	SourceScopeID                  string
	SourceScopeRevision            int64
	ScopeConfigHash                string
	AccessMode                     string
	ConfirmationActorGrantID       string
	ConfirmationActorGrantRevision int64
	ConfirmationActorGrantHash     string
	WarningVersion                 string
	WarningContractHash            string
	AcknowledgementCode            string
	ExpectedPolicyRevision         string
}

// RevokeConfirmationRequest is the ADR-0053 WORKSPACE_MANAGED_CONFIRM_REVOKE
// request. Like grant revocation it carries no current-WorkspaceRevision
// precondition; the exact historical parent ID and hash are the precondition.
type RevokeConfirmationRequest struct {
	IdempotencyKey         string
	OrganizationID         string
	WorkspaceID            string
	ConfirmationID         string
	ConfirmationHash       string
	ExpectedPolicyRevision string
}

// AuthorityResult is the content-free result of a terminal SUCCESS or a replay
// of one. CanonicalBytes are the immutable JCS artifact of the created
// authority row; a transport surface returns the IDs and hashes, never the raw
// bytes, but they are exposed here so a caller can verify them.
type AuthorityResult struct {
	CommandID      string
	Operation      string
	ResultID       string
	ResultHash     string
	CanonicalBytes []byte
}

// The typed canonical request payloads. Field order is irrelevant because JCS
// re-sorts keys; the field set is not — it must equal the closed schema
// exactly, so every field is a plain value with no omitempty.
type grantIssueRequestPayload struct {
	OrganizationID                     string `json:"organization_id"`
	WorkspaceID                        string `json:"workspace_id"`
	ExpectedWorkspaceRevision          int64  `json:"expected_workspace_revision"`
	ExpectedWorkspaceConfigurationHash string `json:"expected_workspace_configuration_hash"`
	TargetPrincipalID                  string `json:"target_principal_id"`
	TTLSeconds                         int64  `json:"ttl_seconds"`
	ExpectedPolicyRevision             string `json:"expected_policy_revision"`
}

type grantRevokeRequestPayload struct {
	OrganizationID         string `json:"organization_id"`
	WorkspaceID            string `json:"workspace_id"`
	GrantID                string `json:"grant_id"`
	GrantRevision          int64  `json:"grant_revision"`
	GrantHash              string `json:"grant_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

type managedConfirmRequestPayload struct {
	OrganizationID                 string `json:"organization_id"`
	WorkspaceID                    string `json:"workspace_id"`
	WorkspaceRevision              int64  `json:"workspace_revision"`
	WorkspaceConfigurationHash     string `json:"workspace_configuration_hash"`
	WorkspaceSourceID              string `json:"workspace_source_id"`
	SourceScopeID                  string `json:"source_scope_id"`
	SourceScopeRevision            int64  `json:"source_scope_revision"`
	ScopeConfigHash                string `json:"scope_config_hash"`
	AccessMode                     string `json:"access_mode"`
	ConfirmationActorGrantID       string `json:"confirmation_actor_grant_id"`
	ConfirmationActorGrantRevision int64  `json:"confirmation_actor_grant_revision"`
	ConfirmationActorGrantHash     string `json:"confirmation_actor_grant_hash"`
	WarningVersion                 string `json:"warning_version"`
	WarningContractHash            string `json:"warning_contract_hash"`
	AcknowledgementCode            string `json:"acknowledgement_code"`
	ExpectedPolicyRevision         string `json:"expected_policy_revision"`
}

type managedConfirmRevokeRequestPayload struct {
	OrganizationID         string `json:"organization_id"`
	WorkspaceID            string `json:"workspace_id"`
	ConfirmationID         string `json:"confirmation_id"`
	ConfirmationHash       string `json:"confirmation_hash"`
	ExpectedPolicyRevision string `json:"expected_policy_revision"`
}

type authorityEnvelope struct {
	SchemaVersion string             `json:"schema_version"`
	Operation     authorityOperation `json:"operation"`
	Request       any                `json:"request"`
}

// authorityCanonicalHash canonicalizes any value to exact JCS bytes and returns
// those bytes with their sha256: hash. It is the one shared engine used for the
// request envelope and for every canonical result document.
func authorityCanonicalHash(value any) ([]byte, string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, "", err
	}
	canonical := jsontext.Value(raw)
	if err := canonical.Canonicalize(); err != nil {
		return nil, "", err
	}
	bytes := append([]byte(nil), canonical...)
	digest := sha256.Sum256(bytes)
	return bytes, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (request IssueGrantRequest) validate() (grantIssueRequestPayload, bool) {
	payload := grantIssueRequestPayload{
		OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID,
		ExpectedWorkspaceRevision:          request.ExpectedWorkspaceRevision,
		ExpectedWorkspaceConfigurationHash: request.ExpectedWorkspaceConfigurationHash,
		TargetPrincipalID:                  request.TargetPrincipalID, TTLSeconds: request.TTLSeconds,
		ExpectedPolicyRevision: request.ExpectedPolicyRevision,
	}
	valid := authorityRequestID(request.OrganizationID) && authorityRequestID(request.WorkspaceID) &&
		authoritySafeRevision(request.ExpectedWorkspaceRevision) &&
		authorityHash(request.ExpectedWorkspaceConfigurationHash) && authorityRequestID(request.TargetPrincipalID) &&
		request.TTLSeconds >= 60 && request.TTLSeconds <= 86400 &&
		authorityPolicyRevisionID(request.ExpectedPolicyRevision)
	return payload, valid
}

func (request RevokeGrantRequest) validate() (grantRevokeRequestPayload, bool) {
	payload := grantRevokeRequestPayload{
		OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID,
		GrantID: request.GrantID, GrantRevision: request.GrantRevision, GrantHash: request.GrantHash,
		ExpectedPolicyRevision: request.ExpectedPolicyRevision,
	}
	valid := authorityRequestID(request.OrganizationID) && authorityRequestID(request.WorkspaceID) &&
		authorityRequestID(request.GrantID) && authoritySafeRevision(request.GrantRevision) &&
		authorityHash(request.GrantHash) && authorityPolicyRevisionID(request.ExpectedPolicyRevision)
	return payload, valid
}

func (request ConfirmRequest) validate() (managedConfirmRequestPayload, bool) {
	payload := managedConfirmRequestPayload{
		OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID,
		WorkspaceRevision: request.WorkspaceRevision, WorkspaceConfigurationHash: request.WorkspaceConfigurationHash,
		WorkspaceSourceID: request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: request.AccessMode, ConfirmationActorGrantID: request.ConfirmationActorGrantID,
		ConfirmationActorGrantRevision: request.ConfirmationActorGrantRevision,
		ConfirmationActorGrantHash:     request.ConfirmationActorGrantHash, WarningVersion: request.WarningVersion,
		WarningContractHash: request.WarningContractHash, AcknowledgementCode: request.AcknowledgementCode,
		ExpectedPolicyRevision: request.ExpectedPolicyRevision,
	}
	valid := authorityRequestID(request.OrganizationID) && authorityRequestID(request.WorkspaceID) &&
		authoritySafeRevision(request.WorkspaceRevision) && authorityHash(request.WorkspaceConfigurationHash) &&
		authorityBindingID(request.WorkspaceSourceID) && authorityRequestID(request.SourceScopeID) &&
		authoritySafeRevision(request.SourceScopeRevision) && authorityHash(request.ScopeConfigHash) &&
		request.AccessMode == authorityAccessModeManaged && authorityRequestID(request.ConfirmationActorGrantID) &&
		authoritySafeRevision(request.ConfirmationActorGrantRevision) && authorityHash(request.ConfirmationActorGrantHash) &&
		request.WarningVersion == authorityWarningVersion && authorityHash(request.WarningContractHash) &&
		request.AcknowledgementCode == authorityAcknowledgementCode &&
		authorityPolicyRevisionID(request.ExpectedPolicyRevision)
	return payload, valid
}

func (request RevokeConfirmationRequest) validate() (managedConfirmRevokeRequestPayload, bool) {
	payload := managedConfirmRevokeRequestPayload{
		OrganizationID: request.OrganizationID, WorkspaceID: request.WorkspaceID,
		ConfirmationID: request.ConfirmationID, ConfirmationHash: request.ConfirmationHash,
		ExpectedPolicyRevision: request.ExpectedPolicyRevision,
	}
	valid := authorityRequestID(request.OrganizationID) && authorityRequestID(request.WorkspaceID) &&
		authorityRequestID(request.ConfirmationID) && authorityHash(request.ConfirmationHash) &&
		authorityPolicyRevisionID(request.ExpectedPolicyRevision)
	return payload, valid
}

// authorityRequestHash marshals the closed envelope of an operation and returns
// its exact JCS bytes and sha256: request hash. The raw Idempotency-Key never
// enters this envelope.
func authorityRequestHash(operation authorityOperation, payload any) ([]byte, string, error) {
	return authorityCanonicalHash(authorityEnvelope{
		SchemaVersion: authorityCommandSchemaVersion, Operation: operation, Request: payload,
	})
}

// authorityRequestID matches the schema `id` primitive exactly:
// ^[A-Za-z0-9][A-Za-z0-9._:-]*$ with a maximum length of 128. It is stricter
// than the audit/workspace validID (which also admits a leading '_' or '-'),
// so a valid request ID is always a valid audit ID as well.
func authorityRequestID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		isAlphanumeric := (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
		if index == 0 {
			if !isAlphanumeric {
				return false
			}
			continue
		}
		if !isAlphanumeric && character != '.' && character != '_' && character != ':' && character != '-' {
			return false
		}
	}
	return true
}

// authorityPolicyRevisionID is an `id` that is never a bare numeric ordinal and
// never a policy hash: the registry tuple is the only bridge between the
// numeric ordinal and the opaque ID.
func authorityPolicyRevisionID(value string) bool {
	if !authorityRequestID(value) {
		return false
	}
	if strings.HasPrefix(value, "sha256:") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return true
		}
	}
	return false
}

func authorityHash(value string) bool { return workspace.IsConfigurationHash(value) }

func authoritySafeRevision(value int64) bool { return value >= 1 && value <= maxSafeInteger }

// authorityBindingID matches ^binding_[0-7][0-9A-HJKMNP-TV-Z]{25}$, the exact
// stable workspace-source binding identity emitted by stableWorkspaceSourceID.
func authorityBindingID(value string) bool { return validStage2SourceID(value, "binding_") }
