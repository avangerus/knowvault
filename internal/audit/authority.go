package audit

import (
	"encoding/json"
	"slices"
)

// The workspace-managed authority command audit contract (ADR-0053).
//
// All four actions share one resource type and one resource-ID rule:
// audit.resource_id is always receipt.command_id, on every terminal outcome.
// Grant, confirmation and revocation IDs never serve as the audit resource ID
// — they appear only inside metadata, and only on SUCCESS — because DENIED,
// NOT_FOUND and PRECONDITION_FAILED have no created or parent authority row to
// name instead.
const (
	ActionWorkspaceSourceConfirmationGrantIssued  Action = "workspace.source_confirmation_grant_issued"
	ActionWorkspaceSourceConfirmationGrantRevoked Action = "workspace.source_confirmation_grant_revoked"
	ActionWorkspaceSourceConfirmed                Action = "workspace.source_confirmed"
	ActionWorkspaceSourceConfirmationRevoked      Action = "workspace.source_confirmation_revoked"
)

const ResourceWorkspaceAuthorityCommand ResourceType = "WORKSPACE_AUTHORITY_COMMAND"

// The closed public error surface of the authority command boundary. Only the
// three codes that map onto a business terminal outcome can ever reach an audit
// event: an invalid request and an idempotency conflict create no receipt and
// no audit event at all, and a persistence failure rolls the whole transaction
// back.
const (
	ErrorAuthorityDenied             = "WORKSPACE_AUTHORITY_DENIED"
	ErrorAuthorityNotFound           = "WORKSPACE_AUTHORITY_NOT_FOUND"
	ErrorAuthorityPreconditionFailed = "WORKSPACE_AUTHORITY_PRECONDITION_FAILED"
)

const (
	authorityOperationGrantIssue    = "WORKSPACE_CONFIRMATION_GRANT_ISSUE"
	authorityOperationGrantRevoke   = "WORKSPACE_CONFIRMATION_GRANT_REVOKE"
	authorityOperationConfirm       = "WORKSPACE_MANAGED_CONFIRM"
	authorityOperationConfirmRevoke = "WORKSPACE_MANAGED_CONFIRM_REVOKE"

	authorityReasonGrantRevoked  = "AUTHORITY_REVOKED"
	authorityReasonAccessRevoked = "ACCESS_REVOKED"

	authorityAccessMode          = "WORKSPACE_MANAGED"
	authorityWarningVersion      = "workspace-managed-risk-v1"
	authorityAcknowledgementCode = "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
)

// authorityActionOperations is the one-to-one action/operation mapping. It is
// the single inventory: every other rule below derives from it, so an action
// cannot be added here without also being given an exact metadata set.
var authorityActionOperations = map[Action]string{
	ActionWorkspaceSourceConfirmationGrantIssued:  authorityOperationGrantIssue,
	ActionWorkspaceSourceConfirmationGrantRevoked: authorityOperationGrantRevoke,
	ActionWorkspaceSourceConfirmed:                authorityOperationConfirm,
	ActionWorkspaceSourceConfirmationRevoked:      authorityOperationConfirmRevoke,
}

// authoritySuccessMetadata is the exact closed metadata key set per action on
// SUCCESS. Values come from persisted, trusted result and parent projections,
// never copied blindly from the unverified request.
var authoritySuccessMetadata = map[Action][]string{
	ActionWorkspaceSourceConfirmationGrantIssued: {
		"authority_operation", "authority_result_id", "authority_result_hash",
		"target_principal_id", "policy_revision",
	},
	ActionWorkspaceSourceConfirmationGrantRevoked: {
		"authority_operation", "authority_parent_id", "authority_parent_hash",
		"authority_revocation_id", "authority_revocation_hash",
		"authority_reason_code", "policy_revision",
	},
	ActionWorkspaceSourceConfirmationRevoked: {
		"authority_operation", "authority_parent_id", "authority_parent_hash",
		"authority_revocation_id", "authority_revocation_hash",
		"authority_reason_code", "policy_revision",
	},
	ActionWorkspaceSourceConfirmed: {
		"authority_operation", "authority_result_id", "authority_result_hash",
		"workspace_revision", "workspace_configuration_hash", "workspace_source_id",
		"source_scope_id", "source_scope_revision", "scope_config_hash", "access_mode",
		"confirmation_actor_grant_id", "confirmation_actor_grant_revision",
		"confirmation_actor_grant_hash", "warning_version", "warning_contract_hash",
		"acknowledgement_code", "policy_revision",
	},
}

// authorityFailureMetadata: a failure carries exactly one key and nothing
// else — no request-supplied target ID, no parent ID or hash, no warning tuple
// and no expected policy revision, because none of those were proven current at
// the point of failure.
var authorityFailureMetadata = []string{"authority_operation"}

// authorityReasonCodes pins the fixed reason code of each revoke action.
var authorityReasonCodes = map[Action]string{
	ActionWorkspaceSourceConfirmationGrantRevoked: authorityReasonGrantRevoked,
	ActionWorkspaceSourceConfirmationRevoked:      authorityReasonAccessRevoked,
}

func authorityOperationForAction(action Action) (string, bool) {
	operation, known := authorityActionOperations[action]
	return operation, known
}

func isAuthorityAction(action Action) bool {
	_, known := authorityActionOperations[action]
	return known
}

// metadataKeySet derives the projected JSON key set from the value itself
// rather than from a second hand-maintained inventory, so a metadata field
// added later cannot silently escape the closed per-action sets above.
func metadataKeySet(metadata Metadata) ([]string, bool) {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys, true
}

func metadataKeySetIsExact(metadata Metadata, expected []string) bool {
	keys, ok := metadataKeySet(metadata)
	if !ok {
		return false
	}
	want := slices.Clone(expected)
	slices.Sort(want)
	return slices.Equal(keys, want)
}

// hasAuthorityMetadata reports whether any authority-only field is set. The
// authority vocabulary is reserved: a non-authority event may never carry it.
func hasAuthorityMetadata(metadata Metadata) bool {
	return metadata.AuthorityOperation != nil || metadata.AuthorityResultID != nil ||
		metadata.AuthorityResultHash != nil || metadata.AuthorityParentID != nil ||
		metadata.AuthorityParentHash != nil || metadata.AuthorityRevocationID != nil ||
		metadata.AuthorityRevocationHash != nil || metadata.AuthorityReasonCode != nil ||
		metadata.TargetPrincipalID != nil || metadata.WorkspaceConfigurationHash != nil ||
		metadata.ConfirmationActorGrantID != nil || metadata.ConfirmationActorGrantRevision != nil ||
		metadata.ConfirmationActorGrantHash != nil || metadata.WarningVersion != nil ||
		metadata.WarningContractHash != nil || metadata.AcknowledgementCode != nil
}

// validAuthorityMetadataFields checks field-level shape only. Which fields may
// be present at all is decided by validAuthorityProjection.
func validAuthorityMetadataFields(metadata Metadata) bool {
	for _, value := range []*string{
		metadata.AuthorityResultID, metadata.AuthorityParentID, metadata.AuthorityRevocationID,
		metadata.TargetPrincipalID, metadata.ConfirmationActorGrantID,
	} {
		if value != nil && !validID(*value) {
			return false
		}
	}
	for _, value := range []*string{
		metadata.AuthorityResultHash, metadata.AuthorityParentHash, metadata.AuthorityRevocationHash,
		metadata.WorkspaceConfigurationHash, metadata.ConfirmationActorGrantHash, metadata.WarningContractHash,
	} {
		if value != nil && !validHash(*value) {
			return false
		}
	}
	if metadata.ConfirmationActorGrantRevision != nil &&
		(*metadata.ConfirmationActorGrantRevision < 1 || *metadata.ConfirmationActorGrantRevision > maxSafeInt64) {
		return false
	}
	if metadata.AuthorityOperation != nil && !slices.Contains([]string{
		authorityOperationGrantIssue, authorityOperationGrantRevoke,
		authorityOperationConfirm, authorityOperationConfirmRevoke,
	}, *metadata.AuthorityOperation) {
		return false
	}
	if metadata.AuthorityReasonCode != nil && !slices.Contains([]string{
		authorityReasonGrantRevoked, authorityReasonAccessRevoked,
	}, *metadata.AuthorityReasonCode) {
		return false
	}
	if metadata.WarningVersion != nil && *metadata.WarningVersion != authorityWarningVersion {
		return false
	}
	if metadata.AcknowledgementCode != nil && *metadata.AcknowledgementCode != authorityAcknowledgementCode {
		return false
	}
	return true
}

// validAuthorityProjection is the Go half of the authority audit contract. It
// is deliberately the exact mirror of the database gates installed by migration
// 000011: the two validators must stay consistent, so both encode the same
// closed action/resource pairing, the same outcome-to-error-code mapping, the
// same workspace_id rule and the same per-action metadata sets.
func validAuthorityProjection(input EventInput) bool {
	operation, known := authorityOperationForAction(input.Action)
	// The four actions and the resource type are a strict one-to-one pair:
	// neither may ever appear without the other.
	if known != (input.ResourceType == ResourceWorkspaceAuthorityCommand) {
		return false
	}
	if !known {
		return true
	}

	if input.ActorType != ActorHuman || input.ActorPrincipalID == nil ||
		input.OnBehalfOfPrincipalID != nil || input.PolicyDecisionID != nil ||
		len(input.ReferencedEvidenceIDs) != 0 {
		return false
	}

	// Receipt status maps to outcome and error code exhaustively. NOT_FOUND
	// collapses onto DENIED at the outcome level so a hidden workspace stays
	// indistinguishable from an insufficient role in the audit trail itself.
	switch input.Outcome {
	case OutcomeSuccess:
		if input.ErrorCode != nil {
			return false
		}
	case OutcomeDenied:
		if input.ErrorCode == nil ||
			(*input.ErrorCode != ErrorAuthorityDenied && *input.ErrorCode != ErrorAuthorityNotFound) {
			return false
		}
	case OutcomeFailed:
		if input.ErrorCode == nil || *input.ErrorCode != ErrorAuthorityPreconditionFailed {
			return false
		}
	default:
		return false
	}

	// AuditEvent.workspace_id follows its own exhaustive rule, distinct from
	// resource_id: exact on SUCCESS and PRECONDITION_FAILED, always null on
	// NOT_FOUND, and on DENIED exact only when same-tenant visibility was
	// already established — so either value is contract-legal there.
	if input.ErrorCode != nil {
		switch *input.ErrorCode {
		case ErrorAuthorityNotFound:
			if input.WorkspaceID != nil {
				return false
			}
		case ErrorAuthorityPreconditionFailed:
			if input.WorkspaceID == nil {
				return false
			}
		}
	}
	if input.Outcome == OutcomeSuccess && input.WorkspaceID == nil {
		return false
	}

	metadata := input.Metadata
	if metadata.AuthorityOperation == nil || *metadata.AuthorityOperation != operation {
		return false
	}
	if input.Outcome != OutcomeSuccess {
		return metadataKeySetIsExact(metadata, authorityFailureMetadata)
	}
	if !metadataKeySetIsExact(metadata, authoritySuccessMetadata[input.Action]) {
		return false
	}
	if reason, fixed := authorityReasonCodes[input.Action]; fixed &&
		(metadata.AuthorityReasonCode == nil || *metadata.AuthorityReasonCode != reason) {
		return false
	}
	if input.Action == ActionWorkspaceSourceConfirmed &&
		(metadata.AccessMode == nil || *metadata.AccessMode != authorityAccessMode) {
		return false
	}
	return true
}
