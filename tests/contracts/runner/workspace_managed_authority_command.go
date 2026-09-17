package contracts

import (
	"math"
	"regexp"
	"strings"
)

// ADR-0053 freezes the workspace-managed authority command boundary as a
// closed canonical envelope. Every syntactic violation terminates with the
// single public code WORKSPACE_AUTHORITY_REQUEST_INVALID: the request shape
// never leaks which internal rule rejected it.
const workspaceManagedAuthorityCommandSchemaVersion = "workspace-managed-authority-command-v1"

const (
	operationConfirmationGrantIssue  = "WORKSPACE_CONFIRMATION_GRANT_ISSUE"
	operationConfirmationGrantRevoke = "WORKSPACE_CONFIRMATION_GRANT_REVOKE"
	operationManagedConfirm          = "WORKSPACE_MANAGED_CONFIRM"
	operationManagedConfirmRevoke    = "WORKSPACE_MANAGED_CONFIRM_REVOKE"
)

const workspaceManagedAuthorityRequestInvalid = "WORKSPACE_AUTHORITY_REQUEST_INVALID"

type authorityFieldKind int

const (
	authorityFieldID authorityFieldKind = iota
	authorityFieldHash
	authorityFieldBindingID
	authorityFieldRevision
	authorityFieldTTLSeconds
	authorityFieldPolicyRevision
	authorityFieldAccessMode
	authorityFieldWarningVersion
	authorityFieldAcknowledgement
)

var (
	authorityCommandIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	authorityCommandHashPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	authorityCommandBindingPattern = regexp.MustCompile(`^binding_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	authorityCommandDigitsPattern  = regexp.MustCompile(`^[0-9]+$`)
)

// workspaceManagedAuthorityRequestFields is the closed request shape per
// operation. Server-owned fields (result IDs and hashes, granted_at/valid_*,
// confirmed_by/confirmed_at, revoked_by/revoked_at, permission, reason codes)
// are deliberately absent: their presence is an unknown-field rejection.
// Neither revoke request carries an expected WorkspaceRevision, because a
// stale parent must remain revocable.
var workspaceManagedAuthorityRequestFields = map[string]map[string]authorityFieldKind{
	operationConfirmationGrantIssue: {
		"organization_id":                       authorityFieldID,
		"workspace_id":                          authorityFieldID,
		"expected_workspace_revision":           authorityFieldRevision,
		"expected_workspace_configuration_hash": authorityFieldHash,
		"target_principal_id":                   authorityFieldID,
		"ttl_seconds":                           authorityFieldTTLSeconds,
		"expected_policy_revision":              authorityFieldPolicyRevision,
	},
	operationConfirmationGrantRevoke: {
		"organization_id":          authorityFieldID,
		"workspace_id":             authorityFieldID,
		"grant_id":                 authorityFieldID,
		"grant_revision":           authorityFieldRevision,
		"grant_hash":               authorityFieldHash,
		"expected_policy_revision": authorityFieldPolicyRevision,
	},
	operationManagedConfirm: {
		"organization_id":                   authorityFieldID,
		"workspace_id":                      authorityFieldID,
		"workspace_revision":                authorityFieldRevision,
		"workspace_configuration_hash":      authorityFieldHash,
		"workspace_source_id":               authorityFieldBindingID,
		"source_scope_id":                   authorityFieldID,
		"source_scope_revision":             authorityFieldRevision,
		"scope_config_hash":                 authorityFieldHash,
		"access_mode":                       authorityFieldAccessMode,
		"confirmation_actor_grant_id":       authorityFieldID,
		"confirmation_actor_grant_revision": authorityFieldRevision,
		"confirmation_actor_grant_hash":     authorityFieldHash,
		"warning_version":                   authorityFieldWarningVersion,
		"warning_contract_hash":             authorityFieldHash,
		"acknowledgement_code":              authorityFieldAcknowledgement,
		"expected_policy_revision":          authorityFieldPolicyRevision,
	},
	operationManagedConfirmRevoke: {
		"organization_id":          authorityFieldID,
		"workspace_id":             authorityFieldID,
		"confirmation_id":          authorityFieldID,
		"confirmation_hash":        authorityFieldHash,
		"expected_policy_revision": authorityFieldPolicyRevision,
	},
}

func validateWorkspaceManagedAuthorityCommand(envelope map[string]any) error {
	for key := range envelope {
		switch key {
		case "schema_version", "operation", "request":
		default:
			return fail(workspaceManagedAuthorityRequestInvalid, "unknown envelope field ", key)
		}
	}
	schemaVersion, ok := envelope["schema_version"].(string)
	if !ok || schemaVersion != workspaceManagedAuthorityCommandSchemaVersion {
		return fail(workspaceManagedAuthorityRequestInvalid, "schema_version")
	}
	operation, ok := envelope["operation"].(string)
	if !ok {
		return fail(workspaceManagedAuthorityRequestInvalid, "operation")
	}
	fields, known := workspaceManagedAuthorityRequestFields[operation]
	if !known {
		return fail(workspaceManagedAuthorityRequestInvalid, "unknown operation ", operation)
	}
	request, ok := envelope["request"].(map[string]any)
	if !ok {
		return fail(workspaceManagedAuthorityRequestInvalid, "request")
	}
	for key := range request {
		if _, allowed := fields[key]; !allowed {
			return fail(workspaceManagedAuthorityRequestInvalid, "unknown request field ", key)
		}
	}
	for key, kind := range fields {
		value, present := request[key]
		if !present {
			return fail(workspaceManagedAuthorityRequestInvalid, "missing request field ", key)
		}
		if value == nil {
			return fail(workspaceManagedAuthorityRequestInvalid, "null request field ", key)
		}
		if !authorityCommandFieldIsValid(kind, value) {
			return fail(workspaceManagedAuthorityRequestInvalid, "invalid request field ", key)
		}
	}
	return nil
}

func authorityCommandFieldIsValid(kind authorityFieldKind, value any) bool {
	switch kind {
	case authorityFieldID:
		text, ok := value.(string)
		return ok && len(text) <= 128 && authorityCommandIDPattern.MatchString(text)
	case authorityFieldHash:
		text, ok := value.(string)
		return ok && authorityCommandHashPattern.MatchString(text)
	case authorityFieldBindingID:
		text, ok := value.(string)
		return ok && authorityCommandBindingPattern.MatchString(text)
	case authorityFieldRevision:
		return authorityCommandIntegerInRange(value, 1, 9007199254740991)
	case authorityFieldTTLSeconds:
		return authorityCommandIntegerInRange(value, 60, 86400)
	case authorityFieldPolicyRevision:
		text, ok := value.(string)
		if !ok || len(text) > 128 || !authorityCommandIDPattern.MatchString(text) {
			return false
		}
		// The opaque policy_revision_id is never a formatted numeric ordinal
		// and never a policy hash; the registry tuple is the only bridge.
		return !authorityCommandDigitsPattern.MatchString(text) && !strings.HasPrefix(text, "sha256:")
	case authorityFieldAccessMode:
		return value == "WORKSPACE_MANAGED"
	case authorityFieldWarningVersion:
		return value == "workspace-managed-risk-v1"
	case authorityFieldAcknowledgement:
		return value == "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL"
	default:
		return false
	}
}

func authorityCommandIntegerInRange(value any, minimum, maximum float64) bool {
	number, ok := value.(float64)
	if !ok || number != math.Trunc(number) {
		return false
	}
	return number >= minimum && number <= maximum
}
