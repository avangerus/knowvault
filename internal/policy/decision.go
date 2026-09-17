// Package policy is the single default-deny decision point for application
// operations. It is deliberately pure: identity/session lookup and database
// persistence live at its boundary, while this package makes the resulting
// authorization rule testable without HTTP or PostgreSQL.
package policy

import (
	"strings"
	"unicode/utf8"
)

// Operation is a server-owned operation identifier. Transport code must map
// routes to these constants; it must never pass a client-provided action name.
type Operation string

const (
	OperationWorkspaceCreate        Operation = "workspace.create"
	OperationWorkspaceViewMetadata  Operation = "workspace.view_metadata"
	OperationWorkspaceReadContent   Operation = "workspace.read_content"
	OperationWorkspaceAsk           Operation = "workspace.ask"
	OperationWorkspaceManage        Operation = "workspace.manage"
	OperationWorkspaceManageSources Operation = "workspace.manage_sources"
	OperationAuditReadMetadata      Operation = "audit.read_metadata"
	OperationSourceRegister         Operation = "source.register"
	OperationSourceActivate         Operation = "source.activate"
	OperationSourceVerifyTrust      Operation = "source.verify_trust"
)

// ReasonCode is safe to persist in a PolicyDecision and an AuditEvent. It
// contains no object title, source locator, or other content-bearing data.
type ReasonCode string

const (
	ReasonAllowed                      ReasonCode = "POLICY_ALLOWED"
	ReasonInvalidContext               ReasonCode = "POLICY_INVALID_CONTEXT"
	ReasonOrganizationMismatch         ReasonCode = "POLICY_ORGANIZATION_MISMATCH"
	ReasonOrganizationUnavailable      ReasonCode = "POLICY_ORGANIZATION_UNAVAILABLE"
	ReasonOrganizationRoleInsufficient ReasonCode = "POLICY_ORGANIZATION_ROLE_INSUFFICIENT"
	ReasonPrincipalInactive            ReasonCode = "POLICY_PRINCIPAL_INACTIVE"
	ReasonWorkspaceUnavailable         ReasonCode = "POLICY_WORKSPACE_UNAVAILABLE"
	ReasonWorkspaceMembershipAbsent    ReasonCode = "POLICY_WORKSPACE_MEMBERSHIP_ABSENT"
	ReasonWorkspaceRoleInsufficient    ReasonCode = "POLICY_WORKSPACE_ROLE_INSUFFICIENT"
	ReasonOperationUnknown             ReasonCode = "POLICY_OPERATION_UNKNOWN"
)

// PrincipalStatus is intentionally narrower than the database enum. A caller
// must resolve an unknown identity to a non-active status before evaluation.
type PrincipalStatus string

const (
	PrincipalActive        PrincipalStatus = "ACTIVE"
	PrincipalDisabled      PrincipalStatus = "DISABLED"
	PrincipalDeprovisioned PrincipalStatus = "DEPROVISIONED"
)

// WorkspaceStatus preserves the 1.0 lifecycle. Only ACTIVE permits a new
// question or management change; historical metadata/content can be read from
// READ_ONLY or ARCHIVED workspaces when a membership still exists.
type WorkspaceStatus string

const (
	WorkspaceActive   WorkspaceStatus = "ACTIVE"
	WorkspaceReadOnly WorkspaceStatus = "READ_ONLY"
	WorkspaceArchived WorkspaceStatus = "ARCHIVED"
	WorkspaceDeleting WorkspaceStatus = "DELETING"
	WorkspaceDeleted  WorkspaceStatus = "DELETED"
)

type WorkspaceRole string

const (
	WorkspaceOwner   WorkspaceRole = "OWNER"
	WorkspaceManager WorkspaceRole = "MANAGER"
	WorkspaceMember  WorkspaceRole = "MEMBER"
	WorkspaceViewer  WorkspaceRole = "VIEWER"
	WorkspaceAuditor WorkspaceRole = "AUDITOR"
)

type OrganizationRole string

const (
	OrganizationOwner           OrganizationRole = "OWNER"
	OrganizationAdmin           OrganizationRole = "ADMIN"
	OrganizationConnectorAdmin  OrganizationRole = "CONNECTOR_ADMIN"
	OrganizationSecurityAuditor OrganizationRole = "SECURITY_AUDITOR"
	OrganizationMember          OrganizationRole = "MEMBER"
)

// OrganizationStatus is independently resolved by the persistence boundary.
// A tenant in any non-active lifecycle state cannot accept new workspaces.
type OrganizationStatus string

const (
	OrganizationActive    OrganizationStatus = "ACTIVE"
	OrganizationSuspended OrganizationStatus = "SUSPENDED"
	OrganizationDeleting  OrganizationStatus = "DELETING"
	OrganizationDeleted   OrganizationStatus = "DELETED"
)

// Organization is the minimal server-resolved tenant state needed before a
// workspace exists. It prevents create authorization from relying on an
// unscoped transport value.
type Organization struct {
	ID     string
	Status OrganizationStatus
}

// OrganizationRequest contains a pre-workspace operation. It deliberately
// cannot grant source or workspace-content access.
type OrganizationRequest struct {
	Operation    Operation
	Subject      Subject
	Organization Organization
}

// Subject is the identity snapshot produced by the identity boundary. The
// session revision is carried so callers cannot later confuse an evaluated
// decision with a revoked session. Revision freshness is verified by identity;
// policy does not guess it from a token claim.
type Subject struct {
	OrganizationID    string
	PrincipalID       string
	Status            PrincipalStatus
	SessionRevision   int64
	OrganizationRoles []OrganizationRole
}

type Workspace struct {
	OrganizationID string
	ID             string
	Status         WorkspaceStatus
}

// Membership is a server-resolved current membership. A group/direct
// expansion is deliberately opaque to policy; an unresolved mapping must be
// represented as Present=false by the caller.
type Membership struct {
	Present bool
	Role    WorkspaceRole
}

type Request struct {
	Operation  Operation
	Subject    Subject
	Workspace  Workspace
	Membership Membership
}

// EvaluateOrganization applies the default-deny organization control-plane
// rule. Workspace creation requires an active OWNER or ADMIN; source
// registration and activation are reserved to the active organization OWNER
// (ADR-0074 s1.9).
func EvaluateOrganization(request OrganizationRequest) Decision {
	if !validID(request.Subject.OrganizationID) || !validID(request.Subject.PrincipalID) || request.Subject.SessionRevision < 1 ||
		!validID(request.Organization.ID) {
		return deny(ReasonInvalidContext)
	}
	if request.Subject.OrganizationID != request.Organization.ID {
		return deny(ReasonOrganizationMismatch)
	}
	if request.Subject.Status != PrincipalActive {
		return deny(ReasonPrincipalInactive)
	}
	if request.Organization.Status != OrganizationActive {
		return deny(ReasonOrganizationUnavailable)
	}
	switch request.Operation {
	case OperationWorkspaceCreate:
		if hasOrganizationRole(request.Subject.OrganizationRoles, OrganizationOwner) ||
			hasOrganizationRole(request.Subject.OrganizationRoles, OrganizationAdmin) {
			return allow()
		}
	case OperationSourceRegister, OperationSourceActivate:
		if hasOrganizationRole(request.Subject.OrganizationRoles, OrganizationOwner) {
			return allow()
		}
	case OperationSourceVerifyTrust:
		if hasOrganizationRole(request.Subject.OrganizationRoles, OrganizationConnectorAdmin) {
			return allow()
		}
	default:
		return deny(ReasonOperationUnknown)
	}
	return deny(ReasonOrganizationRoleInsufficient)
}

// Decision is the typed, content-free policy result. Persistence assigns its
// durable identifier and ties it to a policy revision; callers must not invent
// an ID in this pure package.
type Decision struct {
	Allowed     bool
	ReasonCodes []ReasonCode
}

// EvaluateWorkspace applies the data-access rule shared by Web/API/worker
// callers. It has no allow-by-default branch: malformed state, an unknown
// operation, unknown identity, absent membership and cross-tenant input deny.
func EvaluateWorkspace(request Request) Decision {
	if !validID(request.Subject.OrganizationID) || !validID(request.Subject.PrincipalID) || request.Subject.SessionRevision < 1 ||
		!validID(request.Workspace.OrganizationID) || !validID(request.Workspace.ID) {
		return deny(ReasonInvalidContext)
	}
	if request.Subject.OrganizationID != request.Workspace.OrganizationID {
		return deny(ReasonOrganizationMismatch)
	}
	if request.Subject.Status != PrincipalActive {
		return deny(ReasonPrincipalInactive)
	}

	switch request.Operation {
	case OperationAuditReadMetadata:
		if hasOrganizationRole(request.Subject.OrganizationRoles, OrganizationSecurityAuditor) ||
			(request.Membership.Present && request.Membership.Role == WorkspaceAuditor) {
			return allow()
		}
		return deny(ReasonWorkspaceRoleInsufficient)
	case OperationWorkspaceViewMetadata, OperationWorkspaceReadContent, OperationWorkspaceAsk, OperationWorkspaceManage, OperationWorkspaceManageSources:
		// handled below
	default:
		return deny(ReasonOperationUnknown)
	}

	if !readableWorkspace(request.Workspace.Status) {
		return deny(ReasonWorkspaceUnavailable)
	}
	if !request.Membership.Present {
		return deny(ReasonWorkspaceMembershipAbsent)
	}

	switch request.Operation {
	case OperationWorkspaceViewMetadata:
		if validWorkspaceRole(request.Membership.Role) {
			return allow()
		}
	case OperationWorkspaceReadContent:
		if request.Membership.Role != WorkspaceAuditor && validWorkspaceRole(request.Membership.Role) {
			return allow()
		}
	case OperationWorkspaceAsk:
		if RoleCanAsk(request.Workspace.Status, request.Membership.Role) {
			return allow()
		}
	case OperationWorkspaceManage, OperationWorkspaceManageSources:
		if request.Workspace.Status == WorkspaceActive && (request.Membership.Role == WorkspaceOwner || request.Membership.Role == WorkspaceManager) {
			return allow()
		}
	}
	return deny(ReasonWorkspaceRoleInsufficient)
}

// RoleCanAsk is only the role/status part of workspace.ask, suitable for a UI
// capability hint after authentication and workspace access have succeeded.
// It does not authorize a principal or replace EvaluateWorkspace.
func RoleCanAsk(status WorkspaceStatus, role WorkspaceRole) bool {
	return status == WorkspaceActive && (role == WorkspaceOwner || role == WorkspaceManager || role == WorkspaceMember)
}

func allow() Decision { return Decision{Allowed: true, ReasonCodes: []ReasonCode{ReasonAllowed}} }

func deny(reason ReasonCode) Decision {
	return Decision{Allowed: false, ReasonCodes: []ReasonCode{reason}}
}

func validID(value string) bool {
	return value != "" && len(value) <= 256 && utf8.ValidString(value) && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) })
}

func validWorkspaceRole(role WorkspaceRole) bool {
	switch role {
	case WorkspaceOwner, WorkspaceManager, WorkspaceMember, WorkspaceViewer, WorkspaceAuditor:
		return true
	default:
		return false
	}
}

func readableWorkspace(status WorkspaceStatus) bool {
	switch status {
	case WorkspaceActive, WorkspaceReadOnly, WorkspaceArchived:
		return true
	default:
		return false
	}
}

func hasOrganizationRole(roles []OrganizationRole, wanted OrganizationRole) bool {
	for _, role := range roles {
		if role == wanted {
			return true
		}
	}
	return false
}
