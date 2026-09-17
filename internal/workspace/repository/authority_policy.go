package repository

// Pure authority policy decisions (ADR-0053). These functions never touch the
// database directly: the runtime resolves the current identity, the minimal
// workspace visibility facts and (for a revocation) the parent identity, then
// hands those early facts here as plain values, and hands every *protected
// business projection* — the workspace revision/configuration, target
// eligibility, the actor grant, the binding, the parent hash and revoked state,
// the current policy, the current warning and the existence of a live
// confirmation — as a lazily-evaluated loader.
//
// The laziness is the ADR-0053 decision-phase ordering made mechanical: a
// decision function must not consult any business loader until the trusted
// tenant fence, the operation-specific visibility and the authorization it owns
// have all resolved. An invisible workspace, an unauthorized actor and — for a
// revocation — a missing or invisible parent therefore resolve to NOT_FOUND or
// DENIED strictly before any protected projection (including the workspace
// revision/configuration and the parent hash/revoked state) is read. The
// recording-loader tests assert exactly this: on those early terminals, zero
// business loaders are invoked.
//
// The one visibility predicate shared by every operation mirrors the database
// function app.authority_metadata_is_visible: a row is visible to a current
// workspace member, to an Organization OWNER/ADMIN, or to the exact self
// principal a self-revoke right is given to. Authority-metadata visibility never
// implies content access.

import "knowvault.local/verified-workspace/internal/workspace"

// authorityTerminal is the settled outcome of the decision phase.
type authorityTerminal int

const (
	terminalSuccess authorityTerminal = iota
	terminalDenied
	terminalNotFound
	terminalPreconditionFailed
)

func (terminal authorityTerminal) code() ErrorCode {
	switch terminal {
	case terminalDenied:
		return CodeAuthorityDenied
	case terminalNotFound:
		return CodeAuthorityNotFound
	case terminalPreconditionFailed:
		return CodeAuthorityPreconditionFailed
	default:
		return ""
	}
}

// authorityActor is the resolved current identity of the acting principal.
type authorityActor struct {
	organizationActive bool
	principalActive    bool
	orgOwnerOrAdmin    bool
}

// authorityWorkspace is the minimal workspace visibility projection: existence,
// lifecycle status and the actor's current membership role. It deliberately
// carries no revision or configuration hash — those are protected projections.
type authorityWorkspace struct {
	exists            bool
	status            workspace.Status
	membershipPresent bool
	membershipRole    workspace.Role
}

func (ws authorityWorkspace) isOwner() bool {
	return ws.membershipPresent && ws.membershipRole == workspace.RoleOwner
}

func (ws authorityWorkspace) isOwnerOrManager() bool {
	return ws.membershipPresent && (ws.membershipRole == workspace.RoleOwner || ws.membershipRole == workspace.RoleManager)
}

// revocableWorkspaceStatus is the set of lifecycle states in which authority
// metadata may be revoked and a stored result may be replayed: ACTIVE,
// READ_ONLY and ARCHIVED. DELETING and DELETED are excluded.
func revocableWorkspaceStatus(status workspace.Status) bool {
	return status == workspace.StatusActive || status == workspace.StatusReadOnly || status == workspace.StatusArchived
}

func (actor authorityActor) visible(ws authorityWorkspace, self bool) bool {
	return ws.exists && (ws.membershipPresent || actor.orgOwnerOrAdmin || self)
}

// actorGrantEvaluation is the confirm command's projection of its live actor
// grant. held is true only when the exact (id, revision) grant exists and names
// the actor in the referenced workspace; live adds permission, current policy,
// an unrevoked state and a validity window covering the command second;
// hashMatches is the supplied grant hash against the stored one.
type actorGrantEvaluation struct {
	held        bool
	live        bool
	hashMatches bool
}

type issueBusiness struct {
	targetEligible        func() (bool, error)
	revisionConfigCurrent func() (bool, error)
	policyCurrent         func() (bool, error)
}

type grantRevokeBusiness struct {
	parentBusiness func() (parentBusiness, error)
	policyCurrent  func() (bool, error)
}

type confirmBusiness struct {
	revisionConfigCurrent  func() (bool, error)
	bindingCurrent         func() (bool, error)
	actorGrant             func() (actorGrantEvaluation, error)
	verifierConflict       func() (bool, error)
	policyCurrent          func() (bool, error)
	warningCurrent         func() (bool, error)
	liveConfirmationExists func() (bool, error)
}

type confirmRevokeBusiness struct {
	parentBusiness func() (parentBusiness, error)
	policyCurrent  func() (bool, error)
}

// issueDecision resolves WORKSPACE_CONFIRMATION_GRANT_ISSUE. Issuing is allowed
// only to an active Organization OWNER/ADMIN; the issuer needs no workspace
// membership. Only after that authorization passes does it read the target
// eligibility, then the protected revision/configuration, then the policy.
func issueDecision(actor authorityActor, ws authorityWorkspace, business issueBusiness) (authorityTerminal, error) {
	if !(actor.organizationActive && actor.principalActive && actor.orgOwnerOrAdmin) {
		if actor.visible(ws, false) {
			return terminalDenied, nil
		}
		return terminalNotFound, nil
	}
	if !ws.exists {
		return terminalNotFound, nil
	}
	if ws.status != workspace.StatusActive {
		return terminalDenied, nil
	}
	eligible, err := business.targetEligible()
	if err != nil {
		return terminalSuccess, err
	}
	if !eligible {
		return terminalDenied, nil
	}
	revisionConfigCurrent, err := business.revisionConfigCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !revisionConfigCurrent {
		return terminalPreconditionFailed, nil
	}
	policyCurrent, err := business.policyCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !policyCurrent {
		return terminalPreconditionFailed, nil
	}
	return terminalSuccess, nil
}

// grantRevokeDecision resolves WORKSPACE_CONFIRMATION_GRANT_REVOKE. self and
// parentExists are early facts from the parent identity loaded to resolve self
// and NOT_FOUND; the parent hash/revoked state and the policy are the late
// reads, taken only once visibility, authorization and existence have passed.
func grantRevokeDecision(actor authorityActor, ws authorityWorkspace, self, parentExists bool, business grantRevokeBusiness) (authorityTerminal, error) {
	if !actor.organizationActive || !actor.principalActive {
		if actor.visible(ws, self) {
			return terminalDenied, nil
		}
		return terminalNotFound, nil
	}
	if !actor.visible(ws, self) || !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound, nil
	}
	if !(actor.orgOwnerOrAdmin || ws.isOwner() || self) {
		return terminalDenied, nil
	}
	if !parentExists {
		return terminalNotFound, nil
	}
	parent, err := business.parentBusiness()
	if err != nil {
		return terminalSuccess, err
	}
	if !parent.hashMatches {
		return terminalPreconditionFailed, nil
	}
	if parent.revoked {
		return terminalPreconditionFailed, nil
	}
	policyCurrent, err := business.policyCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !policyCurrent {
		return terminalPreconditionFailed, nil
	}
	return terminalSuccess, nil
}

// confirmDecision resolves WORKSPACE_MANAGED_CONFIRM. The actor must be a
// current effective Workspace OWNER/MANAGER acting under a live exact actor
// grant. Only after visibility and that role check does it read the protected
// revision/configuration, the binding, the actor grant, the ADR-0087 §2
// verifier/confirmer separation-of-duty conflict, the current policy and
// warning, and finally the live-confirmation precheck — which uses the now-known
// current policy and warning so it matches the database derived-live set
// exactly (a stale or grant-revoked confirmation does not block a new confirm).
//
// The verifierConflict check is the reverse direction of ADR-0087 §2's rule
// (review blocker B3'): "A principal cannot be both the CONNECTOR_ADMIN who
// verifies a connector's trust and the workspace owner/manager who confirms
// that scope's WORKSPACE_MANAGED binding under ADR-0053's confirmation
// policy." Migration 000059's app.source_connection_trust_verify already
// denies verify-after-confirm (same principal); this denies confirm-after-
// verify the same way — terminalDenied, exactly as an unheld/non-live actor
// grant is denied a few lines above, with no distinguishing precondition
// detail — so the separation of duty cannot be evaded merely by picking
// whichever of the two commands the same principal performs second.
func confirmDecision(actor authorityActor, ws authorityWorkspace, business confirmBusiness) (authorityTerminal, error) {
	if !actor.organizationActive || !actor.principalActive || !actor.visible(ws, false) {
		return terminalNotFound, nil
	}
	if !ws.isOwnerOrManager() || ws.status != workspace.StatusActive {
		return terminalDenied, nil
	}
	revisionConfigCurrent, err := business.revisionConfigCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !revisionConfigCurrent {
		return terminalPreconditionFailed, nil
	}
	bindingCurrent, err := business.bindingCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !bindingCurrent {
		return terminalPreconditionFailed, nil
	}
	grant, err := business.actorGrant()
	if err != nil {
		return terminalSuccess, err
	}
	if !grant.held || !grant.live {
		return terminalDenied, nil
	}
	if !grant.hashMatches {
		return terminalPreconditionFailed, nil
	}
	verifierConflict, err := business.verifierConflict()
	if err != nil {
		return terminalSuccess, err
	}
	if verifierConflict {
		return terminalDenied, nil
	}
	policyCurrent, err := business.policyCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !policyCurrent {
		return terminalPreconditionFailed, nil
	}
	warningCurrent, err := business.warningCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !warningCurrent {
		return terminalPreconditionFailed, nil
	}
	liveConfirmationExists, err := business.liveConfirmationExists()
	if err != nil {
		return terminalSuccess, err
	}
	if liveConfirmationExists {
		return terminalPreconditionFailed, nil
	}
	return terminalSuccess, nil
}

// confirmRevokeDecision resolves WORKSPACE_MANAGED_CONFIRM_REVOKE, mirroring the
// grant-revoke ordering: parent identity resolves self/visibility/existence
// early, then the parent hash/revoked state and the policy are read after
// authorization.
func confirmRevokeDecision(actor authorityActor, ws authorityWorkspace, self, parentExists bool, business confirmRevokeBusiness) (authorityTerminal, error) {
	if !actor.organizationActive || !actor.principalActive {
		if actor.visible(ws, self) {
			return terminalDenied, nil
		}
		return terminalNotFound, nil
	}
	if !actor.visible(ws, self) || !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound, nil
	}
	if !(actor.orgOwnerOrAdmin || ws.isOwnerOrManager() || self) {
		return terminalDenied, nil
	}
	if !parentExists {
		return terminalNotFound, nil
	}
	parent, err := business.parentBusiness()
	if err != nil {
		return terminalSuccess, err
	}
	if !parent.hashMatches {
		return terminalPreconditionFailed, nil
	}
	if parent.revoked {
		return terminalPreconditionFailed, nil
	}
	policyCurrent, err := business.policyCurrent()
	if err != nil {
		return terminalSuccess, err
	}
	if !policyCurrent {
		return terminalPreconditionFailed, nil
	}
	return terminalSuccess, nil
}

// Replay re-verification. A replay never re-enters the decision phase; it
// repeats only current identity and the operation-specific visibility, never
// the execution-time preconditions that gated the original command. Historical
// replay is permitted only while the workspace is ACTIVE, READ_ONLY or
// ARCHIVED: a DELETING or DELETED workspace terminates NOT_FOUND without
// revealing the stored result.

func issueReplayTerminal(actor authorityActor, ws authorityWorkspace) authorityTerminal {
	// A non-replayable (DELETING/DELETED, or absent) workspace never returns the
	// stored result, regardless of the actor's organization role.
	if !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound
	}
	if actor.organizationActive && actor.principalActive && actor.orgOwnerOrAdmin {
		return terminalSuccess
	}
	if actor.visible(ws, false) {
		return terminalDenied
	}
	return terminalNotFound
}

func confirmReplayTerminal(actor authorityActor, ws authorityWorkspace) authorityTerminal {
	if !actor.organizationActive || !actor.principalActive || !actor.visible(ws, false) || !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound
	}
	if !ws.isOwnerOrManager() {
		return terminalDenied
	}
	return terminalSuccess
}

func grantRevokeReplayTerminal(actor authorityActor, ws authorityWorkspace, self bool) authorityTerminal {
	if !actor.organizationActive || !actor.principalActive || !actor.visible(ws, self) || !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound
	}
	if actor.orgOwnerOrAdmin || ws.isOwner() || self {
		return terminalSuccess
	}
	return terminalDenied
}

func confirmRevokeReplayTerminal(actor authorityActor, ws authorityWorkspace, self bool) authorityTerminal {
	if !actor.organizationActive || !actor.principalActive || !actor.visible(ws, self) || !revocableWorkspaceStatus(ws.status) {
		return terminalNotFound
	}
	if actor.orgOwnerOrAdmin || ws.isOwnerOrManager() || self {
		return terminalSuccess
	}
	return terminalDenied
}

// failureAuditWorkspace applies the AuditEvent.workspace_id rule for a failed
// terminal: exact on PRECONDITION_FAILED, exact on DENIED only when same-tenant
// visibility was already established, and always absent on NOT_FOUND.
func failureAuditWorkspace(terminal authorityTerminal, workspaceID string, visible bool) *string {
	switch terminal {
	case terminalPreconditionFailed:
		return &workspaceID
	case terminalDenied:
		if visible {
			return &workspaceID
		}
		return nil
	default:
		return nil
	}
}
