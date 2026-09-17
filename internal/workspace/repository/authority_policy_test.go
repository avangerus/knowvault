package repository

import (
	"testing"

	"knowvault.local/verified-workspace/internal/workspace"
)

// The authority policy matrix (ADR-0053) is proved here as pure functions, so
// every DENIED/NOT_FOUND/PRECONDITION_FAILED boundary is attributable to one
// fact. The recording-loader tests additionally prove the decision phase reads
// every protected business projection — including the workspace
// revision/configuration and the revocation parent's hash/revoked state — only
// after visibility and authorization have resolved; on an early terminal, zero
// business loaders are invoked.

func activeOrgAdmin() authorityActor {
	return authorityActor{organizationActive: true, principalActive: true, orgOwnerOrAdmin: true}
}

func activeMember() authorityActor {
	return authorityActor{organizationActive: true, principalActive: true, orgOwnerOrAdmin: false}
}

func activeWorkspace(role workspace.Role, present bool) authorityWorkspace {
	return authorityWorkspace{exists: true, status: workspace.StatusActive, membershipPresent: present, membershipRole: role}
}

func okBool(value bool) func() (bool, error) {
	return func() (bool, error) { return value, nil }
}

func okParent(hashMatches, revoked bool) func() (parentBusiness, error) {
	return func() (parentBusiness, error) { return parentBusiness{hashMatches: hashMatches, revoked: revoked}, nil }
}

func liveGrant() actorGrantEvaluation {
	return actorGrantEvaluation{held: true, live: true, hashMatches: true}
}

func issueBiz(targetEligible, revisionConfig, policy bool) issueBusiness {
	return issueBusiness{
		targetEligible:        okBool(targetEligible),
		revisionConfigCurrent: okBool(revisionConfig),
		policyCurrent:         okBool(policy),
	}
}

func grantRevokeBiz(hashMatches, revoked, policy bool) grantRevokeBusiness {
	return grantRevokeBusiness{parentBusiness: okParent(hashMatches, revoked), policyCurrent: okBool(policy)}
}

func confirmRevokeBiz(hashMatches, revoked, policy bool) confirmRevokeBusiness {
	return confirmRevokeBusiness{parentBusiness: okParent(hashMatches, revoked), policyCurrent: okBool(policy)}
}

func confirmBiz(revisionConfig, binding bool, grant actorGrantEvaluation, policy, warning, duplicate bool) confirmBusiness {
	return confirmBizConflict(revisionConfig, binding, grant, false, policy, warning, duplicate)
}

// confirmBizConflict is confirmBiz plus an explicit ADR-0087 §2
// verifier/confirmer separation-of-duty conflict flag (review blocker B3').
func confirmBizConflict(revisionConfig, binding bool, grant actorGrantEvaluation, conflict, policy, warning, duplicate bool) confirmBusiness {
	return confirmBusiness{
		revisionConfigCurrent:  okBool(revisionConfig),
		bindingCurrent:         okBool(binding),
		actorGrant:             func() (actorGrantEvaluation, error) { return grant, nil },
		verifierConflict:       okBool(conflict),
		policyCurrent:          okBool(policy),
		warningCurrent:         okBool(warning),
		liveConfirmationExists: okBool(duplicate),
	}
}

func mustTerminal(terminal authorityTerminal, err error) authorityTerminal {
	if err != nil {
		panic("decision returned error: " + err.Error())
	}
	return terminal
}

func TestIssueDecisionMatrix(t *testing.T) {
	t.Parallel()
	ownerWorkspace := activeWorkspace(workspace.RoleOwner, true)
	cases := []struct {
		name  string
		actor authorityActor
		ws    authorityWorkspace
		biz   issueBusiness
		want  authorityTerminal
	}{
		{"admin, eligible target, current", activeOrgAdmin(), ownerWorkspace, issueBiz(true, true, true), terminalSuccess},
		{"admin, ineligible target", activeOrgAdmin(), ownerWorkspace, issueBiz(false, true, true), terminalDenied},
		{"admin, stale revision", activeOrgAdmin(), ownerWorkspace, issueBiz(true, false, true), terminalPreconditionFailed},
		{"admin, stale policy", activeOrgAdmin(), ownerWorkspace, issueBiz(true, true, false), terminalPreconditionFailed},
		{"admin, non-active workspace", activeOrgAdmin(), authorityWorkspace{exists: true, status: workspace.StatusReadOnly, membershipPresent: true, membershipRole: workspace.RoleOwner}, issueBiz(true, true, true), terminalDenied},
		{"admin, missing workspace", activeOrgAdmin(), authorityWorkspace{exists: false}, issueBiz(true, true, true), terminalNotFound},
		{"member with visibility is denied", activeMember(), ownerWorkspace, issueBiz(true, true, true), terminalDenied},
		{"member without visibility is not found", activeMember(), activeWorkspace(workspace.RoleOwner, false), issueBiz(true, true, true), terminalNotFound},
		{"inactive org denies a visible admin", authorityActor{organizationActive: false, principalActive: true, orgOwnerOrAdmin: true}, activeWorkspace(workspace.RoleOwner, false), issueBiz(true, true, true), terminalDenied},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := mustTerminal(issueDecision(testCase.actor, testCase.ws, testCase.biz)); got != testCase.want {
				t.Fatalf("issueDecision = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestGrantRevokeDecisionMatrix(t *testing.T) {
	t.Parallel()
	member := activeMember()
	ownerWorkspace := activeWorkspace(workspace.RoleOwner, true)
	managerWorkspace := activeWorkspace(workspace.RoleManager, true)
	cases := []struct {
		name               string
		actor              authorityActor
		ws                 authorityWorkspace
		self, parentExists bool
		biz                grantRevokeBusiness
		want               authorityTerminal
	}{
		{"org admin revokes", activeOrgAdmin(), managerWorkspace, false, true, grantRevokeBiz(true, false, true), terminalSuccess},
		{"workspace owner revokes", member, ownerWorkspace, false, true, grantRevokeBiz(true, false, true), terminalSuccess},
		{"manager self-revoke", member, managerWorkspace, true, true, grantRevokeBiz(true, false, true), terminalSuccess},
		{"manager cannot revoke other's grant", member, managerWorkspace, false, true, grantRevokeBiz(true, false, true), terminalDenied},
		{"missing parent is not found", activeOrgAdmin(), managerWorkspace, false, false, grantRevokeBiz(true, false, true), terminalNotFound},
		{"stale grant hash", activeOrgAdmin(), managerWorkspace, false, true, grantRevokeBiz(false, false, true), terminalPreconditionFailed},
		{"already revoked", activeOrgAdmin(), managerWorkspace, false, true, grantRevokeBiz(true, true, true), terminalPreconditionFailed},
		{"stale policy", activeOrgAdmin(), managerWorkspace, false, true, grantRevokeBiz(true, false, false), terminalPreconditionFailed},
		{"no visibility is not found", member, activeWorkspace(workspace.RoleViewer, false), false, true, grantRevokeBiz(true, false, true), terminalNotFound},
		{"deleting workspace is not found", activeOrgAdmin(), authorityWorkspace{exists: true, status: workspace.StatusDeleting, membershipPresent: true, membershipRole: workspace.RoleManager}, false, true, grantRevokeBiz(true, false, true), terminalNotFound},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := mustTerminal(grantRevokeDecision(testCase.actor, testCase.ws, testCase.self, testCase.parentExists, testCase.biz))
			if got != testCase.want {
				t.Fatalf("grantRevokeDecision = %d, want %d", got, testCase.want)
			}
		})
	}
}

func TestConfirmDecisionMatrix(t *testing.T) {
	t.Parallel()
	managerWorkspace := activeWorkspace(workspace.RoleManager, true)
	memberWorkspace := activeWorkspace(workspace.RoleMember, true)
	check := func(name string, ws authorityWorkspace, biz confirmBusiness, want authorityTerminal) {
		if got := mustTerminal(confirmDecision(activeMember(), ws, biz)); got != want {
			t.Fatalf("%s = %d, want %d", name, got, want)
		}
	}
	check("success", managerWorkspace, confirmBiz(true, true, liveGrant(), true, true, false), terminalSuccess)
	check("member role denied", memberWorkspace, confirmBiz(true, true, liveGrant(), true, true, false), terminalDenied)
	check("stale revision", managerWorkspace, confirmBiz(false, true, liveGrant(), true, true, false), terminalPreconditionFailed)
	check("stale binding", managerWorkspace, confirmBiz(true, false, liveGrant(), true, true, false), terminalPreconditionFailed)
	check("no live grant", managerWorkspace, confirmBiz(true, true, actorGrantEvaluation{held: false}, true, true, false), terminalDenied)
	check("stale grant hash", managerWorkspace, confirmBiz(true, true, actorGrantEvaluation{held: true, live: true, hashMatches: false}, true, true, false), terminalPreconditionFailed)
	check("stale policy", managerWorkspace, confirmBiz(true, true, liveGrant(), false, true, false), terminalPreconditionFailed)
	check("stale warning", managerWorkspace, confirmBiz(true, true, liveGrant(), true, false, false), terminalPreconditionFailed)
	check("duplicate live confirmation", managerWorkspace, confirmBiz(true, true, liveGrant(), true, true, true), terminalPreconditionFailed)
	check("no visibility", activeWorkspace(workspace.RoleViewer, false), confirmBiz(true, true, liveGrant(), true, true, false), terminalNotFound)
	check("deleting workspace denied", authorityWorkspace{exists: true, status: workspace.StatusDeleting, membershipPresent: true, membershipRole: workspace.RoleManager}, confirmBiz(true, true, liveGrant(), true, true, false), terminalDenied)
	// ADR-0087 §2 review blocker B3': the reverse separation-of-duty
	// direction. A principal who already verified this connection's trust
	// as CONNECTOR_ADMIN is denied confirming a WORKSPACE_MANAGED binding of
	// one of its scopes -- terminalDenied, the same content-free outcome as
	// "no live grant" a few cases above, never terminalPreconditionFailed
	// (which would let a caller distinguish this conflict from an ordinary
	// stale precondition).
	check("verifier/confirmer conflict denied", managerWorkspace, confirmBizConflict(true, true, liveGrant(), true, true, true, false), terminalDenied)
}

func TestConfirmRevokeDecisionMatrix(t *testing.T) {
	t.Parallel()
	managerWorkspace := activeWorkspace(workspace.RoleManager, true)
	cases := []struct {
		name               string
		actor              authorityActor
		ws                 authorityWorkspace
		self, parentExists bool
		biz                confirmRevokeBusiness
		want               authorityTerminal
	}{
		{"manager revokes", activeMember(), managerWorkspace, false, true, confirmRevokeBiz(true, false, true), terminalSuccess},
		{"self revoke after leaving", activeMember(), authorityWorkspace{exists: true, status: workspace.StatusArchived}, true, true, confirmRevokeBiz(true, false, true), terminalSuccess},
		{"missing parent is not found", activeOrgAdmin(), managerWorkspace, false, false, confirmRevokeBiz(true, false, true), terminalNotFound},
		{"stale confirmation hash", activeOrgAdmin(), managerWorkspace, false, true, confirmRevokeBiz(false, false, true), terminalPreconditionFailed},
		{"already revoked", activeOrgAdmin(), managerWorkspace, false, true, confirmRevokeBiz(true, true, true), terminalPreconditionFailed},
		{"stale policy", activeOrgAdmin(), managerWorkspace, false, true, confirmRevokeBiz(true, false, false), terminalPreconditionFailed},
		{"plain member is denied", activeMember(), activeWorkspace(workspace.RoleMember, true), false, true, confirmRevokeBiz(true, false, true), terminalDenied},
		{"deleting workspace is not found", activeOrgAdmin(), authorityWorkspace{exists: true, status: workspace.StatusDeleting, membershipPresent: true, membershipRole: workspace.RoleManager}, false, true, confirmRevokeBiz(true, false, true), terminalNotFound},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := mustTerminal(confirmRevokeDecision(testCase.actor, testCase.ws, testCase.self, testCase.parentExists, testCase.biz))
			if got != testCase.want {
				t.Fatalf("confirmRevokeDecision = %d, want %d", got, testCase.want)
			}
		})
	}
}

// callRecorder records, in order, which business loaders a decision invoked.
type callRecorder struct{ calls []string }

func (recorder *callRecorder) markBool(name string, value bool) func() (bool, error) {
	return func() (bool, error) { recorder.calls = append(recorder.calls, name); return value, nil }
}

func (recorder *callRecorder) markGrant(name string, value actorGrantEvaluation) func() (actorGrantEvaluation, error) {
	return func() (actorGrantEvaluation, error) { recorder.calls = append(recorder.calls, name); return value, nil }
}

func (recorder *callRecorder) markParent(name string, value parentBusiness) func() (parentBusiness, error) {
	return func() (parentBusiness, error) { recorder.calls = append(recorder.calls, name); return value, nil }
}

func assertSequence(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("read order = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("read order = %v, want %v", got, want)
		}
	}
}

// TestDecisionPhaseReadsBusinessProjectionsOnlyAfterAuthorization proves the
// business projections — target eligibility, the workspace revision/config, the
// binding, the actor grant, the parent hash/revoked state, policy and warning —
// are never read until visibility and authorization resolve, and that when they
// are read it is in the ADR-0053 order.
func TestDecisionPhaseReadsBusinessProjectionsOnlyAfterAuthorization(t *testing.T) {
	t.Parallel()

	t.Run("issue: unauthorized issuer reads nothing", func(t *testing.T) {
		recorder := &callRecorder{}
		business := issueBusiness{
			targetEligible:        recorder.markBool("target", true),
			revisionConfigCurrent: recorder.markBool("revision_config", true),
			policyCurrent:         recorder.markBool("policy", true),
		}
		if got := mustTerminal(issueDecision(activeMember(), activeWorkspace(workspace.RoleOwner, false), business)); got != terminalNotFound {
			t.Fatalf("terminal = %d, want NOT_FOUND", got)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("unauthorized issue read projections: %v", recorder.calls)
		}
	})

	t.Run("issue: success reads target, revision_config, policy in order", func(t *testing.T) {
		recorder := &callRecorder{}
		business := issueBusiness{
			targetEligible:        recorder.markBool("target", true),
			revisionConfigCurrent: recorder.markBool("revision_config", true),
			policyCurrent:         recorder.markBool("policy", true),
		}
		if got := mustTerminal(issueDecision(activeOrgAdmin(), activeWorkspace(workspace.RoleOwner, true), business)); got != terminalSuccess {
			t.Fatalf("terminal = %d, want SUCCESS", got)
		}
		assertSequence(t, recorder.calls, []string{"target", "revision_config", "policy"})
	})

	t.Run("grant revoke: invisible workspace reads no parent business or policy", func(t *testing.T) {
		recorder := &callRecorder{}
		business := grantRevokeBusiness{
			parentBusiness: recorder.markParent("parent_business", parentBusiness{hashMatches: true}),
			policyCurrent:  recorder.markBool("policy", true),
		}
		if got := mustTerminal(grantRevokeDecision(activeMember(), activeWorkspace(workspace.RoleViewer, false), false, false, business)); got != terminalNotFound {
			t.Fatalf("terminal = %d, want NOT_FOUND", got)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("invisible grant revoke read a business projection: %v", recorder.calls)
		}
	})

	t.Run("grant revoke: success reads parent_business then policy", func(t *testing.T) {
		recorder := &callRecorder{}
		business := grantRevokeBusiness{
			parentBusiness: recorder.markParent("parent_business", parentBusiness{hashMatches: true, revoked: false}),
			policyCurrent:  recorder.markBool("policy", true),
		}
		if got := mustTerminal(grantRevokeDecision(activeOrgAdmin(), activeWorkspace(workspace.RoleManager, true), false, true, business)); got != terminalSuccess {
			t.Fatalf("terminal = %d, want SUCCESS", got)
		}
		assertSequence(t, recorder.calls, []string{"parent_business", "policy"})
	})

	t.Run("confirm: insufficient role reads nothing", func(t *testing.T) {
		recorder := &callRecorder{}
		business := confirmBusiness{
			revisionConfigCurrent:  recorder.markBool("revision_config", true),
			bindingCurrent:         recorder.markBool("binding", true),
			actorGrant:             recorder.markGrant("actor_grant", liveGrant()),
			verifierConflict:       recorder.markBool("verifier_conflict", false),
			policyCurrent:          recorder.markBool("policy", true),
			warningCurrent:         recorder.markBool("warning", true),
			liveConfirmationExists: recorder.markBool("duplicate", false),
		}
		if got := mustTerminal(confirmDecision(activeMember(), activeWorkspace(workspace.RoleMember, true), business)); got != terminalDenied {
			t.Fatalf("terminal = %d, want DENIED", got)
		}
		if len(recorder.calls) != 0 {
			t.Fatalf("insufficient-role confirm read projections: %v", recorder.calls)
		}
	})

	t.Run("confirm: verifier/confirmer conflict reads nothing past the grant", func(t *testing.T) {
		recorder := &callRecorder{}
		business := confirmBusiness{
			revisionConfigCurrent:  recorder.markBool("revision_config", true),
			bindingCurrent:         recorder.markBool("binding", true),
			actorGrant:             recorder.markGrant("actor_grant", liveGrant()),
			verifierConflict:       recorder.markBool("verifier_conflict", true),
			policyCurrent:          recorder.markBool("policy", true),
			warningCurrent:         recorder.markBool("warning", true),
			liveConfirmationExists: recorder.markBool("duplicate", false),
		}
		if got := mustTerminal(confirmDecision(activeMember(), activeWorkspace(workspace.RoleManager, true), business)); got != terminalDenied {
			t.Fatalf("terminal = %d, want DENIED", got)
		}
		assertSequence(t, recorder.calls, []string{"revision_config", "binding", "actor_grant", "verifier_conflict"})
	})

	t.Run("confirm: success reads the projections in ADR order with duplicate last", func(t *testing.T) {
		recorder := &callRecorder{}
		business := confirmBusiness{
			revisionConfigCurrent:  recorder.markBool("revision_config", true),
			bindingCurrent:         recorder.markBool("binding", true),
			actorGrant:             recorder.markGrant("actor_grant", liveGrant()),
			verifierConflict:       recorder.markBool("verifier_conflict", false),
			policyCurrent:          recorder.markBool("policy", true),
			warningCurrent:         recorder.markBool("warning", true),
			liveConfirmationExists: recorder.markBool("duplicate", false),
		}
		if got := mustTerminal(confirmDecision(activeMember(), activeWorkspace(workspace.RoleManager, true), business)); got != terminalSuccess {
			t.Fatalf("terminal = %d, want SUCCESS", got)
		}
		assertSequence(t, recorder.calls, []string{"revision_config", "binding", "actor_grant", "verifier_conflict", "policy", "warning", "duplicate"})
	})
}

func TestReplayVisibilityAndLifecycle(t *testing.T) {
	t.Parallel()
	deleting := authorityWorkspace{exists: true, status: workspace.StatusDeleting, membershipPresent: true, membershipRole: workspace.RoleOwner}
	deleted := authorityWorkspace{exists: true, status: workspace.StatusDeleted, membershipPresent: true, membershipRole: workspace.RoleManager}

	// DELETING/DELETED never returns the stored result, on any operation.
	if got := issueReplayTerminal(activeOrgAdmin(), deleting); got != terminalNotFound {
		t.Fatalf("issue replay on DELETING = %d, want NOT_FOUND", got)
	}
	if got := confirmReplayTerminal(activeMember(), deleting); got != terminalNotFound {
		t.Fatalf("confirm replay on DELETING = %d, want NOT_FOUND", got)
	}
	if got := grantRevokeReplayTerminal(activeMember(), deleted, true); got != terminalNotFound {
		t.Fatalf("grant revoke replay on DELETED = %d, want NOT_FOUND", got)
	}
	if got := confirmRevokeReplayTerminal(activeOrgAdmin(), deleted, false); got != terminalNotFound {
		t.Fatalf("confirm revoke replay on DELETED = %d, want NOT_FOUND", got)
	}

	// Operation-specific replay visibility on a replayable workspace.
	lostMembership := authorityWorkspace{exists: true, status: workspace.StatusActive}
	if got := grantRevokeReplayTerminal(activeMember(), lostMembership, true); got != terminalSuccess {
		t.Fatalf("self-revoke replay after membership loss = %d, want SUCCESS", got)
	}
	if got := grantRevokeReplayTerminal(activeMember(), lostMembership, false); got != terminalNotFound {
		t.Fatalf("non-self replay without membership = %d, want NOT_FOUND", got)
	}
	if got := confirmReplayTerminal(activeMember(), activeWorkspace(workspace.RoleOwner, true)); got != terminalSuccess {
		t.Fatalf("confirm replay for current owner = %d, want SUCCESS", got)
	}
	if got := confirmReplayTerminal(activeMember(), activeWorkspace(workspace.RoleMember, true)); got != terminalDenied {
		t.Fatalf("confirm replay for insufficient role = %d, want DENIED", got)
	}
	if got := issueReplayTerminal(activeMember(), activeWorkspace(workspace.RoleOwner, true)); got != terminalDenied {
		t.Fatalf("issue replay for lost org role with visibility = %d, want DENIED", got)
	}
}

func TestFailureAuditWorkspaceRule(t *testing.T) {
	t.Parallel()
	if failureAuditWorkspace(terminalNotFound, "ws", true) != nil {
		t.Fatal("NOT_FOUND must never carry a workspace id")
	}
	if failureAuditWorkspace(terminalPreconditionFailed, "ws", false) == nil {
		t.Fatal("PRECONDITION_FAILED must carry the workspace id")
	}
	if failureAuditWorkspace(terminalDenied, "ws", false) != nil {
		t.Fatal("DENIED without established visibility must omit the workspace id")
	}
	if failureAuditWorkspace(terminalDenied, "ws", true) == nil {
		t.Fatal("DENIED with established visibility must carry the workspace id")
	}
}
