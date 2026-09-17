package policy

import "testing"

func TestEvaluateWorkspaceDefaultsToDenyAcrossTenantAndMembershipBoundaries(t *testing.T) {
	t.Parallel()

	base := Request{
		Operation:  OperationWorkspaceReadContent,
		Subject:    Subject{OrganizationID: "org_alpha", PrincipalID: "usr_alice", Status: PrincipalActive, SessionRevision: 1},
		Workspace:  Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: WorkspaceActive},
		Membership: Membership{Present: true, Role: WorkspaceMember},
	}
	if got := EvaluateWorkspace(base); !got.Allowed || got.ReasonCodes[0] != ReasonAllowed {
		t.Fatalf("member read denied: %#v", got)
	}

	for name, mutate := range map[string]func(*Request){
		"cross tenant":      func(request *Request) { request.Workspace.OrganizationID = "org_beta" },
		"no membership":     func(request *Request) { request.Membership = Membership{} },
		"deprovisioned":     func(request *Request) { request.Subject.Status = PrincipalDeprovisioned },
		"unknown operation": func(request *Request) { request.Operation = "workspace.export_everything" },
		"control character": func(request *Request) { request.Subject.PrincipalID = "usr\nalice" },
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := base
			mutate(&request)
			if got := EvaluateWorkspace(request); got.Allowed {
				t.Fatalf("unexpected allow: %#v", got)
			}
		})
	}
}

func TestOrganizationAdminDoesNotReceiveWorkspaceContentAccess(t *testing.T) {
	t.Parallel()

	request := Request{
		Operation: OperationWorkspaceReadContent,
		Subject: Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_admin", Status: PrincipalActive, SessionRevision: 3,
			OrganizationRoles: []OrganizationRole{OrganizationAdmin},
		},
		Workspace: Workspace{OrganizationID: "org_alpha", ID: "ws_private", Status: WorkspaceActive},
	}
	if got := EvaluateWorkspace(request); got.Allowed || got.ReasonCodes[0] != ReasonWorkspaceMembershipAbsent {
		t.Fatalf("organization admin bypassed data membership: %#v", got)
	}
}

func TestEvaluateOrganizationAllowsOnlyActiveOwnerOrAdminToCreateWorkspace(t *testing.T) {
	t.Parallel()

	base := OrganizationRequest{
		Operation: OperationWorkspaceCreate,
		Subject: Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_alice", Status: PrincipalActive, SessionRevision: 1,
		},
		Organization: Organization{ID: "org_alpha", Status: OrganizationActive},
	}
	tests := map[string]struct {
		roles  []OrganizationRole
		mutate func(*OrganizationRequest)
		want   ReasonCode
	}{
		"owner":                  {roles: []OrganizationRole{OrganizationOwner}, want: ReasonAllowed},
		"admin":                  {roles: []OrganizationRole{OrganizationAdmin}, want: ReasonAllowed},
		"member denied":          {roles: []OrganizationRole{OrganizationMember}, want: ReasonOrganizationRoleInsufficient},
		"auditor denied":         {roles: []OrganizationRole{OrganizationSecurityAuditor}, want: ReasonOrganizationRoleInsufficient},
		"suspended organization": {roles: []OrganizationRole{OrganizationOwner}, mutate: func(request *OrganizationRequest) { request.Organization.Status = OrganizationSuspended }, want: ReasonOrganizationUnavailable},
		"tenant mismatch":        {roles: []OrganizationRole{OrganizationOwner}, mutate: func(request *OrganizationRequest) { request.Organization.ID = "org_beta" }, want: ReasonOrganizationMismatch},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := base
			request.Subject.OrganizationRoles = append([]OrganizationRole(nil), test.roles...)
			if test.mutate != nil {
				test.mutate(&request)
			}
			decision := EvaluateOrganization(request)
			if len(decision.ReasonCodes) != 1 || decision.ReasonCodes[0] != test.want || decision.Allowed != (test.want == ReasonAllowed) {
				t.Fatalf("decision = %#v, want %q", decision, test.want)
			}
		})
	}
}

func TestEvaluateOrganizationAllowsOnlyActiveConnectorAdminToVerifyTrust(t *testing.T) {
	t.Parallel()

	base := OrganizationRequest{
		Operation: OperationSourceVerifyTrust,
		Subject: Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_connector", Status: PrincipalActive, SessionRevision: 1,
		},
		Organization: Organization{ID: "org_alpha", Status: OrganizationActive},
	}
	tests := map[string]struct {
		roles  []OrganizationRole
		mutate func(*OrganizationRequest)
		want   ReasonCode
	}{
		"connector_admin allowed": {roles: []OrganizationRole{OrganizationConnectorAdmin}, want: ReasonAllowed},
		"owner denied":            {roles: []OrganizationRole{OrganizationOwner}, want: ReasonOrganizationRoleInsufficient},
		"admin denied":            {roles: []OrganizationRole{OrganizationAdmin}, want: ReasonOrganizationRoleInsufficient},
		"auditor denied":          {roles: []OrganizationRole{OrganizationSecurityAuditor}, want: ReasonOrganizationRoleInsufficient},
		"member denied":           {roles: []OrganizationRole{OrganizationMember}, want: ReasonOrganizationRoleInsufficient},
		"no roles denied":         {roles: []OrganizationRole{}, want: ReasonOrganizationRoleInsufficient},
		"suspended organization":  {roles: []OrganizationRole{OrganizationConnectorAdmin}, mutate: func(request *OrganizationRequest) { request.Organization.Status = OrganizationSuspended }, want: ReasonOrganizationUnavailable},
		"tenant mismatch":         {roles: []OrganizationRole{OrganizationConnectorAdmin}, mutate: func(request *OrganizationRequest) { request.Organization.ID = "org_beta" }, want: ReasonOrganizationMismatch},
		"inactive principal":      {roles: []OrganizationRole{OrganizationConnectorAdmin}, mutate: func(request *OrganizationRequest) { request.Subject.Status = PrincipalDisabled }, want: ReasonPrincipalInactive},
		"unknown operation":       {roles: []OrganizationRole{OrganizationConnectorAdmin}, mutate: func(request *OrganizationRequest) { request.Operation = "source.export_trust" }, want: ReasonOperationUnknown},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := base
			request.Subject.OrganizationRoles = append([]OrganizationRole(nil), test.roles...)
			if test.mutate != nil {
				test.mutate(&request)
			}
			decision := EvaluateOrganization(request)
			if len(decision.ReasonCodes) != 1 || decision.ReasonCodes[0] != test.want || decision.Allowed != (test.want == ReasonAllowed) {
				t.Fatalf("decision = %#v, want %q", decision, test.want)
			}
		})
	}
}

func TestConnectorAdminDoesNotGainWorkspaceOrSourceCapabilities(t *testing.T) {
	t.Parallel()

	subject := Subject{
		OrganizationID: "org_alpha", PrincipalID: "usr_connector", Status: PrincipalActive, SessionRevision: 1,
		OrganizationRoles: []OrganizationRole{OrganizationConnectorAdmin},
	}
	organization := Organization{ID: "org_alpha", Status: OrganizationActive}
	for _, op := range []Operation{OperationWorkspaceCreate, OperationSourceRegister, OperationSourceActivate} {
		request := OrganizationRequest{Operation: op, Subject: subject, Organization: organization}
		if got := EvaluateOrganization(request); got.Allowed || len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != ReasonOrganizationRoleInsufficient {
			t.Fatalf("CONNECTOR_ADMIN received %q: %#v", op, got)
		}
	}
}

func TestAuditorCanReadOnlyAuditMetadata(t *testing.T) {
	t.Parallel()

	base := Request{
		Operation: OperationAuditReadMetadata,
		Subject: Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_auditor", Status: PrincipalActive, SessionRevision: 1,
			OrganizationRoles: []OrganizationRole{OrganizationSecurityAuditor},
		},
		Workspace: Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: WorkspaceActive},
	}
	if got := EvaluateWorkspace(base); !got.Allowed {
		t.Fatalf("security auditor metadata denied: %#v", got)
	}
	base.Operation = OperationWorkspaceReadContent
	if got := EvaluateWorkspace(base); got.Allowed {
		t.Fatalf("security auditor received content access: %#v", got)
	}
}

func TestWorkspaceStateAndRoleAreOperationSpecific(t *testing.T) {
	t.Parallel()

	request := Request{
		Operation:  OperationWorkspaceAsk,
		Subject:    Subject{OrganizationID: "org_alpha", PrincipalID: "usr_viewer", Status: PrincipalActive, SessionRevision: 1},
		Workspace:  Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: WorkspaceActive},
		Membership: Membership{Present: true, Role: WorkspaceViewer},
	}
	if got := EvaluateWorkspace(request); got.Allowed {
		t.Fatalf("viewer received ask: %#v", got)
	}

	request.Membership.Role = WorkspaceMember
	request.Workspace.Status = WorkspaceReadOnly
	if got := EvaluateWorkspace(request); got.Allowed {
		t.Fatalf("read-only workspace accepted a new question: %#v", got)
	}

	request.Operation = OperationWorkspaceReadContent
	if got := EvaluateWorkspace(request); !got.Allowed {
		t.Fatalf("member could not read historical content: %#v", got)
	}
}

func TestRoleCanAskHintMatchesAuthenticatedWorkspaceDecision(t *testing.T) {
	for _, status := range []WorkspaceStatus{WorkspaceActive, WorkspaceReadOnly, WorkspaceArchived, WorkspaceDeleting, WorkspaceDeleted, "UNKNOWN"} {
		for _, role := range []WorkspaceRole{WorkspaceOwner, WorkspaceManager, WorkspaceMember, WorkspaceViewer, WorkspaceAuditor, "UNKNOWN"} {
			request := Request{
				Operation:  OperationWorkspaceAsk,
				Subject:    Subject{OrganizationID: "org_alpha", PrincipalID: "usr_alpha", Status: PrincipalActive, SessionRevision: 3},
				Workspace:  Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: status},
				Membership: Membership{Present: true, Role: role},
			}
			if RoleCanAsk(status, role) != EvaluateWorkspace(request).Allowed {
				t.Fatalf("ask capability differs from policy for %s/%s", status, role)
			}
			request.Subject.Status = PrincipalDisabled
			if EvaluateWorkspace(request).Allowed {
				t.Fatalf("role/status hint bypassed principal authorization for %s/%s", status, role)
			}
		}
	}
}

func TestWorkspaceSourceManagementIsAnExplicitOwnerManagerOperation(t *testing.T) {
	t.Parallel()

	base := Request{
		Operation: OperationWorkspaceManageSources,
		Subject: Subject{
			OrganizationID: "org_alpha", PrincipalID: "usr_actor", Status: PrincipalActive, SessionRevision: 1,
			OrganizationRoles: []OrganizationRole{OrganizationAdmin},
		},
		Workspace:  Workspace{OrganizationID: "org_alpha", ID: "ws_alpha", Status: WorkspaceActive},
		Membership: Membership{Present: true, Role: WorkspaceOwner},
	}

	for _, role := range []WorkspaceRole{WorkspaceOwner, WorkspaceManager} {
		request := base
		request.Membership.Role = role
		if got := EvaluateWorkspace(request); !got.Allowed || len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != ReasonAllowed {
			t.Fatalf("%s source management denied: %#v", role, got)
		}
	}

	for _, role := range []WorkspaceRole{WorkspaceMember, WorkspaceViewer, WorkspaceAuditor} {
		request := base
		request.Membership.Role = role
		if got := EvaluateWorkspace(request); got.Allowed || len(got.ReasonCodes) != 1 || got.ReasonCodes[0] != ReasonWorkspaceRoleInsufficient {
			t.Fatalf("%s received source management: %#v", role, got)
		}
	}

	withoutMembership := base
	withoutMembership.Membership = Membership{}
	if got := EvaluateWorkspace(withoutMembership); got.Allowed || got.ReasonCodes[0] != ReasonWorkspaceMembershipAbsent {
		t.Fatalf("organization admin bypassed source-management membership: %#v", got)
	}

	readOnly := base
	readOnly.Workspace.Status = WorkspaceReadOnly
	if got := EvaluateWorkspace(readOnly); got.Allowed || got.ReasonCodes[0] != ReasonWorkspaceRoleInsufficient {
		t.Fatalf("read-only workspace accepted source management: %#v", got)
	}
}
