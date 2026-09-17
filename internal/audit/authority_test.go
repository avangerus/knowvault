package audit

import (
	"testing"
	"time"
)

// The Go half of the workspace-managed authority audit contract (ADR-0053) is
// the mirror of the migration 000011 database gates. Both are enforcing
// validators, so this matrix drives every closed rule that the database also
// pins: the action/resource pairing, the outcome-to-error-code map, the
// workspace_id rule, the exact per-action metadata sets and the reserved
// vocabulary. What Go cannot check — that a SUCCESS metadata value names the
// row actually persisted — is proved in PostgreSQL, against the trusted
// persisted row, and is deliberately not restated here.

const (
	authorityTestOrganization = "org_authority"
	authorityTestActor        = "usr_authority_actor"
	authorityTestWorkspace    = "ws_authority"
	authorityTestCommand      = "cmd_authority_0001"
	authorityTestHash         = "sha256:" +
		"1111111111111111111111111111111111111111111111111111111111111111"
	authorityTestPolicy = "policy-org_authority-0001"
)

func authorityOccurredAt() time.Time {
	return time.Date(2026, time.July, 16, 12, 0, 0, 0, time.UTC)
}

// authoritySuccessInput is a valid grant-issue SUCCESS event. Each test mutates
// exactly one facet of it, so a rejection is attributable to that facet alone.
func authoritySuccessInput() EventInput {
	workspace := authorityTestWorkspace
	actor := authorityTestActor
	return EventInput{
		EventID:          "aud_authority_0001",
		WorkspaceID:      &workspace,
		ActorType:        ActorHuman,
		ActorPrincipalID: &actor,
		Action:           ActionWorkspaceSourceConfirmationGrantIssued,
		ResourceType:     ResourceWorkspaceAuthorityCommand,
		ResourceID:       authorityTestCommand,
		RequestID:        "req_authority_0001",
		Outcome:          OutcomeSuccess,
		Metadata: Metadata{
			AuthorityOperation:  ptr(authorityOperationGrantIssue),
			AuthorityResultID:   ptr("grant_authority_0001"),
			AuthorityResultHash: ptr(authorityTestHash),
			TargetPrincipalID:   ptr("usr_authority_target"),
			PolicyRevision:      ptr(authorityTestPolicy),
		},
		OccurredAt: authorityOccurredAt(),
	}
}

func authorityConfirmSuccessInput() EventInput {
	input := authoritySuccessInput()
	input.Action = ActionWorkspaceSourceConfirmed
	revision := int64(1)
	scopeRevision := int64(1)
	workspaceRevision := int64(4)
	input.Metadata = Metadata{
		AuthorityOperation:             ptr(authorityOperationConfirm),
		AuthorityResultID:              ptr("wmc_authority_0001"),
		AuthorityResultHash:            ptr(authorityTestHash),
		WorkspaceRevision:              &workspaceRevision,
		WorkspaceConfigurationHash:     ptr(authorityTestHash),
		WorkspaceSourceID:              ptr("wss_authority_0001"),
		SourceScopeID:                  ptr("scp_authority_0001"),
		SourceScopeRevision:            &scopeRevision,
		ScopeConfigHash:                ptr(authorityTestHash),
		AccessMode:                     ptr(authorityAccessMode),
		ConfirmationActorGrantID:       ptr("grant_authority_0001"),
		ConfirmationActorGrantRevision: &revision,
		ConfirmationActorGrantHash:     ptr(authorityTestHash),
		WarningVersion:                 ptr(authorityWarningVersion),
		WarningContractHash:            ptr(authorityTestHash),
		AcknowledgementCode:            ptr(authorityAcknowledgementCode),
		PolicyRevision:                 ptr(authorityTestPolicy),
	}
	return input
}

func authorityRevokeSuccessInput(action Action, operation string, reason string) EventInput {
	input := authoritySuccessInput()
	input.Action = action
	input.Metadata = Metadata{
		AuthorityOperation:      ptr(operation),
		AuthorityParentID:       ptr("grant_authority_0001"),
		AuthorityParentHash:     ptr(authorityTestHash),
		AuthorityRevocationID:   ptr("rev_authority_0001"),
		AuthorityRevocationHash: ptr(authorityTestHash),
		AuthorityReasonCode:     ptr(reason),
		PolicyRevision:          ptr(authorityTestPolicy),
	}
	return input
}

func authorityFailureInput(outcome Outcome, errorCode string) EventInput {
	input := authoritySuccessInput()
	input.Outcome = outcome
	input.ErrorCode = ptr(errorCode)
	input.Metadata = Metadata{AuthorityOperation: ptr(authorityOperationGrantIssue)}
	if errorCode == ErrorAuthorityNotFound {
		input.WorkspaceID = nil
	}
	return input
}

func authorityBuilds(t *testing.T, input EventInput) error {
	t.Helper()
	_, err := Build(authorityTestOrganization, input, 0, "")
	return err
}

// TestAuthorityAuditAcceptsEveryContractLegalProjection is the positive half of
// the matrix: without it every negative below could pass against a validator
// that simply rejects all authority events.
func TestAuthorityAuditAcceptsEveryContractLegalProjection(t *testing.T) {
	t.Parallel()

	sameTenantDenied := authorityFailureInput(OutcomeDenied, ErrorAuthorityDenied)
	hiddenWorkspaceDenied := authorityFailureInput(OutcomeDenied, ErrorAuthorityDenied)
	hiddenWorkspaceDenied.WorkspaceID = nil

	cases := map[string]EventInput{
		"grant issue SUCCESS":    authoritySuccessInput(),
		"confirm SUCCESS":        authorityConfirmSuccessInput(),
		"grant revoke SUCCESS":   authorityRevokeSuccessInput(ActionWorkspaceSourceConfirmationGrantRevoked, authorityOperationGrantRevoke, authorityReasonGrantRevoked),
		"confirm revoke SUCCESS": authorityRevokeSuccessInput(ActionWorkspaceSourceConfirmationRevoked, authorityOperationConfirmRevoke, authorityReasonAccessRevoked),
		// DENIED is the one outcome where workspace_id is contract-legal
		// either way: exact when same-tenant visibility was already
		// established, absent when it was not.
		"DENIED with workspace":    sameTenantDenied,
		"DENIED without workspace": hiddenWorkspaceDenied,
		"NOT_FOUND":                authorityFailureInput(OutcomeDenied, ErrorAuthorityNotFound),
		"PRECONDITION_FAILED":      authorityFailureInput(OutcomeFailed, ErrorAuthorityPreconditionFailed),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if err := authorityBuilds(t, input); err != nil {
				t.Fatalf("contract-legal authority event rejected: %v", err)
			}
		})
	}
}

// TestAuthorityAuditRejectsEveryContractIllegalProjection mutates exactly one
// facet per case. Each mutation is a real drift a repository could ship.
func TestAuthorityAuditRejectsEveryContractIllegalProjection(t *testing.T) {
	t.Parallel()

	mutations := map[string]func(EventInput) EventInput{
		// The action and the resource type are strictly paired in both
		// directions: neither may appear without the other.
		"authority action on another resource type": func(input EventInput) EventInput {
			input.ResourceType = ResourceWorkspaceSource
			return input
		},
		"non-authority action on the authority resource": func(input EventInput) EventInput {
			input.Action = ActionWorkspaceCreated
			return input
		},
		// The outcome/error-code map is exhaustive.
		"SUCCESS carrying an error code": func(input EventInput) EventInput {
			input.ErrorCode = ptr(ErrorAuthorityDenied)
			return input
		},
		"DENIED without an error code": func(input EventInput) EventInput {
			input.Outcome = OutcomeDenied
			return input
		},
		"DENIED carrying the precondition code": func(input EventInput) EventInput {
			input.Outcome = OutcomeDenied
			input.ErrorCode = ptr(ErrorAuthorityPreconditionFailed)
			return input
		},
		"FAILED carrying the denied code": func(input EventInput) EventInput {
			input.Outcome = OutcomeFailed
			input.ErrorCode = ptr(ErrorAuthorityDenied)
			return input
		},
		// The workspace_id rule.
		"SUCCESS without a workspace": func(input EventInput) EventInput {
			input.WorkspaceID = nil
			return input
		},
		// The actor rule: an authority command is always a human acting for
		// themselves, with no delegated actor and no evidence.
		"a non-human actor": func(input EventInput) EventInput {
			input.ActorType = ActorSystem
			return input
		},
		"an on-behalf-of principal": func(input EventInput) EventInput {
			input.OnBehalfOfPrincipalID = ptr("usr_authority_delegator")
			return input
		},
		"referenced evidence": func(input EventInput) EventInput {
			input.ReferencedEvidenceIDs = []string{"ev_authority_0001"}
			return input
		},
		// The metadata set is exact: neither short nor long.
		"a missing operation": func(input EventInput) EventInput {
			input.Metadata.AuthorityOperation = nil
			return input
		},
		"an operation of another action": func(input EventInput) EventInput {
			input.Metadata.AuthorityOperation = ptr(authorityOperationConfirm)
			return input
		},
		"a missing SUCCESS metadata field": func(input EventInput) EventInput {
			input.Metadata.AuthorityResultHash = nil
			return input
		},
		"an extra SUCCESS metadata field": func(input EventInput) EventInput {
			input.Metadata.AuthorityParentID = ptr("grant_authority_0002")
			return input
		},
		// Field-level shape.
		"a result hash that is not a hash": func(input EventInput) EventInput {
			input.Metadata.AuthorityResultHash = ptr("deadbeef")
			return input
		},
		"a result ID that is not an ID": func(input EventInput) EventInput {
			input.Metadata.AuthorityResultID = ptr(" grant_authority_0001")
			return input
		},
		"an operation outside the closed set": func(input EventInput) EventInput {
			input.Metadata.AuthorityOperation = ptr("WORKSPACE_CONFIRMATION_GRANT_EXTEND")
			return input
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := authorityBuilds(t, mutate(authoritySuccessInput())); err == nil {
				t.Fatal("contract-illegal authority event accepted")
			}
		})
	}
}

// TestAuthorityFailureCarriesNothingButItsOperation proves the failure
// projection is exactly one key. A failure never proved the request current, so
// echoing any request-supplied field back into the audit trail would present
// unverified input as an established fact.
func TestAuthorityFailureCarriesNothingButItsOperation(t *testing.T) {
	t.Parallel()

	extras := map[string]func(*Metadata){
		"a target principal": func(m *Metadata) { m.TargetPrincipalID = ptr("usr_authority_target") },
		"a parent ID":        func(m *Metadata) { m.AuthorityParentID = ptr("grant_authority_0001") },
		"a parent hash":      func(m *Metadata) { m.AuthorityParentHash = ptr(authorityTestHash) },
		"an expected policy": func(m *Metadata) { m.PolicyRevision = ptr(authorityTestPolicy) },
		"a warning version":  func(m *Metadata) { m.WarningVersion = ptr(authorityWarningVersion) },
		"an acknowledgement": func(m *Metadata) { m.AcknowledgementCode = ptr(authorityAcknowledgementCode) },
		"a result ID":        func(m *Metadata) { m.AuthorityResultID = ptr("grant_authority_0001") },
	}
	for _, outcome := range []struct {
		name      string
		outcome   Outcome
		errorCode string
	}{
		{"DENIED", OutcomeDenied, ErrorAuthorityDenied},
		{"NOT_FOUND", OutcomeDenied, ErrorAuthorityNotFound},
		{"PRECONDITION_FAILED", OutcomeFailed, ErrorAuthorityPreconditionFailed},
	} {
		for name, add := range extras {
			t.Run(outcome.name+" with "+name, func(t *testing.T) {
				input := authorityFailureInput(outcome.outcome, outcome.errorCode)
				add(&input.Metadata)
				if err := authorityBuilds(t, input); err == nil {
					t.Fatal("failure event accepted a metadata field it never proved")
				}
			})
		}
	}
}

// TestAuthorityRevokeReasonCodesAreFixed proves each revoke action pins its own
// reason code, so the two revocations can never be confused in the trail.
func TestAuthorityRevokeReasonCodesAreFixed(t *testing.T) {
	t.Parallel()

	swapped := map[string]EventInput{
		"grant revoke claiming ACCESS_REVOKED": authorityRevokeSuccessInput(
			ActionWorkspaceSourceConfirmationGrantRevoked, authorityOperationGrantRevoke, authorityReasonAccessRevoked),
		"confirm revoke claiming AUTHORITY_REVOKED": authorityRevokeSuccessInput(
			ActionWorkspaceSourceConfirmationRevoked, authorityOperationConfirmRevoke, authorityReasonGrantRevoked),
	}
	for name, input := range swapped {
		t.Run(name, func(t *testing.T) {
			if err := authorityBuilds(t, input); err == nil {
				t.Fatal("revoke event accepted the other revocation's reason code")
			}
		})
	}
}

// TestAuthorityConfirmPinsItsAccessMode proves WORKSPACE_MANAGED is the only
// access mode a managed confirmation may record: the whole point of the
// operation is that this exact mode was chosen.
func TestAuthorityConfirmPinsItsAccessMode(t *testing.T) {
	t.Parallel()

	input := authorityConfirmSuccessInput()
	input.Metadata.AccessMode = ptr("SOURCE_NATIVE")
	if err := authorityBuilds(t, input); err == nil {
		t.Fatal("managed confirmation accepted a foreign access mode")
	}
}

// TestAuthorityVocabularyIsReservedToAuthorityEvents proves the reservation the
// database also enforces: a non-authority event may not carry authority
// metadata, whatever its action or resource type.
func TestAuthorityVocabularyIsReservedToAuthorityEvents(t *testing.T) {
	t.Parallel()

	workspace := authorityTestWorkspace
	actor := authorityTestActor
	revision := int64(4)
	scopeRevision := int64(1)
	enabled := true
	base := EventInput{
		EventID:          "aud_authority_0002",
		WorkspaceID:      &workspace,
		ActorType:        ActorHuman,
		ActorPrincipalID: &actor,
		Action:           ActionWorkspaceSourceAdded,
		ResourceType:     ResourceWorkspaceSource,
		ResourceID:       "wss_authority_0001",
		RequestID:        "req_authority_0002",
		Outcome:          OutcomeSuccess,
		Metadata: Metadata{
			WorkspaceRevision:   &revision,
			WorkspaceSourceID:   ptr("wss_authority_0001"),
			SourceScopeID:       ptr("scp_authority_0001"),
			SourceScopeRevision: &scopeRevision,
			ScopeConfigHash:     ptr(authorityTestHash),
			AccessMode:          ptr(authorityAccessMode),
			Enabled:             &enabled,
		},
		OccurredAt: authorityOccurredAt(),
	}
	if err := authorityBuilds(t, base); err != nil {
		t.Fatalf("the non-authority control event must be valid: %v", err)
	}

	reserved := map[string]func(*Metadata){
		"authority_operation":           func(m *Metadata) { m.AuthorityOperation = ptr(authorityOperationConfirm) },
		"authority_result_id":           func(m *Metadata) { m.AuthorityResultID = ptr("grant_authority_0001") },
		"authority_result_hash":         func(m *Metadata) { m.AuthorityResultHash = ptr(authorityTestHash) },
		"authority_parent_id":           func(m *Metadata) { m.AuthorityParentID = ptr("grant_authority_0001") },
		"authority_parent_hash":         func(m *Metadata) { m.AuthorityParentHash = ptr(authorityTestHash) },
		"authority_revocation_id":       func(m *Metadata) { m.AuthorityRevocationID = ptr("rev_authority_0001") },
		"authority_revocation_hash":     func(m *Metadata) { m.AuthorityRevocationHash = ptr(authorityTestHash) },
		"authority_reason_code":         func(m *Metadata) { m.AuthorityReasonCode = ptr(authorityReasonGrantRevoked) },
		"target_principal_id":           func(m *Metadata) { m.TargetPrincipalID = ptr("usr_authority_target") },
		"workspace_configuration_hash":  func(m *Metadata) { m.WorkspaceConfigurationHash = ptr(authorityTestHash) },
		"confirmation_actor_grant_id":   func(m *Metadata) { m.ConfirmationActorGrantID = ptr("grant_authority_0001") },
		"confirmation_actor_grant_hash": func(m *Metadata) { m.ConfirmationActorGrantHash = ptr(authorityTestHash) },
		"warning_version":               func(m *Metadata) { m.WarningVersion = ptr(authorityWarningVersion) },
		"warning_contract_hash":         func(m *Metadata) { m.WarningContractHash = ptr(authorityTestHash) },
		"acknowledgement_code":          func(m *Metadata) { m.AcknowledgementCode = ptr(authorityAcknowledgementCode) },
	}
	for name, add := range reserved {
		t.Run(name, func(t *testing.T) {
			input := base
			add(&input.Metadata)
			if err := authorityBuilds(t, input); err == nil {
				t.Fatalf("a non-authority event was allowed to carry %s", name)
			}
		})
	}

	t.Run("confirmation_actor_grant_revision", func(t *testing.T) {
		revision := int64(1)
		input := base
		input.Metadata.ConfirmationActorGrantRevision = &revision
		if err := authorityBuilds(t, input); err == nil {
			t.Fatal("a non-authority event was allowed to carry confirmation_actor_grant_revision")
		}
	})
}

// TestAuthorityActionInventoryIsClosed proves the inventories cannot drift apart
// from each other: every action has an operation, an exact SUCCESS metadata set
// and a registration in the shared validator.
func TestAuthorityActionInventoryIsClosed(t *testing.T) {
	t.Parallel()

	if len(authorityActionOperations) != 4 {
		t.Fatalf("the authority action inventory is not the four ADR-0053 operations: %v", authorityActionOperations)
	}
	seen := map[string]Action{}
	for action, operation := range authorityActionOperations {
		if !validAction(action) {
			t.Fatalf("action %q is not registered in the shared action registry", action)
		}
		if other, duplicate := seen[operation]; duplicate {
			t.Fatalf("operation %q maps to both %q and %q", operation, other, action)
		}
		seen[operation] = action
		fields, known := authoritySuccessMetadata[action]
		if !known || len(fields) == 0 {
			t.Fatalf("action %q has no exact SUCCESS metadata set", action)
		}
		if fields[0] != "authority_operation" {
			t.Fatalf("action %q does not pin its operation in metadata", action)
		}
	}
	if !validResource(ResourceWorkspaceAuthorityCommand) {
		t.Fatal("the authority resource type is not registered in the shared resource registry")
	}
}
