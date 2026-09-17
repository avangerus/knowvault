package repository

// The workspace-managed authority command runtime (ADR-0052/0053/0054). Each of
// the four operations runs one common decision phase before any terminal branch
// is chosen, in the ADR-0053 order: syntactic validation and canonicalization;
// the trusted tenant fence; opening database.Write under the trusted tenant;
// reservation of the actor-scoped receipt and its command_id; the workspace
// serialization row lock (FOR UPDATE), taken before the current actor is
// reloaded; reloading current identity and operation-specific visibility;
// authorization; and only then loading, locking and exact-matching every
// protected business projection. The read ordering is enforced by the decision
// functions in authority_policy.go, which take the protected projections —
// including the workspace revision/configuration and, for a revocation, the
// parent hash/revoked state — as lazy loaders and never consult one until
// visibility and authorization have resolved. The branch choice follows the
// decision; the decision never follows the branch.
//
// The success branch obtains one PostgreSQL transaction-second, derives every
// server-owned field, builds the canonical result JCS and its hash, inserts
// exactly one authority row, appends one content-free audit event and
// terminalizes the receipt SUCCESS — all in one transaction. A business failure
// appends one audit event and terminalizes the receipt, and creates no result
// ID, timestamp, JCS or authority row. Any infrastructure failure rolls the
// whole transaction back. Replay returns the stored result without re-entering
// the decision phase, a new authority row, a new receipt or a new audit event.

import (
	"context"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// authoritySuccess is the artifact set the success branch produces once the
// decision phase settles SUCCESS.
type authoritySuccess struct {
	resultID         string
	resultHash       string
	canonicalBytes   []byte
	metadata         audit.Metadata
	auditWorkspaceID string
}

type authorityDecider func(context.Context, database.Transaction, int64) (authorityTerminal, *string, *authoritySuccess, error)

type authorityReplayer func(context.Context, database.Transaction) (authorityTerminal, error)

type authorityPlan struct {
	operation    authorityOperation
	action       audit.Action
	keyHash      string
	commandID    string
	auditEventID string
	tenantMatch  bool
	receipt      authorityReceiptInsert
	decide       authorityDecider
	replay       authorityReplayer
}

func authorityFailureMetadata(operation authorityOperation) audit.Metadata {
	value := string(operation)
	return audit.Metadata{AuthorityOperation: &value}
}

func authorityAuditOutcome(terminal authorityTerminal) (audit.Outcome, *string) {
	switch terminal {
	case terminalSuccess:
		return audit.OutcomeSuccess, nil
	case terminalDenied:
		code := audit.ErrorAuthorityDenied
		return audit.OutcomeDenied, &code
	case terminalNotFound:
		code := audit.ErrorAuthorityNotFound
		return audit.OutcomeDenied, &code
	default:
		code := audit.ErrorAuthorityPreconditionFailed
		return audit.OutcomeFailed, &code
	}
}

// IssueConfirmationGrant executes WORKSPACE_CONFIRMATION_GRANT_ISSUE.
func (store *Store) IssueConfirmationGrant(ctx context.Context, access database.AccessContext, request IssueGrantRequest) (AuthorityResult, error) {
	payload, valid := request.validate()
	if !valid {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	requestBytes, requestHash, err := authorityRequestHash(operationConfirmationGrantIssue, payload)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	commandID, auditEventID, err := store.authorityIdentifiers()
	if err != nil {
		return AuthorityResult{}, err
	}
	receipt := authorityReceiptInsert{
		organizationID: access.OrganizationID, actorPrincipalID: access.PrincipalID, keyHash: keyHash,
		commandID: commandID, operation: operationConfirmationGrantIssue,
		canonicalBytes: requestBytes, canonicalHash: requestHash,
		requestOrganizationID: request.OrganizationID, requestWorkspaceID: request.WorkspaceID,
		requestExpectedPolicyRevision:      request.ExpectedPolicyRevision,
		expectedWorkspaceRevision:          request.ExpectedWorkspaceRevision,
		expectedWorkspaceConfigurationHash: request.ExpectedWorkspaceConfigurationHash,
		targetPrincipalID:                  request.TargetPrincipalID, ttlSeconds: request.TTLSeconds,
	}
	plan := authorityPlan{
		operation: operationConfirmationGrantIssue, action: audit.ActionWorkspaceSourceConfirmationGrantIssued,
		keyHash: keyHash, commandID: commandID, auditEventID: auditEventID,
		tenantMatch: request.OrganizationID == access.OrganizationID, receipt: receipt,
		decide: func(txctx context.Context, transaction database.Transaction, epoch int64) (authorityTerminal, *string, *authoritySuccess, error) {
			ws, actor, err := store.lockThenReload(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, nil, nil, err
			}
			var policyNumber int64
			var policyOpaque string
			business := issueBusiness{
				targetEligible: func() (bool, error) {
					return targetEligibleForGrant(txctx, transaction, access.OrganizationID, request.WorkspaceID, request.TargetPrincipalID)
				},
				revisionConfigCurrent: func() (bool, error) {
					currentRevision, configHash, exists, loadErr := loadWorkspaceRevisionConfig(txctx, transaction, access.OrganizationID, request.WorkspaceID)
					if loadErr != nil {
						return false, loadErr
					}
					return exists && currentRevision == request.ExpectedWorkspaceRevision &&
						configHash == request.ExpectedWorkspaceConfigurationHash, nil
				},
				policyCurrent: func() (bool, error) {
					number, opaque, exists, loadErr := loadAuthorityPolicy(txctx, transaction, access.OrganizationID)
					if loadErr != nil {
						return false, loadErr
					}
					policyNumber, policyOpaque = number, opaque
					return exists && opaque == request.ExpectedPolicyRevision, nil
				},
			}
			terminal, err := issueDecision(actor, ws, business)
			if err != nil {
				return 0, nil, nil, err
			}
			if terminal != terminalSuccess {
				return terminal, failureAuditWorkspace(terminal, request.WorkspaceID, actor.visible(ws, false)), nil, nil
			}
			grantID, err := store.generatedID("grant_")
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			grantedAt := authorityTimestamp(epoch)
			validUntil := authorityTimestamp(epoch + request.TTLSeconds)
			document := grantDocument{
				SchemaVersion: grantSchemaVersion, GrantID: grantID, Revision: 1,
				OrganizationID: access.OrganizationID, WorkspaceID: request.WorkspaceID,
				PrincipalID: request.TargetPrincipalID, Permission: authorityGrantPermission,
				ValidFrom: grantedAt, ValidUntil: validUntil, PolicyRevision: policyOpaque,
				GrantedBy: access.PrincipalID, GrantedAt: grantedAt,
			}
			canonicalBytes, canonicalHash, err := authorityCanonicalHash(document)
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			if _, err := transaction.Exec(txctx, `
				INSERT INTO public.workspace_source_confirmation_actor_grant (
					organization_id, grant_id, revision, workspace_id, principal_id, permission,
					valid_from, valid_until, policy_revision_number, policy_revision,
					grant_hash, granted_by, granted_at, command_id, canonical_bytes
				) VALUES ($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			`, access.OrganizationID, grantID, request.WorkspaceID, request.TargetPrincipalID, authorityGrantPermission,
				grantedAt, validUntil, policyNumber, policyOpaque, canonicalHash, access.PrincipalID, grantedAt,
				commandID, canonicalBytes); err != nil {
				return 0, nil, nil, err
			}
			operation := string(operationConfirmationGrantIssue)
			target := request.TargetPrincipalID
			opaque := policyOpaque
			metadata := audit.Metadata{
				AuthorityOperation: &operation, AuthorityResultID: &grantID, AuthorityResultHash: &canonicalHash,
				TargetPrincipalID: &target, PolicyRevision: &opaque,
			}
			return terminalSuccess, nil, &authoritySuccess{
				resultID: grantID, resultHash: canonicalHash, canonicalBytes: canonicalBytes,
				metadata: metadata, auditWorkspaceID: request.WorkspaceID,
			}, nil
		},
		replay: func(txctx context.Context, transaction database.Transaction) (authorityTerminal, error) {
			ws, actor, err := store.reloadForReplay(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, err
			}
			return issueReplayTerminal(actor, ws), nil
		},
	}
	return store.runAuthorityCommand(ctx, access, plan)
}

// RevokeConfirmationGrant executes WORKSPACE_CONFIRMATION_GRANT_REVOKE.
func (store *Store) RevokeConfirmationGrant(ctx context.Context, access database.AccessContext, request RevokeGrantRequest) (AuthorityResult, error) {
	payload, valid := request.validate()
	if !valid {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	requestBytes, requestHash, err := authorityRequestHash(operationConfirmationGrantRevoke, payload)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	commandID, auditEventID, err := store.authorityIdentifiers()
	if err != nil {
		return AuthorityResult{}, err
	}
	receipt := authorityReceiptInsert{
		organizationID: access.OrganizationID, actorPrincipalID: access.PrincipalID, keyHash: keyHash,
		commandID: commandID, operation: operationConfirmationGrantRevoke,
		canonicalBytes: requestBytes, canonicalHash: requestHash,
		requestOrganizationID: request.OrganizationID, requestWorkspaceID: request.WorkspaceID,
		requestExpectedPolicyRevision: request.ExpectedPolicyRevision,
		grantID:                       request.GrantID, grantRevision: request.GrantRevision, grantHash: request.GrantHash,
	}
	plan := authorityPlan{
		operation: operationConfirmationGrantRevoke, action: audit.ActionWorkspaceSourceConfirmationGrantRevoked,
		keyHash: keyHash, commandID: commandID, auditEventID: auditEventID,
		tenantMatch: request.OrganizationID == access.OrganizationID, receipt: receipt,
		decide: func(txctx context.Context, transaction database.Transaction, epoch int64) (authorityTerminal, *string, *authoritySuccess, error) {
			ws, actor, err := store.lockThenReload(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, nil, nil, err
			}
			identity, err := loadParentGrantIdentity(txctx, transaction, access.OrganizationID, request.GrantID, request.GrantRevision)
			if err != nil {
				return 0, nil, nil, err
			}
			self := identity.exists && identity.workspaceID == request.WorkspaceID && identity.self == access.PrincipalID
			parentExists := identity.exists && identity.workspaceID == request.WorkspaceID
			var policyNumber int64
			var policyOpaque string
			business := grantRevokeBusiness{
				parentBusiness: func() (parentBusiness, error) {
					return loadParentGrantBusiness(txctx, transaction, access.OrganizationID, request.GrantID, request.GrantRevision, request.GrantHash)
				},
				policyCurrent: func() (bool, error) {
					number, opaque, exists, loadErr := loadAuthorityPolicy(txctx, transaction, access.OrganizationID)
					if loadErr != nil {
						return false, loadErr
					}
					policyNumber, policyOpaque = number, opaque
					return exists && opaque == request.ExpectedPolicyRevision, nil
				},
			}
			terminal, err := grantRevokeDecision(actor, ws, self, parentExists, business)
			if err != nil {
				return 0, nil, nil, err
			}
			if terminal != terminalSuccess {
				return terminal, failureAuditWorkspace(terminal, request.WorkspaceID, actor.visible(ws, self)), nil, nil
			}
			revocationID, err := store.generatedID("wsgrv_")
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			revokedAt := authorityTimestamp(epoch)
			document := grantRevocationDocument{
				SchemaVersion: grantRevocationSchemaVersion, RevocationID: revocationID,
				OrganizationID: access.OrganizationID, GrantID: request.GrantID, GrantRevision: request.GrantRevision,
				GrantHash: request.GrantHash, RevokedBy: access.PrincipalID, RevokedAt: revokedAt,
				ReasonCode: authorityReasonGrantRevoked, PolicyRevision: policyOpaque,
			}
			canonicalBytes, canonicalHash, err := authorityCanonicalHash(document)
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			if _, err := transaction.Exec(txctx, `
				INSERT INTO public.workspace_source_confirmation_actor_grant_revocation (
					organization_id, revocation_id, confirmation_actor_grant_revocation_hash,
					grant_id, grant_revision, grant_hash, revoked_by, revoked_at, reason_code,
					policy_revision_number, policy_revision, command_id, canonical_bytes
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			`, access.OrganizationID, revocationID, canonicalHash, request.GrantID, request.GrantRevision, request.GrantHash,
				access.PrincipalID, revokedAt, authorityReasonGrantRevoked, policyNumber, policyOpaque, commandID, canonicalBytes); err != nil {
				return 0, nil, nil, err
			}
			metadata := authorityRevocationMetadata(operationConfirmationGrantRevoke, request.GrantID, request.GrantHash,
				revocationID, canonicalHash, authorityReasonGrantRevoked, policyOpaque)
			return terminalSuccess, nil, &authoritySuccess{
				resultID: revocationID, resultHash: canonicalHash, canonicalBytes: canonicalBytes,
				metadata: metadata, auditWorkspaceID: request.WorkspaceID,
			}, nil
		},
		replay: func(txctx context.Context, transaction database.Transaction) (authorityTerminal, error) {
			ws, actor, err := store.reloadForReplay(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, err
			}
			identity, err := loadParentGrantIdentity(txctx, transaction, access.OrganizationID, request.GrantID, request.GrantRevision)
			if err != nil {
				return 0, err
			}
			self := identity.exists && identity.workspaceID == request.WorkspaceID && identity.self == access.PrincipalID
			return grantRevokeReplayTerminal(actor, ws, self), nil
		},
	}
	return store.runAuthorityCommand(ctx, access, plan)
}

// ConfirmManagedSource executes WORKSPACE_MANAGED_CONFIRM.
func (store *Store) ConfirmManagedSource(ctx context.Context, access database.AccessContext, request ConfirmRequest) (AuthorityResult, error) {
	payload, valid := request.validate()
	if !valid {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	requestBytes, requestHash, err := authorityRequestHash(operationManagedConfirm, payload)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	commandID, auditEventID, err := store.authorityIdentifiers()
	if err != nil {
		return AuthorityResult{}, err
	}
	receipt := authorityReceiptInsert{
		organizationID: access.OrganizationID, actorPrincipalID: access.PrincipalID, keyHash: keyHash,
		commandID: commandID, operation: operationManagedConfirm,
		canonicalBytes: requestBytes, canonicalHash: requestHash,
		requestOrganizationID: request.OrganizationID, requestWorkspaceID: request.WorkspaceID,
		requestExpectedPolicyRevision: request.ExpectedPolicyRevision,
		workspaceRevision:             request.WorkspaceRevision,
		workspaceConfigurationHash:    request.WorkspaceConfigurationHash,
		workspaceSourceID:             request.WorkspaceSourceID, sourceScopeID: request.SourceScopeID,
		sourceScopeRevision: request.SourceScopeRevision, scopeConfigHash: request.ScopeConfigHash,
		accessMode:                     request.AccessMode,
		confirmationActorGrantID:       request.ConfirmationActorGrantID,
		confirmationActorGrantRevision: request.ConfirmationActorGrantRevision,
		confirmationActorGrantHash:     request.ConfirmationActorGrantHash,
		warningVersion:                 request.WarningVersion, warningContractHash: request.WarningContractHash,
		acknowledgementCode: request.AcknowledgementCode,
	}
	plan := authorityPlan{
		operation: operationManagedConfirm, action: audit.ActionWorkspaceSourceConfirmed,
		keyHash: keyHash, commandID: commandID, auditEventID: auditEventID,
		tenantMatch: request.OrganizationID == access.OrganizationID, receipt: receipt,
		decide: func(txctx context.Context, transaction database.Transaction, epoch int64) (authorityTerminal, *string, *authoritySuccess, error) {
			ws, actor, err := store.lockThenReload(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, nil, nil, err
			}
			var policyLoaded, policyExists bool
			var policyNumber int64
			var policyOpaque string
			loadPolicyOnce := func() error {
				if policyLoaded {
					return nil
				}
				number, opaque, exists, loadErr := loadAuthorityPolicy(txctx, transaction, access.OrganizationID)
				if loadErr != nil {
					return loadErr
				}
				policyNumber, policyOpaque, policyExists, policyLoaded = number, opaque, exists, true
				return nil
			}
			business := confirmBusiness{
				revisionConfigCurrent: func() (bool, error) {
					currentRevision, configHash, exists, loadErr := loadWorkspaceRevisionConfig(txctx, transaction, access.OrganizationID, request.WorkspaceID)
					if loadErr != nil {
						return false, loadErr
					}
					return exists && currentRevision == request.WorkspaceRevision &&
						configHash == request.WorkspaceConfigurationHash, nil
				},
				bindingCurrent: func() (bool, error) {
					return confirmBindingCurrent(txctx, transaction, access.OrganizationID, request)
				},
				actorGrant: func() (actorGrantEvaluation, error) {
					if policyErr := loadPolicyOnce(); policyErr != nil {
						return actorGrantEvaluation{}, policyErr
					}
					grant, grantErr := loadActorGrant(txctx, transaction, access.OrganizationID, request.ConfirmationActorGrantID, request.ConfirmationActorGrantRevision)
					if grantErr != nil {
						return actorGrantEvaluation{}, grantErr
					}
					held := grant.exists && grant.principalID == access.PrincipalID && grant.workspaceID == request.WorkspaceID
					live := grant.permission == authorityGrantPermission && !grant.revoked && policyExists &&
						grant.policyRevision == policyOpaque && grant.validFromEpoch <= epoch && epoch < grant.validUntilEpoch
					return actorGrantEvaluation{held: held, live: live, hashMatches: grant.grantHash == request.ConfirmationActorGrantHash}, nil
				},
				verifierConflict: func() (bool, error) {
					return confirmVerifierConflict(txctx, transaction, access.OrganizationID, access.PrincipalID, request.SourceScopeID)
				},
				policyCurrent: func() (bool, error) {
					if policyErr := loadPolicyOnce(); policyErr != nil {
						return false, policyErr
					}
					return policyExists && policyOpaque == request.ExpectedPolicyRevision, nil
				},
				warningCurrent: func() (bool, error) {
					head, exists, loadErr := loadWarningHead(txctx, transaction)
					if loadErr != nil {
						return false, loadErr
					}
					return exists && head == request.WarningContractHash, nil
				},
				liveConfirmationExists: func() (bool, error) {
					if policyErr := loadPolicyOnce(); policyErr != nil {
						return false, policyErr
					}
					return confirmLiveConfirmationExists(txctx, transaction, access.OrganizationID, request, policyNumber, policyOpaque)
				},
			}
			terminal, err := confirmDecision(actor, ws, business)
			if err != nil {
				return 0, nil, nil, err
			}
			if terminal != terminalSuccess {
				return terminal, failureAuditWorkspace(terminal, request.WorkspaceID, actor.visible(ws, false)), nil, nil
			}
			confirmationID, err := store.generatedID("wmc_")
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			confirmedAt := authorityTimestamp(epoch)
			document := confirmationDocument{
				SchemaVersion: confirmationSchemaVersion, ConfirmationID: confirmationID,
				OrganizationID: access.OrganizationID, WorkspaceID: request.WorkspaceID,
				WorkspaceRevision: request.WorkspaceRevision, WorkspaceConfigurationHash: request.WorkspaceConfigurationHash,
				WorkspaceSourceID: request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
				SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
				AccessMode: authorityAccessModeManaged, ConfirmationActorGrantID: request.ConfirmationActorGrantID,
				ConfirmationActorGrantRevision: request.ConfirmationActorGrantRevision,
				ConfirmationActorGrantHash:     request.ConfirmationActorGrantHash,
				WarningVersion:                 authorityWarningVersion, WarningContractHash: request.WarningContractHash,
				AcknowledgementCode: authorityAcknowledgementCode, ConfirmedBy: access.PrincipalID,
				ConfirmedAt: confirmedAt, PolicyRevision: policyOpaque,
			}
			canonicalBytes, canonicalHash, err := authorityCanonicalHash(document)
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			if _, err := transaction.Exec(txctx, `
				INSERT INTO public.workspace_managed_grant_confirmation (
					organization_id, confirmation_id, confirmation_hash, workspace_id,
					workspace_revision, workspace_configuration_hash, workspace_source_id,
					source_scope_id, source_scope_revision, scope_config_hash, access_mode,
					confirmation_actor_grant_id, confirmation_actor_grant_revision,
					confirmation_actor_grant_hash, warning_version, warning_contract_hash,
					acknowledgement_code, confirmed_by, confirmed_at,
					policy_revision_number, policy_revision, command_id, canonical_bytes
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)
			`, access.OrganizationID, confirmationID, canonicalHash, request.WorkspaceID,
				request.WorkspaceRevision, request.WorkspaceConfigurationHash, request.WorkspaceSourceID,
				request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, authorityAccessModeManaged,
				request.ConfirmationActorGrantID, request.ConfirmationActorGrantRevision, request.ConfirmationActorGrantHash,
				authorityWarningVersion, request.WarningContractHash, authorityAcknowledgementCode, access.PrincipalID,
				confirmedAt, policyNumber, policyOpaque, commandID, canonicalBytes); err != nil {
				return 0, nil, nil, err
			}
			metadata := confirmSuccessMetadata(request, confirmationID, canonicalHash, policyOpaque)
			return terminalSuccess, nil, &authoritySuccess{
				resultID: confirmationID, resultHash: canonicalHash, canonicalBytes: canonicalBytes,
				metadata: metadata, auditWorkspaceID: request.WorkspaceID,
			}, nil
		},
		replay: func(txctx context.Context, transaction database.Transaction) (authorityTerminal, error) {
			ws, actor, err := store.reloadForReplay(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, err
			}
			return confirmReplayTerminal(actor, ws), nil
		},
	}
	return store.runAuthorityCommand(ctx, access, plan)
}

// RevokeManagedConfirmation executes WORKSPACE_MANAGED_CONFIRM_REVOKE.
func (store *Store) RevokeManagedConfirmation(ctx context.Context, access database.AccessContext, request RevokeConfirmationRequest) (AuthorityResult, error) {
	payload, valid := request.validate()
	if !valid {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	requestBytes, requestHash, err := authorityRequestHash(operationManagedConfirmRevoke, payload)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	commandID, auditEventID, err := store.authorityIdentifiers()
	if err != nil {
		return AuthorityResult{}, err
	}
	receipt := authorityReceiptInsert{
		organizationID: access.OrganizationID, actorPrincipalID: access.PrincipalID, keyHash: keyHash,
		commandID: commandID, operation: operationManagedConfirmRevoke,
		canonicalBytes: requestBytes, canonicalHash: requestHash,
		requestOrganizationID: request.OrganizationID, requestWorkspaceID: request.WorkspaceID,
		requestExpectedPolicyRevision: request.ExpectedPolicyRevision,
		confirmationID:                request.ConfirmationID, confirmationHash: request.ConfirmationHash,
	}
	plan := authorityPlan{
		operation: operationManagedConfirmRevoke, action: audit.ActionWorkspaceSourceConfirmationRevoked,
		keyHash: keyHash, commandID: commandID, auditEventID: auditEventID,
		tenantMatch: request.OrganizationID == access.OrganizationID, receipt: receipt,
		decide: func(txctx context.Context, transaction database.Transaction, epoch int64) (authorityTerminal, *string, *authoritySuccess, error) {
			ws, actor, err := store.lockThenReload(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, nil, nil, err
			}
			identity, err := loadParentConfirmationIdentity(txctx, transaction, access.OrganizationID, request.ConfirmationID)
			if err != nil {
				return 0, nil, nil, err
			}
			self := identity.exists && identity.workspaceID == request.WorkspaceID && identity.self == access.PrincipalID
			parentExists := identity.exists && identity.workspaceID == request.WorkspaceID
			var policyNumber int64
			var policyOpaque string
			business := confirmRevokeBusiness{
				parentBusiness: func() (parentBusiness, error) {
					return loadParentConfirmationBusiness(txctx, transaction, access.OrganizationID, request.ConfirmationID, request.ConfirmationHash)
				},
				policyCurrent: func() (bool, error) {
					number, opaque, exists, loadErr := loadAuthorityPolicy(txctx, transaction, access.OrganizationID)
					if loadErr != nil {
						return false, loadErr
					}
					policyNumber, policyOpaque = number, opaque
					return exists && opaque == request.ExpectedPolicyRevision, nil
				},
			}
			terminal, err := confirmRevokeDecision(actor, ws, self, parentExists, business)
			if err != nil {
				return 0, nil, nil, err
			}
			if terminal != terminalSuccess {
				return terminal, failureAuditWorkspace(terminal, request.WorkspaceID, actor.visible(ws, self)), nil, nil
			}
			revocationID, err := store.generatedID("wmr_")
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			revokedAt := authorityTimestamp(epoch)
			document := confirmationRevocationDocument{
				SchemaVersion: confirmationRevocationSchemaVers, RevocationID: revocationID,
				OrganizationID: access.OrganizationID, ConfirmationID: request.ConfirmationID,
				ConfirmationHash: request.ConfirmationHash, RevokedBy: access.PrincipalID, RevokedAt: revokedAt,
				ReasonCode: authorityReasonAccessRevoked, PolicyRevision: policyOpaque,
			}
			canonicalBytes, canonicalHash, err := authorityCanonicalHash(document)
			if err != nil {
				return 0, nil, nil, &Error{code: CodeAuthorityPersistence, cause: err}
			}
			if _, err := transaction.Exec(txctx, `
				INSERT INTO public.workspace_managed_grant_revocation (
					organization_id, revocation_id, workspace_managed_confirmation_revocation_hash,
					confirmation_id, confirmation_hash, revoked_by, revoked_at, reason_code,
					policy_revision_number, policy_revision, command_id, canonical_bytes
				) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			`, access.OrganizationID, revocationID, canonicalHash, request.ConfirmationID, request.ConfirmationHash,
				access.PrincipalID, revokedAt, authorityReasonAccessRevoked, policyNumber, policyOpaque, commandID, canonicalBytes); err != nil {
				return 0, nil, nil, err
			}
			metadata := authorityRevocationMetadata(operationManagedConfirmRevoke, request.ConfirmationID, request.ConfirmationHash,
				revocationID, canonicalHash, authorityReasonAccessRevoked, policyOpaque)
			return terminalSuccess, nil, &authoritySuccess{
				resultID: revocationID, resultHash: canonicalHash, canonicalBytes: canonicalBytes,
				metadata: metadata, auditWorkspaceID: request.WorkspaceID,
			}, nil
		},
		replay: func(txctx context.Context, transaction database.Transaction) (authorityTerminal, error) {
			ws, actor, err := store.reloadForReplay(txctx, transaction, access, request.WorkspaceID)
			if err != nil {
				return 0, err
			}
			identity, err := loadParentConfirmationIdentity(txctx, transaction, access.OrganizationID, request.ConfirmationID)
			if err != nil {
				return 0, err
			}
			self := identity.exists && identity.workspaceID == request.WorkspaceID && identity.self == access.PrincipalID
			return confirmRevokeReplayTerminal(actor, ws, self), nil
		},
	}
	return store.runAuthorityCommand(ctx, access, plan)
}

// lockThenReload takes the workspace serialization lock (FOR UPDATE) and only
// then reloads the current actor, in the ADR-0053 order. The ordering is proved
// by a real lock-contention test (TestAuthorityRuntimeWorkspaceLockPrecedesActorReload):
// while the actor reload blocks on a held organization row, the workspace lock
// is already held. There is no runtime observability hook.
func (store *Store) lockThenReload(ctx context.Context, transaction database.Transaction, access database.AccessContext, workspaceID string) (authorityWorkspace, authorityActor, error) {
	ws, err := lockWorkspaceVisibility(ctx, transaction, access.OrganizationID, workspaceID, access.PrincipalID, true)
	if err != nil {
		return authorityWorkspace{}, authorityActor{}, err
	}
	actor, err := store.authorityCurrentActor(ctx, transaction, access, true)
	if err != nil {
		return authorityWorkspace{}, authorityActor{}, err
	}
	return ws, actor, nil
}

// reloadForReplay is the read-only counterpart used by replay: it re-verifies
// identity and visibility without taking the serialization lock, because replay
// never mutates.
func (store *Store) reloadForReplay(ctx context.Context, transaction database.Transaction, access database.AccessContext, workspaceID string) (authorityWorkspace, authorityActor, error) {
	ws, err := lockWorkspaceVisibility(ctx, transaction, access.OrganizationID, workspaceID, access.PrincipalID, false)
	if err != nil {
		return authorityWorkspace{}, authorityActor{}, err
	}
	actor, err := store.authorityCurrentActor(ctx, transaction, access, false)
	if err != nil {
		return authorityWorkspace{}, authorityActor{}, err
	}
	return ws, actor, nil
}

// runAuthorityCommand is the one shared receipt lifecycle. The trusted tenant
// fence is evaluated before the reserve, so a cross-tenant reference is always
// NOT_FOUND and a reused idempotency key never turns it into an idempotency
// conflict or an existence oracle for a receipt of another command.
func (store *Store) runAuthorityCommand(ctx context.Context, access database.AccessContext, plan authorityPlan) (AuthorityResult, error) {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil || access.Validate() != nil {
		return AuthorityResult{}, &Error{code: CodeAuthorityRequestInvalid}
	}
	var result AuthorityResult
	var terminalCode ErrorCode
	err := store.database.Write(ctx, access, func(txctx context.Context, transaction database.Transaction) error {
		if !plan.tenantMatch {
			code, tenantErr := store.terminateTenantMismatch(txctx, transaction, access, plan)
			terminalCode = code
			return tenantErr
		}

		reservation, reserveErr := reserveAuthorityCommand(txctx, transaction, plan.receipt)
		if reserveErr != nil {
			return reserveErr
		}
		if !reservation.created {
			replayTerminal, replayErr := plan.replay(txctx, transaction)
			if replayErr != nil {
				return replayErr
			}
			if replayTerminal != terminalSuccess {
				terminalCode = replayTerminal.code()
				return nil
			}
			if reservation.status != receiptSuccess {
				terminalCode = receiptStatusCode(reservation.status)
				return nil
			}
			canonical, loadErr := loadAuthorityResultBytes(txctx, transaction, access.OrganizationID, reservation.commandID, plan.operation)
			if loadErr != nil {
				return loadErr
			}
			result = AuthorityResult{
				CommandID: reservation.commandID, Operation: string(plan.operation),
				ResultID: reservation.resultID, ResultHash: reservation.resultHash, CanonicalBytes: canonical,
			}
			return nil
		}

		epoch, epochErr := authorityTransactionEpoch(txctx, transaction)
		if epochErr != nil {
			return epochErr
		}
		terminal, failureWorkspaceID, success, decideErr := plan.decide(txctx, transaction, epoch)
		if decideErr != nil {
			return decideErr
		}
		outcome, errorCode := authorityAuditOutcome(terminal)
		var auditWorkspaceID *string
		var metadata audit.Metadata
		var resultID, resultHash string
		if terminal == terminalSuccess {
			auditWorkspaceID = &success.auditWorkspaceID
			metadata = success.metadata
			resultID, resultHash = success.resultID, success.resultHash
		} else {
			auditWorkspaceID = failureWorkspaceID
			metadata = authorityFailureMetadata(plan.operation)
		}
		if appendErr := store.appendAuthorityAudit(txctx, transaction, access, plan.action, plan.commandID, plan.auditEventID, auditWorkspaceID, outcome, errorCode, metadata); appendErr != nil {
			return appendErr
		}
		if terminalizeErr := terminalizeAuthorityCommand(txctx, transaction, access.OrganizationID, access.PrincipalID, plan.keyHash, receiptStatusForTerminal(terminal), resultID, resultHash, plan.auditEventID); terminalizeErr != nil {
			return terminalizeErr
		}
		if terminal == terminalSuccess {
			result = AuthorityResult{
				CommandID: plan.commandID, Operation: string(plan.operation),
				ResultID: resultID, ResultHash: resultHash, CanonicalBytes: success.canonicalBytes,
			}
		} else {
			terminalCode = terminal.code()
		}
		return nil
	})
	if err != nil {
		if isCommandResultError(err) {
			return AuthorityResult{}, err
		}
		return AuthorityResult{}, &Error{code: CodeAuthorityPersistence, cause: err}
	}
	if terminalCode != "" {
		return AuthorityResult{}, &Error{code: terminalCode}
	}
	return result, nil
}

// terminateTenantMismatch handles a request whose organization does not match
// the trusted AccessContext. It never runs a workspace, target, grant,
// confirmation, binding, policy or warning lookup. A first-time cross-tenant
// command reserves a trusted-tenant receipt and terminalizes it NOT_FOUND with
// one content-free audit event. A reused idempotency key — whether it conflicts
// with, or replays, another command — returns NOT_FOUND without a new receipt or
// audit event and without revealing that any receipt exists.
func (store *Store) terminateTenantMismatch(ctx context.Context, transaction database.Transaction, access database.AccessContext, plan authorityPlan) (ErrorCode, error) {
	reservation, reserveErr := reserveAuthorityCommand(ctx, transaction, plan.receipt)
	if reserveErr != nil {
		if isAuthorityConflict(reserveErr) {
			// The key belongs to a different command. Do not surface a conflict,
			// which would reveal that a receipt exists for this actor and key.
			return CodeAuthorityNotFound, nil
		}
		return "", reserveErr
	}
	if !reservation.created {
		// The key already resolves a receipt (a replay of this same cross-tenant
		// command, which itself terminated NOT_FOUND). Return NOT_FOUND without a
		// new receipt or audit event.
		return CodeAuthorityNotFound, nil
	}
	if appendErr := store.appendAuthorityAudit(ctx, transaction, access, plan.action, plan.commandID, plan.auditEventID, nil, audit.OutcomeDenied, ptrAuthorityCode(audit.ErrorAuthorityNotFound), authorityFailureMetadata(plan.operation)); appendErr != nil {
		return "", appendErr
	}
	if terminalizeErr := terminalizeAuthorityCommand(ctx, transaction, access.OrganizationID, access.PrincipalID, plan.keyHash, receiptNotFound, "", "", plan.auditEventID); terminalizeErr != nil {
		return "", terminalizeErr
	}
	return CodeAuthorityNotFound, nil
}

func ptrAuthorityCode(code string) *string { return &code }

func isAuthorityConflict(err error) bool {
	return CodeOf(err) == CodeAuthorityIdempotencyConflict
}

func (store *Store) appendAuthorityAudit(ctx context.Context, transaction database.Transaction, access database.AccessContext, action audit.Action, commandID, eventID string, workspaceID *string, outcome audit.Outcome, errorCode *string, metadata audit.Metadata) error {
	actorID := access.PrincipalID
	_, err := store.audit.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: eventID, WorkspaceID: workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: action, ResourceType: audit.ResourceWorkspaceAuthorityCommand, ResourceID: commandID,
		RequestID: access.RequestID, Outcome: outcome, ErrorCode: errorCode, Metadata: metadata, OccurredAt: store.now().UTC(),
	})
	return err
}

func (store *Store) authorityCurrentActor(ctx context.Context, transaction database.Transaction, access database.AccessContext, lock bool) (authorityActor, error) {
	subject, organization, found, err := currentActor(ctx, transaction, access, lock)
	if err != nil {
		return authorityActor{}, err
	}
	if !found {
		return authorityActor{}, nil
	}
	return authorityActorFromSubject(subject, organization), nil
}

func (store *Store) authorityIdentifiers() (string, string, error) {
	commandID, err := store.generatedID("cmd_")
	if err != nil {
		return "", "", &Error{code: CodeAuthorityPersistence, cause: err}
	}
	auditEventID, err := store.generatedID("aud_")
	if err != nil {
		return "", "", &Error{code: CodeAuthorityPersistence, cause: err}
	}
	return commandID, auditEventID, nil
}

func authorityRevocationMetadata(operation authorityOperation, parentID, parentHash, revocationID, revocationHash, reasonCode, policyRevision string) audit.Metadata {
	op := string(operation)
	return audit.Metadata{
		AuthorityOperation: &op, AuthorityParentID: &parentID, AuthorityParentHash: &parentHash,
		AuthorityRevocationID: &revocationID, AuthorityRevocationHash: &revocationHash,
		AuthorityReasonCode: &reasonCode, PolicyRevision: &policyRevision,
	}
}

func confirmSuccessMetadata(request ConfirmRequest, confirmationID, confirmationHash, policyRevision string) audit.Metadata {
	op := string(operationManagedConfirm)
	workspaceRevision := request.WorkspaceRevision
	sourceScopeRevision := request.SourceScopeRevision
	grantRevision := request.ConfirmationActorGrantRevision
	accessMode := authorityAccessModeManaged
	warningVersion := authorityWarningVersion
	acknowledgementCode := authorityAcknowledgementCode
	return audit.Metadata{
		AuthorityOperation: &op, AuthorityResultID: &confirmationID, AuthorityResultHash: &confirmationHash,
		WorkspaceRevision: &workspaceRevision, WorkspaceConfigurationHash: &request.WorkspaceConfigurationHash,
		WorkspaceSourceID: &request.WorkspaceSourceID, SourceScopeID: &request.SourceScopeID,
		SourceScopeRevision: &sourceScopeRevision, ScopeConfigHash: &request.ScopeConfigHash,
		AccessMode: &accessMode, ConfirmationActorGrantID: &request.ConfirmationActorGrantID,
		ConfirmationActorGrantRevision: &grantRevision, ConfirmationActorGrantHash: &request.ConfirmationActorGrantHash,
		WarningVersion: &warningVersion, WarningContractHash: &request.WarningContractHash,
		AcknowledgementCode: &acknowledgementCode, PolicyRevision: &policyRevision,
	}
}

func receiptStatusCode(status receiptStatus) ErrorCode {
	switch status {
	case receiptDenied:
		return CodeAuthorityDenied
	case receiptNotFound:
		return CodeAuthorityNotFound
	case receiptPreconditionFailed:
		return CodeAuthorityPreconditionFailed
	default:
		return CodeAuthorityPersistence
	}
}
