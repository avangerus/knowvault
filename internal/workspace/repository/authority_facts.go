package repository

// Fact loaders for the authority decision phase. Each resolves one current
// projection and returns plain values; the pure matrix in authority_policy.go
// turns those into a terminal. No loader here trusts request.organization_id:
// the caller passes only the trusted AccessContext.OrganizationID.
//
// The loaders are split to make the ADR-0053 read ordering enforceable. The
// minimal visibility facts (existence, lifecycle status, the actor's membership
// role) are separated from the protected revision/configuration projection, and
// a revocation parent's identity (existence, workspace, self principal) is
// separated from its business facts (hash, revoked state). The runtime reads
// only the visibility facts and the parent identity before authorization, and
// the protected projections only after it.

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

func authorityActorFromSubject(subject policy.Subject, organization policy.Organization) authorityActor {
	orgOwnerOrAdmin := false
	for _, role := range subject.OrganizationRoles {
		if role == policy.OrganizationOwner || role == policy.OrganizationAdmin {
			orgOwnerOrAdmin = true
			break
		}
	}
	return authorityActor{
		organizationActive: organization.Status == policy.OrganizationActive,
		principalActive:    subject.Status == policy.PrincipalActive,
		orgOwnerOrAdmin:    orgOwnerOrAdmin,
	}
}

// lockWorkspaceVisibility takes the workspace serialization row lock (FOR
// UPDATE) and returns only the minimal facts visibility and authorization need:
// existence, lifecycle status and the actor's current membership role. It
// deliberately does NOT read the workspace revision or configuration hash —
// those are protected projections loaded later, only after authorization.
func lockWorkspaceVisibility(ctx context.Context, transaction database.Transaction, organizationID, workspaceID, principalID string, lock bool) (authorityWorkspace, error) {
	var result authorityWorkspace
	var statusText string
	query := `SELECT status FROM public.workspace WHERE organization_id = $1 AND id = $2`
	if lock {
		query += " FOR UPDATE"
	}
	err := transaction.QueryRow(ctx, query, organizationID, workspaceID).Scan(&statusText)
	if database.IsNotFound(err) {
		return authorityWorkspace{exists: false}, nil
	}
	if err != nil {
		return authorityWorkspace{}, err
	}
	result.exists = true
	result.status = workspace.Status(statusText)

	var role string
	err = transaction.QueryRow(ctx, `
		SELECT role
		FROM public.workspace_member
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, organizationID, workspaceID, principalID).Scan(&role)
	if err == nil {
		result.membershipPresent = true
		result.membershipRole = workspace.Role(role)
	} else if !database.IsNotFound(err) {
		return authorityWorkspace{}, err
	}
	return result, nil
}

// loadWorkspaceRevisionConfig reads the protected current revision and
// configuration hash of the already-locked workspace. It runs only after
// authorization, so an unauthorized or invisible actor never triggers it.
func loadWorkspaceRevisionConfig(ctx context.Context, transaction database.Transaction, organizationID, workspaceID string) (int64, string, bool, error) {
	var currentRevision int64
	var configHash string
	err := transaction.QueryRow(ctx, `
		SELECT workspace.current_revision, revision.configuration_hash
		FROM public.workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		WHERE workspace.organization_id = $1 AND workspace.id = $2
	`, organizationID, workspaceID).Scan(&currentRevision, &configHash)
	if database.IsNotFound(err) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return currentRevision, configHash, true, nil
}

// loadAuthorityPolicy returns the organization's current policy ordinal and its
// opaque policy_revision_id, locking the organization row FOR SHARE so a
// concurrent advance blocks until this command commits — the same row the
// deferred commit-time gate re-locks.
func loadAuthorityPolicy(ctx context.Context, transaction database.Transaction, organizationID string) (int64, string, bool, error) {
	var number int64
	var opaque string
	err := transaction.QueryRow(ctx, `
		SELECT organization.policy_revision, registry.policy_revision_id
		FROM public.organization AS organization
		JOIN public.organization_policy_revision AS registry
		  ON registry.organization_id = organization.id
		 AND registry.revision = organization.policy_revision
		WHERE organization.id = $1
		FOR SHARE OF organization
	`, organizationID).Scan(&number, &opaque)
	if database.IsNotFound(err) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	return number, opaque, true, nil
}

// loadWarningHead returns the current warning-contract head hash. The registry
// is global and append-only; the head is max(revision).
func loadWarningHead(ctx context.Context, transaction database.Transaction) (string, bool, error) {
	var hash string
	err := transaction.QueryRow(ctx, `
		SELECT warning_contract_hash
		FROM public.workspace_managed_warning_contract
		WHERE revision = (SELECT max(revision) FROM public.workspace_managed_warning_contract)
	`).Scan(&hash)
	if database.IsNotFound(err) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return hash, true, nil
}

// targetEligibleForGrant reports whether the grant target is an exact active
// HUMAN (USER) principal that is currently an effective Workspace OWNER or
// MANAGER. A group, service or non-member principal is not eligible.
func targetEligibleForGrant(ctx context.Context, transaction database.Transaction, organizationID, workspaceID, targetPrincipalID string) (bool, error) {
	var principalType, principalStatus string
	err := transaction.QueryRow(ctx, `
		SELECT type, status FROM public.principal
		WHERE organization_id = $1 AND id = $2
		FOR SHARE
	`, organizationID, targetPrincipalID).Scan(&principalType, &principalStatus)
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if principalType != "USER" || principalStatus != string(policy.PrincipalActive) {
		return false, nil
	}
	var role string
	err = transaction.QueryRow(ctx, `
		SELECT role FROM public.workspace_member
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
	`, organizationID, workspaceID, targetPrincipalID).Scan(&role)
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return role == string(workspace.RoleOwner) || role == string(workspace.RoleManager), nil
}

// actorGrantFacts is the confirm command's live actor-grant projection.
type actorGrantFacts struct {
	exists          bool
	principalID     string
	workspaceID     string
	grantHash       string
	permission      string
	policyRevision  string
	validFromEpoch  int64
	validUntilEpoch int64
	revoked         bool
}

func loadActorGrant(ctx context.Context, transaction database.Transaction, organizationID, grantID string, grantRevision int64) (actorGrantFacts, error) {
	var facts actorGrantFacts
	err := transaction.QueryRow(ctx, `
		SELECT grant_row.principal_id, grant_row.workspace_id, grant_row.grant_hash,
		       grant_row.permission, grant_row.policy_revision,
		       app.authority_timestamp_v1_to_epoch(grant_row.valid_from),
		       app.authority_timestamp_v1_to_epoch(grant_row.valid_until),
		       EXISTS (
		           SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS revocation
		           WHERE revocation.organization_id = grant_row.organization_id
		             AND revocation.grant_id = grant_row.grant_id
		             AND revocation.grant_revision = grant_row.revision
		       )
		FROM public.workspace_source_confirmation_actor_grant AS grant_row
		WHERE grant_row.organization_id = $1 AND grant_row.grant_id = $2 AND grant_row.revision = $3
	`, organizationID, grantID, grantRevision).Scan(
		&facts.principalID, &facts.workspaceID, &facts.grantHash, &facts.permission,
		&facts.policyRevision, &facts.validFromEpoch, &facts.validUntilEpoch, &facts.revoked)
	if database.IsNotFound(err) {
		return actorGrantFacts{exists: false}, nil
	}
	if err != nil {
		return actorGrantFacts{}, err
	}
	facts.exists = true
	return facts, nil
}

// parentIdentity is the minimal projection a revocation reads before
// authorization: enough to resolve self, visibility and existence, and nothing
// more. Hash and revoked state are deliberately absent.
type parentIdentity struct {
	exists      bool
	workspaceID string
	// self is the parent's principal: grant principal for a grant, confirmed_by
	// for a confirmation.
	self string
}

func loadParentGrantIdentity(ctx context.Context, transaction database.Transaction, organizationID, grantID string, grantRevision int64) (parentIdentity, error) {
	var identity parentIdentity
	err := transaction.QueryRow(ctx, `
		SELECT workspace_id, principal_id
		FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id = $1 AND grant_id = $2 AND revision = $3
	`, organizationID, grantID, grantRevision).Scan(&identity.workspaceID, &identity.self)
	if database.IsNotFound(err) {
		return parentIdentity{exists: false}, nil
	}
	if err != nil {
		return parentIdentity{}, err
	}
	identity.exists = true
	return identity, nil
}

func loadParentConfirmationIdentity(ctx context.Context, transaction database.Transaction, organizationID, confirmationID string) (parentIdentity, error) {
	var identity parentIdentity
	err := transaction.QueryRow(ctx, `
		SELECT workspace_id, confirmed_by
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1 AND confirmation_id = $2
	`, organizationID, confirmationID).Scan(&identity.workspaceID, &identity.self)
	if database.IsNotFound(err) {
		return parentIdentity{exists: false}, nil
	}
	if err != nil {
		return parentIdentity{}, err
	}
	identity.exists = true
	return identity, nil
}

// parentBusiness is the revocation parent's business projection, read only
// after authorization: whether the supplied hash matches and whether the parent
// is already revoked.
type parentBusiness struct {
	hashMatches bool
	revoked     bool
}

func loadParentGrantBusiness(ctx context.Context, transaction database.Transaction, organizationID, grantID string, grantRevision int64, expectedHash string) (parentBusiness, error) {
	var storedHash string
	var revoked bool
	err := transaction.QueryRow(ctx, `
		SELECT grant_hash,
		       EXISTS (
		           SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS revocation
		           WHERE revocation.organization_id = $1 AND revocation.grant_id = $2 AND revocation.grant_revision = $3
		       )
		FROM public.workspace_source_confirmation_actor_grant
		WHERE organization_id = $1 AND grant_id = $2 AND revision = $3
	`, organizationID, grantID, grantRevision).Scan(&storedHash, &revoked)
	if err != nil {
		return parentBusiness{}, err
	}
	return parentBusiness{hashMatches: storedHash == expectedHash, revoked: revoked}, nil
}

func loadParentConfirmationBusiness(ctx context.Context, transaction database.Transaction, organizationID, confirmationID, expectedHash string) (parentBusiness, error) {
	var storedHash string
	var revoked bool
	err := transaction.QueryRow(ctx, `
		SELECT confirmation_hash,
		       EXISTS (
		           SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
		           WHERE revocation.organization_id = $1 AND revocation.confirmation_id = $2
		       )
		FROM public.workspace_managed_grant_confirmation
		WHERE organization_id = $1 AND confirmation_id = $2
	`, organizationID, confirmationID).Scan(&storedHash, &revoked)
	if err != nil {
		return parentBusiness{}, err
	}
	return parentBusiness{hashMatches: storedHash == expectedHash, revoked: revoked}, nil
}

// confirmLiveConfirmationExists is the decision-phase precheck of migration
// 000011's deferred derived-live gate, and matches its set exactly: the same
// binding tuple, an enabled binding, the current policy ordinal and opaque ID,
// the current warning registry head, and the absence of both a confirmation
// revocation and the actor-grant revocation. A stale-policy, stale-warning or
// grant-revoked confirmation is therefore NOT live and does not block a new
// confirm — exactly as the database gate would (or would not) count it. Under
// the workspace row lock the command already holds, a redundant confirm is
// resolved PRECONDITION_FAILED here rather than rolled back at commit.
func confirmLiveConfirmationExists(ctx context.Context, transaction database.Transaction, organizationID string, request ConfirmRequest, policyNumber int64, policyOpaque string) (bool, error) {
	var exists bool
	err := transaction.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.workspace_managed_grant_confirmation AS confirmation
			JOIN public.workspace_revision_source AS binding
			  ON binding.organization_id = confirmation.organization_id
			 AND binding.workspace_id = confirmation.workspace_id
			 AND binding.workspace_revision = confirmation.workspace_revision
			 AND binding.workspace_configuration_hash = confirmation.workspace_configuration_hash
			 AND binding.workspace_source_id = confirmation.workspace_source_id
			 AND binding.source_scope_id = confirmation.source_scope_id
			 AND binding.source_scope_revision = confirmation.source_scope_revision
			 AND binding.scope_config_hash = confirmation.scope_config_hash
			 AND binding.access_mode = confirmation.access_mode
			 AND binding.enabled
			JOIN public.workspace_managed_warning_contract AS warning
			  ON warning.warning_version = confirmation.warning_version
			 AND warning.warning_contract_hash = confirmation.warning_contract_hash
			 AND warning.revision = (SELECT max(revision) FROM public.workspace_managed_warning_contract)
			WHERE confirmation.organization_id = $1
			  AND confirmation.workspace_id = $2
			  AND confirmation.workspace_revision = $3
			  AND confirmation.workspace_configuration_hash = $4
			  AND confirmation.workspace_source_id = $5
			  AND confirmation.source_scope_id = $6
			  AND confirmation.source_scope_revision = $7
			  AND confirmation.scope_config_hash = $8
			  AND confirmation.access_mode = 'WORKSPACE_MANAGED'
			  AND confirmation.policy_revision_number = $9
			  AND confirmation.policy_revision = $10
			  AND confirmation.warning_version = $11
			  AND confirmation.warning_contract_hash = $12
			  AND NOT EXISTS (
				  SELECT 1 FROM public.workspace_managed_grant_revocation AS revocation
				  WHERE revocation.organization_id = confirmation.organization_id
				    AND revocation.confirmation_id = confirmation.confirmation_id
			  )
			  AND NOT EXISTS (
				  SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS grant_revocation
				  WHERE grant_revocation.organization_id = confirmation.organization_id
				    AND grant_revocation.grant_id = confirmation.confirmation_actor_grant_id
				    AND grant_revocation.grant_revision = confirmation.confirmation_actor_grant_revision
			  )
		)
	`, organizationID, request.WorkspaceID, request.WorkspaceRevision, request.WorkspaceConfigurationHash,
		request.WorkspaceSourceID, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash,
		policyNumber, policyOpaque, request.WarningVersion, request.WarningContractHash).Scan(&exists)
	return exists, err
}

// confirmBindingCurrent reports whether the exact enabled WORKSPACE_MANAGED
// binding the confirm command references exists at the given workspace revision.
func confirmBindingCurrent(ctx context.Context, transaction database.Transaction, organizationID string, request ConfirmRequest) (bool, error) {
	var enabled bool
	err := transaction.QueryRow(ctx, `
		SELECT enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1 AND workspace_id = $2 AND workspace_revision = $3
		  AND workspace_configuration_hash = $4 AND workspace_source_id = $5
		  AND source_scope_id = $6 AND source_scope_revision = $7
		  AND scope_config_hash = $8 AND access_mode = 'WORKSPACE_MANAGED'
	`, organizationID, request.WorkspaceID, request.WorkspaceRevision, request.WorkspaceConfigurationHash,
		request.WorkspaceSourceID, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash).Scan(&enabled)
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return enabled, nil
}

// confirmVerifierConflict reports whether the confirming principal has
// already, at any time, successfully verified the trust of the source
// connection that owns this scope (ADR-0087 §2, review blocker B3'): "A
// principal cannot be both the CONNECTOR_ADMIN who verifies a connector's
// trust and the workspace owner/manager who confirms that scope's
// WORKSPACE_MANAGED binding under ADR-0053's confirmation policy."
//
// This is the exact mirror of the check migration 000059's
// app.source_connection_trust_verify already runs in the opposite
// direction (verify-after-confirm): same join shape (source_scope to the
// connection, then to a completed record naming this principal), same
// per-connection granularity, same absence of a revocation filter on the
// record being matched (a source_connection_trust_verification row is an
// immutable SUCCESS fact, never revocable, so none exists to filter).
//
// Granularity: this checks every scope of the connection that owns
// SourceScopeID, not only SourceScopeID itself. ADR-0087 §2's own sentence
// names "a connector's trust" (connection-scoped: source_connection_trust_
// projection is keyed by connection, not by scope) against "that scope's
// WORKSPACE_MANAGED binding" (scope-scoped) -- the two halves of the
// conflict are already at different granularities in the ADR's own wording,
// and a verifier who attested a connection's trust has vouched for every
// scope discovered under it, not just the one binding they might later try
// to confirm. Per-connection is therefore not a narrowing substitute for a
// per-scope rule the ADR asked for; it is the strictly wider (never
// weaker) shape: it denies every case a per-SourceScopeID-only check would
// deny (this scope is always one of "every scope of its own connection"),
// plus every case where the same principal tries to confirm a *different*
// scope of a connection they already verified -- a real evasion a
// per-scope-only check would miss entirely.
// TestConfirmManagedSourceDeniesVerifierConflictAcrossDifferentScopesOfSameConnection
// (tests/integration/postgres) proves exactly that additional case: two
// distinct scopes of one connection, verify on one, confirm denied on the
// other.
func confirmVerifierConflict(ctx context.Context, transaction database.Transaction, organizationID, principalID, sourceScopeID string) (bool, error) {
	var conflict bool
	err := transaction.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.source_connection_trust_verification AS verification
			JOIN public.source_scope AS scope
			  ON scope.organization_id = verification.organization_id
			 AND scope.connection_id = verification.connection_id
			WHERE verification.organization_id = $1
			  AND verification.status = 'SUCCESS'
			  AND verification.verified_by = $2
			  AND scope.id = $3
		)
	`, organizationID, principalID, sourceScopeID).Scan(&conflict)
	return conflict, err
}
