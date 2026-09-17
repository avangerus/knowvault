package repository

import (
	"context"
	"crypto/sha256"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

const maxSafeInteger = int64(9007199254740991)

// SourceAccessMode is copied from one immutable source-scope revision. A
// workspace binding does not itself grant access or activate the scope.
type SourceAccessMode string

const (
	SourceAccessWorkspaceManaged SourceAccessMode = "WORKSPACE_MANAGED"
	SourceAccessSourceEnforced   SourceAccessMode = "SOURCE_ENFORCED"
)

// AddSourceRequest binds one exact DRAFT source-scope revision to one exact
// workspace base revision. The stable binding ID is server-derived from the
// organization/workspace/scope lineage and therefore survives re-enable with
// a different idempotency key.
type AddSourceRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedWorkspaceRevision int64
	ExpectedConfigurationHash string
	SourceScopeID             string
	SourceScopeRevision       int64
	ScopeConfigHash           string
	AccessMode                SourceAccessMode
}

// RemoveSourceRequest disables, but never deletes, one exact stable binding.
// The binding ID is a public precondition and part of the canonical command.
type RemoveSourceRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedWorkspaceRevision int64
	ExpectedConfigurationHash string
	WorkspaceSourceID         string
	SourceScopeID             string
	SourceScopeRevision       int64
	ScopeConfigHash           string
	AccessMode                SourceAccessMode
}

type sourceMutationRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedWorkspaceRevision int64
	ExpectedConfigurationHash string
	WorkspaceSourceID         string
	SourceScopeID             string
	SourceScopeRevision       int64
	ScopeConfigHash           string
	AccessMode                SourceAccessMode
	Operation                 commandOperation
	Action                    audit.Action
	Enabled                   bool
	RequestHash               string
}

// AddSource creates an inert binding lineage or re-enables its exact disabled
// projection. It creates no activation, grant, ingestion job or query access.
func (store *Store) AddSource(ctx context.Context, access database.AccessContext, request AddSourceRequest) (workspace.Snapshot, error) {
	if !validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash,
		request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, request.AccessMode) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := addSourceCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	return store.mutateSource(ctx, access, sourceMutationRequest{
		IdempotencyKey: request.IdempotencyKey, WorkspaceID: request.WorkspaceID,
		ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		WorkspaceSourceID:         stableWorkspaceSourceID(access.OrganizationID, request.WorkspaceID, request.SourceScopeID),
		SourceScopeID:             request.SourceScopeID, SourceScopeRevision: request.SourceScopeRevision,
		ScopeConfigHash: request.ScopeConfigHash, AccessMode: request.AccessMode,
		Operation: operationSourceAdd, Action: audit.ActionWorkspaceSourceAdded, Enabled: true, RequestHash: requestHash,
	})
}

// RemoveSource retains the lineage and advances the canonical projection from
// enabled to disabled. It does not delete the shared source scope.
func (store *Store) RemoveSource(ctx context.Context, access database.AccessContext, request RemoveSourceRequest) (workspace.Snapshot, error) {
	if !validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash,
		request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, request.AccessMode) ||
		!validStage2SourceID(request.WorkspaceSourceID, "binding_") ||
		request.WorkspaceSourceID != stableWorkspaceSourceID(access.OrganizationID, request.WorkspaceID, request.SourceScopeID) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := removeSourceCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	return store.mutateSource(ctx, access, sourceMutationRequest{
		IdempotencyKey: request.IdempotencyKey, WorkspaceID: request.WorkspaceID,
		ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		WorkspaceSourceID:         request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: request.AccessMode, Operation: operationSourceRemove,
		Action: audit.ActionWorkspaceSourceRemoved, Enabled: false, RequestHash: requestHash,
	})
}

func (store *Store) mutateSource(ctx context.Context, access database.AccessContext, request sourceMutationRequest) (workspace.Snapshot, error) {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil ||
		access.Validate() != nil || !workspace.IsConfigurationHash(request.RequestHash) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: request.Operation, WorkspaceID: request.WorkspaceID,
		ResourceType: audit.ResourceWorkspaceSource, ResourceID: request.WorkspaceSourceID,
		Source: &sourceCommandIntent{
			ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
			ExpectedConfigurationHash: request.ExpectedConfigurationHash,
			WorkspaceSourceID:         request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
			SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
			AccessMode: request.AccessMode,
		},
	}

	var result workspace.Snapshot
	var terminalCode ErrorCode
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, actorFound, actorErr := currentActor(transactionContext, transaction, access, true)
		if actorErr != nil {
			return actorErr
		}
		if !actorFound || organization.Status != policy.OrganizationActive {
			return &Error{code: CodeDenied}
		}
		reservation, reserveErr := reserveCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, intent, request.RequestHash)
		if reserveErr != nil {
			return reserveErr
		}
		if !reservation.created {
			if reservation.status != receiptSuccess {
				return replayError(reservation.status)
			}
			if replayErr := authorizeReplaySnapshot(transactionContext, transaction, subject, organization, reservation.snapshot); replayErr != nil {
				return replayErr
			}
			result = reservation.snapshot
			return nil
		}

		current, currentHash, currentSources, workspaceIDForEvent, decision, allowed, authorizeErr := store.authorizeSourceMutation(transactionContext, transaction, access, request.WorkspaceID)
		if authorizeErr != nil {
			return authorizeErr
		}
		finish := func(status receiptStatus, outcome audit.Outcome, code ErrorCode, eventWorkspaceID *string) error {
			eventID, appendErr := store.appendSourceTerminal(transactionContext, transaction, access, request, eventWorkspaceID, outcome, code, request.ExpectedWorkspaceRevision)
			if appendErr != nil {
				return appendErr
			}
			if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, status, nil, eventID); completeErr != nil {
				return completeErr
			}
			terminalCode = code
			return nil
		}
		if !allowed {
			_ = decision // the closed source audit intentionally stores no policy projection
			status, code, auditedWorkspaceID := sourceAuthorizationTerminal(workspaceIDForEvent)
			return finish(status, audit.OutcomeDenied, code, auditedWorkspaceID)
		}
		if current.Revision != request.ExpectedWorkspaceRevision || currentHash != request.ExpectedConfigurationHash {
			return finish(receiptPreconditionFailed, audit.OutcomeFailed, CodeRevisionConflict, workspaceIDForEvent)
		}
		var tupleExists bool
		var tupleErr error
		if request.Operation == operationSourceAdd && !sourceScopeAlreadyBound(currentSources, request.SourceScopeID) {
			// A genuinely new binding (the scope has never been added to this
			// workspace before) must still be an unactivated DRAFT scope: ADD is
			// configuration-only and cannot bind an active scope.
			tupleExists, tupleErr = exactDraftScopeTupleExists(transactionContext, transaction, access.OrganizationID, request)
		} else {
			// Re-enabling an existing (disabled) binding, or any REMOVE, targets a
			// scope that has typically already reached an active/ready revision;
			// requiring DRAFT here would make a disabled WORKSPACE_MANAGED source
			// impossible to re-enable through the public API (the "Enable"
			// toggle) once it had ever been activated.
			tupleExists, tupleErr = exactScopeTupleExists(transactionContext, transaction, access.OrganizationID, request)
		}
		if tupleErr != nil {
			return tupleErr
		}
		if !tupleExists {
			// Do not reveal whether a tenant-local scope ID, revision, hash or
			// access mode was the missing component.
			return finish(receiptNotFound, audit.OutcomeDenied, CodeNotFound, nil)
		}

		// ADR-0087 s1 (review blocker B1): a WORKSPACE_MANAGED binding a DELETE
		// disabled must not return to enabled without a live, unrevoked
		// confirmation for this exact scope tuple -- the same authority :sync and
		// Activate already require via app.source_scope_activation_confirmed
		// (internal/source/registration/service.go:893/1020). The denial is
		// fail-closed and content-free: it does not distinguish "never
		// confirmed" from "confirmation revoked" from "policy/warning drifted".
		if request.Operation == operationSourceAdd && request.AccessMode == SourceAccessWorkspaceManaged &&
			disabledManagedBinding(currentSources, request.SourceScopeID) {
			confirmed, confirmErr := managedReenableConfirmationLive(transactionContext, transaction, access.OrganizationID,
				request.WorkspaceID, request.WorkspaceSourceID, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash)
			if confirmErr != nil {
				return confirmErr
			}
			if !confirmed {
				return finish(receiptDenied, audit.OutcomeDenied, CodeDenied, workspaceIDForEvent)
			}
		}

		next, nextSources, createLineage, transitionErr := nextSourceProjection(current, currentSources, request)
		if transitionErr != nil {
			return finish(receiptPreconditionFailed, audit.OutcomeFailed, CodeRevisionConflict, workspaceIDForEvent)
		}
		nextHash, hashErr := workspace.ConfigurationHash(next)
		if hashErr != nil {
			return &Error{code: CodePersistence, cause: hashErr}
		}
		if advanceErr := advanceSnapshot(transactionContext, transaction, current, next, nextHash, access.PrincipalID); advanceErr != nil {
			return advanceErr
		}
		if createLineage {
			if _, insertErr := transaction.Exec(transactionContext, `
				INSERT INTO public.workspace_source (
					organization_id, id, workspace_id, source_scope_id, added_by
				) VALUES ($1, $2, $3, $4, $5)
			`, access.OrganizationID, request.WorkspaceSourceID, request.WorkspaceID, request.SourceScopeID, access.PrincipalID); insertErr != nil {
				return insertErr
			}
		}
		persistedHash, persistErr := persistRevisionSnapshot(transactionContext, transaction, next, nextSources)
		if persistErr != nil || persistedHash != nextHash {
			return &Error{code: CodePersistence, cause: persistErr}
		}
		eventID, appendErr := store.appendSourceTerminal(transactionContext, transaction, access, request, workspaceIDForEvent, audit.OutcomeSuccess, "", next.Revision)
		if appendErr != nil {
			return appendErr
		}
		if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, receiptSuccess, &next, eventID); completeErr != nil {
			return completeErr
		}
		result = next
		return nil
	})
	if err != nil {
		if isCommandResultError(err) {
			return workspace.Snapshot{}, err
		}
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	if terminalCode != "" {
		return workspace.Snapshot{}, &Error{code: terminalCode}
	}
	return result, nil
}

func sourceAuthorizationTerminal(workspaceID *string) (receiptStatus, ErrorCode, *string) {
	if workspaceID == nil {
		return receiptNotFound, CodeNotFound, nil
	}
	return receiptDenied, CodeDenied, workspaceID
}

func (store *Store) authorizeSourceMutation(ctx context.Context, transaction database.Transaction, access database.AccessContext, workspaceID string) (workspace.Snapshot, string, []revisionSourceProjection, *string, policy.Decision, bool, error) {
	subject, organization, actorFound, actorErr := currentActor(ctx, transaction, access, true)
	if actorErr != nil {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, actorErr
	}
	if !actorFound || organization.Status != policy.OrganizationActive {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonOrganizationUnavailable}}, false, nil
	}
	current, hash, sources, exists, loadErr := loadCurrentSnapshot(ctx, transaction, access.OrganizationID, workspaceID, true)
	if loadErr != nil {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, loadErr
	}
	if !exists {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonWorkspaceMembershipAbsent}}, false, nil
	}
	computedHash, hashErr := workspace.ConfigurationHash(current)
	if hashErr != nil || computedHash != hash {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, &Error{code: CodePersistence, cause: hashErr}
	}
	workspaceIDForEvent := current.ID
	decision := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceManageSources, Subject: subject,
		Workspace:  policy.Workspace{OrganizationID: current.OrganizationID, ID: current.ID, Status: policy.WorkspaceStatus(current.Status)},
		Membership: currentMembership(current, access.PrincipalID),
	})
	return current, hash, sources, &workspaceIDForEvent, decision, decision.Allowed, nil
}

// exactDraftScopeTupleExists verifies the immutable DRAFT source tuple before
// a FIRST bind of a scope to a workspace (mutateSource only calls this when
// sourceScopeAlreadyBound reports the scope has no prior binding at all): a
// first ADD is configuration-only and cannot bind an already-active scope.
// The caller still supplies the exact revision, hash and access mode, so a
// different lineage or projection cannot be substituted. Re-enabling an
// existing binding uses exactScopeTupleExists instead, since by then the
// scope has typically already been activated.
func exactDraftScopeTupleExists(ctx context.Context, transaction database.Transaction, organizationID string, request sourceMutationRequest) (bool, error) {
	var exists bool
	err := transaction.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.source_scope AS scope
			JOIN public.source_scope_revision AS revision
			  ON revision.organization_id = scope.organization_id
			 AND revision.source_scope_id = scope.id
			WHERE scope.organization_id = $1
			  AND scope.id = $2
			  AND scope.status = 'DRAFT'
			  AND scope.active_revision IS NULL
			  AND revision.revision = $3
			  AND revision.scope_config_hash = $4
			  AND revision.access_mode = $5
		)
	`, organizationID, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, string(request.AccessMode)).Scan(&exists)
	return exists, err
}

// exactScopeTupleExists verifies the immutable source tuple before a workspace
// binding is disabled.  Removal is a revocation operation and must work for a
// scope that has already reached an active/ready revision; requiring a DRAFT
// scope here would make an enabled source impossible to revoke through the
// public API.  The caller still supplies the exact revision, hash and access
// mode, so a different lineage or projection cannot be substituted.
func exactScopeTupleExists(ctx context.Context, transaction database.Transaction, organizationID string, request sourceMutationRequest) (bool, error) {
	var exists bool
	err := transaction.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.source_scope AS scope
			JOIN public.source_scope_revision AS revision
			  ON revision.organization_id = scope.organization_id
			 AND revision.source_scope_id = scope.id
			WHERE scope.organization_id = $1
			  AND scope.id = $2
			  AND revision.revision = $3
			  AND revision.scope_config_hash = $4
			  AND revision.access_mode = $5
		)
	`, organizationID, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, string(request.AccessMode)).Scan(&exists)
	return exists, err
}

func nextSourceProjection(current workspace.Snapshot, currentSources []revisionSourceProjection, request sourceMutationRequest) (workspace.Snapshot, []revisionSourceProjection, bool, error) {
	desired := workspace.SourceBinding{
		SourceScopeID: request.SourceScopeID, SourceScopeRevision: request.SourceScopeRevision,
		ScopeConfigHash: request.ScopeConfigHash, Enabled: request.Enabled,
	}
	nextSources := append([]revisionSourceProjection(nil), currentSources...)
	found := -1
	for index, source := range nextSources {
		if source.SourceScopeID == request.SourceScopeID {
			found = index
			break
		}
	}
	if request.Enabled {
		next, err := workspace.NextSourceBindingEnabled(current, desired)
		if err != nil {
			return workspace.Snapshot{}, nil, false, &Error{code: CodeRevisionConflict, cause: err}
		}
		if found < 0 {
			nextSources = append(nextSources, revisionSourceProjection{
				WorkspaceConfigurationHash: request.ExpectedConfigurationHash,
				WorkspaceSourceID:          request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
				SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
				AccessMode: string(request.AccessMode), Enabled: true,
			})
			return next, orderSourceProjection(next, nextSources), true, nil
		}
		if !exactProjectionIdentity(nextSources[found], request) || nextSources[found].Enabled {
			return workspace.Snapshot{}, nil, false, &Error{code: CodeRevisionConflict}
		}
		nextSources[found].Enabled = true
		return next, orderSourceProjection(next, nextSources), false, nil
	}

	if found < 0 || !exactProjectionIdentity(nextSources[found], request) || !nextSources[found].Enabled {
		return workspace.Snapshot{}, nil, false, &Error{code: CodeRevisionConflict}
	}
	next, err := workspace.NextSourceBindingDisabled(current, desired)
	if err != nil {
		return workspace.Snapshot{}, nil, false, &Error{code: CodeRevisionConflict, cause: err}
	}
	nextSources[found].Enabled = false
	return next, orderSourceProjection(next, nextSources), false, nil
}

// disabledManagedBinding reports whether the workspace's current source
// projection already carries a binding for this scope that is currently
// disabled -- exactly the transition mutateSource's re-enable gate (ADR-0087
// s1) must apply to.
func disabledManagedBinding(sources []revisionSourceProjection, sourceScopeID string) bool {
	for _, source := range sources {
		if source.SourceScopeID == sourceScopeID {
			return !source.Enabled
		}
	}
	return false
}

// managedReenableConfirmationLive reports whether a live, unrevoked
// WORKSPACE_MANAGED confirmation still exists for this exact scope tuple,
// bound to the current organization policy revision and the current
// warning-contract registry head (ADR-0087 s1, review blockers B1 and B1').
//
// It deliberately does not reuse app.source_scope_activation_confirmed (the
// read-side/:sync/Activate predicate, migration 000018): that predicate also
// requires the confirmation's own workspace_revision to equal the
// workspace's current_revision, and the workspace_revision_source binding at
// that historical revision to already be enabled. Neither can ever be true
// here. mutateSource's re-enable path is, at the moment this function runs,
// still inside the transaction that will create the very next workspace
// revision with this binding flipped back to enabled -- that revision does
// not exist yet, so no confirmation naming it can possibly exist, and no
// operator action could ever make app.source_scope_activation_confirmed
// return true before this command runs. Requiring that would make re-enable
// of a WORKSPACE_MANAGED binding permanently impossible instead of
// fail-closed, which is not what ADR-0087 s1 asks for.
//
// What this predicate keeps, unchanged, is every other dimension of
// liveness the read-side predicate already enforces: the confirmation must
// name this exact (workspace_source_id, source_scope_id,
// source_scope_revision, scope_config_hash) tuple, must not have been
// revoked (workspace_managed_grant_revocation), must not rest on a
// confirmation-actor grant that has since been revoked
// (workspace_source_confirmation_actor_grant_revocation, 000018:513-528 --
// review blocker B1': this second NOT EXISTS clause was missing here, so a
// confirmation whose issuing grant had been revoked still counted as "live"
// for re-enable even though Activate/:sync already reject it), and must
// still be bound to the CURRENT organization policy revision and the CURRENT
// warning-contract registry head -- a policy or warning-contract advance
// since the original confirm forces a fresh confirm before re-enable
// succeeds, exactly as it would before Activate/:sync. Once re-enable itself
// succeeds, the newly created workspace revision is fresh and unconfirmed by
// definition, so an operator must confirm again (ConfirmManagedSource, now
// possible because the binding is enabled) before Activate or :sync will
// accept it -- the "confirm again" half of the fail-closed round trip.
func managedReenableConfirmationLive(ctx context.Context, transaction database.Transaction, organizationID,
	workspaceID, workspaceSourceID, sourceScopeID string, sourceScopeRevision int64, scopeConfigHash string) (bool, error) {
	var live bool
	err := transaction.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM public.workspace_managed_grant_confirmation AS confirmation
			JOIN public.organization AS organization
			  ON organization.id = confirmation.organization_id
			 AND organization.policy_revision = confirmation.policy_revision_number
			JOIN public.workspace_managed_warning_contract AS warning
			  ON warning.warning_version = confirmation.warning_version
			 AND warning.warning_contract_hash = confirmation.warning_contract_hash
			 AND warning.revision = (SELECT max(revision) FROM public.workspace_managed_warning_contract)
			WHERE confirmation.organization_id = $1
			  AND confirmation.workspace_id = $2
			  AND confirmation.workspace_source_id = $3
			  AND confirmation.source_scope_id = $4
			  AND confirmation.source_scope_revision = $5
			  AND confirmation.scope_config_hash = $6
			  AND confirmation.access_mode = 'WORKSPACE_MANAGED'
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
	`, organizationID, workspaceID, workspaceSourceID, sourceScopeID, sourceScopeRevision, scopeConfigHash).Scan(&live)
	return live, err
}

// sourceScopeAlreadyBound reports whether the workspace's current source
// projection already carries a binding (enabled or disabled) for this scope.
// It uses the same lookup key as nextSourceProjection's own `found` search
// (SourceScopeID only) so the tuple-existence gate above and the projection
// transition below always agree on whether this ADD is a first bind or a
// re-enable.
func sourceScopeAlreadyBound(sources []revisionSourceProjection, sourceScopeID string) bool {
	for _, source := range sources {
		if source.SourceScopeID == sourceScopeID {
			return true
		}
	}
	return false
}

func exactProjectionIdentity(projection revisionSourceProjection, request sourceMutationRequest) bool {
	return projection.WorkspaceSourceID == request.WorkspaceSourceID && projection.SourceScopeID == request.SourceScopeID &&
		projection.SourceScopeRevision == request.SourceScopeRevision && projection.ScopeConfigHash == request.ScopeConfigHash &&
		projection.AccessMode == string(request.AccessMode)
}

// Canonical snapshots and relational projections are both ordered by scope
// ID. Rebuilding the projection from the snapshot is forbidden because that
// would discard the stable binding ID and trusted access mode.
func orderSourceProjection(next workspace.Snapshot, sources []revisionSourceProjection) []revisionSourceProjection {
	ordered := make([]revisionSourceProjection, 0, len(sources))
	for _, binding := range next.SourceBindings {
		for _, source := range sources {
			if source.SourceScopeID == binding.SourceScopeID {
				ordered = append(ordered, source)
				break
			}
		}
	}
	return ordered
}

func (store *Store) appendSourceTerminal(ctx context.Context, transaction database.Transaction, access database.AccessContext, request sourceMutationRequest, workspaceID *string, outcome audit.Outcome, code ErrorCode, revision int64) (string, error) {
	eventID, err := store.generatedID("aud_")
	if err != nil {
		return "", err
	}
	actorID := access.PrincipalID
	bindingID, scopeID, scopeHash, accessMode, enabled := request.WorkspaceSourceID, request.SourceScopeID, request.ScopeConfigHash, string(request.AccessMode), request.Enabled
	metadata := audit.Metadata{
		WorkspaceRevision: &revision, WorkspaceSourceID: &bindingID, SourceScopeID: &scopeID,
		SourceScopeRevision: &request.SourceScopeRevision, ScopeConfigHash: &scopeHash,
		AccessMode: &accessMode, Enabled: &enabled,
	}
	var errorCode *string
	if outcome != audit.OutcomeSuccess {
		value := string(code)
		errorCode = &value
	}
	_, err = store.audit.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: eventID, WorkspaceID: workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: request.Action, ResourceType: audit.ResourceWorkspaceSource, ResourceID: request.WorkspaceSourceID,
		RequestID: access.RequestID, Outcome: outcome, ErrorCode: errorCode, Metadata: metadata, OccurredAt: store.now().UTC(),
	})
	return eventID, err
}

func validSourceRequest(workspaceID string, workspaceRevision int64, workspaceHash, scopeID string, scopeRevision int64, scopeHash string, accessMode SourceAccessMode) bool {
	return validID(workspaceID) && workspaceRevision >= 1 && workspaceRevision <= maxSafeInteger &&
		workspace.IsConfigurationHash(workspaceHash) && validStage2SourceID(scopeID, "scope_") &&
		scopeRevision >= 1 && scopeRevision <= maxSafeInteger && workspace.IsConfigurationHash(scopeHash) &&
		(accessMode == SourceAccessWorkspaceManaged || accessMode == SourceAccessSourceEnforced)
}

func stableWorkspaceSourceID(organizationID, workspaceID, sourceScopeID string) string {
	digest := sha256.Sum256([]byte("workspace-source-lineage-v1\x00" + organizationID + "\x00" + workspaceID + "\x00" + sourceScopeID))
	return "binding_" + crockford128(digest[:16])
}

func crockford128(value []byte) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	result := make([]byte, 0, 26)
	var accumulator uint32
	bits := uint(2) // two zero pad bits make the first symbol fall in [0,7]
	for _, item := range value {
		accumulator = (accumulator << 8) | uint32(item)
		bits += 8
		for bits >= 5 {
			bits -= 5
			result = append(result, alphabet[(accumulator>>bits)&31])
			if bits == 0 {
				accumulator = 0
			} else {
				accumulator &= (1 << bits) - 1
			}
		}
	}
	return string(result)
}

func validStage2SourceID(value, prefix string) bool {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if len(value) != len(prefix)+26 || value[:len(prefix)] != prefix {
		return false
	}
	encoded := value[len(prefix):]
	if encoded[0] < '0' || encoded[0] > '7' {
		return false
	}
	for index := 1; index < len(encoded); index++ {
		found := false
		for alphabetIndex := 0; alphabetIndex < len(alphabet); alphabetIndex++ {
			if encoded[index] == alphabet[alphabetIndex] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
