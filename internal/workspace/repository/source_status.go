package repository

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

// SourceStatus is the content-free sync status projection of one source bound
// to the current revision of a workspace (ADR-0074 D3-3). The sync_run fields
// are pointers: a scope without a completed run has no run row yet.
type SourceStatus struct {
	WorkspaceSourceID          string
	SourceScopeID              string
	SourceScopeRevision        int64
	AccessMode                 string
	Enabled                    bool
	ScopeConfigHash            string
	ConnectionID               string
	ConnectionName             string
	SourceType                 string
	PostgreSQLSchemaName       *string
	PostgreSQLRelationName     *string
	ActivationStatus           string
	TrustVerified              bool
	SyncStatus                 *string
	SyncErrorCode              *string
	SyncStartedAt              *time.Time
	SyncCompletedAt            *time.Time
	ObjectsSeen                *int64
	ObjectsIngested            *int64
	VersionsCreated            *int64
	EvidencePublished          *int64
	Quarantined                *int64
	JobID                      *string
	JobStatus                  *string
	JobAttemptCount            *int64
	JobMaxAttempts             *int64
	JobAvailableAt             *time.Time
	JobLeaseExpiresAt          *time.Time
	JobLastErrorCode           *string
	ContentFreshnessSLASeconds int64
	LastSuccessfulSyncAt       *time.Time
	FreshnessState             string
	// SyncIntervalSeconds is the operator-chosen schedule the worker's
	// autonomous scheduler uses for this scope (V1-A, migration 000061/000062).
	SyncIntervalSeconds int64
	// Confirmed is the workspace-local live confirmation for this exact binding
	// tuple. It uses the same warning/policy/revocation gates as activation but
	// scopes the result to this workspace; app.source_scope_activation_confirmed
	// remains the global any-workspace worker activation predicate.
	Confirmed bool
	// ViewerVerifyConflict mirrors, from the read side, the exact
	// verifier/confirmer separation-of-duty check ADR-0087 §2 enforces at
	// write time in both directions (migration 000059's app.source_
	// connection_trust_verify and confirmVerifierConflict,
	// authority_facts.go): whether the CURRENT VIEWER has already confirmed
	// a WORKSPACE_MANAGED binding of some scope of this source's own
	// connection. When true, a VerifyConnectionTrust call by this viewer
	// against this connection would be denied by the SoD check, so
	// ConfirmationContext.CanVerifyConnectionTrust alone (role-only) is not
	// enough to decide whether the "Verify trust" action would
	// succeed for this particular source (review-opus-s2-6-7.md remark:
	// can_verify_connection_trust did not account for SoD, so the button
	// was shown to a viewer 000059 would refuse).
	ViewerVerifyConflict bool
}

// SelfConfirmationGrant is the caller's own live, unrevoked, unexpired
// workspace.source.confirm grant, if one exists. The grant is workspace-wide
// (ADR-0053): it is not tied to one source scope, so it is reported once per
// workspace rather than once per source.
type SelfConfirmationGrant struct {
	GrantID       string
	GrantRevision int64
	GrantHash     string
	ValidUntil    string
}

// ConfirmationContext is the operator-visible read half of ADR-0087 §1-§2: the
// exact identifiers and current values a UI or agent needs to build the
// confirmation-grant, managed-source-confirmation and verify-trust command
// bodies without a database session, plus the viewer's own eligibility so a
// denied action can be explained rather than only refused.
type ConfirmationContext struct {
	ExpectedPolicyRevision string
	WarningVersion         string
	WarningContractHash    string
	ViewerPrincipalID      string
	// CanIssueConfirmationGrant mirrors ADR-0053's issuer role rule: only an
	// organization OWNER or ADMIN may call IssueConfirmationGrant.
	CanIssueConfirmationGrant bool
	// CanVerifyConnectionTrust mirrors ADR-0087 §2's role rule only: whether
	// the viewer currently holds CONNECTOR_ADMIN. It deliberately does NOT
	// account for the §2 verifier/confirmer separation of duty, because that
	// conflict is connection-specific and this context is workspace-wide, not
	// per-source. SourceStatus.ViewerVerifyConflict (and the per-source
	// sourceStatusResponse.CanVerifyConnectionTrust the REST handler derives
	// from it) is the field the UI must gate the verify-trust action on.
	CanVerifyConnectionTrust bool
	// SelfGrant is nil when the caller holds no live grant yet: the UI must
	// issue one (if CanIssueConfirmationGrant) before it can confirm.
	SelfGrant *SelfConfirmationGrant
}

// ListSources returns the current sync status of every source bound to the
// current revision of one workspace, only for a caller with a current
// membership that may read workspace metadata. Absence and a policy denial
// intentionally have the same external result.
func (store *Store) listSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceStatus, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) {
		return nil, &Error{code: CodeRequestInvalid}
	}
	result := []SourceStatus{}
	denied := false
	notFound := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		membership := currentMembership(snapshot, access.PrincipalID)
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: membership,
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT status.workspace_source_id, status.source_scope_id, status.source_scope_revision, status.access_mode,
			       status.enabled, status.scope_config_hash,
			       status.connection_id, status.connection_name, status.activation_status, status.trust_verified, status.sync_status,
			       status.sync_error_code, status.sync_started_at, status.sync_completed_at, status.objects_seen, status.objects_ingested,
			       status.versions_created, status.evidence_published, status.quarantined, status.job_id, status.job_status,
			       status.job_attempt_count, status.job_max_attempts, status.job_available_at, status.job_lease_expires_at,
			       status.job_last_error_code, status.content_freshness_sla_seconds, status.last_successful_sync_at,
			       status.freshness_state, status.sync_interval_seconds,
			       scope_revision.source_type, projection.schema_name, projection.relation_name,
			       app.workspace_source_confirmation_live($1, status.workspace_source_id, status.source_scope_id,
			           status.source_scope_revision, status.scope_config_hash, status.access_mode),
			       EXISTS (
			           SELECT 1
			             FROM public.workspace_managed_grant_confirmation AS confirmation
			             JOIN public.source_scope AS conflict_scope
			               ON conflict_scope.organization_id = confirmation.organization_id
			              AND conflict_scope.connection_id = status.connection_id
			            WHERE confirmation.organization_id = $2
			              AND confirmation.confirmed_by = $3
			              AND confirmation.source_scope_id = conflict_scope.id
			       ) AS viewer_verify_conflict
			FROM app.workspace_source_status_v3($1) AS status
			JOIN public.source_scope_revision AS scope_revision
			  ON scope_revision.organization_id = $2
			 AND scope_revision.source_scope_id = status.source_scope_id
			 AND scope_revision.revision = status.source_scope_revision
			 AND scope_revision.connection_id = status.connection_id
			LEFT JOIN public.postgresql_query_projection AS projection
			  ON projection.organization_id = scope_revision.organization_id
			 AND projection.source_scope_id = scope_revision.source_scope_id
			 AND projection.source_scope_revision = scope_revision.revision
			 AND projection.connection_id = scope_revision.connection_id
			 AND scope_revision.source_type = 'POSTGRESQL_QUERY'`, workspaceID, access.OrganizationID, access.PrincipalID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var status SourceStatus
			if scanErr := rows.Scan(
				&status.WorkspaceSourceID, &status.SourceScopeID, &status.SourceScopeRevision, &status.AccessMode, &status.Enabled,
				&status.ScopeConfigHash, &status.ConnectionID, &status.ConnectionName, &status.ActivationStatus,
				&status.TrustVerified, &status.SyncStatus, &status.SyncErrorCode, &status.SyncStartedAt,
				&status.SyncCompletedAt, &status.ObjectsSeen, &status.ObjectsIngested, &status.VersionsCreated,
				&status.EvidencePublished, &status.Quarantined, &status.JobID, &status.JobStatus,
				&status.JobAttemptCount, &status.JobMaxAttempts, &status.JobAvailableAt,
				&status.JobLeaseExpiresAt, &status.JobLastErrorCode, &status.ContentFreshnessSLASeconds,
				&status.LastSuccessfulSyncAt, &status.FreshnessState, &status.SyncIntervalSeconds,
				&status.SourceType, &status.PostgreSQLSchemaName, &status.PostgreSQLRelationName,
				&status.Confirmed, &status.ViewerVerifyConflict,
			); scanErr != nil {
				return scanErr
			}
			result = append(result, status)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		rows.Close()
		// app.workspace_source_confirmation_live (just scanned into
		// status.Confirmed above) always reports false for a disabled
		// binding: it requires the binding to already be enabled at the
		// workspace's current revision, which a disabled binding by
		// definition is not. That makes it meaningless for telling an
		// operator whether a disabled WORKSPACE_MANAGED source is
		// "DISABLED, one click from re-enabling" or "NEEDS_CONFIRMATION
		// before it can be re-enabled" (ADR-0087 s1, review blocker B1). For
		// a disabled WORKSPACE_MANAGED binding, re-derive Confirmed from the
		// same live-confirmation fact mutateSource's re-enable gate itself
		// checks (managedReenableConfirmationLive), so the read side and the
		// write-side gate never disagree about whether re-enable would
		// succeed. This runs as its own pass, after the result set above is
		// fully consumed and closed: the underlying connection cannot run a
		// second query while that first row set is still open.
		for index := range result {
			status := &result[index]
			if status.Enabled || status.AccessMode != string(SourceAccessWorkspaceManaged) {
				continue
			}
			live, liveErr := managedReenableConfirmationLive(transactionContext, transaction, access.OrganizationID,
				workspaceID, status.WorkspaceSourceID, status.SourceScopeID, status.SourceScopeRevision, status.ScopeConfigHash)
			if liveErr != nil {
				return liveErr
			}
			status.Confirmed = live
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return nil, err
		}
		return nil, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return nil, &Error{code: CodeNotFound}
	}
	if notFound {
		return nil, &Error{code: CodeNotFound}
	}
	return result, nil
}

// ConfirmationContext returns the ADR-0087 §1-§2 operator-visible read: the
// organization's current expected_policy_revision and warning-contract head,
// the caller's own eligibility to issue a confirmation grant (organization
// OWNER/ADMIN) or verify connection trust (CONNECTOR_ADMIN), and the caller's
// own live confirmation-actor grant if one already exists. It uses the exact
// same visibility gate as ListSources (current membership, workspace-metadata
// policy) so absence and denial stay indistinguishable, and it reads only
// tables and functions already granted to knowvault_app for this purpose: no
// new migration, grant or SECURITY DEFINER surface is introduced here. No
// secret, credential or source content is ever read or returned.
func (store *Store) confirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (ConfirmationContext, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) {
		return ConfirmationContext{}, &Error{code: CodeRequestInvalid}
	}
	var result ConfirmationContext
	denied := false
	notFound := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, _, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
		if loadErr != nil {
			return loadErr
		}
		if !exists {
			notFound = true
			return nil
		}
		membership := currentMembership(snapshot, access.PrincipalID)
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: membership,
		})
		if !decision.Allowed {
			denied = true
			return nil
		}

		result.ViewerPrincipalID = access.PrincipalID
		for _, role := range subject.OrganizationRoles {
			switch role {
			case policy.OrganizationOwner, policy.OrganizationAdmin:
				result.CanIssueConfirmationGrant = true
			case policy.OrganizationConnectorAdmin:
				result.CanVerifyConnectionTrust = true
			}
		}

		if err := transaction.QueryRow(transactionContext, `
			SELECT registry.policy_revision_id
			FROM public.organization AS organization
			JOIN public.organization_policy_revision AS registry
			  ON registry.organization_id = organization.id
			 AND registry.revision = organization.policy_revision
			WHERE organization.id = $1
		`, access.OrganizationID).Scan(&result.ExpectedPolicyRevision); err != nil && !database.IsNotFound(err) {
			return err
		}

		// app.workspace_managed_warning_contract_current_revision() and
		// app.authority_transaction_epoch() are deliberately not granted to
		// knowvault_app (migration 000010's "lock down every helper/trigger
		// function" REVOKE, 000011's comment: reachable only from a CHECK or a
		// SECURITY DEFINER guard that resolves them as the owner). Rather than
		// widen that grant, this read recomputes the exact same values inline
		// from tables/columns knowvault_app already has SELECT on.
		if err := transaction.QueryRow(transactionContext, `
			SELECT warning_version, warning_contract_hash
			FROM public.workspace_managed_warning_contract
			WHERE revision = (SELECT max(revision) FROM public.workspace_managed_warning_contract)
		`).Scan(&result.WarningVersion, &result.WarningContractHash); err != nil && !database.IsNotFound(err) {
			return err
		}

		var grant SelfConfirmationGrant
		grantErr := transaction.QueryRow(transactionContext, `
			SELECT grant_row.grant_id, grant_row.revision, grant_row.grant_hash, grant_row.valid_until
			FROM public.workspace_source_confirmation_actor_grant AS grant_row
			WHERE grant_row.organization_id = $1 AND grant_row.workspace_id = $2
			  AND grant_row.principal_id = $3 AND grant_row.permission = 'workspace.source.confirm'
			  AND NOT EXISTS (
			      SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation AS revocation
			      WHERE revocation.organization_id = grant_row.organization_id
			        AND revocation.grant_id = grant_row.grant_id
			        AND revocation.grant_revision = grant_row.revision
			  )
			  AND app.authority_timestamp_v1_to_epoch(grant_row.valid_until) > extract(epoch FROM date_trunc('second', transaction_timestamp()))::bigint
			ORDER BY grant_row.revision DESC
			LIMIT 1
		`, access.OrganizationID, workspaceID, access.PrincipalID).Scan(&grant.GrantID, &grant.GrantRevision, &grant.GrantHash, &grant.ValidUntil)
		if grantErr == nil {
			result.SelfGrant = &grant
		} else if !database.IsNotFound(grantErr) {
			return grantErr
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return ConfirmationContext{}, err
		}
		return ConfirmationContext{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return ConfirmationContext{}, &Error{code: CodeNotFound}
	}
	if notFound {
		return ConfirmationContext{}, &Error{code: CodeNotFound}
	}
	return result, nil
}
