// Package repository persists the Stage 1 workspace control plane.
//
// It is the only layer in this slice that joins authenticated database access,
// default-deny policy, immutable workspace configuration and the audit chain.
// HTTP handlers never receive a PostgreSQL transaction or choose an
// organization filter themselves.
package repository

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

// ErrorCode is content-free and safe for API error mapping.
type ErrorCode string

const (
	CodeRequestInvalid      ErrorCode = "WORKSPACE_REQUEST_INVALID"
	CodeDenied              ErrorCode = "WORKSPACE_DENIED"
	CodeNotFound            ErrorCode = "WORKSPACE_NOT_FOUND"
	CodeRevisionConflict    ErrorCode = "WORKSPACE_REVISION_CONFLICT"
	CodeIdempotencyConflict ErrorCode = "WORKSPACE_IDEMPOTENCY_CONFLICT"
	CodePersistence         ErrorCode = "WORKSPACE_PERSISTENCE_FAILED"
)

// Error preserves a safe code while retaining its cause only for trusted
// in-process diagnostics. Its string form never includes workspace text.
type Error struct {
	code  ErrorCode
	cause error
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }

// NewError constructs a typed repository error for transport boundaries and
// cross-package tests. It carries the safe code and, for trusted in-process
// diagnostics only, the cause; the string form never includes workspace text.
func NewError(code ErrorCode, cause error) *Error {
	return &Error{code: code, cause: cause}
}

// CodeOf maps every unexpected dependency error to a safe repository code.
func CodeOf(err error) ErrorCode {
	var repositoryError *Error
	if errors.As(err, &repositoryError) {
		return repositoryError.code
	}
	return CodePersistence
}

// Store is constructed only at the application composition root.
type Store struct {
	database *database.Store
	audit    *audit.Store
	now      func() time.Time
	newID    func(prefix string) (string, error)
}

// New binds workspace persistence to the reviewed database and audit stores.
func New(databaseStore *database.Store, auditStore *audit.Store) (*Store, error) {
	if databaseStore == nil || auditStore == nil {
		return nil, &Error{code: CodePersistence}
	}
	return &Store{database: databaseStore, audit: auditStore, now: time.Now, newID: randomID}, nil
}

// CreateRequest contains the user-controlled workspace fields. The ID,
// revision, owner membership and audit ID are always server generated.
type CreateRequest struct {
	IdempotencyKey    string
	Name              string
	Description       string
	RetentionPolicyID string
}

// UpdateRequest replaces the mutable metadata of one active workspace. A
// partial patch is deliberately absent: the server always hashes the complete
// resulting configuration.
type UpdateRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
	Name                      string
	Description               string
	RetentionPolicyID         string
}

// AddMemberRequest adds one active principal with a non-owner workspace role.
type AddMemberRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
	PrincipalID               string
	Role                      workspace.Role
}

// ChangeMemberRoleRequest replaces one active non-owner membership with a new
// historical row. OWNER can only change through TransferOwnership.
type ChangeMemberRoleRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
	PrincipalID               string
	Role                      workspace.Role
}

// RemoveMemberRequest closes one active non-owner membership.
type RemoveMemberRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
	PrincipalID               string
}

// TransferOwnershipRequest moves the sole OWNER role to an existing active
// member. Only the current owner may execute this command.
type TransferOwnershipRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
	NewOwnerPrincipalID       string
}

// ArchiveRequest requires the configuration hash observed by the caller.
type ArchiveRequest struct {
	IdempotencyKey            string
	WorkspaceID               string
	ExpectedConfigurationHash string
}

// Summary is the content-free workspace projection used by a future list UI.
//
// Degraded is set when the workspace is readable but its live metadata no
// longer hashes to the immutable configuration hash of its current revision.
// The list stays available and the marker carries only a closed reason code;
// neither the stored nor the recomputed hash is ever projected.
type Summary struct {
	ID             string
	Name           string
	Status         workspace.Status
	Revision       int64
	Role           workspace.Role
	Degraded       bool
	DegradedReason string
}

// SummaryDegradedReasonConfigurationHashStale is the closed, content-free
// reason attached to a readable workspace whose recomputed configuration hash
// does not match the hash recorded on its current immutable revision. It names
// no hash bytes and no workspace content.
const SummaryDegradedReasonConfigurationHashStale = "WORKSPACE_CONFIGURATION_HASH_STALE"

// configurationHashChange is the closed result of comparing a workspace's
// persisted revision configuration hash with the hash recomputed from its live
// metadata. Both the read path (Get) and the mutation repair path
// (authorizeMutation) classify that comparison through
// compareConfigurationHash, so a degraded read and a re-hash repair are decided
// by exactly one predicate and a merely stale hash can never hard-fail with
// WORKSPACE_PERSISTENCE_FAILED.
type configurationHashChange struct {
	// Stale reports that the persisted revision hash no longer matches the
	// live metadata, so the workspace must be reported degraded and a mutation
	// must persist a corrected revision hash.
	Stale bool
	// EffectiveHash is the optimistic precondition a mutation compares against:
	// the recomputed live hash when the stored hash is stale, otherwise the
	// stored revision hash.
	EffectiveHash string
}

// compareConfigurationHash classifies one stored-versus-recomputed
// configuration-hash pair for the 12.09 acc2 guard. It carries no extra hash
// bytes beyond the values the caller already loaded from the same snapshot.
func compareConfigurationHash(storedHash, computedHash string) configurationHashChange {
	if storedHash == computedHash {
		return configurationHashChange{Stale: false, EffectiveHash: storedHash}
	}
	return configurationHashChange{Stale: true, EffectiveHash: computedHash}
}

// configurationHashReadOutcome maps the stored-versus-recomputed comparison to
// the read-path result Get must expose: a readable workspace carrying the
// closed degraded reason, never a persistence failure. The healthy case reports
// no marker at all.
func configurationHashReadOutcome(storedHash, computedHash string) (bool, string) {
	if compareConfigurationHash(storedHash, computedHash).Stale {
		return true, SummaryDegradedReasonConfigurationHashStale
	}
	return false, ""
}

// authorizeReplayConfigurationHash maps the stored-versus-recomputed
// configuration-hash pair observed on the idempotent replay path to the error
// that replay must surface. The 12.09 acc2 guard repair path tolerates a stale
// stored hash on Get (configurationHashReadOutcome) and on authorizeMutation
// (compareConfigurationHash), so a member retrying a workspace mutation must
// not turn the same condition into WORKSPACE_PERSISTENCE_FAILED either: replay
// classifies it through the shared predicate and continues authorizing against
// the readable live snapshot, leaving membership denial to the caller. Only a
// genuine failure to recompute the live hash stays a persistence failure.
func authorizeReplayConfigurationHash(storedHash, computedHash string, recomputeErr error) error {
	if recomputeErr != nil {
		return &Error{code: CodePersistence, cause: recomputeErr}
	}
	// A stale stored hash is deliberately not an error here; the classification
	// is the single rule that decides staleness for every other path.
	compareConfigurationHash(storedHash, computedHash)
	return nil
}

// revisionSourceProjection carries the relational fields that deliberately do
// not belong to workspace-configuration-v1.  Ordinary workspace mutations
// must copy these exact immutable rows; reconstructing them from the canonical
// SourceBinding would lose the stable binding identity and trusted access mode.
type revisionSourceProjection struct {
	WorkspaceConfigurationHash string
	WorkspaceSourceID          string
	SourceScopeID              string
	SourceScopeRevision        int64
	ScopeConfigHash            string
	AccessMode                 string
	Enabled                    bool
}

// Create authorizes an active organization owner/admin, writes revision one
// with its one owner membership and appends workspace.created in one database
// transaction. A denied create is itself audited when the actor is known.
func (store *Store) Create(ctx context.Context, access database.AccessContext, request CreateRequest) (workspace.Snapshot, error) {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil || access.Validate() != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return workspace.Snapshot{}, err
	}
	requestHash, err := createCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	workspaceID := commandResourceID("ws_", access.OrganizationID, access.PrincipalID, keyHash, operationCreate)
	memberID := commandResourceID("wsm_", access.OrganizationID, access.PrincipalID, keyHash, operationCreate)
	eventID, err := store.generatedID("aud_")
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	snapshot, hash, err := initialSnapshot(access.OrganizationID, access.PrincipalID, workspaceID, request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: operationCreate, WorkspaceID: snapshot.ID,
		ResourceType: audit.ResourceWorkspace, ResourceID: snapshot.ID,
	}

	var result workspace.Snapshot
	denied := false
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, true)
		if actorErr != nil {
			return actorErr
		}
		if !found {
			return &Error{code: CodeDenied}
		}
		reservation, reserveErr := reserveCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, intent, requestHash)
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
		decision := policy.EvaluateOrganization(policy.OrganizationRequest{
			Operation: policy.OperationWorkspaceCreate, Subject: subject, Organization: organization,
		})
		if !decision.Allowed {
			auditEventID, appendErr := store.appendDenied(transactionContext, transaction, access, audit.ActionWorkspaceCreated, audit.ResourceWorkspace, workspaceID, nil, decision)
			if appendErr != nil {
				return appendErr
			}
			if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, receiptDenied, nil, auditEventID); completeErr != nil {
				return completeErr
			}
			denied = true
			return nil
		}

		if _, insertErr := transaction.Exec(transactionContext, `
			INSERT INTO public.workspace (
				id, organization_id, name, description, status, owner_principal_id, current_revision, retention_policy_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''))
		`, snapshot.ID, snapshot.OrganizationID, snapshot.Name, snapshot.Description, string(snapshot.Status), snapshot.OwnerPrincipalID, snapshot.Revision, snapshot.RetentionPolicyID); insertErr != nil {
			return insertErr
		}
		if _, insertErr := transaction.Exec(transactionContext, `
			INSERT INTO public.workspace_revision (
				organization_id, workspace_id, revision, configuration_hash, created_by
			) VALUES ($1, $2, $3, $4, $5)
		`, snapshot.OrganizationID, snapshot.ID, snapshot.Revision, hash, access.PrincipalID); insertErr != nil {
			return insertErr
		}
		if _, insertErr := transaction.Exec(transactionContext, `
			INSERT INTO public.workspace_member (
				id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
			) VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, memberID, snapshot.OrganizationID, snapshot.ID, snapshot.OwnerPrincipalID, string(workspace.RoleOwner), snapshot.Revision, access.PrincipalID); insertErr != nil {
			return insertErr
		}
		if displayNameErr := hydrateMemberDisplayNames(transactionContext, transaction, &snapshot); displayNameErr != nil {
			return displayNameErr
		}
		persistedHash, snapshotErr := persistRevisionSnapshot(transactionContext, transaction, snapshot, nil)
		if snapshotErr != nil || persistedHash != hash {
			return &Error{code: CodePersistence, cause: snapshotErr}
		}
		workspaceIDForEvent := snapshot.ID
		actorID := access.PrincipalID
		_, appendErr := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceIDForEvent, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionWorkspaceCreated, ResourceType: audit.ResourceWorkspace, ResourceID: snapshot.ID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
		})
		if appendErr != nil {
			return appendErr
		}
		if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, receiptSuccess, &snapshot, eventID); completeErr != nil {
			return completeErr
		}
		result = snapshot
		return nil
	})
	if err != nil {
		if isCommandResultError(err) {
			return workspace.Snapshot{}, err
		}
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return workspace.Snapshot{}, &Error{code: CodeDenied}
	}
	return result, nil
}

// Get returns one current, hash-verified workspace only when the caller has a
// current direct membership with metadata-read permission. Absence and a
// policy denial intentionally have the same external result.
func (store *Store) Get(ctx context.Context, access database.AccessContext, workspaceID string) (workspace.Snapshot, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	var result workspace.Snapshot
	denied := false
	notFound := false
	degraded := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		snapshot, hash, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
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
		computedHash, hashErr := workspace.ConfigurationHash(snapshot)
		if hashErr != nil {
			return &Error{code: CodePersistence}
		}
		if staleMarker, reason := configurationHashReadOutcome(hash, computedHash); staleMarker {
			// 12.09 acc2 guard repair path: the same stale configuration hash that
			// List already marks degraded must not make a member's Get hard-fail
			// with WORKSPACE_PERSISTENCE_FAILED. Return the readable, live
			// snapshot carrying the closed degraded marker and journal one
			// content-free policy.decision FAILED event before it is returned.
			degraded = true
			snapshot.Degraded = true
			snapshot.DegradedReason = reason
		}
		result = snapshot
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return workspace.Snapshot{}, err
		}
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return workspace.Snapshot{}, &Error{code: CodeNotFound}
	}
	if notFound {
		return workspace.Snapshot{}, &Error{code: CodeNotFound}
	}
	if degraded {
		if journalErr := store.journalDegradedConfiguration(ctx, access, []string{workspaceID}); journalErr != nil {
			return workspace.Snapshot{}, journalErr
		}
	}
	return result, nil
}

// List returns only workspaces for which the current principal has a current
// readable membership. It does not perform cross-workspace search or infer a
// membership from organization administration.
func (store *Store) List(ctx context.Context, access database.AccessContext) ([]Summary, error) {
	if store == nil || store.database == nil || access.Validate() != nil {
		return nil, &Error{code: CodeRequestInvalid}
	}
	result := []Summary{}
	degradedWorkspaceIDs := []string{}
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			return nil
		}
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT workspace.id
			FROM public.workspace
			JOIN public.workspace_member AS member
			  ON member.organization_id = workspace.organization_id
			 AND member.workspace_id = workspace.id
			 AND member.principal_id = $2
			 AND member.removed_at IS NULL
			WHERE workspace.organization_id = $1
			ORDER BY workspace.id
		`, access.OrganizationID, access.PrincipalID)
		if queryErr != nil {
			return queryErr
		}
		workspaceIDs := []string{}
		for rows.Next() {
			var workspaceID string
			if scanErr := rows.Scan(&workspaceID); scanErr != nil {
				rows.Close()
				return scanErr
			}
			workspaceIDs = append(workspaceIDs, workspaceID)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			return rowsErr
		}
		// pgx permits only one active result set per connection. Close the
		// membership cursor before loading each hash-verified snapshot below;
		// otherwise the nested query fails with conn busy on a real pool even
		// though lightweight transaction fakes may not expose that ordering bug.
		rows.Close()
		for _, workspaceID := range workspaceIDs {
			snapshot, hash, _, exists, loadErr := loadCurrentSnapshot(transactionContext, transaction, access.OrganizationID, workspaceID, false)
			if loadErr != nil {
				return loadErr
			}
			if !exists {
				return &Error{code: CodePersistence}
			}
			membership := currentMembership(snapshot, access.PrincipalID)
			decision := policy.EvaluateWorkspace(policy.Request{
				Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
				Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
				Membership: membership,
			})
			if !decision.Allowed {
				continue
			}
			computedHash, hashErr := workspace.ConfigurationHash(snapshot)
			if hashErr != nil || compareConfigurationHash(hash, computedHash).Stale {
				// 12.09 acc2 guard: one stale configuration hash must not abort
				// the whole membership list. Keep every other readable workspace,
				// mark only the affected one with a closed reason and journal the
				// condition before the summaries leave this method.
				result = append(result, Summary{
					ID: snapshot.ID, Name: snapshot.Name, Status: snapshot.Status,
					Revision: snapshot.Revision, Role: workspace.Role(membership.Role),
					Degraded: true, DegradedReason: SummaryDegradedReasonConfigurationHashStale,
				})
				degradedWorkspaceIDs = append(degradedWorkspaceIDs, snapshot.ID)
				continue
			}
			result = append(result, Summary{ID: snapshot.ID, Name: snapshot.Name, Status: snapshot.Status, Revision: snapshot.Revision, Role: workspace.Role(membership.Role)})
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return nil, err
		}
		return nil, &Error{code: CodePersistence, cause: err}
	}
	if journalErr := store.journalDegradedConfiguration(ctx, access, degradedWorkspaceIDs); journalErr != nil {
		return nil, journalErr
	}
	return result, nil
}

// journalDegradedConfiguration records one content-free policy.decision FAILED
// event per degraded workspace through the existing R1 audit journal. Every
// event carries only the organization/principal ids supplied by the caller,
// the workspace id and the closed reason code; it never carries the stored or
// recomputed hash or any workspace content. The append happens after the read
// transaction closes and before the degraded summaries are returned, so the
// journal admission precedes the data.
func (store *Store) journalDegradedConfiguration(ctx context.Context, access database.AccessContext, workspaceIDs []string) error {
	if len(workspaceIDs) == 0 {
		return nil
	}
	if store == nil || store.audit == nil || store.now == nil || store.newID == nil {
		return &Error{code: CodePersistence}
	}
	actorType := audit.ActorHuman
	if access.ActorKind == database.ActorKindService {
		actorType = audit.ActorService
	}
	actorID := access.PrincipalID
	occurredAt := store.now().UTC()
	for _, id := range workspaceIDs {
		eventID, idErr := store.newID("aud_")
		if idErr != nil {
			return &Error{code: CodePersistence, cause: idErr}
		}
		workspaceID := id
		errorCode := SummaryDegradedReasonConfigurationHashStale
		if _, appendErr := store.audit.Append(ctx, access, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceID, ActorType: actorType,
			ActorPrincipalID: &actorID, Action: audit.ActionPolicyDecision,
			ResourceType: audit.ResourcePolicy, ResourceID: workspaceID, RequestID: access.RequestID,
			Outcome: audit.OutcomeFailed, ErrorCode: &errorCode,
			Metadata: audit.Metadata{ReasonCodes: []string{SummaryDegradedReasonConfigurationHashStale}},
			OccurredAt: occurredAt,
		}); appendErr != nil {
			return &Error{code: CodePersistence, cause: appendErr}
		}
	}
	return nil
}

// Update advances an active workspace to a newly hashed metadata revision.
func (store *Store) Update(ctx context.Context, access database.AccessContext, request UpdateRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := updateCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: operationUpdate, WorkspaceID: request.WorkspaceID,
		ResourceType: audit.ResourceWorkspace, ResourceID: request.WorkspaceID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceUpdated,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextMetadata(current, request.Name, request.Description, request.RetentionPolicyID)
		}, nil, nil)
}

// Archive advances an active workspace to ARCHIVED. It does not delete its
// existing revisions, evidence or audit chain.
func (store *Store) Archive(ctx context.Context, access database.AccessContext, request ArchiveRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := archiveCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: operationArchive, WorkspaceID: request.WorkspaceID,
		ResourceType: audit.ResourceWorkspace, ResourceID: request.WorkspaceID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceArchived,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextArchived(current)
		}, nil, nil)
}

// AddMember advances an active workspace revision and adds exactly one direct
// non-owner membership. The target must be an existing active principal in
// the same organization; organization administration never substitutes for a
// direct workspace grant.
func (store *Store) AddMember(ctx context.Context, access database.AccessContext, request AddMemberRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) || !validID(request.PrincipalID) || request.Role == workspace.RoleOwner {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := addMemberCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	memberID := commandResourceID("wsm_", access.OrganizationID, access.PrincipalID, keyHash, operationMemberAdd)
	intent := commandIntent{
		Operation: operationMemberAdd, WorkspaceID: request.WorkspaceID,
		TargetPrincipalID: request.PrincipalID, TargetRole: request.Role,
		ResourceType: audit.ResourceWorkspaceMember, ResourceID: memberID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceMemberAdded,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithMember(current, workspace.Member{PrincipalID: request.PrincipalID, Role: request.Role})
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			active, targetErr := activePrincipal(transactionContext, transaction, snapshot.OrganizationID, request.PrincipalID)
			if targetErr != nil {
				return targetErr
			}
			if !active {
				return &Error{code: CodeDenied}
			}
			return nil
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			_, insertErr := transaction.Exec(transactionContext, `
				INSERT INTO public.workspace_member (
					id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
				) VALUES ($1, $2, $3, $4, $5, $6, $7)
			`, memberID, snapshot.OrganizationID, snapshot.ID, request.PrincipalID, string(request.Role), snapshot.Revision, access.PrincipalID)
			return insertErr
		})
}

// ChangeMemberRole advances the workspace revision, closes the old membership
// interval and inserts its replacement in the same transaction.
func (store *Store) ChangeMemberRole(ctx context.Context, access database.AccessContext, request ChangeMemberRoleRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) || !validID(request.PrincipalID) || request.Role == workspace.RoleOwner {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	requestHash, err := changeMemberRoleCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(request.IdempotencyKey)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	memberID := commandResourceID("wsm_", access.OrganizationID, access.PrincipalID, keyHash, operationMemberRoleChange)
	intent := commandIntent{
		Operation: operationMemberRoleChange, WorkspaceID: request.WorkspaceID,
		TargetPrincipalID: request.PrincipalID, TargetRole: request.Role,
		ResourceType: audit.ResourceWorkspaceMember, ResourceID: memberID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceRoleChanged,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithMemberRole(current, request.PrincipalID, request.Role)
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			active, targetErr := activePrincipal(transactionContext, transaction, snapshot.OrganizationID, request.PrincipalID)
			if targetErr != nil {
				return targetErr
			}
			if !active {
				return &Error{code: CodeDenied}
			}
			return nil
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			if _, closeErr := closeMembership(transactionContext, transaction, snapshot.OrganizationID, snapshot.ID, request.PrincipalID, snapshot.Revision); closeErr != nil {
				return closeErr
			}
			return insertMembership(transactionContext, transaction, memberID, snapshot.OrganizationID, snapshot.ID, request.PrincipalID, request.Role, snapshot.Revision, access.PrincipalID)
		})
}

// RemoveMember advances the workspace revision and closes one non-owner
// membership. The sole owner cannot be removed through this command.
func (store *Store) RemoveMember(ctx context.Context, access database.AccessContext, request RemoveMemberRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) || !validID(request.PrincipalID) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	resourceID := request.WorkspaceID + ":" + request.PrincipalID
	requestHash, err := removeMemberCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: operationMemberRemove, WorkspaceID: request.WorkspaceID,
		TargetPrincipalID: request.PrincipalID,
		ResourceType:      audit.ResourceWorkspaceMember, ResourceID: resourceID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceMemberRemoved,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithoutMember(current, request.PrincipalID)
		}, nil, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			_, closeErr := closeMembership(transactionContext, transaction, snapshot.OrganizationID, snapshot.ID, request.PrincipalID, snapshot.Revision)
			return closeErr
		})
}

// TransferOwnership atomically moves both historical membership intervals and
// the workspace owner pointer. Managers may manage members but cannot seize
// ownership.
func (store *Store) TransferOwnership(ctx context.Context, access database.AccessContext, request TransferOwnershipRequest) (workspace.Snapshot, error) {
	if !validID(request.WorkspaceID) || !workspace.IsConfigurationHash(request.ExpectedConfigurationHash) || !validID(request.NewOwnerPrincipalID) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	previousOwnerMemberID, err := store.generatedID("wsm_")
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	newOwnerMemberID, err := store.generatedID("wsm_")
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	previousOwnerPrincipalID := ""
	requestHash, err := transferOwnershipCommandHash(request)
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	intent := commandIntent{
		Operation: operationOwnershipTransfer, WorkspaceID: request.WorkspaceID,
		TargetPrincipalID: request.NewOwnerPrincipalID, TargetRole: workspace.RoleOwner,
		ResourceType: audit.ResourceWorkspace, ResourceID: request.WorkspaceID,
	}
	return store.mutate(ctx, access, request.IdempotencyKey, intent, requestHash, request.ExpectedConfigurationHash, audit.ActionWorkspaceRoleChanged,
		func(current workspace.Snapshot) (workspace.Snapshot, error) {
			if current.OwnerPrincipalID != access.PrincipalID {
				return workspace.Snapshot{}, &Error{code: CodeDenied}
			}
			previousOwnerPrincipalID = current.OwnerPrincipalID
			return workspace.NextOwnershipTransferred(current, request.NewOwnerPrincipalID)
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			active, targetErr := activePrincipal(transactionContext, transaction, snapshot.OrganizationID, request.NewOwnerPrincipalID)
			if targetErr != nil {
				return targetErr
			}
			if !active {
				return &Error{code: CodeDenied}
			}
			return nil
		}, func(transactionContext context.Context, transaction database.Transaction, snapshot workspace.Snapshot) error {
			if _, closeErr := closeMembership(transactionContext, transaction, snapshot.OrganizationID, snapshot.ID, previousOwnerPrincipalID, snapshot.Revision); closeErr != nil {
				return closeErr
			}
			if _, closeErr := closeMembership(transactionContext, transaction, snapshot.OrganizationID, snapshot.ID, request.NewOwnerPrincipalID, snapshot.Revision); closeErr != nil {
				return closeErr
			}
			if insertErr := insertMembership(transactionContext, transaction, previousOwnerMemberID, snapshot.OrganizationID, snapshot.ID, previousOwnerPrincipalID, workspace.RoleManager, snapshot.Revision, access.PrincipalID); insertErr != nil {
				return insertErr
			}
			return insertMembership(transactionContext, transaction, newOwnerMemberID, snapshot.OrganizationID, snapshot.ID, request.NewOwnerPrincipalID, workspace.RoleOwner, snapshot.Revision, access.PrincipalID)
		})
}

type snapshotMutation func(workspace.Snapshot) (workspace.Snapshot, error)
type mutationPrePersist func(context.Context, database.Transaction, workspace.Snapshot) error
type mutationAfterPersist func(context.Context, database.Transaction, workspace.Snapshot) error

func (store *Store) mutate(ctx context.Context, access database.AccessContext, idempotencyKey string, intent commandIntent, requestHash, expectedConfigurationHash string, action audit.Action, change snapshotMutation, before mutationPrePersist, after mutationAfterPersist) (workspace.Snapshot, error) {
	if store == nil || store.database == nil || store.audit == nil || store.now == nil || store.newID == nil || access.Validate() != nil || !workspace.IsConfigurationHash(expectedConfigurationHash) || change == nil {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	keyHash, err := idempotencyKeyHash(idempotencyKey)
	if err != nil || !workspace.IsConfigurationHash(requestHash) {
		return workspace.Snapshot{}, &Error{code: CodeRequestInvalid}
	}
	eventID, err := store.generatedID("aud_")
	if err != nil {
		return workspace.Snapshot{}, &Error{code: CodePersistence, cause: err}
	}
	var result workspace.Snapshot
	denied := false
	conflicted := false
	err = store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, actorFound, actorErr := currentActor(transactionContext, transaction, access, true)
		if actorErr != nil {
			return actorErr
		}
		if !actorFound || organization.Status != policy.OrganizationActive {
			return &Error{code: CodeDenied}
		}
		reservation, reserveErr := reserveCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, intent, requestHash)
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

		current, currentHash, currentSources, workspaceIDForEvent, decision, allowed, repaired, authorizeErr := store.authorizeMutation(transactionContext, transaction, access, intent.WorkspaceID)
		if authorizeErr != nil {
			return authorizeErr
		}
		terminalizeDenied := func(denial policy.Decision) error {
			auditEventID, appendErr := store.appendDenied(transactionContext, transaction, access, action, intent.ResourceType, intent.ResourceID, workspaceIDForEvent, denial)
			if appendErr != nil {
				return appendErr
			}
			if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, receiptDenied, nil, auditEventID); completeErr != nil {
				return completeErr
			}
			denied = true
			return nil
		}
		if !allowed {
			return terminalizeDenied(decision)
		}
		if currentHash != expectedConfigurationHash {
			auditEventID, appendErr := store.appendFailed(transactionContext, transaction, access, action, intent.ResourceType, intent.ResourceID, workspaceIDForEvent, CodeRevisionConflict)
			if appendErr != nil {
				return appendErr
			}
			if completeErr := completeCommand(transactionContext, transaction, access.OrganizationID, access.PrincipalID, keyHash, receiptPreconditionFailed, nil, auditEventID); completeErr != nil {
				return completeErr
			}
			conflicted = true
			return nil
		}
		next, changeErr := change(current)
		if changeErr != nil {
			if CodeOf(changeErr) == CodeDenied {
				return terminalizeDenied(policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonWorkspaceRoleInsufficient}})
			}
			return &Error{code: CodeRequestInvalid}
		}
		if before != nil {
			if beforeErr := before(transactionContext, transaction, next); beforeErr != nil {
				if CodeOf(beforeErr) == CodeDenied {
					return terminalizeDenied(policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonPrincipalInactive}})
				}
				return beforeErr
			}
		}
		hash, hashErr := workspace.ConfigurationHash(next)
		if hashErr != nil {
			return &Error{code: CodeRequestInvalid}
		}
		if advanceErr := advanceSnapshot(transactionContext, transaction, current, next, hash, access.PrincipalID); advanceErr != nil {
			return advanceErr
		}
		persistedHash, snapshotErr := persistRevisionSnapshot(transactionContext, transaction, next, currentSources)
		if snapshotErr != nil || persistedHash != hash {
			return &Error{code: CodePersistence, cause: snapshotErr}
		}
		if after != nil {
			if afterErr := after(transactionContext, transaction, next); afterErr != nil {
				return afterErr
			}
		}
		if displayNameErr := hydrateMemberDisplayNames(transactionContext, transaction, &next); displayNameErr != nil {
			return displayNameErr
		}
		actorID := access.PrincipalID
		currentWorkspaceID := next.ID
		_, appendErr := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: eventID, WorkspaceID: &currentWorkspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: action, ResourceType: intent.ResourceType, ResourceID: intent.ResourceID, RequestID: access.RequestID,
			Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
		})
		if appendErr != nil {
			return appendErr
		}
		// 12.09 acc2 guard audited repair: a successful mutation against a
		// workspace whose live metadata no longer hashed to its stored revision
		// hash persisted a corrected revision. Journal that repair with exactly
		// one additional content-free policy.decision SUCCESS event in the same
		// transaction, so the repair is never silent while the read-path
		// degraded journal keeps its existing one-event behavior.
		if repaired {
			if repairErr := store.appendConfigurationHashRepair(transactionContext, transaction, access, next.ID); repairErr != nil {
				return repairErr
			}
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
	if denied {
		return workspace.Snapshot{}, &Error{code: CodeDenied}
	}
	if conflicted {
		return workspace.Snapshot{}, &Error{code: CodeRevisionConflict}
	}
	return result, nil
}

// authorizeMutation resolves and authorizes one workspace mutation. The
// separate repaired return value reports whether the workspace's live metadata
// no longer hashed to its stored revision hash and the caller must therefore
// persist a corrected revision; mutate owns the one content-free audit event
// that records that repair.
func (store *Store) authorizeMutation(ctx context.Context, transaction database.Transaction, access database.AccessContext, workspaceID string) (workspace.Snapshot, string, []revisionSourceProjection, *string, policy.Decision, bool, bool, error) {
	subject, organization, actorFound, actorErr := currentActor(ctx, transaction, access, true)
	if actorErr != nil {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, false, actorErr
	}
	if !actorFound || organization.Status != policy.OrganizationActive {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonOrganizationUnavailable}}, false, false, nil
	}
	current, hash, sources, exists, loadErr := loadCurrentSnapshot(ctx, transaction, access.OrganizationID, workspaceID, true)
	if loadErr != nil {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, false, loadErr
	}
	if !exists {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonWorkspaceMembershipAbsent}}, false, false, nil
	}
	computedHash, hashErr := workspace.ConfigurationHash(current)
	if hashErr != nil {
		return workspace.Snapshot{}, "", nil, nil, policy.Decision{}, false, false, &Error{code: CodePersistence}
	}
	change := compareConfigurationHash(hash, computedHash)
	repaired := change.Stale
	if repaired {
		// 12.09 acc2 guard repair path: a stale stored revision hash must not
		// make the workspace unrepairable. Expose the recomputed hash as the
		// optimistic precondition (a caller observes the same value as its ETag)
		// and let this mutation persist a corrected revision hash instead of
		// hard-failing with WORKSPACE_PERSISTENCE_FAILED. Authorization is still
		// evaluated below, so a non-member mutation remains denied.
		hash = change.EffectiveHash
	}
	workspaceIDForEvent := current.ID
	decision := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceManage, Subject: subject,
		Workspace:  policy.Workspace{OrganizationID: current.OrganizationID, ID: current.ID, Status: policy.WorkspaceStatus(current.Status)},
		Membership: currentMembership(current, access.PrincipalID),
	})
	return current, hash, sources, &workspaceIDForEvent, decision, decision.Allowed, repaired, nil
}

// appendConfigurationHashRepair journals exactly one content-free
// policy.decision SUCCESS event when a member mutation repaired a workspace
// whose live metadata had diverged from its immutable revision configuration
// hash. The event carries only the organization/principal ids supplied by the
// caller, the workspace id and the closed reason code; it never carries the
// stored or recomputed hash or any workspace content. mutate calls it inside
// the same publication transaction that persists the corrected revision, so a
// repair can never be committed without its audit event.
func (store *Store) appendConfigurationHashRepair(ctx context.Context, transaction database.Transaction, access database.AccessContext, workspaceID string) error {
	eventID, idErr := store.generatedID("aud_")
	if idErr != nil {
		return &Error{code: CodePersistence, cause: idErr}
	}
	if _, appendErr := store.audit.AppendInTransaction(ctx, access, transaction,
		configurationHashRepairAuditEvent(eventID, workspaceID, access.PrincipalID, access.RequestID, store.now().UTC())); appendErr != nil {
		return &Error{code: CodePersistence, cause: appendErr}
	}
	return nil
}

// configurationHashRepairAuditEvent builds the one content-free
// policy.decision SUCCESS event that records an audited configuration-hash
// repair. It carries only the server-generated event id, the workspace id, the
// caller's organization/principal ids, the request id and the closed reason
// code; it never carries the stored or recomputed hash or any workspace
// content. mutate appends it inside the same publication transaction that
// persists the corrected revision, so a repair can never be committed without
// its audit event. Keeping the construction pure lets the unit test prove the
// journal shape without a database.
func configurationHashRepairAuditEvent(eventID, workspaceID, actorID, requestID string, occurredAt time.Time) audit.EventInput {
	return audit.EventInput{
		EventID: eventID, WorkspaceID: &workspaceID, ActorType: audit.ActorHuman,
		ActorPrincipalID: &actorID, Action: audit.ActionPolicyDecision, ResourceType: audit.ResourcePolicy,
		ResourceID: workspaceID, RequestID: requestID, Outcome: audit.OutcomeSuccess,
		Metadata: audit.Metadata{ReasonCodes: []string{SummaryDegradedReasonConfigurationHashStale}},
		OccurredAt: occurredAt,
	}
}

func advanceSnapshot(ctx context.Context, transaction database.Transaction, current, next workspace.Snapshot, hash, actorID string) error {
	if next.Revision != current.Revision+1 || next.OrganizationID != current.OrganizationID || next.ID != current.ID {
		return &Error{code: CodePersistence}
	}
	tag, err := transaction.Exec(ctx, `
		UPDATE public.workspace
		SET name = $3, description = $4, status = $5, owner_principal_id = $6,
		    current_revision = $7, retention_policy_id = NULLIF($8, ''), updated_at = transaction_timestamp()
		WHERE organization_id = $1 AND id = $2 AND current_revision = $9
	`, next.OrganizationID, next.ID, next.Name, next.Description, string(next.Status), next.OwnerPrincipalID, next.Revision, next.RetentionPolicyID, current.Revision)
	if err != nil || tag.RowsAffected() != 1 {
		return &Error{code: CodePersistence, cause: err}
	}
	if _, err := transaction.Exec(ctx, `
		INSERT INTO public.workspace_revision (
			organization_id, workspace_id, revision, configuration_hash, created_by
		) VALUES ($1, $2, $3, $4, $5)
	`, next.OrganizationID, next.ID, next.Revision, hash, actorID); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func activePrincipal(ctx context.Context, transaction database.Transaction, organizationID, principalID string) (bool, error) {
	var status string
	err := transaction.QueryRow(ctx, `
		SELECT status
		FROM public.principal
		WHERE organization_id = $1 AND id = $2
		FOR SHARE
	`, organizationID, principalID).Scan(&status)
	if database.IsNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return status == string(policy.PrincipalActive), nil
}

func closeMembership(ctx context.Context, transaction database.Transaction, organizationID, workspaceID, principalID string, revision int64) (string, error) {
	var membershipID string
	err := transaction.QueryRow(ctx, `
		UPDATE public.workspace_member
		SET valid_to_revision = $4, removed_at = transaction_timestamp()
		WHERE organization_id = $1 AND workspace_id = $2 AND principal_id = $3 AND removed_at IS NULL
		RETURNING id
	`, organizationID, workspaceID, principalID, revision).Scan(&membershipID)
	if err != nil {
		return "", &Error{code: CodePersistence, cause: err}
	}
	return membershipID, nil
}

func insertMembership(ctx context.Context, transaction database.Transaction, membershipID, organizationID, workspaceID, principalID string, role workspace.Role, revision int64, actorID string) error {
	_, err := transaction.Exec(ctx, `
		INSERT INTO public.workspace_member (
			id, organization_id, workspace_id, principal_id, role, valid_from_revision, added_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, membershipID, organizationID, workspaceID, principalID, string(role), revision, actorID)
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	return nil
}

func initialSnapshot(organizationID, principalID, workspaceID string, request CreateRequest) (workspace.Snapshot, string, error) {
	snapshot, err := workspace.Normalize(workspace.Snapshot{
		OrganizationID: organizationID, ID: workspaceID, Revision: 1, Name: request.Name, Description: request.Description,
		Status: workspace.StatusActive, OwnerPrincipalID: principalID, RetentionPolicyID: request.RetentionPolicyID,
		Members: []workspace.Member{{PrincipalID: principalID, Role: workspace.RoleOwner}}, SourceBindings: []workspace.SourceBinding{},
	})
	if err != nil {
		return workspace.Snapshot{}, "", err
	}
	hash, err := workspace.ConfigurationHash(snapshot)
	if err != nil {
		return workspace.Snapshot{}, "", err
	}
	return snapshot, hash, nil
}

func currentActor(ctx context.Context, transaction database.Transaction, access database.AccessContext, lock bool) (policy.Subject, policy.Organization, bool, error) {
	query := `
		SELECT organization.status, principal.status, principal.session_revision
		FROM public.organization AS organization
		JOIN public.principal AS principal
		  ON principal.organization_id = organization.id
		WHERE organization.id = $1 AND principal.id = $2
	`
	if lock {
		query += " FOR SHARE OF organization, principal"
	}
	var organizationStatus, principalStatus string
	var sessionRevision int64
	if err := transaction.QueryRow(ctx, query, access.OrganizationID, access.PrincipalID).Scan(&organizationStatus, &principalStatus, &sessionRevision); err != nil {
		if database.IsNotFound(err) {
			return policy.Subject{}, policy.Organization{}, false, nil
		}
		return policy.Subject{}, policy.Organization{}, false, err
	}

	rolesQuery := `
		SELECT role
		FROM public.organization_role_assignment
		WHERE organization_id = $1 AND principal_id = $2 AND revoked_at IS NULL
		ORDER BY role
	`
	if lock {
		rolesQuery += " FOR SHARE"
	}
	rows, err := transaction.Query(ctx, rolesQuery, access.OrganizationID, access.PrincipalID)
	if err != nil {
		return policy.Subject{}, policy.Organization{}, false, err
	}
	defer rows.Close()
	roles := []policy.OrganizationRole{}
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return policy.Subject{}, policy.Organization{}, false, err
		}
		roles = append(roles, policy.OrganizationRole(role))
	}
	if err := rows.Err(); err != nil {
		return policy.Subject{}, policy.Organization{}, false, err
	}
	return policy.Subject{
		OrganizationID: access.OrganizationID, PrincipalID: access.PrincipalID, Status: policy.PrincipalStatus(principalStatus),
		SessionRevision: sessionRevision, OrganizationRoles: roles,
	}, policy.Organization{ID: access.OrganizationID, Status: policy.OrganizationStatus(organizationStatus)}, true, nil
}

func loadCurrentSnapshot(ctx context.Context, transaction database.Transaction, organizationID, workspaceID string, lock bool) (workspace.Snapshot, string, []revisionSourceProjection, bool, error) {
	var snapshot workspace.Snapshot
	var hash string
	var canonical []byte
	var lockedRevision int64
	if lock {
		// Lock the mutable serialization point in its own statement. Under
		// READ COMMITTED a joined SELECT ... FOR UPDATE can begin with a stale
		// statement snapshot, wait for another command, and then fail its joins
		// after the workspace pointer advances. A fresh second statement sees
		// the committed pointer and turns a concurrent command into an exact
		// revision precondition failure rather than a false NOT_FOUND.
		err := transaction.QueryRow(ctx, `
			SELECT current_revision
			FROM public.workspace
			WHERE organization_id = $1 AND id = $2
			FOR UPDATE
		`, organizationID, workspaceID).Scan(&lockedRevision)
		if database.IsNotFound(err) {
			return workspace.Snapshot{}, "", nil, false, nil
		}
		if err != nil {
			return workspace.Snapshot{}, "", nil, false, err
		}
		var currentlyVisible bool
		if err := transaction.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM public.workspace_member
				WHERE organization_id = $1
				  AND workspace_id = $2
				  AND principal_id = app.current_principal_id()
				  AND removed_at IS NULL
			)
		`, organizationID, workspaceID).Scan(&currentlyVisible); err != nil {
			return workspace.Snapshot{}, "", nil, false, err
		}
		if !currentlyVisible {
			// The tenant row is deliberately broader than content visibility.
			// Do not turn the serialization barrier into an existence oracle.
			return workspace.Snapshot{}, "", nil, false, nil
		}
	}
	query := `
		SELECT workspace.organization_id, workspace.id, workspace.current_revision,
		       workspace.name, workspace.description, workspace.status, workspace.owner_principal_id,
		       COALESCE(workspace.retention_policy_id, ''), revision.configuration_hash,
		       revision_snapshot.canonical_bytes
		FROM public.workspace
		JOIN public.workspace_revision AS revision
		  ON revision.organization_id = workspace.organization_id
		 AND revision.workspace_id = workspace.id
		 AND revision.revision = workspace.current_revision
		JOIN public.workspace_revision_snapshot AS revision_snapshot
		  ON revision_snapshot.organization_id = revision.organization_id
		 AND revision_snapshot.workspace_id = revision.workspace_id
		 AND revision_snapshot.revision = revision.revision
		 AND revision_snapshot.configuration_hash = revision.configuration_hash
		WHERE workspace.organization_id = $1 AND workspace.id = $2
	`
	if lock {
		query += " AND workspace.current_revision = $3"
	}
	arguments := []any{organizationID, workspaceID}
	if lock {
		arguments = append(arguments, lockedRevision)
	}
	err := transaction.QueryRow(ctx, query, arguments...).Scan(
		&snapshot.OrganizationID, &snapshot.ID, &snapshot.Revision, &snapshot.Name, &snapshot.Description,
		&snapshot.Status, &snapshot.OwnerPrincipalID, &snapshot.RetentionPolicyID, &hash, &canonical,
	)
	if database.IsNotFound(err) {
		if lock {
			// The locked workspace cannot disappear or change its pointer inside
			// this transaction; a missing exact revision is integrity failure.
			return workspace.Snapshot{}, "", nil, false, &Error{code: CodePersistence}
		}
		return workspace.Snapshot{}, "", nil, false, nil
	}
	if err != nil {
		return workspace.Snapshot{}, "", nil, false, err
	}
	membersQuery := `
		SELECT member.principal_id, member.role, principal.display_name
		FROM public.workspace_member AS member
		JOIN public.principal AS principal
		  ON principal.organization_id = member.organization_id
		 AND principal.id = member.principal_id
		WHERE member.organization_id = $1 AND member.workspace_id = $2 AND member.removed_at IS NULL
		ORDER BY member.principal_id
	`
	if lock {
		membersQuery += " FOR UPDATE OF member"
	}
	rows, err := transaction.Query(ctx, membersQuery, organizationID, workspaceID)
	if err != nil {
		return workspace.Snapshot{}, "", nil, false, err
	}
	for rows.Next() {
		var member workspace.Member
		if err := rows.Scan(&member.PrincipalID, &member.Role, &member.DisplayName); err != nil {
			rows.Close()
			return workspace.Snapshot{}, "", nil, false, err
		}
		snapshot.Members = append(snapshot.Members, member)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return workspace.Snapshot{}, "", nil, false, err
	}
	rows.Close()

	sourceRows, err := transaction.Query(ctx, `
		SELECT workspace_configuration_hash, workspace_source_id,
		       source_scope_id, source_scope_revision, scope_config_hash,
		       access_mode, enabled
		FROM public.workspace_revision_source
		WHERE organization_id = $1
		  AND workspace_id = $2
		  AND workspace_revision = $3
		ORDER BY source_scope_id
	`, organizationID, workspaceID, snapshot.Revision)
	if err != nil {
		return workspace.Snapshot{}, "", nil, false, err
	}
	projections := []revisionSourceProjection{}
	for sourceRows.Next() {
		var projection revisionSourceProjection
		if err := sourceRows.Scan(
			&projection.WorkspaceConfigurationHash, &projection.WorkspaceSourceID,
			&projection.SourceScopeID, &projection.SourceScopeRevision,
			&projection.ScopeConfigHash, &projection.AccessMode, &projection.Enabled,
		); err != nil {
			sourceRows.Close()
			return workspace.Snapshot{}, "", nil, false, err
		}
		projections = append(projections, projection)
		snapshot.SourceBindings = append(snapshot.SourceBindings, workspace.SourceBinding{
			SourceScopeID: projection.SourceScopeID, SourceScopeRevision: projection.SourceScopeRevision,
			ScopeConfigHash: projection.ScopeConfigHash, Enabled: projection.Enabled,
		})
	}
	if err := sourceRows.Err(); err != nil {
		sourceRows.Close()
		return workspace.Snapshot{}, "", nil, false, err
	}
	sourceRows.Close()

	normalized, err := workspace.Normalize(snapshot)
	if err != nil {
		return workspace.Snapshot{}, "", nil, false, &Error{code: CodePersistence, cause: err}
	}
	canonicalSnapshot, err := workspace.ParseCanonicalSnapshot(canonical)
	if err != nil || !sourceProjectionMatchesSnapshot(projections, normalized, hash) {
		return workspace.Snapshot{}, "", nil, false, &Error{code: CodePersistence, cause: err}
	}
	loadedCanonical, err := workspace.CanonicalSnapshot(canonicalSnapshot)
	if err != nil || !bytes.Equal(loadedCanonical, canonical) {
		return workspace.Snapshot{}, "", nil, false, &Error{code: CodePersistence, cause: err}
	}
	// The persisted revision artifact above must stay exactly canonical and
	// hash-verified, but the live workspace row may legitimately diverge from
	// it. Return the live snapshot with the stored hash so callers can detect
	// the stale configuration hash (12.09 acc2 guard) and mark the workspace
	// degraded instead of failing the whole read with CodePersistence.
	canonicalHash, err := workspace.ConfigurationHash(canonicalSnapshot)
	if err != nil || canonicalHash != hash {
		return workspace.Snapshot{}, "", nil, false, &Error{code: CodePersistence, cause: err}
	}
	return normalized, hash, projections, true, nil
}

// hydrateMemberDisplayNames projects current same-organization principal
// names onto a snapshot after a write or an idempotent replay. The lookup is
// intentionally one bounded query for the whole member set and follows the
// snapshot's exact principal IDs, so historical command replays remain valid
// after later membership changes. Display names are live metadata and are
// never persisted in workspace-configuration-v1.
func hydrateMemberDisplayNames(ctx context.Context, transaction database.Transaction, snapshot *workspace.Snapshot) error {
	if snapshot == nil {
		return &Error{code: CodePersistence}
	}
	if len(snapshot.Members) == 0 {
		return nil
	}
	principalIDs := make([]string, len(snapshot.Members))
	for index, member := range snapshot.Members {
		principalIDs[index] = member.PrincipalID
	}
	rows, err := transaction.Query(ctx, `
		SELECT principal.id, principal.display_name
		FROM public.principal AS principal
		WHERE principal.organization_id = $1 AND principal.id = ANY($2::text[])
		ORDER BY principal.id
	`, snapshot.OrganizationID, principalIDs)
	if err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	defer rows.Close()
	names := make(map[string]string, len(snapshot.Members))
	for rows.Next() {
		var principalID, displayName string
		if err := rows.Scan(&principalID, &displayName); err != nil {
			return &Error{code: CodePersistence, cause: err}
		}
		if _, exists := names[principalID]; exists {
			return &Error{code: CodePersistence}
		}
		names[principalID] = displayName
	}
	if err := rows.Err(); err != nil {
		return &Error{code: CodePersistence, cause: err}
	}
	if len(names) != len(snapshot.Members) {
		return &Error{code: CodePersistence}
	}
	for index := range snapshot.Members {
		displayName, exists := names[snapshot.Members[index].PrincipalID]
		if !exists {
			return &Error{code: CodePersistence}
		}
		snapshot.Members[index].DisplayName = displayName
	}
	return nil
}

func sourceProjectionMatchesSnapshot(projections []revisionSourceProjection, snapshot workspace.Snapshot, configurationHash string) bool {
	if !sourceProjectionMatchesBindings(projections, snapshot) || !workspace.IsConfigurationHash(configurationHash) {
		return false
	}
	for _, projection := range projections {
		if projection.WorkspaceConfigurationHash != configurationHash {
			return false
		}
	}
	return true
}

func sourceProjectionMatchesBindings(projections []revisionSourceProjection, snapshot workspace.Snapshot) bool {
	if len(projections) != len(snapshot.SourceBindings) {
		return false
	}
	for index, projection := range projections {
		binding := snapshot.SourceBindings[index]
		if !workspace.IsConfigurationHash(projection.WorkspaceConfigurationHash) || !validID(projection.WorkspaceSourceID) ||
			(projection.AccessMode != "WORKSPACE_MANAGED" && projection.AccessMode != "SOURCE_ENFORCED") ||
			projection.SourceScopeID != binding.SourceScopeID || projection.SourceScopeRevision != binding.SourceScopeRevision ||
			projection.ScopeConfigHash != binding.ScopeConfigHash || projection.Enabled != binding.Enabled {
			return false
		}
	}
	return true
}

func carrySourceProjection(projections []revisionSourceProjection, next workspace.Snapshot, nextConfigurationHash string) ([]revisionSourceProjection, bool) {
	if !workspace.IsConfigurationHash(nextConfigurationHash) || !sourceProjectionMatchesBindings(projections, next) {
		return nil, false
	}
	carried := append([]revisionSourceProjection(nil), projections...)
	for index := range carried {
		carried[index].WorkspaceConfigurationHash = nextConfigurationHash
	}
	return carried, true
}

func currentMembership(snapshot workspace.Snapshot, principalID string) policy.Membership {
	for _, member := range snapshot.Members {
		if member.PrincipalID == principalID {
			return policy.Membership{Present: true, Role: policy.WorkspaceRole(member.Role)}
		}
	}
	return policy.Membership{}
}

func authorizeReplaySnapshot(ctx context.Context, transaction database.Transaction, subject policy.Subject, organization policy.Organization, original workspace.Snapshot) error {
	if organization.Status != policy.OrganizationActive || subject.OrganizationID != original.OrganizationID {
		return &Error{code: CodeNotFound}
	}
	current, hash, _, exists, err := loadCurrentSnapshot(ctx, transaction, original.OrganizationID, original.ID, false)
	if err != nil {
		return err
	}
	if !exists {
		return &Error{code: CodeNotFound}
	}
	computedHash, hashErr := workspace.ConfigurationHash(current)
	if replayHashErr := authorizeReplayConfigurationHash(hash, computedHash, hashErr); replayHashErr != nil {
		return replayHashErr
	}
	decision := policy.EvaluateWorkspace(policy.Request{
		Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
		Workspace:  policy.Workspace{OrganizationID: current.OrganizationID, ID: current.ID, Status: policy.WorkspaceStatus(current.Status)},
		Membership: currentMembership(current, subject.PrincipalID),
	})
	if !decision.Allowed {
		return &Error{code: CodeNotFound}
	}
	return nil
}

func isCommandResultError(err error) bool {
	var repositoryError *Error
	return errors.As(err, &repositoryError)
}

func (store *Store) appendDenied(ctx context.Context, transaction database.Transaction, access database.AccessContext, action audit.Action, resourceType audit.ResourceType, resourceID string, workspaceID *string, decision policy.Decision) (string, error) {
	eventID, err := store.newID("aud_")
	if err != nil {
		return "", err
	}
	actorID := access.PrincipalID
	errorCode := string(CodeDenied)
	reasonCodes := make([]string, len(decision.ReasonCodes))
	for index, reason := range decision.ReasonCodes {
		reasonCodes[index] = string(reason)
	}
	_, err = store.audit.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: eventID, WorkspaceID: workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID, RequestID: access.RequestID,
		Outcome: audit.OutcomeDenied, ErrorCode: &errorCode, Metadata: audit.Metadata{ReasonCodes: reasonCodes}, OccurredAt: store.now().UTC(),
	})
	return eventID, err
}

func (store *Store) appendFailed(ctx context.Context, transaction database.Transaction, access database.AccessContext, action audit.Action, resourceType audit.ResourceType, resourceID string, workspaceID *string, code ErrorCode) (string, error) {
	eventID, err := store.newID("aud_")
	if err != nil {
		return "", err
	}
	actorID := access.PrincipalID
	errorCode := string(code)
	_, err = store.audit.AppendInTransaction(ctx, access, transaction, audit.EventInput{
		EventID: eventID, WorkspaceID: workspaceID, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID, RequestID: access.RequestID,
		Outcome: audit.OutcomeFailed, ErrorCode: &errorCode, OccurredAt: store.now().UTC(),
	})
	return eventID, err
}

func (store *Store) newIDs(prefixes ...string) (string, string, string, error) {
	if len(prefixes) != 3 {
		return "", "", "", errors.New("invalid identifier request")
	}
	values := make([]string, len(prefixes))
	for index, prefix := range prefixes {
		value, err := store.newID(prefix)
		if err != nil || !validID(value) {
			if err == nil {
				err = errors.New("invalid generated identifier")
			}
			return "", "", "", err
		}
		values[index] = value
	}
	return values[0], values[1], values[2], nil
}

func (store *Store) generatedID(prefix string) (string, error) {
	if store == nil || store.newID == nil {
		return "", errors.New("identifier generator is unavailable")
	}
	value, err := store.newID(prefix)
	if err != nil || !validID(value) {
		if err == nil {
			err = errors.New("invalid generated identifier")
		}
		return "", err
	}
	return value, nil
}

func randomID(prefix string) (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(bytes), nil
}

func validID(value string) bool {
	if len(value) < 3 || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}
