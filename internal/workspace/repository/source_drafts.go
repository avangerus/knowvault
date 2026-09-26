package repository

// Card D-1: the workspace-scoped read and discard half of the PostgreSQL
// onboarding draft.
//
// Bootstrap (internal/source/registration, migration 000091) creates an
// immutable DRAFT connection revision and 000114 records which workspace
// started it. This file turns that pointer into the two operator-visible
// operations the Sources surface needs: list this workspace's unfinished
// connections with their derived state, and discard one pointer. It owns no
// source, trust or activation authority -- a discarded draft leaves the
// connection exactly where it was, and every row is re-read through the
// workspace-membership policy gate the other source metadata reads use.

import (
	"context"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
)

const sourceConnectionDraftListRead = "SOURCE_CONNECTION_DRAFT_LIST"

// The derived draft states: the wizard resumes at trust verification or at
// discovery, and nothing else is possible for a connection that has no scope
// and no active revision yet.
const (
	SourceConnectionDraftAwaitingTrust = "AWAITING_TRUST_VERIFICATION"
	SourceConnectionDraftReadyForDiscovery = "READY_FOR_DISCOVERY"
)

// SourceConnectionDraft is one unfinished source connection of the caller's
// own workspace. It carries only the content-free identifiers the wizard needs
// to resume and the two fields the Sources row displays.
type SourceConnectionDraft struct {
	ConnectionID       string
	ConnectionRevision int64
	ConnectionName     string
	SourceType         string
	TrustStatus        string
	State              string
	CreatedAt          time.Time
}

// ListSourceConnectionDrafts returns the caller's workspace's unfinished
// PostgreSQL connections. Authorization, auditing and the content-free denial
// are exactly those of ListSources: a non-member, an unknown workspace and a
// foreign workspace all resolve to the same CodeNotFound.
func (store *Store) ListSourceConnectionDrafts(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceConnectionDraft, error) {
	var result []SourceConnectionDraft
	err := store.sourceMetadataRead(ctx, access, workspaceID, sourceConnectionDraftListRead, func() error {
		var readErr error
		result, readErr = store.listSourceConnectionDrafts(ctx, access, workspaceID)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (store *Store) listSourceConnectionDrafts(ctx context.Context, access database.AccessContext, workspaceID string) ([]SourceConnectionDraft, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) {
		return nil, &Error{code: CodeRequestInvalid}
	}
	result := []SourceConnectionDraft{}
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
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceViewMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: currentMembership(snapshot, access.PrincipalID),
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		// The database read repeats the tenant and workspace-membership check
		// inside its own SECURITY DEFINER boundary, so a weakened application
		// gate still cannot expose a foreign workspace's draft.
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT connection_id, connection_revision, connection_name, source_type,
			       trust_status, state, created_at
			FROM app.source_connection_draft_list($1)`, workspaceID)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var draft SourceConnectionDraft
			if scanErr := rows.Scan(&draft.ConnectionID, &draft.ConnectionRevision, &draft.ConnectionName,
				&draft.SourceType, &draft.TrustStatus, &draft.State, &draft.CreatedAt); scanErr != nil {
				return scanErr
			}
			result = append(result, draft)
		}
		return rows.Err()
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return nil, err
		}
		return nil, &Error{code: CodePersistence, cause: err}
	}
	if denied || notFound {
		return nil, &Error{code: CodeNotFound}
	}
	return result, nil
}

// DiscardSourceConnectionDraft removes this workspace's pointer to an
// unfinished connection. It deletes no connection, revision, trust record or
// artifact: the control-plane lineage stays immutable, and only the
// workspace's own visibility of the draft changes. Denied and absent are one
// content-free CodeNotFound, exactly as the read above.
func (store *Store) DiscardSourceConnectionDraft(ctx context.Context, access database.AccessContext, workspaceID, connectionID string) error {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) || !validID(connectionID) {
		return &Error{code: CodeRequestInvalid}
	}
	denied := false
	notFound := false
	err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
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
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceManage, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: snapshot.OrganizationID, ID: snapshot.ID, Status: policy.WorkspaceStatus(snapshot.Status)},
			Membership: currentMembership(snapshot, access.PrincipalID),
		})
		if !decision.Allowed {
			denied = true
			return nil
		}
		var removed bool
		if err := transaction.QueryRow(transactionContext,
			`SELECT app.source_connection_draft_discard($1, $2)`, workspaceID, connectionID).Scan(&removed); err != nil {
			if database.SQLStateCode(err) == "42501" {
				denied = true
				return nil
			}
			return err
		}
		if !removed {
			notFound = true
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return err
		}
		return &Error{code: CodePersistence, cause: err}
	}
	if denied || notFound {
		return &Error{code: CodeNotFound}
	}
	return nil
}
