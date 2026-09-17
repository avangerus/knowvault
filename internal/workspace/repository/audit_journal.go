package repository

import (
	"context"
	"encoding/json"
	"strconv"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

// auditJournalPageSize is the only page boundary the journal surface offers.
// The transport route accepts at most one before_sequence cursor and no other
// filter, so the page size stays a server constant rather than a
// client-controlled limit.
const auditJournalPageSize = 100

// AuditJournal returns the latest page of the workspace-scoped audit stream
// through the audit.read_metadata policy gate (SECURITY_AUDITOR organization
// role or a current WORKSPACE_AUDITOR membership). The read itself is
// auditable: an allowed read and a policy denial are recorded as audit.viewed
// events in the same transaction, so a lawful journal read can never leave
// the stream untouched. Two branches end without an event by design — an
// unknown actor and an inactive organization — because no principal row
// exists for the audit event principal foreign key to reference. Absence and
// denial both surface as CodeNotFound with no existence oracle.
//
// AuditJournal is the legacy first-screen form: it reads the newest page and
// ignores any cursor. AuditJournalBefore is the narrow keyset-continuation
// capability; both share auditJournalPage so there is exactly one
// authorization, tenant and auditing implementation.
//
// The journal deliberately probes workspace existence through the
// tenant-scoped workspace row rather than the configuration snapshot:
// workspace_revision_snapshot row security hides snapshots from non-members,
// while the audit.read_metadata policy allows organization security auditors
// who hold no membership. The snapshot-gated probe would turn a lawful
// auditor read into a false not-found.
func (store *Store) AuditJournal(ctx context.Context, access database.AccessContext, workspaceID string) (audit.Journal, error) {
	return store.auditJournalPage(ctx, access, workspaceID, nil)
}

// AuditJournalBefore returns one older page of the same workspace-scoped audit
// stream: exactly the events with sequence < beforeSequence, newest first. It
// repeats the full audit.read_metadata and tenant/workspace gate on every
// call, because a continuation is a fresh authorized read, not a replay of a
// previously granted decision. beforeSequence is the cursor returned as
// next_before_sequence by the previous page; a non-positive cursor is a
// request error rather than a silently ignored argument.
func (store *Store) AuditJournalBefore(ctx context.Context, access database.AccessContext, workspaceID string, beforeSequence int64) (audit.Journal, error) {
	if beforeSequence <= 0 {
		return audit.Journal{}, &Error{code: CodeRequestInvalid}
	}
	return store.auditJournalPage(ctx, access, workspaceID, &beforeSequence)
}

func (store *Store) auditJournalPage(ctx context.Context, access database.AccessContext, workspaceID string, beforeSequence *int64) (audit.Journal, error) {
	if store == nil || store.database == nil || store.audit == nil || access.Validate() != nil || !validID(workspaceID) {
		return audit.Journal{}, &Error{code: CodeRequestInvalid}
	}
	result := audit.Journal{Events: []audit.JournalEntry{}}
	denied := false
	err := store.database.Write(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		target, exists, targetErr := loadJournalTarget(transactionContext, transaction, access.OrganizationID, workspaceID)
		if targetErr != nil {
			return targetErr
		}
		if !exists {
			// The workspace row is not visible in this tenant, so an event
			// carrying its workspace_id would violate the audit event foreign
			// key. The refusal is recorded organization-scoped with the opaque
			// id as the resource id instead.
			if _, appendErr := store.appendDenied(transactionContext, transaction, access, audit.ActionAuditViewed, audit.ResourceWorkspace, workspaceID, nil, policy.Decision{ReasonCodes: []policy.ReasonCode{policy.ReasonWorkspaceMembershipAbsent}}); appendErr != nil {
				return appendErr
			}
			denied = true
			return nil
		}
		probe := workspace.Snapshot{OrganizationID: target.OrganizationID, ID: target.ID, Status: target.Status, Members: target.Members}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationAuditReadMetadata, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: target.OrganizationID, ID: target.ID, Status: policy.WorkspaceStatus(target.Status)},
			Membership: currentMembership(probe, access.PrincipalID),
		})
		if !decision.Allowed {
			workspaceIDForEvent := target.ID
			if _, appendErr := store.appendDenied(transactionContext, transaction, access, audit.ActionAuditViewed, audit.ResourceWorkspace, target.ID, &workspaceIDForEvent, decision); appendErr != nil {
				return appendErr
			}
			denied = true
			return nil
		}

		if err := transaction.QueryRow(transactionContext, `
			SELECT last_sequence, last_event_hash
			FROM public.audit_chain_head
			WHERE organization_id = $1
		`, access.OrganizationID).Scan(&result.HeadSequence, &result.HeadHash); err != nil {
			return err
		}
		// The keyset predicate is a strict less-than on the organization-wide
		// sequence: sequences are unique per organization, so the cursor is
		// unambiguous even when several events share an occurred_at. The
		// cursor is never turned into a float and the query never uses OFFSET
		// or loads the whole stream. Content-read denials deliberately carry no
		// workspace FK: an unknown and a forbidden workspace must look alike to
		// the requester. Their closed contract names the attempted workspace in
		// resource_id. Include only that exact denial shape after the existing
		// live workspace/auditor gate, without rewriting the immutable event or
		// exposing any other organization-scoped events.
		query := `
			SELECT id, sequence, actor_type, actor_principal_id, on_behalf_of_principal_id,
			       action, resource_type, resource_id, request_id, policy_decision_id,
			       outcome, error_code, referenced_evidence_ids_json, metadata_json,
			       previous_event_hash, event_hash, occurred_at
			FROM public.audit_event
			WHERE organization_id = $1 AND (
				workspace_id = $2 OR (
					workspace_id IS NULL AND resource_id = $2
					AND action = 'evidence.read.admitted' AND resource_type = 'CITATION'
					AND outcome = 'DENIED'
					AND error_code IN ('WORKSPACE_OBJECT_DENIED', 'WORKSPACE_OBJECTS_DENIED', 'WORKSPACE_SEARCH_DENIED')
				)
			)`
		args := []any{access.OrganizationID, target.ID}
		if beforeSequence != nil {
			query += ` AND sequence < $3`
			args = append(args, *beforeSequence)
		}
		query += ` ORDER BY sequence DESC LIMIT $` + strconv.Itoa(len(args)+1)
		args = append(args, auditJournalPageSize+1)
		rows, queryErr := transaction.Query(transactionContext, query, args...)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var entry audit.JournalEntry
			var actorType, action, resourceType, outcome string
			var evidenceJSON, metadataJSON []byte
			if scanErr := rows.Scan(&entry.EventID, &entry.Sequence, &actorType, &entry.ActorPrincipalID, &entry.OnBehalfOfPrincipalID,
				&action, &resourceType, &entry.ResourceID, &entry.RequestID, &entry.PolicyDecisionID,
				&outcome, &entry.ErrorCode, &evidenceJSON, &metadataJSON,
				&entry.PreviousEventHash, &entry.EventHash, &entry.OccurredAt); scanErr != nil {
				return scanErr
			}
			entry.ActorType = audit.ActorType(actorType)
			entry.Action = audit.Action(action)
			entry.ResourceType = audit.ResourceType(resourceType)
			entry.Outcome = audit.Outcome(outcome)
			if unmarshalErr := json.Unmarshal(evidenceJSON, &entry.ReferencedEvidenceIDs); unmarshalErr != nil {
				return unmarshalErr
			}
			if unmarshalErr := json.Unmarshal(metadataJSON, &entry.Metadata); unmarshalErr != nil {
				return unmarshalErr
			}
			result.Events = append(result.Events, entry)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		// The page boundary is a server constant; reading one row beyond it
		// turns the boundary into data: Truncated tells the surface that the
		// stream continues below this page, and the sequence of the last
		// returned entry becomes the continuation cursor. A page with no
		// continuation leaves the cursor unset, including an empty tail.
		if int64(len(result.Events)) > auditJournalPageSize {
			result.Events = result.Events[:auditJournalPageSize]
			result.Truncated = true
			cursor := result.Events[len(result.Events)-1].Sequence
			result.NextBeforeSequence = &cursor
		}

		eventID, idErr := store.newID("aud_")
		if idErr != nil {
			return idErr
		}
		actorID := access.PrincipalID
		workspaceIDForEvent := target.ID
		if _, appendErr := store.audit.AppendInTransaction(transactionContext, access, transaction, audit.EventInput{
			EventID: eventID, WorkspaceID: &workspaceIDForEvent, ActorType: audit.ActorHuman, ActorPrincipalID: &actorID,
			Action: audit.ActionAuditViewed, ResourceType: audit.ResourceWorkspace, ResourceID: target.ID,
			RequestID: access.RequestID, Outcome: audit.OutcomeSuccess, OccurredAt: store.now().UTC(),
		}); appendErr != nil {
			return appendErr
		}
		result.WorkspaceID = target.ID
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return audit.Journal{}, err
		}
		return audit.Journal{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return audit.Journal{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// journalTarget is the membership-independent workspace projection the audit
// journal needs: tenant-scoped identity, status, and the member set for the
// policy membership leg. It is deliberately not the configuration snapshot —
// the journal must stay readable to organization security auditors with no
// workspace membership, while snapshot row security binds snapshot visibility
// to membership. The tenant row is broader than content visibility by design.
type journalTarget struct {
	OrganizationID string
	ID             string
	Status         workspace.Status
	Members        []workspace.Member
}

// loadJournalTarget resolves the journal target through the tenant-scoped
// workspace and workspace_member relations. Both are visible to every
// principal of the organization under row security, which is exactly the
// visibility the audit.read_metadata policy operates on: the policy, not the
// snapshot gate, decides whether a reader may see the workspace-scoped stream.
// A workspace invisible in this tenant yields exists=false with no error, so
// absence stays indistinguishable from denial.
func loadJournalTarget(ctx context.Context, transaction database.Transaction, organizationID, workspaceID string) (journalTarget, bool, error) {
	var target journalTarget
	err := transaction.QueryRow(ctx, `
		SELECT organization_id, id, status
		FROM public.workspace
		WHERE organization_id = $1 AND id = $2
	`, organizationID, workspaceID).Scan(&target.OrganizationID, &target.ID, &target.Status)
	if database.IsNotFound(err) {
		return journalTarget{}, false, nil
	}
	if err != nil {
		return journalTarget{}, false, err
	}
	rows, err := transaction.Query(ctx, `
		SELECT principal_id, role
		FROM public.workspace_member
		WHERE organization_id = $1 AND workspace_id = $2 AND removed_at IS NULL
		ORDER BY principal_id
	`, organizationID, workspaceID)
	if err != nil {
		return journalTarget{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var member workspace.Member
		if err := rows.Scan(&member.PrincipalID, &member.Role); err != nil {
			return journalTarget{}, false, err
		}
		target.Members = append(target.Members, member)
	}
	if err := rows.Err(); err != nil {
		return journalTarget{}, false, err
	}
	return target, true, nil
}
