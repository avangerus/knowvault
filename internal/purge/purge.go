// Package purge is the privileged control-plane owner of source-derived
// retention purge. It orchestrates the fenced state machine in migration 000015:
// a fail-close transition that makes a SourceVersion and its Evidence inaccessible
// and advances the retention fence, an idempotently resumable physical cleanup of
// the encrypted artifacts, and a completion that reaches PURGED only when nothing
// resurrectable remains. Every state transition leaves one content-free audit
// event in the same transaction as the change.
//
// The package holds no ambient authority: it runs as the trusted knowvault_purger
// role, the only role granted EXECUTE on the SECURITY DEFINER purge functions, and
// it names the exact tenant and version. Neither the web/API runtime nor the sync
// worker can reach these functions.
package purge

import (
	"context"
	"errors"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// Purger orchestrates the retention purge phases for one privileged caller.
type Purger struct {
	db    *database.Store
	audit *audit.Store
	now   func() time.Time
	newID func(string) (string, error)
}

// NewPurger wires a purger over a store opened as the knowvault_purger role.
func NewPurger(db *database.Store, now func() time.Time, newID func(string) (string, error)) (*Purger, error) {
	auditStore, err := audit.NewStore(db)
	if err != nil {
		return nil, err
	}
	return &Purger{db: db, audit: auditStore, now: now, newID: newID}, nil
}

// BeginPurge runs the single-transaction fail-close ACTIVE -> PURGING: it reads
// the current fence and hands it to the SECURITY DEFINER function as a CAS, so a
// version whose retention already moved cannot be purged under a stale view. The
// content becomes inaccessible and the fence advances before this transaction
// commits; the audit event is written in the same transaction. It returns the new
// fence.
func (p *Purger) BeginPurge(ctx context.Context, access database.AccessContext, versionID, reason string) (int64, error) {
	var newFence int64
	err := p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var fence int64
		var state string
		if err := tx.QueryRow(ctx, `SELECT retention_fence, state FROM public.source_version_retention
			WHERE organization_id=$1 AND source_version_id=$2`, access.OrganizationID, versionID).Scan(&fence, &state); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT app.source_version_begin_purge($1, $2, $3, $4)`,
			access.OrganizationID, versionID, reason, fence).Scan(&newFence); err != nil {
			return err
		}
		return p.appendPurgeAudit(ctx, access, tx, audit.ActionSourceVersionPurging, versionID, reason)
	})
	return newFence, err
}

// Cleanup irreversibly forgets the decryptable Evidence artifacts of the version.
// It is a consequence of a committed fail-close, is idempotent, and is safely
// resumable after a crash. It returns how many artifacts it purged this call.
func (p *Purger) Cleanup(ctx context.Context, access database.AccessContext, versionID string) (int64, error) {
	var purged int64
	err := p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		// A source-version purge also owns the external search projection.  Queue
		// one deterministic DELETE per SearchChunk before erasing its ciphertext;
		// the worker will execute the network mutation and publish the event in
		// tenant sequence order.  The SQL helper is idempotent, so a crash/retry
		// cannot create duplicate delete events for the same chunk.
		rows, err := tx.Query(ctx, `SELECT search_chunk_id FROM app.search_chunk_ids_for_purge($1)`, versionID)
		if err != nil {
			return err
		}
		var chunkIDs []string
		for rows.Next() {
			var chunkID string
			if err := rows.Scan(&chunkID); err != nil {
				rows.Close()
				return err
			}
			chunkIDs = append(chunkIDs, chunkID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if p.newID == nil {
			return errors.New("purge: search delete id generator unavailable")
		}
		for _, chunkID := range chunkIDs {
			eventID, err := p.newID("searchdel")
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `SELECT app.enqueue_search_chunk_delete($1, $2, $3)`, eventID, chunkID, versionID); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT app.source_version_purge_cleanup($1, $2)`,
			access.OrganizationID, versionID).Scan(&purged)
	})
	return purged, err
}

// CompletePurge runs the PURGING -> PURGED transition, which the SECURITY DEFINER
// function permits only when no decryptable artifact, active pointer or running
// job of the version remains. The audit event is written in the same transaction.
func (p *Purger) CompletePurge(ctx context.Context, access database.AccessContext, versionID, reason string) error {
	return p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.source_version_complete_purge($1, $2)`,
			access.OrganizationID, versionID); err != nil {
			return err
		}
		return p.appendPurgeAudit(ctx, access, tx, audit.ActionSourceVersionPurged, versionID, reason)
	})
}

// BeginConversationPurge runs the conversation retention fail-close.  The
// workspace and conversation ids are explicit inputs to the fenced database
// function; no caller-provided SQL or model-generated selector participates in
// the operation.  Conversation content is still physically present after this
// commit, but every REST/MCP disclosure gate is closed before cleanup starts.
func (p *Purger) BeginConversationPurge(ctx context.Context, access database.AccessContext,
	workspaceID, conversationID, reason string) (int64, error) {
	var newFence int64
	err := p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var fence int64
		var state string
		if err := tx.QueryRow(ctx, `SELECT retention_fence, state
			FROM public.conversation_retention
			WHERE organization_id=$1 AND workspace_id=$2 AND conversation_id=$3`,
			access.OrganizationID, workspaceID, conversationID).Scan(&fence, &state); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT app.conversation_begin_purge($1, $2, $3, $4, $5)`,
			access.OrganizationID, workspaceID, conversationID, reason, fence).Scan(&newFence); err != nil {
			return err
		}
		return p.appendConversationPurgeAudit(ctx, access, tx, audit.ActionConversationPurging,
			workspaceID, conversationID, reason)
	})
	return newFence, err
}

// CompleteConversationPurge irreversibly erases every encrypted artifact
// owned by a conversation's Question Runs, citations and authorized-candidate
// snapshot, then closes the conversation retention state.  It is resumable:
// a retry after the terminal transition returns success without appending a
// duplicate audit event.
func (p *Purger) CompleteConversationPurge(ctx context.Context, access database.AccessContext,
	workspaceID, conversationID, reason string) (int64, error) {
	var purged int64
	err := p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state
			FROM public.conversation_retention
			WHERE organization_id=$1 AND workspace_id=$2 AND conversation_id=$3
			FOR UPDATE`,
			access.OrganizationID, workspaceID, conversationID).Scan(&state); err != nil {
			return err
		}
		if state == "PURGED" {
			return nil
		}
		if err := tx.QueryRow(ctx, `SELECT app.conversation_purge_cleanup($1, $2, $3)`,
			access.OrganizationID, workspaceID, conversationID).Scan(&purged); err != nil {
			return err
		}
		return p.appendConversationPurgeAudit(ctx, access, tx, audit.ActionConversationPurged,
			workspaceID, conversationID, reason)
	})
	return purged, err
}

// ProcessNextConversationPurge leases one queued request and drives the
// existing fenced retention authority to completion.  A retry after a crash
// observes PURGING and resumes cleanup; it never attempts to reopen a fence.
// The queue is deliberately separate from the retention functions so a lease
// expiry can re-deliver work without weakening the data lifecycle.
func (p *Purger) ProcessNextConversationPurge(ctx context.Context, access database.AccessContext,
	queue *Queue, workerID string, leaseSeconds int) (bool, error) {
	if queue == nil {
		return false, &QueueError{code: QueueCodeInvalid}
	}
	request, found, err := queue.Claim(ctx, access, workerID, leaseSeconds)
	if err != nil || !found {
		return found, err
	}

	// Refresh the lease immediately after claim.  Long-running deployments may
	// call Heartbeat again around connector/network work; every call remains
	// fenced by the exact epoch returned here.
	if err := queue.Heartbeat(ctx, access, request.ID, workerID, request.LeaseEpoch, leaseSeconds); err != nil {
		return true, err
	}

	state, err := p.conversationRetentionState(ctx, access, request.WorkspaceID, request.ConversationID)
	if err != nil {
		return true, p.failQueuedConversationPurge(ctx, access, queue, request, workerID, err)
	}
	switch state {
	case "ACTIVE":
		if _, err := p.BeginConversationPurge(ctx, access, request.WorkspaceID, request.ConversationID, request.ReasonCode); err != nil {
			return true, p.failQueuedConversationPurge(ctx, access, queue, request, workerID, err)
		}
		state = "PURGING"
	case "PURGING":
		// A previous attempt committed the disclosure fence; resume cleanup.
	case "PURGED":
		// The data authority is already terminal; only the queue receipt remains.
	default:
		return true, p.failQueuedConversationPurge(ctx, access, queue, request, workerID, errors.New("purge retention state unavailable"))
	}

	if state == "PURGING" {
		if _, err := p.CompleteConversationPurge(ctx, access, request.WorkspaceID, request.ConversationID, request.ReasonCode); err != nil {
			return true, p.failQueuedConversationPurge(ctx, access, queue, request, workerID, err)
		}
	}
	if err := queue.Complete(ctx, access, request.ID, workerID, request.LeaseEpoch); err != nil {
		return true, err
	}
	return true, nil
}

// ProcessNextSourceVersionPurge leases one trusted source-version request and
// drives the existing fenced source retention authority to completion. A retry
// after a crash observes PURGING and resumes cleanup; it never reopens a
// retention fence. The source queue is separate from the generic worker jobs so
// knowvault_worker cannot acquire purge authority accidentally.
func (p *Purger) ProcessNextSourceVersionPurge(ctx context.Context, access database.AccessContext,
	queue *SourceQueue, workerID string, leaseSeconds int) (bool, error) {
	if queue == nil {
		return false, &QueueError{code: QueueCodeInvalid}
	}
	request, found, err := queue.Claim(ctx, access, workerID, leaseSeconds)
	if err != nil || !found {
		return found, err
	}
	if err := queue.Heartbeat(ctx, access, request.ID, workerID, request.LeaseEpoch, leaseSeconds); err != nil {
		return true, err
	}

	state, err := p.sourceVersionRetentionState(ctx, access, request.SourceVersion)
	if err != nil {
		return true, p.failQueuedSourceVersionPurge(ctx, access, queue, request, workerID, err)
	}
	switch state {
	case "ACTIVE":
		if _, err := p.BeginPurge(ctx, access, request.SourceVersion, request.ReasonCode); err != nil {
			return true, p.failQueuedSourceVersionPurge(ctx, access, queue, request, workerID, err)
		}
		state = "PURGING"
	case "PURGING":
		// The fail-close committed on a previous attempt; continue cleanup.
	case "PURGED":
		// The data authority is terminal; only the queue receipt remains.
	default:
		return true, p.failQueuedSourceVersionPurge(ctx, access, queue, request, workerID,
			errors.New("purge retention state unavailable"))
	}

	if state == "PURGING" {
		if _, err := p.Cleanup(ctx, access, request.SourceVersion); err != nil {
			return true, p.failQueuedSourceVersionPurge(ctx, access, queue, request, workerID, err)
		}
		if err := p.CompletePurge(ctx, access, request.SourceVersion, request.ReasonCode); err != nil {
			return true, p.failQueuedSourceVersionPurge(ctx, access, queue, request, workerID, err)
		}
	}
	if err := queue.Complete(ctx, access, request.ID, workerID, request.LeaseEpoch); err != nil {
		return true, err
	}
	return true, nil
}

func (p *Purger) sourceVersionRetentionState(ctx context.Context, access database.AccessContext,
	versionID string) (string, error) {
	var state string
	err := p.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT state FROM public.source_version_retention
			WHERE organization_id=$1 AND source_version_id=$2`,
			access.OrganizationID, versionID).Scan(&state)
	})
	return state, err
}

func (p *Purger) failQueuedSourceVersionPurge(ctx context.Context, access database.AccessContext,
	queue *SourceQueue, request SourceRequest, workerID string, cause error) error {
	if err := queue.Fail(ctx, access, request.ID, workerID, request.LeaseEpoch, "PURGE_EXECUTION_FAILED", 0); err != nil {
		return err
	}
	return cause
}

func (p *Purger) conversationRetentionState(ctx context.Context, access database.AccessContext,
	workspaceID, conversationID string) (string, error) {
	var state string
	err := p.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT state FROM public.conversation_retention
			WHERE organization_id=$1 AND workspace_id=$2 AND conversation_id=$3`,
			access.OrganizationID, workspaceID, conversationID).Scan(&state)
	})
	return state, err
}

func (p *Purger) failQueuedConversationPurge(ctx context.Context, access database.AccessContext,
	queue *Queue, request Request, workerID string, cause error) error {
	// The caller receives the safe queue code; the database error and retention
	// details remain private to the trusted process.  The fixed code is part of
	// the closed operational vocabulary and is retryable until max_attempts.
	if err := queue.Fail(ctx, access, request.ID, workerID, request.LeaseEpoch, "PURGE_EXECUTION_FAILED", 0); err != nil {
		return err
	}
	return cause
}

func (p *Purger) appendConversationPurgeAudit(ctx context.Context, access database.AccessContext,
	tx database.Transaction, action audit.Action, workspaceID, conversationID, reason string) error {
	eventID, err := p.newID("audit")
	if err != nil {
		return err
	}
	workspace := workspaceID
	_, err = p.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorSystem,
		Action: action, ResourceType: audit.ResourceConversation, ResourceID: conversationID,
		RequestID: access.RequestID, Outcome: audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{}, OccurredAt: p.now().UTC(),
		Metadata: audit.Metadata{ReasonCodes: []string{reason}},
	})
	return err
}

// appendPurgeAudit appends one content-free purge audit event: a SYSTEM actor, the
// exact version id on the SOURCE_OBJECT resource type, the reason as a safe code,
// and no path, title or content.
func (p *Purger) appendPurgeAudit(ctx context.Context, access database.AccessContext, tx database.Transaction,
	action audit.Action, versionID, reason string) error {
	eventID, err := p.newID("audit")
	if err != nil {
		return err
	}
	_, err = p.audit.AppendInTransaction(ctx, access, tx, audit.EventInput{
		EventID:      eventID,
		ActorType:    audit.ActorSystem,
		Action:       action,
		ResourceType: audit.ResourceSourceObject,
		ResourceID:   versionID,
		RequestID:    access.RequestID,
		Outcome:      audit.OutcomeSuccess,
		OccurredAt:   p.now(),
		Metadata:     audit.Metadata{ReasonCodes: []string{reason}},
	})
	return err
}
