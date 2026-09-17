package ingestion

import (
	"context"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// publishObjectPresence runs only after the observed bytes have a successful
// current extraction. The database rechecks lease, scope authority and retention
// before restoring absence; terminal membership/object closures stay closed.
func (h *Handler) publishObjectPresence(ctx context.Context, tx database.Transaction, access database.AccessContext,
	claimed jobs.ClaimedJob, scopeID string, scopeRevision int64, syncRunID, objectID, versionID string, reuseExtraction bool) error {
	var restored, membershipRestored bool
	if err := tx.QueryRow(ctx, `SELECT * FROM app.source_object_observation_publish($1,$2,$3,$4,$5,$6,$7,$8)`,
		objectID, scopeID, scopeRevision, versionID, syncRunID, claimed.ID, h.workerID, claimed.LeaseEpoch).Scan(&restored, &membershipRestored); err != nil {
		return failure("INGEST_PRESENCE_PUBLICATION", err)
	}
	if membershipRestored && reuseExtraction {
		// Existing immutable chunks cannot use their original enqueue ID again:
		// that event may already be published (or converged to a missing DELETE).
		// Refresh also a single restored overlapping scope, without claiming the
		// object itself was absent. New chunks are enqueued by their own creation.
		rows, err := tx.Query(ctx, `SELECT chunk.id FROM public.search_chunk AS chunk
			JOIN public.source_version_active_extraction AS active
			ON active.organization_id=chunk.organization_id AND active.source_version_id=chunk.source_version_id
			AND active.extraction_id=chunk.extraction_id
			WHERE chunk.organization_id=$1 AND chunk.source_version_id=$2 ORDER BY chunk.id`, access.OrganizationID, versionID)
		if err != nil {
			return failure("INGEST_PRESENCE_SEARCH", err)
		}
		var chunks []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			chunks = append(chunks, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, chunkID := range chunks {
			eventID, err := h.newID("searchupd")
			if err != nil {
				return err
			}
			var sequence int64
			if err := tx.QueryRow(ctx, `SELECT app.enqueue_search_chunk_reobservation($1,$2)`, chunkID, eventID).Scan(&sequence); err != nil {
				return failure("INGEST_PRESENCE_SEARCH", err)
			}
		}
	}
	if restored {
		return h.auditEntity(ctx, access, tx, audit.ActionSourceObjectRestored, audit.ResourceSourceObject, objectID, syncRunID, claimed.ID)
	}
	return nil
}

// A cutover may leave another live scope with an absent membership. Such an
// object is MISSING, whereas one with no remaining source authority is DELETED.
// The transition function returns only changed objects; audit their own state,
// never call one missing merely because a single overlapping membership closed.
func (h *Handler) auditObjectClosure(ctx context.Context, tx database.Transaction, access database.AccessContext,
	objectID, syncRunID, jobID string) error {
	var state string
	if err := tx.QueryRow(ctx, `SELECT lifecycle_state FROM public.source_object WHERE organization_id=$1 AND id=$2`,
		access.OrganizationID, objectID).Scan(&state); err != nil {
		return err
	}
	action := audit.ActionSourceObjectDeleted
	if state == "MISSING" {
		action = audit.ActionSourceObjectMissing
	} else if state != "DELETED" {
		return failure("INGEST_PRESENCE_STATE", nil)
	}
	return h.auditEntity(ctx, access, tx, action, audit.ResourceSourceObject, objectID, syncRunID, jobID)
}
