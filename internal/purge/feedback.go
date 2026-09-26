package purge

import (
	"context"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// ProcessFeedbackCommentPurgeQueue drains up to limit queued, superseded
// question_feedback comment artifacts, tombstoning each one's ciphertext
// (migration 000122/000123). The app role can enqueue a superseded artifact
// but can never mutate the envelope-encryption table itself (000019's state-guard
// trigger rejects any such mutation by session_user = 'knowvault_app'), so
// this drain -- run under the trusted knowvault_purger role -- is the actual
// erasure step. It is safe to call on every purger poll tick, exactly like
// the existing conversation/source-version purge queues: an empty queue is a
// cheap no-op, and FOR UPDATE SKIP LOCKED inside the SQL function makes two
// concurrent purger processes not contend for the same row.
func (p *Purger) ProcessFeedbackCommentPurgeQueue(ctx context.Context, access database.AccessContext, limit int) (int64, error) {
	if p == nil || p.db == nil || limit < 1 || limit > 1000 {
		return 0, errors.New("invalid feedback comment purge queue request")
	}
	var purged int64
	err := p.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		return tx.QueryRow(ctx, `SELECT app.question_feedback_process_comment_purge_queue($1)`, limit).Scan(&purged)
	})
	if err != nil {
		return 0, err
	}
	return purged, nil
}
