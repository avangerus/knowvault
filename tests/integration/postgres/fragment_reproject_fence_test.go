package postgres_test

// 000021 hardening (ADR-0077 §1.3 reviewer note): the worker digest reproject
// branch of the fragment guard must itself reject NULL digest targets instead
// of relying on the deferred commit-time artifact guard.  The NULL pair shape
// is reserved for purge cleanup (knowvault_purger, PURGING/PURGED versions);
// a worker UPDATE that erases one or both keyed pairs is rejected by the
// BEFORE trigger, before any commit.  The legitimate channel (the full digest
// rotation pass of TestRotationHandlerDigestFullCycle) writes both complete
// pairs and stays green.

import (
	"testing"
)

// TestWorkerReprojectNullFenceRejectsErasure proves the BEFORE layer: the
// worker role (session_user = knowvault_worker) cannot move any digest pair
// to NULL through a direct fragment UPDATE.  The statement must fail inside
// the transaction, not at commit.
func TestWorkerReprojectNullFenceRejectsErasure(t *testing.T) {
	for name, setClause := range map[string]string{
		"both pairs": `anchor_hash = NULL, anchor_digest_key_version = NULL,
			text_hash = NULL, text_digest_key_version = NULL`,
		"text pair":   `text_hash = NULL, text_digest_key_version = NULL`,
		"anchor pair": `anchor_hash = NULL, anchor_digest_key_version = NULL`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, admin, _, worker, extractionID := rotationSetup(t)
			fragments := s1dFragments(t, ctx, admin, extractionID)
			if len(fragments) == 0 {
				t.Fatal("no evidence fragments seeded")
			}
			fragmentID := fragments[0].id

			tx, err := worker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContext(t, ctx, tx, s1dOrg)

			if _, err := tx.Exec(ctx, `UPDATE public.evidence_fragment
				SET `+setClause+`
				WHERE organization_id = $1 AND id = $2`, s1dOrg, fragmentID); err == nil {
				t.Fatal("worker moved a digest pair to NULL: the reproject fence did not fire")
			}
		})
	}
}
