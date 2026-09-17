package postgres_test

import (
	"context"
	"testing"
)

// TestS1dHeadControlPlaneTransitions is the head-of-history counterpart to the
// three source control-plane suites that were re-pinned to migration 000013
// (resetPreCatalogDatabase). Those historical suites prove the pre-S1d DRAFT-only,
// fully-immutable contract; this proves the S1d checkpoint's opened contract at
// head — the exact transitions 000014 introduces and, just as important, that
// every transition it does NOT open still fails closed. No privilege, lifecycle
// or immutability invariant disappears under historical compatibility.
func TestS1dHeadControlPlaneTransitions(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t) // head: through 000014
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	insertSourceScopeDraftChain(t, ctx, admin, "org_alpha", "usr_alice", "parity", "workspace_managed")

	setAccessCtx := func(sql string, args ...any) error {
		_, err := admin.Exec(ctx, sql, args...)
		return err
	}

	// Trust projection: DRAFT->VERIFIED is now opened (historical: immutable).
	t.Run("trust projection opens DRAFT to VERIFIED", func(t *testing.T) {
		if err := setAccessCtx(`UPDATE public.source_connection_trust_projection SET status='VERIFIED'
			WHERE organization_id='org_alpha' AND trust_record_id='trust_parity'`); err != nil {
			t.Fatalf("DRAFT->VERIFIED rejected at head: %v", err)
		}
		// ...but the transition is monotonic: it never reverses.
		if err := setAccessCtx(`UPDATE public.source_connection_trust_projection SET status='DRAFT'
			WHERE organization_id='org_alpha' AND trust_record_id='trust_parity'`); err == nil {
			t.Fatal("VERIFIED->DRAFT was permitted")
		}
		// A terminal state is final.
		if err := setAccessCtx(`UPDATE public.source_connection_trust_projection SET status='REVOKED'
			WHERE organization_id='org_alpha' AND trust_record_id='trust_parity'`); err != nil {
			t.Fatalf("VERIFIED->REVOKED rejected: %v", err)
		}
		if err := setAccessCtx(`UPDATE public.source_connection_trust_projection SET status='VERIFIED'
			WHERE organization_id='org_alpha' AND trust_record_id='trust_parity'`); err == nil {
			t.Fatal("REVOKED->VERIFIED was permitted")
		}
	})

	// Scope activation: the state machine is opened, but only the exact edges.
	t.Run("scope activation opens only its exact edges", func(t *testing.T) {
		// DRAFT->SYNCING is opened.
		if err := setAccessCtx(`UPDATE public.source_scope_activation SET status='SYNCING'
			WHERE organization_id='org_alpha' AND source_scope_id='scope_01ARZ3NDEKTSV4RRFFQ69G5FAV'`); err != nil {
			t.Fatalf("DRAFT->SYNCING rejected at head: %v", err)
		}
		// SYNCING->DRAFT is not a permitted edge.
		if err := setAccessCtx(`UPDATE public.source_scope_activation SET status='DRAFT'
			WHERE organization_id='org_alpha' AND source_scope_id='scope_01ARZ3NDEKTSV4RRFFQ69G5FAV'`); err == nil {
			t.Fatal("SYNCING->DRAFT was permitted")
		}
	})

	// The invariants 000014 does NOT change still hold at head.
	t.Run("connection and scope revisions stay immutable at head", func(t *testing.T) {
		if err := setAccessCtx(`UPDATE public.source_connection_revision SET max_scope_objects=1
			WHERE organization_id='org_alpha' AND connection_id='conn_parity'`); err == nil {
			t.Fatal("connection revision was mutated at head")
		}
		if err := setAccessCtx(`UPDATE public.source_scope_revision SET object_limit=2
			WHERE organization_id='org_alpha' AND source_scope_id='scope_01ARZ3NDEKTSV4RRFFQ69G5FAV'`); err == nil {
			t.Fatal("scope revision was mutated at head")
		}
	})
}
