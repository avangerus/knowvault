package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// Caller-owned transactions cannot be retried by the audit store: they also
// contain the caller's business mutation. Slow the INSERT after the event has
// been built to expose competing reads of the chain head deterministically.
func TestConcurrentTransactionalAuditPreservesEveryEventAndChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	if _, err := admin.Exec(ctx, `
		CREATE FUNCTION public.audit_test_pause() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN PERFORM pg_sleep(0.02); RETURN NEW; END $$;
		CREATE TRIGGER audit_00_test_pause BEFORE INSERT ON public.audit_event
		FOR EACH ROW EXECUTE FUNCTION public.audit_test_pause();
	`); err != nil {
		t.Fatal(err)
	}
	db := openStore(t, ctx, appRole, "knowvault_app")
	journal, err := audit.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 16
	start := make(chan struct{})
	results := make(chan error, writers)
	var group sync.WaitGroup
	for i := range writers {
		group.Go(func() {
			<-start
			access := database.AccessContext{OrganizationID: "org_alpha", PrincipalID: "usr_alice", RequestID: fmt.Sprintf("req_parallel_%d", i)}
			results <- db.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
				for step := range 2 {
					_, err := journal.AppendInTransaction(txCtx, access, tx, audit.EventInput{
						EventID: fmt.Sprintf("aud_parallel_%d_%d", i, step), ActorType: audit.ActorHuman, ActorPrincipalID: &access.PrincipalID,
						Action: audit.ActionAuditViewed, ResourceType: audit.ResourceWorkspace, ResourceID: "ws_alpha", RequestID: access.RequestID,
						Outcome: audit.OutcomeSuccess, ReferencedEvidenceIDs: []string{}, OccurredAt: time.Now().UTC(),
					})
					if err != nil {
						return err
					}
				}
				return nil
			})
		})
	}
	close(start)
	group.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Errorf("concurrent caller-owned transaction failed: %v", err)
		}
	}
	rows, err := admin.Query(ctx, `SELECT sequence,previous_event_hash,event_hash,canonical_bytes FROM public.audit_event WHERE organization_id='org_alpha' ORDER BY sequence`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := int64(0)
	previous := "sha256:" + strings.Repeat("0", 64)
	for rows.Next() {
		var sequence int64
		var before, hash string
		var canonical []byte
		if err := rows.Scan(&sequence, &before, &hash, &canonical); err != nil {
			t.Fatal(err)
		}
		count++
		if sequence != count || before != previous || hash != canon.Hash(canonical) {
			t.Fatal("audit chain is discontinuous or its hash is invalid")
		}
		previous = hash
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != writers*2 {
		t.Fatalf("committed %d audit events, want %d", count, writers*2)
	}
	var head int64
	var hash string
	if err := admin.QueryRow(ctx, `SELECT last_sequence,last_event_hash FROM public.audit_chain_head WHERE organization_id='org_alpha'`).Scan(&head, &hash); err != nil {
		t.Fatal(err)
	}
	if head != count || hash != previous {
		t.Fatal("chain head does not match committed events")
	}
}
