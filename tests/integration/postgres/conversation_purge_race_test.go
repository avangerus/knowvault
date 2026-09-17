package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestConversationPurgeConcurrentTerminalAuditOnce proves that the purger's
// retry/idempotency contract also holds when two workers complete the same
// conversation concurrently.  The first worker owns the terminal transition;
// the second waits on the row fence and returns without minting a duplicate
// conversation.purged audit event.
func TestConversationPurgeConcurrentTerminalAuditOnce(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_conversation_race"
		ownerID        = "usr_conversation_race"
		workspaceID    = "ws_conversation_race"
		conversationID = "conv_conversation_race"
		questionRunID  = "qrun_conversation_race"
		turnID         = "turn_conversation_race"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_conversation_race_seed"}
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id,id,workspace_id,workspace_revision,created_by,
				conversation_id,conversation_turn_id,question_hash,answer_mode,
				verification_method,workspace_scope_hash,policy_revision
			) VALUES ($1,$2,$3,1,$4,$5,$6,$7,'EXTRACTIVE','BYTE_EXACT_CITATION',$7,'policy-race')
		`, organizationID, questionRunID, workspaceID, ownerID, conversationID, turnID, "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			VALUES ($1,$2,$3,1,$4)
		`, organizationID, conversationID, workspaceID, ownerID); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ($1,$2,$3,1)
		`, organizationID, conversationID, workspaceID); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id,question_run_id)
			VALUES ($1,$2)
		`, organizationID, questionRunID); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (
				organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id
			) VALUES ($1,$2,$3,$4,1,1,$5)
		`, organizationID, turnID, conversationID, workspaceID, questionRunID)
		return err
	}); err != nil {
		t.Fatalf("seed concurrent purge conversation: %v", err)
	}

	openPurger := func(requestID string) *purge.Purger {
		store := openStore(t, ctx, purgerRole, "knowvault_purger")
		p, err := purge.NewPurger(store, time.Now, ids.New)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := openPurger("req_conversation_race_first")
	second := openPurger("req_conversation_race_second")
	beginAccess := func(requestID string) database.AccessContext {
		return database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_conversation_purger", RequestID: requestID}
	}

	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	type beginResult struct {
		fence int64
		err   error
	}
	results := make(chan beginResult, 2)
	var wg sync.WaitGroup
	for _, item := range []struct {
		p   *purge.Purger
		req string
	}{
		{first, "req_conversation_race_first"},
		{second, "req_conversation_race_second"},
	} {
		wg.Add(1)
		go func(item struct {
			p   *purge.Purger
			req string
		}) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			fence, err := item.p.BeginConversationPurge(ctx, beginAccess(item.req), workspaceID, conversationID, "RETENTION_REQUEST")
			results <- beginResult{fence: fence, err: err}
		}(item)
	}
	<-ready
	<-ready
	close(start)
	wg.Wait()
	close(results)
	var successfulBegins, failedBegins int
	for result := range results {
		if result.err == nil && result.fence == 1 {
			successfulBegins++
		} else if result.err != nil {
			failedBegins++
		} else {
			t.Fatalf("unexpected begin result fence=%d err=%v", result.fence, result.err)
		}
	}
	if successfulBegins != 1 || failedBegins != 1 {
		t.Fatalf("concurrent begin results success=%d failed=%d, want 1/1", successfulBegins, failedBegins)
	}

	start = make(chan struct{})
	ready = make(chan struct{}, 2)
	type completeResult struct {
		count int64
		err   error
	}
	completeResults := make(chan completeResult, 2)
	wg = sync.WaitGroup{}
	for _, item := range []struct {
		p   *purge.Purger
		req string
	}{
		{first, "req_conversation_race_first_complete"},
		{second, "req_conversation_race_second_complete"},
	} {
		wg.Add(1)
		go func(item struct {
			p   *purge.Purger
			req string
		}) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			count, err := item.p.CompleteConversationPurge(ctx, beginAccess(item.req), workspaceID, conversationID, "RETENTION_REQUEST")
			completeResults <- completeResult{count: count, err: err}
		}(item)
	}
	<-ready
	<-ready
	close(start)
	wg.Wait()
	close(completeResults)
	for result := range completeResults {
		if result.err != nil || result.count != 0 {
			t.Fatalf("concurrent complete count=%d err=%v, want 0/nil", result.count, result.err)
		}
	}

	var purgingAudits, purgedAudits int
	if err := admin.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_type='CONVERSATION' AND resource_id=$2 AND action='conversation.purging'),
			(SELECT count(*) FROM public.audit_event WHERE organization_id=$1 AND resource_type='CONVERSATION' AND resource_id=$2 AND action='conversation.purged')
	`, organizationID, conversationID).Scan(&purgingAudits, &purgedAudits); err != nil {
		t.Fatal(err)
	}
	if purgingAudits != 1 || purgedAudits != 1 {
		t.Fatalf("concurrent purge audits purging=%d purged=%d, want 1/1", purgingAudits, purgedAudits)
	}
}
