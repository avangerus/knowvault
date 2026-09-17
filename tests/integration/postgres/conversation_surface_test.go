package postgres_test

import (
	"context"
	"encoding/base64"
	"strings"
	"sync"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/conversation"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/source/ids"
)

func TestConversationServiceSurfaceAndArchive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_surface_alpha", "usr_surface_alice", "ws_surface_alpha")
	seedOrganization(t, ctx, admin, "org_surface_beta", "usr_surface_bob", "ws_surface_beta")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}

	// Seed only opaque conversation/turn metadata through the real RLS role;
	// Question text and answer bytes are intentionally absent.
	seedAccess := database.AccessContext{OrganizationID: "org_surface_alpha", PrincipalID: "usr_surface_alice", RequestID: "req_surface_seed"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		for _, item := range []struct{ conversationID, runID, turnID string }{
			{"conv_surface_1", "qrun_surface_1", "turn_surface_1"},
			{"conv_surface_2", "qrun_surface_2", "turn_surface_2"},
		} {
			if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id, question_hash, answer_mode,
				verification_method, workspace_scope_hash, policy_revision
			) VALUES ($1,$2,'ws_surface_alpha',1,'usr_surface_alice',$3,$4,$5,'EXTRACTIVE','BYTE_EXACT_CITATION',$5,'policy-surface')
			`, "org_surface_alpha", item.runID, item.conversationID, item.turnID, "sha256:"+strings.Repeat("a", 64)); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			VALUES ('org_surface_alpha',$1,'ws_surface_alpha',1,'usr_surface_alice')
		`, item.conversationID); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ('org_surface_alpha',$1,'ws_surface_alpha',1)
		`, item.conversationID); err != nil {
				return err
			}
			if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id)
			VALUES ('org_surface_alpha',$1,$2,'ws_surface_alpha',1,1,$3)
		`, item.turnID, item.conversationID, item.runID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	access := database.AccessContext{OrganizationID: "org_surface_alpha", PrincipalID: "usr_surface_alice", RequestID: "req_surface_read"}
	views, err := service.List(ctx, access, "ws_surface_alpha")
	if err != nil {
		t.Fatalf("list conversations: %v", err)
	}
	if len(views) != 2 || len(views[0].Turns) != 1 || len(views[1].Turns) != 1 {
		t.Fatalf("conversation projection=%+v, want two metadata views with one turn each", views)
	}
	for _, view := range views {
		if view.ID == "" || view.CreatedBy != "usr_surface_alice" || view.WorkspaceID != "ws_surface_alpha" || view.Turns[0].QuestionRunID == "" {
			t.Fatalf("incomplete opaque projection=%+v", view)
		}
	}
	if _, err := service.Get(ctx, access, "ws_surface_beta", "conv_surface_1"); conversation.CodeOf(err) != conversation.CodeNotFound {
		t.Fatalf("cross-workspace lookup code=%s err=%v, want NOT_FOUND", conversation.CodeOf(err), err)
	}
	if _, err := service.Get(ctx, database.AccessContext{OrganizationID: "org_surface_beta", PrincipalID: "usr_surface_bob", RequestID: "req_surface_foreign"}, "ws_surface_beta", "conv_surface_1"); conversation.CodeOf(err) != conversation.CodeNotFound {
		t.Fatalf("cross-organization lookup code=%s err=%v, want NOT_FOUND", conversation.CodeOf(err), err)
	}

	keyBytes := make([]byte, 32)
	copy(keyBytes, []byte("surface-archive"))
	key := base64.RawURLEncoding.EncodeToString(keyBytes)
	archived, err := service.Archive(ctx, access, conversation.ArchiveRequest{WorkspaceID: "ws_surface_alpha", ConversationID: "conv_surface_1", IdempotencyKey: key})
	if err != nil {
		t.Fatalf("archive conversation: %v", err)
	}
	if archived.ArchivedAt == nil || len(archived.Turns) != 1 {
		t.Fatalf("archive projection=%+v, want archived metadata and one opaque turn", archived)
	}
	replay, err := service.Archive(ctx, access, conversation.ArchiveRequest{WorkspaceID: "ws_surface_alpha", ConversationID: "conv_surface_1", IdempotencyKey: key})
	if err != nil || replay.ID != archived.ID || replay.ArchivedAt == nil {
		t.Fatalf("archive replay=%+v err=%v", replay, err)
	}
	if _, err := service.Archive(ctx, access, conversation.ArchiveRequest{WorkspaceID: "ws_surface_alpha", ConversationID: "conv_surface_2", IdempotencyKey: key}); conversation.CodeOf(err) != conversation.CodeIdempotencyConflict {
		t.Fatalf("archive key reuse code=%s err=%v, want conflict", conversation.CodeOf(err), err)
	}

	var auditCount int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.audit_event WHERE organization_id='org_surface_alpha' AND action='conversation.archived' AND resource_id='conv_surface_1'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("archive audit events=%d, want exactly one on replay", auditCount)
	}

	// Retention revocation removes the conversation from the app-facing graph
	// before any physical purge; the service must return the same NOT_FOUND.
	purger := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
	tx, err := purger.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('app.organization_id','org_surface_alpha',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state='PURGING', disclosure_allowed=false, retention_fence=1, purge_started_at=clock_timestamp()
		 WHERE organization_id='org_surface_alpha' AND conversation_id='conv_surface_2'
	`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Get(ctx, access, "ws_surface_alpha", "conv_surface_2"); conversation.CodeOf(err) != conversation.CodeNotFound {
		t.Fatalf("revoked conversation code=%s err=%v, want NOT_FOUND", conversation.CodeOf(err), err)
	}
}

// TestConversationContentPurge proves the production retention boundary for a
// conversation.  The purger first commits the disclosure fence, then erases
// the decryptable Question Run artifact through the migration-owned SECURITY
// DEFINER function.  Opaque Question Run/conversation metadata remains as a
// tombstone, an unrelated artifact remains active, and the runtime role cannot
// call either privileged function or resurrect the terminal state.
func TestConversationContentPurge(t *testing.T) {
	ctx := context.Background()
	const (
		organizationID = "org_content_purge"
		ownerID        = "usr_content_alice"
		workspaceID    = "ws_content_purge"
		conversationID = "conv_content_purge"
		runID          = "qrun_content_purge"
		turnID         = "turn_content_purge"
	)
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_content_seed"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id, question_hash, answer_mode,
				verification_method, workspace_scope_hash, policy_revision
			) VALUES ($1,$2,$3,1,$4,$5,$6,$7,'EXTRACTIVE','BYTE_EXACT_CITATION',$7,'policy-content-purge')
		`, organizationID, runID, workspaceID, ownerID, conversationID, turnID, "sha256:"+strings.Repeat("1", 64)); err != nil {
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
		`, organizationID, runID); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (
				organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id
			) VALUES ($1,$2,$3,$4,1,1,$5)
		`, organizationID, turnID, conversationID, workspaceID, runID)
		return err
	}); err != nil {
		t.Fatalf("seed conversation content metadata: %v", err)
	}

	// The artifact is sealed with the same mounted provider used by the live
	// ingestion/question paths.  It is bound to the run by the runtime role only
	// after the immutable encrypted row exists.
	codec := s1dCodec(t, organizationID)
	artifactID := mustID(t, "artifact")
	candidateArtifactID := mustID(t, "artifact")
	unrelatedArtifactID := mustID(t, "artifact")
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.QuestionText, organizationID, artifactID, runID,
		"question_run", "question_text_artifact_id", "QUESTION_RUN", "QUESTION_TEXT", []byte("private question"))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.AuthorizedCandidateSet, organizationID, candidateArtifactID, runID,
		"question_authorized_candidate_set", "canonical_artifact_id", "AUTHORIZED_CANDIDATE_SET", "CANONICAL_BYTES", []byte("candidate set"))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.QuestionText, organizationID, unrelatedArtifactID, "qrun_unrelated",
		"question_run", "question_text_artifact_id", "QUESTION_RUN", "QUESTION_TEXT", []byte("unrelated private question"))
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			UPDATE public.question_run
			   SET question_text_artifact_id=$1
			 WHERE organization_id=$2 AND id=$3 AND question_text_artifact_id IS NULL
		`, artifactID, organizationID, runID); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.question_authorized_candidate_set
				(organization_id, question_run_id, candidate_count, canonical_artifact_id, candidate_set_hash)
			VALUES ($1,$2,0,$3,$4)
		`, organizationID, runID, candidateArtifactID, "sha256:"+strings.Repeat("2", 64))
		return err
	}); err != nil {
		t.Fatalf("bind question artifact: %v", err)
	}

	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	purgeAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_content_purger", RequestID: "req_content_purge"}
	if fence, err := purger.BeginConversationPurge(ctx, purgeAccess, workspaceID, conversationID, "RETENTION_REQUEST"); err != nil || fence != 1 {
		t.Fatalf("begin conversation purge fence=%d err=%v, want fence 1", fence, err)
	}

	var state string
	var ciphertextPresent, wrappedDEKPresent, purgedAtPresent bool
	if err := admin.QueryRow(ctx, `SELECT state FROM public.conversation_retention WHERE organization_id=$1 AND conversation_id=$2`, organizationID, conversationID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "PURGING" {
		t.Fatalf("conversation retention after begin=%s, want PURGING", state)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM public.question_run_retention WHERE organization_id=$1 AND question_run_id=$2`, organizationID, runID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "PURGING" {
		t.Fatalf("question run retention after begin=%s, want PURGING", state)
	}
	if err := admin.QueryRow(ctx, `
		SELECT ciphertext IS NOT NULL, wrapped_dek IS NOT NULL, purged_at IS NOT NULL
		  FROM public.encrypted_artifact WHERE organization_id=$1 AND id=$2
	`, organizationID, artifactID).Scan(&ciphertextPresent, &wrappedDEKPresent, &purgedAtPresent); err != nil {
		t.Fatal(err)
	}
	if !ciphertextPresent || !wrappedDEKPresent || purgedAtPresent {
		t.Fatalf("begin physically changed artifact ciphertext=%v wrapped_dek=%v purged_at=%v", ciphertextPresent, wrappedDEKPresent, purgedAtPresent)
	}

	purgedCount, err := purger.CompleteConversationPurge(ctx, purgeAccess, workspaceID, conversationID, "RETENTION_REQUEST")
	if err != nil || purgedCount != 2 {
		t.Fatalf("complete conversation purge count=%d err=%v, want two bound artifacts", purgedCount, err)
	}
	for _, boundArtifactID := range []string{artifactID, candidateArtifactID} {
		if err := admin.QueryRow(ctx, `
			SELECT ciphertext IS NOT NULL, wrapped_dek IS NOT NULL, purged_at IS NOT NULL
			  FROM public.encrypted_artifact WHERE organization_id=$1 AND id=$2
		`, organizationID, boundArtifactID).Scan(&ciphertextPresent, &wrappedDEKPresent, &purgedAtPresent); err != nil {
			t.Fatal(err)
		}
		if ciphertextPresent || wrappedDEKPresent || !purgedAtPresent {
			t.Fatalf("completed artifact %s still decryptable ciphertext=%v wrapped_dek=%v purged_at=%v", boundArtifactID, ciphertextPresent, wrappedDEKPresent, purgedAtPresent)
		}
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM public.conversation_retention WHERE organization_id=$1 AND conversation_id=$2`, organizationID, conversationID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "PURGED" {
		t.Fatalf("conversation retention after cleanup=%s, want PURGED", state)
	}
	if err := admin.QueryRow(ctx, `SELECT state FROM public.question_run_retention WHERE organization_id=$1 AND question_run_id=$2`, organizationID, runID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "PURGED" {
		t.Fatalf("question run retention after cleanup=%s, want PURGED", state)
	}
	var questionArtifactRef, candidateArtifactRef string
	if err := admin.QueryRow(ctx, `
		SELECT run.question_text_artifact_id, candidate.canonical_artifact_id
		  FROM public.question_run AS run
		  JOIN public.question_authorized_candidate_set AS candidate
		    ON candidate.organization_id = run.organization_id
		   AND candidate.question_run_id = run.id
		 WHERE run.organization_id=$1 AND run.id=$2
	`, organizationID, runID).Scan(&questionArtifactRef, &candidateArtifactRef); err != nil {
		t.Fatal(err)
	}
	if questionArtifactRef != artifactID || candidateArtifactRef != candidateArtifactID {
		t.Fatalf("purge rewrote opaque tombstone references question=%s candidate=%s", questionArtifactRef, candidateArtifactRef)
	}

	// The cleanup is idempotent and does not mint a second terminal audit event.
	if repeated, err := purger.CompleteConversationPurge(ctx, purgeAccess, workspaceID, conversationID, "RETENTION_REQUEST"); err != nil || repeated != 0 {
		t.Fatalf("idempotent cleanup count=%d err=%v, want 0/nil", repeated, err)
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
		t.Fatalf("conversation purge audits purging=%d purged=%d, want 1/1", purgingAudits, purgedAudits)
	}
	if err := admin.QueryRow(ctx, `SELECT purged_at IS NULL FROM public.encrypted_artifact WHERE organization_id=$1 AND id=$2`, organizationID, unrelatedArtifactID).Scan(&purgedAtPresent); err != nil {
		t.Fatal(err)
	}
	if !purgedAtPresent {
		t.Fatal("conversation purge touched an unrelated Question Run artifact")
	}

	// App cannot invoke the privileged function and cannot reopen the terminal
	// retention state; both checks run through the real role boundary.
	appPool := openApplicationPool(t, ctx, testDatabaseURL(t))
	appTx, err := appPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, appTx, organizationID, ownerID)
	if _, err := appTx.Exec(ctx, `SELECT app.conversation_purge_cleanup($1,$2,$3)`, organizationID, workspaceID, conversationID); err == nil {
		_ = appTx.Rollback(ctx)
		t.Fatal("runtime role invoked conversation purge cleanup")
	}
	_ = appTx.Rollback(ctx)
	appTx, err = appPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, appTx, organizationID, ownerID)
	if _, err := appTx.Exec(ctx, `SELECT app.conversation_begin_purge($1,$2,$3,$4,$5)`, organizationID, workspaceID, conversationID, "RETENTION_REQUEST", 2); err == nil {
		_ = appTx.Rollback(ctx)
		t.Fatal("runtime role invoked conversation purge begin")
	}
	_ = appTx.Rollback(ctx)

	purgerPool := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
	purgerTx, err := purgerPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purgerTx.Exec(ctx, `SELECT set_config('app.organization_id',$1,true)`, organizationID); err != nil {
		_ = purgerTx.Rollback(ctx)
		t.Fatal(err)
	}
	if _, err := purgerTx.Exec(ctx, `
		UPDATE public.conversation_retention
		   SET state='PURGING', disclosure_allowed=false, retention_fence=3
		 WHERE organization_id=$1 AND workspace_id=$2 AND conversation_id=$3
	`, organizationID, workspaceID, conversationID); err == nil {
		_ = purgerTx.Rollback(ctx)
		t.Fatal("purged conversation retention resurrected")
	}
	_ = purgerTx.Rollback(ctx)
}

func TestConversationArchiveConcurrentDistinctKeysAuditOnce(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_surface_race", "usr_surface_race", "ws_surface_race")
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	service, err := conversation.New(appStore, auditStore)
	if err != nil {
		t.Fatal(err)
	}
	seedAccess := database.AccessContext{OrganizationID: "org_surface_race", PrincipalID: "usr_surface_race", RequestID: "req_surface_race_seed"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			VALUES ('org_surface_race','conv_surface_race','ws_surface_race',1,'usr_surface_race')`); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ('org_surface_race','conv_surface_race','ws_surface_race',1)`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	type archiveResult struct {
		view conversation.View
		err  error
	}
	results := make(chan archiveResult, 2)
	var waitGroup sync.WaitGroup
	for index, requestID := range []string{"req_surface_race_a", "req_surface_race_b"} {
		index, requestID := index, requestID
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			keyBytes := make([]byte, 32)
			copy(keyBytes, []byte{byte('a' + index), 'r', 'c', 'h'})
			<-start
			view, err := service.Archive(ctx, database.AccessContext{
				OrganizationID: "org_surface_race", PrincipalID: "usr_surface_race", RequestID: requestID,
			}, conversation.ArchiveRequest{
				WorkspaceID: "ws_surface_race", ConversationID: "conv_surface_race",
				IdempotencyKey: base64.RawURLEncoding.EncodeToString(keyBytes),
			})
			results <- archiveResult{view: view, err: err}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)
	for result := range results {
		if result.err != nil || result.view.ArchivedAt == nil || result.view.ID != "conv_surface_race" {
			t.Fatalf("concurrent archive result=%+v err=%v", result.view, result.err)
		}
	}

	var auditCount int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.audit_event
		 WHERE organization_id='org_surface_race' AND action='conversation.archived'
		   AND resource_id='conv_surface_race'`).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatalf("concurrent archive audit events=%d, want exactly one", auditCount)
	}
	var receiptCount, successfulReceipts, distinctAuditIDs int
	if err := admin.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status='SUCCESS'), count(DISTINCT audit_event_id)
		  FROM public.conversation_command_receipt
		 WHERE organization_id='org_surface_race' AND conversation_id='conv_surface_race'`).Scan(&receiptCount, &successfulReceipts, &distinctAuditIDs); err != nil {
		t.Fatal(err)
	}
	if receiptCount != 2 || successfulReceipts != 2 || distinctAuditIDs != 1 {
		t.Fatalf("concurrent archive receipts=(%d total,%d success,%d audit ids), want 2/2/1", receiptCount, successfulReceipts, distinctAuditIDs)
	}
}

func TestConversationArchiveRetentionRevocationRace(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		organization  string
		principal     string
		workspace     string
		conversation  string
		requestID     string
		idempotencyID string
		purgeFirst    bool
	}{
		{
			name:          "purge committed first",
			organization:  "org_surface_purge_first",
			principal:     "usr_surface_purge_first",
			workspace:     "ws_surface_purge_first",
			conversation:  "conv_surface_purge_first",
			requestID:     "req_surface_purge_first",
			idempotencyID: "purge-first",
			purgeFirst:    true,
		},
		{
			name:          "archive committed first",
			organization:  "org_surface_archive_first",
			principal:     "usr_surface_archive_first",
			workspace:     "ws_surface_archive_first",
			conversation:  "conv_surface_archive_first",
			requestID:     "req_surface_archive_first",
			idempotencyID: "archive-first",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			ctx := context.Background()
			admin := resetStage1Database(t)
			seedOrganization(t, ctx, admin, testCase.organization, testCase.principal, testCase.workspace)
			appStore := openStore(t, ctx, appRole, "knowvault_app")
			auditStore, err := audit.NewStore(appStore)
			if err != nil {
				t.Fatal(err)
			}
			service, err := conversation.New(appStore, auditStore)
			if err != nil {
				t.Fatal(err)
			}
			access := database.AccessContext{
				OrganizationID: testCase.organization,
				PrincipalID:    testCase.principal,
				RequestID:      testCase.requestID,
			}
			if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
				if _, err := tx.Exec(txCtx, `
					INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
					VALUES ($1,$2,$3,1,$4)
				`, testCase.organization, testCase.conversation, testCase.workspace, testCase.principal); err != nil {
					return err
				}
				_, err := tx.Exec(txCtx, `
					INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
					VALUES ($1,$2,$3,1)
				`, testCase.organization, testCase.conversation, testCase.workspace)
				return err
			}); err != nil {
				t.Fatal(err)
			}

			keyBytes := make([]byte, 32)
			copy(keyBytes, []byte(testCase.idempotencyID))
			request := conversation.ArchiveRequest{
				WorkspaceID:    testCase.workspace,
				ConversationID: testCase.conversation,
				IdempotencyKey: base64.RawURLEncoding.EncodeToString(keyBytes),
			}
			if testCase.purgeFirst {
				purger := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
				purgeTx, err := purger.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = purgeTx.Rollback(ctx) }()
				if _, err := purgeTx.Exec(ctx, `SELECT set_config('app.organization_id',$1,true)`, testCase.organization); err != nil {
					t.Fatal(err)
				}
				if _, err := purgeTx.Exec(ctx, `
					UPDATE public.conversation_retention
					   SET state='PURGING', disclosure_allowed=false, retention_fence=1, purge_started_at=clock_timestamp()
					 WHERE organization_id=$1 AND conversation_id=$2 AND workspace_id=$3
				`, testCase.organization, testCase.conversation, testCase.workspace); err != nil {
					t.Fatal(err)
				}

				type archiveResult struct {
					view conversation.View
					err  error
				}
				started := make(chan struct{})
				results := make(chan archiveResult, 1)
				go func() {
					close(started)
					view, archiveErr := service.Archive(ctx, access, request)
					results <- archiveResult{view: view, err: archiveErr}
				}()
				<-started
				select {
				case result := <-results:
					t.Fatalf("archive completed before purge commit: view=%+v err=%v", result.view, result.err)
				default:
				}
				if err := purgeTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				result := <-results
				if conversation.CodeOf(result.err) != conversation.CodeNotFound || result.view.ArchivedAt != nil {
					t.Fatalf("purge-first archive result=%+v err=%v, want NOT_FOUND without archive", result.view, result.err)
				}
			} else {
				archived, err := service.Archive(ctx, access, request)
				if err != nil || archived.ArchivedAt == nil {
					t.Fatalf("archive-first result=%+v err=%v, want point-in-time success", archived, err)
				}
				purger := openConversationPurgerPool(t, ctx, testDatabaseURL(t))
				purgeTx, err := purger.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = purgeTx.Rollback(ctx) }()
				if _, err := purgeTx.Exec(ctx, `SELECT set_config('app.organization_id',$1,true)`, testCase.organization); err != nil {
					t.Fatal(err)
				}
				if _, err := purgeTx.Exec(ctx, `
					UPDATE public.conversation_retention
					   SET state='PURGING', disclosure_allowed=false, retention_fence=1, purge_started_at=clock_timestamp()
					 WHERE organization_id=$1 AND conversation_id=$2 AND workspace_id=$3
				`, testCase.organization, testCase.conversation, testCase.workspace); err != nil {
					t.Fatal(err)
				}
				if err := purgeTx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			}

			var auditCount, receiptCount, archivedCount int
			if err := admin.QueryRow(ctx, `
				SELECT
				       (SELECT count(*) FROM public.audit_event
				         WHERE organization_id=$1 AND action='conversation.archived' AND resource_id=$2),
				       (SELECT count(*) FROM public.conversation_command_receipt
				         WHERE organization_id=$1 AND conversation_id=$2)
			`, testCase.organization, testCase.conversation).Scan(&auditCount, &receiptCount); err != nil {
				t.Fatal(err)
			}
			if err := admin.QueryRow(ctx, `
				SELECT count(*) FROM public.conversation
				 WHERE organization_id=$1 AND id=$2 AND archived_at IS NOT NULL
			`, testCase.organization, testCase.conversation).Scan(&archivedCount); err != nil {
				t.Fatal(err)
			}
			if testCase.purgeFirst {
				if auditCount != 0 || receiptCount != 0 || archivedCount != 0 {
					t.Fatalf("purge-first persisted audit=%d receipts=%d archived=%d, want 0/0/0", auditCount, receiptCount, archivedCount)
				}
			} else if auditCount != 1 || receiptCount != 1 || archivedCount != 1 {
				t.Fatalf("archive-first persisted audit=%d receipts=%d archived=%d, want 1/1/1", auditCount, receiptCount, archivedCount)
			}
		})
	}
}
