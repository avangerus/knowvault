package postgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

type contextRolloverSnapshot struct {
	contextRows      []string
	manifestBytes    []byte
	manifestHash     string
	sourceObjectID   string
	sourceVersionID  string
	extractionID     string
	activeExtraction string
	fragmentID       string
	activationRev    int64
	extractionHash   string
}

func captureContextRolloverSnapshot(t *testing.T, ctx context.Context, admin *pgxpool.Pool,
	organizationID, questionRunID string) contextRolloverSnapshot {
	t.Helper()
	var snapshot contextRolloverSnapshot
	rows, err := admin.Query(ctx, `SELECT row_to_json(context_entry)::text
		FROM public.question_retrieval_context_entry context_entry
		WHERE organization_id=$1 AND question_run_id=$2 ORDER BY ordinal`, organizationID, questionRunID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		snapshot.contextRows = append(snapshot.contextRows, encoded)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.contextRows) == 0 {
		t.Fatalf("completed question run %s has no retrieval context entries", questionRunID)
	}
	if err := admin.QueryRow(ctx, `SELECT source_object_id, source_version_id, extraction_id,
		active_extraction_id, activation_revision, evidence_fragment_id, extraction_profile_hash
		FROM public.question_retrieval_context_entry
		WHERE organization_id=$1 AND question_run_id=$2 ORDER BY ordinal LIMIT 1`, organizationID, questionRunID).
		Scan(&snapshot.sourceObjectID, &snapshot.sourceVersionID, &snapshot.extractionID,
			&snapshot.activeExtraction, &snapshot.activationRev, &snapshot.fragmentID, &snapshot.extractionHash); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `SELECT canonical_bytes, snapshot_hash
		FROM public.question_retrieval_authorization_snapshot
		WHERE organization_id=$1 AND question_run_id=$2`, organizationID, questionRunID).
		Scan(&snapshot.manifestBytes, &snapshot.manifestHash); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.manifestBytes) == 0 || snapshot.manifestHash != canon.Hash(snapshot.manifestBytes) {
		t.Fatalf("question run %s has an invalid authorization manifest hash %q", questionRunID, snapshot.manifestHash)
	}
	return snapshot
}

// This exercises the observed-active-extraction composite FK through the real
// question service. Both ingestions use the current layout-v2 writer; the
// fixture targets active-extraction rollover, while pre-layout legacy reads
// are verified against the pre-deploy corpus separately.
func TestQuestionContextSurvivesActiveExtractionRollover(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	content := "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432.\n\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0437\u0430\u043a\u0440\u044b\u0442 \u0434\u0438\u0441\u043f\u0435\u0442\u0447\u0435\u0440\u043e\u043c.\n"
	writeS1dFile(t, filepath.Join(fileDir, "waste.txt"), content)
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	authorityFixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, neighborsStableWorkspaceSourceID(s1dOrg, s1dWorkspace, s1dScopeID),
		"grant_context_rollover", "confirmation_context_rollover", true)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	newHandler := func() *ingestion.Handler {
		return ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
			ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
			time.Now, ids.New)
	}
	initialHandler := newHandler()
	runSync(t, ctx, initialHandler.WithParserRevision("text-v1-a"), queue,
		workerAccess(t, s1dOrg), "context-rollover-initial")
	objectID, versionID, initialExtractionID := s1dActiveEvidence(t, ctx, admin)
	var initialProfileHash string
	var initialActivationRevision int64
	if err := admin.QueryRow(ctx, `SELECT extraction.profile_hash, active.activation_revision
		FROM public.source_version_active_extraction active
		JOIN public.source_extraction extraction
		  ON extraction.organization_id=active.organization_id AND extraction.id=active.extraction_id
		WHERE active.organization_id=$1 AND active.source_version_id=$2`, s1dOrg, versionID).
		Scan(&initialProfileHash, &initialActivationRevision); err != nil {
		t.Fatal(err)
	}
	if len(s1dFragments(t, ctx, admin, initialExtractionID)) == 0 {
		t.Fatal("initial extraction has no evidence fragments")
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.New(appStore, auditStore, codec, viewer)
	if err != nil {
		t.Fatal(err)
	}
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_context_rollover"}
	idempotencyBytes := make([]byte, 32)
	copy(idempotencyBytes, []byte("context-rollover-completed-question"))
	completed, err := questions.Create(ctx, access, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(idempotencyBytes),
	})
	if err != nil {
		t.Fatalf("create completed question: %v (code=%s)", err, question.CodeOf(err))
	}
	if completed.ResultStatus != "COMPLETED" || len(completed.Citations) == 0 {
		t.Fatalf("question status=%s citations=%d, want COMPLETED with evidence", completed.ResultStatus, len(completed.Citations))
	}
	before := captureContextRolloverSnapshot(t, ctx, admin, s1dOrg, completed.ID)
	if before.sourceObjectID != objectID || before.sourceVersionID != versionID ||
		before.extractionID != initialExtractionID || before.activeExtraction != initialExtractionID ||
		before.activationRev != initialActivationRevision {
		t.Fatalf("question context did not capture the initial active tuple: object/version/extraction/active/revision=%s/%s/%s/%s/%d",
			before.sourceObjectID, before.sourceVersionID, before.extractionID, before.activeExtraction, before.activationRev)
	}
	initialExact, err := viewer.ReadExactVersion(ctx, access, s1dWorkspace, before.fragmentID, versionID)
	if err != nil {
		t.Fatalf("exact read before profile refresh: %v", err)
	}
	if initialExact.ExtractionID != initialExtractionID || initialExact.ParserProfileRevision != "text-v1-a-layout-v2" {
		t.Fatalf("initial extraction profile/address=%s/%q, want %s/text-v1-a-layout-v2",
			initialExact.ExtractionID, initialExact.ParserProfileRevision, initialExtractionID)
	}
	initialWhole, err := viewer.ReadObjectExactVersion(ctx, access, s1dWorkspace, before.fragmentID, versionID)
	if err != nil {
		t.Fatalf("exact whole-object read before profile refresh: %v", err)
	}
	if initialWhole.Fragment.ExtractionID != initialExtractionID || !bytes.Contains(initialExact.Text, []byte("42")) {
		t.Fatalf("initial exact object did not bind expected evidence extraction/content: extraction=%s text=%q",
			initialWhole.Fragment.ExtractionID, initialExact.Text)
	}

	// The unchanged source version is re-extracted by a fresh default handler.
	// Its new profile changes only the active extraction pointer and revision.
	runSync(t, ctx, newHandler(), queue, workerAccess(t, s1dOrg), "context-rollover-default-profile")
	newObjectID, newVersionID, newExtractionID := s1dActiveEvidence(t, ctx, admin)
	var newProfileHash string
	var newActivationRevision int64
	if err := admin.QueryRow(ctx, `SELECT extraction.profile_hash, active.activation_revision
		FROM public.source_version_active_extraction active
		JOIN public.source_extraction extraction
		  ON extraction.organization_id=active.organization_id AND extraction.id=active.extraction_id
		WHERE active.organization_id=$1 AND active.source_version_id=$2`, s1dOrg, newVersionID).
		Scan(&newProfileHash, &newActivationRevision); err != nil {
		t.Fatal(err)
	}
	if newObjectID != objectID || newVersionID != versionID || newExtractionID == initialExtractionID ||
		newProfileHash == initialProfileHash || newActivationRevision != initialActivationRevision+1 {
		t.Fatalf("profile refresh changed object/version or failed to switch extraction: object/version/extraction=%s/%s/%s profile=%s revision=%d; initial=%s/%s/%s profile=%s revision=%d",
			newObjectID, newVersionID, newExtractionID, newProfileHash, newActivationRevision,
			objectID, versionID, initialExtractionID, initialProfileHash, initialActivationRevision)
	}
	newFragments := s1dFragments(t, ctx, admin, newExtractionID)
	if len(newFragments) == 0 {
		t.Fatal("profile refresh created no evidence fragments")
	}
	newExtraction, err := viewer.ReadExactVersion(ctx, access, s1dWorkspace, newFragments[0].id, versionID)
	if err != nil {
		t.Fatalf("read new extraction after profile refresh: %v", err)
	}
	if newExtraction.ParserProfileRevision != "text-v1-layout-v2" {
		t.Fatalf("default extraction profile=%q, want text-v1-layout-v2", newExtraction.ParserProfileRevision)
	}
	// Ordinary retrieval follows the current pointer. Historical reads above
	// require the explicit version path; retaining context does not make the
	// old extraction a current candidate again.
	currentOld, err := viewer.Read(ctx, access, s1dWorkspace, before.fragmentID)
	if !errors.Is(err, evidence.ErrNotFound) || currentOld.FragmentID != "" ||
		len(currentOld.Text) != 0 || len(currentOld.Anchor) != 0 {
		t.Fatalf("ordinary old-extraction read must deny without content: err=%v fragment=%+v", err, currentOld)
	}
	currentNew, err := viewer.Read(ctx, access, s1dWorkspace, newFragments[0].id)
	if err != nil || currentNew.ExtractionID != newExtractionID {
		t.Fatalf("ordinary new-extraction read must succeed: err=%v extraction=%s", err, currentNew.ExtractionID)
	}

	after := captureContextRolloverSnapshot(t, ctx, admin, s1dOrg, completed.ID)
	if len(before.contextRows) != len(after.contextRows) {
		t.Fatalf("profile refresh changed question context row count %d -> %d", len(before.contextRows), len(after.contextRows))
	}
	for i := range before.contextRows {
		if before.contextRows[i] != after.contextRows[i] {
			t.Fatalf("profile refresh rewrote immutable question context row %d", i+1)
		}
	}
	if !bytes.Equal(before.manifestBytes, after.manifestBytes) || before.manifestHash != after.manifestHash {
		t.Fatalf("profile refresh changed question authorization manifest bytes/hash: %x/%s -> %x/%s",
			before.manifestBytes, before.manifestHash, after.manifestBytes, after.manifestHash)
	}
	if after.extractionID != initialExtractionID || after.activeExtraction != initialExtractionID ||
		after.activationRev != initialActivationRevision || after.extractionHash != before.extractionHash {
		t.Fatalf("stored question context followed the active pointer: extraction=%s active=%s rev=%d profile=%s",
			after.extractionID, after.activeExtraction, after.activationRev, after.extractionHash)
	}
	oldExact, err := viewer.ReadExactVersion(ctx, access, s1dWorkspace, before.fragmentID, versionID)
	if err != nil {
		t.Fatalf("old context exact address after active extraction rollover: %v", err)
	}
	assertSameExactFragment(t, initialExact, oldExact, true)
	oldWhole, err := viewer.ReadObjectExactVersion(ctx, access, s1dWorkspace, before.fragmentID, versionID)
	if err != nil {
		t.Fatalf("old context exact whole-object address after active extraction rollover: %v", err)
	}
	if oldWhole.Fragment.ExtractionID != initialExtractionID || !bytes.Equal(oldWhole.Text, initialWhole.Text) {
		t.Fatalf("whole-object exact read changed across extraction rollover: extraction=%s old-text-bytes=%d new-text-bytes=%d",
			oldWhole.Fragment.ExtractionID, len(initialWhole.Text), len(oldWhole.Text))
	}

	// A new Question Run after rollover must retrieve from the newly active
	// extraction and capture its activation revision in every context row.
	freshIdempotencyBytes := make([]byte, 32)
	copy(freshIdempotencyBytes, []byte("context-rollover-new-profile-question"))
	freshAccess := access
	freshAccess.RequestID = "req_context_rollover_new_profile"
	freshQuestion, err := questions.Create(ctx, freshAccess, question.CreateRequest{
		WorkspaceID: s1dWorkspace, Question: "\u0421\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e 42 \u0442\u043e\u043d\u043d\u044b \u043e\u0442\u0445\u043e\u0434\u043e\u0432?", AnswerMode: "EXTRACTIVE",
		IdempotencyKey: base64.RawURLEncoding.EncodeToString(freshIdempotencyBytes),
	})
	if err != nil {
		t.Fatalf("create post-rollover question: %v (code=%s)", err, question.CodeOf(err))
	}
	if freshQuestion.ID == completed.ID || freshQuestion.ResultStatus != "COMPLETED" || len(freshQuestion.Citations) == 0 {
		t.Fatalf("post-rollover question id/status/citations=%s/%s/%d, want a fresh completed run with evidence",
			freshQuestion.ID, freshQuestion.ResultStatus, len(freshQuestion.Citations))
	}
	freshContext := captureContextRolloverSnapshot(t, ctx, admin, s1dOrg, freshQuestion.ID)
	if freshContext.sourceObjectID != objectID || freshContext.sourceVersionID != versionID ||
		freshContext.extractionID != newExtractionID || freshContext.activeExtraction != newExtractionID ||
		freshContext.activationRev != newActivationRevision || freshContext.extractionHash != newProfileHash {
		t.Fatalf("post-rollover question captured stale context tuple: object/version/extraction/active/revision/profile=%s/%s/%s/%s/%d/%s, want %s/%s/%s/%s/%d/%s",
			freshContext.sourceObjectID, freshContext.sourceVersionID, freshContext.extractionID,
			freshContext.activeExtraction, freshContext.activationRev, freshContext.extractionHash,
			objectID, versionID, newExtractionID, newExtractionID, newActivationRevision, newProfileHash)
	}
	var mixedFreshContextRows int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.question_retrieval_context_entry
		WHERE organization_id=$1 AND question_run_id=$2
		  AND (source_object_id IS DISTINCT FROM $3 OR source_version_id IS DISTINCT FROM $4
		    OR extraction_id IS DISTINCT FROM $5 OR active_extraction_id IS DISTINCT FROM $5
		    OR activation_revision IS DISTINCT FROM $6 OR extraction_profile_hash IS DISTINCT FROM $7)`,
		s1dOrg, freshQuestion.ID, objectID, versionID, newExtractionID, newActivationRevision, newProfileHash).
		Scan(&mixedFreshContextRows); err != nil {
		t.Fatal(err)
	}
	if mixedFreshContextRows != 0 {
		t.Fatalf("post-rollover question contains %d context rows outside the new active tuple", mixedFreshContextRows)
	}

	// Copying historical context into a different run is not an authorization
	// decision. This probe checks the trusted-authority guard (42501), not the
	// active-catalog guard, which executes later in the trigger chain.
	var runWorkspaceRevision int64
	var runWorkspaceScopeHash, retrievalVersion, policyRevision string
	if err := admin.QueryRow(ctx, `SELECT workspace_revision, workspace_scope_hash, retrieval_version, policy_revision
		FROM public.question_run WHERE organization_id=$1 AND id=$2`, s1dOrg, completed.ID).
		Scan(&runWorkspaceRevision, &runWorkspaceScopeHash, &retrievalVersion, &policyRevision); err != nil {
		t.Fatal(err)
	}
	staleRunID := mustID(t, "qrun")
	if err := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `INSERT INTO public.question_run
			(organization_id, id, workspace_id, workspace_revision, created_by, question_hash,
			 answer_mode, verification_method, result_status, corpus_status,
			 workspace_scope_hash, retrieval_version, policy_revision)
			VALUES ($1,$2,$3,$4,$5,$6,'EXTRACTIVE','BYTE_EXACT_CITATION','RUNNING','COMPLETE',$7,$8,$9)`,
			s1dOrg, staleRunID, s1dWorkspace, runWorkspaceRevision, s1dOwner,
			canon.Hash([]byte("stale active extraction context probe")), runWorkspaceScopeHash, retrievalVersion, policyRevision); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `INSERT INTO public.question_run_retention (organization_id, question_run_id)
			VALUES ($1,$2)`, s1dOrg, staleRunID)
		return err
	}); err != nil {
		t.Fatalf("create active question run for stale-context guard check: %v", err)
	}
	staleContextErr := appStore.Write(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(txCtx, `INSERT INTO public.question_retrieval_context_entry
			SELECT (jsonb_populate_record(NULL::public.question_retrieval_context_entry,
				to_jsonb(context_entry) || jsonb_build_object(
					'question_run_id', $1::text, 'ordinal', 1, 'authorized_at', transaction_timestamp()
				))).*
			FROM public.question_retrieval_context_entry context_entry
			WHERE context_entry.organization_id=$2 AND context_entry.question_run_id=$3
			ORDER BY context_entry.ordinal LIMIT 1`, staleRunID, s1dOrg, completed.ID)
		return err
	})
	if staleContextErr == nil || database.SQLStateCode(staleContextErr) != "42501" {
		t.Fatalf("copied historical context insert error=%v sqlstate=%s, want trusted-authority rejection 42501",
			staleContextErr, database.SQLStateCode(staleContextErr))
	}

	// The retained old extraction remains readable only while the actual source
	// confirmation is live; an immutable context snapshot is not a grant.
	var confirmationID, confirmationHash string
	if err := admin.QueryRow(ctx, `SELECT c.confirmation_id, c.confirmation_hash
		FROM public.workspace_managed_grant_confirmation c
		JOIN public.workspace w ON w.organization_id=c.organization_id AND w.id=c.workspace_id
		JOIN public.workspace_revision_source wrs ON wrs.organization_id=w.organization_id
		 AND wrs.workspace_id=w.id AND wrs.workspace_revision=w.current_revision
		 AND wrs.workspace_source_id=c.workspace_source_id AND wrs.source_scope_id=c.source_scope_id
		 AND wrs.source_scope_revision=c.source_scope_revision AND wrs.scope_config_hash=c.scope_config_hash
		 AND wrs.access_mode=c.access_mode AND wrs.enabled
		WHERE c.organization_id=$1 AND c.workspace_id=$2 AND c.workspace_source_id=$3
		  AND NOT EXISTS (SELECT 1 FROM public.workspace_managed_grant_revocation gr
			  WHERE gr.organization_id=c.organization_id AND gr.confirmation_id=c.confirmation_id)
		  AND NOT EXISTS (SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
			  WHERE ar.organization_id=c.organization_id AND ar.grant_id=c.confirmation_actor_grant_id)
		ORDER BY c.confirmation_id DESC LIMIT 1`, s1dOrg, authorityFixture.workspaceID,
		authorityFixture.workspaceSourceID).Scan(&confirmationID, &confirmationHash); err != nil {
		t.Fatalf("resolve active source confirmation: %v", err)
	}
	authority := newAuthorityRuntime(t, ctx)
	if _, err := authority.RevokeManagedConfirmation(ctx,
		authorityAccess(authorityFixture, s1dOwner, "req_context_rollover_revoke"),
		workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("context-rollover-revoke"), OrganizationID: s1dOrg,
			WorkspaceID: authorityFixture.workspaceID, ConfirmationID: confirmationID,
			ConfirmationHash: confirmationHash, ExpectedPolicyRevision: authorityFixture.policyID,
		}); err != nil {
		t.Fatalf("revoke source confirmation: %v", err)
	}
	revoked, err := viewer.ReadExactVersion(ctx, access, s1dWorkspace, before.fragmentID, versionID)
	if !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("exact old context read after source confirmation revoke error=%v, want ErrNotFound", err)
	}
	if revoked.FragmentID != "" || revoked.SourceVersionID != "" || len(revoked.Text) != 0 || len(revoked.Anchor) != 0 {
		t.Fatalf("revoked exact read disclosed old question evidence: %+v", revoked)
	}
}
