package postgres_test

import (
	"context"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// TestConversationCitationArtifactPurge exercises the three closed citation
// owner branches against a real source-backed Evidence fragment.  Conversation
// cleanup must erase the decryptable citation artifacts without touching the
// independently governed source Evidence or rewriting citation tombstone
// references.
func TestConversationCitationArtifactPurge(t *testing.T) {
	ctx, admin, versionID, extractionID, purger := s1ePurgeSetup(t)
	const (
		conversationID = "conv_citation_purge"
		questionRunID  = "qrun_citation_purge"
		turnID         = "turn_citation_purge"
		citationID     = "citation_citation_purge"
	)
	var objectID, sourceContentHash, fragmentID, evidenceTextHash string
	if err := admin.QueryRow(ctx, `
		SELECT source_object_id, content_hash
		  FROM public.source_version
		 WHERE organization_id=$1 AND id=$2
	`, s1dOrg, versionID).Scan(&objectID, &sourceContentHash); err != nil {
		t.Fatal(err)
	}
	if err := admin.QueryRow(ctx, `
		SELECT id, text_hash
		  FROM public.evidence_fragment
		 WHERE organization_id=$1 AND extraction_id=$2
		 ORDER BY ordinal LIMIT 1
	`, s1dOrg, extractionID).Scan(&fragmentID, &evidenceTextHash); err != nil {
		t.Fatal(err)
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	seedAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_citation_seed"}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run (
				organization_id, id, workspace_id, workspace_revision, created_by,
				conversation_id, conversation_turn_id, question_hash, answer_mode,
				verification_method, result_status, workspace_scope_hash, policy_revision
			) VALUES ($1,$2,$3,1,$4,$5,$6,$7,'EXTRACTIVE','BYTE_EXACT_CITATION','RUNNING',$7,'policy-citation-purge')
		`, s1dOrg, questionRunID, s1dWorkspace, s1dOwner, conversationID, turnID, "sha256:"+strings.Repeat("3", 64)); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation (organization_id,id,workspace_id,workspace_revision,created_by)
			VALUES ($1,$2,$3,1,$4)
		`, s1dOrg, conversationID, s1dWorkspace, s1dOwner); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_retention (organization_id,conversation_id,workspace_id,workspace_revision)
			VALUES ($1,$2,$3,1)
		`, s1dOrg, conversationID, s1dWorkspace); err != nil {
			return err
		}
		if _, err := tx.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id,question_run_id)
			VALUES ($1,$2)
		`, s1dOrg, questionRunID); err != nil {
			return err
		}
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.conversation_turn (
				organization_id,id,conversation_id,workspace_id,workspace_revision,turn_index,question_run_id
			) VALUES ($1,$2,$3,$4,1,1,$5)
		`, s1dOrg, turnID, conversationID, s1dWorkspace, questionRunID)
		return err
	}); err != nil {
		t.Fatalf("seed citation conversation: %v", err)
	}

	codec := s1dCodec(t, s1dOrg)
	artifactIDs := []string{mustID(t, "artifact"), mustID(t, "artifact"), mustID(t, "artifact")}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.CitationCitedExcerpt, s1dOrg, artifactIDs[0], citationID,
		"question_citation", "cited_excerpt_artifact_id", "CITED_EXCERPT", "EXACT_TEXT", []byte("citation excerpt"))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.CitationAnchor, s1dOrg, artifactIDs[1], citationID,
		"question_citation", "anchor_artifact_id", "CITATION_ANCHOR", "CANONICAL_ANCHOR", []byte("citation anchor"))
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.CitationDeepLink, s1dOrg, artifactIDs[2], citationID,
		"question_citation", "deep_link_artifact_id", "SOURCE_DEEPLINK", "DEEPLINK", []byte("citation link"))
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := appStore.Write(ctx, seedAccess, func(txCtx context.Context, tx database.Transaction) error {
		_, err := tx.Exec(txCtx, `
			INSERT INTO public.question_citation (
				organization_id,id,question_run_id,citation_number,source_object_id,source_version_id,
				extraction_id,evidence_fragment_id,cited_excerpt_artifact_id,source_version_content_hash,
				evidence_text_hash,cited_excerpt_hash,anchor_artifact_id,deep_link_artifact_id,state_at_generation
			) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'ACTIVE')
		`, s1dOrg, citationID, questionRunID, objectID, versionID, extractionID, fragmentID,
			artifactIDs[0], sourceContentHash, evidenceTextHash, "sha256:"+strings.Repeat("4", 64), artifactIDs[1], artifactIDs[2])
		return err
	}); err != nil {
		t.Fatalf("bind citation artifacts: %v", err)
	}

	if fence, err := purger.BeginConversationPurge(ctx, purgerAccess(), s1dWorkspace, conversationID, "RETENTION_REQUEST"); err != nil || fence != 1 {
		t.Fatalf("begin citation purge fence=%d err=%v, want fence 1", fence, err)
	}
	var activeArtifacts int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.encrypted_artifact
		 WHERE organization_id=$1 AND resource_id=$2 AND purged_at IS NULL
	`, s1dOrg, citationID).Scan(&activeArtifacts); err != nil {
		t.Fatal(err)
	}
	if activeArtifacts != len(artifactIDs) {
		t.Fatalf("begin changed citation artifact count=%d, want %d", activeArtifacts, len(artifactIDs))
	}
	if purged, err := purger.CompleteConversationPurge(ctx, purgerAccess(), s1dWorkspace, conversationID, "RETENTION_REQUEST"); err != nil || purged != int64(len(artifactIDs)) {
		t.Fatalf("complete citation purge count=%d err=%v, want %d", purged, err, len(artifactIDs))
	}
	var remainingCiphertext int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.encrypted_artifact
		 WHERE organization_id=$1 AND resource_id=$2 AND (ciphertext IS NOT NULL OR wrapped_dek IS NOT NULL)
	`, s1dOrg, citationID).Scan(&remainingCiphertext); err != nil {
		t.Fatal(err)
	}
	if remainingCiphertext != 0 {
		t.Fatalf("citation artifacts remain decryptable: %d", remainingCiphertext)
	}
	var citedExcerptRef, anchorRef, deepLinkRef string
	if err := admin.QueryRow(ctx, `
		SELECT cited_excerpt_artifact_id, anchor_artifact_id, deep_link_artifact_id
		  FROM public.question_citation WHERE organization_id=$1 AND id=$2
	`, s1dOrg, citationID).Scan(&citedExcerptRef, &anchorRef, &deepLinkRef); err != nil {
		t.Fatal(err)
	}
	if citedExcerptRef != artifactIDs[0] || anchorRef != artifactIDs[1] || deepLinkRef != artifactIDs[2] {
		t.Fatalf("purge rewrote citation tombstone refs: %s %s %s", citedExcerptRef, anchorRef, deepLinkRef)
	}

	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_source_after_citation_purge"}
	if _, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, fragmentID); err != nil {
		t.Fatalf("independent source Evidence was revoked by conversation purge: %v", err)
	}
}
