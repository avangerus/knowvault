package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestP3RetrievalAuthorizationSnapshotLive proves that post-authorization
// provenance is durable and exact-match bound to the current catalog. It uses
// the real folder->Evidence path, app role, encrypted candidate artifact and
// workspace binding; no index or model runtime is substituted.
func TestP3RetrievalAuthorizationSnapshotLive(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "projects", "alpha"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(root, "projects", "alpha", "notes.txt"), "waste was collected today\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_retrieval_live", "confirmation_retrieval_live")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "retrieval-snapshot")

	var versionID, extractionID, fragmentID, objectID string
	var fragmentTextHash, anchorHash, contentHash, profileHash string
	var versionState, versionRetentionState, extractionRetentionState string
	var versionQueryable, extractionQueryable bool
	var versionFence, extractionFence, activationRevision int64
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_retrieval_snapshot"}
	repository, err := retrieval.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	var runID string
	var capturedProvenance retrieval.AccessProvenance
	if err := appStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		if err := transaction.QueryRow(txCtx, `
			SELECT object.id, version.id, extraction.id, fragment.id,
			       fragment.text_hash, fragment.anchor_hash, version.content_hash,
			       version.state, version_retention.state, version_retention.queryable,
			       version_retention.retention_fence, extraction.profile_hash,
			       extraction_retention.state, extraction_retention.queryable,
			       extraction.retention_fence_at_start, active_extraction.activation_revision
			  FROM public.evidence_fragment fragment
			  JOIN public.source_version version
			    ON version.organization_id=fragment.organization_id AND version.id=fragment.source_version_id
			  JOIN public.source_object object
			    ON object.organization_id=version.organization_id AND object.id=version.source_object_id
			  JOIN public.source_version_retention version_retention
			    ON version_retention.organization_id=version.organization_id AND version_retention.source_version_id=version.id
			  JOIN public.source_extraction extraction
			    ON extraction.organization_id=fragment.organization_id AND extraction.id=fragment.extraction_id
			  JOIN public.source_extraction_retention extraction_retention
			    ON extraction_retention.organization_id=extraction.organization_id AND extraction_retention.extraction_id=extraction.id
			  JOIN public.source_version_active_extraction active_extraction
			    ON active_extraction.organization_id=version.organization_id AND active_extraction.source_version_id=version.id
			 WHERE fragment.organization_id=$1
			 LIMIT 1`, s1dOrg).Scan(&objectID, &versionID, &extractionID, &fragmentID,
			&fragmentTextHash, &anchorHash, &contentHash, &versionState, &versionRetentionState,
			&versionQueryable, &versionFence, &profileHash, &extractionRetentionState,
			&extractionQueryable, &extractionFence, &activationRevision); err != nil {
			return err
		}
		if err := transaction.QueryRow(txCtx, `
			INSERT INTO public.question_run
				(organization_id, id, workspace_id, workspace_revision, created_by, question_hash,
				 answer_mode, verification_method, result_status, corpus_status,
				 workspace_scope_hash, retrieval_version, policy_revision)
			VALUES ($1,$2,$3,1,$4,$5,'EXTRACTIVE','BYTE_EXACT_CITATION','RUNNING','COMPLETE',
				$6,'retrieval-p3-v1','policy-s1d-01ARZ3NDEKTSV4RRFFQ69G5FAV')
			RETURNING id`, s1dOrg, mustID(t, "qrun"), s1dWorkspace, s1dOwner,
			canon.Hash([]byte("retrieval snapshot question")),
			sha256Value("a")).Scan(&runID); err != nil {
			return err
		}
		if _, err := transaction.Exec(txCtx, `
			INSERT INTO public.question_run_retention (organization_id, question_run_id)
			VALUES ($1,$2)`, s1dOrg, runID); err != nil {
			return err
		}
		var startedAt time.Time
		if err := transaction.QueryRow(txCtx, `SELECT started_at FROM public.question_run WHERE organization_id=$1 AND id=$2`, s1dOrg, runID).Scan(&startedAt); err != nil {
			return err
		}
		provenance, err := repository.CaptureAccessProvenance(txCtx, transaction, access, runID, startedAt)
		if err != nil {
			return err
		}
		capturedProvenance = provenance
		if err := repository.CreateCorpusSnapshot(txCtx, transaction, access, retrieval.CorpusSnapshot{
			ID: mustID(t, "corpus"), OrganizationID: s1dOrg, QuestionRunID: runID,
			SourceScopeID: s1dScopeID, SourceScopeRevision: 1, AccessMode: "WORKSPACE_MANAGED",
			ScopeConfigHash: configHash, ConnectorType: "FOLDER", ConnectorVersion: "folder-live-v1",
			Health: "HEALTHY", ContentWatermark: 1, CapturedAt: startedAt,
		}); err != nil {
			return err
		}
		canonicalBytes := []byte(`{"schema_version":"authorized-candidate-set-v1","candidates":[{"evidence_fragment_id":"` + fragmentID + `","evidence_text_hash":"` + fragmentTextHash + `"}]}`)
		candidateSetHash := canon.Hash(canonicalBytes)
		candidateSet := retrieval.CandidateSet{OrganizationID: s1dOrg, QuestionRunID: runID,
			CandidateCount: 1, CandidateSetHash: candidateSetHash, CanonicalBytes: canonicalBytes}
		if err := repository.CreateCandidateSet(txCtx, transaction, access, candidateSet); err != nil {
			return err
		}
		artifactID := mustID(t, "artifact")
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.AuthorizedCandidateSet, s1dOrg, runID)
		if err != nil {
			return err
		}
		envelope, err := codec.Seal(owner, canonicalBytes)
		if err != nil {
			return err
		}
		if err := repository.BindCandidateSetArtifact(txCtx, transaction, access, runID, artifactID, envelope); err != nil {
			return err
		}
		if err := repository.AddCandidate(txCtx, transaction, access, retrieval.Candidate{
			OrganizationID: s1dOrg, QuestionRunID: runID, Ordinal: 1, EvidenceFragmentID: fragmentID,
			SourceVersionID: versionID, ExtractionID: extractionID, EvidenceTextHash: fragmentTextHash,
			ExactContextHash: sha256Value("b"), AuthorizationGrantHash: sha256Value("c"),
		}); err != nil {
			return err
		}
		now := startedAt.Add(time.Millisecond)
		if err := repository.AddContextEntry(txCtx, transaction, access, retrieval.ContextEntry{
			OrganizationID: s1dOrg, QuestionRunID: runID, Ordinal: 1, SourceObjectID: objectID,
			SourceVersionID: versionID, SourceVersionState: versionState,
			SourceVersionRetentionState: versionRetentionState, SourceVersionQueryable: versionQueryable,
			SourceVersionRetentionFence: versionFence, ExtractionID: extractionID,
			ActiveExtractionID: extractionID, ActivationRevision: activationRevision,
			ExtractionRetentionState: extractionRetentionState, ExtractionQueryable: extractionQueryable,
			ExtractionRetentionFenceAtStart: extractionFence, EvidenceFragmentID: fragmentID,
			ExtractionProfileHash: profileHash, SourceVersionContentHash: contentHash,
			EvidenceTextHash: fragmentTextHash, AnchorHash: anchorHash, ExactContextHash: sha256Value("b"),
			SourceScopeID: s1dScopeID, SourceScopeRevision: 1, AccessMode: "WORKSPACE_MANAGED",
			MembershipState: "ACTIVE", PolicyDecisionID: provenance.PolicyDecisionID, PolicyDecision: "ALLOW",
			PrincipalSetSnapshotID: provenance.PrincipalSetSnapshotID, PrincipalSetSnapshotHash: provenance.PrincipalSetSnapshotHash,
			PrincipalSetCapturedAt: provenance.CapturedAt, PrincipalSetExpiresAt: provenance.ExpiresAt, AuthorizedAt: now,
		}); err != nil {
			return err
		}
		snapshotBytes := []byte(`{"schema_version":"retrieval-authorization-snapshot-v1","authorized_candidate_count":1,"context_count":1}`)
		if err := repository.CreateAuthorizationSnapshot(txCtx, transaction, access, retrieval.AuthorizationSnapshot{
			OrganizationID: s1dOrg, QuestionRunID: runID, CapturedAt: now.Add(time.Millisecond),
			PipelineVersion: "retrieval-p3-v1", PipelineProfileHash: sha256Value("f"),
			AuthorizedCandidateSetHash: candidateSetHash, AuthorizedCandidateCount: 1, ContextCount: 1,
			ErrorCodes: []string{}, CanonicalBytes: snapshotBytes, SnapshotHash: canon.Hash(snapshotBytes),
		}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("retrieval authorization snapshot write: %v (sqlstate=%s cause=%v)", err, database.SQLStateCode(err), errors.Unwrap(err))
	}

	assertRetrievalSnapshotCounts(t, ctx, appStore, s1dOrg, s1dOwner, 1, 1, 1, 1)
	assertRetrievalSnapshotCounts(t, ctx, appStore, "org_other", "usr_test", 0, 0, 0, 0)

	// Snapshot and candidate rows are immutable once captured. An app caller
	// cannot rewrite evidence hashes or delete the provenance chain.
	checkRetrievalSnapshotImmutable(t, ctx, appStore, s1dOrg, s1dOwner)

	// Revoking the principal session after capture must invalidate the
	// post-authorization resolver; a persisted ALLOW is not a bypass around
	// current identity state.
	if _, err := admin.Exec(ctx, `UPDATE public.principal SET session_revision = session_revision + 1 WHERE organization_id=$1 AND id=$2`, s1dOrg, s1dOwner); err != nil {
		t.Fatal(err)
	}
	if err := appStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		_, _, resolveErr := repository.ResolveEvidence(txCtx, transaction, access, runID, fragmentID, 1, capturedProvenance.CapturedAt.Add(time.Millisecond))
		if resolveErr == nil {
			t.Fatal("ResolveEvidence succeeded after principal session revocation")
		}
		if retrieval.CodeOf(resolveErr) != retrieval.CodeDenied {
			t.Fatalf("ResolveEvidence revocation code=%s err=%v", retrieval.CodeOf(resolveErr), resolveErr)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertRetrievalSnapshotCounts(t *testing.T, ctx context.Context, store *database.Store,
	organizationID, principalID string, corpus, candidates, contextEntries, snapshots int) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: principalID, RequestID: "req_retrieval_counts"}
	if err := store.Read(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		var gotCorpus, gotCandidates, gotContext, gotSnapshots int
		if err := transaction.QueryRow(txCtx, `SELECT count(*) FROM public.question_corpus_snapshot`).Scan(&gotCorpus); err != nil {
			return err
		}
		if err := transaction.QueryRow(txCtx, `SELECT count(*) FROM public.question_authorized_candidate`).Scan(&gotCandidates); err != nil {
			return err
		}
		if err := transaction.QueryRow(txCtx, `SELECT count(*) FROM public.question_retrieval_context_entry`).Scan(&gotContext); err != nil {
			return err
		}
		if err := transaction.QueryRow(txCtx, `SELECT count(*) FROM public.question_retrieval_authorization_snapshot`).Scan(&gotSnapshots); err != nil {
			return err
		}
		if gotCorpus != corpus || gotCandidates != candidates || gotContext != contextEntries || gotSnapshots != snapshots {
			t.Fatalf("tenant %s retrieval counts=(%d,%d,%d,%d), want=(%d,%d,%d,%d)", organizationID,
				gotCorpus, gotCandidates, gotContext, gotSnapshots, corpus, candidates, contextEntries, snapshots)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func checkRetrievalSnapshotImmutable(t *testing.T, ctx context.Context, store *database.Store, organizationID, principalID string) {
	t.Helper()
	access := database.AccessContext{OrganizationID: organizationID, PrincipalID: principalID, RequestID: "req_retrieval_immutable"}
	if err := store.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		_, err := transaction.Exec(txCtx, `UPDATE public.question_authorized_candidate SET evidence_text_hash=$1`, sha256Value("z"))
		return err
	}); err == nil {
		t.Fatal("candidate update unexpectedly succeeded")
	}
	if err := store.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		_, err := transaction.Exec(txCtx, `DELETE FROM public.question_retrieval_context_entry`)
		return err
	}); err == nil {
		t.Fatal("context delete unexpectedly succeeded")
	}
}
