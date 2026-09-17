package postgres_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestOCRExtractionIdentityConstraints is a real PostgreSQL proof for the
// forward OCR schema gate. The row is attached to a real SourceVersion created
// by the folder ingestion path; only the OCR extraction identity itself is
// inserted directly so this test isolates the database contract and cannot
// accidentally pass through Go-side validation.
func TestOCRExtractionIdentityConstraints(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "identity.txt"), "seed source version")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "ocr-identity-seed")
	_, versionID, _ := s1dTargetEvidence(t, ctx, admin, "projects/alpha/identity.txt")

	const (
		profileHash  = "sha256:" + "a" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		artifactHash = "sha256:" + "b" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	newExtraction := func(t *testing.T) string {
		t.Helper()
		id, err := ids.New("extraction")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	insert := func(t *testing.T, canonical string, used bool, modelID, modelRevision, modelHash, profileRevision string) error {
		t.Helper()
		id := newExtraction(t)
		_, err := admin.Exec(ctx, `INSERT INTO public.source_extraction
			(organization_id, id, source_version_id, retention_fence_at_start, canonical_format,
			 profile_json, profile_hash, extractor_name, extractor_version, extractor_artifact_hash,
			 normalization_version, parser_profile_revision, ocr_used, ocr_model_id,
			 ocr_model_revision, ocr_artifact_hash, ocr_profile_revision, status, started_at)
			VALUES ($1,$2,$3,0,$4,'{}'::jsonb,$5,'knowvault-ocr-test','1.0.0',$6,'text-v1','ocr-v1',$7,$8,$9,$10,$11,'RUNNING',now())`,
			s1dOrg, id, versionID, canonical, profileHash, artifactHash, used,
			nullable(modelID), nullable(modelRevision), nullable(modelHash), nullable(profileRevision))
		return err
	}

	if err := insert(t, "OCR", true, "eng", "tessdata-v1", artifactHash, "tessdata-v1"); err != nil {
		t.Fatalf("complete OCR identity was rejected: %v", err)
	}

	for name, args := range map[string]struct {
		canonical, modelID, modelRevision, modelHash, profileRevision string
		used                                                               bool
	}{
		"used-on-text": {canonical: "TEXT", used: true, modelID: "eng", modelRevision: "tessdata-v1", modelHash: artifactHash, profileRevision: "tessdata-v1"},
		"missing-model": {canonical: "OCR", used: true, modelRevision: "tessdata-v1", modelHash: artifactHash, profileRevision: "tessdata-v1"},
		"unused-with-identity": {canonical: "TEXT", used: false, modelID: "eng", modelRevision: "tessdata-v1", modelHash: artifactHash, profileRevision: "tessdata-v1"},
		"invalid-model-hash": {canonical: "OCR", used: true, modelID: "eng", modelRevision: "tessdata-v1", modelHash: "not-a-hash", profileRevision: "tessdata-v1"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := insert(t, args.canonical, args.used, args.modelID, args.modelRevision, args.modelHash, args.profileRevision); err == nil {
				t.Fatal("incomplete or mismatched OCR identity unexpectedly committed")
			}
		})
	}

	var used bool
	var modelID, modelRevision, storedHash, profileRevision *string
	if err := admin.QueryRow(ctx, `SELECT ocr_used, ocr_model_id, ocr_model_revision, ocr_artifact_hash, ocr_profile_revision
		FROM public.source_extraction WHERE organization_id=$1 AND source_version_id=$2 AND ocr_used`, s1dOrg, versionID).
		Scan(&used, &modelID, &modelRevision, &storedHash, &profileRevision); err != nil {
		t.Fatal(err)
	}
	if !used || modelID == nil || modelRevision == nil || storedHash == nil || profileRevision == nil ||
		*modelID != "eng" || *modelRevision != "tessdata-v1" || *storedHash != artifactHash || *profileRevision != "tessdata-v1" {
		t.Fatalf("stored OCR identity drifted: used=%v model=%v/%v hash=%v profile=%v", used, modelID, modelRevision, storedHash, profileRevision)
	}
}

func nullable(value string) *string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return &value
}
