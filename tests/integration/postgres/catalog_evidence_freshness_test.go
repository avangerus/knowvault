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

// TestS1dSupersededVersionCannotResurrect pins the forward-only version
// lifecycle (FRESH-003): once a source_version is SUPERSEDED it can never
// return to CURRENT, so a stale write cannot make an old version fresh again.
// The refusal must come from the lifecycle guard and must leave the state
// unchanged (fail-closed).
func TestS1dSupersededVersionCannotResurrect(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	fileDir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(fileDir, "notes.txt"), "first version\n")

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
	access := workerAccess(t, s1dOrg)

	runSync(t, ctx, handler, queue, access, "sync-1")
	_, firstVersionID, _ := s1dActiveEvidence(t, ctx, admin)

	// Supersede the version through the legal lifecycle (CURRENT->SUPERSEDED)
	// so it is SUPERSEDED while no other CURRENT version exists. The
	// resurrection attempt below must then fail on the lifecycle guard alone,
	// not on the one-current partial index.
	if _, err := admin.Exec(ctx, `UPDATE public.source_version SET state='SUPERSEDED' WHERE organization_id=$1 AND id=$2`,
		s1dOrg, firstVersionID); err != nil {
		t.Fatalf("legal CURRENT->SUPERSEDED transition refused: %v", err)
	}

	var state string
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`,
		s1dOrg, firstVersionID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "SUPERSEDED" {
		t.Fatalf("first version state=%s, want SUPERSEDED", state)
	}

	// A stale write that tries to make the superseded version current again
	// must be refused by the forward-only lifecycle guard.
	if _, err := admin.Exec(ctx, `UPDATE public.source_version SET state='CURRENT' WHERE organization_id=$1 AND id=$2`,
		s1dOrg, firstVersionID); err == nil {
		t.Fatal("superseded version resurrected to CURRENT; forward-only lifecycle violated")
	} else if !strings.Contains(err.Error(), "source_version state transition is not permitted") {
		t.Fatalf("unexpected refusal: %v", err)
	}

	// The refused write leaves the version SUPERSEDED.
	if err := admin.QueryRow(ctx, `SELECT state FROM public.source_version WHERE organization_id=$1 AND id=$2`,
		s1dOrg, firstVersionID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "SUPERSEDED" {
		t.Fatalf("refused write changed state to %s", state)
	}
}
