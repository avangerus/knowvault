package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestWorkerArtifactReadGateDeniesNonWorkerRoleAndAllowsWorker proves D7-1 at
// the access point: the worker's own artifact branches authorize every read,
// and a session outside the dedicated worker role (the web/API runtime role)
// receives a typed denial even when it presents a valid tenant context and a
// real fragment id, while the worker role under the same tenant reads and
// decrypts the fragment envelope.
func TestWorkerArtifactReadGateDeniesNonWorkerRoleAndAllowsWorker(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "gate canary one\ngate two\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	// The claim-time liveness re-check (000018 s5) needs a live confirmation.
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, _ := jobs.New(workerStore)
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "gate")

	// The worker's read path resolves the encrypted scope-config artifact by
	// its stored resource id (the seed stores a hash-derived id, not the
	// display artifact id). This is the branch the pipeline really reads, so
	// the gate must admit the worker role and refuse the web/API runtime role.
	var scopeConfigArtifactID string
	if err := admin.QueryRow(ctx, `SELECT resource_id FROM public.encrypted_artifact
		WHERE organization_id=$1 AND resource_type='SOURCE_SCOPE_CONFIG'`, s1dOrg).Scan(&scopeConfigArtifactID); err != nil {
		t.Fatalf("resolve scope config artifact: %v", err)
	}

	// The web/API runtime role presents a valid tenant context and the real
	// artifact id: the worker-branch gate must still refuse it with the typed
	// repository denial (never a not-found and never a plaintext disclosure).
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	appAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_gate_app"}
	if err := appAccess.Validate(); err != nil {
		t.Fatalf("app access context: %v", err)
	}
	denied := appStore.Read(ctx, appAccess, func(ctx context.Context, tx database.Transaction) error {
		_, _, err := mustRepo(t).Fetch(ctx, tx, appAccess, artifactcrypto.SourceScopeConfig, scopeConfigArtifactID)
		return err
	})
	if !errors.As(denied, new(*repository.Error)) || repository.CodeOf(denied) != repository.CodeDenied {
		t.Fatalf("app-role read = %v (code %s), want typed CodeDenied", denied, repository.CodeOf(denied))
	}

	// The worker role under the same tenant passes the gate and can decrypt.
	workerDenied := workerStore.Read(ctx, workerAccess(t, s1dOrg), func(ctx context.Context, tx database.Transaction) error {
		owner, envelope, err := mustRepo(t).Fetch(ctx, tx, workerAccess(t, s1dOrg), artifactcrypto.SourceScopeConfig, scopeConfigArtifactID)
		if err != nil {
			return err
		}
		if _, err := codec.Open(owner, envelope); err != nil {
			return err
		}
		return nil
	})
	if workerDenied != nil {
		t.Fatalf("worker-role read = %v, want success", workerDenied)
	}
}
