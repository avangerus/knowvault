package postgres_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestP3SearchPersistenceUsesRealCatalogAndTenantRLS proves the first durable
// retrieval slice against the same live PostgreSQL catalog used by ingestion.
// It deliberately stops before OpenSearch composition: the rows are durable
// candidates, not a citation or disclosure authority.
func TestP3SearchPersistenceUsesRealCatalogAndTenantRLS(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(directory, "notes.txt"), "waste was collected today\n")
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")
	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New).WithSearchRepository(searchRepository)
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "search-p3")
	// A second full scan must reconcile the already-published extraction without
	// allocating another SearchChunk or outbox event.
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "search-p3-replay")
	_, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	access := workerAccess(t, s1dOrg)
	var chunkID string
	if err := admin.QueryRow(ctx, `SELECT id FROM public.search_chunk WHERE organization_id=$1 AND source_version_id=$2 AND extraction_id=$3`, s1dOrg, versionID, extractionID).Scan(&chunkID); err != nil {
		t.Fatalf("ingestion did not emit lexical SearchChunk: %v", err)
	}
	if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		return searchRepository.CreateStagingProfile(txCtx, transaction, access, mustID(t, "profile"),
			"sha256:"+strings.Repeat("f", 64), 1, 1, 0, 1, 0)
	}); err != nil {
		t.Fatalf("worker search projection write: %v (sqlstate=%s cause=%v)", err, database.SQLStateCode(err), errors.Unwrap(err))
	}
	// A replay after the transaction committed does not allocate a second event
	// sequence: the chunk id is the idempotency key for its initial projection.
	var replaySequence int64
	if err := workerStore.Write(ctx, access, func(txCtx context.Context, transaction database.Transaction) error {
		return transaction.QueryRow(txCtx,
			`SELECT app.enqueue_search_chunk_upsert($1)`, chunkID).Scan(&replaySequence)
	}); err != nil {
		t.Fatalf("worker search outbox replay: %v (sqlstate=%s cause=%v)", err, database.SQLStateCode(err), errors.Unwrap(err))
	}
	if replaySequence != 1 {
		t.Fatalf("search outbox replay sequence = %d, want 1", replaySequence)
	}

	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	assertSearchProjectionCount(t, ctx, app, "org_s1d", 1, 1, 1)
	assertSearchProjectionCount(t, ctx, app, "org_other", 0, 0, 0)

	// The worker publication is in the same transaction as the SearchChunk and
	// encrypted text bind. App can inspect the typed reference event but cannot
	// insert or publish it, and no plaintext appears in the JSON payload.
	outboxTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = outboxTransaction.Rollback(ctx) }()
	setAccessContext(t, ctx, outboxTransaction, s1dOrg)
	var sequence int64
	var aggregateType, eventType string
	var payload string
	if err := outboxTransaction.QueryRow(ctx, `
		SELECT sequence, aggregate_type, event_type, payload_json::text
		  FROM public.outbox_event
		 WHERE organization_id=$1 AND id=$2`, s1dOrg, chunkID).
		Scan(&sequence, &aggregateType, &eventType, &payload); err != nil {
		t.Fatal(err)
	}
	if sequence != 1 || aggregateType != "SEARCH_CHUNK" || eventType != "search.chunk.upsert" {
		t.Fatalf("search outbox event identity = (%d,%s,%s)", sequence, aggregateType, eventType)
	}
	if strings.Contains(payload, "waste was collected today") {
		t.Fatal("search outbox payload leaked plaintext")
	}
	if !strings.Contains(payload, `"search_chunk_id"`) || !strings.Contains(payload, `"operation": "UPSERT"`) {
		t.Fatalf("search outbox payload is missing typed references: %s", payload)
	}
	var otherTenantEvents int
	otherTransaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContext(t, ctx, otherTransaction, "org_other")
	if err := otherTransaction.QueryRow(ctx, `SELECT count(*) FROM public.outbox_event`).Scan(&otherTenantEvents); err != nil {
		t.Fatal(err)
	}
	_ = otherTransaction.Rollback(ctx)
	if otherTenantEvents != 0 {
		t.Fatalf("other tenant observed %d search outbox events", otherTenantEvents)
	}

	// App role is read-only on the derived projection and cannot mutate it.
	transaction, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setAccessContext(t, ctx, transaction, s1dOrg)
	if _, err := transaction.Exec(ctx, `DELETE FROM public.search_chunk WHERE organization_id=$1`, s1dOrg); err == nil {
		t.Fatal("application role unexpectedly deleted a search chunk")
	}
}

func assertSearchProjectionCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	organizationID string, chunks, fragments, profiles int) {
	t.Helper()
	transaction, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setAccessContext(t, ctx, transaction, organizationID)
	var gotChunks, gotFragments, gotProfiles int
	if err := transaction.QueryRow(ctx, `SELECT count(*) FROM public.search_chunk`).Scan(&gotChunks); err != nil {
		t.Fatal(err)
	}
	if err := transaction.QueryRow(ctx, `SELECT count(*) FROM public.search_chunk_fragment`).Scan(&gotFragments); err != nil {
		t.Fatal(err)
	}
	if err := transaction.QueryRow(ctx, `SELECT count(*) FROM public.organization_search_profile`).Scan(&gotProfiles); err != nil {
		t.Fatal(err)
	}
	if gotChunks != chunks || gotFragments != fragments || gotProfiles != profiles {
		t.Fatalf("organization %s projection counts = (%d,%d,%d), want (%d,%d,%d)",
			organizationID, gotChunks, gotFragments, gotProfiles, chunks, fragments, profiles)
	}
}
