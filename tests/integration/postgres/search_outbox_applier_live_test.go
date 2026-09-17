package postgres_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/purge"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// TestP3SearchOutboxApplierAgainstLiveOpenSearch proves the durable worker
// bridge against a real OpenSearch HTTPS endpoint.  PostgreSQL remains the
// source of truth: the event is indexed first, then published through the
// worker-only ordered function, and a retry sees an empty queue.  The test is
// opt-in because the normal PostgreSQL suite intentionally has no qualified
// OpenSearch dependency.
func TestP3SearchOutboxApplierAgainstLiveOpenSearch(t *testing.T) {
	endpoint := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_URL"))
	rootPath := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ROOT_CA"))
	certificatePath := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_CERT"))
	keyPath := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_KEY"))
	alias := strings.TrimSpace(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ALIAS"))
	if endpoint == "" || rootPath == "" || certificatePath == "" || keyPath == "" || alias == "" {
		t.Skip("live OpenSearch TLS variables are not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
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
	queue := mustQueue(t, workerStore)
	handler := newS1dHandler(t, workerStore, queue, codec, root).WithKnowledgeGraph(knowledgegraph.NewRepository())
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "search-live")
	_, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragmentID := s1dFragments(t, ctx, admin, extractionID)[0].id
	chunkID := mustID(t, "chunk")
	artifactID := mustID(t, "artifact")
	owner := mustSearchOwner(t, s1dOrg, chunkID)
	envelope, err := codec.Seal(owner, []byte("waste was collected today"))
	if err != nil {
		t.Fatal(err)
	}
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	workerAccessContext := workerAccess(t, s1dOrg)
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
		chunk := search.Chunk{
			ID: chunkID, OrganizationID: s1dOrg, SourceVersionID: versionID,
			ExtractionID: extractionID, ChunkHash: envelope.PlaintextHash(), TokenCount: 4,
			EmbeddingProfileHash:       "sha256:" + strings.Repeat("d", 64),
			EmbeddingModelArtifactHash: "sha256:" + strings.Repeat("e", 64),
			EmbeddingDimension:         384,
		}
		if err := searchRepository.CreateChunk(txCtx, transaction, workerAccessContext, chunk, artifactID, envelope); err != nil {
			return err
		}
		if err := searchRepository.AddFragment(txCtx, transaction, workerAccessContext, chunkID, fragmentID, 1); err != nil {
			return err
		}
		if err := searchRepository.CreateStagingProfile(txCtx, transaction, workerAccessContext,
			mustID(t, "profile"), "sha256:"+strings.Repeat("f", 64), 1, 1, 1, 1, 1); err != nil {
			return err
		}
		return searchRepository.ActivateProfile(txCtx, transaction, workerAccessContext, 1, 1, 1, 1, time.Now().UTC())
	}); err != nil {
		t.Fatalf("durable search projection: %v", err)
	}

	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootBytes) {
		t.Fatal("OpenSearch trust root is not a PEM certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	client, err := search.New(search.Config{
		Endpoint: endpoint, IndexAlias: alias, OrganizationID: s1dOrg,
		Generation: 1, GenerationFence: 1,
		TrustRoots: roots, ClientCertificate: &certificate, Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := search.NewApplier(workerStore, searchRepository, codec, client)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := applier.ApplyOnce(ctx, workerAccessContext)
	if err != nil || !applied {
		t.Fatalf("live outbox applier: applied=%v err=%v cause=%v", applied, err, errors.Unwrap(err))
	}
	t.Cleanup(func() { _ = client.Delete(context.Background(), chunkID) })
	var publishedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT published_at FROM public.outbox_event WHERE organization_id=$1 AND id=$2`, s1dOrg, chunkID).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	if publishedAt.IsZero() {
		t.Fatal("search outbox event remained unpublished after successful index")
	}
	if applied, err := applier.ApplyOnce(ctx, workerAccessContext); err != nil || applied {
		t.Fatalf("published event replay: applied=%v err=%v", applied, err)
	}
	// Retention is authoritative even after the SearchChunk and outbox rows
	// committed.  A purge/retention transition racing the worker must stop the
	// external PUT before any stale cleartext is projected.  Restoring the
	// queryable bit is safe here (the state remains ACTIVE) and lets the same
	// event prove retry convergence after the transient denial.
	retentionChunkID := mustID(t, "chunk")
	retentionArtifactID := mustID(t, "artifact")
	retentionOwner := mustSearchOwner(t, s1dOrg, retentionChunkID)
	retentionEnvelope, err := codec.Seal(retentionOwner, []byte("waste was collected today, retention probe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
		chunk := search.Chunk{
			ID: retentionChunkID, OrganizationID: s1dOrg, SourceVersionID: versionID,
			ExtractionID: extractionID, ChunkHash: retentionEnvelope.PlaintextHash(), TokenCount: 6,
			EmbeddingProfileHash:       "sha256:" + strings.Repeat("d", 64),
			EmbeddingModelArtifactHash: "sha256:" + strings.Repeat("e", 64), EmbeddingDimension: 384,
		}
		if err := searchRepository.CreateChunk(txCtx, transaction, workerAccessContext, chunk, retentionArtifactID, retentionEnvelope); err != nil {
			return err
		}
		return searchRepository.AddFragment(txCtx, transaction, workerAccessContext, retentionChunkID, fragmentID, 1)
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Delete(context.Background(), retentionChunkID) })
	if _, err := admin.Exec(ctx, `UPDATE public.source_extraction_retention
		SET queryable=false
		WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID); err != nil {
		t.Fatal(err)
	}
	if applied, err := applier.ApplyOnce(ctx, workerAccessContext); applied || search.CodeOf(err) != search.CodeProfileUnavailable {
		t.Fatalf("non-queryable retention applier: applied=%v code=%q", applied, search.CodeOf(err))
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_extraction_retention
		SET queryable=true
		WHERE organization_id=$1 AND extraction_id=$2`, s1dOrg, extractionID); err != nil {
		t.Fatal(err)
	}
	if applied, err := applier.ApplyOnce(ctx, workerAccessContext); err != nil || !applied {
		t.Fatalf("retention event retry: applied=%v err=%v cause=%v", applied, err, errors.Unwrap(err))
	}
	// A worker bound to a newer alias generation cannot replay the still-active
	// profile. The event remains pending and no OpenSearch request is made.
	staleChunkID := mustID(t, "chunk")
	staleArtifactID := mustID(t, "artifact")
	staleOwner := mustSearchOwner(t, s1dOrg, staleChunkID)
	staleEnvelope, err := codec.Seal(staleOwner, []byte("stale generation probe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
		chunk := search.Chunk{
			ID: staleChunkID, OrganizationID: s1dOrg, SourceVersionID: versionID,
			ExtractionID: extractionID, ChunkHash: staleEnvelope.PlaintextHash(), TokenCount: 3,
			EmbeddingProfileHash:       "sha256:" + strings.Repeat("d", 64),
			EmbeddingModelArtifactHash: "sha256:" + strings.Repeat("e", 64), EmbeddingDimension: 384,
		}
		if err := searchRepository.CreateChunk(txCtx, transaction, workerAccessContext, chunk, staleArtifactID, staleEnvelope); err != nil {
			return err
		}
		return searchRepository.AddFragment(txCtx, transaction, workerAccessContext, staleChunkID, fragmentID, 1)
	}); err != nil {
		t.Fatal(err)
	}
	staleClient, err := search.New(search.Config{
		Endpoint: endpoint, IndexAlias: alias, OrganizationID: s1dOrg,
		Generation: 2, GenerationFence: 1, TrustRoots: roots, ClientCertificate: &certificate,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	staleApplier, err := search.NewApplier(workerStore, searchRepository, codec, staleClient)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := staleApplier.ApplyOnce(ctx, workerAccessContext); applied || search.CodeOf(err) != search.CodeProfileUnavailable {
		t.Fatalf("stale generation applier: applied=%v code=%q", applied, search.CodeOf(err))
	}
	var result search.Result
	indexed := false
	for attempt := 0; attempt < 50; attempt++ {
		result, err = client.Search(ctx, search.Query{Text: "waste collected", Size: 10})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total >= 1 && len(result.Hits) >= 1 && result.Hits[0].Document.ID == chunkID {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if result.Total < 1 || len(result.Hits) < 1 || result.Hits[0].Document.ID != chunkID {
		t.Fatalf("live OpenSearch result did not contain indexed chunk before post-authorization: %+v", result)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	executor, err := retrieval.NewExecutor(client, viewer)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := executor.Retrieve(ctx,
		database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_search_live"},
		s1dWorkspace, "waste collected")
	if err != nil {
		t.Fatalf("post-authorized retrieval: %v", err)
	}
	if authorized.Partial || len(authorized.Candidates) != 1 || authorized.Candidates[0].ID != fragmentID ||
		string(authorized.Candidates[0].Text) != "waste was collected today" {
		t.Fatalf("post-authorized retrieval=%+v, want one exact Evidence candidate", authorized)
	}
	// The graph-aware execution path consumes the same live OpenSearch result
	// plus semantic terms produced by the worker ingestion transaction. Vector
	// qualification is intentionally absent in this environment, so the fused
	// result must remain explicitly partial rather than publishing a complete
	// answer from lexical/entity signals alone.
	hybridExecutor, err := retrieval.NewExecutorWithGraph(client, viewer, appStore, knowledgegraph.NewRepository())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := planner.New().Plan("Where was waste collected today?")
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := hybridExecutor.RetrievePlan(ctx,
		database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_search_hybrid"},
		s1dWorkspace, plan)
	if err != nil {
		for cause := err; cause != nil; cause = errors.Unwrap(cause) {
			t.Logf("graph-aware hybrid failure: %T: %v", cause, cause)
		}
		t.Fatalf("graph-aware hybrid retrieval: %v", err)
	}
	if !hybrid.Partial || len(hybrid.Candidates) == 0 || hybrid.Candidates[0].ID != fragmentID {
		t.Fatalf("hybrid retrieval=%+v, want authorized candidate with explicit vector partial", hybrid)
	}
	for index := range hybrid.Candidates {
		clear(hybrid.Candidates[index].Text)
		clear(hybrid.Candidates[index].Anchor)
	}
	for index := range authorized.Candidates {
		clear(authorized.Candidates[index].Text)
		clear(authorized.Candidates[index].Anchor)
	}
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatal(err)
	}
	questions, err := question.NewWithRetrieval(appStore, auditStore, codec, viewer, executor)
	if err != nil {
		t.Fatal(err)
	}
	idempotencyKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	run, err := questions.Create(ctx,
		database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dOwner, RequestID: "req_search_question"},
		question.CreateRequest{WorkspaceID: s1dWorkspace, Question: "What was collected today?", AnswerMode: "EXTRACTIVE", IdempotencyKey: idempotencyKey})
	if err != nil {
		t.Fatalf("question with live retrieval: %v", err)
	}
	if run.ResultStatus != "COMPLETED" || len(run.Citations) != 1 || !strings.Contains(run.Answer, "waste was collected today") {
		t.Fatalf("question run=%+v, want completed exact Evidence-backed answer", run)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.workspace_member SET removed_at=now(), valid_to_revision=2
		WHERE organization_id=$1 AND workspace_id=$2 AND principal_id=$3`, s1dOrg, s1dWorkspace, s1dViewer); err != nil {
		t.Fatal(err)
	}
	revoked, err := executor.Retrieve(ctx,
		database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_search_revoked"},
		s1dWorkspace, "waste collected")
	if err != nil {
		t.Fatalf("revoked post-authorized retrieval: %v", err)
	}
	if !revoked.Partial || len(revoked.Candidates) != 0 {
		t.Fatalf("revoked retrieval=%+v, want fail-closed partial with no candidates", revoked)
	}
	for attempt := 0; attempt < 50; attempt++ {
		result, err = client.Search(ctx, search.Query{Text: "waste collected", Size: 10})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total >= 1 && len(result.Hits) >= 1 && result.Hits[0].Document.ID == chunkID {
			indexed = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !indexed {
		t.Fatalf("live OpenSearch result did not contain indexed chunk: %+v", result)
	}

	// Retention cleanup is exercised against the same live cluster.  It first
	// erases SearchChunk ciphertext and appends DELETE events; the worker then
	// converges both already-published and purge-racing UPSERTs to an external
	// absence before the test accepts the purge as complete.
	purgerStore := openStore(t, ctx, purgerRole, "knowvault_purger")
	purger, err := purge.NewPurger(purgerStore, time.Now, ids.New)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := purger.BeginPurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("live search begin purge: %v", err)
	}
	if purged, err := purger.Cleanup(ctx, purgerAccess(), versionID); err != nil || purged == 0 {
		t.Fatalf("live search cleanup: purged=%d err=%v", purged, err)
	}
	if err := purger.CompletePurge(ctx, purgerAccess(), versionID, "OPERATOR_REQUEST"); err != nil {
		t.Fatalf("live search complete purge: %v", err)
	}
	if drained, err := applier.Drain(ctx, workerAccessContext, 10); err != nil || drained < 1 {
		t.Fatalf("live search delete drain: drained=%d err=%v", drained, err)
	}
	for attempt := 0; attempt < 50; attempt++ {
		result, err = client.Search(ctx, search.Query{Text: "waste collected", Size: 10})
		if err != nil {
			t.Fatal(err)
		}
		if result.Total == 0 && len(result.Hits) == 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("purged SearchChunk remained in live OpenSearch: %+v", result)
}

func mustQueue(t *testing.T, store *database.Store) *jobs.Queue {
	t.Helper()
	queue, err := jobs.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return queue
}

func newS1dHandler(t *testing.T, store *database.Store, queue *jobs.Queue, codec *artifactcrypto.Codec, root string) *ingestion.Handler {
	t.Helper()
	return ingestion.NewHandler(store, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID,
		time.Now, ids.New)
}

func mustSearchOwner(t *testing.T, organizationID, chunkID string) artifactcrypto.OwnerIdentity {
	t.Helper()
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SearchChunkText, organizationID, chunkID)
	if err != nil {
		t.Fatal(err)
	}
	return owner
}
