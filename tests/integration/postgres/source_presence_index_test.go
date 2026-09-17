package postgres_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
)

type presencePausingIndex struct {
	base        *s3IndexTransport
	deletes     int
	failDeletes bool
	deletedIDs  []string
}

func (index *presencePausingIndex) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method == http.MethodDelete {
		index.deletes++
		index.deletedIDs = append(index.deletedIDs, strings.Split(request.URL.Path, "/_doc/")[1])
		if index.failDeletes {
			return s3Response(http.StatusServiceUnavailable, `{}`), nil
		}
	}
	return index.base.RoundTrip(request)
}

type changedPresenceIndex struct {
	f                                   *exactEvidenceFixture
	worker                              database.AccessContext
	store                               *database.Store
	repository                          *search.Repository
	applier                             *search.Applier
	transport                           *presencePausingIndex
	client                              *search.Client
	oldVersion, oldExtraction, oldChunk string
}

func newChangedPresenceIndex(t *testing.T) changedPresenceIndex {
	t.Helper()
	f := newExactEvidenceFixture(t, "beforeabsence old unique bytes\n")
	_, oldVersion, oldExtraction := s1dActiveEvidence(t, f.ctx, f.admin)
	worker := workerAccess(t, s1dOrg)
	store := openStore(t, f.ctx, workerRole, "knowvault_worker")
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	f.handler = f.handler.WithSearchRepository(repository)
	if err := store.Write(f.ctx, worker, func(ctx context.Context, tx database.Transaction) error {
		return repository.EnsureMountedLexicalProfile(ctx, tx, worker, 1, 1)
	}); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "sentinel.txt"), "sentinel\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "changed-pending-initial")
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, worker, "changed-pending-absent")
	writeS1dFile(t, f.target, "afterabsence returned changed authoritative bytes\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "changed-pending-return")
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	transport := &presencePausingIndex{base: index}
	client, err := search.New(search.Config{Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg, Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(), HTTPClient: &http.Client{Transport: transport, Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := search.NewApplier(store, repository, s1dCodec(t, s1dOrg), client)
	if err != nil {
		t.Fatal(err)
	}
	var oldChunk string
	if err := f.admin.QueryRow(f.ctx, `SELECT id FROM public.search_chunk WHERE organization_id=$1 AND source_version_id=$2 ORDER BY id LIMIT 1`, s1dOrg, oldVersion).Scan(&oldChunk); err != nil {
		t.Fatal(err)
	}
	return changedPresenceIndex{f: f, worker: worker, store: store, repository: repository, applier: applier, transport: transport, client: client, oldVersion: oldVersion, oldExtraction: oldExtraction, oldChunk: oldChunk}
}

func TestSourcePresenceChangedReturnBeforeIndexDrain(t *testing.T) {
	fixture := newChangedPresenceIndex(t)
	f, worker, store, applier, client := fixture.f, fixture.worker, fixture.store, fixture.applier, fixture.client
	assertPending := func(label string) {
		t.Helper()
		if applied, err := applier.ApplyOnce(f.ctx, worker); applied || search.CodeOf(err) != search.CodeProfileUnavailable || fixture.transport.deletes != 0 {
			t.Fatalf("%s was treated as obsolete: %v %v deletes=%d", label, applied, err, fixture.transport.deletes)
		}
	}
	for _, control := range []string{"version_queryable", "extraction_queryable", "extraction_allowed"} {
		table, column, idColumn, id := "source_version_retention", "queryable", "source_version_id", fixture.oldVersion
		if control == "extraction_queryable" {
			table, idColumn, id = "source_extraction_retention", "extraction_id", fixture.oldExtraction
		}
		if control == "extraction_allowed" {
			column = "extraction_allowed"
		}
		statement := "UPDATE public." + table + " SET " + column + "=$3 WHERE organization_id=$1 AND " + idColumn + "=$2"
		if _, err := f.admin.Exec(f.ctx, statement, s1dOrg, id, false); err != nil {
			t.Fatal(err)
		}
		assertPending(control)
		if _, err := f.admin.Exec(f.ctx, statement, s1dOrg, id, true); err != nil {
			t.Fatal(err)
		}
	}
	staleClient, err := search.New(search.Config{Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg, Generation: 2, GenerationFence: 2, TrustRoots: s3TrustRoots(), HTTPClient: &http.Client{Transport: fixture.transport, Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	stale, err := search.NewApplier(store, fixture.repository, s1dCodec(t, s1dOrg), staleClient)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := stale.ApplyOnce(f.ctx, worker); applied || search.CodeOf(err) != search.CodeProfileUnavailable || fixture.transport.deletes != 0 {
		t.Fatalf("superseded cleanup ignored generation fence: %v %v", applied, err)
	}
	fixture.transport.failDeletes = true
	if applied, err := applier.ApplyOnce(f.ctx, worker); applied || search.CodeOf(err) != search.CodeIndexFailed {
		t.Fatalf("failed DELETE was acknowledged: %v %v", applied, err)
	}
	var pending bool
	if err := f.admin.QueryRow(f.ctx, `SELECT published_at IS NULL FROM public.outbox_event WHERE organization_id=$1 AND id=$2`, s1dOrg, fixture.oldChunk).Scan(&pending); err != nil || !pending {
		t.Fatalf("failed DELETE lost durable pending event: %v", err)
	}
	fixture.transport.failDeletes = false
	if count, err := applier.Drain(f.ctx, worker, 100); err != nil || count != 3 {
		t.Fatalf("changed return blocked behind prior immutable version: count=%d error=%v", count, err)
	}
	result, err := client.Search(f.ctx, search.Query{Text: "afterabsence", Size: 10, SourceScopeIDs: []string{s1dScopeID}, VersionState: search.VersionStateCurrent})
	if err != nil || len(result.Hits) != 1 {
		t.Fatalf("changed return absent from index after delayed drain: hits=%d error=%v", len(result.Hits), err)
	}
	for _, id := range fixture.transport.deletedIDs {
		if id != fixture.oldChunk {
			t.Fatal("cleanup deleted a replacement/current chunk")
		}
	}
}

// A faulty producer may emit a syntactically valid but mismatched immutable
// reference. Append new synthetic events; never rewrite old outbox records.
func TestSourcePresenceSupersededRejectsMismatchedEvent(t *testing.T) {
	for _, field := range []string{"source_version_id", "extraction_id", "artifact_id", "text_hash"} {
		t.Run(field, func(t *testing.T) {
			fixture := newChangedPresenceIndex(t)
			f := fixture.f
			if _, err := fixture.applier.Drain(f.ctx, fixture.worker, 100); err != nil {
				t.Fatal(err)
			}
			deletedBefore := fixture.transport.deletes
			value := mustID(t, "version")
			if field == "text_hash" {
				value = "sha256:" + strings.Repeat("a", 64)
			}
			eventID := mustID(t, "searchupd")
			tx, err := f.admin.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			var sequence int64
			if err := tx.QueryRow(f.ctx, `UPDATE public.outbox_sequence_head SET last_assigned_sequence=last_assigned_sequence+1 WHERE organization_id=$1 RETURNING last_assigned_sequence`, s1dOrg).Scan(&sequence); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(f.ctx, `INSERT INTO public.outbox_event(organization_id,id,sequence,aggregate_type,aggregate_id,event_type,payload_json)
                SELECT organization_id,$2,$3,aggregate_type,aggregate_id,event_type,payload_json||jsonb_build_object($4::text,$5::text) FROM public.outbox_event WHERE organization_id=$1 AND id=$6`, s1dOrg, eventID, sequence, field, value, fixture.oldChunk); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if applied, err := fixture.applier.ApplyOnce(f.ctx, fixture.worker); applied || search.CodeOf(err) != search.CodeProfileUnavailable || fixture.transport.deletes != deletedBefore {
				t.Fatalf("mismatched %s tuple deleted or acknowledged: %v %v", field, applied, err)
			}
		})
	}
}

// PostgreSQL, ingestion, encrypted artifacts and outbox are real; only the
// index HTTP boundary is simulated. No embedding/model request is involved.
func TestSourcePresencePendingIndexReturnAndGraph(t *testing.T) {
	f := newExactEvidenceFixture(t, "reappearneedle technical document\n")
	objectID, versionID, _ := s1dActiveEvidence(t, f.ctx, f.admin)
	worker := workerAccess(t, s1dOrg)
	store := openStore(t, f.ctx, workerRole, "knowvault_worker")
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatal(err)
	}
	graph := knowledgegraph.NewRepository()
	f.handler = f.handler.WithSearchRepository(repository).WithKnowledgeGraph(graph)
	if err := store.Write(f.ctx, worker, func(ctx context.Context, tx database.Transaction) error {
		return repository.EnsureMountedLexicalProfile(ctx, tx, worker, 1, 1)
	}); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(filepath.Dir(f.target), "sentinel.txt"), "sentinel\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-index-create")
	var chunkID string
	var firstSequence int64
	if err := f.admin.QueryRow(f.ctx, `SELECT c.id,e.sequence FROM public.search_chunk c JOIN public.outbox_event e ON e.organization_id=c.organization_id AND e.id=c.id WHERE c.organization_id=$1 AND c.source_version_id=$2 ORDER BY c.id LIMIT 1`, s1dOrg, versionID).Scan(&chunkID, &firstSequence); err != nil {
		t.Fatal(err)
	}
	graphMatches := func(want int) {
		t.Helper()
		var matches []knowledgegraph.EntityMatch
		app := openStore(t, f.ctx, appRole, "knowvault_app")
		if err := app.Read(f.ctx, f.access, func(ctx context.Context, tx database.Transaction) error {
			var err error
			matches, err = graph.ResolveTerms(ctx, tx, f.access, knowledgegraph.ResolveQuery{WorkspaceID: s1dWorkspace, Terms: []string{"exact-history.txt"}, Limit: 10})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, match := range matches {
			if match.SourceObjectID == objectID {
				found++
			}
		}
		if found != want {
			t.Fatalf("live graph target matches=%d want=%d", found, want)
		}
	}
	graphMatches(1)
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	pausing := &presencePausingIndex{base: index}
	client, err := search.New(search.Config{Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg, Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(), HTTPClient: &http.Client{Transport: pausing, Timeout: 5 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	applier, err := search.NewApplier(store, repository, s1dCodec(t, s1dOrg), client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_version_retention SET queryable=false WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
		t.Fatal(err)
	}
	if applied, err := applier.ApplyOnce(f.ctx, worker); applied || search.CodeOf(err) != search.CodeProfileUnavailable || pausing.deletes != 0 {
		t.Fatalf("unavailable CURRENT chunk was treated as obsolete: %v %v", applied, err)
	}
	if _, err := f.admin.Exec(f.ctx, `UPDATE public.source_version_retention SET queryable=true WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-index-absent")
	graphMatches(0)
	staleClient, err := search.New(search.Config{Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg, Generation: 2, GenerationFence: 2, TrustRoots: s3TrustRoots(), HTTPClient: &http.Client{Transport: pausing, Timeout: time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	staleApplier, err := search.NewApplier(store, repository, s1dCodec(t, s1dOrg), staleClient)
	if err != nil {
		t.Fatal(err)
	}
	if applied, err := staleApplier.ApplyOnce(f.ctx, worker); applied || search.CodeOf(err) != search.CodeProfileUnavailable || pausing.deletes != 0 {
		t.Fatalf("missing cleanup bypassed generation fence: %v %v deletes=%d", applied, err, pausing.deletes)
	}
	if count, err := applier.Drain(f.ctx, worker, 100); err != nil || count < 2 {
		t.Fatalf("pending UPSERTs did not drain past confirmed absence: %d %v", count, err)
	}
	if _, exists := index.documents[chunkID]; exists {
		t.Fatal("missing object retained its index document")
	}
	writeS1dFile(t, f.target, "reappearneedle technical document\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-index-return")
	var events int
	var lastSequence int64
	if err := f.admin.QueryRow(f.ctx, `SELECT count(*),max(sequence) FROM public.outbox_event WHERE organization_id=$1 AND aggregate_type='SEARCH_CHUNK' AND aggregate_id=$2`, s1dOrg, chunkID).Scan(&events, &lastSequence); err != nil {
		t.Fatal(err)
	}
	if events != 2 || lastSequence <= firstSequence {
		t.Fatalf("immutable chunk return did not acquire a fresh ordered event: %d %d %d", events, firstSequence, lastSequence)
	}
	if count, err := applier.Drain(f.ctx, worker, 100); err != nil || count != 1 {
		t.Fatalf("return index projection: %d %v", count, err)
	}
	result, err := client.Search(f.ctx, search.Query{Text: "reappearneedle", Size: 10, SourceScopeIDs: []string{s1dScopeID}, VersionState: search.VersionStateCurrent})
	if err != nil || len(result.Hits) != 1 || result.Hits[0].ID != chunkID {
		t.Fatalf("returned immutable chunk not searchable: hits=%d err=%v", len(result.Hits), err)
	}
	graphMatches(1)
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-index-repeat")
	if count, err := applier.Drain(f.ctx, worker, 100); err != nil || count != 0 {
		t.Fatalf("ordinary repeat manufactured projection events: %d %v", count, err)
	}
	// Produce another genuine return event, leave it pending, then observe the
	// object absent again. Its physical copy must remain fail-closed in the DB.
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-race-absent-one")
	writeS1dFile(t, f.target, "reappearneedle technical document\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-race-return-one")
	if err := os.Remove(f.target); err != nil {
		t.Fatal(err)
	}
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-race-absent-two")
	pausing.failDeletes = true
	if applied, err := applier.ApplyOnce(f.ctx, worker); err != nil || !applied || pausing.deletes != 0 {
		t.Fatalf("MISSING skip attempted external deletion: %v %v deletes=%d", applied, err, pausing.deletes)
	}
	if _, exists := index.documents[chunkID]; !exists {
		t.Fatal("fixture did not retain the previously indexed physical copy")
	}
	graphMatches(0)
	var fragmentID string
	if err := f.admin.QueryRow(f.ctx, `SELECT evidence_fragment_id FROM public.search_chunk_fragment WHERE organization_id=$1 AND search_chunk_id=$2 ORDER BY ordinal LIMIT 1`, s1dOrg, chunkID).Scan(&fragmentID); err != nil {
		t.Fatal(err)
	}
	assertCurrentReadDenied(t, f, s1dWorkspace, fragmentID, "MISSING with stale physical index")
	assertExactReadDenied(t, f, f.access, s1dWorkspace, fragmentID, versionID, "MISSING with stale physical index")
	authorized, err := f.viewer.AuthorizeFragments(f.ctx, f.access, s1dWorkspace, []string{fragmentID})
	if err != nil || len(authorized) != 0 {
		t.Fatalf("stale physical index candidate passed final authorization: %v", err)
	}
	visible, err := f.viewer.SearchFragments(f.ctx, f.access, s1dWorkspace, "reappearneedle", false, 0, 10)
	if err != nil || len(visible.Hits) != 0 {
		t.Fatalf("MISSING physical copy leaked through authorized search: %v", err)
	}
	writeS1dFile(t, f.target, "reappearneedle technical document\n")
	runSync(t, f.ctx, f.handler, f.queue, worker, "presence-race-final-return")
	if count, err := applier.Drain(f.ctx, worker, 100); err != nil || count != 1 || pausing.deletes != 0 {
		t.Fatalf("fresh UPSERT after MISSING skip: %d %v deletes=%d", count, err, pausing.deletes)
	}
	result, err = client.Search(f.ctx, search.Query{Text: "reappearneedle", Size: 10, SourceScopeIDs: []string{s1dScopeID}, VersionState: search.VersionStateCurrent})
	if err != nil || len(result.Hits) != 1 || result.Hits[0].ID != chunkID {
		t.Fatalf("MISSING skip hid the restored search hit: %d %v", len(result.Hits), err)
	}
}
