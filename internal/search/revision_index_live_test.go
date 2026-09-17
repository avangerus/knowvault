package search

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"
)

// Real OpenSearch proves what a transport stub cannot: two incompatible
// knn_vector mappings coexist, and deletion reaches an unrefreshed copy.
func TestLiveSearchRevisionDimensionChange(t *testing.T) {
	endpoint, alias := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_URL"), os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ALIAS")
	if endpoint == "" {
		t.Skip("live OpenSearch is not configured")
	}
	if !strings.HasPrefix(alias, "knowvault-release-test-") {
		t.Fatal("revision test requires an isolated synthetic index prefix")
	}
	roots := x509.NewCertPool()
	raw, err := os.ReadFile(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ROOT_CA"))
	if err != nil || !roots.AppendCertsFromPEM(raw) {
		t.Fatal("live trust root unavailable")
	}
	certificate, err := tls.LoadX509KeyPair(os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_CERT"), os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Endpoint: endpoint, IndexAlias: alias, OrganizationID: "knowvault-revision-synthetic", Generation: 4, GenerationFence: 7,
		VectorProfileHash: "sha256:" + strings.Repeat("a", 64), VectorDimension: 3, TrustRoots: roots, ClientCertificate: &certificate, Timeout: 20 * time.Second}
	old, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	config.VectorProfileHash = "sha256:" + strings.Repeat("b", 64)
	config.VectorDimension = 4
	candidate, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	ctx := context.Background()
	if err := old.EnsureRevisionIndex(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := candidate.EnsureRevisionIndex(ctx, 2); err != nil {
		t.Fatal(err)
	}
	document := testDocument(config.OrganizationID)
	document.ID = "synthetic-revision-chunk"
	document.SourceScopeIDs = []string{"synthetic-scope"}
	document.VersionState = VersionStateCurrent
	document.ProfileRevision = 1
	document.EmbeddingProfileHash = old.vectorProfileHash
	document.EmbeddingDimension = 3
	document.Embedding = []float32{1, 0, 0}
	if err := old.Index(ctx, document); err != nil {
		t.Fatal(err)
	}
	if err := old.RefreshRevision(ctx, 1); err != nil {
		t.Fatal(err)
	}
	document.ProfileRevision = 2
	document.EmbeddingProfileHash = candidate.vectorProfileHash
	document.EmbeddingDimension = 4
	document.Embedding = []float32{1, 0, 0, 0}
	if err := candidate.Index(ctx, document); err != nil {
		t.Fatal(err)
	}
	foreign := document
	foreign.ID = "synthetic-foreign-scope"
	foreign.SourceScopeIDs = []string{"unbound-scope"}
	if err := candidate.Index(ctx, foreign); err != nil {
		t.Fatal(err)
	}
	if err := candidate.RefreshRevision(ctx, 2); err != nil {
		t.Fatal(err)
	}
	lexical, err := candidate.Search(ctx, Query{Text: "waste", Size: 5, ProfileRevision: 2, ProfileHash: candidate.vectorProfileHash, SourceScopeIDs: []string{"synthetic-scope"}, VersionState: VersionStateCurrent})
	if err != nil || lexical.Total != 1 || len(lexical.Hits) != 1 || lexical.Hits[0].ID != document.ID {
		t.Fatalf("BM25 scoped ranking: total=%d err=%v", lexical.Total, err)
	}
	for _, item := range []struct {
		client   *Client
		revision int64
		vector   []float32
	}{{old, 1, []float32{1, 0, 0}}, {candidate, 2, []float32{1, 0, 0, 0}}} {
		result, err := item.client.VectorSearch(ctx, VectorQuery{ProfileRevision: item.revision, ProfileHash: item.client.vectorProfileHash, Dimension: len(item.vector), Vector: item.vector, Size: 5, SourceScopeIDs: []string{"synthetic-scope"}, VersionState: VersionStateCurrent})
		if err != nil || len(result.Hits) != 1 {
			t.Fatalf("revision %d: hits=%d err=%v", item.revision, len(result.Hits), err)
		}
	}
	// A second ID is purged immediately after PUT, before index refresh.
	document.ID = "synthetic-unrefreshed-chunk"
	if err := candidate.Index(ctx, document); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"synthetic-revision-chunk", "synthetic-unrefreshed-chunk", "synthetic-foreign-scope"} {
		if err := candidate.DeleteProfileCopies(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		client   *Client
		revision int64
	}{{old, 1}, {candidate, 2}} {
		if err := item.client.RefreshRevision(ctx, item.revision); err != nil {
			t.Fatal(err)
		}
		result, err := item.client.Search(ctx, Query{Text: "waste", Size: 5, ProfileRevision: item.revision, ProfileHash: item.client.vectorProfileHash})
		if err != nil || result.Total != 0 {
			t.Fatalf("purged revision %d: total=%d err=%v", item.revision, result.Total, err)
		}
	}
}
