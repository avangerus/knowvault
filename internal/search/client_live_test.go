package search

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
	"time"
)

// TestSearchLiveOpenSearchTLS is opt-in because the normal unit/full profile
// deliberately has no qualified OpenSearch deployment. When all variables are
// provided it exercises the exact production HTTPS/mTLS client against a real
// OpenSearch node; an absent variable is a skip, never an insecure fallback.
func TestSearchLiveOpenSearchTLS(t *testing.T) {
	endpoint := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_URL")
	rootPath := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ROOT_CA")
	certificatePath := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_CERT")
	keyPath := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_CLIENT_KEY")
	alias := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ALIAS")
	organizationID := os.Getenv("KNOWVAULT_TEST_OPENSEARCH_ORGANIZATION")
	if endpoint == "" || rootPath == "" || certificatePath == "" || keyPath == "" || alias == "" || organizationID == "" {
		t.Skip("live OpenSearch TLS variables are not configured")
	}
	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		t.Fatalf("read OpenSearch trust root: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootBytes) {
		t.Fatal("OpenSearch trust root is not a PEM certificate")
	}
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load OpenSearch client certificate: %v", err)
	}
	client, err := New(Config{
		Endpoint: endpoint, IndexAlias: alias, OrganizationID: organizationID,
		Generation: 1, GenerationFence: 1,
		TrustRoots: roots, ClientCertificate: &certificate,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("construct live OpenSearch client: %v", err)
	}
	document := IndexDocument{
		ID:                 "live-search-chunk",
		OrganizationID:     organizationID,
		SourceObjectID:     "live-search-source",
		SourceVersionID:    "live-search-version",
		ExtractionID:       "live-search-extraction",
		EvidenceFragmentID: "live-search-fragment",
		Text:               "live OpenSearch transport evidence",
		ContentHash:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TextHash:           "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		AnchorHash:         "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		Generation:         1,
		GenerationFence:    1,
	}
	if err := client.Index(context.Background(), document); err != nil {
		t.Fatalf("live OpenSearch index: %v", err)
	}
	t.Cleanup(func() { _ = client.Delete(context.Background(), document.ID) })
	var result Result
	for attempt := 0; attempt < 50; attempt++ {
		result, err = client.Search(context.Background(), Query{Text: "OpenSearch transport", Size: 10})
		if err != nil {
			t.Fatalf("live OpenSearch search: %v", err)
		}
		if result.Total >= 1 && len(result.Hits) >= 1 && result.Hits[0].Document.ID == document.ID {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("live OpenSearch result did not contain indexed document: %+v", result)
}
