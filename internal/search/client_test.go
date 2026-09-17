package search

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func testResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testRoots() *x509.CertPool {
	// CertPool only needs a non-empty administrator-owned subject at this
	// transport boundary; no TLS handshake is performed by these unit tests.
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("search.example")})
	return roots
}

func newTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := New(Config{
		Endpoint:        "https://search.example",
		IndexAlias:      "org-a-v1",
		OrganizationID:  "org-a",
		Generation:      4,
		GenerationFence: 7,
		TrustRoots:      testRoots(),
		HTTPClient:      &http.Client{Transport: transport, Timeout: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

func vectorProfileHash() string {
	return "sha256:" + strings.Repeat("f", 64)
}

func newVectorTestClient(t *testing.T, transport http.RoundTripper) *Client {
	t.Helper()
	client, err := New(Config{
		Endpoint:          "https://search.example",
		IndexAlias:        "org-a-v1",
		OrganizationID:    "org-a",
		Generation:        4,
		GenerationFence:   7,
		VectorProfileHash: vectorProfileHash(),
		VectorDimension:   3,
		TrustRoots:        testRoots(),
		HTTPClient:        &http.Client{Transport: transport, Timeout: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("New(vector) error = %v", err)
	}
	return client
}

func testDocument(organization string) IndexDocument {
	return IndexDocument{
		ID:                 "chunk/1",
		OrganizationID:     organization,
		SourceObjectID:     "source-1",
		SourceVersionID:    "version-1",
		ExtractionID:       "extraction-1",
		EvidenceFragmentID: "fragment-1",
		Text:               "waste was collected",
		ContentHash:        "sha256:" + strings.Repeat("a", 64),
		TextHash:           "sha256:" + strings.Repeat("b", 64),
		AnchorHash:         "sha256:" + strings.Repeat("c", 64),
		Generation:         4,
		GenerationFence:    7,
	}
}

func TestNewRejectsUnboundedOrNonTLSConfiguration(t *testing.T) {
	base := Config{
		Endpoint:        "https://search.example",
		IndexAlias:      "org-a-v1",
		OrganizationID:  "org-a",
		Generation:      4,
		GenerationFence: 7,
		TrustRoots:      testRoots(),
		HTTPClient:      &http.Client{Timeout: time.Second},
	}
	cases := map[string]func(*Config){
		"http endpoint":            func(config *Config) { config.Endpoint = "http://search.example" },
		"ip endpoint":              func(config *Config) { config.Endpoint = "https://127.0.0.1" },
		"endpoint user":            func(config *Config) { config.Endpoint = "https://user:secret@search.example" },
		"endpoint path":            func(config *Config) { config.Endpoint = "https://search.example/path" },
		"endpoint query":           func(config *Config) { config.Endpoint = "https://search.example?x=1" },
		"uppercase host":           func(config *Config) { config.Endpoint = "https://Search.example" },
		"missing roots":            func(config *Config) { config.TrustRoots = nil },
		"missing generation":       func(config *Config) { config.Generation = 0 },
		"missing generation fence": func(config *Config) { config.GenerationFence = 0 },
		"invalid alias":            func(config *Config) { config.IndexAlias = "_org-a" },
		"long timeout":             func(config *Config) { config.Timeout = 61 * time.Second },
		"unbounded client": func(config *Config) {
			config.HTTPClient = &http.Client{}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			config := base
			mutate(&config)
			if _, err := New(config); CodeOf(err) != CodeInvalid {
				t.Fatalf("New() error code = %q, want %q", CodeOf(err), CodeInvalid)
			}
		})
	}
}

func TestCloseIsIdempotentAndDoesNotExposeTransport(t *testing.T) {
	client := newTestClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return testResponse(http.StatusOK, `{}`), nil
	}))
	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSearchBuildsTenantBoundQueryAndParsesEvidenceReferences(t *testing.T) {
	document := testDocument("org-a")
	document.EvidenceFragmentIDs = []string{"fragment-1", "fragment-2"}
	document.EvidenceTextHashes = []string{document.TextHash, "hmac-sha256:k1:" + strings.Repeat("d", 64)}
	document.EvidenceAnchorHashes = []string{document.AnchorHash, "hmac-sha256:k1:" + strings.Repeat("e", 64)}
	var request *http.Request
	var payload []byte
	client := newTestClient(t, roundTripFunc(func(got *http.Request) (*http.Response, error) {
		request = got
		payload, _ = io.ReadAll(got.Body)
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 1, "relation": "eq"},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 1.25, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))

	result, err := client.Search(context.Background(), Query{Text: "waste collected", Size: 10, From: 2})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	if result.Total != 1 || len(result.Hits) != 1 || result.Hits[0].Document.EvidenceFragmentID != document.EvidenceFragmentID ||
		len(result.Hits[0].Document.EvidenceFragmentIDs) != 2 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if request == nil || request.Method != http.MethodPost || request.URL.EscapedPath() != "/org-a-v1/_search" {
		t.Fatalf("unexpected request: %#v", request)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	queryBody := body["query"].(map[string]any)["bool"].(map[string]any)
	filter := queryBody["filter"].([]any)[0].(map[string]any)["bool"].(map[string]any)
	if filter["minimum_should_match"] != float64(1) {
		t.Fatalf("tenant filter minimum_should_match = %#v", filter["minimum_should_match"])
	}
	terms := filter["should"].([]any)
	if len(terms) != 2 {
		t.Fatalf("tenant filter terms = %#v", terms)
	}
	seenTenant := false
	for _, raw := range terms {
		term := raw.(map[string]any)["term"].(map[string]any)
		if term["organization_id"] == "org-a" || term["organization_id.keyword"] == "org-a" {
			seenTenant = true
		}
	}
	if !seenTenant {
		t.Fatalf("tenant filter = %#v", filter)
	}
	must := queryBody["must"].([]any)[0].(map[string]any)["match"].(map[string]any)["text"].(map[string]any)
	if must["query"] != "waste collected" || must["operator"] != "and" {
		t.Fatalf("text query = %#v", must)
	}
}

func TestIndexRejectsUnalignedEvidenceHashArrays(t *testing.T) {
	document := testDocument("org-a")
	document.EvidenceFragmentIDs = []string{"fragment-1", "fragment-2"}
	document.EvidenceTextHashes = []string{document.TextHash}
	document.EvidenceAnchorHashes = []string{document.AnchorHash}
	called := false
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusCreated, `{}`), nil
	}))
	if err := client.Index(context.Background(), document); CodeOf(err) != CodeInvalid {
		t.Fatalf("unaligned evidence hashes code=%q, want %q", CodeOf(err), CodeInvalid)
	}
	if called {
		t.Fatal("malformed multi-fragment document reached OpenSearch")
	}
}

func TestSearchAllowsTypedNaturalLanguageAnyTermOperator(t *testing.T) {
	document := testDocument("org-a")
	var payload []byte
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		payload, _ = io.ReadAll(request.Body)
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 1},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 1, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))
	if _, err := client.Search(context.Background(), Query{Text: "how many waste", Size: 1, Operator: MatchAny}); err != nil {
		t.Fatalf("Search() error = %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	operator := body["query"].(map[string]any)["bool"].(map[string]any)["must"].([]any)[0].(map[string]any)["match"].(map[string]any)["text"].(map[string]any)["operator"]
	if operator != string(MatchAny) {
		t.Fatalf("operator=%v, want %q", operator, MatchAny)
	}
}

func TestVectorSearchRequiresDeploymentProfile(t *testing.T) {
	called := false
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusOK, `{}`), nil
	}))
	_, err := client.VectorSearch(context.Background(), VectorQuery{
		Vector:      []float32{0.1, 0.2, 0.3},
		ProfileHash: vectorProfileHash(),
		Dimension:   3,
		Size:        1,
	})
	if CodeOf(err) != CodeVectorProfileUnavailable {
		t.Fatalf("VectorSearch() code = %q, want %q", CodeOf(err), CodeVectorProfileUnavailable)
	}
	if called {
		t.Fatal("vector search without a qualified profile reached OpenSearch")
	}
}

func TestVectorSearchBuildsTenantAndProfileBoundKNN(t *testing.T) {
	document := testDocument("org-a")
	document.EmbeddingProfileHash = vectorProfileHash()
	document.EmbeddingDimension = 3
	document.Embedding = []float32{0.3, 0.2, 0.1}
	var payload []byte
	client := newVectorTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		payload, _ = io.ReadAll(request.Body)
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 1, "relation": "eq"},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 0.91, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))
	result, err := client.VectorSearch(context.Background(), VectorQuery{
		Vector:      []float32{0.1, 0.2, 0.3},
		ProfileHash: vectorProfileHash(),
		Dimension:   3,
		Size:        2,
		From:        1,
	})
	if err != nil {
		t.Fatalf("VectorSearch() error = %v", err)
	}
	if result.Total != 1 || len(result.Hits) != 1 || result.Hits[0].Document.EmbeddingDimension != 3 {
		t.Fatalf("unexpected vector result: %+v", result)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	queryBody := body["query"].(map[string]any)["bool"].(map[string]any)
	filters := queryBody["filter"].([]any)
	if len(filters) != 2 {
		t.Fatalf("filters = %#v, want tenant and profile filters", filters)
	}
	seenTenant, seenProfile := false, false
	for _, raw := range filters {
		filter := raw.(map[string]any)["bool"].(map[string]any)
		for _, termRaw := range filter["should"].([]any) {
			term := termRaw.(map[string]any)["term"].(map[string]any)
			if term["organization_id"] == "org-a" || term["organization_id.keyword"] == "org-a" {
				seenTenant = true
			}
			if term["embedding_profile_hash"] == vectorProfileHash() || term["embedding_profile_hash.keyword"] == vectorProfileHash() {
				seenProfile = true
			}
		}
	}
	if !seenTenant || !seenProfile {
		t.Fatalf("missing tenant/profile filters: %#v", filters)
	}
	knn := queryBody["must"].([]any)[0].(map[string]any)["knn"].(map[string]any)["embedding"].(map[string]any)
	if knn["k"] != float64(3) {
		t.Fatalf("k = %#v, want 3", knn["k"])
	}
	if got := knn["vector"].([]any); len(got) != 3 {
		t.Fatalf("vector = %#v", got)
	}
}

func TestVectorSearchRejectsProfileDimensionAndNumericDrift(t *testing.T) {
	called := false
	client := newVectorTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusOK, `{}`), nil
	}))
	cases := map[string]VectorQuery{
		"profile":   {Vector: []float32{0.1, 0.2, 0.3}, ProfileHash: "sha256:" + strings.Repeat("e", 64), Dimension: 3, Size: 1},
		"dimension": {Vector: []float32{0.1, 0.2, 0.3}, ProfileHash: vectorProfileHash(), Dimension: 4, Size: 1},
		"length":    {Vector: []float32{0.1, 0.2}, ProfileHash: vectorProfileHash(), Dimension: 3, Size: 1},
		"nan":       {Vector: []float32{0.1, float32(math.NaN()), 0.3}, ProfileHash: vectorProfileHash(), Dimension: 3, Size: 1},
		"infinity":  {Vector: []float32{0.1, float32(math.Inf(1)), 0.3}, ProfileHash: vectorProfileHash(), Dimension: 3, Size: 1},
	}
	for name, query := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := client.VectorSearch(context.Background(), query); CodeOf(err) != CodeInvalid {
				t.Fatalf("VectorSearch() code = %q, want %q", CodeOf(err), CodeInvalid)
			}
		})
	}
	if called {
		t.Fatal("invalid vector query reached OpenSearch")
	}
}

func TestVectorIndexRequiresExactEmbeddingAndLexicalClientRejectsIt(t *testing.T) {
	document := testDocument("org-a")
	document.EmbeddingProfileHash = vectorProfileHash()
	document.EmbeddingDimension = 3
	called := false
	vectorClient := newVectorTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusCreated, `{}`), nil
	}))
	if err := vectorClient.Index(context.Background(), document); CodeOf(err) != CodeInvalid {
		t.Fatalf("missing embedding code = %q, want %q", CodeOf(err), CodeInvalid)
	}
	if called {
		t.Fatal("incomplete vector document reached OpenSearch")
	}
	document.Embedding = []float32{0.1, 0.2, 0.3}
	if err := vectorClient.Index(context.Background(), document); err != nil {
		t.Fatalf("valid vector document rejected: %v", err)
	}
	lexicalClient := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return testResponse(http.StatusCreated, `{}`), nil
	}))
	if err := lexicalClient.Index(context.Background(), document); CodeOf(err) != CodeInvalid {
		t.Fatalf("lexical client accepted vector document code = %q, want %q", CodeOf(err), CodeInvalid)
	}
}

func TestIndexAndDeleteUseOnlyBoundAliasAndDocumentID(t *testing.T) {
	document := testDocument("org-a")
	var requests []*http.Request
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request)
		if request.Method == http.MethodPut {
			return testResponse(http.StatusCreated, `{}`), nil
		}
		return testResponse(http.StatusNoContent, ""), nil
	}))
	if err := client.Index(context.Background(), document); err != nil {
		t.Fatalf("Index() error = %v", err)
	}
	if err := client.Delete(context.Background(), document.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if len(requests) != 2 || requests[0].Method != http.MethodPut || requests[1].Method != http.MethodDelete {
		t.Fatalf("requests = %v", len(requests))
	}
	for _, request := range requests {
		if request.URL.Host != "search.example" || !strings.HasPrefix(request.URL.EscapedPath(), "/org-a-v1/_doc/chunk%2F1") {
			t.Fatalf("request escaped target = %s", request.URL.String())
		}
		if request.URL.RawQuery != "" {
			t.Fatal("request unexpectedly contains query parameters")
		}
	}
}

func TestIndexRejectsStaleGenerationBeforeNetwork(t *testing.T) {
	document := testDocument("org-a")
	document.Generation = 3
	called := false
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusCreated, `{}`), nil
	}))
	if err := client.Index(context.Background(), document); CodeOf(err) != CodeInvalid {
		t.Fatalf("stale generation error code = %q, want %q", CodeOf(err), CodeInvalid)
	}
	if called {
		t.Fatal("stale generation reached OpenSearch")
	}
}

func TestIndexAcceptsOrganizationKeyedEvidenceDigests(t *testing.T) {
	document := testDocument("org-a")
	document.TextHash = "hmac-sha256:k7:" + strings.Repeat("b", 64)
	document.AnchorHash = "hmac-sha256:k7:" + strings.Repeat("c", 64)
	called := false
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusCreated, `{}`), nil
	}))
	if err := client.Index(context.Background(), document); err != nil {
		t.Fatalf("keyed Evidence digests rejected: %v", err)
	}
	if !called {
		t.Fatal("valid keyed Evidence document did not reach OpenSearch")
	}
}

func TestSearchRejectsCrossTenantOrMalformedHit(t *testing.T) {
	document := testDocument("org-b")
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 1},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 1, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))
	if _, err := client.Search(context.Background(), Query{Text: "waste", Size: 1}); CodeOf(err) != CodeResponse {
		t.Fatalf("Search() error code = %q, want %q", CodeOf(err), CodeResponse)
	}
}

func TestSearchRejectsInconsistentTotal(t *testing.T) {
	document := testDocument("org-a")
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 0},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 1, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))
	if _, err := client.Search(context.Background(), Query{Text: "waste", Size: 1}); CodeOf(err) != CodeResponse {
		t.Fatalf("inconsistent total code = %q, want %q", CodeOf(err), CodeResponse)
	}
}

func TestSearchPreservesApproximateTotalAsInexact(t *testing.T) {
	document := testDocument("org-a")
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		wire, _ := json.Marshal(map[string]any{
			"hits": map[string]any{
				"total": map[string]any{"value": 100, "relation": "gte"},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 1, "_source": document}},
			},
		})
		return testResponse(http.StatusOK, string(wire)), nil
	}))
	result, err := client.Search(context.Background(), Query{Text: "waste", Size: 1})
	if err != nil || result.TotalExact {
		t.Fatalf("approximate total result=%+v err=%v, want inexact", result, err)
	}
}

func TestDependencyErrorsDoNotExposeBodyOrEndpoint(t *testing.T) {
	client := newTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return testResponse(http.StatusBadGateway, "password=do-not-log"), nil
	}))
	_, err := client.Search(context.Background(), Query{Text: "waste", Size: 1})
	if CodeOf(err) != CodeRejected || strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "search.example") {
		t.Fatalf("unsafe dependency error: %v", err)
	}
	if errors.Is(err, context.Canceled) {
		t.Fatal("unexpected context cancellation")
	}
}
