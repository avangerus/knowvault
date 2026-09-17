package retrieval

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/canon"
)

type vectorRoundTripFunc func(*http.Request) (*http.Response, error)

func (function vectorRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func vectorTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func vectorTestRoots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("embed.example")})
	return roots
}

func vectorTestProfile() embedding.Profile {
	profile := embedding.Profile{
		SchemaVersion:     embedding.ProfileSchemaVersion,
		ID:                "mxbai-embed-large-v1",
		ModelID:           "mixedbread-ai/mxbai-embed-large-v1",
		ArtifactHash:      "sha256:" + strings.Repeat("a", 64),
		TokenizerHash:     "sha256:" + strings.Repeat("b", 64),
		RuntimeHash:       "sha256:" + strings.Repeat("c", 64),
		ConfigurationHash: "sha256:" + strings.Repeat("d", 64),
		Endpoint:          "https://embed.example",
		ServerName:        "embed.example",
		Dimension:         3,
		MaxInputBytes:     1024,
		Revision:          1,
	}
	raw, err := profile.CanonicalBytes()
	if err != nil {
		panic(err)
	}
	profile.ProfileHash = canon.Hash(raw)
	return profile
}

func vectorTestDocument() search.IndexDocument {
	return search.IndexDocument{
		ID: "chunk-1", OrganizationID: "org-a", SourceObjectID: "object-1", SourceVersionID: "version-1",
		ExtractionID: "extraction-1", EvidenceFragmentID: "fragment-1", Text: "waste was collected",
		ContentHash: "sha256:" + strings.Repeat("a", 64),
		TextHash:    "hmac-sha256:k1:" + strings.Repeat("b", 64),
		AnchorHash:  "hmac-sha256:k1:" + strings.Repeat("c", 64),
		Generation:  4, GenerationFence: 7,
	}
}

func TestOpenSearchVectorProviderBindsEmbeddingAndSearchCapabilities(t *testing.T) {
	profile := vectorTestProfile()
	embedClient, err := embedding.New(profile, vectorTestRoots(), nil, &http.Client{Transport: vectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/embeddings" {
			t.Fatalf("embedding path = %s", request.URL.Path)
		}
		return vectorTestResponse(http.StatusOK, `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1"}`), nil
	}), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("embedding.New: %v", err)
	}
	document := vectorTestDocument()
	document.EmbeddingProfileHash = profile.ProfileHash
	document.EmbeddingDimension = profile.Dimension
	document.Embedding = []float32{0.3, 0.2, 0.1}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-a-v1", OrganizationID: "org-a",
		Generation: 4, GenerationFence: 7, VectorProfileHash: profile.ProfileHash, VectorDimension: profile.Dimension,
		TrustRoots: vectorTestRoots(), HTTPClient: &http.Client{Transport: vectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if request.URL.Path != "/org-a-v1/_search" {
				t.Fatalf("search path = %s", request.URL.Path)
			}
			wire, _ := json.Marshal(map[string]any{"hits": map[string]any{
				"total": map[string]any{"value": 1, "relation": "eq"},
				"hits":  []any{map[string]any{"_id": document.ID, "_score": 0.9, "_source": document}},
			}})
			return vectorTestResponse(http.StatusOK, string(wire)), nil
		}), Timeout: 2 * time.Second},
	})
	if err != nil {
		t.Fatalf("search.New: %v", err)
	}
	provider, err := NewOpenSearchVectorProvider(embedClient, searchClient)
	if err != nil {
		t.Fatalf("NewOpenSearchVectorProvider: %v", err)
	}
	executor := &Executor{vector: provider}
	active := activeSearchProfile{id: profile.ID, hash: profile.ProfileHash, revision: 2}
	if executor.vectorForProfile(active, false) != nil {
		t.Fatal("unactivated mounted profile was admitted")
	}
	drifted := active
	drifted.hash = "sha256:" + strings.Repeat("e", 64)
	if executor.vectorForProfile(drifted, true) != nil {
		t.Fatal("staging mount answered against a different active profile")
	}
	qualified, ok := executor.vectorForProfile(active, true).(*OpenSearchVectorProvider)
	if !ok || qualified.profileRevision != 2 || provider.profileRevision != 0 {
		t.Fatal("revision selection mutated shared provider")
	}
	channel, err := provider.RetrieveVector(context.Background(), database.AccessContext{
		OrganizationID: "org-a", PrincipalID: "principal-a", RequestID: "request-a",
	}, "workspace-a", "question-run-a", "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e?")
	if err != nil {
		t.Fatalf("RetrieveVector: %v", err)
	}
	if channel.Channel != ChannelVector || !channel.CoverageComplete || len(channel.Hits) != 1 || channel.Hits[0].EvidenceFragmentID != "fragment-1" {
		t.Fatalf("unexpected vector channel: %+v", channel)
	}
}

func TestOpenSearchVectorProviderRejectsCrossTenantBeforeProviderCall(t *testing.T) {
	profile := vectorTestProfile()
	called := false
	embedClient, err := embedding.New(profile, vectorTestRoots(), nil, &http.Client{Transport: vectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return vectorTestResponse(http.StatusOK, `{}`), nil
	}), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-a-v1", OrganizationID: "org-a", Generation: 4, GenerationFence: 7,
		VectorProfileHash: profile.ProfileHash, VectorDimension: profile.Dimension, TrustRoots: vectorTestRoots(),
		HTTPClient: &http.Client{Transport: vectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
			called = true
			return vectorTestResponse(http.StatusOK, `{}`), nil
		}), Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewOpenSearchVectorProvider(embedClient, searchClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.RetrieveVector(context.Background(), database.AccessContext{
		OrganizationID: "org-b", PrincipalID: "principal-a", RequestID: "request-a",
	}, "workspace-a", "question-run-a", "question")
	if CodeOf(err) != CodeExecutorInvalid {
		t.Fatalf("cross-tenant error code = %q, want %q", CodeOf(err), CodeExecutorInvalid)
	}
	if called {
		t.Fatal("cross-tenant vector request reached a provider")
	}
}

func TestOpenSearchVectorProviderRejectsSearchProfileDrift(t *testing.T) {
	profile := vectorTestProfile()
	embedClient, err := embedding.New(profile, vectorTestRoots(), nil, &http.Client{
		Transport: vectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return vectorTestResponse(http.StatusOK, `{}`), nil
		}), Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-a-v1", OrganizationID: "org-a",
		Generation: 4, GenerationFence: 7,
		VectorProfileHash: "sha256:" + strings.Repeat("e", 64), VectorDimension: profile.Dimension,
		TrustRoots: vectorTestRoots(),
		HTTPClient: &http.Client{Transport: vectorRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return vectorTestResponse(http.StatusOK, `{}`), nil
		}), Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewOpenSearchVectorProvider(embedClient, searchClient); CodeOf(err) != CodeExecutorInvalid {
		t.Fatalf("profile drift error code = %q, want %q", CodeOf(err), CodeExecutorInvalid)
	}
}

func TestOpenSearchVectorProviderGroupedPropagatesLineageIntegrity(t *testing.T) {
	profile := vectorTestProfile()
	embedClient, err := embedding.New(profile, vectorTestRoots(), nil, &http.Client{Transport: vectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		return vectorTestResponse(http.StatusOK, `{"object":"list","data":[{"object":"embedding","embedding":[0.1,0.2,0.3],"index":0}],"model":"mixedbread-ai/mxbai-embed-large-v1"}`), nil
	}), Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	first := vectorTestDocument()
	first.EmbeddingProfileHash = profile.ProfileHash
	first.EmbeddingDimension = profile.Dimension
	first.Embedding = []float32{0.3, 0.2, 0.1}
	second := first
	second.TextHash = "hmac-sha256:k1:" + strings.Repeat("d", 64)
	second.AnchorHash = "hmac-sha256:k1:" + strings.Repeat("e", 64)
	wire, err := json.Marshal(map[string]any{"hits": map[string]any{
		"total": map[string]any{"value": 2, "relation": "eq"},
		"hits": []any{
			map[string]any{"_id": first.ID, "_score": 0.9, "_source": first},
			map[string]any{"_id": second.ID, "_score": 0.8, "_source": second},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-a-v1", OrganizationID: "org-a",
		Generation: 4, GenerationFence: 7, VectorProfileHash: profile.ProfileHash, VectorDimension: profile.Dimension,
		TrustRoots: vectorTestRoots(), HTTPClient: &http.Client{Transport: vectorRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return vectorTestResponse(http.StatusOK, string(wire)), nil
		}), Timeout: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewOpenSearchVectorProvider(embedClient, searchClient)
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.RetrieveScopedVectorGroups(context.Background(), database.AccessContext{
		OrganizationID: "org-a", PrincipalID: "principal-a", RequestID: "request-a",
	}, "workspace-a", "question-run-a", "question", []string{"scope-a"}, search.VersionStateCurrent)
	var integrity *workspaceGroupedIntegrityError
	if !errors.As(err, &integrity) {
		t.Fatalf("group lineage drift was downgraded or lost: %v", err)
	}
}
