package search

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// S3 Outcome 2: the rights-bearing scope and the current-version state are
// predicates of the k-NN query itself, so a workspace's nearest neighbours are
// drawn from the passages it may read instead of from the whole tenant corpus
// and pruned afterwards.
func TestVectorSearchAppliesScopeAndVersionStateBeforeRanking(t *testing.T) {
	document := testDocument("org-a")
	document.EmbeddingProfileHash = vectorProfileHash()
	document.EmbeddingDimension = 3
	document.Embedding = []float32{0.3, 0.2, 0.1}
	document.SourceScopeIDs = []string{"scope-a"}
	document.VersionState = VersionStateCurrent
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
	if _, err := client.VectorSearch(context.Background(), VectorQuery{
		Vector: []float32{0.1, 0.2, 0.3}, ProfileHash: vectorProfileHash(), Dimension: 3, Size: 2,
		SourceScopeIDs: []string{"scope-a", "scope-b"}, VersionState: VersionStateCurrent,
	}); err != nil {
		t.Fatalf("VectorSearch() error = %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("request JSON: %v", err)
	}
	filters := body["query"].(map[string]any)["bool"].(map[string]any)["filter"].([]any)
	if len(filters) != 4 {
		t.Fatalf("filters = %#v, want tenant, profile, scope and version-state filters", filters)
	}
	scopes := map[string]bool{}
	versionState := ""
	for _, raw := range filters {
		clause := raw.(map[string]any)["bool"].(map[string]any)
		for _, shouldRaw := range clause["should"].([]any) {
			should := shouldRaw.(map[string]any)
			if terms, ok := should["terms"].(map[string]any); ok {
				for field, values := range terms {
					if field != "source_scope_ids" && field != "source_scope_ids.keyword" {
						t.Fatalf("unexpected terms field %q", field)
					}
					for _, value := range values.([]any) {
						scopes[value.(string)] = true
					}
				}
			}
			if term, ok := should["term"].(map[string]any); ok {
				if value, present := term["version_state"]; present {
					versionState = value.(string)
				}
			}
		}
	}
	if !scopes["scope-a"] || !scopes["scope-b"] || len(scopes) != 2 {
		t.Fatalf("scope filter = %#v, want exactly the two authorized scopes", scopes)
	}
	if versionState != VersionStateCurrent {
		t.Fatalf("version_state filter = %q, want %q", versionState, VersionStateCurrent)
	}
}

// A scope set or lifecycle value that is not server-shaped never reaches the
// network: the k-NN adapter refuses it, so a malformed pre-filter can never
// silently degrade into an unscoped tenant-wide ranking.
func TestVectorSearchRejectsMalformedPreFilter(t *testing.T) {
	called := false
	client := newVectorTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		return testResponse(http.StatusOK, `{}`), nil
	}))
	base := VectorQuery{Vector: []float32{0.1, 0.2, 0.3}, ProfileHash: vectorProfileHash(), Dimension: 3, Size: 1}
	duplicate := base
	duplicate.SourceScopeIDs = []string{"scope-a", "scope-a"}
	empty := base
	empty.SourceScopeIDs = []string{""}
	oversized := base
	oversized.SourceScopeIDs = make([]string, maximumScopeFilterSize+1)
	for index := range oversized.SourceScopeIDs {
		oversized.SourceScopeIDs[index] = "scope-" + strings.Repeat("x", index%8) + string(rune('a'+index%26))
	}
	state := base
	state.VersionState = "DRAFT"
	for name, query := range map[string]VectorQuery{
		"duplicate scope": duplicate, "empty scope": empty, "oversized scope": oversized, "unknown state": state,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.VectorSearch(context.Background(), query); CodeOf(err) != CodeInvalid {
				t.Fatalf("VectorSearch() code = %q, want %q", CodeOf(err), CodeInvalid)
			}
		})
	}
	if called {
		t.Fatal("a malformed pre-filter reached OpenSearch")
	}
}

// The provisioning mapping declares the pre-filter fields as exact keywords.
// Left to dynamic mapping they become analyzed text and every term predicate
// against them matches nothing, which is indistinguishable from an empty
// corpus at query time and silently unscopes the ranking.
func TestEnsureIndexMapsPreFilterFieldsAsKeywords(t *testing.T) {
	var created map[string]any
	client := newVectorTestClient(t, roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return testResponse(http.StatusNotFound, `{}`), nil
		}
		raw, _ := io.ReadAll(request.Body)
		_ = json.Unmarshal(raw, &created)
		return testResponse(http.StatusOK, `{}`), nil
	}))
	if err := client.EnsureIndex(context.Background()); err != nil {
		t.Fatalf("EnsureIndex() error = %v", err)
	}
	properties := created["mappings"].(map[string]any)["properties"].(map[string]any)
	for _, field := range []string{"source_scope_ids", "version_state", "organization_id", "embedding_profile_hash"} {
		mapping, ok := properties[field].(map[string]any)
		if !ok || mapping["type"] != "keyword" {
			t.Fatalf("%s mapping = %#v, want keyword", field, properties[field])
		}
	}
	if properties["embedding"].(map[string]any)["method"].(map[string]any)["engine"] != "lucene" {
		t.Fatalf("k-NN engine must stay lucene so filters apply during the graph walk: %#v", properties["embedding"])
	}
}
