package search

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func revisionMapping(index string, dimension int) string {
	properties := map[string]any{"embedding": map[string]any{"type": "knn_vector", "dimension": dimension, "method": map[string]any{"engine": "lucene", "space_type": "cosinesimil"}}}
	for _, field := range []string{"organization_id", "embedding_profile_hash", "source_scope_ids", "version_state"} {
		properties[field] = map[string]any{"type": "keyword"}
	}
	raw, _ := json.Marshal(map[string]any{index: map[string]any{"mappings": map[string]any{"properties": properties}}})
	return string(raw)
}

func TestRevisionIndexPreservesLegacyAndIsolatesDimensions(t *testing.T) {
	var requests []string
	client := newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/_mapping") {
			return testResponse(200, revisionMapping(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_mapping"), 3)), nil
		}
		return testResponse(200, `{}`), nil
	}))
	legacy, _ := client.revisionIndex(1, "")
	candidate, _ := client.revisionIndex(2, client.vectorProfileHash)
	repeated, _ := client.revisionIndex(3, client.vectorProfileHash)
	if legacy != client.indexAlias || candidate == legacy || repeated == candidate {
		t.Fatal("revision indices overlap")
	}
	if err := client.EnsureRevisionIndex(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if err := client.EnsureRevisionIndex(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0] != "GET /"+candidate || requests[1] != "GET /"+candidate+"/_mapping" {
		t.Fatalf("preparation/cache requests: %v", requests)
	}
	for _, revision := range []int64{-1, maximumGeneration + 1} {
		if _, err := client.revisionIndex(revision, client.vectorProfileHash); err == nil {
			t.Fatal("invalid revision accepted")
		}
	}
	if _, err := client.revisionIndex(2, "../foreign"); err == nil {
		t.Fatal("invalid hash accepted")
	}
}

func TestRevisionIndexRejectsIncompatibleMapping(t *testing.T) {
	client := newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, "/_mapping") {
			return testResponse(200, revisionMapping(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/_mapping"), 384)), nil
		}
		return testResponse(200, `{}`), nil
	}))
	if err := client.EnsureRevisionIndex(context.Background(), 2); CodeOf(err) != CodeVectorProfileUnavailable {
		t.Fatalf("mapping mismatch: %v", err)
	}
}

func TestRevisionRefreshRejectsPartialSuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"_shards":{"total":1,"successful":0,"failed":1}}`, `{"_shards":{"total":2,"successful":1,"failed":1}}`} {
		client := newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) { return testResponse(200, body), nil }))
		if err := client.RefreshRevision(context.Background(), 2); err == nil {
			t.Fatalf("accepted incomplete refresh %s", body)
		}
	}
	client := newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return testResponse(200, `{"_shards":{"total":2,"successful":1,"failed":0}}`), nil
	}))
	if err := client.RefreshRevision(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
}

func TestPurgeDeletesUnrefreshedCopiesByIDAndRejectsForeignIndex(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "all revisions", true: "foreign response"}[foreign], func(t *testing.T) {
			var paths []string
			var client *Client
			client = newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if r.Method == http.MethodGet {
					index, _ := client.revisionIndex(2, client.vectorProfileHash)
					if foreign {
						index = "foreign-tenant"
					}
					raw, _ := json.Marshal(map[string]any{index: map[string]any{}})
					return testResponse(200, string(raw)), nil
				}
				if r.Method != http.MethodDelete {
					t.Fatal("purge must delete by ID, not search snapshot")
				}
				paths = append(paths, r.URL.Path)
				return testResponse(200, `{}`), nil
			}))
			err := client.DeleteProfileCopies(context.Background(), "chunk-a")
			if foreign {
				if CodeOf(err) != CodeResponse || len(paths) != 0 {
					t.Fatalf("foreign namespace accepted: %v %v", err, paths)
				}
				return
			}
			if err != nil || len(paths) != 2 {
				t.Fatalf("purge: %v %v", err, paths)
			}
			for _, path := range paths {
				if !strings.HasSuffix(path, "/_doc/chunk-a") {
					t.Fatal(path)
				}
			}
		})
	}
}

func TestIndexCreationRejectsArbitraryBadRequest(t *testing.T) {
	client := newVectorTestClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return testResponse(404, `{}`), nil
		}
		return testResponse(400, `{"error":{"type":"illegal_argument_exception"}}`), nil
	}))
	if err := client.EnsureIndex(context.Background()); CodeOf(err) != CodeRejected {
		t.Fatalf("invalid mapping was treated as created: %v", err)
	}
}
