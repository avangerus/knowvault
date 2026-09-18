package workspaceapi

// API-contract tests over searchProfileProjection, the one shared projection
// both REST and MCP read. They pin the exact mounted reranker identity, that a
// mounted failure stays visible while retaining that identity, that an absent
// reranker omits identity, and that no text or credentials leak.

import (
	"encoding/json"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/retrieval"
)

const (
	rerankTestModelID   = "BAAI/bge-reranker-v2-m3"
	rerankTestReprFull  = "authorized-fragment-text-v1"
	rerankTestReprGroup = "authorized-group-members-v1"
)

func rerankTestHash() string { return "sha256:" + strings.Repeat("a", 64) }

// TestRerankProfileMountedIdentityIsExact: a successful mounted reranker echoes
// its exact modelID/hash/candidateCount/representation and is not degraded.
func TestRerankProfileMountedIdentityIsExact(t *testing.T) {
	projection := searchProfileProjection(retrieval.WorkspaceSearchProfile{
		Mode: retrieval.SearchModeHybrid, Lexical: true, Vector: true,
		Fusion: "rrf", K: 60, Reranker: true,
		RerankerModelID: rerankTestModelID, RerankerProfileHash: rerankTestHash(),
		RerankerCandidates: 32, RerankerRepresentation: rerankTestReprFull,
	})
	if got := projection["reranker"]; got != true {
		t.Fatalf("reranker = %v, want true", got)
	}
	if got := projection["reranker_model_id"]; got != rerankTestModelID {
		t.Fatalf("reranker_model_id = %v, want %s", got, rerankTestModelID)
	}
	if got := projection["reranker_profile_hash"]; got != rerankTestHash() {
		t.Fatalf("reranker_profile_hash = %v, want the exact mounted hash", got)
	}
	if got := projection["reranker_candidates"]; got != 32 {
		t.Fatalf("reranker_candidates = %v, want 32", got)
	}
	if got := projection["reranker_representation"]; got != rerankTestReprFull {
		t.Fatalf("reranker_representation = %v, want %s", got, rerankTestReprFull)
	}
	if _, present := projection["reranker_degraded"]; present {
		t.Fatalf("healthy reranker must not set reranker_degraded: %v", projection)
	}
	if got := projection["degraded"]; got != false {
		t.Fatalf("degraded = %v, want false for a healthy reranker", got)
	}
}

// TestRerankProfileMountedFailureRetainsIdentityAndIsVisible: a mounted reranker
// that could not answer keeps its exact identity (modelID/hash/representation)
// with candidates 0, while reranker=false and both degraded flags are true, so a
// degraded answer never reads as a reranked one.
func TestRerankProfileMountedFailureRetainsIdentityAndIsVisible(t *testing.T) {
	projection := searchProfileProjection(retrieval.WorkspaceSearchProfile{
		Mode: retrieval.SearchModeHybrid, Lexical: true, Vector: true,
		Fusion: "rrf", K: 60, Reranker: false,
		RerankerModelID: rerankTestModelID, RerankerProfileHash: rerankTestHash(),
		RerankerCandidates: 0, RerankerRepresentation: rerankTestReprGroup,
		RerankerDegraded: true, Degraded: true,
	})
	if got := projection["reranker"]; got != false {
		t.Fatalf("reranker = %v, want false when inference failed", got)
	}
	if got := projection["degraded"]; got != true {
		t.Fatalf("degraded = %v, want true when the mounted reranker failed", got)
	}
	if got := projection["reranker_degraded"]; got != true {
		t.Fatalf("reranker_degraded = %v, want true when the mounted reranker failed", got)
	}
	if got := projection["reranker_model_id"]; got != rerankTestModelID {
		t.Fatalf("reranker_model_id = %v, want retained %s", got, rerankTestModelID)
	}
	if got := projection["reranker_profile_hash"]; got != rerankTestHash() {
		t.Fatalf("reranker_profile_hash = %v, want retained exact hash", got)
	}
	if got := projection["reranker_candidates"]; got != 0 {
		t.Fatalf("reranker_candidates = %v, want 0 on failure", got)
	}
	if got := projection["reranker_representation"]; got != rerankTestReprGroup {
		t.Fatalf("reranker_representation = %v, want %s", got, rerankTestReprGroup)
	}
}

// TestRerankProfileAbsentRerankerOmitsIdentity: with no reranker mounted the
// projection still answers "did a reranker run?" false and carries no identity.
func TestRerankProfileAbsentRerankerOmitsIdentity(t *testing.T) {
	projection := searchProfileProjection(retrieval.WorkspaceSearchProfile{
		Mode: retrieval.SearchModeLexical, Lexical: true, Fusion: "rrf", K: 60,
	})
	if got := projection["reranker"]; got != false {
		t.Fatalf("reranker = %v, want false when no reranker is mounted", got)
	}
	if got, present := projection["degraded"]; !present || got != false {
		t.Fatalf("degraded must be present and false: %v", projection)
	}
	for _, key := range []string{"reranker_model_id", "reranker_profile_hash",
		"reranker_candidates", "reranker_representation", "reranker_degraded"} {
		if _, present := projection[key]; present {
			t.Fatalf("absent reranker must omit %q: %v", key, projection)
		}
	}
}

// TestRerankProfileCarriesNoTextOrCredentials: the projection is metadata only,
// leaking no candidate text, endpoints or credentials.
func TestRerankProfileCarriesNoTextOrCredentials(t *testing.T) {
	projection := searchProfileProjection(retrieval.WorkspaceSearchProfile{
		Mode: retrieval.SearchModeHybrid, Lexical: true, Vector: true,
		Fusion: "rrf", K: 60, Reranker: true,
		RerankerModelID: rerankTestModelID, RerankerProfileHash: rerankTestHash(),
		RerankerCandidates: 32, RerankerRepresentation: rerankTestReprFull,
		ProfileID: "embed-default", Diversity: "deterministic",
	})
	encoded, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("projection must be JSON-serializable: %v", err)
	}
	rendered := strings.ToLower(string(encoded))
	for _, forbidden := range []string{"http://", "https://", "://", "@",
		"token", "secret", "password", "credential", "authorization",
		"endpoint", "api_key", "bearer"} {
		if strings.Contains(rendered, forbidden) {
			t.Fatalf("projection leaked %q in %s", forbidden, rendered)
		}
	}
	for key, value := range projection {
		switch value.(type) {
		case string, bool, int:
		default:
			t.Fatalf("projection[%q] has non-metadata type %T", key, value)
		}
	}
}
