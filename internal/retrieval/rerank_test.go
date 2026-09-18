package retrieval

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

type rerankTestProvider struct {
	scores []float64
	err    error
	texts  []string
	calls  int
	cancel context.CancelFunc
}

func (provider *rerankTestProvider) RerankingIdentity() (string, string) {
	return "test/model", "sha256:test"
}
func (provider *rerankTestProvider) Scores(_ context.Context, _ string, texts []string) ([]float64, error) {
	provider.calls++
	provider.texts = append([]string(nil), texts...)
	if provider.cancel != nil {
		provider.cancel()
	}
	return provider.scores, provider.err
}

func TestRerankHitsGlobalPrefixKeepsCitationScoresAndHistoricalState(t *testing.T) {
	hits := make([]WorkspaceHit, 35)
	scores := make([]float64, maximumRerankCandidates)
	for index := range hits {
		hits[index] = WorkspaceHit{Fragment: evidence.Fragment{FragmentID: fmt.Sprintf("fragment-%02d", index), Text: []byte(fmt.Sprintf("text-%02d", index))},
			Score: float64(100 - index), Channel: HitChannelHybrid, VersionState: "SUPERSEDED"}
		if index < len(scores) {
			scores[index] = float64(index)
		}
	}
	provider := &rerankTestProvider{scores: scores}
	executor := &Executor{reranker: provider}
	profile := WorkspaceSearchProfile{}
	ordered, err := executor.rerankWorkspaceHits(context.Background(), "query", hits, WorkspaceSearchOptions{}, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Reranker || profile.RerankerCandidates != 32 || profile.RerankerModelID != "test/model" || profile.RerankerRepresentation != "authorized-fragment-text-v1" {
		t.Fatalf("inference identity missing: %+v", profile)
	}
	if ordered[0].Fragment.FragmentID != "fragment-31" || ordered[0].Score != hits[31].Score || ordered[0].VersionState != "SUPERSEDED" || !reflect.DeepEqual(ordered[32:], hits[32:]) {
		t.Fatal("global prefix changed evidence scores, historical state, or baseline tail")
	}
	// Every page request ranks the same full set before slicing.
	second, err := executor.rerankWorkspaceHits(context.Background(), "query", hits, WorkspaceSearchOptions{Offset: 10, Limit: 10}, &WorkspaceSearchProfile{})
	if err != nil || !reflect.DeepEqual(ordered, second) {
		t.Fatal("page options changed global ordering")
	}
	if string(hits[0].Fragment.Text) != "text-00" || hits[0].Fragment.FragmentID != "fragment-00" {
		t.Fatal("baseline mutated")
	}
}

func TestRerankInvalidResponsesFallBackVisibly(t *testing.T) {
	for name, provider := range map[string]*rerankTestProvider{
		"missing": {scores: []float64{1}}, "nan": {scores: []float64{1, math.NaN()}},
		"infinite": {scores: []float64{math.Inf(1), 0}}, "endpoint": {err: errors.New("unavailable")},
	} {
		t.Run(name, func(t *testing.T) {
			hits := []WorkspaceHit{{Fragment: evidence.Fragment{Text: []byte("first")}}, {Fragment: evidence.Fragment{Text: []byte("second")}}}
			profile := WorkspaceSearchProfile{}
			actual, err := (&Executor{reranker: provider}).rerankWorkspaceHits(context.Background(), "q", hits, WorkspaceSearchOptions{}, &profile)
			if err != nil || !reflect.DeepEqual(actual, hits) || profile.Reranker || !profile.RerankerDegraded || !profile.Degraded {
				t.Fatalf("invalid inference hidden or reordered: %+v %v", profile, err)
			}
		})
	}
}

func TestRerankCancellationAndAblation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := &rerankTestProvider{scores: []float64{1}, cancel: cancel}
	executor := &Executor{reranker: provider}
	hits := []WorkspaceHit{{Fragment: evidence.Fragment{Text: []byte("text")}}}
	if _, err := executor.rerankWorkspaceHits(ctx, "q", hits, WorkspaceSearchOptions{}, &WorkspaceSearchProfile{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation hidden: %v", err)
	}
	profile := WorkspaceSearchProfile{}
	if _, err := executor.rerankWorkspaceHits(context.Background(), "q", hits, WorkspaceSearchOptions{DisableRerank: true}, &profile); err != nil || provider.calls != 1 || profile.Reranker || profile.RerankerDegraded {
		t.Fatal("diagnostic ablation invoked provider")
	}
	profile = WorkspaceSearchProfile{}
	(&Executor{}).rerankWorkspaceHits(context.Background(), "q", hits, WorkspaceSearchOptions{Rerank: true}, &profile)
	if profile.Reranker || !profile.RerankerDegraded {
		t.Fatal("missing explicitly requested capability hidden")
	}
}

func TestRerankTiesPreserveBaselineOrder(t *testing.T) {
	provider := &rerankTestProvider{scores: []float64{2, 2, 2}}
	order, err := (&Executor{reranker: provider}).rerankOrder(context.Background(), "q", []string{"a", "b", "c"}, &WorkspaceSearchProfile{})
	if err != nil || !reflect.DeepEqual(order, []int{0, 1, 2}) {
		t.Fatalf("unstable tie order: %v %v", order, err)
	}
}

func rerankTestGroup(t *testing.T, id string, count int) workspaceSearchGroup {
	t.Helper()
	group, err := workspaceGroupFromDocument(workspaceGroupTestDocument(id, count))
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestRerankSQLRepresentationIncludesAllAuthorizedMembersOnly(t *testing.T) {
	readable := rerankTestGroup(t, "readable", 3)
	denied := rerankTestGroup(t, "denied", 2)
	fragments := map[string]evidence.Fragment{}
	for index, text := range []string{"site: Central", "supplier: Demo", "containers: 12"} {
		member := readable.Members[index]
		fragments[member.FragmentID] = workspaceGroupTestFragment(member, text)
	}
	fragments[denied.Members[0].FragmentID] = workspaceGroupTestFragment(denied.Members[0], "secret probe")
	groups, texts, partial, err := authorizedWorkspaceRerankText([]workspaceSearchGroup{readable, denied}, fragments)
	if err != nil || !partial || len(groups) != 1 || !reflect.DeepEqual(texts, []string{"site: Central\nsupplier: Demo\ncontainers: 12"}) {
		t.Fatalf("SQL row representation or authorization wrong: %v %v %v", texts, partial, err)
	}
	provider := &rerankTestProvider{scores: []float64{1}}
	if _, err := (&Executor{reranker: provider}).rerankOrder(context.Background(), "q", texts, &WorkspaceSearchProfile{}); err != nil {
		t.Fatal(err)
	}
	if len(provider.texts) != 1 || provider.texts[0] != texts[0] {
		t.Fatal("denied partial group sent to ranking provider")
	}
	changed := fragments[readable.Members[2].FragmentID]
	changed.SourceVersionID = "other-version"
	fragments[changed.FragmentID] = changed
	if _, _, _, err := authorizedWorkspaceRerankText([]workspaceSearchGroup{readable}, fragments); !errors.Is(err, errWorkspaceGroupLineageConflict) {
		t.Fatal("member lineage conflict passed neural ranking gate")
	}
}

func TestRerankPrefixBudgetsFullRowsAndFinalReadback(t *testing.T) {
	groups := []workspaceSearchGroup{rerankTestGroup(t, "large-a", 128), rerankTestGroup(t, "large-b", 256)}
	prefix, ids, partial := planWorkspaceRerankPrefix(groups, 128)
	if !partial || len(prefix) != 1 || len(ids) != 128 {
		t.Fatalf("unbounded ranking read budget: %d %d %v", len(prefix), len(ids), partial)
	}
	window, err := planWorkspaceGroupWindow(groups, workspaceGroupTestProbeMap(groups), 128+len(ids), 1, 1)
	if err != nil || len(window.Groups) != 1 || len(window.ExtraIDs)+len(ids)+128 > maximumWorkspaceGroupBudget {
		t.Fatal("ranking preparation starved final SQL-row readback")
	}
}

func TestRerankPrefixDefersCopiesBeforeCandidateSelection(t *testing.T) {
	groups := []workspaceSearchGroup{rerankTestGroup(t, "file-a", 1), rerankTestGroup(t, "file-copy", 1), rerankTestGroup(t, "file-other", 1)}
	probes := workspaceGroupTestProbeMap(groups)
	for id, fragment := range probes {
		fragment.ObjectType, fragment.CanonicalFormat, fragment.ParserProfileRevision = "FILE", "MD", "parser-1"
		probes[id] = fragment
	}
	groups[2].ContentHash = workspaceGroupTestHash("sha256:", 3)
	groups[2].Members[0].ContentHash = groups[2].ContentHash
	fragment := probes[groups[2].Members[0].FragmentID]
	fragment.ContentHash = groups[2].ContentHash
	probes[fragment.FragmentID] = fragment
	visible, err := visibleWorkspaceGroups(groups, probes)
	if err != nil || visible[0].ID != "file-a" || visible[1].ID != "file-other" || visible[2].ID != "file-copy" {
		t.Fatalf("copies consumed neural candidate prefix: %v %v", visible, err)
	}
	delete(probes, groups[0].Members[0].FragmentID)
	visible, err = visibleWorkspaceGroups(groups, probes)
	if err != nil || len(visible) != 2 {
		t.Fatal("revoked probe admitted to candidate prefix")
	}
}
