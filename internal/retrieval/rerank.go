package retrieval

import (
	"context"
	"math"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

const maximumRerankCandidates = 32

// RerankProvider scores canonical, live-authorized candidate text. Scores are
// ordering inputs only: they never replace channel scores or citation lineage.
type RerankProvider interface {
	Scores(ctx context.Context, query string, texts []string) ([]float64, error)
	RerankingIdentity() (modelID, profileHash string)
}

func (executor *Executor) rerankEnabled(options WorkspaceSearchOptions, profile *WorkspaceSearchProfile) bool {
	if options.DisableRerank {
		return false
	}
	if executor.reranker == nil {
		if options.Rerank {
			profile.RerankerDegraded, profile.Degraded = true, true
		}
		return false
	}
	profile.RerankerModelID, profile.RerankerProfileHash = executor.reranker.RerankingIdentity()
	return true
}

// rerankOrder validates the entire response before changing ordering. A failed
// provider remains visible and preserves the deterministic baseline order.
func (executor *Executor) rerankOrder(ctx context.Context, query string, texts []string,
	profile *WorkspaceSearchProfile) ([]int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(texts) == 0 {
		return nil, nil
	}
	scores, err := executor.reranker.Scores(ctx, query, texts)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	valid := err == nil && len(scores) == len(texts)
	if valid {
		for _, score := range scores {
			if math.IsNaN(score) || math.IsInf(score, 0) {
				valid = false
				break
			}
		}
	}
	if !valid {
		profile.RerankerDegraded, profile.Degraded = true, true
		return nil, nil
	}
	profile.Reranker, profile.RerankerCandidates = true, len(texts)
	order := make([]int, len(texts))
	for index := range order {
		order[index] = index
	}
	sort.SliceStable(order, func(i, j int) bool { return scores[order[i]] > scores[order[j]] })
	return order, nil
}

func (executor *Executor) rerankWorkspaceHits(ctx context.Context, query string, hits []WorkspaceHit,
	options WorkspaceSearchOptions, profile *WorkspaceSearchProfile) ([]WorkspaceHit, error) {
	if !executor.rerankEnabled(options, profile) {
		return hits, ctx.Err()
	}
	count := len(hits)
	if count > maximumRerankCandidates {
		count = maximumRerankCandidates
	}
	texts := make([]string, count)
	for index := range texts {
		texts[index] = string(hits[index].Fragment.Text)
	}
	profile.RerankerRepresentation = "authorized-fragment-text-v1"
	order, err := executor.rerankOrder(ctx, query, texts, profile)
	if err != nil || order == nil {
		return hits, err
	}
	ranked := append([]WorkspaceHit(nil), hits...)
	for index, original := range order {
		ranked[index] = hits[original]
	}
	return ranked, nil
}

// planWorkspaceRerankPrefix reserves a global prefix before pagination. Reserve
// room for final readback of the largest group; the preparation budget and its
// ordering therefore do not change between repeated page requests.
func planWorkspaceRerankPrefix(groups []workspaceSearchGroup, probeCount int) (prefix []workspaceSearchGroup, ids []string, partial bool) {
	reserve := 0
	for _, group := range groups {
		if len(group.Members) > reserve {
			reserve = len(group.Members)
		}
	}
	remaining := maximumWorkspaceGroupBudget - probeCount - reserve
	for _, group := range groups {
		if len(prefix) == maximumRerankCandidates {
			break
		}
		if len(ids)+len(group.Members) > remaining {
			partial = true
			break
		}
		prefix = append(prefix, group)
		for _, member := range group.Members {
			ids = append(ids, member.FragmentID)
		}
	}
	return prefix, ids, partial
}

// authorizedWorkspaceRerankText admits a group only when every member has
// passed the Evidence gate with matching immutable lineage. SQL row fields
// become one ordered representation, never separate ranked candidates.
func authorizedWorkspaceRerankText(groups []workspaceSearchGroup, fragments map[string]evidence.Fragment) ([]workspaceSearchGroup, []string, bool, error) {
	authorized := make([]workspaceSearchGroup, 0, len(groups))
	texts := make([]string, 0, len(groups))
	partial := false
	for _, group := range groups {
		complete := true
		var text strings.Builder
		for index, member := range group.Members {
			fragment, found := fragments[member.FragmentID]
			if !found {
				complete = false
				continue
			}
			if !workspaceFragmentMatchesMember(fragment, member) {
				return nil, nil, false, errWorkspaceGroupLineageConflict
			}
			if index > 0 {
				text.WriteByte('\n')
			}
			text.Write(fragment.Text)
		}
		if !complete {
			partial = true
			continue
		}
		authorized = append(authorized, group)
		texts = append(texts, text.String())
	}
	return authorized, texts, partial, nil
}
