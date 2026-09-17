package workspaceapi

// This file is the S3 transport half of knowvault_search: the optional hybrid
// retrieval capability, the operator-only retrieval-profile channel, and the
// one page shape both the MCP tool and its REST parity route render.
//
// Two things are deliberate here. First, the tool's argument schema does not
// gain a profile field and stays additionalProperties:false, so a model that
// tries to pick the retrieval algorithm is refused as an unknown member — the
// algorithm is not part of the answer. Second, a deployment without the hybrid
// capability keeps exactly the lexical page it served before, labelled as
// lexical rather than silently presented as hybrid.

import (
	"context"
	"net/http"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/searchprofile"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// searchProfileHeader is the operator channel of §7.5. It is a transport
// header rather than a tool argument because a model must not be able to
// select the retrieval algorithm, and because an ablation whose profile the
// model could have influenced measures nothing.
const searchProfileHeader = "X-KnowVault-Search-Profile"

// WorkspaceHybridSearch is S3's optional hybrid retrieval capability
// (internal/retrieval.Executor satisfies it). A handler composed without it
// keeps the existing lexical search, so every existing composition and every
// existing fake stays source compatible and fails closed to lexical rather
// than to nothing.
type WorkspaceHybridSearch interface {
	SearchWorkspace(context.Context, database.AccessContext, string, string,
		retrieval.WorkspaceSearchOptions) (retrieval.WorkspaceSearchPage, error)
}

// SearchProfileChannel authorizes and journals one presented retrieval-profile
// value (internal/searchprofile.Service satisfies it). It is separate from the
// hybrid capability because the decision is an authorization and audit
// question, not a retrieval one: the transport never decides on its own who
// may run an ablation.
type SearchProfileChannel interface {
	ResolveCallProfile(context.Context, database.AccessContext, string, string) (searchprofile.CallProfile, bool, error)
}

// EnableHybridSearch wires S3's hybrid retrieval and its operator-only profile
// channel. Like every other optional capability it is additive: a nil search
// capability leaves knowvault_search exactly the lexical tool it was, and a nil
// profile channel means a presented profile header is ignored (there is no
// authority to grant it and no journal to record it in).
func (handler *Handler) EnableHybridSearch(search WorkspaceHybridSearch, profiles SearchProfileChannel) {
	if handler == nil {
		return
	}
	handler.hybridSearch = search
	handler.searchProfiles = profiles
}

// workspaceSearchHit is the one hit shape both surfaces render, whichever
// channel produced it.
type workspaceSearchHit struct {
	Fragment evidence.Fragment
	Excerpt  string
	Score    float64
	// Channel is lexical, vector, hybrid or term: the answer to "why is this
	// here". A lexical-only deployment reports lexical rather than nothing.
	Channel string
	// VersionState is empty when the serving path cannot establish it, CURRENT
	// for a live hit and SUPERSEDED for an old version returned under
	// all_versions. It is never guessed.
	VersionState string
	// TermKind is set only on a term hit.
	TermKind string
}

// workspaceSearchOutcome is one rendered page plus the retrieval profile it
// actually ran under. The profile travels with the page so a measurement run
// never has to assume which algorithm produced the score it compares.
type workspaceSearchOutcome struct {
	Hits           []workspaceSearchHit
	TermHits       []workspaceSearchHit
	TermsTruncated bool
	HasMore        bool
	Partial        bool
	NextOffset     int64
	Profile        map[string]any
}

// requestedSearchProfile reads the operator channel off the request. An absent
// header is the ordinary case; a present one is a claim to be authorized, never
// a value to be trusted.
func requestedSearchProfile(request *http.Request) string {
	if request == nil {
		return ""
	}
	return strings.TrimSpace(request.Header.Get(searchProfileHeader))
}

// resolveSearchMode turns a presented profile value into the mode this call
// actually runs under. Without a profile authority a presented value is
// ignored: granting it would be an unjournalled ablation, and the whole point
// of the channel is that the journal can tell a weak answer from a
// deliberately weakened one.
func (handler *Handler) resolveSearchMode(request *http.Request, access database.AccessContext, workspaceID string) retrieval.SearchMode {
	requested := requestedSearchProfile(request)
	if requested == "" || handler == nil || handler.searchProfiles == nil {
		return retrieval.SearchModeHybrid
	}
	profile, granted, err := handler.searchProfiles.ResolveCallProfile(request.Context(), access, workspaceID, requested)
	if err != nil || !granted {
		return retrieval.SearchModeHybrid
	}
	return retrieval.SearchMode(profile)
}

// hybridSearchOutcome runs one hybrid search and renders it into the shared
// page shape.
func (handler *Handler) hybridSearchOutcome(request *http.Request, access database.AccessContext,
	workspaceID, query string, allVersions bool, offset, limit int64) (workspaceSearchOutcome, error) {
	page, err := handler.hybridSearch.SearchWorkspace(request.Context(), access, workspaceID, query,
		retrieval.WorkspaceSearchOptions{
			AllVersions: allVersions, Offset: offset, Limit: limit,
			Mode: handler.resolveSearchMode(request, access, workspaceID),
		})
	if err != nil {
		return workspaceSearchOutcome{}, err
	}
	outcome := workspaceSearchOutcome{
		HasMore: page.HasMore, Partial: page.Partial, NextOffset: page.NextOffset, TermsTruncated: page.TermsTruncated,
		Profile: searchProfileProjection(page.Profile),
	}
	outcome.Hits = make([]workspaceSearchHit, 0, len(page.Hits))
	for _, hit := range page.Hits {
		outcome.Hits = append(outcome.Hits, workspaceSearchHit{Fragment: hit.Fragment, Excerpt: hit.Excerpt,
			Score: hit.Score, Channel: hit.Channel, VersionState: hit.VersionState})
	}
	outcome.TermHits = make([]workspaceSearchHit, 0, len(page.TermHits))
	for _, hit := range page.TermHits {
		outcome.TermHits = append(outcome.TermHits, workspaceSearchHit{Fragment: hit.Fragment, Excerpt: hit.Excerpt,
			Score: hit.Score, Channel: hit.Channel, VersionState: hit.VersionState, TermKind: hit.TermKind})
	}
	return outcome, nil
}

// lexicalSearchOutcome renders the existing lexical page unchanged, labelled
// with the profile it really ran under. A deployment with no vector channel
// says so instead of letting a client read a lexical answer as a hybrid one.
func lexicalSearchOutcome(page evidence.SearchPage, offset int64) workspaceSearchOutcome {
	outcome := workspaceSearchOutcome{HasMore: page.HasMore, NextOffset: page.NextOffset,
		Profile: map[string]any{
			"mode": string(retrieval.SearchModeLexical), "lexical": true, "vector": false,
			"fusion": "none", "reranker": false, "degraded": true,
		}}
	outcome.Hits = make([]workspaceSearchHit, 0, len(page.Hits))
	for _, hit := range page.Hits {
		outcome.Hits = append(outcome.Hits, workspaceSearchHit{Fragment: hit.Fragment,
			Excerpt: hit.Excerpt, Score: float64(hit.Score), Channel: retrieval.HitChannelLexical})
	}
	if outcome.NextOffset == 0 && page.HasMore {
		outcome.NextOffset = offset + int64(len(page.Hits))
	}
	return outcome
}

// searchProfileProjection renders the retrieval profile of one call. Every
// member is a server-owned fact about what ran, never a knob a caller may set
// on the next call.
func searchProfileProjection(profile retrieval.WorkspaceSearchProfile) map[string]any {
	projection := map[string]any{
		"mode": string(profile.Mode), "lexical": profile.Lexical, "vector": profile.Vector,
		"fusion": profile.Fusion, "reranker": profile.Reranker, "degraded": profile.Degraded,
	}
	if profile.Fusion == "rrf" {
		projection["k"] = profile.K
	}
	if profile.ProfileID != "" {
		projection["embedding_profile"] = profile.ProfileID
	}
	if profile.Diversity != "" {
		projection["diversity"] = profile.Diversity
	}
	return projection
}
