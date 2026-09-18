package retrieval

// This file is the S3 hybrid core of knowvault_search: one question, a lexical
// channel and a vector channel that each apply the workspace, the rights-bearing
// scope and the current-version state INSIDE their own query, reciprocal-rank
// fusion of the two, live re-authorization of every survivor, and a separate
// `term` channel that answers "what does this workspace call this" with an
// addressed fragment rather than with a definition the product invented.
//
// The product still does not think. It ranks, it narrows by rights, it returns
// addresses; the model reads the addresses and decides what they mean. In
// particular the algorithm profile of a call never arrives from the model: it
// is an operator channel used for measurement (§7.5), because a model that
// picks the retrieval algorithm has made the algorithm part of its answer.

import (
	"context"
	"sort"
	"strings"
	"unicode"

	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// SearchMode is the closed retrieval-profile vocabulary of one call. It exists
// for ablation: a stage that cannot switch the vector channel off cannot prove
// the vector channel contributes anything.
type SearchMode string

const (
	SearchModeHybrid  SearchMode = "hybrid"
	SearchModeLexical SearchMode = "lexical"
	SearchModeVector  SearchMode = "vector"
)

// ValidSearchMode reports whether value is one of the three server-owned modes.
func ValidSearchMode(value SearchMode) bool {
	return value == SearchModeHybrid || value == SearchModeLexical || value == SearchModeVector
}

// Channel values carried on a returned hit. They are the answer to "why is this
// here", not a ranking knob.
const (
	HitChannelLexical = "lexical"
	HitChannelVector  = "vector"
	HitChannelHybrid  = "hybrid"
	HitChannelTerm    = "term"
)

const (
	// maximumFusedCandidates bounds the candidate set carried from fusion into
	// post-authorization. It is a ceiling on work, not a page: paging happens
	// after authorization so a page never shrinks because a neighbouring
	// candidate was denied.
	maximumFusedCandidates = 128
	// maximumTermHits bounds the term channel. A homonym is two hits; a
	// catalogue that resolves a query to more entities than this is reported
	// truncated rather than silently narrowed.
	maximumTermHits = 16
	// maximumSearchPageLimit is the largest page the workspace search returns.
	maximumSearchPageLimit = 100
)

// WorkspaceSearchProfile is the retrieval profile a call actually ran under.
// It is echoed in every result so a measurement run never has to assume which
// algorithm produced the score it is comparing.
type WorkspaceSearchProfile struct {
	Mode                   SearchMode
	Lexical                bool
	Vector                 bool
	Fusion                 string
	K                      int
	Reranker               bool
	RerankerModelID        string
	RerankerProfileHash    string
	RerankerCandidates     int
	RerankerRepresentation string
	RerankerDegraded       bool
	// Diversity identifies deterministic copy deferral after live authorization.
	// Scores remain the original channel/fusion scores, before this ordering.
	Diversity string
	// Degraded is true when a channel this profile declared could not answer:
	// no vector capability is mounted, the embedding endpoint refused, or the
	// index is unavailable. It is deliberately visible rather than silent — a
	// hybrid answer that was in fact lexical-only must not read as hybrid.
	Degraded bool
	// ProfileID is the embedding profile identity behind the vector channel,
	// empty when no vector channel answered.
	ProfileID string
}

// WorkspaceHit is one addressed, post-authorized hit.
type WorkspaceHit struct {
	Fragment evidence.Fragment
	Excerpt  string
	Score    float64
	Channel  string
	// VersionState distinguishes current results from retained historical hits
	// admitted by an explicit all_versions search.
	VersionState string
	// TermKind and TermLanguage are set only on a `term` hit: they say which
	// catalogue entry matched, not what the term means.
	TermKind     string
	TermLanguage string
}

// WorkspaceSearchPage is one page of ranked hits plus the term hits that
// accompany it. Term hits are additional, never a replacement: the ranked page
// is the same page it would have been without them.
type WorkspaceSearchPage struct {
	Hits           []WorkspaceHit
	TermHits       []WorkspaceHit
	TermsTruncated bool
	HasMore        bool
	// Partial reports bounded candidate coverage or an evidence-read budget stop.
	// It is independent of profile degradation and of the next-page cursor.
	Partial    bool
	NextOffset int64
	Profile    WorkspaceSearchProfile
}

// WorkspaceSearchOptions carries the page window, the version scope and the
// operator-owned retrieval profile of one call.
type WorkspaceSearchOptions struct {
	AllVersions bool
	Offset      int64
	Limit       int64
	// Mode is empty for the product default (hybrid). A non-empty value only
	// ever arrives from the owner-only ablation channel, never from a tool
	// argument.
	Mode SearchMode
	// Rerank explicitly requests ranking; a mounted provider enables it by default.
	Rerank bool
	// DisableRerank is an operator diagnostic ablation, not a model tool argument.
	DisableRerank bool
}

// WorkspaceSearchReady reports whether this executor can serve the hybrid
// workspace search at all. The lexical channel and the authorization gate are
// the minimum; the vector channel is an addition on top.
func (executor *Executor) WorkspaceSearchReady() bool {
	return executor != nil && executor.viewer != nil
}

// WorkspaceVectorReady reports whether a scope-aware vector capability is
// mounted. An unscoped provider is deliberately not enough.
func (executor *Executor) WorkspaceVectorReady() bool {
	if executor == nil || executor.vector == nil {
		return false
	}
	_, scoped := executor.vector.(ScopedVectorProvider)
	return scoped
}

// SearchWorkspace answers one workspace question over the lexical and vector
// channels and returns addressed, post-authorized hits.
//
// Every mode journals admission before reading an index or corpus. Rebuilt
// revisions use scoped BM25 and k-NN; legacy indices without scope memberships
// retain the governed scan. All surviving candidates are re-authorized live.
func (executor *Executor) SearchWorkspace(ctx context.Context, access database.AccessContext,
	workspaceID, query string, options WorkspaceSearchOptions) (WorkspaceSearchPage, error) {
	if executor == nil || executor.viewer == nil || ctx == nil || access.Validate() != nil ||
		!validOpaque(workspaceID) || strings.TrimSpace(query) == "" {
		return WorkspaceSearchPage{}, &Error{code: CodeExecutorInvalid}
	}
	mode := options.Mode
	if mode == "" {
		mode = SearchModeHybrid
	}
	if !ValidSearchMode(mode) || options.Offset < 0 || options.Limit < 1 || options.Limit > maximumSearchPageLimit {
		return WorkspaceSearchPage{}, &Error{code: CodeExecutorInvalid}
	}
	profile := WorkspaceSearchProfile{
		Mode: mode, Lexical: mode != SearchModeVector, Vector: mode != SearchModeLexical,
		Fusion: "rrf", K: int(rrfConstant), Reranker: false,
	}
	if evidence.LexicalSearchQuery(query) == "" {
		// No subject is not an invitation to retrieve nearest neighbours for
		// question words. Keep admission/denial durable before the empty page.
		if err := executor.viewer.AdmitSearch(ctx, access, workspaceID); err != nil {
			return WorkspaceSearchPage{}, err
		}
		return WorkspaceSearchPage{Profile: WorkspaceSearchProfile{Mode: mode, Fusion: "none"}}, nil
	}

	// 1. Admission and lexical candidates. Indexed hits are scoped before
	// ranking; PostgreSQL below remains the authority on their disclosure.
	channels := make([]ChannelResult, 0, 2)
	byFragment := make(map[string]evidence.Fragment)
	active, found, err := executor.activeSearchProfile(ctx, access)
	if err != nil {
		return WorkspaceSearchPage{}, &Error{code: CodeExecutorFailed, cause: err}
	}
	indexed := executor.client != nil && found && active.revision > 1 && !options.AllVersions
	if indexed {
		return executor.searchIndexedWorkspace(ctx, access, workspaceID, query, options, active, profile)
	}
	if !indexed {
		// Legacy revisions have no indexed scope memberships. Their explicit
		// fallback remains the authorized scan until a full revision is active.
		lexicalPage, err := executor.viewer.SearchFragments(ctx, access, workspaceID, query,
			options.AllVersions, 0, maximumFusedCandidates)
		if err != nil {
			return WorkspaceSearchPage{}, err
		}
		if profile.Lexical {
			lexical := ChannelResult{Channel: ChannelLexical, CoverageComplete: !lexicalPage.HasMore}
			for _, hit := range lexicalPage.Hits {
				byFragment[hit.Fragment.FragmentID] = hit.Fragment
				lexical.Hits = append(lexical.Hits, channelHitFromFragment(ChannelLexical, hit.Fragment, float64(hit.Score)))
			}
			channels = append(channels, lexical)
		}
	}

	// 2. Vector channel. It is skipped — visibly — rather than faked when no
	//    scope-aware capability is mounted or the endpoint refuses.
	if profile.Vector {
		vectorChannel, profileID, ok := executor.workspaceVectorChannel(ctx, access, workspaceID, query, options, active, found)
		if ok {
			profile.ProfileID = profileID
			channels = append(channels, vectorChannel)
		} else {
			profile.Vector = false
			profile.Degraded = true
		}
	}
	if len(channels) == 0 {
		// The only declared channel could not answer. Report the degradation
		// instead of returning an empty page that reads like an empty corpus.
		profile.Fusion = "none"
		return WorkspaceSearchPage{Profile: profile}, &Error{code: CodeExecutorFailed, cause: errWorkspaceChannelsUnavailable}
	}
	if len(channels) == 1 {
		profile.Fusion = "none"
	}

	fused, err := FuseWithOptions(channels, maximumFusedCandidates, FuseOptions{
		OptionalChannels: []Channel{ChannelEntity, ChannelVector, ChannelLexical},
	})
	if err != nil {
		return WorkspaceSearchPage{}, err
	}
	answeredChannelPartial := false
	for _, channel := range channels {
		if !channel.CoverageComplete {
			answeredChannelPartial = true
			break
		}
	}

	// 3. Live re-authorization of every survivor. A lexical hit was authorized
	//    when it was read and a vector hit was never authorized at all; both go
	//    through the same access-point predicate here, so a right revoked
	//    between indexing and now removes the hit regardless of which channel
	//    found it.
	fragmentIDs := make([]string, 0, len(fused.Hits))
	versionRefs := make([]evidence.FragmentVersionRef, 0, len(fused.Hits))
	for _, hit := range fused.Hits {
		fragmentIDs = append(fragmentIDs, hit.EvidenceFragmentID)
		if options.AllVersions {
			versionRefs = append(versionRefs, evidence.FragmentVersionRef{
				FragmentID: hit.EvidenceFragmentID, SourceVersionID: hit.SourceVersionID,
			})
		}
	}
	var authorized []evidence.Fragment
	if options.AllVersions {
		authorized, err = executor.viewer.AuthorizeFragmentVersions(ctx, access, workspaceID, versionRefs)
	} else {
		authorized, err = executor.viewer.AuthorizeFragments(ctx, access, workspaceID, fragmentIDs)
	}
	if err != nil {
		return WorkspaceSearchPage{}, err
	}
	for _, fragment := range authorized {
		byFragment[fragment.FragmentID] = fragment
	}
	live := make(map[string]struct{}, len(authorized))
	for _, fragment := range authorized {
		live[fragment.FragmentID] = struct{}{}
	}

	ranked := make([]WorkspaceHit, 0, len(fused.Hits))
	for _, hit := range fused.Hits {
		fragment, known := byFragment[hit.EvidenceFragmentID]
		if !known {
			continue
		}
		if _, authorizedNow := live[hit.EvidenceFragmentID]; !authorizedNow {
			// all_versions is never permission to reuse a previously readable
			// fragment after live authorization no longer admits it.
			continue
		}
		versionState := search.VersionStateCurrent
		if options.AllVersions && !fragment.IsCurrentVersion {
			versionState = search.VersionStateSuperseded
		}
		ranked = append(ranked, WorkspaceHit{Fragment: fragment,
			Excerpt: evidence.Excerpt(fragment.Text, query), Score: hit.Score,
			Channel: hitChannel(hit.Channels), VersionState: versionState})
	}

	ranked, err = executor.rerankWorkspaceHits(ctx, query, ranked, options, &profile)
	if err != nil {
		return WorkspaceSearchPage{}, err
	}
	page := WorkspaceSearchPage{Profile: profile, Partial: fused.Partial || answeredChannelPartial}
	start := options.Offset
	if start > int64(len(ranked)) {
		start = int64(len(ranked))
	}
	end := start + options.Limit
	if end > int64(len(ranked)) {
		end = int64(len(ranked))
	}
	page.Hits = append([]WorkspaceHit(nil), ranked[start:end]...)
	if end < int64(len(ranked)) {
		page.HasMore = true
		page.NextOffset = end
	}

	// 4. Term channel, on top of the ranked page and never instead of it.
	termHits, truncated := executor.workspaceTermHits(ctx, access, workspaceID, query)
	page.TermHits = termHits
	page.TermsTruncated = truncated
	return page, nil
}

// workspaceVectorChannel embeds the question and runs the k-NN channel with the
// caller's live authorized scope set applied inside the query. It reports
// false — never an empty channel that would read as an empty corpus — when the
// capability is absent, the workspace binds nothing readable, or the endpoint
// refuses.
func (executor *Executor) workspaceVectorChannel(ctx context.Context, access database.AccessContext,
	workspaceID, query string, options WorkspaceSearchOptions, active activeSearchProfile, found bool) (ChannelResult, string, bool) {
	provider, scoped := executor.vectorForProfile(active, found).(ScopedVectorProvider)
	if !scoped || provider == nil {
		return ChannelResult{}, "", false
	}
	scopes, err := executor.viewer.AuthorizedScopeIDs(ctx, access, workspaceID)
	if err != nil || len(scopes) == 0 {
		return ChannelResult{}, "", false
	}
	// Only current versions are ever admitted to the index, so an all_versions
	// question is answered on its superseded half by the lexical channel alone;
	// asking the vector channel for SUPERSEDED would be asking for a state the
	// corpus does not hold.
	versionState := search.VersionStateCurrent
	channel, err := provider.RetrieveScopedVector(ctx, access, workspaceID,
		workspaceOperationID(workspaceID, query), query, scopes, versionState)
	if err != nil {
		return ChannelResult{}, "", false
	}
	if options.AllVersions {
		// The channel covered the current half of the asked corpus only.
		channel.CoverageComplete = false
	}
	return channel, provider.ProfileHash(), true
}

// workspaceTermHits resolves the query against the workspace's own term
// catalogue and returns the definition of each distinct thing the workspace
// calls by that name, as an ordinary addressed fragment.
//
// Nothing here is a dictionary and nothing here is a rule. The catalogue is
// workspace data that ingest produced; a `term` hit is the fragment where the
// definition is written, read through the same authorization gate as any other
// fragment. Two entities behind one name produce two hits and the product does
// not choose between them — exactly as it does not choose between two
// documents.
//
// A failure of the catalogue is not a failure of the search: the ranked page is
// still correct without it, so this returns no term hits rather than failing
// the question.
func (executor *Executor) workspaceTermHits(ctx context.Context, access database.AccessContext,
	workspaceID, query string) ([]WorkspaceHit, bool) {
	if executor.db == nil || executor.graph == nil {
		return nil, false
	}
	candidates := expandPhraseTerms(queryTerms(evidence.LexicalSearchQuery(query)))
	if len(candidates) == 0 {
		return nil, false
	}
	var resolution knowledgegraph.TermResolution
	if err := executor.db.Read(ctx, access, func(txCtx context.Context, tx database.Transaction) error {
		var readErr error
		resolution, readErr = executor.graph.ResolveTermsDetailed(txCtx, tx, access,
			knowledgegraph.ResolveQuery{WorkspaceID: workspaceID, Terms: candidates, Limit: maximumGraphMatches})
		return readErr
	}); err != nil {
		return nil, false
	}
	if len(resolution.Matches) == 0 {
		return nil, false
	}
	// One hit per distinct thing the workspace names, not one per catalogue
	// row: a canonical term, its synonym and its abbreviation are three rows
	// about one entity, while a homonym is two entities and therefore two hits.
	type candidate struct {
		match knowledgegraph.EntityMatch
		order int
	}
	best := make(map[string]candidate, len(resolution.Matches))
	for index, match := range resolution.Matches {
		if !definingTermKind(match.TermKind) {
			// A CONTEXT row records that a word occurred in a fragment, not that
			// the workspace defines anything by it. Returning one as a `term`
			// hit would turn every ordinary word of the corpus into a
			// definition, which is exactly the "smart answer" the product does
			// not make.
			continue
		}
		existing, seen := best[match.EntityID]
		if !seen || match.Confidence > existing.match.Confidence {
			best[match.EntityID] = candidate{match: match, order: index}
		}
	}
	if len(best) == 0 {
		return nil, false
	}
	selected := make([]candidate, 0, len(best))
	for _, value := range best {
		selected = append(selected, value)
	}
	sort.SliceStable(selected, func(i, j int) bool {
		if selected[i].match.Confidence != selected[j].match.Confidence {
			return selected[i].match.Confidence > selected[j].match.Confidence
		}
		return selected[i].match.EntityID < selected[j].match.EntityID
	})
	truncated := len(selected) > maximumTermHits || resolution.Incomplete()
	if len(selected) > maximumTermHits {
		selected = selected[:maximumTermHits]
	}
	fragmentIDs := make([]string, 0, len(selected))
	for _, value := range selected {
		fragmentIDs = append(fragmentIDs, value.match.EvidenceFragmentID)
	}
	// A `term` hit is an ordinary addressable fragment, so it passes the
	// ordinary gate. A catalogue entry whose address no longer resolves to a
	// readable span simply produces no hit — the product never renders a
	// definition it cannot address.
	authorized, err := executor.viewer.AuthorizeFragments(ctx, access, workspaceID, fragmentIDs)
	if err != nil {
		return nil, false
	}
	byFragment := make(map[string]evidence.Fragment, len(authorized))
	for _, fragment := range authorized {
		byFragment[fragment.FragmentID] = fragment
	}
	hits := make([]WorkspaceHit, 0, len(selected))
	for _, value := range selected {
		fragment, ok := byFragment[value.match.EvidenceFragmentID]
		if !ok {
			truncated = true
			continue
		}
		hits = append(hits, WorkspaceHit{
			Fragment: fragment, Excerpt: evidence.Excerpt(fragment.Text, query),
			Score: value.match.Confidence, Channel: HitChannelTerm,
			VersionState: search.VersionStateCurrent,
			TermKind:     value.match.TermKind, TermLanguage: value.match.Language,
		})
	}
	return hits, truncated
}

// definingTermKind reports whether a catalogue row asserts that the workspace
// calls something by this name. It is the same distinction the catalogue's own
// ambiguity count makes: CANONICAL, SYNONYM and ABBREVIATION are assertions an
// ingest actually read out of a document, while CONTEXT is co-occurrence.
func definingTermKind(kind string) bool {
	return kind == "CANONICAL" || kind == "SYNONYM" || kind == "ABBREVIATION"
}

// hitChannel names the provenance of a fused hit: the single channel that found
// it, or `hybrid` when both did.
func hitChannel(channels []Channel) string {
	lexical, vector := false, false
	for _, channel := range channels {
		switch channel {
		case ChannelLexical:
			lexical = true
		case ChannelVector:
			vector = true
		}
	}
	switch {
	case lexical && vector:
		return HitChannelHybrid
	case vector:
		return HitChannelVector
	default:
		return HitChannelLexical
	}
}

// channelHitFromFragment projects an authorized fragment onto the fusion
// vocabulary. The lineage values are the catalogue's own, so the fusion layer's
// lineage-conflict guard compares two channels' claims about the same fragment.
func channelHitFromFragment(channel Channel, fragment evidence.Fragment, score float64) ChannelHit {
	if score < 0 {
		score = 0
	}
	return ChannelHit{Channel: channel, EvidenceFragmentID: fragment.FragmentID,
		SourceObjectID: fragment.SourceObjectID, SourceVersionID: fragment.SourceVersionID,
		ExtractionID: fragment.ExtractionID, ContentHash: fragment.ContentHash,
		TextHash: fragment.EvidenceTextHash, AnchorHash: fragment.AnchorHash, Score: score}
}

// queryTerms tokenizes a question into the distinct words a catalogue lookup
// may be keyed by. It is deliberately the same shape as the lexical tokenizer:
// the catalogue key normalization itself lives in knowledgegraph.
func queryTerms(query string) []string {
	fields := strings.FieldsFunc(strings.ToLower(query), func(character rune) bool {
		return !unicode.IsLetter(character) && !unicode.IsDigit(character) && character != '_' && character != '-'
	})
	seen := make(map[string]struct{}, len(fields))
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		if _, duplicate := seen[field]; duplicate {
			continue
		}
		seen[field] = struct{}{}
		terms = append(terms, field)
		if len(terms) >= maximumExpandedTerms {
			break
		}
	}
	return terms
}

// workspaceOperationID binds one embedding request to one question without
// sending the question text to the model provider as an identifier. It is
// server-owned binding context: the embedding gateway refuses a result whose
// binding does not match the one it asked under.
func workspaceOperationID(workspaceID, query string) string {
	digest, err := knowledgegraph.SemanticTermHash(strings.TrimSpace(query))
	if err != nil || digest == "" {
		return "search:" + workspaceID
	}
	return "search:" + digest
}
