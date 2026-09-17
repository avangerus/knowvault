package retrieval

// The indexed workspace search stores one search document per retrieval unit.
// PostgreSQL row cards bind several Evidence fragments to that document.  The
// ordinary retrieval path intentionally keeps its fragment vocabulary for
// planned/legacy callers; this file is the workspace-only grouped path used by
// SearchWorkspace so a row is ranked once and is never expanded into the page
// before ranking and authorization.

import (
	"context"
	"errors"
	"sort"
	"strings"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

const (
	maximumWorkspaceGroupMembers = 256
	maximumWorkspaceGroupBudget  = 512
)

var errWorkspaceGroupLineageConflict = errors.New("RETRIEVAL_WORKSPACE_GROUP_LINEAGE_CONFLICT")

type workspaceGroupedIntegrityError struct {
	cause error
}

func (err *workspaceGroupedIntegrityError) Error() string {
	if err == nil || err.cause == nil {
		return "workspace grouped integrity failure"
	}
	return "workspace grouped integrity failure: " + err.cause.Error()
}

func (err *workspaceGroupedIntegrityError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

// workspaceGroupMember is the immutable member lineage carried by one indexed
// search document. Order is the member's position in the search_chunk, not a
// ranking value; it makes cross-channel comparisons exact and deterministic.
type workspaceGroupMember struct {
	FragmentID      string
	SourceObjectID  string
	SourceVersionID string
	ExtractionID    string
	ContentHash     string
	TextHash        string
	AnchorHash      string
	Order           int
}

// workspaceSearchGroup is one indexed retrieval unit (IndexDocument.ID). Its
// Score is the group RRF score after fusion. Members remain ordered so the
// selected display fragment can be chosen only after the group has passed the
// live authorization gate.
type workspaceSearchGroup struct {
	ID              string
	SourceObjectID  string
	SourceVersionID string
	ExtractionID    string
	ContentHash     string
	Members         []workspaceGroupMember
	Score           float64
	Channels        []Channel
}

type workspaceGroupedChannelResult struct {
	Channel          Channel
	Groups           []workspaceSearchGroup
	CoverageComplete bool
}

type workspaceGroupedFusion struct {
	Groups  []workspaceSearchGroup
	Partial bool
}

// workspaceGroupedPage is the authorized result of one grouped page. The
// public WorkspaceSearchPage owns the same fields; keeping this small return
// shape lets the group authorization code be tested without a transport.
type workspaceGroupedPage struct {
	Hits     []WorkspaceHit
	Partial  bool
	HasMore  bool
	NextPage int64
}

// indexedGroupedChannel parses indexed documents into retrieval-unit groups.
// Unlike indexedChannel, it deliberately does not fan one hit out into one
// ChannelHit per member. The existing indexedChannel remains available to the
// legacy/planned retrieval paths.
func indexedGroupedChannel(result search.Result, kind Channel) (workspaceGroupedChannelResult, error) {
	if !validChannel(kind) || len(result.Hits) > maximumHybridHits {
		return workspaceGroupedChannelResult{}, invalidFusion("workspace grouped channel shape invalid")
	}
	channel := workspaceGroupedChannelResult{Channel: kind,
		CoverageComplete: result.TotalExact && result.Total <= maximumSearchHits && result.Total <= len(result.Hits)}
	byID := make(map[string]int, len(result.Hits))
	for _, hit := range result.Hits {
		group, err := workspaceGroupFromDocument(hit.Document)
		if err != nil {
			return workspaceGroupedChannelResult{}, err
		}
		group.Score = hit.Score
		if index, exists := byID[group.ID]; exists {
			if !workspaceGroupLineageEqual(channel.Groups[index], group) {
				return workspaceGroupedChannelResult{}, errWorkspaceGroupLineageConflict
			}
			if group.Score > channel.Groups[index].Score {
				channel.Groups[index].Score = group.Score
			}
			continue
		}
		byID[group.ID] = len(channel.Groups)
		channel.Groups = append(channel.Groups, group)
	}
	sort.SliceStable(channel.Groups, func(i, j int) bool {
		if channel.Groups[i].Score != channel.Groups[j].Score {
			return channel.Groups[i].Score > channel.Groups[j].Score
		}
		return channel.Groups[i].ID < channel.Groups[j].ID
	})
	if len(channel.Groups) > maximumHybridHits {
		channel.Groups = channel.Groups[:maximumHybridHits]
		channel.CoverageComplete = false
	}
	return channel, nil
}

func workspaceGroupFromDocument(document search.IndexDocument) (workspaceSearchGroup, error) {
	if !validOpaque(document.ID) || !validOpaque(document.SourceObjectID) ||
		!validOpaque(document.SourceVersionID) || !validOpaque(document.ExtractionID) ||
		!validOpaque(document.EvidenceFragmentID) || !validDigest(document.ContentHash) ||
		!validDigest(document.TextHash) || !validDigest(document.AnchorHash) {
		return workspaceSearchGroup{}, invalidFusion("workspace grouped document lineage invalid")
	}
	fragmentIDs := document.EvidenceFragmentIDs
	textHashes := document.EvidenceTextHashes
	anchorHashes := document.EvidenceAnchorHashes
	if len(fragmentIDs) == 0 {
		fragmentIDs = []string{document.EvidenceFragmentID}
		textHashes = []string{document.TextHash}
		anchorHashes = []string{document.AnchorHash}
	} else if len(fragmentIDs) == 1 && len(textHashes) == 0 && len(anchorHashes) == 0 {
		// The indexed document contract permits a one-member array to omit the
		// parallel arrays; the top-level hashes are that member's lineage.
		textHashes = []string{document.TextHash}
		anchorHashes = []string{document.AnchorHash}
	}
	if len(fragmentIDs) == 0 || len(fragmentIDs) > maximumWorkspaceGroupMembers ||
		len(fragmentIDs) != len(textHashes) || len(fragmentIDs) != len(anchorHashes) {
		return workspaceSearchGroup{}, invalidFusion("workspace grouped document members invalid")
	}
	primaryIndex := -1
	for index, fragmentID := range fragmentIDs {
		if fragmentID == document.EvidenceFragmentID {
			primaryIndex = index
			break
		}
	}
	if primaryIndex < 0 || textHashes[primaryIndex] != document.TextHash || anchorHashes[primaryIndex] != document.AnchorHash {
		return workspaceSearchGroup{}, invalidFusion("workspace grouped primary lineage invalid")
	}
	group := workspaceSearchGroup{ID: document.ID,
		SourceObjectID: document.SourceObjectID, SourceVersionID: document.SourceVersionID,
		ExtractionID: document.ExtractionID, ContentHash: document.ContentHash,
		Members: make([]workspaceGroupMember, 0, len(fragmentIDs))}
	seen := make(map[string]struct{}, len(fragmentIDs))
	for index, fragmentID := range fragmentIDs {
		if !validOpaque(fragmentID) || !validDigest(textHashes[index]) || !validDigest(anchorHashes[index]) {
			return workspaceSearchGroup{}, invalidFusion("workspace grouped member lineage invalid")
		}
		if _, duplicate := seen[fragmentID]; duplicate {
			return workspaceSearchGroup{}, invalidFusion("workspace grouped member duplicate")
		}
		seen[fragmentID] = struct{}{}
		group.Members = append(group.Members, workspaceGroupMember{
			FragmentID: fragmentID, SourceObjectID: document.SourceObjectID,
			SourceVersionID: document.SourceVersionID, ExtractionID: document.ExtractionID,
			ContentHash: document.ContentHash, TextHash: textHashes[index],
			AnchorHash: anchorHashes[index], Order: index,
		})
	}
	return group, nil
}

func workspaceGroupLineageEqual(left, right workspaceSearchGroup) bool {
	if left.ID != right.ID || left.SourceObjectID != right.SourceObjectID ||
		left.SourceVersionID != right.SourceVersionID || left.ExtractionID != right.ExtractionID ||
		left.ContentHash != right.ContentHash || len(left.Members) != len(right.Members) {
		return false
	}
	for index := range left.Members {
		if left.Members[index] != right.Members[index] {
			return false
		}
	}
	return true
}

func workspaceGroupMemberIdentityEqual(left, right workspaceGroupMember) bool {
	return left.FragmentID == right.FragmentID && left.SourceObjectID == right.SourceObjectID &&
		left.SourceVersionID == right.SourceVersionID && left.ExtractionID == right.ExtractionID &&
		left.ContentHash == right.ContentHash && left.TextHash == right.TextHash && left.AnchorHash == right.AnchorHash
}

// fuseWorkspaceGroups applies RRF to retrieval units, not their Evidence
// members. A group with the same IndexDocument.ID from lexical and vector
// channels must carry byte-for-byte identical member lineage.
func fuseWorkspaceGroups(results []workspaceGroupedChannelResult, limit int, options FuseOptions) (workspaceGroupedFusion, error) {
	if len(results) == 0 || limit < 1 || limit > maximumHybridLimit {
		return workspaceGroupedFusion{}, invalidFusion("workspace grouped fusion shape invalid")
	}
	optionalChannels := make(map[Channel]struct{}, len(options.OptionalChannels))
	for _, channel := range options.OptionalChannels {
		if !validChannel(channel) {
			return workspaceGroupedFusion{}, invalidFusion("optional channel invalid")
		}
		if _, duplicate := optionalChannels[channel]; duplicate {
			return workspaceGroupedFusion{}, invalidFusion("duplicate optional channel")
		}
		optionalChannels[channel] = struct{}{}
	}
	seenChannels := make(map[Channel]struct{}, len(results))
	byID := make(map[string]*workspaceSearchGroup)
	partial := false
	for _, result := range results {
		if !validChannel(result.Channel) || len(result.Groups) > maximumHybridHits {
			return workspaceGroupedFusion{}, invalidFusion("workspace grouped channel shape invalid")
		}
		if _, duplicate := seenChannels[result.Channel]; duplicate {
			return workspaceGroupedFusion{}, invalidFusion("duplicate channel")
		}
		seenChannels[result.Channel] = struct{}{}
		if !result.CoverageComplete {
			// An answered channel that was truncated is incomplete regardless of
			// whether another channel is optional. Missing capabilities are
			// represented by the caller's channel set/profile; present-channel
			// coverage cannot be hidden by OptionalChannels.
			partial = true
		}
		seenGroups := make(map[string]struct{}, len(result.Groups))
		for rank, group := range result.Groups {
			if err := validateWorkspaceGroup(group); err != nil {
				return workspaceGroupedFusion{}, err
			}
			if _, duplicate := seenGroups[group.ID]; duplicate {
				return workspaceGroupedFusion{}, invalidFusion("duplicate workspace group")
			}
			seenGroups[group.ID] = struct{}{}
			fused := byID[group.ID]
			if fused == nil {
				copyGroup := group
				copyGroup.Members = append([]workspaceGroupMember(nil), group.Members...)
				copyGroup.Channels = []Channel{result.Channel}
				copyGroup.Score = 1 / (rrfConstant + float64(rank+1))
				byID[group.ID] = &copyGroup
				continue
			}
			if !workspaceGroupLineageEqual(*fused, group) {
				return workspaceGroupedFusion{}, errWorkspaceGroupLineageConflict
			}
			fused.Score += 1 / (rrfConstant + float64(rank+1))
			fused.Channels = append(fused.Channels, result.Channel)
		}
	}
	// A missing channel is not itself incomplete coverage: callers append only
	// channels declared and available for this profile. Missing vector support
	// is surfaced through WorkspaceSearchProfile.Degraded; a channel that did
	// answer can independently report a bounded/inexact result above.
	groups := make([]workspaceSearchGroup, 0, len(byID))
	for _, group := range byID {
		sort.Slice(group.Channels, func(i, j int) bool { return group.Channels[i] < group.Channels[j] })
		groups = append(groups, *group)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Score != groups[j].Score {
			return groups[i].Score > groups[j].Score
		}
		return groups[i].ID < groups[j].ID
	})
	if len(groups) > limit {
		groups = groups[:limit]
		partial = true
	}
	return workspaceGroupedFusion{Groups: groups, Partial: partial}, nil
}

func validateWorkspaceGroup(group workspaceSearchGroup) error {
	if !validOpaque(group.ID) || !validOpaque(group.SourceObjectID) ||
		!validOpaque(group.SourceVersionID) || !validOpaque(group.ExtractionID) ||
		!validDigest(group.ContentHash) || len(group.Members) < 1 || len(group.Members) > maximumWorkspaceGroupMembers {
		return invalidFusion("workspace grouped lineage invalid")
	}
	seen := make(map[string]struct{}, len(group.Members))
	for index, member := range group.Members {
		if member.Order != index || !validOpaque(member.FragmentID) ||
			member.SourceObjectID != group.SourceObjectID || member.SourceVersionID != group.SourceVersionID ||
			member.ExtractionID != group.ExtractionID || member.ContentHash != group.ContentHash ||
			!validDigest(member.TextHash) || !validDigest(member.AnchorHash) {
			return invalidFusion("workspace grouped member lineage invalid")
		}
		if _, duplicate := seen[member.FragmentID]; duplicate {
			return invalidFusion("workspace grouped member duplicate")
		}
		seen[member.FragmentID] = struct{}{}
	}
	return nil
}

type workspaceGroupWindow struct {
	Groups     []workspaceSearchGroup
	ExtraIDs   []string
	Consumed   int64
	Partial    bool
	HasMore    bool
	NextOffset int64
}

// planWorkspaceGroupWindow removes groups whose authoritative probe is not
// readable before applying offset/limit, then reserves complete groups under
// the combined probe/member budget. A group is never split.
func planWorkspaceGroupWindow(groups []workspaceSearchGroup, probes map[string]evidence.Fragment,
	probeCount int, offset, limit int64) (workspaceGroupWindow, error) {
	if offset < 0 || limit < 1 || probeCount < 0 || probeCount > maximumWorkspaceGroupBudget {
		return workspaceGroupWindow{}, invalidFusion("workspace grouped page shape invalid")
	}
	visible := make([]workspaceSearchGroup, 0, len(groups))
	seenMembers := make(map[string]workspaceGroupMember)
	for _, group := range groups {
		if err := validateWorkspaceGroup(group); err != nil {
			return workspaceGroupWindow{}, err
		}
		for _, member := range group.Members {
			if previous, duplicate := seenMembers[member.FragmentID]; duplicate {
				if !workspaceGroupMemberIdentityEqual(previous, member) {
					return workspaceGroupWindow{}, errWorkspaceGroupLineageConflict
				}
			} else {
				seenMembers[member.FragmentID] = member
			}
		}
		probeID := group.Members[0].FragmentID
		probe, authorized := probes[probeID]
		if !authorized {
			// A probe denial is the ordinary live ACL result. The group is removed
			// before offset/limit so a revoked row cannot consume page space.
			continue
		}
		if !workspaceFragmentMatchesMember(probe, group.Members[0]) {
			return workspaceGroupWindow{}, errWorkspaceGroupLineageConflict
		}
		visible = append(visible, group)
	}
	visible = deferWorkspaceCopyUnits(visible, probes)
	start := offset
	if start > int64(len(visible)) {
		start = int64(len(visible))
	}
	window := workspaceGroupWindow{}
	remaining := maximumWorkspaceGroupBudget - probeCount
	used := 0
	for index := start; index < int64(len(visible)) && window.Consumed < limit; index++ {
		group := visible[index]
		requested := len(group.Members)
		if requested > remaining-used {
			window.Partial = true
			window.HasMore = true
			window.NextOffset = start + window.Consumed
			break
		}
		window.Groups = append(window.Groups, group)
		for _, member := range group.Members {
			window.ExtraIDs = append(window.ExtraIDs, member.FragmentID)
		}
		used += requested
		window.Consumed++
	}
	if !window.HasMore && start+window.Consumed < int64(len(visible)) {
		window.HasMore = true
		window.NextOffset = start + window.Consumed
	}
	return window, nil
}

// deferWorkspaceCopyUnits keeps the first ranked copy of an identical file
// passage ahead of its copies. It only reorders the authorized candidate set:
// all groups, scores, addresses and later pages remain available. Distinct
// passages in the same file are not collapsed, nor are database row cards.
// Matching the extraction profile and ordered text hashes avoids treating two
// different readings of the same original bytes as interchangeable.
func deferWorkspaceCopyUnits(groups []workspaceSearchGroup, probes map[string]evidence.Fragment) []workspaceSearchGroup {
	type copyKey struct {
		contentHash, format, parser, textHashes string
	}
	firstObject := make(map[copyKey]string)
	primary := make([]workspaceSearchGroup, 0, len(groups))
	copies := make([]workspaceSearchGroup, 0)
	for _, group := range groups {
		probe := probes[group.Members[0].FragmentID]
		if probe.ObjectType != "FILE" || probe.CanonicalFormat == "" || probe.ParserProfileRevision == "" {
			primary = append(primary, group)
			continue
		}
		var hashes strings.Builder
		for _, member := range group.Members {
			hashes.WriteString(member.TextHash)
			hashes.WriteByte('\n')
		}
		key := copyKey{group.ContentHash, probe.CanonicalFormat, probe.ParserProfileRevision, hashes.String()}
		objectID, seen := firstObject[key]
		if seen && objectID != group.SourceObjectID {
			copies = append(copies, group)
			continue
		}
		firstObject[key] = group.SourceObjectID
		primary = append(primary, group)
	}
	return append(primary, copies...)
}

func workspaceFragmentMatchesMember(fragment evidence.Fragment, member workspaceGroupMember) bool {
	return fragment.FragmentID == member.FragmentID && fragment.SourceObjectID == member.SourceObjectID &&
		fragment.SourceVersionID == member.SourceVersionID && fragment.ExtractionID == member.ExtractionID &&
		fragment.ContentHash == member.ContentHash && fragment.EvidenceTextHash == member.TextHash &&
		fragment.AnchorHash == member.AnchorHash
}

// workspaceDisplayMember chooses only among fragments that passed the live
// authorization/readback gate. Lexical groups use the same term-frequency
// scoring as the legacy viewer; semantic-only groups use the longest canonical
// text as a deterministic useful representative.
func workspaceDisplayMember(group workspaceSearchGroup, fragments map[string]evidence.Fragment, query string) (evidence.Fragment, bool) {
	if len(group.Members) == 0 {
		return evidence.Fragment{}, false
	}
	bestScore := int64(0)
	var best evidence.Fragment
	bestMember := workspaceGroupMember{}
	found := false
	for _, member := range group.Members {
		fragment, ok := fragments[member.FragmentID]
		if !ok {
			continue
		}
		score := workspaceMemberLexicalScore(fragment.Text, query)
		if !found || score > bestScore || score == bestScore && workspaceMemberBefore(member, bestMember) {
			best, bestMember, bestScore, found = fragment, member, score, true
		}
	}
	if found && bestScore > 0 {
		return best, true
	}
	best = evidence.Fragment{}
	bestMember = workspaceGroupMember{}
	found = false
	for _, member := range group.Members {
		fragment, ok := fragments[member.FragmentID]
		if !ok || len(fragment.Text) == 0 {
			continue
		}
		if !found || len(fragment.Text) > len(best.Text) || len(fragment.Text) == len(best.Text) && workspaceMemberBefore(member, bestMember) {
			best, bestMember, found = fragment, member, true
		}
	}
	return best, found
}

func workspaceMemberBefore(left, right workspaceGroupMember) bool {
	if left.Order != right.Order {
		return left.Order < right.Order
	}
	return left.FragmentID < right.FragmentID
}

func workspaceMemberLexicalScore(text []byte, query string) int64 {
	if len(text) == 0 {
		return 0
	}
	lower := strings.ToLower(string(text))
	var score int64
	for _, term := range queryTerms(evidence.LexicalSearchQuery(query)) {
		score += int64(strings.Count(lower, term))
	}
	return score
}

func (executor *Executor) authorizeWorkspaceGroups(ctx context.Context, access database.AccessContext,
	workspaceID, query string, fusion workspaceGroupedFusion, offset, limit int64) (workspaceGroupedPage, error) {
	if executor == nil || executor.viewer == nil || len(fusion.Groups) > maximumFusedCandidates {
		return workspaceGroupedPage{}, &Error{code: CodeExecutorInvalid}
	}
	probeIDs := make([]string, 0, len(fusion.Groups))
	for _, group := range fusion.Groups {
		if err := validateWorkspaceGroup(group); err != nil {
			return workspaceGroupedPage{}, err
		}
		probeIDs = append(probeIDs, group.Members[0].FragmentID)
	}
	probes, err := executor.viewer.AuthorizeFragments(ctx, access, workspaceID, probeIDs)
	if err != nil {
		return workspaceGroupedPage{}, err
	}
	probeByID := make(map[string]evidence.Fragment, len(probes))
	for _, fragment := range probes {
		probeByID[fragment.FragmentID] = fragment
	}
	window, err := planWorkspaceGroupWindow(fusion.Groups, probeByID, len(probeIDs), offset, limit)
	if err != nil {
		return workspaceGroupedPage{}, err
	}
	// Re-authorize every member of every selected group in the final read
	// batch, including the probe. The probe only determines ordering and live
	// visibility before the page window; it is never reused as display data.
	allFragments := make(map[string]evidence.Fragment, len(window.ExtraIDs))
	if len(window.ExtraIDs) > 0 {
		members, err := executor.viewer.AuthorizeFragments(ctx, access, workspaceID, window.ExtraIDs)
		if err != nil {
			return workspaceGroupedPage{}, err
		}
		for _, fragment := range members {
			allFragments[fragment.FragmentID] = fragment
		}
	}
	page := workspaceGroupedPage{Partial: fusion.Partial || window.Partial,
		HasMore: window.HasMore, NextPage: window.NextOffset,
		Hits: make([]WorkspaceHit, 0, len(window.Groups))}
	for _, group := range window.Groups {
		complete := true
		for _, member := range group.Members {
			fragment, ok := allFragments[member.FragmentID]
			if !ok {
				complete = false
				break
			}
			if !workspaceFragmentMatchesMember(fragment, member) {
				return workspaceGroupedPage{}, errWorkspaceGroupLineageConflict
			}
		}
		if !complete {
			page.Partial = true
			continue
		}
		fragment, ok := workspaceDisplayMember(group, allFragments, query)
		if !ok {
			page.Partial = true
			continue
		}
		page.Hits = append(page.Hits, WorkspaceHit{Fragment: fragment,
			Excerpt: evidence.Excerpt(fragment.Text, query), Score: group.Score,
			Channel: hitChannel(group.Channels), VersionState: search.VersionStateCurrent})
	}
	return page, nil
}

func (executor *Executor) searchIndexedWorkspace(ctx context.Context, access database.AccessContext,
	workspaceID, query string, options WorkspaceSearchOptions, active activeSearchProfile,
	profile WorkspaceSearchProfile) (WorkspaceSearchPage, error) {
	if err := executor.viewer.AdmitSearch(ctx, access, workspaceID); err != nil {
		return WorkspaceSearchPage{}, err
	}
	channels := make([]workspaceGroupedChannelResult, 0, 2)
	if profile.Lexical {
		scopes, err := executor.viewer.AuthorizedScopeIDs(ctx, access, workspaceID)
		if err != nil {
			return WorkspaceSearchPage{}, err
		}
		lexical := workspaceGroupedChannelResult{Channel: ChannelLexical, CoverageComplete: true}
		if len(scopes) > 0 {
			// Strip only the lexical question envelope; the vector channel below
			// still receives the original question, including its full intent.
			result, err := executor.client.Search(ctx, search.Query{Text: evidence.LexicalSearchQuery(query), Size: maximumSearchHits + 1,
				Operator: search.MatchAny, ProfileRevision: active.revision, ProfileHash: active.hash,
				SourceScopeIDs: scopes, VersionState: search.VersionStateCurrent})
			if err != nil {
				return WorkspaceSearchPage{}, &Error{code: CodeExecutorFailed, cause: err}
			}
			lexical, err = indexedGroupedChannel(result, ChannelLexical)
			if err != nil {
				return WorkspaceSearchPage{}, err
			}
		}
		channels = append(channels, lexical)
	}
	if profile.Vector {
		vector, profileID, ok, vectorErr := executor.workspaceGroupedVectorChannel(ctx, access, workspaceID, query, options, active, true)
		if vectorErr != nil {
			return WorkspaceSearchPage{}, vectorErr
		}
		if ok {
			profile.ProfileID = profileID
			channels = append(channels, vector)
		} else {
			profile.Vector = false
			profile.Degraded = true
		}
	}
	if len(channels) == 0 {
		profile.Fusion = "none"
		return WorkspaceSearchPage{Profile: profile}, &Error{code: CodeExecutorFailed, cause: errWorkspaceChannelsUnavailable}
	}
	if len(channels) == 1 {
		profile.Fusion = "none"
	}
	fused, err := fuseWorkspaceGroups(channels, maximumFusedCandidates, FuseOptions{
		OptionalChannels: []Channel{ChannelEntity, ChannelVector, ChannelLexical},
	})
	if err != nil {
		return WorkspaceSearchPage{}, err
	}
	groupedPage, err := executor.authorizeWorkspaceGroups(ctx, access, workspaceID, query, fused, options.Offset, options.Limit)
	if err != nil {
		return WorkspaceSearchPage{}, err
	}
	profile.Diversity = "file-copy-units-v1"
	page := WorkspaceSearchPage{Hits: groupedPage.Hits, Partial: groupedPage.Partial,
		HasMore: groupedPage.HasMore, NextOffset: groupedPage.NextPage, Profile: profile}
	termHits, truncated := executor.workspaceTermHits(ctx, access, workspaceID, query)
	page.TermHits = termHits
	page.TermsTruncated = truncated
	return page, nil
}

// workspaceGroupedVectorChannel is the indexed workspace counterpart of the
// historical fragment-channel helper. Providers without the grouped method
// are intentionally reported as unavailable so the caller can expose a
// degraded vector profile instead of silently reintroducing fanout.
func (executor *Executor) workspaceGroupedVectorChannel(ctx context.Context, access database.AccessContext,
	workspaceID, query string, options WorkspaceSearchOptions, active activeSearchProfile, found bool) (workspaceGroupedChannelResult, string, bool, error) {
	provider, scoped := executor.vectorForProfile(active, found).(ScopedVectorProvider)
	if !scoped || provider == nil {
		return workspaceGroupedChannelResult{}, "", false, nil
	}
	grouped, supported := provider.(groupedScopedVectorProvider)
	if !supported || grouped == nil {
		return workspaceGroupedChannelResult{}, "", false, nil
	}
	scopes, err := executor.viewer.AuthorizedScopeIDs(ctx, access, workspaceID)
	if err != nil || len(scopes) == 0 {
		return workspaceGroupedChannelResult{}, "", false, nil
	}
	channel, err := grouped.RetrieveScopedVectorGroups(ctx, access, workspaceID,
		workspaceOperationID(workspaceID, query), query, scopes, search.VersionStateCurrent)
	if err != nil {
		var integrity *workspaceGroupedIntegrityError
		if errors.As(err, &integrity) {
			return workspaceGroupedChannelResult{}, "", false, err
		}
		return workspaceGroupedChannelResult{}, "", false, nil
	}
	if options.AllVersions {
		channel.CoverageComplete = false
	}
	return channel, provider.ProfileHash(), true, nil
}
