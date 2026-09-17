package retrieval

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

func workspaceGroupTestHash(prefix string, index int) string {
	letter := string("0123456789abcdef"[index%16])
	return prefix + strings.Repeat(letter, 64)
}

func workspaceGroupTestDocument(id string, members int) search.IndexDocument {
	fragmentIDs := make([]string, members)
	textHashes := make([]string, members)
	anchorHashes := make([]string, members)
	for index := 0; index < members; index++ {
		fragmentIDs[index] = id + "-fragment-" + string(rune('a'+index/26)) + string(rune('a'+index%26))
		textHashes[index] = workspaceGroupTestHash("hmac-sha256:k1:", index)
		anchorHashes[index] = workspaceGroupTestHash("hmac-sha256:k1:", index+7)
	}
	return search.IndexDocument{
		ID: id, OrganizationID: "org-a", SourceObjectID: id + "-object", SourceVersionID: id + "-version",
		ExtractionID: id + "-extraction", EvidenceFragmentID: fragmentIDs[0], EvidenceFragmentIDs: fragmentIDs,
		EvidenceTextHashes: textHashes, EvidenceAnchorHashes: anchorHashes, ContentHash: "sha256:" + strings.Repeat("a", 64),
		TextHash: textHashes[0], AnchorHash: anchorHashes[0], Text: "indexed row",
	}
}

func workspaceGroupTestFragment(member workspaceGroupMember, text string) evidence.Fragment {
	return evidence.Fragment{FragmentID: member.FragmentID, Text: []byte(text), SourceObjectID: member.SourceObjectID,
		SourceVersionID: member.SourceVersionID, ExtractionID: member.ExtractionID, ContentHash: member.ContentHash,
		EvidenceTextHash: member.TextHash, AnchorHash: member.AnchorHash}
}

func workspaceGroupTestProbeMap(groups []workspaceSearchGroup) map[string]evidence.Fragment {
	probes := make(map[string]evidence.Fragment, len(groups))
	for _, group := range groups {
		member := group.Members[0]
		probes[member.FragmentID] = workspaceGroupTestFragment(member, "probe")
	}
	return probes
}

func TestIndexedGroupedChannelKeepsRowsBeforeFragmentFanout(t *testing.T) {
	first := workspaceGroupTestDocument("chunk-a", 16)
	second := workspaceGroupTestDocument("chunk-b", 16)
	result, err := indexedGroupedChannel(search.Result{Total: 2, TotalExact: true, Hits: []search.Hit{
		{ID: first.ID, Score: 2, Document: first}, {ID: second.ID, Score: 1, Document: second},
	}}, ChannelLexical)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 2 || len(result.Groups[0].Members) != 16 || len(result.Groups[1].Members) != 16 {
		t.Fatalf("indexed documents were fanned out before grouping: groups=%d members=%d/%d", len(result.Groups), len(result.Groups[0].Members), len(result.Groups[1].Members))
	}
	if !result.CoverageComplete {
		t.Fatal("complete two-row result reported partial")
	}
}

func TestIndexedGroupedChannelUsesTopLevelHashesForOneMemberArray(t *testing.T) {
	document := workspaceGroupTestDocument("chunk-single", 1)
	document.EvidenceTextHashes = nil
	document.EvidenceAnchorHashes = nil
	result, err := indexedGroupedChannel(search.Result{Total: 1, TotalExact: true, Hits: []search.Hit{{ID: document.ID, Score: 1, Document: document}}}, ChannelLexical)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 1 || len(result.Groups[0].Members) != 1 || result.Groups[0].Members[0].TextHash != document.TextHash {
		t.Fatalf("one-member top-level lineage was not retained: %+v", result)
	}
}

func TestIndexedGroupedChannelKeepsDistinctChunksForSameObjectVersion(t *testing.T) {
	first := workspaceGroupTestDocument("chunk-file-a", 2)
	second := workspaceGroupTestDocument("chunk-file-b", 2)
	second.SourceObjectID, second.SourceVersionID, second.ExtractionID = first.SourceObjectID, first.SourceVersionID, first.ExtractionID
	result, err := indexedGroupedChannel(search.Result{Total: 2, TotalExact: true, Hits: []search.Hit{
		{ID: first.ID, Score: 2, Document: first}, {ID: second.ID, Score: 1, Document: second},
	}}, ChannelLexical)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Groups) != 2 || result.Groups[0].SourceObjectID != result.Groups[1].SourceObjectID ||
		result.Groups[0].SourceVersionID != result.Groups[1].SourceVersionID {
		t.Fatalf("distinct FILE chunks were merged: %+v", result.Groups)
	}
}

func TestWorkspaceDisplayMemberUsesTermScoreAcrossChannelsThenSemanticFallback(t *testing.T) {
	document := workspaceGroupTestDocument("chunk-display", 3)
	group, err := workspaceGroupFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	group.Channels = []Channel{ChannelVector}
	fragments := map[string]evidence.Fragment{
		group.Members[0].FragmentID: workspaceGroupTestFragment(group.Members[0], "SVC-CORE once"),
		group.Members[1].FragmentID: workspaceGroupTestFragment(group.Members[1], "SVC-CORE SVC-CORE"),
		group.Members[2].FragmentID: workspaceGroupTestFragment(group.Members[2], "unrelated but longest canonical text"),
	}
	selected, ok := workspaceDisplayMember(group, fragments, "SVC-CORE")
	if !ok || selected.FragmentID != group.Members[1].FragmentID {
		t.Fatalf("term score did not choose the best authorized member: %+v", selected)
	}
	for index := range fragments {
		fragment := fragments[index]
		fragment.Text = []byte("no query match")
		fragments[index] = fragment
	}
	fragments[group.Members[2].FragmentID] = workspaceGroupTestFragment(group.Members[2], "longest authorized canonical text")
	selected, ok = workspaceDisplayMember(group, fragments, "missing-term")
	if !ok || selected.FragmentID != group.Members[2].FragmentID {
		t.Fatalf("semantic fallback did not choose longest canonical text: %+v", selected)
	}
}

func TestWorkspaceDefinitionQuestionSelectsSubjectWithoutChangingEvidence(t *testing.T) {
	document := workspaceGroupTestDocument("chunk-question-subject", 3)
	group, err := workspaceGroupFromDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 SVC-CORE?", "what is SVC-CORE?", "SVC-CORE"} {
		fragments := map[string]evidence.Fragment{
			group.Members[0].FragmentID: workspaceGroupTestFragment(group.Members[0], "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 what is \u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 what is"),
			group.Members[1].FragmentID: workspaceGroupTestFragment(group.Members[1], "SVC-CORE = 42"),
			group.Members[2].FragmentID: workspaceGroupTestFragment(group.Members[2], "longest semantic-only passage without any matching word or identifier"),
		}
		for _, channel := range []Channel{ChannelLexical, ChannelVector} {
			group.Channels = []Channel{channel}
			selected, ok := workspaceDisplayMember(group, fragments, query)
			if !ok || selected.FragmentID != group.Members[1].FragmentID || string(selected.Text) != "SVC-CORE = 42" ||
				selected.EvidenceTextHash != fragments[selected.FragmentID].EvidenceTextHash || selected.AnchorHash != fragments[selected.FragmentID].AnchorHash {
				t.Fatalf("query=%q channel=%s selected noise or changed evidence: %+v", query, channel, selected)
			}
		}
		group.Channels = []Channel{ChannelVector}
		selected, ok := workspaceDisplayMember(group, fragments, "what is missing-subject?")
		if !ok || selected.FragmentID != group.Members[2].FragmentID {
			t.Fatal("definition normalization disabled the semantic-only representative")
		}
	}
}

func TestFuseWorkspaceGroupsDetectsMemberDriftAndVectorOnlyIsComplete(t *testing.T) {
	document := workspaceGroupTestDocument("chunk-shared", 2)
	lexical, err := indexedGroupedChannel(search.Result{Total: 1, TotalExact: true, Hits: []search.Hit{{ID: document.ID, Score: 2, Document: document}}}, ChannelLexical)
	if err != nil {
		t.Fatal(err)
	}
	drifted := document
	drifted.EvidenceTextHashes = append([]string(nil), document.EvidenceTextHashes...)
	drifted.EvidenceTextHashes[1] = workspaceGroupTestHash("hmac-sha256:k1:", 31)
	vector, err := indexedGroupedChannel(search.Result{Total: 1, TotalExact: true, Hits: []search.Hit{{ID: drifted.ID, Score: 1, Document: drifted}}}, ChannelVector)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fuseWorkspaceGroups([]workspaceGroupedChannelResult{lexical, vector}, maximumFusedCandidates, FuseOptions{}); err != errWorkspaceGroupLineageConflict {
		t.Fatalf("member lineage drift was accepted: %v", err)
	}
	complete, err := fuseWorkspaceGroups([]workspaceGroupedChannelResult{vector}, maximumFusedCandidates,
		FuseOptions{OptionalChannels: []Channel{ChannelLexical, ChannelEntity}})
	if err != nil {
		t.Fatal(err)
	}
	if complete.Partial {
		t.Fatal("vector-only declared channel was marked partial solely because lexical is absent")
	}
	truncated := vector
	truncated.CoverageComplete = false
	incomplete, err := fuseWorkspaceGroups([]workspaceGroupedChannelResult{truncated}, maximumFusedCandidates,
		FuseOptions{OptionalChannels: []Channel{ChannelLexical, ChannelEntity}})
	if err != nil {
		t.Fatal(err)
	}
	if !incomplete.Partial {
		t.Fatal("truncated answered channel was hidden by OptionalChannels")
	}
}

func TestFuseWorkspaceGroupsCombinesLexicalVectorHybridGroups(t *testing.T) {
	shared := workspaceGroupTestDocument("chunk-shared", 2)
	lexicalOnly := workspaceGroupTestDocument("chunk-lexical", 2)
	vectorOnly := workspaceGroupTestDocument("chunk-vector", 2)
	lexical, err := indexedGroupedChannel(search.Result{Total: 2, TotalExact: true, Hits: []search.Hit{
		{ID: shared.ID, Score: 2, Document: shared}, {ID: lexicalOnly.ID, Score: 1, Document: lexicalOnly},
	}}, ChannelLexical)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := indexedGroupedChannel(search.Result{Total: 2, TotalExact: true, Hits: []search.Hit{
		{ID: shared.ID, Score: 0.9, Document: shared}, {ID: vectorOnly.ID, Score: 0.8, Document: vectorOnly},
	}}, ChannelVector)
	if err != nil {
		t.Fatal(err)
	}
	fused, err := fuseWorkspaceGroups([]workspaceGroupedChannelResult{lexical, vector}, maximumFusedCandidates,
		FuseOptions{OptionalChannels: []Channel{ChannelEntity}})
	if err != nil {
		t.Fatal(err)
	}
	if fused.Partial || len(fused.Groups) != 3 {
		t.Fatalf("unexpected lexical/vector fusion: partial=%v groups=%d", fused.Partial, len(fused.Groups))
	}
	for _, group := range fused.Groups {
		if group.ID == shared.ID && len(group.Channels) != 2 {
			t.Fatalf("shared group did not retain both channel lineages: %+v", group.Channels)
		}
	}
}

func TestPlanWorkspaceGroupWindowOmitsRevokedBeforeOffset(t *testing.T) {
	firstDocument := workspaceGroupTestDocument("chunk-revoked", 2)
	secondDocument := workspaceGroupTestDocument("chunk-readable", 2)
	first, err := workspaceGroupFromDocument(firstDocument)
	if err != nil {
		t.Fatal(err)
	}
	second, err := workspaceGroupFromDocument(secondDocument)
	if err != nil {
		t.Fatal(err)
	}
	probes := workspaceGroupTestProbeMap([]workspaceSearchGroup{second})
	window, err := planWorkspaceGroupWindow([]workspaceSearchGroup{first, second}, probes, 2, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Groups) != 1 || window.Groups[0].ID != second.ID || window.Consumed != 1 || window.Partial {
		t.Fatalf("revoked group consumed page window: %+v", window)
	}
}

func TestPlanWorkspaceGroupWindowAllowsEqualSharedFragmentAndRejectsDrift(t *testing.T) {
	firstDocument := workspaceGroupTestDocument("chunk-shared-a", 2)
	secondDocument := workspaceGroupTestDocument("chunk-shared-b", 2)
	first, err := workspaceGroupFromDocument(firstDocument)
	if err != nil {
		t.Fatal(err)
	}
	second, err := workspaceGroupFromDocument(secondDocument)
	if err != nil {
		t.Fatal(err)
	}
	second.SourceObjectID, second.SourceVersionID, second.ExtractionID, second.ContentHash = first.SourceObjectID, first.SourceVersionID, first.ExtractionID, first.ContentHash
	for index := range second.Members {
		second.Members[index].SourceObjectID, second.Members[index].SourceVersionID = first.SourceObjectID, first.SourceVersionID
		second.Members[index].ExtractionID, second.Members[index].ContentHash = first.ExtractionID, first.ContentHash
	}
	second.Members[0].FragmentID = first.Members[0].FragmentID
	second.Members[0].TextHash, second.Members[0].AnchorHash = first.Members[0].TextHash, first.Members[0].AnchorHash
	probes := workspaceGroupTestProbeMap([]workspaceSearchGroup{first, second})
	window, err := planWorkspaceGroupWindow([]workspaceSearchGroup{first, second}, probes, 2, 0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Groups) != 2 || len(window.ExtraIDs) != 4 {
		t.Fatalf("equal shared fragment identity was rejected or dropped: %+v", window)
	}
	drifted := second
	drifted.Members[0].TextHash = workspaceGroupTestHash("hmac-sha256:k1:", 15)
	if _, err := planWorkspaceGroupWindow([]workspaceSearchGroup{first, drifted}, probes, 2, 0, 2); err != errWorkspaceGroupLineageConflict {
		t.Fatalf("conflicting shared fragment identity was not rejected: %v", err)
	}
}

func TestPlanWorkspaceGroupWindowStopsAtBudgetAndAdvancesCursor(t *testing.T) {
	groups := make([]workspaceSearchGroup, 3)
	for index := range groups {
		document := workspaceGroupTestDocument("chunk-budget-"+string(rune('a'+index)), 200)
		group, err := workspaceGroupFromDocument(document)
		if err != nil {
			t.Fatal(err)
		}
		groups[index] = group
	}
	probes := workspaceGroupTestProbeMap(groups)
	window, err := planWorkspaceGroupWindow(groups, probes, len(groups), 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(window.Groups) != 2 || len(window.ExtraIDs) != 400 || window.ExtraIDs[0] != groups[0].Members[0].FragmentID || window.Consumed != 2 ||
		!window.Partial || !window.HasMore || window.NextOffset != 2 || len(probes)+len(window.ExtraIDs) > maximumWorkspaceGroupBudget {
		t.Fatalf("budget stop did not preserve complete groups/cursor: groups=%d reads=%d consumed=%d partial=%v more=%v next=%d",
			len(window.Groups), len(window.ExtraIDs), window.Consumed, window.Partial, window.HasMore, window.NextOffset)
	}
	next, err := planWorkspaceGroupWindow(groups, probes, len(groups), window.NextOffset, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Groups) != 1 || next.Groups[0].ID != groups[2].ID || next.NextOffset != 0 || next.Partial || next.HasMore {
		t.Fatalf("budget cursor did not make progress: %+v", next)
	}
}
