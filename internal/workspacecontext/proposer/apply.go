package proposer

import (
	"strings"

	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// termIDPrefix mirrors workspacecontext.go's own (unexported) termPrefix:
// "the internal/source/ids.New prefix the store (card A) mints ... glossary-
// term ids with". A NEW_TERM acceptance mints a new glossary term the same
// way card A's store would, so it must use the identical prefix.
const termIDPrefix = "term"

// applyProposal computes the edited Document Accept mints a new version
// from: current, with proposal's change applied, preferring edits.Term,
// edits.Synonyms and edits.Definition over the proposal's own
// CandidateTerm/SuggestedText wherever the caller supplied them (POST
// .../proposals/{id}:accept's optional body, S2-CONTRACT.md "Изменить и
// принять"). It is a pure function — no id it mints depends on anything but
// internal/source/ids's own CSPRNG — so it is fully unit-testable without a
// database; Store.Accept is the only caller.
func applyProposal(current workspacecontext.Document, proposal workspacecontext.Proposal, edits workspacecontext.ProposalEdits) (workspacecontext.Document, error) {
	term := proposal.CandidateTerm
	if edits.Term != "" {
		term = edits.Term
	}
	definition := proposal.SuggestedText
	if edits.Definition != "" {
		definition = edits.Definition
	}

	edited := current
	edited.Glossary = append([]workspacecontext.Term{}, current.Glossary...)

	switch proposal.Kind {
	case workspacecontext.ProposalKindNewTerm:
		newTermID, err := ids.New(termIDPrefix)
		if err != nil {
			return workspacecontext.Document{}, newError(CodeInternal, err)
		}
		added := workspacecontext.Term{
			ID: newTermID, Term: term, Definition: definition, Synonyms: mergedSynonyms(nil, edits.Synonyms),
		}
		edited.Glossary = append(edited.Glossary, added)
		// Card W-2 result 4: accepting a proposed term adds it as one line of
		// the plain-text glossary. When the administrator already wrote
		// glossary text the new line is appended to their own words; otherwise
		// the whole block is re-rendered from the structured glossary, which
		// now includes the accepted term.
		if strings.TrimSpace(edited.GlossaryText) != "" {
			edited.GlossaryText = strings.TrimRight(edited.GlossaryText, "\n") + "\n" + workspacecontext.TermLine(added)
		} else {
			edited.GlossaryText = workspacecontext.DerivedGlossaryText(edited.Glossary)
		}
		return edited, nil

	case workspacecontext.ProposalKindSynonym:
		index := indexOfTermID(edited.Glossary, proposal.TargetTermID)
		if index < 0 {
			return workspacecontext.Document{}, newError(CodeTargetTermMissing, nil)
		}
		targetTerm := edited.Glossary[index]
		targetTerm.Synonyms = mergedSynonyms(targetTerm.Synonyms, append([]string{term}, edits.Synonyms...))
		edited.Glossary[index] = targetTerm
		return edited, nil

	case workspacecontext.ProposalKindDefinitionCorrection:
		index := indexOfTermID(edited.Glossary, proposal.TargetTermID)
		if index < 0 {
			return workspacecontext.Document{}, newError(CodeTargetTermMissing, nil)
		}
		targetTerm := edited.Glossary[index]
		targetTerm.Definition = definition
		targetTerm.Synonyms = mergedSynonyms(targetTerm.Synonyms, edits.Synonyms)
		edited.Glossary[index] = targetTerm
		return edited, nil

	default:
		return workspacecontext.Document{}, newError(CodeInternal, nil)
	}
}

// mergedSynonyms appends each of additions to a fresh copy of existing
// (never aliasing existing's backing array, exactly like the single-synonym
// append this replaces), case/ё-fold-deduplicated against existing and
// against any addition already appended in this same call, and dropping
// empty strings (an edits.Term the caller left blank surfaces here as "",
// never a literal synonym).
func mergedSynonyms(existing []string, additions []string) []string {
	merged := append([]string{}, existing...)
	for _, addition := range additions {
		if addition != "" && !containsFold(merged, addition) {
			merged = append(merged, addition)
		}
	}
	return merged
}

func indexOfTermID(glossary []workspacecontext.Term, termID string) int {
	for i, term := range glossary {
		if term.ID == termID {
			return i
		}
	}
	return -1
}

func containsFold(values []string, candidate string) bool {
	key := foldToken(candidate)
	for _, value := range values {
		if foldToken(value) == key {
			return true
		}
	}
	return false
}
