package proposer

import (
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// termIDPrefix mirrors workspacecontext.go's own (unexported) termPrefix:
// "the internal/source/ids.New prefix the store (card A) mints ... glossary-
// term ids with". A NEW_TERM acceptance mints a new glossary term the same
// way card A's store would, so it must use the identical prefix.
const termIDPrefix = "term"

// applyProposal computes the edited Document Accept mints a new version
// from: current, with proposal's change applied, preferring edits.
// SuggestedText over proposal.SuggestedText when the caller supplied one
// (POST .../proposals/{id}:accept's optional body, S2-CONTRACT.md
// "Изменить и принять"). It is a pure function — no id it mints depends on
// anything but internal/source/ids's own CSPRNG — so it is fully unit-
// testable without a database; Store.Accept is the only caller.
func applyProposal(current workspacecontext.Document, proposal workspacecontext.Proposal, edits workspacecontext.ProposalEdits) (workspacecontext.Document, error) {
	text := proposal.SuggestedText
	if edits.SuggestedText != "" {
		text = edits.SuggestedText
	}

	edited := current
	edited.Glossary = append([]workspacecontext.Term{}, current.Glossary...)

	switch proposal.Kind {
	case workspacecontext.ProposalKindNewTerm:
		newTermID, err := ids.New(termIDPrefix)
		if err != nil {
			return workspacecontext.Document{}, newError(CodeInternal, err)
		}
		edited.Glossary = append(edited.Glossary, workspacecontext.Term{
			ID: newTermID, Term: proposal.CandidateTerm, Definition: text,
		})
		return edited, nil

	case workspacecontext.ProposalKindSynonym:
		index := indexOfTermID(edited.Glossary, proposal.TargetTermID)
		if index < 0 {
			return workspacecontext.Document{}, newError(CodeTargetTermMissing, nil)
		}
		term := edited.Glossary[index]
		if !containsFold(term.Synonyms, proposal.CandidateTerm) {
			term.Synonyms = append(append([]string{}, term.Synonyms...), proposal.CandidateTerm)
		}
		edited.Glossary[index] = term
		return edited, nil

	case workspacecontext.ProposalKindDefinitionCorrection:
		index := indexOfTermID(edited.Glossary, proposal.TargetTermID)
		if index < 0 {
			return workspacecontext.Document{}, newError(CodeTargetTermMissing, nil)
		}
		term := edited.Glossary[index]
		term.Definition = text
		edited.Glossary[index] = term
		return edited, nil

	default:
		return workspacecontext.Document{}, newError(CodeInternal, nil)
	}
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
