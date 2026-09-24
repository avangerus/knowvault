package proposer

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/workspacecontext"
)

func TestApplyProposalNewTerm(t *testing.T) {
	current := workspacecontext.Document{Glossary: []workspacecontext.Term{
		{ID: "term_existing", Term: "МНО"},
	}}
	proposal := workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindNewTerm, CandidateTerm: "виджет", SuggestedText: "элемент интерфейса",
	}

	edited, err := applyProposal(current, proposal, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if len(edited.Glossary) != 2 {
		t.Fatalf("len(Glossary) = %d, want 2", len(edited.Glossary))
	}
	added := edited.Glossary[1]
	if added.Term != "виджет" || added.Definition != "элемент интерфейса" {
		t.Fatalf("added term = %#v", added)
	}
	if added.ID == "" || added.ID == "term_existing" {
		t.Fatalf("added term ID = %q, want a fresh non-empty id", added.ID)
	}
	// The original Document's own slice must not be mutated.
	if len(current.Glossary) != 1 {
		t.Fatalf("current.Glossary mutated: %#v", current.Glossary)
	}
}

func TestApplyProposalNewTermEditOverridesSuggestedText(t *testing.T) {
	current := workspacecontext.Document{}
	proposal := workspacecontext.Proposal{Kind: workspacecontext.ProposalKindNewTerm, CandidateTerm: "виджет", SuggestedText: "старый текст"}

	edited, err := applyProposal(current, proposal, workspacecontext.ProposalEdits{SuggestedText: "новое определение"})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if edited.Glossary[0].Definition != "новое определение" {
		t.Fatalf("Definition = %q, want the edit override", edited.Glossary[0].Definition)
	}
}

func TestApplyProposalSynonymAddsAndDedups(t *testing.T) {
	current := workspacecontext.Document{Glossary: []workspacecontext.Term{
		{ID: "term_mno", Term: "МНО", Synonyms: []string{"мно-отчёт"}},
	}}

	edited, err := applyProposal(current, workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindSynonym, TargetTermID: "term_mno", CandidateTerm: "КП",
	}, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if got := edited.Glossary[0].Synonyms; len(got) != 2 || got[1] != "КП" {
		t.Fatalf("Synonyms = %#v, want [мно-отчёт КП]", got)
	}

	// Accepting the same (already-applied) synonym again must not duplicate it.
	edited2, err := applyProposal(edited, workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindSynonym, TargetTermID: "term_mno", CandidateTerm: "кп",
	}, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("applyProposal (dedup): %v", err)
	}
	if got := edited2.Glossary[0].Synonyms; len(got) != 2 {
		t.Fatalf("Synonyms after re-accept = %#v, want no duplicate", got)
	}
}

func TestApplyProposalDefinitionCorrection(t *testing.T) {
	current := workspacecontext.Document{Glossary: []workspacecontext.Term{
		{ID: "term_kp", Term: "КП", Definition: "старое определение"},
	}}

	edited, err := applyProposal(current, workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_kp",
		CandidateTerm: "КП", SuggestedText: "коммерческое предложение",
	}, workspacecontext.ProposalEdits{})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if edited.Glossary[0].Definition != "коммерческое предложение" {
		t.Fatalf("Definition = %q", edited.Glossary[0].Definition)
	}
}

func TestApplyProposalTargetTermMissing(t *testing.T) {
	current := workspacecontext.Document{}
	for _, kind := range []workspacecontext.ProposalKind{
		workspacecontext.ProposalKindSynonym, workspacecontext.ProposalKindDefinitionCorrection,
	} {
		_, err := applyProposal(current, workspacecontext.Proposal{
			Kind: kind, TargetTermID: "term_missing", CandidateTerm: "x",
		}, workspacecontext.ProposalEdits{})
		if CodeOf(err) != CodeTargetTermMissing {
			t.Fatalf("kind=%s: CodeOf(err) = %s, want %s", kind, CodeOf(err), CodeTargetTermMissing)
		}
	}
}

func TestCursorRoundTrip(t *testing.T) {
	when := time.Date(2026, 9, 24, 12, 34, 56, 789000000, time.UTC)
	cursor := encodeCursor(when, "ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV")

	gotTime, gotID, err := decodeCursor(cursor)
	if err != nil {
		t.Fatalf("decodeCursor: %v", err)
	}
	if !gotTime.Equal(when) {
		t.Fatalf("time = %v, want %v", gotTime, when)
	}
	if gotID != "ctxprop_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("id = %q", gotID)
	}
}

func TestDecodeCursorRejectsGarbage(t *testing.T) {
	if _, _, err := decodeCursor("not-base64!!"); err == nil {
		t.Fatal("expected an error for invalid base64")
	}
	if _, _, err := decodeCursor(""); err == nil {
		t.Fatal("expected an error for an empty cursor")
	}
}
