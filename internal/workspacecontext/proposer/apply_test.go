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

	edited, err := applyProposal(current, proposal, workspacecontext.ProposalEdits{Definition: "новое определение"})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if edited.Glossary[0].Definition != "новое определение" {
		t.Fatalf("Definition = %q, want the edit override", edited.Glossary[0].Definition)
	}
}

// TestApplyProposalNewTermEditOverridesTermAndAddsSynonyms proves accept-
// with-edits applies all three overrides together (S2-CONTRACT.md accept
// body {"term", "synonyms", "definition"}): edits.Term replaces the proposed
// CandidateTerm as the new glossary term's own name, edits.Synonyms seeds
// its initial synonym list, and edits.Definition replaces the proposal's own
// SuggestedText -- not just Definition alone.
func TestApplyProposalNewTermEditOverridesTermAndAddsSynonyms(t *testing.T) {
	current := workspacecontext.Document{}
	proposal := workspacecontext.Proposal{Kind: workspacecontext.ProposalKindNewTerm, CandidateTerm: "виджет", SuggestedText: "старый текст"}

	edited, err := applyProposal(current, proposal, workspacecontext.ProposalEdits{
		Term: "гаджет", Synonyms: []string{"устройство", "девайс"}, Definition: "новое определение",
	})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	added := edited.Glossary[0]
	if added.Term != "гаджет" {
		t.Fatalf("Term = %q, want the edit override", added.Term)
	}
	if added.Definition != "новое определение" {
		t.Fatalf("Definition = %q, want the edit override", added.Definition)
	}
	if got := added.Synonyms; len(got) != 2 || got[0] != "устройство" || got[1] != "девайс" {
		t.Fatalf("Synonyms = %#v, want [устройство девайс]", got)
	}
}

// TestApplyProposalSynonymEditOverridesTermAndAddsMore proves a SYNONYM
// accept's edits.Term replaces which text is added as the synonym (not the
// proposal's own CandidateTerm), and edits.Synonyms adds further synonyms in
// the same call, both deduplicated against the target term's existing ones.
func TestApplyProposalSynonymEditOverridesTermAndAddsMore(t *testing.T) {
	current := workspacecontext.Document{Glossary: []workspacecontext.Term{
		{ID: "term_mno", Term: "МНО", Synonyms: []string{"мно-отчёт"}},
	}}

	edited, err := applyProposal(current, workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindSynonym, TargetTermID: "term_mno", CandidateTerm: "кп",
	}, workspacecontext.ProposalEdits{Term: "КП", Synonyms: []string{"коммерческое предложение", "мно-отчёт"}})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	got := edited.Glossary[0].Synonyms
	want := []string{"мно-отчёт", "КП", "коммерческое предложение"}
	if len(got) != len(want) {
		t.Fatalf("Synonyms = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Synonyms = %#v, want %#v", got, want)
		}
	}
	// The original Document's own slice must not be mutated (aliasing check).
	if len(current.Glossary[0].Synonyms) != 1 {
		t.Fatalf("current.Glossary[0].Synonyms mutated: %#v", current.Glossary[0].Synonyms)
	}
}

// TestApplyProposalDefinitionCorrectionEditAddsSynonyms proves a
// DEFINITION_CORRECTION accept's edits.Synonyms extends the target term's
// synonyms alongside the corrected definition.
func TestApplyProposalDefinitionCorrectionEditAddsSynonyms(t *testing.T) {
	current := workspacecontext.Document{Glossary: []workspacecontext.Term{
		{ID: "term_kp", Term: "КП", Definition: "старое определение"},
	}}

	edited, err := applyProposal(current, workspacecontext.Proposal{
		Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_kp",
		CandidateTerm: "КП", SuggestedText: "коммерческое предложение",
	}, workspacecontext.ProposalEdits{Synonyms: []string{"предложение"}})
	if err != nil {
		t.Fatalf("applyProposal: %v", err)
	}
	if edited.Glossary[0].Definition != "коммерческое предложение" {
		t.Fatalf("Definition = %q", edited.Glossary[0].Definition)
	}
	if got := edited.Glossary[0].Synonyms; len(got) != 1 || got[0] != "предложение" {
		t.Fatalf("Synonyms = %#v, want [предложение]", got)
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
