package proposer

import (
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacecontext"
)

func TestDetectSynonym(t *testing.T) {
	tests := []struct {
		name  string
		event workspacecontext.RunEvent
		want  []Candidate
	}{
		{
			name: "unknown abbreviation while search args use a known term",
			event: workspacecontext.RunEvent{
				QuestionText: "Что означает КП по этому проекту?",
				MatchedTerms: []workspacecontext.TermMatch{
					{TermID: "term_mno", Term: "МНО", MatchedText: "МНО"},
				},
			},
			want: []Candidate{
				{Kind: workspacecontext.ProposalKindSynonym, CandidateTerm: "КП", TargetTermID: "term_mno"},
			},
		},
		{
			name: "quoted phrase candidate",
			event: workspacecontext.RunEvent{
				QuestionText: `Где хранится «клиентский профиль»?`,
				MatchedTerms: []workspacecontext.TermMatch{
					{TermID: "term_profile", Term: "профиль клиента", MatchedText: "профиль клиента"},
				},
			},
			want: []Candidate{
				{Kind: workspacecontext.ProposalKindSynonym, CandidateTerm: "клиентский профиль", TargetTermID: "term_profile"},
			},
		},
		{
			name: "candidate already known is not unknown",
			event: workspacecontext.RunEvent{
				QuestionText: "Расскажи про МНО подробнее",
				MatchedTerms: []workspacecontext.TermMatch{
					{TermID: "term_mno", Term: "МНО", MatchedText: "МНО"},
				},
			},
			want: nil,
		},
		{
			name: "ё folds to е when comparing candidate to a matched term",
			event: workspacecontext.RunEvent{
				QuestionText: "Что такое ВСЁ в отчёте?",
				MatchedTerms: []workspacecontext.TermMatch{
					{TermID: "term_all", Term: "всё", MatchedText: "всё"},
				},
			},
			want: nil,
		},
		{
			name: "no matched terms means no synonym pairing",
			event: workspacecontext.RunEvent{
				QuestionText: "Что означает КП?",
			},
			want: nil,
		},
		{
			name:  "no abbreviation or quote in the question",
			event: workspacecontext.RunEvent{QuestionText: "обычный текст без сокращений", MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_x", Term: "x", MatchedText: "x"}}},
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.event).Candidates
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Candidates = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestDetectDefinitionCorrection(t *testing.T) {
	tests := []struct {
		name  string
		event workspacecontext.RunEvent
		want  *Candidate
	}{
		{
			name: "под X понимается Y",
			event: workspacecontext.RunEvent{
				QuestionText: "Под КП понимается коммерческое предложение",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_kp", Term: "КП", MatchedText: "КП"}},
			},
			want: &Candidate{
				Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_kp",
				CandidateTerm: "КП", SuggestedText: "коммерческое предложение",
			},
		},
		{
			name: "X - это Y (em dash)",
			event: workspacecontext.RunEvent{
				QuestionText: "КП — это коммерческое предложение, а не контрольный пункт",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_kp", Term: "КП", MatchedText: "КП"}},
			},
			want: &Candidate{
				Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_kp",
				CandidateTerm: "КП", SuggestedText: "коммерческое предложение, а не контрольный пункт",
			},
		},
		{
			name: "bare marker uses the run's first matched term",
			event: workspacecontext.RunEvent{
				QuestionText: "Я имел в виду годовой отчёт, а не квартальный",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_report", Term: "отчёт", MatchedText: "отчёт"}},
			},
			want: &Candidate{
				Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_report",
				CandidateTerm: "отчёт", SuggestedText: "годовой отчёт, а не квартальный",
			},
		},
		{
			name: "не так marker",
			event: workspacecontext.RunEvent{
				QuestionText: "Не так, речь о выручке за квартал",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_rev", Term: "выручка", MatchedText: "выручка"}},
			},
			want: &Candidate{
				Kind: workspacecontext.ProposalKindDefinitionCorrection, TargetTermID: "term_rev",
				CandidateTerm: "выручка", SuggestedText: "речь о выручке за квартал",
			},
		},
		{
			name: "bare marker without any matched term is skipped",
			event: workspacecontext.RunEvent{
				QuestionText: "Нет, это не так",
			},
			want: nil,
		},
		{
			name: "под X понимается Y but X does not match a known term",
			event: workspacecontext.RunEvent{
				QuestionText: "Под ОБФ понимается объём бумажного фонда",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_kp", Term: "КП", MatchedText: "КП"}},
			},
			want: nil,
		},
		{
			name: "ordinary question is not a correction",
			event: workspacecontext.RunEvent{
				QuestionText: "Какая выручка за квартал?",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_rev", Term: "выручка", MatchedText: "выручка"}},
			},
			want: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates := Detect(tc.event).Candidates
			var got *Candidate
			for i := range candidates {
				if candidates[i].Kind == workspacecontext.ProposalKindDefinitionCorrection {
					got = &candidates[i]
				}
			}
			if tc.want == nil {
				if got != nil {
					t.Fatalf("unexpected DEFINITION_CORRECTION candidate: %#v", got)
				}
				return
			}
			if got == nil || *got != *tc.want {
				t.Fatalf("DEFINITION_CORRECTION candidate = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestDetectNewTermTokens(t *testing.T) {
	tests := []struct {
		name  string
		event workspacecontext.RunEvent
		want  []string
	}{
		{
			name:  "unknown non-stop-word token is a candidate",
			event: workspacecontext.RunEvent{QuestionText: "Где найти виджет в отчёте?"},
			want:  []string{"найти", "виджет", "отчёте"},
		},
		{
			name:  "stop words are excluded",
			event: workspacecontext.RunEvent{QuestionText: "и в на с по для"},
			want:  nil,
		},
		{
			name: "already matched glossary term is excluded",
			event: workspacecontext.RunEvent{
				QuestionText: "Покажи выручку компании",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_rev", Term: "выручка", MatchedText: "выручку"}},
			},
			want: []string{"Покажи", "компании"},
		},
		{
			name: "token already used as a synonym candidate this run is excluded",
			event: workspacecontext.RunEvent{
				QuestionText: "Что такое КП?",
				MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_mno", Term: "МНО", MatchedText: "МНО"}},
			},
			want: []string{"такое"},
		},
		{
			name:  "duplicate tokens are deduplicated within one run",
			event: workspacecontext.RunEvent{QuestionText: "виджет виджет ВИДЖЕТ"},
			want:  []string{"виджет"},
		},
		{
			name:  "a purely numeric token is not a word",
			event: workspacecontext.RunEvent{QuestionText: "код 12345 виджета"},
			want:  []string{"код", "виджета"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Detect(tc.event).NewTermTokens
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("NewTermTokens = %#v, want %#v", got, tc.want)
			}
		})
	}
}

// TestDetectProposalsPerRunBound proves the "at most 3 proposals per run"
// bound (S2-MODEL-CONTEXT-DESIGN.md "Proposer") holds purely on Detect's own
// output, with no store or database involved: five distinct unknown
// abbreviations in one question, all pairing with the same matched term,
// yield only 3 Candidates.
func TestDetectProposalsPerRunBound(t *testing.T) {
	event := workspacecontext.RunEvent{
		QuestionText: "Сверь КП, АБВ, ГДЕ, ЁЖЗ и ИКЛ с планом",
		MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_mno", Term: "МНО", MatchedText: "МНО"}},
	}
	got := Detect(event).Candidates
	if len(got) != maxProposalsPerRun {
		t.Fatalf("len(Candidates) = %d, want %d (bound); got %#v", len(got), maxProposalsPerRun, got)
	}
	for _, c := range got {
		if c.Kind != workspacecontext.ProposalKindSynonym {
			t.Fatalf("unexpected kind in bounded output: %#v", c)
		}
	}
}

// TestDetectDedupWithinRun proves the same unknown token appearing multiple
// times in one question produces exactly one SYNONYM candidate, not one per
// occurrence.
func TestDetectDedupWithinRun(t *testing.T) {
	event := workspacecontext.RunEvent{
		QuestionText: "КП готово? Проверь КП ещё раз, кп важен.",
		MatchedTerms: []workspacecontext.TermMatch{{TermID: "term_mno", Term: "МНО", MatchedText: "МНО"}},
	}
	got := Detect(event).Candidates
	if len(got) != 1 {
		t.Fatalf("len(Candidates) = %d, want 1 (dedup within run); got %#v", len(got), got)
	}
	if !strings.EqualFold(got[0].CandidateTerm, "КП") {
		t.Fatalf("CandidateTerm = %q, want case-insensitive КП", got[0].CandidateTerm)
	}
}
