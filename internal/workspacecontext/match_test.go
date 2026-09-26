package workspacecontext

import "testing"

func TestMatchTermsRequiresWholeWordBoundary(t *testing.T) {
	t.Parallel()
	doc := Document{Glossary: []Term{{ID: "term_1", Term: "МНО"}}}

	if matches := MatchTerms(doc, "Сколько стоит МНОГО единиц?"); len(matches) != 0 {
		t.Fatalf("МНО unexpectedly matched inside МНОГО: %#v", matches)
	}
	matches := MatchTerms(doc, "Что такое МНО?")
	if len(matches) != 1 || matches[0].TermID != "term_1" || matches[0].MatchedText != "МНО" {
		t.Fatalf("МНО did not match as a whole token: %#v", matches)
	}
}

func TestMatchTermsIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	doc := Document{Glossary: []Term{{ID: "term_1", Term: "мно"}}}

	matches := MatchTerms(doc, "Расскажи про МНО.")
	if len(matches) != 1 || matches[0].MatchedText != "МНО" {
		t.Fatalf("case-insensitive match failed: %#v", matches)
	}
}

func TestMatchTermsFoldsYoToYe(t *testing.T) {
	t.Parallel()

	// ё in the glossary term, е in the question.
	doc := Document{Glossary: []Term{{ID: "term_1", Term: "ёлка"}}}
	matches := MatchTerms(doc, "У нас растет елка во дворе.")
	if len(matches) != 1 || matches[0].MatchedText != "елка" {
		t.Fatalf("ё->е folding failed (term side): %#v", matches)
	}

	// е in the glossary term, ё in the question.
	doc = Document{Glossary: []Term{{ID: "term_2", Term: "елка"}}}
	matches = MatchTerms(doc, "У нас растет ёлка во дворе.")
	if len(matches) != 1 || matches[0].MatchedText != "ёлка" {
		t.Fatalf("ё->е folding failed (question side): %#v", matches)
	}
}

func TestMatchTermsMatchesSynonyms(t *testing.T) {
	t.Parallel()
	doc := Document{Glossary: []Term{{ID: "term_1", Term: "Оплата", Synonyms: []string{"Платёж", "Payment"}}}}

	matches := MatchTerms(doc, "Какой у нас последний платеж?")
	if len(matches) != 1 || matches[0].TermID != "term_1" || matches[0].MatchedText != "платеж" {
		t.Fatalf("synonym match (with ё folding) failed: %#v", matches)
	}

	matches = MatchTerms(doc, "What was the last Payment?")
	if len(matches) != 1 || matches[0].MatchedText != "Payment" {
		t.Fatalf("Latin synonym match failed: %#v", matches)
	}
}

func TestMatchTermsReportsEachTermAtMostOnce(t *testing.T) {
	t.Parallel()
	doc := Document{Glossary: []Term{{ID: "term_1", Term: "МНО"}}}

	matches := MatchTerms(doc, "МНО и снова МНО в одном вопросе")
	if len(matches) != 1 {
		t.Fatalf("expected exactly one match for a repeated term, got %#v", matches)
	}
}
