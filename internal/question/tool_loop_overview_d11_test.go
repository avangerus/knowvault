package question

import (
	"strings"
	"testing"
)

// Card D-11 (ADR-0099): the kind of answer for a "did it change" question and
// for a hypothetical question about the workspace's data is no longer chosen
// by a server-side word or stem match. Card D-8's overviewChangeCue,
// overviewCounterfactualCue, toolLoopOverviewClassRecency and
// toolLoopOverviewClassCounterfactual are removed with their tests; this file
// checks what replaces them: the classifier no longer special-cases such a
// question at all (it is either the ordinary full loop or, when it also
// matches one of the classes card D-7/D-5 still recognize by word, that
// class's overview), and the generic, wording-independent rule the answering
// model follows lives in toolLoopInstructions. Recognition itself is proven
// only by real runs of the model (tests/e2e/questions), never by a unit test
// over a list of phrasings (ADR-0099 decision 3) -- this file does not
// attempt to.

// TestToolLoopOverviewQuestionClassNoLongerSpecialCasesChangeOrHypothetical
// covers the removal itself: a "did it change" or hypothetical question that
// names none of the workspace/source/database words card D-7 and D-5 still
// recognize by word falls through to classNone, the ordinary full tool loop,
// exactly like any other question the classifier does not recognize. It no
// longer receives a dedicated recency or counterfactual overview.
func TestToolLoopOverviewQuestionClassNoLongerSpecialCasesChangeOrHypothetical(t *testing.T) {
	for _, question := range []string{
		"регламент менялся?",
		"регламент ещё актуален?",
		"has the regulation changed recently?",
		"будь у нас другой профиль деятельности, что показали бы материалы?",
		"what would the records look like under a different line of work?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassNone {
			t.Fatalf("question %q classified %v, want classNone (the ordinary full tool loop)", question, got)
		}
	}
}

// TestToolLoopInstructionsRecognizeChangeAndHypotheticalByMeaning covers the
// generic, wording-independent replacement itself: toolLoopInstructions
// (sent on every question, not conditioned on any word match) tells the
// model to recognize both kinds by meaning, to verify the version fact with
// a real tool call for the first, to answer from the real source names for
// the second, and that this recognition defers to a more specific overview
// framing's own text only for the D-7 source/database overview shapes -- not
// for the count/value rule or the off-topic rule, which stay in force (return
// 1, card D-11: an English counting question regressed when the rule's
// priority was written broadly enough to shadow them too).
func TestToolLoopInstructionsRecognizeChangeAndHypotheticalByMeaning(t *testing.T) {
	for _, want := range []string{
		"recognized by the meaning of the question",
		"never by matching specific words",
		"this rule decides instead of that shape",
		"whether a document or material itself has changed, was updated, or is still current",
		"knowvault_list_objects with all_versions true",
		"hypothetical or counterfactual question that explicitly imagines this same workspace doing a different business",
	} {
		if !strings.Contains(toolLoopInstructions, want) {
			t.Fatalf("toolLoopInstructions is missing the meaning-based recognition rule: %q", want)
		}
	}
}

// TestToolLoopInstructionsExcludeCountingAndOffTopicQuestions covers return 1
// and return 2 (card D-11 RETURN-1.md): a count/value/listing question keeps
// running the live read (an English "how many active contracts?" must not be
// pulled toward the recency exception by the word "active" echoing "current"),
// and a question genuinely unrelated to the workspace's subject keeps the
// zero-tool-call off-topic answer even when it is phrased hypothetically (a
// reworded "what's the weather" must not be pulled toward the counterfactual
// exception and its source-name lookup).
func TestToolLoopInstructionsExcludeCountingAndOffTopicQuestions(t *testing.T) {
	for _, want := range []string{
		"neither ever applies to a question asking for a count, a total, a specific value or a listing of records",
		"Neither ever applies to a question that is not about this workspace's subject at all either",
		"an imagined or hypothetical framing alone does not turn an unrelated topic into workspace data",
	} {
		if !strings.Contains(toolLoopInstructions, want) {
			t.Fatalf("toolLoopInstructions is missing the counting/off-topic exclusion: %q", want)
		}
	}
}

// TestToolLoopOverviewDeferToGenericRuleOnConflict covers the one real
// collision left after the word-based cues were removed: a hypothetical or
// change question can still contain the word "база"/"источник" and so still
// reach the D-7 database or sources overview. Both overview texts now name
// the general rule above them and tell the model to prefer it when the
// question is actually one of those two kinds by meaning.
func TestToolLoopOverviewDeferToGenericRuleOnConflict(t *testing.T) {
	database := toolLoopDatabaseOverviewText(questionLanguageRussian, []string{"Договоры"}, "")
	sources := toolLoopSourcesOverviewText(questionLanguageRussian, []string{"Договоры"})
	for name, text := range map[string]string{"database": database, "sources": sources} {
		if !strings.Contains(text, "общему правилу об этих двух видах вопроса") {
			t.Fatalf("%s overview text does not defer to the general recognition rule: %q", name, text)
		}
	}
}

// TestToolLoopCaveatRuleIsConditional covers card D-8 requirement 2, kept
// unchanged by this card: the generic instruction still does not demand an
// unconditional boundaries paragraph.
func TestToolLoopCaveatRuleIsConditional(t *testing.T) {
	if !strings.Contains(toolLoopInstructions, "Add a caveat or boundary sentence only when the answer would otherwise mislead") ||
		!strings.Contains(toolLoopInstructions, "at most one short sentence") {
		t.Fatal("toolLoopInstructions lost the conditional caveat rule")
	}
	if strings.Contains(toolLoopInstructions, "state what is supported and what its boundaries are in plain words") {
		t.Fatal("toolLoopInstructions still demands an unconditional boundaries statement")
	}
}

// TestToolLoopOverviewQuestionClassStillRecognizesSourcesAndDatabase covers a
// regression guard for the classes this card leaves untouched (out of
// scope): the D-7 source-list and database-business classes still classify
// their own canonical wording after the recency/counterfactual removal.
func TestToolLoopOverviewQuestionClassStillRecognizesSourcesAndDatabase(t *testing.T) {
	if got := toolLoopOverviewQuestionClass("какие источники подключены?"); got != toolLoopOverviewClassSources {
		t.Fatalf("sources question classified %v, want toolLoopOverviewClassSources", got)
	}
	if got := toolLoopOverviewQuestionClass("расскажи бизнес-терминами, что есть в базе"); got != toolLoopOverviewClassDatabase {
		t.Fatalf("database question classified %v, want toolLoopOverviewClassDatabase", got)
	}
}
