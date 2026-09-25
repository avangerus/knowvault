package question

import (
	"strings"
	"testing"
)

// Card D-7: a question about which sources exist gets only their human
// names, and a question about what the database holds in business words gets
// a business description, never a table, column or status list. This file
// tests the classifier and the two renderers directly; the question-set run
// is the behavioral proof (see tests/e2e/questions).

// TestToolLoopOverviewQuestionClassRecognizesSources covers requirement 1: a
// question built on "источник"/"source" is the narrow sources-only class,
// under any wording, while a question naming a concrete subject (card D-5's
// existing cue) still keeps the ordinary full tool loop.
func TestToolLoopOverviewQuestionClassRecognizesSources(t *testing.T) {
	for _, question := range []string{
		"какие есть источники?",
		"какие источники есть?",
		"что за источники подключены?",
		"источники данных какие?",
		"what sources are there?",
		"list the sources",
		"which sources do you have?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassSources {
			t.Fatalf("question %q classified %v, want sources", question, got)
		}
	}
	for _, question := range []string{
		"из какого источника взяты данные по договору № 47?",
		"в каком источнике зарегистрирована таблица с договорами?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got == toolLoopOverviewClassSources {
			t.Fatalf("question naming a concrete subject %q was still classified as the sources-only class", question)
		}
	}
}

// TestToolLoopOverviewQuestionClassRecognizesDatabase covers requirement 2: a
// question about the database's content in business words, or an explicit
// business-terms request, is the narrow database class, under any wording.
func TestToolLoopOverviewQuestionClassRecognizesDatabase(t *testing.T) {
	for _, question := range []string{
		"что в базе данных можем посмотреть?",
		"что можно узнать из базы?",
		"расскажи бизнес-терминами, что есть в базе",
		"объясни простыми словами, что хранится в базе",
		"what is in the database, in business terms?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassDatabase {
			t.Fatalf("question %q classified %v, want database", question, got)
		}
	}
}

// TestToolLoopOverviewQuestionClassKeepsConcreteAndHypotheticalQuestionsOut
// covers the two guards that keep the new classes narrow: a question naming
// a concrete subject (card D-5's existing cue) and a hypothetical about a
// different, imagined workspace both keep the ordinary full tool loop, even
// when they mention "база" or "источник" in passing.
func TestToolLoopOverviewQuestionClassKeepsConcreteAndHypotheticalQuestionsOut(t *testing.T) {
	for _, question := range []string{
		"какие данные есть в базе про договоры?",
		"что было бы написано в базе, если бы мы занимались не МНО, а пирогами?",
		"сколько записей в базе?",
	} {
		if got := toolLoopOverviewQuestionClass(question); got != toolLoopOverviewClassNone {
			t.Fatalf("question %q classified %v, want the ordinary full tool loop", question, got)
		}
	}
}

// TestToolLoopSourcesOverviewTextNamesOnly covers requirement 1: the rendered
// context carries only the sources' human names, never a status, type, sync
// state or object count, so nothing the model could echo would fail the
// no-internal-markers rule.
func TestToolLoopSourcesOverviewTextNamesOnly(t *testing.T) {
	text := toolLoopSourcesOverviewText(questionLanguageRussian, []string{"Договоры", "Клиенты", "МНО"})
	for _, want := range []string{"Договоры", "Клиенты", "МНО", "clarification"} {
		if !strings.Contains(text, want) {
			t.Fatalf("sources overview text %q omitted %q", text, want)
		}
	}
	for _, unwanted := range []string{"source_id", "READY", "sync_status", "public."} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("sources overview text %q leaked internal state %q", text, unwanted)
		}
	}
}

// TestToolLoopDatabaseOverviewTextNamesOnly covers requirement 2: the
// rendered context is grounded only in the sources' human names and the
// workspace description, never a table, column or status.
func TestToolLoopDatabaseOverviewTextNamesOnly(t *testing.T) {
	text := toolLoopDatabaseOverviewText(questionLanguageRussian, []string{"Договоры", "Клиенты", "МНО"}, "Учёт вывоза отходов")
	for _, want := range []string{"Договоры", "Клиенты", "МНО", "Учёт вывоза отходов", "clarification"} {
		if !strings.Contains(text, want) {
			t.Fatalf("database overview text %q omitted %q", text, want)
		}
	}
	for _, unwanted := range []string{"source_id", "READY", "sync_status", "public.", "container_group"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("database overview text %q leaked a technical reference %q", text, unwanted)
		}
	}
}

// TestToolLoopOverviewSourceNamesDeduplicate covers the shared name
// projection both new classes render from.
func TestToolLoopOverviewSourceNamesDeduplicate(t *testing.T) {
	sources := []toolLoopOverviewSource{
		{Name: "Договоры", ConnectionID: "conn_a"},
		{Name: "Регламенты и договоры", ConnectionID: "conn_b"},
		{Name: "Договоры", ConnectionID: "conn_c"},
		{Name: "", ConnectionID: "conn_d"},
	}
	got := toolLoopOverviewSourceNames(sources)
	want := []string{"Договоры", "Регламенты и договоры"}
	if len(got) != len(want) {
		t.Fatalf("source names = %v, want %v", got, want)
	}
	for index, name := range want {
		if got[index] != name {
			t.Fatalf("source names = %v, want %v", got, want)
		}
	}
}
