package question

import (
	"strings"
	"testing"
)

// Card D-16 result 2: the plain_overview route mounts only read-only knowledge
// tools. No tool that writes SQL or reads live data can be offered.
func TestPlainOverviewToolAllowlistExcludesDataTools(t *testing.T) {
	for _, name := range []string{
		"knowvault_search", "knowvault_read", "knowvault_evidence_read",
		"knowvault_list_objects", "knowvault_workspace_list", "knowvault_related",
		"knowvault_grep", "knowvault_sources", "knowvault_sources_list",
		"knowvault_workspace_context",
	} {
		if !plainOverviewToolAllowed(name) {
			t.Fatalf("knowledge tool %q is not mounted on the plain_overview route", name)
		}
	}
	for _, name := range []string{
		sourceSQLToolName, "knowvault_source_schema", liveDataToolName,
		trustedMetricToolName, analyticScalarToolName, submitAnswerToolName,
	} {
		if plainOverviewToolAllowed(name) {
			t.Fatalf("data tool %q is mounted on the plain_overview route", name)
		}
	}
}

// Card D-16 result 1: a plain_overview answer ends with a next question, so the
// server reads only the text after the last question mark.
func TestToolLoopAnswerHasNextQuestion(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{name: "question at the end", text: "Данные о договорах есть. Хотите узнать про договор № 47?", want: true},
		{name: "quoted closing", text: "Сведения о площадках есть. Показать адреса?", want: true},
		{name: "trailing period", text: "Сведения есть. Что именно показать?.", want: true},
		{name: "closing bracket", text: "Сведения есть (что уточнить?)", want: true},
		{name: "no question", text: "В рабочей области есть сведения о договорах.", want: false},
		{name: "question in the middle", text: "Что показать? Пока известны только договоры.", want: false},
		{name: "empty", text: "", want: false},
	}
	for _, example := range cases {
		t.Run(example.name, func(t *testing.T) {
			if got := toolLoopAnswerHasNextQuestion(example.text); got != example.want {
				t.Fatalf("toolLoopAnswerHasNextQuestion(%q) = %v, want %v", example.text, got, example.want)
			}
		})
	}
}

// Card D-16 result 1: the kind-specific instruction carries every rule the
// route needs: read the workspace first, say when nothing is held, name no
// technical location, and finish with a next question.
func TestPlainOverviewInstructionsCarryRouteRules(t *testing.T) {
	for _, want := range []string{
		"what this workspace's information holds about one subject",
		"When the workspace holds nothing about the subject, say plainly that there is nothing on it and describe no data",
		"never write or request SQL",
		"never names a table, relation, column, field, schema, connection or source identifier",
		"Always finish with at least one concrete question",
		"in the language of the user's question",
	} {
		if !strings.Contains(plainOverviewInstructions, want) {
			t.Fatalf("plainOverviewInstructions is missing %q", want)
		}
	}
	// The instruction is this route's own: it must not carry the full loop's
	// SQL or live-data rules.
	for _, forbidden := range []string{"knowvault_source_sql", "knowvault_ask_live_data", "knowvault_compare_metric"} {
		if strings.Contains(plainOverviewInstructions, forbidden) {
			t.Fatalf("plainOverviewInstructions carries a data-tool rule: %q", forbidden)
		}
	}
}

// Card D-16: the server orientation names the sources by their human names and
// the workspace description, and repeats the two rules a model most easily
// misses. It never carries a connection identifier, status or count.
func TestToolLoopPlainOverviewTextUsesHumanNamesOnly(t *testing.T) {
	text := toolLoopPlainOverviewText(questionLanguageRussian,
		[]string{"Договоры", "Клиенты"}, "Краткое описание рабочей области.")
	for _, want := range []string{"«Договоры»", "«Клиенты»", "Краткое описание рабочей области.", "ничего нет", "конкретным вопросом"} {
		if !strings.Contains(text, want) {
			t.Fatalf("plain overview orientation is missing %q: %q", want, text)
		}
	}
	for _, forbidden := range []string{"conn_", "READY", "source_id"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("plain overview orientation leaks %q: %q", forbidden, text)
		}
	}
}

// Card D-16: the plain_overview route uses its own system instruction, and the
// untouched wrapper still uses the full loop's instruction byte for byte.
func TestInitialToolLoopMessagesWithKindInstruction(t *testing.T) {
	outbound, persisted := initialToolLoopMessagesWith("вопрос", nil, 32*1024, "\nCONTEXT", plainOverviewInstructions)
	if len(outbound) != 2 || outbound[0].Content != plainOverviewInstructions+"\nCONTEXT" {
		t.Fatalf("plain_overview system message = %#v", outbound)
	}
	if len(persisted) != 2 || persisted[0].Content != plainOverviewInstructions+"\nCONTEXT" {
		t.Fatalf("persisted plain_overview system message = %#v", persisted)
	}
	generic, _ := initialToolLoopMessages("вопрос", nil, 32*1024, "")
	if len(generic) != 2 || generic[0].Content != toolLoopInstructions {
		t.Fatal("the generic route lost its own instruction")
	}
}
