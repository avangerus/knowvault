package questions

// Card D-15 result 2: a question-set run's report shows the kind of every run,
// with the greeting, off-topic and vague questions under their own kinds.

import (
	"strings"
	"testing"
)

func TestReportShowsRecognisedKindPerRun(t *testing.T) {
	report := Report{
		Title: "kind report test",
		Runs: []RunReport{
			{QuestionID: "O2", QuestionText: "привет", Run: 1, Kind: "greeting", Answer: "Здравствуйте."},
			{QuestionID: "H1", QuestionText: "какая погода в Москве?", Run: 1, Kind: "off_topic", Answer: "Это вне темы."},
			{QuestionID: "H2", QuestionText: "покажи данные", Run: 1, Kind: "vague", Answer: "Уточните, что показать."},
			{QuestionID: "Q3", QuestionText: "сколько договоров действует?", Run: 1, Kind: "full", Answer: "3"},
		},
	}
	markdown := RenderMarkdown(report)
	for _, want := range []string{
		"## Recognised kinds",
		"| `greeting` | 1 | O2/1 |",
		"| `off_topic` | 1 | H1/1 |",
		"| `vague` | 1 | H2/1 |",
		"| `full` | 1 | Q3/1 |",
		"| O2 | 1 | greeting |",
		"| H1 | 1 | off_topic |",
		"| H2 | 1 | vague |",
		"- Kind (card D-15, separate recognition step): `greeting`",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("report does not contain %q:\n%s", want, markdown)
		}
	}
}

// A run that never reached the recognition step is shown as not recognised
// rather than being given a kind it did not receive.
func TestReportMarksMissingKind(t *testing.T) {
	markdown := RenderMarkdown(Report{Title: "missing kind", Runs: []RunReport{{QuestionID: "Q1", Run: 1, Answer: "x"}}})
	if !strings.Contains(markdown, "| Q1 | 1 | — |") || !strings.Contains(markdown, "| `(not recognised)` | 1 | Q1/1 |") {
		t.Fatalf("report does not mark a missing kind:\n%s", markdown)
	}
}
