package question

import (
	"strings"
	"testing"
)

// TestMetaDialogueQuestionPatternRecognizesTheReproducedTrace proves FIX-6
// #3's closed recognizer catches exactly the owner-reproduced turn 3
// ("you said 3 but showed 23") and its stated variant ("why are the numbers
// different?"), while leaving an ordinary data question alone.
func TestMetaDialogueQuestionPatternRecognizesTheReproducedTrace(t *testing.T) {
	cases := []struct {
		question string
		want     bool
	}{
		{"\u0442\u044b \u0441\u043a\u0430\u0437\u0430\u043b 3 \u0430 \u043f\u043e\u043a\u0430\u0437\u0430\u043b 23", true},
		{"\u043f\u043e\u0447\u0435\u043c\u0443 \u0440\u0430\u0437\u043d\u044b\u0435 \u0447\u0438\u0441\u043b\u0430?", true},
		{"\u043f\u043e\u0447\u0435\u043c\u0443 \u0443 \u0432\u0430\u0441 \u0440\u0430\u0437\u043d\u044b\u0435 \u043e\u0442\u0432\u0435\u0442\u044b?", true},
		{"\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?", false},
		{"\u043a\u0430\u043a\u0438\u0435?", false},
	}
	for _, tc := range cases {
		if got := metaDialogueQuestionPattern.MatchString(tc.question); got != tc.want {
			t.Fatalf("metaDialogueQuestionPattern.MatchString(%q) = %v, want %v", tc.question, got, tc.want)
		}
	}
}

// TestRenderMetaDialogueAnswerExplainsTheDifferingConditions proves FIX-6 #3
// answers the reproduced defect (turn1 COUNT=3 today/vehicle, turn2 LIST=23
// unscoped) by naming the operation/period difference, never with
// INSUFFICIENT_EVIDENCE copy.
func TestRenderMetaDialogueAnswerExplainsTheDifferingConditions(t *testing.T) {
	earlier := metaTurnSnapshot{
		runID: "qrun_1", question: "\u0441\u043a\u043e\u043b\u044c\u043a\u043e \u043c\u0430\u0448\u0438\u043d \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u043d\u0430 \u0440\u0430\u0431\u043e\u0442\u0435?", operation: "AGGREGATE",
		result: &AnswerResult{Operation: "COUNT", Value: "3", Period: &AnswerPeriod{Label: "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", From: "2026-09-08", To: "2026-09-08"}},
	}
	later := metaTurnSnapshot{
		runID: "qrun_2", question: "\u043a\u0430\u043a\u0438\u0435?", operation: "AGGREGATE",
		result: &AnswerResult{Operation: "LIST", Value: "23"},
	}
	answer := renderMetaDialogueAnswer([]metaTurnSnapshot{later, earlier})
	if strings.Contains(answer, "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043d\u0430\u0439\u0442\u0438 \u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0439") {
		t.Fatalf("meta-dialogue answer must never fall back to the generic INSUFFICIENT_EVIDENCE copy: %q", answer)
	}
	for _, want := range []string{"COUNT", "LIST", "\u0441\u0435\u0433\u043e\u0434\u043d\u044f", "3", "23"} {
		if !strings.Contains(answer, want) {
			t.Fatalf("meta-dialogue answer %q missing expected term %q", answer, want)
		}
	}
}

// TestRenderMetaDialogueAnswerIsHonestWithFewerThanTwoTurns proves the
// contract's explicit fallback: when a comparison is not possible, the
// answer says so plainly instead of fabricating one.
func TestRenderMetaDialogueAnswerIsHonestWithFewerThanTwoTurns(t *testing.T) {
	answer := renderMetaDialogueAnswer(nil)
	if !strings.Contains(answer, "previous answers") {
		t.Fatalf("answer with no recoverable turns should say this is a question about prior answers: %q", answer)
	}
}
