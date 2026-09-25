package question

import (
	"context"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspacetools"
)

// TestToolLoopOverviewQuestionIsNarrow is card D-5 requirement 3's detector
// contract: only questions about the workspace as a whole and greetings take
// the quick overview path. A question that names a concrete subject keeps the
// full tool loop, so this never turns a data question into a one-turn guess.
func TestToolLoopOverviewQuestionIsNarrow(t *testing.T) {
	for _, question := range []string{
		"\u0447\u0442\u043e \u0442\u044b \u0437\u043d\u0430\u0435\u0448\u044c?",
		"\u0427\u0442\u043e \u0442\u0443\u0442 \u0435\u0441\u0442\u044c?",
		"\u0447\u0442\u043e \u0442\u044b \u0443\u043c\u0435\u0435\u0448\u044c",
		"\u041a\u0430\u043a\u0438\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b?",
		"\u043f\u0440\u0438\u0432\u0435\u0442",
		"\u0417\u0434\u0440\u0430\u0432\u0441\u0442\u0432\u0443\u0439\u0442\u0435!",
		"what do you know?",
		"hello",
		"good morning",
		"what data do you have",
		"workspace overview",
		// Card D-5 requirement 3: the class is the question's meaning, not one
		// fixed sentence, so a paraphrase of the same overview question is
		// recognized too.
		"\u0447\u0442\u043e \u0437\u0434\u0435\u0441\u044c \u0435\u0441\u0442\u044c?",
		"\u0447\u0435\u043c \u0442\u044b \u043c\u043e\u0436\u0435\u0448\u044c \u043f\u043e\u043c\u043e\u0447\u044c?",
		"\u043a\u0430\u043a\u0438\u0435 \u0441\u0432\u0435\u0434\u0435\u043d\u0438\u044f \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b?",
		"what can you tell me?",
		"what is available here?",
	} {
		if !toolLoopOverviewQuestion(question) {
			t.Fatalf("overview question not recognized: %q", question)
		}
	}
	for _, question := range []string{
		"",
		"\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0441\u0435\u0433\u043e\u0434\u043d\u044f \u0432\u044b\u0432\u0435\u0437\u0435\u043d\u043e \u043e\u0442\u0445\u043e\u0434\u043e\u0432?",
		"\u0427\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u041c\u041d\u041e?",
		"What is contract.manage.taskitems?",
		"hello, how many dispatches were completed yesterday?",
		"Compare 2026-09-10 with 2026-09-09.",
		// A workspace-overview phrase must not swallow a concrete data question:
		// the named subject keeps the full tool loop.
		"\u0427\u0442\u043e \u0435\u0441\u0442\u044c \u0432 \u0431\u0430\u0437\u0435 \u043f\u043e \u0440\u0435\u0439\u0441\u0430\u043c \u0437\u0430 \u0432\u0447\u0435\u0440\u0430?",
		"\u041a\u0430\u043a\u0438\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0435\u0441\u0442\u044c \u0437\u0430 2026-09-10?",
		"what data do you have about the revenue table?",
		"\u041a\u0430\u043a\u0438\u0435 \u0434\u0430\u043d\u043d\u044b\u0435 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b \u043f\u043e \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u0430\u043c?",
		"\u0427\u0442\u043e \u0442\u044b \u0437\u043d\u0430\u0435\u0448\u044c \u043e \u043a\u043e\u043c\u043f\u0430\u043d\u0438\u0438 \u00ab\u0420\u043e\u043c\u0430\u0448\u043a\u0430\u00bb?",
	} {
		if toolLoopOverviewQuestion(question) {
			t.Fatalf("data question took the quick overview path: %q", question)
		}
	}
}

// TestToolLoopForcedFinalTurnAllowed covers card D-5 requirement 1's single
// decision point. The forced turn is spent exactly when the loop has no answer
// yet and the run can still act.
func TestToolLoopForcedFinalTurnAllowed(t *testing.T) {
	answer := &toolAnswer{Claims: []toolClaim{{Text: "A fact."}}}
	for _, testCase := range []struct {
		name         string
		final        *toolAnswer
		scopeChanged bool
		ctxErr       error
		want         bool
	}{
		{name: "no answer yet", ctxErr: nil, want: true},
		{name: "cancelled run", ctxErr: context.Canceled, want: false},
		{name: "expired run", ctxErr: context.DeadlineExceeded, want: false},
		{name: "scope changed", scopeChanged: true, want: false},
		{name: "answer already submitted", final: answer, want: false},
		{name: "scope changed despite no answer", scopeChanged: true, want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := toolLoopForcedFinalTurnAllowed(testCase.final, testCase.scopeChanged, testCase.ctxErr); got != testCase.want {
				t.Fatalf("toolLoopForcedFinalTurnAllowed() = %v; want %v", got, testCase.want)
			}
		})
	}
}

// TestToolLoopUserVisibleTextsFollowQuestionLanguage covers card D-5
// requirement 4 for every text the tool loop can show.
func TestToolLoopUserVisibleTextsFollowQuestionLanguage(t *testing.T) {
	if got := questionLanguage("\u0447\u0442\u043e \u0442\u044b \u0437\u043d\u0430\u0435\u0448\u044c?"); got != questionLanguageRussian {
		t.Fatalf("russian question language = %q", got)
	}
	if got := questionLanguage("what do you know?"); got != questionLanguageEnglish {
		t.Fatalf("english question language = %q", got)
	}
	if got := toolLoopUnverifiedAnswer(questionLanguageRussian); got != unverifiedAnswerRussianForTest {
		t.Fatalf("russian unverified text = %q", got)
	}
	if got := toolLoopUnverifiedAnswer(questionLanguageEnglish); !strings.Contains(got, "could be verified") {
		t.Fatalf("english unverified text = %q", got)
	}
	if got := toolLoopIncompleteAnswer(questionLanguageRussian, &ToolLoopRecord{}); !strings.Contains(got, "\u041c\u043e\u0434\u0435\u043b\u044c") {
		t.Fatalf("russian incomplete text = %q", got)
	}
	if got := toolLoopIncompleteAnswer(questionLanguageEnglish, &ToolLoopRecord{}); !strings.Contains(got, "The model") {
		t.Fatalf("english incomplete text = %q", got)
	}
	if got := toolLoopIncompleteAnswer(questionLanguageRussian, &ToolLoopRecord{Calls: []ToolCallRecord{{
		Name: "knowvault_read", Outcome: "SUCCEEDED",
		Result: workspacetools.Result{Structured: []byte(`{"objects":[{"source_path":"projects/alpha/waste.txt"}]}`)},
	}}}); !strings.Contains(got, "projects/alpha/waste.txt") || strings.Contains(strings.ToLower(got), "проверен") {
		t.Fatalf("russian incomplete text must name the consulted source without verification prose: %q", got)
	}
	if got := toolLoopUnverifiedCitationsText(questionLanguageRussian); !strings.Contains(got, "\u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c") {
		t.Fatalf("russian unverified-citations text = %q", got)
	}
	if got := toolLoopUnverifiedCitationsText(questionLanguageEnglish); !strings.Contains(got, "could not be verified") {
		t.Fatalf("english unverified-citations text = %q", got)
	}
	if got := toolLoopUnverifiedComparisonText(questionLanguageRussian); !strings.Contains(got, "\u0421\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435") {
		t.Fatalf("russian unverified-comparison text = %q", got)
	}
	if got := toolLoopUnverifiedComparisonText(questionLanguageEnglish); !strings.Contains(got, "comparison") {
		t.Fatalf("english unverified-comparison text = %q", got)
	}
}

const unverifiedAnswerRussianForTest = "\u041d\u0438 \u043e\u0434\u043d\u043e \u0443\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u043f\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0442\u044c \u043d\u0435\u0447\u0435\u0433\u043e. \u0423\u0442\u043e\u0447\u043d\u0438\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441 \u0438\u043b\u0438 \u043d\u0430\u0437\u043e\u0432\u0438\u0442\u0435 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0441\u043b\u0435\u0434\u0443\u0435\u0442 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c."

// TestToolLoopAnswerLanguageMismatch covers card D-5 requirement 4's guard: an
// English question must not receive a Russian answer, while a Russian answer is
// never churned for the Latin identifiers a schema answer needs.
func TestToolLoopAnswerLanguageMismatch(t *testing.T) {
	russian := toolAnswer{Claims: []toolClaim{{Text: "\u041f\u043e \u0434\u0430\u043d\u043d\u044b\u043c \u0442\u0430\u0431\u043b\u0438\u0446\u044b \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u0432 \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u0445 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u043e\u0432 3."}}}
	english := toolAnswer{Claims: []toolClaim{{Text: "There are 3 active contracts."}}}
	mixed := toolAnswer{Claims: []toolClaim{{Text: "There are 3 active contracts, because \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u043c \u0441\u0447\u0438\u0442\u0430\u0435\u0442\u0441\u044f \u0434\u043e\u0433\u043e\u0432\u043e\u0440 \u0441\u043e \u0441\u0442\u0430\u0442\u0443\u0441\u043e\u043c active \u0438 \u0442\u0430\u043a\u0438\u0435 \u0434\u043e\u0433\u043e\u0432\u043e\u0440\u044b \u0441\u0447\u0438\u0442\u0430\u044e\u0442\u0441\u044f \u0434\u0435\u0439\u0441\u0442\u0432\u0443\u044e\u0449\u0438\u043c\u0438 \u043f\u043e \u043f\u0440\u0430\u0432\u0438\u043b\u0443."}}}
	if !toolLoopAnswerLanguageMismatch(russian, questionLanguageEnglish) {
		t.Fatal("a Russian answer to an English question was accepted")
	}
	if toolLoopAnswerLanguageMismatch(english, questionLanguageEnglish) {
		t.Fatal("an English answer to an English question was rejected")
	}
	if !toolLoopAnswerLanguageMismatch(mixed, questionLanguageEnglish) {
		t.Fatal("a half-Russian answer to an English question was accepted")
	}
	if toolLoopAnswerLanguageMismatch(english, questionLanguageRussian) {
		t.Fatal("a Russian question's answer was rejected by the one-sided guard")
	}
	if !strings.Contains(toolLoopLanguageRepairInstruction(questionLanguageEnglish), "English") {
		t.Fatal("the English language repair instruction is not in English")
	}
	if !strings.Contains(toolLoopLanguageRepairInstruction(questionLanguageRussian), "\u0440\u0443\u0441\u0441\u043a\u0438") {
		t.Fatal("the Russian language repair instruction is not in Russian")
	}
	if toolLoopLiveResultMarker(questionLanguageRussian, 1) != " [\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442 1]" ||
		toolLoopLiveResultMarker(questionLanguageEnglish, 1) != " [Live result 1]" ||
		toolLoopLiveResultMarker("", 2) != " [Live result 2]" {
		t.Fatal("live-result marker does not follow the question's language")
	}
}

// TestToolLoopAnswerInternalMarker covers the second half of requirement 4's
// presentation guard: an internal connection/rule/term identifier in the answer
// text is rejected instead of being shown to the user.
func TestToolLoopAnswerInternalMarker(t *testing.T) {
	for _, text := range []string{
		"\u0412 \u0442\u0430\u0431\u043b\u0438\u0446\u0435 container_group \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430 conn_0858ZEMMX17HG65PFQ0E36R58F \u043f\u044f\u0442\u044c \u0437\u0430\u043f\u0438\u0441\u0435\u0439.",
		"\u041f\u0440\u0430\u0432\u0438\u043b\u043e rule_01ABC says contracts are active.",
		"The observation field observed_at is not user text.",
	} {
		if marker := toolLoopAnswerInternalMarker(toolAnswer{Claims: []toolClaim{{Text: text}}}); marker == "" {
			t.Fatalf("internal identifier was not found in %q", text)
		}
	}
	for _, text := range []string{
		"\u0412 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0435 \u00ab\u041c\u041d\u041e\u00bb \u043f\u044f\u0442\u044c \u0437\u0430\u043f\u0438\u0441\u0435\u0439.",
		"There are 3 active contracts in the contract table.",
	} {
		if marker := toolLoopAnswerInternalMarker(toolAnswer{Claims: []toolClaim{{Text: text}}}); marker != "" {
			t.Fatalf("clean answer %q matched internal marker %q", text, marker)
		}
	}
	if toolLoopInternalMarkerRepairInstruction(questionLanguageRussian) == toolLoopInternalMarkerRepairInstruction(questionLanguageEnglish) {
		t.Fatal("the internal-marker repair instruction is not localized")
	}
}

// TestToolLoopAnswerVerificationProse covers the third presentation guard: the
// internal verification vocabulary is rejected instead of being shown.
func TestToolLoopAnswerVerificationProse(t *testing.T) {
	for _, text := range []string{
		"The claim was verified against the fragment.",
		"That needs no verification.",
		"\u042d\u0442\u043e \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043e \u043f\u043e \u043c\u0430\u0442\u0435\u0440\u0438\u0430\u043b\u0430\u043c.",
		"\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u043f\u0440\u043e\u0439\u0434\u0435\u043d\u0430.",
	} {
		if wording := toolLoopAnswerVerificationProse(text); wording == "" {
			t.Fatalf("verification wording was not found in %q", text)
		}
	}
	for _, text := range []string{
		"\u0414\u0440\u0443\u0433\u0438\u0435 \u043f\u0435\u0440\u0438\u043e\u0434\u044b \u043d\u0435 \u0447\u0438\u0442\u0430\u043b\u0438\u0441\u044c.",
		"There are 3 active contracts.",
	} {
		if wording := toolLoopAnswerVerificationProse(text); wording != "" {
			t.Fatalf("clean answer %q matched verification wording %q", text, wording)
		}
	}
	if toolLoopVerificationProseRepairInstruction(questionLanguageRussian) == toolLoopVerificationProseRepairInstruction(questionLanguageEnglish) {
		t.Fatal("the verification-prose repair instruction is not localized")
	}
}
