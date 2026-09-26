package question

// Card D-14: answers the product composes itself -- calculations, refusals,
// extractive answers, their explanations and labels -- follow the language of
// the question, exactly like the tool loop's own fallback texts already do
// (tool_loop_language.go). The question is the only language signal this
// package has; a Russian question must never receive an English service
// sentence such as "Answer:" or "Insufficient evidence in the connected
// sources.", and an English question must never receive a Russian one.

import "strings"

// insufficientEvidenceAnswer is the single stable refusal sentence used when a
// run has no citation to stand on. It is the transport-identical sentence the
// question authority already published, now selected by the question's own
// language.
func insufficientEvidenceAnswer(language string) string {
	return localizedText(language,
		"\u041d\u0435\u0434\u043e\u0441\u0442\u0430\u0442\u043e\u0447\u043d\u043e \u0434\u043e\u043a\u0430\u0437\u0430\u0442\u0435\u043b\u044c\u0441\u0442\u0432 \u0432 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u0445.",
		"Insufficient evidence in the connected sources.")
}

// ambiguousStructuredSourceAnswer is the named clarifying refusal for a
// question more than one enabled structured source could resolve. Source names
// are the workspace's own data and stay exactly as the operator wrote them;
// only the product's own sentence follows the question language.
func ambiguousStructuredSourceAnswer(language string, names []string) string {
	var answer strings.Builder
	answer.WriteString(localizedText(language,
		"\u0412\u043e\u043f\u0440\u043e\u0441 \u043d\u0435 \u0443\u043a\u0430\u0437\u044b\u0432\u0430\u0435\u0442 \u043e\u0434\u043d\u043e\u0437\u043d\u0430\u0447\u043d\u043e \u043d\u0430 \u043e\u0434\u0438\u043d \u0438\u0437 \u0432\u043a\u043b\u044e\u0447\u0451\u043d\u043d\u044b\u0445 \u0441\u0442\u0440\u0443\u043a\u0442\u0443\u0440\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u043e\u0432: ",
		"The question does not uniquely identify one of the enabled structured sources: "))
	for index, name := range names {
		if index > 0 {
			answer.WriteString(", ")
		}
		answer.WriteString("\u00ab")
		answer.WriteString(name)
		answer.WriteString("\u00bb")
	}
	answer.WriteString(localizedText(language,
		". \u0414\u043e\u0431\u0430\u0432\u044c\u0442\u0435 \u0441\u043b\u043e\u0432\u043e, \u0445\u0430\u0440\u0430\u043a\u0442\u0435\u0440\u043d\u043e\u0435 \u0434\u043b\u044f \u043e\u0434\u043d\u043e\u0433\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430, \u0438\u043b\u0438 \u0437\u0430\u0434\u0430\u0439\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441, \u0432\u043a\u043b\u044e\u0447\u0438\u0432 \u0442\u043e\u043b\u044c\u043a\u043e \u0435\u0433\u043e.",
		". Add a term specific to one source, or ask with only that source enabled."))
	return answer.String()
}
