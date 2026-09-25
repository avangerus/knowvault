package question

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// Card D-5 requirement 4: every fallback, uncertainty and failure text the
// user actually sees is written in the language of the question. The question
// is the only language signal this package has, and the existing
// analyticScalarPresentation already uses containsCyrillic for the same
// purpose, so one helper fixes the language for the whole tool loop and every
// text it emits.
const (
	questionLanguageRussian = "ru"
	questionLanguageEnglish = "en"
)

func questionLanguage(questionText string) string {
	if containsCyrillic(questionText) {
		return questionLanguageRussian
	}
	return questionLanguageEnglish
}

func localizedText(language, russian, english string) string {
	if language == questionLanguageRussian {
		return russian
	}
	return english
}

// toolLoopLiveResultMarker renders the inline marker that binds a displayed
// claim to the live result it cites. It follows the question's language, so a
// Russian answer carries no English service marker (card D-5 requirement 4).
// An empty or unknown language keeps the historical English spelling, so a
// record persisted before AnswerLanguage existed reconstructs the exact answer
// bytes it was written with.
func toolLoopLiveResultMarker(language string, ordinal int) string {
	label := "Live result"
	if language == questionLanguageRussian {
		label = "\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442"
	}
	return fmt.Sprintf(" [%s %d]", label, ordinal)
}

// toolLoopEnglishCyrillicMax is the share of Cyrillic letters above which an
// answer to an English question is no longer an English answer. A short
// answer that quotes a Russian term stays below it; an answer written in the
// workspace materials' language does not.
const toolLoopEnglishCyrillicMax = 0.25

// toolLoopAnswerLanguageMismatch reports whether a submitted answer is written
// in a language other than the question's. Card D-5 requirement 4: the answer
// the user reads follows the question's language, so a model that slips into
// the workspace materials' language is asked to rewrite it instead of having
// it shown. The guard is deliberately one-sided: an English question must not
// receive Russian prose, while a Russian answer is allowed to carry the Latin
// identifiers a schema answer legitimately needs.
func toolLoopAnswerLanguageMismatch(answer toolAnswer, language string) bool {
	if language != questionLanguageEnglish {
		return false
	}
	var builder strings.Builder
	for _, claim := range answer.Claims {
		builder.WriteString(claim.Text)
		builder.WriteString("\n")
	}
	builder.WriteString(answer.Clarification)
	cyrillic, letters := 0, 0
	for _, character := range builder.String() {
		if !unicode.IsLetter(character) {
			continue
		}
		letters++
		if unicode.Is(unicode.Cyrillic, character) {
			cyrillic++
		}
	}
	if letters == 0 {
		return false
	}
	return float64(cyrillic)/float64(letters) > toolLoopEnglishCyrillicMax
}

// toolLoopLanguageRepairInstruction tells the model, in the question's own
// language, that the submission was rejected only because of its language.
func toolLoopLanguageRepairInstruction(language string) string {
	return localizedText(language,
		"\u041e\u0442\u0432\u0435\u0442 \u0434\u043e\u043b\u0436\u0435\u043d \u0431\u044b\u0442\u044c \u043d\u0430 \u044f\u0437\u044b\u043a\u0435 \u0432\u043e\u043f\u0440\u043e\u0441\u0430. \u041f\u0435\u0440\u0435\u043f\u0438\u0448\u0438\u0442\u0435 \u0432\u0435\u0441\u044c \u043e\u0442\u0432\u0435\u0442 \u043f\u043e-\u0440\u0443\u0441\u0441\u043a\u0438, \u0432\u043a\u043b\u044e\u0447\u0430\u044f \u043f\u0440\u0430\u0432\u0438\u043b\u0430 \u0438 \u0444\u043e\u0440\u043c\u0443\u043b\u0438\u0440\u043e\u0432\u043a\u0438 \u0438\u0437 \u043c\u0430\u0442\u0435\u0440\u0438\u0430\u043b\u043e\u0432 \u0440\u0430\u0431\u043e\u0447\u0435\u0439 \u043e\u0431\u043b\u0430\u0441\u0442\u0438.",
		"The question is in English and the answer must be in English. Rewrite the whole answer in English, including any rule or wording taken from the workspace materials; do not answer in Russian.")
}

// toolLoopAnswerInternalMarkers are the internal identifiers that must never
// appear in a user-visible answer: a connection, rule, term or binding id, a
// raw observation field, a paraphrase marker or an inbox path. They are the
// enforceable half of the presentation rule that tells the model to name a
// source by its human name.
var toolLoopAnswerInternalMarkers = []*regexp.Regexp{
	regexp.MustCompile(`conn_[0-9A-Z]`),
	regexp.MustCompile(`rule_[0-9A-Z]`),
	regexp.MustCompile(`term_[0-9A-Z]`),
	regexp.MustCompile(`binding_[0-9A-Z]`),
	regexp.MustCompile(`observed_at`),
	regexp.MustCompile(`paraphrase`),
	regexp.MustCompile(`inbox/`),
}

// toolLoopAnswerInternalMarker returns the first internal identifier found in a
// submitted answer, or the empty string. A model that leaks one is asked to
// rewrite the answer instead of having it shown to the user.
func toolLoopAnswerInternalMarker(answer toolAnswer) string {
	return toolLoopAnswerInternalMarkerInText(toolLoopAnswerText(answer))
}

// toolLoopAnswerText is the user-visible text of a submitted answer.
func toolLoopAnswerText(answer toolAnswer) string {
	var builder strings.Builder
	for _, claim := range answer.Claims {
		builder.WriteString(claim.Text)
		builder.WriteString("\n")
	}
	builder.WriteString(answer.Clarification)
	return builder.String()
}

// toolLoopAnswerInternalMarkerInText returns the first internal identifier in a
// user-visible answer text, or the empty string.
func toolLoopAnswerInternalMarkerInText(text string) string {
	for _, pattern := range toolLoopAnswerInternalMarkers {
		if match := pattern.FindString(text); match != "" {
			return match
		}
	}
	return ""
}

// toolLoopAnswerForbiddenProse matches the words the presentation rules reserve
// for the internal verification machinery. "verif" covers verified and
// verification; "провер" covers проверено, проверенный, проверка and проверять.
var toolLoopAnswerForbiddenProse = regexp.MustCompile(`(?i)(verif|провер)`)

// toolLoopAnswerVerificationProse returns the forbidden verification wording in
// a user-visible answer text, or the empty string.
func toolLoopAnswerVerificationProse(text string) string {
	return toolLoopAnswerForbiddenProse.FindString(text)
}

// toolLoopVerificationProseRepairInstruction tells the model, in the question's
// language, which presentation rule its rejected submission broke.
func toolLoopVerificationProseRepairInstruction(language string) string {
	return localizedText(language,
		"\u0412 \u0442\u0435\u043a\u0441\u0442\u0435 \u043e\u0442\u0432\u0435\u0442\u0430 \u0435\u0441\u0442\u044c \u0441\u043b\u043e\u0432\u043e \u043e \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0435. \u041d\u0435 \u0443\u043f\u043e\u0442\u0440\u0435\u0431\u043b\u044f\u0439\u0442\u0435 \u0441\u043b\u043e\u0432\u0430 \u00ab\u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043e\u00bb, \u00ab\u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u043d\u044b\u0439\u00bb, \u00ab\u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0430\u00bb, \u00ab\u043f\u0440\u043e\u0432\u0435\u0440\u044f\u0442\u044c\u00bb; \u043d\u0430\u043f\u0438\u0448\u0438\u0442\u0435 \u00ab\u0432 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d\u043d\u044b\u0445 \u043c\u0430\u0442\u0435\u0440\u0438\u0430\u043b\u0430\u0445\u00bb \u0438\u043b\u0438 \u00ab\u0432 \u043f\u0440\u043e\u0441\u043c\u043e\u0442\u0440\u0435\u043d\u043d\u044b\u0445 \u043c\u0430\u0442\u0435\u0440\u0438\u0430\u043b\u0430\u0445\u00bb.",
		"The answer contains verification wording. Do not write verified, verification or similar words; write \"in the materials read\" instead.")
}

// toolLoopInternalMarkerRepairInstruction tells the model, in the question's
// language, which presentation rule its rejected submission broke.
func toolLoopInternalMarkerRepairInstruction(language string) string {
	return localizedText(language,
		"\u0412 \u0442\u0435\u043a\u0441\u0442\u0435 \u043e\u0442\u0432\u0435\u0442\u0430 \u0435\u0441\u0442\u044c \u0432\u043d\u0443\u0442\u0440\u0435\u043d\u043d\u0438\u0439 \u0438\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440. \u0423\u0431\u0435\u0440\u0438\u0442\u0435 \u0435\u0433\u043e \u0438 \u043d\u0430\u0437\u043e\u0432\u0438\u0442\u0435 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a \u043f\u043e \u0447\u0435\u043b\u043e\u0432\u0435\u0447\u0435\u0441\u043a\u043e\u043c\u0443 \u0438\u043c\u0435\u043d\u0438; \u0438\u0434\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0442\u043e\u0440\u044b \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0439, \u043f\u0440\u0430\u0432\u0438\u043b \u0438 \u0442\u0435\u0440\u043c\u0438\u043d\u043e\u0432 \u0432 \u043e\u0442\u0432\u0435\u0442\u0435 \u043d\u0435\u0434\u043e\u043f\u0443\u0441\u0442\u0438\u043c\u044b.",
		"The answer text contains an internal identifier. Remove it and name the source by its human name; connection, rule and term identifiers must never appear in the answer.")
}

// toolLoopNoDataFallback is the answer shown when the model submitted no_data
// (or no claim at all) with nothing readable to fall back on. The variants and
// the precedence between them are unchanged; only the wording follows the
// question's language.
func toolLoopNoDataFallback(record *ToolLoopRecord, hasSuccessfulComparison bool, language string) string {
	if hasSuccessfulComparison || record == nil {
		return localizedText(language, noWorkspaceDataRussian, noWorkspaceData)
	}
	refused := false
	for _, call := range record.Calls {
		if call.Name == trustedMetricToolName && call.Outcome == "REFUSED" {
			return localizedText(language, refusedMetricComparisonRussian, refusedMetricComparison)
		}
		if call.Outcome == "REFUSED" {
			refused = true
		}
	}
	if refused {
		return localizedText(language, unreadableWorkspaceDataRussian, unreadableWorkspaceData)
	}
	return localizedText(language, noWorkspaceDataRussian, noWorkspaceData)
}

// toolLoopIncompleteAnswer is the last-resort text for a run whose forced final
// turn also produced no answer at all. It names honestly what happened and, when
// this run actually consulted sources, lists them; it never mentions profile
// limits (the caller only reaches this string when no limit was hit).
func toolLoopIncompleteAnswer(language string, record *ToolLoopRecord) string {
	sources := toolLoopConsultedSources(record)
	if len(sources) == 0 {
		return localizedText(language,
			"\u041c\u043e\u0434\u0435\u043b\u044c \u043d\u0435 \u043f\u0440\u0435\u0434\u0441\u0442\u0430\u0432\u0438\u043b\u0430 \u043e\u0442\u0432\u0435\u0442\u0430 \u043f\u043e \u0443\u0436\u0435 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d\u043d\u044b\u043c \u0434\u0430\u043d\u043d\u044b\u043c, \u0438 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0451\u043d\u043d\u044b\u0445 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u043e\u0432 \u043d\u0435\u0442. \u0423\u0442\u043e\u0447\u043d\u0438\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441 \u0438\u043b\u0438 \u043d\u0430\u0437\u043e\u0432\u0438\u0442\u0435 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0441\u043b\u0435\u0434\u0443\u0435\u0442 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c.",
			"The model did not submit an answer from the data already read, and no source was verified. Refine the question or name the document to read.")
	}
	return localizedText(language,
		"\u041c\u043e\u0434\u0435\u043b\u044c \u043d\u0435 \u043f\u0440\u0435\u0434\u0441\u0442\u0430\u0432\u0438\u043b\u0430 \u043e\u0442\u0432\u0435\u0442\u0430 \u043f\u043e \u0443\u0436\u0435 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u043d\u043d\u044b\u043c \u0434\u0430\u043d\u043d\u044b\u043c. \u0418\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u044b \u043c\u0430\u0442\u0435\u0440\u0438\u0430\u043b\u044b: ",
		"The model did not submit an answer from the data already read. Sources consulted: ") +
		strings.Join(sources, "; ") + localizedText(language,
		". \u0423\u0442\u043e\u0447\u043d\u0438\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441 \u0438\u043b\u0438 \u0437\u0430\u0434\u0430\u0439\u0442\u0435 \u0435\u0433\u043e \u043f\u043e \u0447\u0430\u0441\u0442\u044f\u043c.",
		". Refine the question or ask it in smaller parts.")
}

// toolLoopUnverifiedAnswer is the honest text for a final answer whose every
// citation failed verification: nothing verifiable remains, so the answer says
// so plainly and suggests how to ask.
func toolLoopUnverifiedAnswer(language string) string {
	return localizedText(language,
		"\u041d\u0438 \u043e\u0434\u043d\u043e \u0443\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u0435 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u043f\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c, \u043f\u043e\u044d\u0442\u043e\u043c\u0443 \u043f\u043e\u043a\u0430\u0437\u044b\u0432\u0430\u0442\u044c \u043d\u0435\u0447\u0435\u0433\u043e. \u0423\u0442\u043e\u0447\u043d\u0438\u0442\u0435 \u0432\u043e\u043f\u0440\u043e\u0441 \u0438\u043b\u0438 \u043d\u0430\u0437\u043e\u0432\u0438\u0442\u0435 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442, \u043a\u043e\u0442\u043e\u0440\u044b\u0439 \u0441\u043b\u0435\u0434\u0443\u0435\u0442 \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c.",
		"None of the claims could be verified against their sources, so there is nothing to show. Refine the question or name the document to read.")
}

// toolLoopConsultedSources lists, content-free, the workspace source paths this
// run actually reached in a successful call's structured result. It is what the
// honest failure text names when nothing could be verified, and it never
// invents a source the run did not read.
func toolLoopConsultedSources(record *ToolLoopRecord) []string {
	if record == nil {
		return nil
	}
	seen := make(map[string]struct{})
	sources := make([]string, 0)
	for _, call := range record.Calls {
		if call.Outcome != "SUCCEEDED" || len(call.Result.Structured) == 0 {
			continue
		}
		for _, path := range toolResultSourcePaths(call.Result.Structured) {
			if _, duplicate := seen[path]; duplicate {
				continue
			}
			seen[path] = struct{}{}
			sources = append(sources, path)
			if len(sources) == 3 {
				return sources
			}
		}
	}
	return sources
}

// toolLoopUnverifiedCitationsText is the tool-loop text shown when a run whose
// live or scalar result could not be authenticated falls back to a plain
// statement. It is the same honest message as toolLoopUnverifiedAnswer, in the
// question's language (card D-5 requirement 4).
func toolLoopUnverifiedCitationsText(language string) string {
	return localizedText(language,
		"\u0423\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0438\u044f \u043e\u0442\u0432\u0435\u0442\u0430 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u043f\u043e \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430\u043c. \u041f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0437\u0430\u043f\u0440\u043e\u0441.",
		"The answer citations could not be verified against their sources. Please try again.")
}

// toolLoopUnverifiedComparisonText is the same statement for the approved
// metric comparison whose own result could not be authenticated.
func toolLoopUnverifiedComparisonText(language string) string {
	return localizedText(language,
		"\u0421\u0440\u0430\u0432\u043d\u0435\u043d\u0438\u0435 \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c. \u041f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435 \u0437\u0430\u043f\u0440\u043e\u0441.",
		"The comparison could not be verified. Please try again.")
}

// toolResultSourcePaths extracts the source-path strings a knowledge tool
// published: list_objects' structured objects[].source_path, and search/grep/
// read results' own source_path member, at any depth. Only strings are
// reported; the walk is bounded by the result the run already holds.
func toolResultSourcePaths(raw []byte) []string {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	paths := make([]string, 0)
	var visit func(any)
	visit = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				if key == "source_path" {
					if text, ok := child.(string); ok && text != "" {
						paths = append(paths, text)
					}
					continue
				}
				visit(child)
			}
		case []any:
			for _, child := range value {
				visit(child)
			}
		}
	}
	visit(value)
	return paths
}
