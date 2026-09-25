package question

import (
	"encoding/json"
	"strings"
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
