package question

import (
	"regexp"
	"strings"
)

var (
	comparisonISODate     = regexp.MustCompile(`\b20\d{2}-\d{2}-\d{2}\b`)
	comparisonWrittenDate = regexp.MustCompile(`\b([0-3]?\d)\s+([\p{L}]+)\s+(20\d{2})\b`)
	comparisonSharedMonth = regexp.MustCompile(`\b([0-3]?\d)\s+(?:and|` + "\u0438" + `)\s+([0-3]?\d)\s+([\p{L}]+)\s+(20\d{2})\b`)
)

// recognizedComparison is deliberately narrow. It routes explicit two-day
// comparisons through the server-owned metric comparison when one is available.
// This does not try to infer periods or metric identities from free-form prose.
func recognizedComparison(question string) bool {
	text := strings.ToLower(question)
	if !hasComparisonCue(text) {
		return false
	}
	return comparisonFollowup(question) || len(explicitComparisonDates(question)) == 2
}

func hasComparisonCue(text string) bool {
	for _, cue := range []string{
		"compare", "comparison", "versus", " vs ", "higher", "lower", "difference", "percent", "%",
		"\u0441\u0440\u0430\u0432",                   // compare
		"\u0432\u044b\u0448\u0435",                   // higher
		"\u043d\u0438\u0436\u0435",                   // lower
		"\u0440\u0430\u0437\u043d\u0438\u0446",       // difference
		"\u043f\u0440\u043e\u0446\u0435\u043d\u0442", // percent
		"\u0431\u043e\u043b\u044c\u0448\u0435",       // more
		"\u043c\u0435\u043d\u044c\u0448\u0435",       // less
	} {
		if strings.Contains(text, cue) {
			return true
		}
	}
	return false
}

func comparisonMonth(value string) int {
	for index, prefixes := range [][]string{
		{"jan", "\u044f\u043d\u0432"}, {"feb", "\u0444\u0435\u0432"}, {"mar", "\u043c\u0430\u0440"},
		{"apr", "\u0430\u043f\u0440"}, {"may", "\u043c\u0430\u0439", "\u043c\u0430\u044f"},
		{"jun", "\u0438\u044e\u043d"}, {"jul", "\u0438\u044e\u043b"}, {"aug", "\u0430\u0432\u0433"},
		{"sep", "\u0441\u0435\u043d"}, {"oct", "\u043e\u043a\u0442"}, {"nov", "\u043d\u043e\u044f"},
		{"dec", "\u0434\u0435\u043a"},
	} {
		for _, prefix := range prefixes {
			if strings.HasPrefix(value, prefix) {
				return index + 1
			}
		}
	}
	return 0
}
